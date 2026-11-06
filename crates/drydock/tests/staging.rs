//! Staging through drydockd's prepare: an image a registry-pull provider cannot
//! reach is copied once into a registry it can pull from, and the host is
//! handed that copy (drydock#190). On the provider-push route the copy goes
//! into the provider's own registry with access it mints.
#![cfg(unix)]
use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use drydock::{
    HostConnection,
    config::Config,
    daemon::{Daemon, HostOption, ProviderApi, Seams},
    staging::{CHUNK_BYTES, Transfer},
};
use drydock_host::module::{ByteStream, Credentials, HttpClient, Module, Provider, Result as ModuleResult};
use drydock_protocol::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

const LAB: &str = "lab.test";
const STAGE: &str = "stage.test";
const STAGED: &str = "stage.test/org/staging";
const MIRROR: &str = "quay.test/org/mirror";
/// A provider's own registry, which it mints push access to.
const OWN: &str = "harbor.test";
const OWN_REPOSITORY: &str = "project/drydock-vessel";
/// The public tools registry: anyone may pull.
const TOOLS: &str = "tools.test";
const CHUNK: u64 = 256;
/// GHCR's limit on one upload request's body.
const PATCH_LIMIT: usize = 4 << 20;

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn basic(user: &str, secret: &str) -> String {
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{secret}")))
}
fn credential(user: &str, secret: &str) -> RegistryCredential {
    RegistryCredential { username: user.into(), secret: Secret::new(secret) }
}

/// One registry account: the Basic authorization it signs in with, the host
/// it belongs to, and whether it may push.
struct Account {
    host: &'static str,
    user: &'static str,
    secret: &'static str,
    push: bool,
}
const ACCOUNTS: [Account; 4] = [
    Account { host: LAB, user: "lab-user", secret: "lab-secret", push: false },
    Account { host: STAGE, user: "bot", secret: "push-token", push: true },
    Account { host: STAGE, user: "bot", secret: "pull-token", push: false },
    Account { host: OWN, user: "robot$drydock", secret: "minted-secret", push: true },
];

#[derive(Default)]
struct Oci {
    blobs: BTreeMap<(String, String), Bytes>,
    /// (host, repository, reference) to (media type, bytes).
    manifests: BTreeMap<(String, String, String), (String, Bytes)>,
    uploads: BTreeMap<String, Vec<u8>>,
    /// Bearer tokens to the host they were issued by and whether they may push.
    tokens: BTreeMap<String, (String, bool)>,
    /// Every request: host, method and path.
    requests: Vec<(String, String, String)>,
    /// Basic authorizations seen at each host, by the account's own host.
    signins: Vec<(String, &'static str)>,
    /// The staging registry answers uploads with this status.
    refuse_push: Option<u16>,
    /// The message it refuses with, when not the usual one.
    refusal_message: Option<String>,
    /// The provider's registry serves a new manifest only after this many reads.
    visibility_delay: usize,
    hidden: BTreeMap<String, usize>,
    /// Source registries answer ranged reads with the whole blob.
    ignore_range: bool,
    /// The provider's registry refuses the next tag put.
    refuse_tag_once: bool,
    violations: Vec<String>,
}
/// Stands in for the network boundary to every registry: the OCI distribution
/// API with bearer-token challenges, blob HEAD, ranged reads, chunked uploads
/// with Content-Range, and manifest puts by digest. Registries are private:
/// anonymous token requests are refused.
#[derive(Default, Clone)]
struct Registries(Arc<Mutex<Oci>>);
#[async_trait]
impl HttpClient for Registries {
    async fn execute(&self, request: reqwest::Request, _: &rigging_http_client::ChannelLabel) -> Result<http::Response<Bytes>, String> {
        // Every registry call yields, as a network call would, so concurrent
        // prepares interleave between calls.
        tokio::task::yield_now().await;
        Ok(respond(&mut self.0.lock().unwrap(), &request))
    }
}
fn respond(s: &mut Oci, request: &reqwest::Request) -> http::Response<Bytes> {
    let reply = |status: u16, headers: &[(&str, String)], body: Bytes| {
        let mut response = http::Response::builder().status(status);
        for (name, value) in headers {
            response = response.header(*name, value);
        }
        response.body(body).unwrap()
    };
    let host = request.url().host_str().unwrap().to_owned();
    let path = request.url().path().to_owned();
    let method = request.method().as_str().to_owned();
    s.requests.push((host.clone(), method.clone(), path.clone()));
    let authorization = request.headers().get("authorization").map(|v| v.to_str().unwrap().to_owned());
    if path == "/token" {
        let account = ACCOUNTS.iter().find(|a| authorization.as_deref() == Some(&basic(a.user, a.secret)));
        if account.is_none() && authorization.is_none() && host == TOOLS {
            let token = format!("token-{}", s.tokens.len());
            s.tokens.insert(token.clone(), (host, false));
            return reply(200, &[], Bytes::from(json!({ "token": token }).to_string()));
        }
        let Some(account) = account else { return reply(401, &[], Bytes::new()) };
        s.signins.push((host.clone(), account.host));
        if account.host != host {
            s.violations.push(format!("{}'s credential sent to {host}", account.host));
            return reply(401, &[], Bytes::new());
        }
        let scope = request.url().query_pairs().find(|(k, _)| k == "scope").map(|(_, v)| v.into_owned()).unwrap_or_default();
        let token = format!("token-{}", s.tokens.len());
        s.tokens.insert(token.clone(), (host, account.push && scope.ends_with(":pull,push")));
        return reply(200, &[], Bytes::from(json!({ "token": token }).to_string()));
    }
    let writes = matches!(method.as_str(), "POST" | "PATCH" | "PUT");
    let granted = authorization.as_deref().and_then(|a| a.strip_prefix("Bearer ")).and_then(|t| s.tokens.get(t));
    if !granted.is_some_and(|(h, push)| *h == host && (*push || !writes)) {
        return reply(401, &[("www-authenticate", format!(r#"Bearer realm="https://{host}/token",service="{host}""#))], Bytes::new());
    }
    let body = request.body().and_then(|b| b.as_bytes()).map(Bytes::copy_from_slice).unwrap_or_default();
    let rest = path.strip_prefix("/v2/").unwrap_or_default().to_owned();
    if let Some((repository, reference)) = rest.rsplit_once("/manifests/") {
        if method == "PUT" {
            let manifest: Value = serde_json::from_slice(&body).unwrap();
            let referenced = std::iter::once(&manifest["config"]).chain(manifest["layers"].as_array().unwrap());
            if referenced.into_iter().any(|d| !s.blobs.contains_key(&(host.clone(), d["digest"].as_str().unwrap().into()))) {
                s.violations.push("manifest put before its blobs".into());
                return reply(400, &[], Bytes::new());
            }
            // Only the provider's own registry, which drops untagged images, is tagged.
            if reference != sha256(&body) && (host != OWN || reference != sha256(&body).replace(':', "-")) {
                s.violations.push(format!("manifest put under {reference}, not its digest"));
                return reply(400, &[], Bytes::new());
            }
            if host == OWN && reference != sha256(&body) && std::mem::take(&mut s.refuse_tag_once) {
                return reply(503, &[], Bytes::new());
            }
            if host == OWN && reference == sha256(&body) && s.visibility_delay > 0 {
                s.hidden.insert(reference.into(), s.visibility_delay);
            }
            let media_type = request.headers()["content-type"].to_str().unwrap().to_owned();
            s.manifests.insert((host, repository.into(), reference.into()), (media_type, body.clone()));
            return reply(201, &[("docker-content-digest", sha256(&body))], Bytes::new());
        }
        if let Some(reads) = s.hidden.get_mut(reference) {
            *reads -= 1;
            if *reads == 0 {
                s.hidden.remove(reference);
            }
            return reply(404, &[], Bytes::new());
        }
        return match s.manifests.get(&(host, repository.into(), reference.into())) {
            Some((media_type, bytes)) => reply(
                200,
                &[("content-type", media_type.clone()), ("docker-content-digest", sha256(bytes))],
                if method == "HEAD" { Bytes::new() } else { bytes.clone() },
            ),
            None => reply(404, &[], Bytes::new()),
        };
    }
    if let Some((repository, id)) = rest.split_once("/blobs/uploads/") {
        if let Some(status) = s.refuse_push {
            let challenge = format!(r#"Bearer realm="https://{host}/token",service="{host}""#);
            let headers = if status == 401 { vec![("www-authenticate", challenge)] } else { vec![] };
            let message = s.refusal_message.clone().unwrap_or_else(|| "permission_denied: write_package".into());
            return reply(status, &headers, Bytes::from(json!({"errors":[{"code":"DENIED","message":message}]}).to_string()));
        }
        let location = |id: &str| format!("/v2/{repository}/blobs/uploads/{id}");
        if method == "POST" {
            let id = format!("upload-{}", s.requests.len());
            s.uploads.insert(id.clone(), vec![]);
            return reply(202, &[("location", location(&id))], Bytes::new());
        }
        let Some(data) = s.uploads.get_mut(id) else { return reply(404, &[], Bytes::new()) };
        if method == "PATCH" {
            // As GHCR answers an upload request over its limit.
            if body.len() > PATCH_LIMIT {
                let error = r#"{"errors":[{"code":"REQUESTED_RANGE_NOT_SATISFIABLE","message":"the request body is too large and exceeds the maximum permissible limit of 4.00MiB"}]}"#;
                return reply(416, &[], Bytes::from_static(error.as_bytes()));
            }
            let expected = format!("{}-{}", data.len(), data.len() + body.len() - 1);
            if request.headers().get("content-range").and_then(|v| v.to_str().ok()) != Some(&expected) {
                s.violations.push(format!("chunk out of order; expected {expected}"));
                return reply(416, &[], Bytes::new());
            }
            data.extend_from_slice(&body);
            return reply(202, &[("location", location(id)), ("range", format!("0-{}", data.len() - 1))], Bytes::new());
        }
        let mut data = s.uploads.remove(id).unwrap();
        data.extend_from_slice(&body);
        let digest = request.url().query_pairs().find(|(k, _)| k == "digest").map(|(_, v)| v.into_owned()).unwrap_or_default();
        if sha256(&data) != digest {
            s.violations.push("upload committed under the wrong digest".into());
            return reply(400, &[], Bytes::new());
        }
        s.blobs.insert((host, digest.clone()), data.into());
        return reply(201, &[("docker-content-digest", digest)], Bytes::new());
    }
    if let Some((_, digest)) = rest.rsplit_once("/blobs/") {
        let Some(bytes) = s.blobs.get(&(host, digest.to_owned())).cloned() else { return reply(404, &[], Bytes::new()) };
        if method == "HEAD" {
            return reply(200, &[("content-length", bytes.len().to_string())], Bytes::new());
        }
        let range = request.headers().get("range").and_then(|v| v.to_str().ok()).and_then(|r| r.strip_prefix("bytes="));
        let range = range.filter(|_| !s.ignore_range);
        let Some((start, end)) = range.and_then(|r| r.split_once('-')) else { return reply(200, &[], bytes) };
        let (start, end): (usize, usize) = (start.parse().unwrap(), end.parse::<usize>().unwrap().min(bytes.len() - 1));
        return reply(206, &[("content-range", format!("bytes {start}-{end}/{}", bytes.len()))], bytes.slice(start..=end));
    }
    s.violations.push(format!("unexpected registry request {method} {path}"));
    reply(400, &[], Bytes::new())
}
impl Registries {
    /// Stores an image index over an amd64 and an arm64 image at `host/repository`
    /// and returns its reference and the amd64 manifest's digest. Layers span
    /// several transfer chunks.
    fn seed(&self, host: &str, repository: &str) -> (String, String) {
        self.seed_with(host, repository, 0)
    }
    /// As [`Self::seed`], with `padding` more bytes in each image's first layer.
    fn seed_with(&self, host: &str, repository: &str, padding: usize) -> (String, String) {
        let mut s = self.0.lock().unwrap();
        let mut entries = vec![];
        let mut amd64 = String::new();
        for arch in ["amd64", "arm64"] {
            let layers: Vec<Bytes> = (0..3)
                .map(|i| {
                    let mut layer = format!("{repository}:{arch}:{i}:").repeat(40).into_bytes();
                    layer.resize(layer.len() + if i == 0 { padding } else { 0 }, b'.');
                    Bytes::from(layer)
                })
                .collect();
            let config = Bytes::from(
                json!({"os":"linux","architecture":arch,"rootfs":{"type":"layers","diff_ids":layers.iter().map(|l| sha256(l)).collect::<Vec<_>>()}})
                    .to_string(),
            );
            let descriptor = |media_type: &str, bytes: &Bytes| json!({"mediaType":media_type,"digest":sha256(bytes),"size":bytes.len()});
            let manifest = Bytes::from(
                json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
                    "config":descriptor("application/vnd.oci.image.config.v1+json",&config),
                    "layers":layers.iter().map(|l| descriptor("application/vnd.oci.image.layer.v1.tar+gzip", l)).collect::<Vec<_>>()})
                .to_string(),
            );
            for blob in layers.iter().chain([&config]) {
                s.blobs.insert((host.into(), sha256(blob)), blob.clone());
            }
            let digest = sha256(&manifest);
            if arch == "amd64" {
                amd64 = digest.clone();
            }
            entries.push(json!({"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":digest,"size":manifest.len(),"platform":{"os":"linux","architecture":arch}}));
            s.manifests.insert((host.into(), repository.into(), digest), ("application/vnd.oci.image.manifest.v1+json".into(), manifest));
        }
        let index =
            Bytes::from(json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":entries}).to_string());
        let digest = sha256(&index);
        s.manifests.insert((host.into(), repository.into(), digest.clone()), ("application/vnd.oci.image.index.v1+json".into(), index));
        (format!("{host}/{repository}@{digest}"), amd64)
    }
    fn uploads_to(&self, host: &str) -> usize {
        self.0.lock().unwrap().requests.iter().filter(|(h, m, _)| h == host && matches!(m.as_str(), "POST" | "PATCH" | "PUT")).count()
    }
    fn violations(&self) -> Vec<String> {
        self.0.lock().unwrap().violations.clone()
    }
}

/// A provider that records the prepare requests its host hands it, and how
/// often it minted push access. By default it pulls from registries; its
/// `route` setting makes it push into its own (`push`, with the route's
/// `max_image_bytes`, `chunk_bytes` and minted access's `lifetime_seconds`).
#[derive(Clone, Default)]
struct Pulling(Arc<Mutex<Vec<(String, PrepareRequest)>>>, Arc<std::sync::atomic::AtomicUsize>);
#[async_trait]
impl Module for Pulling {
    fn version(&self) -> &str {
        "test"
    }
    async fn configure(&self, name: &str, c: &ProviderConfiguration, _: Arc<dyn HttpClient>) -> ModuleResult<Arc<dyn Provider>> {
        let settings = serde_json::to_value(&c.settings).unwrap();
        Ok(Arc::new(PullingProvider { name: name.into(), seen: self.0.clone(), mints: self.1.clone(), settings }))
    }
}
struct PullingProvider {
    name: String,
    seen: Arc<Mutex<Vec<(String, PrepareRequest)>>>,
    mints: Arc<std::sync::atomic::AtomicUsize>,
    settings: Value,
}
#[async_trait]
impl drydock_host::module::PushAccessOperation for PullingProvider {
    async fn push_access(&self, _: &Credentials) -> ModuleResult<PushAccess> {
        self.mints.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let lifetime = self.settings["lifetime_seconds"].as_i64().unwrap_or(3600);
        Ok(PushAccess {
            repository: format!("{OWN}/{OWN_REPOSITORY}"),
            credential: credential("robot$drydock", "minted-secret"),
            expires_at: Some((chrono::Utc::now() + chrono::TimeDelta::seconds(lifetime)).into()),
        })
    }
}
#[async_trait]
impl Provider for PullingProvider {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            material_modes: vec![MaterialMode::Frozen],
            checkout_strategies: vec![CheckoutStrategy::CloneInVessel],
            workspace_root: "/workspace".into(),
            suspend_resume: false,
            suspend_preserves_memory: None,
            export: false,
            egress: EgressCapability { routes: vec![EgressRoute::Open], model: EgressModel::unfiltered() },
            fallback_runner: false,
            bootstrap: BootstrapRoute::Bake,
            agent: false,
            platforms: vec![Platform::new("linux", "amd64")],
            image_routes: vec![match self.settings["route"].as_str() {
                Some("push") => ImageRoute::ProviderPush {
                    protocol: PushProtocol::OciDistribution,
                    credential_lifetime_seconds: Some(3600),
                    tools_layer: ToolsLayer::Upload,
                    max_image_bytes: self.settings["max_image_bytes"].as_u64(),
                    chunk_bytes: self.settings["chunk_bytes"].as_u64(),
                },
                _ => ImageRoute::RegistryPull {
                    auth: RegistryAuthKind::Basic,
                    registration: CredentialRegistration::PerRequest,
                    digest_references: true,
                    tools_layer: ToolsLayer::Provider,
                },
            }],
            usage: false,
            quota: false,
            host_filesystem: false,
            host_processes: false,
            exclusive_label: false,
            agent_tcp_port: None,
            reach_ways: vec![],
            semantics: Default::default(),
        }
    }
    fn ways_in(&self) -> Vec<WayIn> {
        vec![WayIn::Poll { interval_ms: 60_000 }]
    }
    fn operations(&self) -> drydock_host::module::Operations<'_> {
        drydock_host::module::Operations {
            push_access: (self.settings["route"] == "push").then_some(self as &dyn drydock_host::module::PushAccessOperation),
            ..Default::default()
        }
    }
    fn readiness(&self, _: &Credentials) -> Readiness {
        Readiness::Ready
    }
    async fn prepare(&self, r: PrepareRequest, _: &Credentials) -> ModuleResult<Prepared> {
        self.seen.lock().unwrap().push((self.name.clone(), r.clone()));
        let platform = r.platform.clone().unwrap();
        Ok(Prepared {
            provider: self.name.clone(),
            id: "prepared".into(),
            platform,
            image_digest: r.image_digest,
            tools_digest: r.tools_digest,
        })
    }
    async fn provision(&self, _: ProvisionRequest, _: &Credentials) -> ModuleResult<drydock_host::module::Provisioned> {
        unimplemented!()
    }
    async fn list(&self, _: &Credentials) -> ModuleResult<Vec<Environment>> {
        Ok(vec![])
    }
    async fn inspect(&self, _: &str, _: &Credentials) -> ModuleResult<Environment> {
        unimplemented!()
    }
    async fn destroy(&self, _: &str, _: &Credentials) -> ModuleResult<()> {
        unimplemented!()
    }
    async fn reach(&self, _: &str, _: &Credentials) -> ModuleResult<Reach> {
        unimplemented!()
    }
    async fn relay(&self, _: &str, _: &Credentials) -> ModuleResult<ByteStream> {
        unimplemented!()
    }
}

struct Digests;
#[async_trait]
impl drydock::launch::ImageResolver for Digests {
    async fn resolve(&self, image: &str) -> Result<String, drydock::client::Error> {
        Ok(image.into())
    }
}

/// A daemon whose `e2b` and `modal` instances both pull from the `ghcr`
/// staging registry, with its push and pull credentials in files; `e2b`
/// can also pull from `quay`.
async fn start(dir: &Path, registries: &Registries, module: &Pulling) -> Arc<Daemon> {
    start_with(dir, registries, module, CHUNK, "").await
}
/// As [`start`], uploading `chunk` bytes per request by default and with
/// `ghcr` extra settings for the `ghcr` registry.
async fn start_with(dir: &Path, registries: &Registries, module: &Pulling, chunk: u64, ghcr: &str) -> Arc<Daemon> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.join("host.sock");
    let host = drydock_host::Host::new(BTreeMap::from([("pulling".into(), Arc::new(module.clone()) as Arc<dyn Module>)]));
    let served = socket.clone();
    tokio::spawn(async move { host.serve_unix(served, std::future::pending()).await.unwrap() });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !socket.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    std::fs::write(dir.join("push"), "push-token\n").unwrap();
    std::fs::write(dir.join("pull"), "pull-token\n").unwrap();
    let text = format!(
        r#"[registries.ghcr]
repository = "{STAGED}"
push = {{ username = "bot", credential = {{ file = "{push}" }} }}
pull = {{ username = "bot", credential = {{ file = "{pull}" }} }}
{ghcr}
[registries.quay]
repository = "{MIRROR}"
push = {{ username = "bot", credential = {{ file = "{push}" }} }}
[providers.e2b]
module = "pulling"
pull_from = ["ghcr", "quay"]
[providers.modal]
module = "pulling"
pull_from = ["ghcr"]
[providers.daytona]
module = "pulling"
settings = {{ route = "push", chunk_bytes = 100 }}
[providers.small]
module = "pulling"
settings = {{ route = "push", max_image_bytes = 1000 }}
[providers.brief]
module = "pulling"
settings = {{ route = "push", lifetime_seconds = 10 }}
"#,
        push = dir.join("push").display(),
        pull = dir.join("pull").display(),
    );
    let run = dir.join("run");
    let option = HostOption { optional: false, name: "rust".into(), connection: HostConnection::ExternalUnix { path: socket } };
    let seams = Seams { registries: Transfer { http: Arc::new(registries.clone()), chunk_bytes: chunk }, ..Seams::new(Arc::new(Digests)) };
    Daemon::start_with_seams(Config::parse(&text).unwrap(), &run, run.join("keys"), vec![option], seams).await.unwrap()
}
fn tools() -> String {
    format!("ghcr.io/flotilla-org/drydock-tools@sha256:{}", "7".repeat(64))
}
fn request(image: &str, image_pull: Option<RegistryCredential>) -> PrepareRequest {
    PrepareRequest {
        size: Size { cpus: 1., memory_bytes: 1 << 30, disk_bytes: 1 << 30 },
        platform: None,
        route: None,
        image_pull,
        image_digest: image.into(),
        tools_digest: tools(),
    }
}

// The first provider's prepare copies the platform manifest it needs, with
// its config and layers, into the staging registry by digest, and its host is
// handed that reference with the registry's pull credential; the tools image
// is left as named. A second provider pulling from the same registry gets the
// same copy without anything being uploaded again.
#[tokio::test]
async fn staged_once_and_reused_by_another_provider() {
    let dir = tempfile::tempdir().unwrap();
    let registries = Registries::default();
    let module = Pulling::default();
    let (image, amd64) = registries.seed(LAB, "crew/base");
    let daemon = start(dir.path(), &registries, &module).await;

    ProviderApi::prepare(&*daemon, "e2b", &request(&image, Some(credential("lab-user", "lab-secret")))).await.unwrap();
    let staged = format!("{STAGED}@{amd64}");
    {
        let s = registries.0.lock().unwrap();
        let (_, manifest) = &s.manifests[&(STAGE.to_owned(), "org/staging".to_owned(), amd64.clone())];
        assert_eq!(manifest, &s.manifests[&(LAB.to_owned(), "crew/base".to_owned(), amd64.clone())].1, "manifest copied verbatim");
        let manifest: Value = serde_json::from_slice(manifest).unwrap();
        for blob in std::iter::once(&manifest["config"]).chain(manifest["layers"].as_array().unwrap()) {
            assert!(s.blobs.contains_key(&(STAGE.to_owned(), blob["digest"].as_str().unwrap().to_owned())));
        }
        // Only the platform the provider runs is staged.
        assert_eq!(s.manifests.keys().filter(|(h, _, _)| h == STAGE).count(), 1);
    }
    let uploads = registries.uploads_to(STAGE);
    assert!(uploads > 0);

    ProviderApi::prepare(&*daemon, "modal", &request(&image, Some(credential("lab-user", "lab-secret")))).await.unwrap();
    assert_eq!(registries.uploads_to(STAGE), uploads, "the second provider reuses the staged copy");

    let seen = module.0.lock().unwrap().clone();
    assert_eq!(seen.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(), ["e2b", "modal"]);
    for (_, request) in seen {
        assert_eq!(request.image_digest, staged);
        assert_eq!(request.image_pull, Some(credential("bot", "pull-token")));
        assert_eq!(request.tools_digest, tools());
    }
    assert_eq!(registries.violations(), Vec::<String>::new());
}

// An image already under any registry the provider pulls from (here, a path
// below its second one) reaches the host as requested, with no registry
// traffic at all.
#[tokio::test]
async fn an_image_in_a_pull_from_registry_passes_through() {
    let dir = tempfile::tempdir().unwrap();
    let registries = Registries::default();
    let module = Pulling::default();
    let daemon = start(dir.path(), &registries, &module).await;
    let image = format!("{MIRROR}/crew@sha256:{}", "1".repeat(64));
    let pull = Some(credential("someone", "their-token"));

    ProviderApi::prepare(&*daemon, "e2b", &request(&image, pull.clone())).await.unwrap();
    let (_, seen) = module.0.lock().unwrap()[0].clone();
    assert_eq!((seen.image_digest, seen.image_pull), (image, pull));
    assert!(registries.0.lock().unwrap().requests.is_empty());
}

// The request's pull credential is used at the source registry only, and the
// staging registry's push credential at the staging registry only.
#[tokio::test]
async fn credentials_stay_with_their_registries() {
    let dir = tempfile::tempdir().unwrap();
    let registries = Registries::default();
    let module = Pulling::default();
    let (image, _) = registries.seed(LAB, "crew/base");
    let daemon = start(dir.path(), &registries, &module).await;

    ProviderApi::prepare(&*daemon, "e2b", &request(&image, Some(credential("lab-user", "lab-secret")))).await.unwrap();
    let signins = registries.0.lock().unwrap().signins.clone();
    assert!(signins.contains(&(LAB.into(), LAB)) && signins.contains(&(STAGE.into(), STAGE)), "{signins:?}");
    assert!(signins.iter().all(|(at, owner)| at == owner), "{signins:?}");
    assert_eq!(registries.violations(), Vec::<String>::new());
}

// A staging registry that refuses the copy (authentication, permission or
// quota) is named by the typed staging refusal, and the provider is never asked.
#[tokio::test]
async fn a_push_refusal_names_the_staging_registry() {
    for status in [401, 403, 413] {
        let dir = tempfile::tempdir().unwrap();
        let registries = Registries::default();
        registries.0.lock().unwrap().refuse_push = Some(status);
        let module = Pulling::default();
        let (image, _) = registries.seed(LAB, "crew/base");
        let daemon = start(dir.path(), &registries, &module).await;

        let error = ProviderApi::prepare(&*daemon, "e2b", &request(&image, Some(credential("lab-user", "lab-secret")))).await.unwrap_err();
        match error {
            drydock::client::Error::Protocol(ProtocolError::ImageRefused {
                refusal: ImageRefusal::StagingRefused { registry },
                reason,
            }) => {
                assert_eq!(registry, "ghcr");
                // The caller learns why from the registry itself.
                assert!(reason.contains(&status.to_string()) && reason.contains("permission_denied: write_package"), "{status}: {reason}");
            }
            other => panic!("{status}: {other:?}"),
        }
        assert!(module.0.lock().unwrap().is_empty());
    }
}

// Concurrent prepares of one image, for two providers, copy it once: each
// blob is uploaded once and the manifest put once.
#[tokio::test]
async fn concurrent_prepares_copy_once() {
    let dir = tempfile::tempdir().unwrap();
    let registries = Registries::default();
    let module = Pulling::default();
    let (image, _) = registries.seed(LAB, "crew/base");
    let daemon = start(dir.path(), &registries, &module).await;

    let request = request(&image, Some(credential("lab-user", "lab-secret")));
    let (first, second) = tokio::join!(ProviderApi::prepare(&*daemon, "e2b", &request), ProviderApi::prepare(&*daemon, "modal", &request));
    assert_eq!(first.unwrap().image_digest, second.unwrap().image_digest);
    let s = registries.0.lock().unwrap();
    let count = |method: &str, path: &str| s.requests.iter().filter(|(h, m, p)| h == STAGE && m == method && p.contains(path)).count();
    // An amd64 image is a config and three layers.
    assert_eq!(count("POST", "/blobs/uploads/"), 4);
    assert_eq!(count("PUT", "/manifests/"), 1);
}

// A layer larger than one upload request is sent in requests the registry
// accepts: by default within GHCR's 4 MiB, otherwise within the staging
// registry's own `chunk_bytes`. A registry that refuses a request as too large
// says why in the staging refusal.
#[tokio::test]
async fn uploads_fit_the_registry_request_limit() {
    for (ghcr, accepted) in [("", true), ("chunk_bytes = 1048576", true), ("chunk_bytes = 8388608", false)] {
        let dir = tempfile::tempdir().unwrap();
        let registries = Registries::default();
        let module = Pulling::default();
        // The first layer is just over two default requests.
        let (image, amd64) = registries.seed_with(LAB, "crew/large", 2 * PATCH_LIMIT + 1);
        let daemon = start_with(dir.path(), &registries, &module, CHUNK_BYTES, ghcr).await;

        let result = ProviderApi::prepare(&*daemon, "e2b", &request(&image, Some(credential("lab-user", "lab-secret")))).await;
        match (accepted, result) {
            (true, Ok(prepared)) => assert_eq!(prepared.image_digest, format!("{STAGED}@{amd64}"), "{ghcr}"),
            (
                false,
                Err(drydock::client::Error::Protocol(ProtocolError::ImageRefused {
                    refusal: ImageRefusal::StagingRefused { registry },
                    reason,
                })),
            ) => {
                assert_eq!(registry, "ghcr");
                assert!(reason.contains("416") && reason.contains("exceeds the maximum permissible limit"), "{reason}");
            }
            (_, other) => panic!("{ghcr}: {other:?}"),
        }
        assert_eq!(registries.violations(), Vec::<String>::new());
    }
}

// A registry message that repeats the push credential, raw or Basic-encoded,
// is left out of the refusal: the reason travels to callers that must never
// see it.
#[tokio::test]
async fn a_refusal_never_repeats_the_push_secret() {
    let dir = tempfile::tempdir().unwrap();
    let registries = Registries::default();
    {
        let mut s = registries.0.lock().unwrap();
        s.refuse_push = Some(403);
    }
    let module = Pulling::default();
    let (image, _) = registries.seed(LAB, "crew/base");
    let daemon = start(dir.path(), &registries, &module).await;

    // The secret as configured, and as the Basic authorization carrying it.
    let basic = basic("bot", "push-token");
    let encoded = basic.trim_start_matches("Basic ");
    for (echo, secret) in
        [("token push-token may not write here".to_owned(), "push-token"), (format!("bad credentials {encoded}"), encoded)]
    {
        registries.0.lock().unwrap().refusal_message = Some(echo);
        let error = ProviderApi::prepare(&*daemon, "e2b", &request(&image, Some(credential("lab-user", "lab-secret")))).await.unwrap_err();
        assert!(matches!(&error, drydock::client::Error::Protocol(ProtocolError::ImageRefused { .. })), "{error:?}");
        assert!(!format!("{error:?}").contains(secret), "{error:?}");
    }
}

/// The provider-push request a provider of `route` is handed, and its source.
fn lab_request(image: &str) -> PrepareRequest {
    request(image, Some(credential("lab-user", "lab-secret")))
}
fn refusal(result: Result<Prepared, drydock::client::Error>) -> ImageRefusal {
    match result {
        Err(drydock::client::Error::Protocol(ProtocolError::ImageRefused { refusal, .. })) => refusal,
        other => panic!("{other:?}"),
    }
}

// Provider-push route (Daytona's): drydockd copies the base alone, for the
// provider's platform, from a private registry the provider cannot reach into
// the provider's own, in requests of the route's chunk size, with the push
// access the provider minted; tags it so the registry keeps it; waits out the
// registry's visibility delay; and hands the module the copy by digest with no
// pull credential. Another prepare, under a bumped tools pin, uploads nothing.
#[tokio::test]
async fn pushed_into_the_providers_own_registry() {
    let dir = tempfile::tempdir().unwrap();
    let registries = Registries::default();
    registries.0.lock().unwrap().visibility_delay = 2;
    let module = Pulling::default();
    let (image, amd64) = registries.seed(LAB, "crew/base");
    let daemon = start(dir.path(), &registries, &module).await;

    let started = std::time::Instant::now();
    let prepared = ProviderApi::prepare(&*daemon, "daytona", &lab_request(&image)).await.unwrap();
    assert!(started.elapsed() >= Duration::from_secs(1), "waited for the registry to serve the copy");
    let copy = format!("{OWN}/{OWN_REPOSITORY}@{amd64}");
    assert_eq!(prepared.image_digest, copy);
    let (_, seen) = module.0.lock().unwrap()[0].clone();
    assert_eq!((seen.image_digest.as_str(), seen.image_pull, seen.route), (copy.as_str(), None, Some(ImageRouteKind::ProviderPush)));
    {
        let s = registries.0.lock().unwrap();
        let own = |reference: &str| s.manifests[&(OWN.to_owned(), OWN_REPOSITORY.to_owned(), reference.to_owned())].1.clone();
        let source = &s.manifests[&(LAB.to_owned(), "crew/base".to_owned(), amd64.clone())].1;
        assert_eq!(&own(&amd64), source, "the base's manifest, verbatim");
        assert_eq!(&own(&amd64.replace(':', "-")), source, "tagged so the registry keeps it");
        let patches: Vec<_> = s.requests.iter().filter(|(h, m, _)| h == OWN && m == "PATCH").collect();
        assert!(patches.len() > 4, "layers go in bounded requests");
        assert!(!s.requests.iter().any(|(h, ..)| h == TOOLS), "the tools image is never read");
        assert!(s.signins.iter().all(|(at, owner)| at == owner), "{:?}", s.signins);
    }
    let uploads = registries.uploads_to(OWN);

    let mut bumped = lab_request(&image);
    bumped.tools_digest = format!("ghcr.io/flotilla-org/drydock-tools@sha256:{}", "8".repeat(64));
    assert_eq!(ProviderApi::prepare(&*daemon, "daytona", &bumped).await.unwrap().image_digest, copy);
    assert_eq!(registries.uploads_to(OWN), uploads, "nothing is put again");
    assert_eq!(module.1.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(registries.violations(), Vec::<String>::new());
}

// A platform the base does not offer and an image over the route's declared
// limit are each the typed refusal before push access is minted; push access
// that expires before the upload completes is the typed expiry. The module is
// never asked to prepare.
#[tokio::test]
async fn push_route_refusals_are_typed() {
    let dir = tempfile::tempdir().unwrap();
    let registries = Registries::default();
    let module = Pulling::default();
    let (image, _) = registries.seed(LAB, "crew/base");
    let daemon = start(dir.path(), &registries, &module).await;

    let arm = Platform::new("linux", "arm64");
    let mut other = lab_request(&image);
    other.platform = Some(arm.clone());
    let declared = refusal(ProviderApi::prepare(&*daemon, "daytona", &other).await);
    assert_eq!(declared, ImageRefusal::UnsupportedPlatform { platform: arm });
    assert!(matches!(
        refusal(ProviderApi::prepare(&*daemon, "small", &lab_request(&image)).await),
        ImageRefusal::TooLarge { bytes, limit_bytes: 1000 } if bytes > 1000
    ));
    assert_eq!(module.1.load(std::sync::atomic::Ordering::SeqCst), 0, "refused before minting push access");
    assert_eq!(refusal(ProviderApi::prepare(&*daemon, "brief", &lab_request(&image)).await), ImageRefusal::PushCredentialExpired);
    assert_eq!(registries.uploads_to(OWN), 0);
    // The provider's registry refusing the copy is its staging refusal, not
    // a rejection of the provider's own credential.
    registries.0.lock().unwrap().refuse_push = Some(403);
    let refused = refusal(ProviderApi::prepare(&*daemon, "daytona", &lab_request(&image)).await);
    assert_eq!(refused, ImageRefusal::StagingRefused { registry: "daytona".into() });
    assert!(module.0.lock().unwrap().is_empty());
}

// A source blob is copied only when it can be verified inside bounded
// requests: a registry that ignores Range for a blob larger than one request,
// and a blob whose bytes do not match its digest, are each refused before the
// upload commits, so the provider's registry never holds the layer.
#[tokio::test]
async fn unverifiable_source_blobs_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let registries = Registries::default();
    let module = Pulling::default();
    let (image, amd64) = registries.seed(LAB, "crew/base");
    let layer = {
        let s = registries.0.lock().unwrap();
        let manifest: Value = serde_json::from_slice(&s.manifests[&(LAB.to_owned(), "crew/base".to_owned(), amd64)].1).unwrap();
        manifest["layers"][0]["digest"].as_str().unwrap().to_owned()
    };
    let daemon = start(dir.path(), &registries, &module).await;
    let refused_unstored = |result: Result<Prepared, drydock::client::Error>| {
        assert!(matches!(result, Err(drydock::client::Error::Protocol(ProtocolError::Internal { .. }))), "{result:?}");
        assert!(!registries.0.lock().unwrap().blobs.contains_key(&(OWN.to_owned(), layer.clone())));
    };
    registries.0.lock().unwrap().ignore_range = true;
    refused_unstored(ProviderApi::prepare(&*daemon, "daytona", &lab_request(&image)).await);
    {
        let mut s = registries.0.lock().unwrap();
        s.ignore_range = false;
        let stored = s.blobs.get_mut(&(LAB.to_owned(), layer.clone())).unwrap();
        let mut corrupt = stored.to_vec();
        corrupt[0] ^= 1;
        *stored = Bytes::from(corrupt);
    }
    refused_unstored(ProviderApi::prepare(&*daemon, "daytona", &lab_request(&image)).await);
    assert!(module.0.lock().unwrap().is_empty());
}

// A copy whose retention tag failed to go in (the manifest put, then the tag
// refused) gets its tag on the next prepare, which finds the copy already
// there: the registry never holds it untagged for long.
#[tokio::test]
async fn a_lost_retention_tag_is_put_again() {
    let dir = tempfile::tempdir().unwrap();
    let registries = Registries::default();
    registries.0.lock().unwrap().refuse_tag_once = true;
    let module = Pulling::default();
    let (image, amd64) = registries.seed(LAB, "crew/base");
    let daemon = start(dir.path(), &registries, &module).await;
    let tagged =
        || registries.0.lock().unwrap().manifests.contains_key(&(OWN.to_owned(), OWN_REPOSITORY.to_owned(), amd64.replace(':', "-")));

    assert!(ProviderApi::prepare(&*daemon, "daytona", &lab_request(&image)).await.is_err());
    assert!(!tagged());
    ProviderApi::prepare(&*daemon, "daytona", &lab_request(&image)).await.unwrap();
    assert!(tagged());
    assert_eq!(registries.violations(), Vec::<String>::new());
}

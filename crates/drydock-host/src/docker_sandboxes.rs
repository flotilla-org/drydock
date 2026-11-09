//! Docker Cloud Sandboxes translator: each verb is Docker's own operation, and
//! each answer is what Docker said. Waiting, idempotence and ownership are
//! drydockd's, as the declared [`Semantics`] leave them (see `capabilities`).
//! Commands and files go to each sandbox's own endpoint with a short-lived
//! credential the management API issues; drydock reaches the agent through a
//! process running `drydock-agent --bridge`, over Docker's interact WebSocket.
//! API contract: https://docs.docker.com/reference/api/sandboxes/api.yaml
use crate::{
    kit::{
        self, LABEL_TAG, MIB, StateTable, Vendor,
        api::{Api, Auth, Body, EXPLANATION_CHARS, Failure, MAX_PAGES, Text, cut, operation},
        guest::GuestOutput,
        image::{check_prepare, check_prepared},
    },
    module::*,
};
use async_trait::async_trait;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use drydock_protocol::*;
use drydock_transport::websocket::{
    DialError, TlsDialer, WebSocket, WebSocketDialer,
    tungstenite::{
        Message,
        http::{HeaderMap, HeaderValue, header},
    },
};
use futures::{SinkExt, StreamExt};
use reqwest::Method;
use serde::{Deserialize, de::IgnoredAny};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const DOCKER: Vendor = Vendor("Docker Sandboxes");
const DOCKER_HUB: Vendor = Vendor("Docker Hub");
const AGENT: &str = "/opt/drydock/drydock-agent";
const SUBPROTOCOL: &str = "sandboxes.v1";
/// The most stdin bytes one interact frame carries.
const STDIN_FRAME: usize = 32 << 10;
/// How long before an exchanged access token expires a new one is asked for.
const RENEW_MARGIN: Duration = Duration::from_secs(60);

/// Docker does not say who stopped a sandbox; a failed one carries its error
/// beside the state, and a degraded one is Docker's own word that it has lost
/// contact with it.
const STATES: StateTable = &[
    ("creating", Observation::Transitioning { phase: TransitionPhase::Preparing }),
    ("starting", kit::starting()),
    ("running", Observation::Running),
    ("stopping", kit::stopping()),
    ("stopped", Observation::Stopped { cause: None }),
    ("deleting", Observation::Transitioning { phase: TransitionPhase::Destroying }),
    ("failed", Observation::Unknown { reason: UnknownReason::ProviderApiError }),
    ("degraded", Observation::Unknown { reason: UnknownReason::ProviderStateUnknown }),
];

// Docker's wire types (see the API contract above), only the fields read.
// Docker answers in protobuf's JSON form, which leaves out empty lists and
// zero numbers.
#[derive(Deserialize)]
struct Sandbox {
    uid: Text,
    core: Core,
    failure: Option<ErrorBody>,
}
#[derive(Deserialize)]
struct Core {
    status: Text,
    etag: Text,
    platform: Option<WirePlatform>,
    labels: Option<BTreeMap<String, String>>,
    endpoint: Option<Endpoint>,
}
#[derive(Deserialize)]
struct WirePlatform {
    os: Option<String>,
    architecture: Option<String>,
}
#[derive(Deserialize)]
struct Endpoint {
    uri: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    #[serde(default)]
    sandboxes: Vec<Sandbox>,
    next_page_token: Option<String>,
}
/// One sandbox's network policy as Docker installed it.
#[derive(Deserialize)]
struct Policies {
    effective: Effective,
    exact: Exact,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Effective {
    mode: Text,
    #[serde(default)]
    allow_networks: Vec<Rule>,
}
/// An allowed network, and the policy layer that allowed it.
#[derive(Deserialize)]
struct Rule {
    layer: Option<String>,
}
#[derive(Deserialize)]
struct Exact {
    revision: Text,
    #[serde(default)]
    nodes: Vec<Node>,
}
#[derive(Deserialize)]
struct Node {
    source: Option<Source>,
}
#[derive(Deserialize)]
struct Source {
    origin: String,
}
#[derive(Deserialize)]
struct Issued {
    token: Text,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Executed {
    exit_code: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
    #[serde(default)]
    incomplete: bool,
}
#[derive(Deserialize)]
struct Process {
    name: Text,
}
/// One server frame on an interact stream: output, its end, a heartbeat, or
/// the error that ends it.
#[derive(Deserialize)]
struct Output {
    chunk: Option<Chunk>,
    exited: Option<IgnoredAny>,
    code: Option<IgnoredAny>,
}
#[derive(Deserialize)]
struct Chunk {
    stream: Option<String>,
    data: Option<String>,
}
#[derive(Deserialize, Default)]
struct ErrorBody {
    #[serde(default)]
    code: String,
    message: Option<String>,
    #[serde(default)]
    details: Vec<Detail>,
}
#[derive(Deserialize)]
struct Detail {
    #[serde(rename = "@type", default)]
    kind: String,
    #[serde(rename = "retryDelay")]
    retry_delay: Option<String>,
}
/// A personal access token and its owner, which Docker Hub exchanges for an
/// access token.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pat {
    username: String,
    personal_access_token: String,
}
#[derive(Deserialize)]
struct Exchanged {
    access_token: Text,
}
#[derive(Deserialize)]
struct Claims {
    exp: Option<u64>,
}

pub struct DockerSandboxesModule {
    dialer: Arc<dyn WebSocketDialer>,
}
impl DockerSandboxesModule {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self::with_dialer(Arc::new(TlsDialer::new()?)))
    }
    pub fn with_dialer(dialer: Arc<dyn WebSocketDialer>) -> Self {
        Self { dialer }
    }
}

/// Every key has a default.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Settings {
    api_url: String,
    /// Where Docker Hub exchanges a personal access token for an access token.
    token_exchange_url: String,
    /// How often drydockd lists sandboxes.
    poll_seconds: u64,
    /// How long one command may run: Docker answers an exec once it ends.
    exec_seconds: u64,
    /// How long one file upload may take.
    upload_seconds: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            api_url: "https://connect.docker.com/sandboxes".into(),
            token_exchange_url: "https://hub.docker.com/v2/auth/token".into(),
            poll_seconds: 30,
            exec_seconds: 60,
            upload_seconds: 300,
        }
    }
}

#[async_trait]
impl Module for DockerSandboxesModule {
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn smallest_size(&self) -> Size {
        let (_, cpus, mib) = SHAPES[0];
        Size { cpus: cpus as f64, memory_bytes: mib * MIB, disk_bytes: 0 }
    }
    async fn configure(&self, name: &str, config: &ProviderConfiguration, http: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
        let settings: Settings =
            serde_json::from_value(json!(config.settings)).map_err(|e| refused(format!("invalid Docker Sandboxes settings: {e}")))?;
        if [settings.poll_seconds, settings.exec_seconds, settings.upload_seconds].contains(&0) {
            return Err(refused("Docker Sandboxes' poll, exec and upload settings must be positive"));
        }
        let api = Api::new(DOCKER, &settings.api_url, Auth::Bearer, http.clone())?.classify(classify);
        let hub = Api::new(DOCKER_HUB, &settings.token_exchange_url, Auth::Bearer, http)?.classify(|f| match f.status {
            401 | 403 => ProtocolError::CredentialRejected { reason: f.reason(&f.message()) },
            _ => f.standard(f.reason(&f.message())),
        });
        Ok(Arc::new(DockerSandboxes {
            name: name.to_owned(),
            ownership: config.ownership,
            settings,
            api,
            hub,
            dialer: self.dialer.clone(),
            held: Mutex::default(),
        }))
    }
}

pub struct DockerSandboxes {
    name: String,
    ownership: Ownership,
    settings: Settings,
    api: Api,
    hub: Api,
    dialer: Arc<dyn WebSocketDialer>,
    /// The access token last exchanged, for the credential it came from.
    held: Mutex<Option<Held>>,
}
struct Held {
    credential: String,
    token: Secret,
    renew_at: SystemTime,
}

/// Docker's errors carry a stable code, and Google's typed details: a quota
/// failure, and when to retry: https://docs.docker.com/reference/api/sandboxes/api.yaml#/components/schemas/Error
fn classify(f: &Failure) -> ProtocolError {
    let error = serde_json::from_slice::<ErrorBody>(f.body).unwrap_or_default();
    let message = error.message.map_or_else(|| f.message(), |message| cut(&message, EXPLANATION_CHARS));
    let reason = f.reason(&if error.code.is_empty() { message } else { format!("{}: {message}", error.code) });
    let retry_after = f.retry_after.or_else(|| error.details.iter().find_map(|d| d.retry_delay.as_deref().and_then(seconds)));
    match f.status {
        _ if error.details.iter().any(|d| d.kind == "type.googleapis.com/google.rpc.QuotaFailure") => {
            ProtocolError::QuotaExhausted { reason }
        }
        // The sandbox changed between the read that gave its etag and the change.
        412 => ProtocolError::Unavailable { reason, retry_after, provider_error: None },
        _ => Failure { retry_after, ..*f }.standard(reason),
    }
}
/// A protobuf duration (`1.5s`) in whole seconds, rounded up.
fn seconds(duration: &str) -> Option<u64> {
    let seconds: f64 = duration.strip_suffix('s')?.parse().ok()?;
    (seconds.is_finite() && seconds >= 0.0).then(|| seconds.ceil() as u64)
}
/// Docker's spec lists no platforms; create asks for this one, and Docker
/// refuses what it cannot place.
fn platform() -> Platform {
    Platform::new("linux", "amd64")
}
/// When a JWT says it expires, if it does.
fn expiry(token: &str) -> Option<SystemTime> {
    let payload = URL_SAFE_NO_PAD.decode(token.split('.').nth(1)?).ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(serde_json::from_slice::<Claims>(&payload).ok()?.exp?))
}

impl DockerSandboxes {
    /// The bearer for management calls: the access token Docker Hub exchanges
    /// the personal access token and its owner for, held until shortly before
    /// it expires.
    async fn access(&self, c: &Credentials) -> Result<Credentials> {
        let rejected = || ProtocolError::CredentialRejected {
            reason: r#"a Docker Sandboxes credential is {"username": …, "personal_access_token": …}"#.into(),
        };
        let credential = c.token().ok_or_else(rejected)?;
        let pat: Pat = serde_json::from_str(credential.expose()).map_err(|_| rejected())?;
        let digest = kit::digest(credential.expose());
        let held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(|held| (held.credential == digest && SystemTime::now() < held.renew_at).then(|| held.token.clone()));
        if let Some(token) = held {
            return Ok(Credentials::new(Some(token)));
        }
        let body = json!({"identifier": pat.username, "secret": pat.personal_access_token});
        let url = self.hub.url(&[])?;
        let operation = operation(&Method::POST, &url);
        let response = self.hub.send(Method::POST, url, Body::json(&body)?, c, false, &[]).await?;
        let exchanged: Exchanged = self.hub.answer(&operation, &response)?;
        let token = Secret::new(String::from(exchanged.access_token));
        if let Some(expires) = expiry(token.expose()) {
            let renew_at = expires.checked_sub(RENEW_MARGIN).unwrap_or(UNIX_EPOCH);
            let fresh = Held { credential: digest, token: token.clone(), renew_at };
            *self.held.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(fresh);
        }
        Ok(Credentials::new(Some(token)))
    }
    fn sandbox_url(&self, id: &str, rest: &[&str]) -> Result<reqwest::Url> {
        if id.is_empty() || id == "." || id == ".." {
            return Err(ProtocolError::NotFound { reason: "not a Docker Sandboxes sandbox id".into() });
        }
        self.api.url(&[&["v1", "sandboxes", id][..], rest].concat())
    }
    async fn sandbox(&self, id: &str, c: &Credentials) -> Result<Sandbox> {
        self.api.get(self.sandbox_url(id, &[])?, c).await
    }
    /// A change of an existing sandbox, which Docker takes only with the etag
    /// of its last read.
    async fn change(&self, id: &str, method: Method, rest: &[&str], c: &Credentials) -> Result<()> {
        let etag = self.sandbox(id, c).await?.core.etag;
        let precondition = [(header::IF_MATCH, HeaderValue::from_str(&etag).map_err(|_| DOCKER.bad_response())?)];
        self.api.call_with::<IgnoredAny>(method, self.sandbox_url(id, rest)?, Body::None, c, &precondition).await.map(drop)
    }
    /// The sandbox's endpoint, and a credential for it carrying `permissions`.
    async fn endpoint(&self, id: &str, permissions: &[&str], c: &Credentials) -> Result<(Api, Credentials)> {
        let sandbox = self.sandbox(id, c).await?;
        let Some(uri) = sandbox.core.endpoint.and_then(|e| e.uri) else {
            let reason = format!("Docker Sandboxes states no endpoint for sandbox {id} while it is {}", &*sandbox.core.status);
            return Err(ProtocolError::unavailable(reason, None));
        };
        let endpoint = Api::new(DOCKER, &uri, Auth::Bearer, self.api.http().clone())?.classify(classify);
        let body = json!({"permissions": permissions});
        let issued: Issued = self.api.call(Method::POST, self.sandbox_url(id, &["endpoint-credentials"])?, Body::json(&body)?, c).await?;
        Ok((endpoint, Credentials::new(Some(Secret::new(String::from(issued.token))))))
    }
    /// A row as Docker gives it. No row carries the network policy, so its
    /// egress is advisory and its policy unstated; inspect reads both.
    fn environment(&self, v: Sandbox) -> Environment {
        let core = v.core;
        Environment {
            id: v.uid.into(),
            provider: self.name.clone(),
            label: core.labels.as_ref().and_then(|l| l.get(LABEL_TAG)).cloned(),
            state: kit::observe(STATES, &core.status),
            // Docker states CPUs and memory but no disk, and a size has all three.
            granted_size: None,
            egress: Enforcement::Advisory,
            platform: core.platform.and_then(|p| Some(Platform::new(p.os?, p.architecture?))),
            egress_measured: false,
            egress_policy: None,
            // Docker states when a sandbox was made, not when it reached its state.
            timestamp: None,
            vendor: Some(VendorState {
                state: core.status.into(),
                reason: v.failure.and_then(|f| f.message.or(Some(f.code)).filter(|r| !r.is_empty())),
                tags: core.labels,
            }),
        }
    }
    /// One command, its argv as given, run as root to its end.
    async fn run(&self, id: &str, argv: &[String], c: &Credentials) -> Result<GuestOutput> {
        let c = &self.access(c).await?;
        let (endpoint, scoped) = self.endpoint(id, &["sandboxesExec"], c).await?;
        let body = json!({"cmd": argv, "user": "root"});
        let url = endpoint.url(&["v1", "processes", "exec"])?;
        let deadline = Duration::from_secs(self.settings.exec_seconds);
        let v: Executed = endpoint.call_within(Method::POST, url, Body::json(&body)?, &scoped, deadline).await?;
        let bytes = |text: Option<String>| STANDARD.decode(text.unwrap_or_default()).map_err(|_| DOCKER.bad_response());
        let chunks = [(false, bytes(v.stdout)?), (true, bytes(v.stderr)?)].into_iter().filter(|(_, b)| !b.is_empty()).collect();
        let note = v.incomplete.then(|| "Docker Sandboxes kept only part of the command's output".to_owned());
        // A zero exit status is left out, as protobuf leaves out every zero.
        Ok(GuestOutput { chunks, exit: Some(v.exit_code.unwrap_or(0)), timed_out: false, note })
    }
}

/// Docker's sandbox shapes: a name, whole vCPUs and MiB of memory. Docker
/// takes no disk size.
const SHAPES: &[(&str, u64, u64)] = &[("Micro", 1, 2048), ("Small", 2, 4096), ("Medium", 4, 8192), ("Large", 8, 16384), ("XL", 16, 32768)];

/// The size as Docker's resources, when it is one of Docker's shapes.
fn resources(size: &Size) -> Result<Value> {
    let shape = SHAPES.iter().find(|(_, cpus, mib)| size.cpus == *cpus as f64 && size.memory_bytes == mib * MIB && size.disk_bytes == 0);
    let Some((_, cpus, mib)) = shape else {
        let shapes: Vec<_> = SHAPES.iter().map(|(name, cpus, mib)| format!("{name} ({cpus} CPU / {mib} MiB)")).collect();
        return Err(refused(format!("Docker Sandboxes' supported shapes are {}, with a disk of 0", shapes.join(", "))));
    };
    Ok(json!({"cpus": cpus, "memoryMib": mib}))
}
/// Docker's create takes a sandbox's own policy document, but installs it
/// beside the account's default layer, which allows every network: a live
/// deny-all document left the sandbox open. Its spec states no way to narrow
/// egress below that default, so only an open request is taken.
fn check_egress(request: &EgressRequest) -> Result<()> {
    match request {
        EgressRequest::Open => Ok(()),
        EgressRequest::DenyAll { .. } => Err(refused(
            "Docker Sandboxes installs a sandbox's own network policy beside the account's default layer, which allows every \
             network, so it cannot deny egress: ask for open egress",
        )),
    }
}

fn egress_model() -> EgressModel {
    EgressModel {
        side_effects: vec![EgressSideEffect {
            shapes: vec![EgressShape::Open],
            opens: vec![],
            note: "Docker's default policy layer allows every network.".into(),
        }],
        sources: vec![
            "https://docs.docker.com/reference/api/sandboxes/api.yaml#/components/schemas/NetworkPolicy".into(),
            "https://docs.docker.com/reference/api/sandboxes/api.yaml#/components/schemas/PolicyLayer".into(),
        ],
        ..EgressModel::unfiltered()
    }
}

#[async_trait]
impl Provider for DockerSandboxes {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            material_modes: vec![MaterialMode::Frozen],
            checkout_strategies: vec![CheckoutStrategy::CloneInVessel],
            workspace_root: "/workspace".into(),
            suspend_resume: true,
            // Docker's stop hibernates a sandbox whose backend preserves memory,
            // and its sandboxes have resumed with their processes running.
            suspend_preserves_memory: Some(true),
            export: false,
            egress: EgressCapability { routes: vec![EgressRoute::ExplicitProxy, EgressRoute::Open], model: egress_model() },
            fallback_runner: true,
            bootstrap: BootstrapRoute::Upload,
            agent: true,
            agent_tcp_port: None,
            platforms: vec![platform()],
            // Docker pulls a public image by digest; its API takes no
            // credential for a private registry.
            image_routes: vec![ImageRoute::RegistryPull {
                auth: RegistryAuthKind::Anonymous,
                registration: CredentialRegistration::NotRequired,
                digest_references: true,
                tools_layer: ToolsLayer::Upload,
            }],
            usage: false,
            quota: false,
            host_filesystem: false,
            host_processes: false,
            exclusive_label: false,
            reach_ways: vec![ReachWay::OutwardExposure],
            // Create, stop and start answer once Docker accepts them; a repeated
            // one is Docker's to answer; list and delete reach the whole
            // account; and Docker starts a sandbox by id alone.
            semantics: Semantics { token_is_id: true, ..Semantics::default() },
        }
    }
    fn ways_in(&self) -> Vec<WayIn> {
        vec![WayIn::Poll { interval_ms: self.settings.poll_seconds.saturating_mul(1000) }]
    }
    fn operations(&self) -> Operations<'_> {
        Operations { exec: Some(self), files: Some(self), suspend_resume: Some(self), ..Operations::default() }
    }
    /// Nothing is made at Docker: a sandbox runs the image by its digest.
    async fn prepare(&self, r: PrepareRequest, _: &Credentials) -> Result<Prepared> {
        let (_, platform) = check_prepare(DOCKER, &r, &[ImageRouteKind::RegistryPull], &platform())?;
        if r.image_pull.is_some() {
            return Err(refused("Docker Sandboxes pulls public images only: its API takes no registry credential"));
        }
        Ok(Prepared {
            provider: self.name.clone(),
            id: r.image_digest.clone(),
            platform,
            image_digest: r.image_digest,
            tools_digest: r.tools_digest,
        })
    }
    /// One create, answered with Docker's row. The owner tag goes on only on a
    /// shared account; no policy goes on, since only open egress is taken.
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        check_prepared(DOCKER, &self.name, &r.prepared, &r.prepared.image_digest)?;
        check_egress(&r.egress)?;
        let mut labels = BTreeMap::from([(LABEL_TAG, r.label.as_str())]);
        if self.ownership == Ownership::SharedAccount {
            labels.insert(OWNER_TAG, &self.name);
        }
        let body = json!({
            "imageRef": r.prepared.image_digest,
            "platform": {"os": r.prepared.platform.os, "architecture": r.prepared.platform.architecture},
            "resources": resources(&r.size)?,
            "labels": labels,
        });
        let c = &self.access(c).await?;
        let created: Sandbox = self.api.call(Method::POST, self.api.url(&["v1", "sandboxes"])?, Body::json(&body)?, c).await?;
        Ok(Provisioned::Created(self.environment(created)))
    }
    /// Every sandbox the credential's owner has, every page: Docker filters by
    /// no label, so drydockd applies ownership to the tags.
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        let c = &self.access(c).await?;
        let (mut rows, mut cursor, mut seen) = (Vec::new(), None::<String>, BTreeSet::new());
        loop {
            let mut url = self.api.url(&["v1", "sandboxes"])?;
            if let Some(cursor) = &cursor {
                url.query_pairs_mut().append_pair("pageToken", cursor);
            }
            let page: Page = self.api.get(url, c).await?;
            rows.extend(page.sandboxes.into_iter().map(|v| self.environment(v)));
            match page.next_page_token.filter(|t| !t.is_empty()) {
                None => return Ok(rows),
                Some(next) if seen.len() + 1 < MAX_PAGES && seen.insert(next.clone()) => cursor = Some(next),
                Some(_) => return Err(DOCKER.bad_response()),
            }
        }
    }
    /// The sandbox and, while it runs, its installed network policy. Egress is
    /// enforced when Docker states a deny-all policy that holds the sandbox's
    /// own (`attached`) document and allows nothing that document did not: a
    /// deny-all mode alone has been seen beside a default layer allowing every
    /// network. Docker states a policy only for a running sandbox; in any other
    /// state egress is not stated.
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        let c = &self.access(c).await?;
        let sandbox = self.sandbox(id, c).await?;
        let running = &*sandbox.core.status == "running";
        let mut environment = self.environment(sandbox);
        if !running {
            return Ok(environment);
        }
        let policies: Policies = self.api.get(self.sandbox_url(id, &["network-policies"])?, c).await?;
        let own = policies.exact.nodes.iter().any(|n| n.source.as_ref().is_some_and(|s| s.origin == "attached"));
        let only_own = policies.effective.allow_networks.iter().all(|rule| rule.layer.as_deref() == Some("attached"));
        if &*policies.effective.mode == "denyAll" && own && only_own {
            environment.egress = Enforcement::Enforced;
        }
        environment.egress_policy = Some(policies.exact.revision.into());
        Ok(environment)
    }
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        self.change(id, Method::DELETE, &[], &self.access(c).await?).await
    }
    async fn reach(&self, id: &str, _: &Credentials) -> Result<Reach> {
        Ok(Reach::relay(&self.name, id))
    }
    /// A process running the agent's bridge, its stdin and stdout carried over
    /// Docker's interact WebSocket. A sandbox that isn't running fails with
    /// Docker's answer.
    async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream> {
        let c = &self.access(c).await?;
        let (endpoint, scoped) = self.endpoint(id, &["sandboxesExec"], c).await?;
        let body = json!({"cmd": [AGENT, "--bridge"], "user": "root"});
        let process: Process = endpoint.call(Method::POST, endpoint.url(&["v1", "processes"])?, Body::json(&body)?, &scoped).await?;
        let pid = process.name.strip_prefix("processes/").filter(|p| !p.is_empty()).ok_or_else(|| DOCKER.bad_response())?;
        match self.attach(&endpoint, &scoped, &process.name, pid).await {
            Ok(socket) => {
                let (near, far) = tokio::io::duplex(1 << 16);
                tokio::spawn(interact(socket, far));
                Ok(Box::new(near))
            }
            Err(error) => {
                // The bridge would wait on stdin for good: end it, as far as Docker lets.
                let url = endpoint.url(&["v1", "processes", pid, "signal"])?;
                let kill = Body::json(&json!({"signal": "kill"}))?;
                if let Err(failed) = endpoint.call::<IgnoredAny>(Method::POST, url, kill, &scoped).await {
                    tracing::debug!(error = failed.class(), "the bridge of a failed relay was not ended");
                }
                Err(error)
            }
        }
    }
}

impl DockerSandboxes {
    /// The interact WebSocket to process `name`, attached from its first output.
    async fn attach(&self, endpoint: &Api, scoped: &Credentials, name: &str, pid: &str) -> Result<WebSocket> {
        let mut url = endpoint.url(&["v1", "processes", pid, "interact"])?;
        url.set_scheme("wss").map_err(|_| DOCKER.bad_response())?;
        let headers = HeaderMap::from_iter([
            (header::AUTHORIZATION, endpoint.key(scoped)?),
            (header::SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_static(SUBPROTOCOL)),
        ]);
        let mut socket = self.dialer.dial(url.as_str(), headers).await.map_err(|error| match error {
            DialError::Refused { status, body } => {
                classify(&Failure { vendor: DOCKER, operation: "interact", status, body: body.as_bytes(), retry_after: None })
            }
            DialError::Io(error) => ProtocolError::Unavailable {
                reason: "Docker Sandboxes interact transport failed".into(),
                retry_after: None,
                provider_error: Some(error.to_string()),
            },
        })?;
        let attach = json!({"attach": {"name": name, "resumeFrom": 0}});
        socket.send(Message::text(attach.to_string())).await.map_err(|error| ProtocolError::Unavailable {
            reason: "Docker Sandboxes interact attach failed".into(),
            retry_after: None,
            provider_error: Some(error.to_string()),
        })?;
        Ok(socket)
    }
}

/// Carries `local`'s bytes to the process's stdin, closing it at their end,
/// and its stdout back, until the process exits, Docker ends the stream, or
/// either side fails.
async fn interact(socket: WebSocket, local: DuplexStream) {
    let (mut frames_out, mut frames_in) = socket.split();
    let (mut reader, mut writer) = tokio::io::split(local);
    let input = async {
        let mut buffer = vec![0; STDIN_FRAME];
        loop {
            // Reading the local end of a duplex does not fail; if it did, its
            // end would be stdin's end all the same.
            let read = reader.read(&mut buffer).await.unwrap_or(0);
            let frame = if read == 0 { json!({"closeStdin": true}) } else { json!({"stdin": STANDARD.encode(&buffer[..read])}) };
            if frames_out.send(Message::text(frame.to_string())).await.is_err() || read == 0 {
                break;
            }
        }
        std::future::pending::<()>().await
    };
    let output = async {
        while let Some(Ok(message)) = frames_in.next().await {
            let text = match message {
                Message::Text(text) => text,
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Close(_) => break,
                _ => {
                    tracing::debug!("Docker Sandboxes interact sent a frame that is not text; the relay ends");
                    break;
                }
            };
            let Ok(frame) = serde_json::from_str::<Output>(text.as_str()) else {
                tracing::debug!("Docker Sandboxes interact sent a frame that is not its output; the relay ends");
                break;
            };
            if frame.code.is_some() {
                tracing::debug!("Docker Sandboxes interact ended with an error frame");
            }
            if frame.exited.is_some() || frame.code.is_some() {
                break;
            }
            let Some(chunk) = frame.chunk.filter(|c| c.stream.as_deref() == Some("stdout")) else { continue };
            let Ok(bytes) = STANDARD.decode(chunk.data.unwrap_or_default()) else {
                tracing::debug!("Docker Sandboxes interact sent output that is not base64; the relay ends");
                break;
            };
            if writer.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    };
    tokio::select! {
        () = input => {}
        () = output => {}
    }
}

/// Stop and start. Docker starts a sandbox by id alone, so the token is the id.
#[async_trait]
impl SuspendResume for DockerSandboxes {
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        self.change(id, Method::POST, &["stop"], &self.access(c).await?).await?;
        Ok(ResumeToken { token: Secret::new(id) })
    }
    async fn resume(&self, id: &str, _: ResumeToken, c: &Credentials) -> Result<()> {
        self.change(id, Method::POST, &["start"], &self.access(c).await?).await
    }
}

#[async_trait]
impl Exec for DockerSandboxes {
    async fn exec(&self, id: &str, r: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        Ok(self.run(id, &r.command, c).await?.success(DOCKER)?.into_stream())
    }
}

/// The file's directory first, since a write makes no parents.
#[async_trait]
impl GuestFiles for DockerSandboxes {
    async fn put(&self, id: &str, file: GuestFile, bytes: Bytes, c: &Credentials) -> Result<()> {
        let parent = std::path::Path::new(&file.path).parent().and_then(|p| p.to_str()).filter(|p| !p.is_empty());
        let parent = parent.ok_or_else(|| refused(format!("{} names no file", file.path)))?;
        let c = &self.access(c).await?;
        let (endpoint, scoped) = self.endpoint(id, &["sandboxesFilesWrite"], c).await?;
        let directory = Body::json(&json!({"path": parent, "parents": true}))?;
        endpoint.call::<IgnoredAny>(Method::PUT, endpoint.url(&["v1", "files", "directories"])?, directory, &scoped).await?;
        let mut url = endpoint.url(&["v1", "files", "content"])?;
        // The mode is an integer of permission bits, as JSON numbers are: 0o755 goes as 493.
        url.query_pairs_mut().append_pair("path", &file.path).append_pair("mode", &file.mode.to_string());
        let deadline = Duration::from_secs(self.settings.upload_seconds);
        let content = Body::Bytes(bytes, "application/octet-stream");
        endpoint.call_within::<IgnoredAny>(Method::PUT, url, content, &scoped, deadline).await.map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use drydock_transport::{
        Listener,
        websocket::{
            tokio_tungstenite::accept_hdr_async,
            tungstenite::handshake::server::{ErrorResponse, Request, Response},
        },
    };
    use rigging_http_client::ChannelLabel;

    /// One request as sent: `METHOD host/path?query`, its bearer, its
    /// precondition and its body.
    struct Asked {
        line: String,
        bearer: Option<String>,
        if_match: Option<String>,
        body: Vec<u8>,
    }
    impl Asked {
        fn json(&self) -> Value {
            serde_json::from_slice(&self.body).unwrap_or_default()
        }
    }
    /// Answers each request with the next scripted (status, body). With an
    /// access token, Docker Hub's exchanges are answered with it and not
    /// recorded.
    #[derive(Default)]
    struct Script {
        answers: Mutex<Vec<(u16, String)>>,
        asked: Mutex<Vec<Asked>>,
        access_token: Option<&'static str>,
    }
    #[async_trait]
    impl HttpClient for Script {
        async fn execute(&self, request: reqwest::Request, _: &ChannelLabel) -> std::result::Result<http::Response<Bytes>, String> {
            let url = request.url();
            if let Some(token) = self.access_token.filter(|_| url.host_str() == Some("hub.docker.com")) {
                return Ok(http::Response::new(Bytes::from(format!(r#"{{"access_token":"{token}"}}"#))));
            }
            let query = url.query().map(|q| format!("?{q}")).unwrap_or_default();
            let header = |name| request.headers().get(name).map(|v: &HeaderValue| v.to_str().unwrap().to_owned());
            self.asked.lock().unwrap().push(Asked {
                line: format!("{} {}{}{query}", request.method(), url.host_str().unwrap(), url.path()),
                bearer: header(header::AUTHORIZATION),
                if_match: header(header::IF_MATCH),
                body: request.body().and_then(|b| b.as_bytes()).unwrap_or_default().to_vec(),
            });
            let (status, body) = {
                let mut answers = self.answers.lock().unwrap();
                assert!(!answers.is_empty(), "unscripted request {} {}", request.method(), request.url());
                answers.remove(0)
            };
            Ok(http::Response::builder().status(status).body(Bytes::from(body)).unwrap())
        }
    }
    impl Script {
        fn lines(&self) -> Vec<String> {
            self.asked.lock().unwrap().iter().map(|a| a.line.clone()).collect()
        }
    }
    async fn configure(
        ownership: Ownership,
        settings: Value,
        script: Arc<Script>,
        dialer: Arc<dyn WebSocketDialer>,
    ) -> Result<Arc<dyn Provider>> {
        let settings = serde_json::from_value(settings).unwrap();
        let config = ProviderConfiguration { module: "docker_sandboxes".into(), settings, ownership, ..Default::default() };
        DockerSandboxesModule::with_dialer(dialer).configure("ds", &config, script).await
    }
    /// A script whose Docker Hub exchanges answer the access token `k`.
    fn script(answers: &[(u16, &str)]) -> Arc<Script> {
        let answers = answers.iter().map(|(status, body)| (*status, (*body).to_owned())).collect();
        Arc::new(Script { answers: Mutex::new(answers), access_token: Some("k"), ..Script::default() })
    }
    async fn docker(ownership: Ownership, answers: Vec<(u16, &str)>) -> (Arc<dyn Provider>, Arc<Script>) {
        let script = script(&answers);
        (configure(ownership, json!({}), script.clone(), Arc::new(drydock_transport::memory().0)).await.unwrap(), script)
    }
    fn pat(username: &str) -> Credentials {
        Credentials::new(Some(Secret::new(format!(r#"{{"username":"{username}","personal_access_token":"dckr_pat_x"}}"#))))
    }
    fn key() -> Credentials {
        pat("u")
    }
    const ID: &str = "sb1";
    const API: &str = "connect.docker.com/sandboxes/v1";
    const ENDPOINT: &str = "sb1.endpoint.example/sb/v1";
    const RUNNING: &str = r#"{"name":"sandboxes/sb1","uid":"sb1","core":{"status":"running","etag":"\"v1\"",
        "createdAt":"2026-11-09T00:00:00Z","platform":{"os":"linux","architecture":"amd64"},
        "labels":{"flotilla.label":"crew-1","drydock.provider":"ds"},
        "endpoint":{"uri":"https://sb1.endpoint.example/sb","sandbox":"sandboxes/sb1"}}}"#;
    const CREATING: &str =
        r#"{"name":"sandboxes/sb1","uid":"sb1","core":{"status":"creating","etag":"\"v0\"","createdAt":"2026-11-09T00:00:00Z"}}"#;
    const ISSUED: &str = r#"{"token":"scoped","expireTime":"2026-11-09T00:05:00Z","permissions":["sandboxesExec"],
        "sandbox":"sandboxes/sb1","audience":"a"}"#;
    const DIGEST: &str = "registry.example/base@sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn request(egress: EgressRequest, size: Size) -> ProvisionRequest {
        let prepared = Prepared {
            provider: "ds".into(),
            id: DIGEST.into(),
            platform: platform(),
            image_digest: DIGEST.into(),
            tools_digest: "t".into(),
        };
        ProvisionRequest { label: "crew-1".into(), prepared, size, egress, ssh_public_key: None }
    }
    fn size() -> Size {
        Size { cpus: 2.0, memory_bytes: 4 << 30, disk_bytes: 0 }
    }

    // Provision is one create of the image by digest on the prepared
    // platform, answered with Docker's row as it stands. The owner tag goes on
    // only on a shared account, and no network policy goes on.
    #[tokio::test]
    async fn provision_is_one_create_tagged_by_ownership() {
        for (ownership, tags) in [(Ownership::SharedAccount, 2), (Ownership::OwnedAccount, 1)] {
            let (docker, script) = docker(ownership, vec![(202, CREATING)]).await;
            let created = docker.provision(request(EgressRequest::Open, size()), &key()).await.unwrap();
            let Provisioned::Created(e) = created else { panic!("not created") };
            assert_eq!((e.id.as_str(), &e.state, e.vendor.unwrap().state.as_str()), (ID, &STATES[0].1, "creating"));
            assert_eq!(script.lines(), [format!("POST {API}/sandboxes")]);
            let body = script.asked.lock().unwrap()[0].json();
            assert_eq!((&body["imageRef"], &body["platform"]), (&json!(DIGEST), &json!({"os": "linux", "architecture": "amd64"})));
            assert_eq!(body["resources"], json!({"cpus": 2, "memoryMib": 4096}));
            assert_eq!((body["labels"].as_object().unwrap().len(), &body["labels"][LABEL_TAG]), (tags, &json!("crew-1")));
            assert_eq!(body.get("networkPolicies"), None);
        }
    }

    // What Docker cannot hold is refused in its terms before any call: denied
    // egress, which its default policy layer opens whatever the sandbox's own
    // policy says, and a private registry's credential.
    #[tokio::test]
    async fn requests_docker_cannot_hold_are_refused_before_any_call() {
        let (docker, script) = docker(Ownership::SharedAccount, vec![]).await;
        let host = Destination::Host { host: "example.com".parse().unwrap() };
        for direct in [vec![], vec![host]] {
            let Err(ProtocolError::Refused { reason }) = docker.provision(request(EgressRequest::DenyAll { direct }, size()), &key()).await
            else {
                panic!("deny-all not refused")
            };
            assert!(reason.contains("default layer, which allows every network"), "{reason}");
        }
        let prepare = PrepareRequest {
            size: size(),
            platform: Some(platform()),
            route: Some(ImageRouteKind::RegistryPull),
            image_pull: Some(RegistryCredential { username: "u".into(), secret: Secret::new("p") }),
            image_digest: DIGEST.into(),
            tools_digest: DIGEST.replace("base", "tools"),
        };
        assert!(matches!(docker.prepare(prepare.clone(), &key()).await, Err(ProtocolError::Refused { .. })));
        assert_eq!(docker.prepare(PrepareRequest { image_pull: None, ..prepare }, &key()).await.unwrap().id, DIGEST);
        assert!(script.lines().is_empty());
    }

    // A size is one of Docker's shapes, the smallest being Micro, and is sent
    // as its CPUs and MiB. Any other size, or any disk, is refused naming the
    // shapes before any call.
    #[tokio::test]
    async fn sizes_are_dockers_shapes() {
        let shapes = [(1, 2048), (2, 4096), (4, 8192), (8, 16384), (16, 32768)];
        let (docker, script) = docker(Ownership::OwnedAccount, vec![(202, CREATING); shapes.len()]).await;
        for (cpus, mib) in shapes {
            let size = Size { cpus: cpus as f64, memory_bytes: mib * MIB, disk_bytes: 0 };
            docker.provision(request(EgressRequest::Open, size), &key()).await.unwrap();
        }
        let sent: Vec<_> = script.asked.lock().unwrap().iter().map(|a| a.json()["resources"].clone()).collect();
        assert_eq!(sent, shapes.map(|(cpus, mib)| json!({"cpus": cpus, "memoryMib": mib})));
        for size in
            [Size { cpus: 1.0, memory_bytes: 1 << 30, ..size() }, Size { cpus: 1.5, ..size() }, Size { disk_bytes: 1 << 30, ..size() }]
        {
            let Err(ProtocolError::Refused { reason }) = docker.provision(request(EgressRequest::Open, size), &key()).await else {
                panic!("not refused")
            };
            assert!(reason.contains("Micro (1 CPU / 2048 MiB), Small (2 CPU / 4096 MiB)"), "{reason}");
        }
        assert_eq!(script.lines().len(), shapes.len());
        let smallest = DockerSandboxesModule::with_dialer(Arc::new(drydock_transport::memory().0)).smallest_size();
        assert_eq!(smallest, Size { cpus: 1.0, memory_bytes: 2048 * MIB, disk_bytes: 0 });
    }

    // List follows every page; a page without sandboxes holds none, as
    // protobuf leaves an empty list out. Rows carry Docker's state, its
    // failure as the reason, its labels as tags and its platform; no size,
    // since Docker states no disk.
    #[tokio::test]
    async fn list_reads_every_page_and_reports_rows_as_docker_gives_them() {
        let failed = r#"{"name":"sandboxes/sb2","uid":"sb2","core":{"status":"failed","etag":"\"v9\"","createdAt":"2026-11-09T00:00:00Z"},
            "failure":{"code":"internal","message":"placement lost"}}"#;
        let first: &str = &format!(r#"{{"sandboxes":[{RUNNING},{failed}],"nextPageToken":"p2"}}"#);
        let (docker, script) = docker(Ownership::SharedAccount, vec![(200, first), (200, "{}")]).await;
        let listed = docker.list(&key()).await.unwrap();
        assert_eq!(script.lines(), [format!("GET {API}/sandboxes"), format!("GET {API}/sandboxes?pageToken=p2")]);
        let seen: Vec<_> = listed.iter().map(|e| (e.id.as_str(), e.label.as_deref(), e.state.clone(), e.granted_size.clone())).collect();
        assert_eq!(
            seen,
            [
                ("sb1", Some("crew-1"), Observation::Running, None),
                ("sb2", None, Observation::Unknown { reason: UnknownReason::ProviderApiError }, None)
            ]
        );
        assert_eq!(listed[0].platform, Some(platform()));
        assert_eq!(listed[0].vendor.as_ref().unwrap().tags.as_ref().unwrap()[OWNER_TAG], "ds");
        let failed = listed[1].vendor.as_ref().unwrap();
        assert_eq!((failed.state.as_str(), failed.reason.as_deref(), &failed.tags), ("failed", Some("placement lost"), &None));
    }

    // Inspect reads the sandbox and its installed policy: egress is enforced
    // only when Docker states deny-all holding the sandbox's own document and
    // allowing only what it allows, never from an owner's or account's layer
    // alone, nor beside a default layer that opens every network. The policy
    // identity is Docker's revision.
    #[tokio::test]
    async fn inspect_reports_enforcement_from_the_sandboxs_own_policy() {
        let policy = |mode: &str, origin: &str, allowed: &str| {
            format!(
                r#"{{"effective":{{"mode":"{mode}","allowNetworks":[{allowed}]}},"exact":{{"revision":"r-{origin}",
                "selectorVersion":"destination.v1","nodes":[{{"source":{{"origin":"{origin}","id":"p"}},"constant":"false"}}]}}}}"#
            )
        };
        let own = policy("denyAll", "attached", r#"{"layer":"attached","network":"example.com"}"#);
        let (owner, open) = (policy("denyAll", "owner", ""), policy("allowAll", "attached", ""));
        let defaulted = policy("denyAll", "attached", r#"{"layer":"default","network":"**"}"#);
        let answers = vec![
            (200, RUNNING),
            (200, &*own),
            (200, RUNNING),
            (200, &*owner),
            (200, RUNNING),
            (200, &*open),
            (200, RUNNING),
            (200, &*defaulted),
        ];
        let (docker, script) = docker(Ownership::OwnedAccount, answers).await;
        let mut seen = Vec::new();
        for _ in 0..4 {
            let e = docker.inspect(ID, &key()).await.unwrap();
            seen.push((e.egress, e.egress_policy.unwrap()));
        }
        assert_eq!(
            seen,
            [
                (Enforcement::Enforced, "r-attached".to_owned()),
                (Enforcement::Advisory, "r-owner".to_owned()),
                (Enforcement::Advisory, "r-attached".to_owned()),
                (Enforcement::Advisory, "r-attached".to_owned())
            ]
        );
        assert_eq!(script.lines()[..2], [format!("GET {API}/sandboxes/{ID}"), format!("GET {API}/sandboxes/{ID}/network-policies")]);
    }

    // Docker states a sandbox's policy only while it runs: inspect of a
    // sandbox in any other state reads the sandbox alone and states no egress.
    #[tokio::test]
    async fn inspect_states_no_egress_for_a_sandbox_not_running() {
        let stopped = RUNNING.replace(r#""status":"running""#, r#""status":"stopped""#);
        let (docker, script) = docker(Ownership::OwnedAccount, vec![(200, &stopped)]).await;
        let e = docker.inspect(ID, &key()).await.unwrap();
        assert_eq!((e.state, e.egress, e.egress_policy), (Observation::Stopped { cause: None }, Enforcement::Advisory, None));
        assert_eq!(script.lines(), [format!("GET {API}/sandboxes/{ID}")]);
    }

    // Destroy, stop and start each read the sandbox for its etag and send it
    // as the precondition; the resume token is the id. A sandbox that changed
    // in between is Docker's 412, which may succeed when sent again.
    #[tokio::test]
    async fn changes_send_the_etag_they_read() {
        let moved = r#"{"code":"failedPrecondition","message":"etag_mismatch: stale"}"#;
        let answers =
            vec![(200, RUNNING), (204, ""), (200, RUNNING), (202, RUNNING), (200, RUNNING), (200, RUNNING), (200, RUNNING), (412, moved)];
        let (docker, script) = docker(Ownership::OwnedAccount, answers).await;
        docker.destroy(ID, &key()).await.unwrap();
        let port = docker.operations().suspend_resume.unwrap();
        assert_eq!(port.suspend(ID, &key()).await.unwrap(), ResumeToken { token: Secret::new(ID) });
        port.resume(ID, ResumeToken { token: Secret::new("anything") }, &key()).await.unwrap();
        assert!(matches!(docker.destroy(ID, &key()).await, Err(ProtocolError::Unavailable { .. })));
        let read = format!("GET {API}/sandboxes/{ID}");
        let (delete, stop, start) =
            (format!("DELETE {API}/sandboxes/{ID}"), format!("POST {API}/sandboxes/{ID}/stop"), format!("POST {API}/sandboxes/{ID}/start"));
        assert_eq!(script.lines(), [read.clone(), delete.clone(), read.clone(), stop, read.clone(), start, read, delete]);
        let preconditions: Vec<_> = script.asked.lock().unwrap().iter().map(|a| a.if_match.clone()).collect();
        assert_eq!(preconditions.iter().filter(|p| p.as_deref() == Some("\"v1\"")).count(), 4);
        assert!(preconditions.iter().step_by(2).all(Option::is_none));
    }

    // Docker's typed details decide the error: a quota failure is exhausted
    // quota, and a retry delay rounds up to whole seconds.
    #[tokio::test]
    async fn errors_read_dockers_code_and_details() {
        let quota = r#"{"code":"resourceExhausted","message":"too many sandboxes",
            "details":[{"@type":"type.googleapis.com/google.rpc.QuotaFailure","violations":[]}]}"#;
        let busy = r#"{"code":"unavailable","message":"busy","details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"1.5s"}]}"#;
        let (docker, _) = docker(Ownership::OwnedAccount, vec![(429, quota), (503, busy)]).await;
        let Err(ProtocolError::QuotaExhausted { reason }) = docker.list(&key()).await else { panic!("not quota") };
        assert!(reason.contains("resourceExhausted: too many sandboxes"), "{reason}");
        assert!(matches!(docker.list(&key()).await, Err(ProtocolError::Unavailable { retry_after: Some(2), .. })));
    }

    // Exec runs the argv as given, unshelled, as root, at the sandbox's own
    // endpoint with a credential the management API issued for it. A zero
    // exit status Docker leaves out is success; another is a failed command,
    // which says when Docker kept only part of its output.
    #[tokio::test]
    async fn exec_runs_the_argv_at_the_sandbox_endpoint() {
        let answers = vec![
            (200, RUNNING),
            (200, ISSUED),
            (200, r#"{"stdout":"aGk="}"#),
            (200, RUNNING),
            (200, ISSUED),
            (200, r#"{"exitCode":3,"stderr":"Ym9v","incomplete":true}"#),
        ];
        let (docker, script) = docker(Ownership::OwnedAccount, answers).await;
        let exec = docker.operations().exec.unwrap();
        let mut output = String::new();
        let command = ExecRequest { command: vec!["echo".into(), "it's $HOME".into()] };
        exec.exec(ID, command.clone(), &key()).await.unwrap().read_to_string(&mut output).await.unwrap();
        assert_eq!(output, "hi");
        let Err(ProtocolError::CommandFailed { exit_code: 3, output, .. }) = exec.exec(ID, command, &key()).await else {
            panic!("not failed")
        };
        assert_eq!(output.expose(), "boo\nDocker Sandboxes kept only part of the command's output");
        let asked = script.asked.lock().unwrap();
        let seen: Vec<_> = asked[..3].iter().map(|a| (a.line.as_str(), a.bearer.as_deref())).collect();
        let (issue, run) = (format!("POST {API}/sandboxes/{ID}/endpoint-credentials"), format!("POST {ENDPOINT}/processes/exec"));
        assert_eq!(
            seen,
            [(&*format!("GET {API}/sandboxes/{ID}"), Some("Bearer k")), (&*issue, Some("Bearer k")), (&*run, Some("Bearer scoped"))]
        );
        assert_eq!(asked[1].json(), json!({"permissions": ["sandboxesExec"]}));
        assert_eq!(asked[2].json(), json!({"cmd": ["echo", "it's $HOME"], "user": "root"}));
    }

    // A file goes to the sandbox's endpoint: its directory first, parents and
    // all, then its bytes with its mode.
    #[tokio::test]
    async fn files_make_their_directory_then_write() {
        let (docker, script) = docker(Ownership::OwnedAccount, vec![(200, RUNNING), (200, ISSUED), (200, "{}"), (200, "{}")]).await;
        let file = GuestFile { path: AGENT.into(), mode: 0o755 };
        docker.operations().files.unwrap().put(ID, file, Bytes::from_static(b"agent"), &key()).await.unwrap();
        let asked = script.asked.lock().unwrap();
        assert_eq!(asked[1].json(), json!({"permissions": ["sandboxesFilesWrite"]}));
        let (directory, content) = (&asked[2], &asked[3]);
        assert_eq!(
            (directory.line.as_str(), directory.json()),
            (&*format!("PUT {ENDPOINT}/files/directories"), json!({"path": "/opt/drydock", "parents": true}))
        );
        assert_eq!(content.line, format!("PUT {ENDPOINT}/files/content?path=%2Fopt%2Fdrydock%2Fdrydock-agent&mode=493"));
        assert_eq!((content.body.as_slice(), content.bearer.as_deref()), (&b"agent"[..], Some("Bearer scoped")));
    }

    // A personal access token and its owner are exchanged at Docker Hub,
    // without the API's bearer, for an access token that is used until shortly
    // before it expires; one that states no expiry is exchanged again for each
    // call. Docker Hub's 401 rejects it, and a bare token, which Docker's API
    // does not take as a bearer, is rejected before any call.
    #[tokio::test]
    async fn personal_access_tokens_are_exchanged_until_their_token_expires() {
        let jwt = |claims: Value| format!("h.{}.s", URL_SAFE_NO_PAD.encode(claims.to_string()));
        let (lasting, unstated) = (jwt(json!({"exp": 4_102_444_800u64})), jwt(json!({})));
        let exchanged = |token: &str| format!(r#"{{"access_token":"{token}"}}"#);
        let (first, second) = (exchanged(&lasting), exchanged(&unstated));
        let answers =
            vec![(200, &*first), (200, "{}"), (200, "{}"), (200, &*second), (200, "{}"), (200, &*second), (200, "{}"), (401, "{}")];
        let answers = answers.into_iter().map(|(status, body)| (status, body.to_owned())).collect();
        let script = Arc::new(Script { answers: Mutex::new(answers), ..Script::default() });
        let exchanging =
            configure(Ownership::OwnedAccount, json!({}), script.clone(), Arc::new(drydock_transport::memory().0)).await.unwrap();
        for credential in [pat("a"), pat("a"), pat("b"), pat("b")] {
            exchanging.list(&credential).await.unwrap();
        }
        assert!(matches!(exchanging.list(&pat("c")).await, Err(ProtocolError::CredentialRejected { .. })));
        let seen: Vec<_> = script.asked.lock().unwrap().iter().map(|a| (a.line.clone(), a.bearer.clone())).collect();
        let hub = ("POST hub.docker.com/v2/auth/token".to_owned(), None);
        let list = |token: &str| (format!("GET {API}/sandboxes"), Some(format!("Bearer {token}")));
        assert_eq!(seen, [hub.clone(), list(&lasting), list(&lasting), hub.clone(), list(&unstated), hub.clone(), list(&unstated), hub]);
        assert_eq!(script.asked.lock().unwrap()[0].json(), json!({"identifier": "a", "secret": "dckr_pat_x"}));
        let bare = Credentials::new(Some(Secret::new("dckr_pat_x")));
        assert!(matches!(exchanging.list(&bare).await, Err(ProtocolError::CredentialRejected { .. })));
        assert_eq!(script.asked.lock().unwrap().len(), 8);
    }

    // The relay starts the agent's bridge, attaches to it over Docker's
    // interact WebSocket with the endpoint credential and Docker's
    // subprotocol, and carries bytes: written ones as stdin, stdout back
    // (stderr, heartbeats and pings are not the agent's), closing stdin at
    // the end of what was written, and ending when the process exits.
    #[tokio::test]
    async fn relays_carry_the_bridges_stdin_and_stdout() {
        let (dialer, mut listener) = drydock_transport::memory();
        let process = r#"{"name":"processes/p1","label":"l"}"#;
        let script = script(&[(200, RUNNING), (200, ISSUED), (201, process)]);
        let docker = configure(Ownership::OwnedAccount, json!({}), script.clone(), Arc::new(dialer)).await.unwrap();
        let server = tokio::spawn(async move {
            #[allow(clippy::result_large_err)]
            let check = |request: &Request, mut response: Response| -> std::result::Result<Response, ErrorResponse> {
                assert_eq!(request.uri().path(), "/sb/v1/processes/p1/interact");
                assert_eq!(request.headers()[header::AUTHORIZATION], "Bearer scoped");
                assert_eq!(request.headers()[header::SEC_WEBSOCKET_PROTOCOL], SUBPROTOCOL);
                response.headers_mut().insert(header::SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_static(SUBPROTOCOL));
                Ok(response)
            };
            let mut socket = accept_hdr_async(listener.accept().await.unwrap(), check).await.unwrap();
            assert_eq!(frame(&mut socket).await, json!({"attach": {"name": "processes/p1", "resumeFrom": 0}}));
            assert_eq!(frame(&mut socket).await, json!({"stdin": STANDARD.encode("ping")}));
            socket.send(Message::Ping(Bytes::from_static(b"p"))).await.unwrap();
            for out in [
                json!({"chunk": {"stream": "stderr", "data": STANDARD.encode("log"), "streamSequence": "1"}}),
                json!({"heartbeat": {}}),
                json!({"chunk": {"stream": "stdout", "data": STANDARD.encode("pong"), "streamSequence": "2"}}),
            ] {
                socket.send(Message::text(out.to_string())).await.unwrap();
            }
            assert_eq!(frame(&mut socket).await, json!({"closeStdin": true}));
            socket.send(Message::text(json!({"exited": {}}).to_string())).await.unwrap();
        });
        let mut relay = docker.relay(ID, &key()).await.unwrap();
        relay.write_all(b"ping").await.unwrap();
        let mut pong = [0; 4];
        relay.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
        relay.shutdown().await.unwrap();
        let mut rest = Vec::new();
        relay.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        server.await.unwrap();
        assert_eq!(script.asked.lock().unwrap()[2].json(), json!({"cmd": [AGENT, "--bridge"], "user": "root"}));
    }

    // A relay whose interact upgrade Docker refuses fails with Docker's answer,
    // and the bridge it started is killed rather than left waiting on stdin.
    #[tokio::test]
    async fn a_refused_relay_ends_its_bridge() {
        let (dialer, mut listener) = drydock_transport::memory();
        let script = script(&[(200, RUNNING), (200, ISSUED), (201, r#"{"name":"processes/p1","label":"l"}"#), (200, "{}")]);
        let docker = configure(Ownership::OwnedAccount, json!({}), script.clone(), Arc::new(dialer)).await.unwrap();
        tokio::spawn(async move {
            #[allow(clippy::result_large_err)]
            let refuse = |_: &Request, _: Response| -> std::result::Result<Response, ErrorResponse> {
                let mut refusal = ErrorResponse::new(Some(r#"{"code":"permissionDenied","message":"no exec"}"#.into()));
                *refusal.status_mut() = http::StatusCode::FORBIDDEN;
                Err(refusal)
            };
            let _ = accept_hdr_async(listener.accept().await.unwrap(), refuse).await;
        });
        let Err(ProtocolError::Refused { reason }) = docker.relay(ID, &key()).await else { panic!("not refused") };
        assert!(reason.contains("permissionDenied: no exec"), "{reason}");
        let asked = script.asked.lock().unwrap();
        let kill = &asked[3];
        assert_eq!((kill.line.as_str(), kill.bearer.as_deref()), (&*format!("POST {ENDPOINT}/processes/p1/signal"), Some("Bearer scoped")));
        assert_eq!(kill.json(), json!({"signal": "kill"}));
    }

    /// The next text frame, past the client's answers to pings.
    async fn frame(socket: &mut WebSocket) -> Value {
        loop {
            if let Message::Text(text) = socket.next().await.unwrap().unwrap() {
                return serde_json::from_str(text.as_str()).unwrap();
            }
        }
    }

    // Every setting has a default; a zero or an unknown key is refused.
    #[tokio::test]
    async fn settings_refuse_zeroes_and_unknown_keys() {
        let dialer = || Arc::new(drydock_transport::memory().0);
        assert!(configure(Ownership::SharedAccount, json!({}), Arc::default(), dialer()).await.is_ok());
        for refused in [json!({"poll_seconds": 0}), json!({"exec_seconds": 0}), json!({"upload_seconds": 0}), json!({"api": "x"})] {
            let result = configure(Ownership::SharedAccount, refused.clone(), Arc::default(), dialer()).await;
            assert!(matches!(result, Err(ProtocolError::Refused { .. })), "{refused}");
        }
    }
}

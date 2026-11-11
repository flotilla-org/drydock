//! Docker Engine translator: containers on an engine reached through its API
//! alone, at a Unix socket on this machine or over TLS with a client
//! certificate. Each verb is the engine's own calls and each answer is what
//! the engine said. Nothing runs on the engine's machine and nothing is
//! mounted: the agent goes in through the archive call and runs through
//! exec, whose connection the engine takes over.
//! API reference: https://docs.docker.com/reference/api/engine/version/v1.44/
use crate::{
    kit::{
        self, GIB, LABEL_TAG, StateTable, Vendor,
        api::{Api, Auth, Body, operation},
        endpoint::{Endpoint, TlsFiles, Upgrade},
        guest::{Guest, GuestOutput},
        image::{check_prepare, check_prepared},
        relay::{multiplexed, read_output},
    },
    module::*,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use drydock_protocol::*;
use reqwest::{
    Method,
    header::{CONTENT_TYPE, HeaderName, HeaderValue},
};
use serde::{Deserialize, de::IgnoredAny};
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

const ENGINE: Vendor = Vendor("Docker Engine");
/// The API version every request names: Engine 25 and later.
const API_VERSION: &str = "v1.44";
const AGENT: &str = "/opt/drydock/drydock-agent";
/// How long the engine may take to answer an exec start; the process's own
/// time is bounded apart.
const HANDSHAKE: Duration = Duration::from_secs(30);
/// How many times an exec's exit is asked for once its stream ends.
const EXIT_POLLS: usize = 10;

/// The engine says nothing of who stopped a container, nor whether a paused
/// one will be unpaused; a created one will not start by itself.
const STATES: StateTable = &[
    ("created", Observation::Stopped { cause: None }),
    ("running", Observation::Running),
    ("paused", Observation::Stopped { cause: None }),
    ("restarting", kit::starting()),
    ("removing", Observation::Transitioning { phase: TransitionPhase::Destroying }),
    ("exited", Observation::Stopped { cause: None }),
    ("dead", Observation::Unknown { reason: UnknownReason::ProviderStateUnknown }),
];

// The engine's wire types, only the fields read.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Version {
    os: Option<String>,
    arch: Option<String>,
}
#[derive(Deserialize)]
struct Info {
    #[serde(rename = "MemoryLimit")]
    memory_limit: Option<bool>,
    #[serde(rename = "SwapLimit")]
    swap_limit: Option<bool>,
    #[serde(rename = "CpuCfsQuota")]
    cpu_cfs_quota: Option<bool>,
    #[serde(rename = "ContainersRunning")]
    containers_running: Option<u64>,
    #[serde(rename = "Warnings")]
    warnings: Option<Vec<String>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Image {
    id: kit::api::Text,
    os: Option<String>,
    architecture: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Made {
    id: kit::api::Text,
    warnings: Option<Vec<String>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Container {
    id: kit::api::Text,
    state: State,
    config: Option<Config>,
    host_config: Option<HostConfig>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct State {
    status: kit::api::Text,
    exit_code: Option<i64>,
    #[serde(rename = "OOMKilled")]
    oom_killed: Option<bool>,
    error: Option<String>,
    started_at: Option<String>,
    finished_at: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Config {
    labels: Option<BTreeMap<String, String>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HostConfig {
    network_mode: Option<String>,
}
/// A list row: the state is its name alone.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Row {
    id: kit::api::Text,
    state: kit::api::Text,
    labels: Option<BTreeMap<String, String>>,
    host_config: Option<HostConfig>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ExecState {
    exit_code: Option<i64>,
    running: bool,
}
/// One entry of a pull's progress stream; a failure is an entry with an error.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Progress {
    error: Option<String>,
    error_detail: Option<ErrorDetail>,
}
#[derive(Deserialize)]
struct ErrorDetail {
    message: Option<String>,
}

pub struct DockerEngineModule;

/// Every key but `endpoint` has a default.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Settings {
    /// `unix://` and a path, or `tcp://host:port` with `tls`.
    endpoint: Option<String>,
    tls: Option<TlsFiles>,
    /// How often drydockd lists containers.
    poll_seconds: u64,
    /// How long a pull may take: the engine answers once it ends.
    pull_seconds: u64,
    /// How long one command's output is read.
    exec_seconds: u64,
    /// How long one file upload may take.
    upload_seconds: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self { endpoint: None, tls: None, poll_seconds: 30, pull_seconds: 600, exec_seconds: 60, upload_seconds: 300 }
    }
}

#[async_trait]
impl Module for DockerEngineModule {
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn smallest_size(&self) -> Size {
        Size { cpus: 1.0, memory_bytes: GIB, disk_bytes: 0 }
    }
    /// The engine is reached through its own endpoint, never the host's HTTPS
    /// client.
    async fn configure(&self, name: &str, config: &ProviderConfiguration, _: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
        let settings: Settings =
            serde_json::from_value(json!(config.settings)).map_err(|e| refused(format!("invalid Docker Engine settings: {e}")))?;
        if [settings.poll_seconds, settings.pull_seconds, settings.exec_seconds, settings.upload_seconds].contains(&0) {
            return Err(refused("Docker Engine's poll, pull, exec and upload settings must be positive"));
        }
        let Some(address) = settings.endpoint.as_deref() else {
            return Err(refused(
                "Docker Engine needs an endpoint in its settings: endpoint = \"unix:///var/run/docker.sock\", or \"tcp://host:2376\" with tls = { ca, cert, key }",
            ));
        };
        let endpoint = Arc::new(Endpoint::new(ENGINE, address, settings.tls.as_ref())?);
        let base = kit::api::join(endpoint.base(), &[API_VERSION, ""])?;
        let api = Api::over(ENGINE, base, Auth::None, endpoint.clone());
        Ok(Arc::new(DockerEngine {
            name: name.to_owned(),
            ownership: config.ownership,
            settings,
            api,
            endpoint,
            stated: Mutex::new((Readiness::Unknown { reason: "Docker Engine has not been asked yet".into() }, None)),
        }))
    }
}

pub struct DockerEngine {
    name: String,
    ownership: Ownership,
    settings: Settings,
    api: Api,
    endpoint: Arc<Endpoint>,
    /// What the engine last said of itself: whether it answered, and its platform.
    stated: Mutex<(Readiness, Option<Platform>)>,
}

/// An OCI platform from the engine's words, when they make one.
fn stated_platform(os: Option<String>, architecture: Option<String>) -> Option<Platform> {
    serde_json::from_value(json!({"os": os?, "architecture": architecture?})).ok()
}
/// The error in a pull's progress stream, if one arrived: the engine answers
/// 200 before the pull ends, and a failure is an entry of its own.
fn pull_error(stream: &[u8]) -> Option<String> {
    stream
        .split(|b| *b == b'\n')
        .filter_map(|line| serde_json::from_slice::<Progress>(line).ok())
        .find_map(|entry| entry.error_detail.and_then(|d| d.message).or(entry.error).filter(|e| !e.is_empty()))
}
/// The engine's statement that it cannot enforce a memory limit or a CPU
/// quota: either flag false or absent from `/info`, and its warnings.
fn unenforced(info: &Info) -> Option<String> {
    let flags = [("MemoryLimit", info.memory_limit), ("CpuCfsQuota", info.cpu_cfs_quota)];
    let missing: Vec<String> = flags
        .iter()
        .filter(|(_, stated)| *stated != Some(true))
        .map(|(name, stated)| stated.map_or_else(|| format!("no {name}"), |s| format!("{name} {s}")))
        .collect();
    if missing.is_empty() {
        return None;
    }
    let mut reason = format!("Docker Engine cannot enforce this size: its /info states {}", missing.join(", "));
    if let Some(warnings) = info.warnings.as_ref().filter(|w| !w.is_empty()) {
        reason.push_str(&format!("; {}", warnings.join("; ")));
    }
    Some(reason)
}
/// The engine's time for a state, unless it is Go's zero time, which says none.
fn time(text: Option<&str>) -> Option<Timestamp> {
    let at = chrono::DateTime::parse_from_rfc3339(text?).ok()?.with_timezone(&chrono::Utc);
    (chrono::Datelike::year(&at) > 1).then(|| at.into())
}
/// No network is the engine's whole egress control; it has no allow-list.
fn network_mode(request: &EgressRequest) -> Result<Option<&'static str>> {
    match request {
        EgressRequest::Open => Ok(None),
        EgressRequest::DenyAll { direct } if direct.is_empty() => Ok(Some("none")),
        EgressRequest::DenyAll { .. } => {
            Err(refused("Docker Engine denies egress only whole (no network): it has no allow-list, so ask for no destinations"))
        }
    }
}
fn egress_model() -> EgressModel {
    EgressModel {
        shapes: vec![EgressShape::Open, EgressShape::DenyAll],
        enforced: EnforcementSite::OutsideGuest,
        side_effects: vec![],
        mutable_while_running: false,
        sources: vec!["https://docs.docker.com/engine/network/drivers/none/".into()],
    }
}

impl DockerEngine {
    fn platform(&self) -> Option<Platform> {
        self.stated.lock().unwrap_or_else(PoisonError::into_inner).1.clone()
    }
    fn url(&self, segments: &[&str]) -> Result<reqwest::Url> {
        self.api.url(segments)
    }
    fn container_url(&self, id: &str, rest: &[&str]) -> Result<reqwest::Url> {
        if id.is_empty() || id == "." || id == ".." {
            return Err(ProtocolError::NotFound { reason: "not a Docker Engine container id".into() });
        }
        self.url(&[&["containers", id][..], rest].concat())
    }
    async fn container(&self, id: &str, c: &Credentials) -> Result<Container> {
        self.api.get(self.container_url(id, &["json"])?, c).await
    }
    /// A row as the engine states it. Egress is enforced when the container
    /// has no network; the engine states no disk, so no granted size.
    fn environment(&self, id: String, state: String, labels: Option<BTreeMap<String, String>>, network: Option<String>) -> Environment {
        let isolated = network.as_deref() == Some("none");
        Environment {
            id,
            provider: self.name.clone(),
            label: labels.as_ref().and_then(|l| l.get(LABEL_TAG)).cloned(),
            state: kit::observe(STATES, &state),
            granted_size: None,
            egress: if isolated { Enforcement::Enforced } else { Enforcement::Advisory },
            platform: None,
            egress_measured: false,
            egress_policy: network.filter(|_| isolated),
            timestamp: None,
            vendor: Some(VendorState { state, reason: None, tags: labels }),
        }
    }
    /// Inspect's row: the list row's words, with the exit code, the memory
    /// kill and the engine's error as the reason, and the time of the state.
    fn inspected(&self, v: Container) -> Environment {
        let s = v.state;
        let mut words = Vec::new();
        if matches!(&*s.status, "exited" | "dead") {
            words.extend(s.exit_code.map(|code| format!("ExitCode {code}")));
            words.extend(s.oom_killed.filter(|k| *k).map(|_| "OOMKilled".to_owned()));
        }
        words.extend(s.error.filter(|e| !e.is_empty()));
        let at = match &*s.status {
            "running" => time(s.started_at.as_deref()),
            "exited" | "dead" => time(s.finished_at.as_deref()),
            _ => None,
        };
        let network = v.host_config.and_then(|h| h.network_mode);
        let mut environment = self.environment(v.id.into(), s.status.into(), v.config.and_then(|c| c.labels), network);
        environment.timestamp = at;
        if let Some(vendor) = &mut environment.vendor {
            vendor.reason = (!words.is_empty()).then(|| words.join(", "));
        }
        environment
    }
    /// A process made by exec, as root, with stdin attached or stderr. Root is
    /// uid 0 inside the container, which a user-namespaced engine maps to an
    /// unprivileged uid on its machine.
    async fn exec_create(&self, id: &str, argv: &[String], env: BTreeMap<&str, String>, stdin: bool, c: &Credentials) -> Result<String> {
        #[derive(Deserialize)]
        struct Made {
            #[serde(rename = "Id")]
            id: kit::api::Text,
        }
        let env: Vec<String> = env.into_iter().map(|(k, v)| format!("{k}={v}")).collect();
        let body = json!({
            "AttachStdin": stdin, "AttachStdout": true, "AttachStderr": !stdin, "Tty": false,
            "Cmd": argv, "Env": env, "User": "0",
        });
        let made: Made = self.api.call(Method::POST, self.container_url(id, &["exec"])?, Body::json(&body)?, c).await?;
        Ok(made.id.into())
    }
    /// `failure`, after removing the container it left; when the removal
    /// fails too, the reason says the container may still be there.
    async fn removed(&self, id: &str, doing: &str, failure: ProtocolError, c: &Credentials) -> ProtocolError {
        match self.destroy(id, c).await {
            Ok(()) => failure.context(&format!("{doing}, so it was removed")),
            Err(e) => failure.context(&format!("{doing}; container {id} may be left on the engine, as removing it failed ({e})")),
        }
    }
    /// Starts the process, the engine taking the connection over for its streams.
    async fn exec_start(&self, exec: &str) -> Result<ByteStream> {
        let url = self.url(&["exec", exec, "start"])?;
        let operation = operation(&Method::POST, &url);
        let mut request = reqwest::Request::new(Method::POST, url);
        *request.timeout_mut() = Some(HANDSHAKE);
        request.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        *request.body_mut() = Some(json!({"Detach": false, "Tty": false}).to_string().into());
        match self.endpoint.upgrade(request, "tcp").await {
            Ok(Upgrade::Switched(stream)) => Ok(stream),
            Ok(Upgrade::Answered(response)) => Err(self.api.failure(&operation, &response)),
            Err(error) => Err(ProtocolError::Unavailable {
                reason: format!("Docker Engine {operation} transport failed"),
                retry_after: None,
                provider_error: Some(error),
            }),
        }
    }
}

#[async_trait]
impl Provider for DockerEngine {
    fn capabilities(&self) -> Capabilities {
        let remote = kit::remote_sandbox(egress_model());
        Capabilities {
            bootstrap: BootstrapRoute::Upload,
            platforms: self.platform().into_iter().collect(),
            // The engine pulls by digest with the credential sent in the pull.
            image_routes: vec![ImageRoute::RegistryPull {
                auth: RegistryAuthKind::Basic,
                registration: CredentialRegistration::PerRequest,
                digest_references: true,
                tools_layer: ToolsLayer::Upload,
            }],
            quota: true,
            ..remote
        }
    }
    fn ways_in(&self) -> Vec<WayIn> {
        vec![WayIn::Poll { interval_ms: self.settings.poll_seconds.saturating_mul(1000) }]
    }
    fn operations(&self) -> Operations<'_> {
        Operations { exec: Some(self), files: Some(self), quota: Some(self), ..Operations::default() }
    }
    /// Access is the endpoint's own; no credential is delivered.
    fn readiness(&self, _: &Credentials) -> Readiness {
        self.stated.lock().unwrap_or_else(PoisonError::into_inner).0.clone()
    }
    /// The engine's own version answer: whether it answers, and the platform
    /// it runs.
    async fn refresh_readiness(&self, c: &Credentials) {
        let Ok(url) = self.url(&["version"]) else { return };
        let stated = match self.api.get::<Version>(url, c).await {
            Ok(v) => (Readiness::Ready, stated_platform(v.os, v.arch)),
            Err(error) => (Readiness::Unknown { reason: error.to_string() }, self.platform()),
        };
        *self.stated.lock().unwrap_or_else(PoisonError::into_inner) = stated;
    }
    /// The pull, read to the end of its progress stream, then the image the
    /// engine holds. The prepared form is the engine's image id.
    async fn prepare(&self, r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
        let stated = self.platform().ok_or_else(|| ProtocolError::unavailable("Docker Engine has not stated its platform", None))?;
        let (_, platform) = check_prepare(ENGINE, &r, &[ImageRouteKind::RegistryPull], &stated)?;
        let mut url = self.url(&["images", "create"])?;
        url.query_pairs_mut().append_pair("fromImage", &r.image_digest).append_pair("platform", &platform.to_string());
        let mut headers = Vec::new();
        if let Some(pull) = &r.image_pull {
            let registry = drydock_oci::ImageRef::parse(&r.image_digest).map_err(|e| refused(e.to_string()))?.registry;
            let auth = json!({"username": pull.username, "password": pull.secret.expose(), "serveraddress": registry});
            let value = kit::api::sensitive(&URL_SAFE.encode(auth.to_string())).map_err(|_| refused("invalid registry credential"))?;
            headers.push((HeaderName::from_static("x-registry-auth"), value));
        }
        let operation = operation(&Method::POST, &url);
        // The engine answers once the pull ends, its progress held whole.
        let deadline = Some(Duration::from_secs(self.settings.pull_seconds));
        let response = self.api.send_within(Method::POST, url, Body::None, c, true, &headers, deadline).await?;
        if !response.status().is_success() {
            return Err(self.api.failure(&operation, &response));
        }
        if let Some(error) = pull_error(response.body()) {
            return Err(refused(format!("Docker Engine pull of {} failed: {error}", r.image_digest)));
        }
        let image: Image = self.api.get(self.url(&["images", &r.image_digest, "json"])?, c).await?;
        if stated_platform(image.os, image.architecture).as_ref() != Some(&platform) {
            return Err(ProtocolError::ImageRefused {
                reason: format!("Docker Engine holds {} for another platform than {platform}", r.image_digest),
                refusal: ImageRefusal::UnsupportedPlatform { platform },
            });
        }
        Ok(Prepared {
            provider: self.name.clone(),
            id: image.id.into(),
            platform,
            image_digest: r.image_digest,
            tools_digest: r.tools_digest,
        })
    }
    /// Create and start, the size as limits the engine states it enforces,
    /// the labels as container labels, under the engine's init. The container
    /// waits on `sleep` until drydockd puts the agent in and starts it.
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        check_prepared(ENGINE, &self.name, &r.prepared, &r.prepared.id)?;
        let network = network_mode(&r.egress)?;
        if r.size.disk_bytes != 0 {
            return Err(refused("Docker Engine sets no per-container disk size: ask for a disk of 0"));
        }
        let info: Info = self.api.get(self.url(&["info"])?, c).await?;
        if let Some(reason) = unenforced(&info) {
            return Err(refused(reason));
        }
        let mut labels = BTreeMap::from([(LABEL_TAG, r.label.as_str())]);
        if self.ownership == Ownership::SharedAccount {
            labels.insert(OWNER_TAG, &self.name);
        }
        let memory = i64::try_from(r.size.memory_bytes).map_err(|_| refused("memory size too large for Docker Engine"))?;
        let mut host = json!({"NanoCpus": (r.size.cpus * 1e9).round() as i64, "Memory": memory, "Init": true});
        if info.swap_limit == Some(true) {
            host["MemorySwap"] = json!(memory);
        }
        if let Some(mode) = network {
            host["NetworkMode"] = json!(mode);
        }
        let body = json!({
            "Image": r.prepared.id, "Entrypoint": ["sleep"], "Cmd": ["infinity"], "Labels": labels, "HostConfig": host,
        });
        let mut url = self.url(&["containers", "create"])?;
        url.query_pairs_mut().append_pair("platform", &r.prepared.platform.to_string());
        let made: Made = self.api.call(Method::POST, url, Body::json(&body)?, c).await?;
        // The engine discards a limit it cannot apply and warns.
        if let Some(warnings) = made.warnings.filter(|w| !w.is_empty()) {
            let warned = refused(format!("Docker Engine warned: {}", warnings.join("; ")));
            return Err(self.removed(&made.id, "creating the container", warned, c).await);
        }
        let start = self.container_url(&made.id, &["start"])?;
        if let Err(e) = self.api.call::<IgnoredAny>(Method::POST, start, Body::None, c).await {
            return Err(self.removed(&made.id, "starting the container", e, c).await);
        }
        // An error answer leaves drydockd without the id, so a container kept
        // here would be one nothing records.
        match self.container(&made.id, c).await {
            Ok(container) => Ok(Provisioned::Created(self.inspected(container))),
            Err(e) => Err(self.removed(&made.id, "inspecting the started container", e, c).await),
        }
    }
    /// Every container, stopped ones included; on a shared account only those
    /// carrying this instance's label, by the engine's own filter.
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        let mut url = self.url(&["containers", "json"])?;
        url.query_pairs_mut().append_pair("all", "1");
        if self.ownership == Ownership::SharedAccount {
            let filters = json!({"label": [format!("{OWNER_TAG}={}", self.name)]});
            url.query_pairs_mut().append_pair("filters", &filters.to_string());
        }
        let rows: Vec<Row> = self.api.get(url, c).await?;
        Ok(rows
            .into_iter()
            .map(|v| self.environment(v.id.into(), v.state.into(), v.labels, v.host_config.and_then(|h| h.network_mode)))
            .collect())
    }
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        Ok(self.inspected(self.container(id, c).await?))
    }
    /// Removes a running container too, with its anonymous volumes.
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        let mut url = self.container_url(id, &[])?;
        url.query_pairs_mut().append_pair("force", "1").append_pair("v", "1");
        self.api.call::<IgnoredAny>(Method::DELETE, url, Body::None, c).await.map(drop)
    }
    async fn reach(&self, id: &str, _: &Credentials) -> Result<Reach> {
        Ok(Reach::relay(&self.name, id))
    }
    /// A process running the agent's bridge through exec, its stdin and
    /// stdout carried over the connection the engine takes over.
    async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream> {
        let exec = self.exec_create(id, &[AGENT.into(), "--bridge".into()], BTreeMap::new(), true, c).await?;
        Ok(multiplexed(ENGINE, self.exec_start(&exec).await?))
    }
}

/// The engine's exec takes an argv and env; its output is read until the
/// process ends or `exec_seconds` pass, then its exit code is read.
#[async_trait]
impl Guest for DockerEngine {
    fn vendor(&self) -> Vendor {
        ENGINE
    }
    async fn run(&self, id: &str, script: &str, env: BTreeMap<&str, String>, c: &Credentials) -> Result<GuestOutput> {
        self.run_argv(id, &["sh".into(), "-c".into(), script.into()], env, c).await
    }
    async fn run_argv(&self, id: &str, argv: &[String], env: BTreeMap<&str, String>, c: &Credentials) -> Result<GuestOutput> {
        let exec = self.exec_create(id, argv, env, false, c).await?;
        let deadline = Duration::from_secs(self.settings.exec_seconds);
        let mut output = GuestOutput::default();
        let read = async {
            let stream = self.exec_start(&exec).await?;
            read_output(stream, &mut output.chunks).await.map_err(|error| ProtocolError::Unavailable {
                reason: "Docker Engine exec stream failed".into(),
                retry_after: None,
                provider_error: Some(error.to_string()),
            })
        };
        if tokio::time::timeout(deadline, read).await.ok().transpose()?.is_none() {
            output.timed_out = true;
            output.note = Some("Docker Engine has no exec timeout: the command may still be running".into());
            return Ok(output);
        }
        // The engine may close the stream a moment before it records the exit.
        for _ in 0..EXIT_POLLS {
            let state: ExecState = self.api.get(self.url(&["exec", &exec, "json"])?, c).await?;
            if !state.running {
                output.exit = state.exit_code.map(|code| i32::try_from(code).unwrap_or(-1));
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok(output)
    }
}
#[async_trait]
impl Exec for DockerEngine {
    async fn exec(&self, id: &str, r: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        Guest::exec(self, id, r, c).await
    }
}

/// The archive call makes no directories, so the file's directory is made
/// through exec first; the file goes in a tar holding it alone, owned by root.
#[async_trait]
impl GuestFiles for DockerEngine {
    async fn put(&self, id: &str, file: GuestFile, bytes: Bytes, c: &Credentials) -> Result<()> {
        let path = std::path::Path::new(&file.path);
        if !path.is_absolute() {
            return Err(refused(format!("Docker Engine puts files at absolute paths only, not {}", file.path)));
        }
        let (Some(parent), Some(name)) = (path.parent().and_then(|p| p.to_str()), path.file_name()) else {
            return Err(refused(format!("{} names no file", file.path)));
        };
        let mkdir = ["mkdir", "-p", "--", parent].map(str::to_owned);
        self.run_argv(id, &mkdir, BTreeMap::new(), c).await?.success(ENGINE)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(file.mode);
        header.set_entry_type(tar::EntryType::Regular);
        let mut archive = tar::Builder::new(Vec::new());
        let tar_failed =
            |e: std::io::Error| ProtocolError::Internal { reason: "the upload's tar did not build".into(), provider_error: e.to_string() };
        archive.append_data(&mut header, name, &bytes[..]).map_err(tar_failed)?;
        let archive = archive.into_inner().map_err(tar_failed)?;
        let mut url = self.container_url(id, &["archive"])?;
        url.query_pairs_mut().append_pair("path", parent);
        let deadline = Duration::from_secs(self.settings.upload_seconds);
        let body = Body::Bytes(archive.into(), "application/x-tar");
        self.api.call_within::<IgnoredAny>(Method::PUT, url, body, c, deadline).await.map(drop)
    }
}

/// What the engine states of its load: its count of running containers, all
/// of them. It states no limit, and admits nothing.
#[async_trait]
impl QuotaOperation for DockerEngine {
    async fn quota(&self, c: &Credentials) -> Result<Quota> {
        let info: Info = self.api.get(self.url(&["info"])?, c).await?;
        Ok(Quota { concurrency_in_use: info.containers_running, ..Quota::default() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The engine's zero time is a time it does not state.
    #[test]
    fn times() {
        assert!(time(Some("0001-01-01T00:00:00Z")).is_none());
        assert!(time(Some("2026-11-11T21:00:00.123456789Z")).is_some());
    }

    fn info(memory: Option<bool>, cpu: Option<bool>, warnings: &[&str]) -> Info {
        let warnings = Some(warnings.iter().map(|w| w.to_string()).collect());
        Info { memory_limit: memory, swap_limit: None, cpu_cfs_quota: cpu, containers_running: None, warnings }
    }

    // The progress stream's error entry is the pull's failure, whatever the status.
    #[test]
    fn a_pull_fails_by_its_error_entry() {
        let failed = b"{\"status\":\"Pulling from library/ubuntu\"}\n{\"errorDetail\":{\"message\":\"manifest unknown\"},\"error\":\"manifest unknown\"}\n";
        assert_eq!(pull_error(failed).as_deref(), Some("manifest unknown"));
        assert_eq!(pull_error(b"{\"status\":\"Digest: sha256:00\"}\n{\"status\":\"Status: Downloaded\"}\n"), None);
    }

    // Deny-all is no network; deny-all with a destination is refused.
    #[test]
    fn egress_is_no_network_or_open() {
        assert_eq!(network_mode(&EgressRequest::Open).unwrap(), None);
        assert_eq!(network_mode(&EgressRequest::DenyAll { direct: vec![] }).unwrap(), Some("none"));
        let destination = serde_json::from_value(json!({"kind": "host", "host": "example.com"})).unwrap();
        assert!(matches!(network_mode(&EgressRequest::DenyAll { direct: vec![destination] }), Err(ProtocolError::Refused { .. })));
    }

    // A size is refused unless /info states both limits enforced, in the engine's words.
    #[test]
    fn limits_the_engine_does_not_state_refuse_a_size() {
        let reason = unenforced(&info(Some(false), None, &["WARNING: No memory limit support"])).unwrap();
        assert_eq!(
            reason,
            "Docker Engine cannot enforce this size: its /info states MemoryLimit false, no CpuCfsQuota; WARNING: No memory limit support"
        );
        assert_eq!(unenforced(&info(Some(true), Some(true), &["WARNING: bridge-nf-call-iptables is disabled"])), None);
    }
}

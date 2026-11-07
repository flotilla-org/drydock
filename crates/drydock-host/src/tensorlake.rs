//! Tensorlake translator: each verb is Tensorlake's own operation, and each
//! answer is what Tensorlake said. Waiting, idempotence and ownership are
//! drydockd's, as the declared [`Semantics`] leave them (see `capabilities`).
//! Sandboxes are reached through the sandbox proxy's TCP tunnel to the agent's
//! token-gated listener. API: https://docs.tensorlake.ai/api-reference/openapi.yaml;
//! the Image Service and snapshots follow the SDK
//! (https://github.com/tensorlakeai/tensorlake, crates/cloud-sdk); webhooks:
//! https://docs.tensorlake.ai/platform/webhooks/events.md.
use crate::{
    kit::{
        self, GIB, LABEL_TAG, MIB, StateTable, Vendor,
        api::{Amount, Api, Auth, Body, Failure, Next, Paging, Text, absent_on_not_found},
        egress::{ipv6, normal_cidr, normal_host, private_host},
        guest::{Guest, GuestOutput},
        image::{check_prepare, check_prepared, content_name, platform_dockerfile},
    },
    module::*,
    oci::ImageRef,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use drydock_protocol::*;
use drydock_transport::{
    tcp::{self, Token},
    websocket::{self, DialError, TlsDialer, WebSocketDialer, tungstenite::http::HeaderMap},
};
use reqwest::{
    Method, Url,
    header::{HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize, de::IgnoredAny};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    num::NonZeroU16,
    sync::Arc,
    time::Duration,
};

const TENSORLAKE: Vendor = Vendor("Tensorlake");
// The tunnel proxy drops a connection that carries a frame over 64 KiB.
const TUNNEL_FRAME: usize = 64 << 10;
const DISK_MB: std::ops::RangeInclusive<u64> = 10_240..=102_400;
const MEMORY_MB_PER_CPU: std::ops::RangeInclusive<u64> = 1024..=8192;
// Tensorlake says neither whose a suspension or a termination was: its
// outcome and reason, reported beside the state, say what it knows.
// `resume_failed` is not classed: its state is reported as Tensorlake gives it.
const STATES: StateTable = &[
    ("pending", kit::starting()),
    ("running", Observation::Running),
    ("snapshotting", Observation::Transitioning { phase: TransitionPhase::Reconfiguring }),
    ("suspending", kit::stopping()),
    ("suspended", Observation::Stopped { cause: None }),
    ("terminated", Observation::Gone { cause: None }),
];

pub struct TensorlakeModule {
    dialer: Arc<dyn WebSocketDialer>,
}
impl TensorlakeModule {
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
    /// The project whose webhooks the relay receives: a delivery for another
    /// project says nothing drydock follows.
    project_id: Option<String>,
    api_url: String,
    sandbox_domain: String,
    tunnel_port: NonZeroU16,
    max_cpus: u32,
    max_memory: u64,
    poll_interval_ms: u64,
    /// Prepare reads an image build's status every `build_poll_seconds`, up to
    /// `build_polls` times, then answers unavailable.
    build_poll_seconds: u64,
    build_polls: u32,
    /// The agent upload is one proxy request: an agent build (about 12 MB)
    /// needs longer than an ordinary call on a slow link.
    upload_seconds: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            project_id: None,
            api_url: "https://api.tensorlake.ai/".into(),
            sandbox_domain: "sandbox.tensorlake.ai".into(),
            tunnel_port: const { NonZeroU16::new(7811).unwrap() },
            max_cpus: 4,
            max_memory: 16 * GIB,
            poll_interval_ms: 30_000,
            build_poll_seconds: 3,
            build_polls: 150,
            upload_seconds: 300,
        }
    }
}

// Tensorlake's wire types (see the API contract above), only the fields read.
#[derive(Deserialize)]
struct Sandbox {
    id: Text,
    name: Option<String>,
    status: Text,
    outcome: Option<String>,
    termination_reason: Option<String>,
    resources: Option<Resources>,
    network_policy: Option<Network>,
}
/// A create's answer: 200 with `status` when Tensorlake waited, 202 with
/// `state` when it accepted the sandbox pending.
#[derive(Deserialize)]
struct Created {
    sandbox_id: Text,
    #[serde(alias = "state")]
    status: Text,
}
#[derive(Deserialize)]
struct Resources {
    cpus: Amount,
    memory_mb: Amount,
    disk_mb: Amount,
}
#[derive(Serialize)]
struct SizeRequest {
    cpus: f64,
    memory_mb: u64,
    disk_mb: u64,
}
#[derive(Serialize, Deserialize, Default)]
struct Network {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow_internet_access: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allow_out: Vec<String>,
    #[serde(default, skip_serializing)]
    deny_out: Vec<String>,
}
#[derive(Serialize)]
struct CreateSandbox<'a> {
    name: &'a str,
    image: &'a str,
    resources: SizeRequest,
    timeout_secs: u64,
    auto_resume: bool,
    wait: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<Network>,
}
#[derive(Serialize)]
struct CreateBuild<'a> {
    kind: &'static str,
    dockerfile_path: &'static str,
    parents: [&'static str; 0],
    build_args: BTreeMap<&'static str, &'static str>,
    name: &'a str,
    disk_mb: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_credentials_json: Option<String>,
}
#[derive(Deserialize)]
struct Build {
    build_id: Text,
    context_upload: Option<ContextUpload>,
}
#[derive(Deserialize)]
struct ContextUpload {
    url: Text,
}
#[derive(Deserialize)]
struct BuildConflict {
    code: Option<String>,
    active_build_id: Option<Text>,
}
#[derive(Serialize)]
struct Seal {
    digest: String,
}
#[derive(Deserialize)]
struct BuildState {
    status: Text,
    error: Option<String>,
}
#[derive(Deserialize)]
struct Snapshot {
    snapshot_id: Option<Text>,
    id: Option<Text>,
    sandbox_id: Option<String>,
    status: Option<String>,
}
#[derive(Serialize)]
struct RunRequest<'a> {
    command: &'static str,
    args: [&'a str; 2],
    user: &'static str,
    env: BTreeMap<&'a str, String>,
}
#[derive(Deserialize)]
struct RunEvent {
    line: Option<String>,
    stream: Option<String>,
    exit_code: Option<i64>,
    signal: Option<i64>,
}
#[async_trait]
impl Module for TensorlakeModule {
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn smallest_size(&self) -> Size {
        Size { cpus: 1.0, memory_bytes: GIB, disk_bytes: DISK_MB.start() * MIB }
    }
    async fn configure(&self, name: &str, config: &ProviderConfiguration, http: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
        let settings: Settings =
            serde_json::from_value(serde_json::json!(config.settings)).map_err(|e| refused(format!("invalid Tensorlake settings: {e}")))?;
        let api = Api::new(TENSORLAKE, &settings.api_url, Auth::Bearer, http)?.classify(classify);
        if settings.project_id.as_deref().is_some_and(|p| p.is_empty() || p.trim() != p)
            || settings.max_cpus == 0
            || settings.max_memory < GIB
            || [settings.poll_interval_ms, settings.build_poll_seconds, settings.upload_seconds].contains(&0)
            || settings.build_polls == 0
            || settings.sandbox_domain.is_empty()
            || !settings.sandbox_domain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(refused(
                "Tensorlake requires a sandbox_domain host name, a tunnel port, a project_id without surrounding spaces when set, and positive \
                 max_cpus, max_memory, poll_interval_ms, build_poll_seconds, build_polls and upload_seconds",
            ));
        }
        Ok(Arc::new(Tensorlake { name: name.to_owned(), settings, api, dialer: self.dialer.clone() }))
    }
}

pub struct Tensorlake {
    name: String,
    settings: Settings,
    api: Api,
    dialer: Arc<dyn WebSocketDialer>,
}

// Guest-plane and Image Service refusals carry `error`; plan limits are 400s
// whose text names the quota or capacity.
fn classify(f: &Failure) -> ProtocolError {
    #[derive(Deserialize)]
    struct Refusal {
        error: String,
    }
    let text =
        serde_json::from_slice::<Refusal>(f.body).map_or_else(|_| f.message(), |r| kit::api::cut(&r.error, kit::api::EXPLANATION_CHARS));
    let lower = text.to_ascii_lowercase();
    match f.status {
        400 if lower.contains("quota") || lower.contains("capacity") => ProtocolError::QuotaExhausted { reason: f.reason(&text) },
        _ => f.standard(f.reason(&text)),
    }
}
const fn paging(rows: &'static str) -> Paging {
    Paging { rows: Some(rows), cursor: "cursor", next: Next::Body(&["next_cursor", "cursor"]) }
}
fn platform() -> Platform {
    Platform::new("linux", "amd64")
}

impl Tensorlake {
    fn guest(&self, id: &str, segments: &[&str]) -> Result<Url> {
        // The proxy host is the sandbox's id or name, as one DNS label.
        if !name_valid(id) {
            return Err(ProtocolError::NotFound { reason: "not a Tensorlake sandbox id".into() });
        }
        let base = Url::parse(&format!("https://{id}.{}/api/v1", self.settings.sandbox_domain)).map_err(|_| TENSORLAKE.bad_response())?;
        kit::api::join(&base, segments)
    }
    async fn paged<T: serde::de::DeserializeOwned>(&self, segments: &[&str], rows: &'static str, c: &Credentials) -> Result<Vec<T>> {
        let mut url = self.api.url(segments)?;
        url.query_pairs_mut().append_pair("limit", "100");
        self.api.paged(url, &paging(rows), c).await
    }
    async fn sandbox(&self, id: &str, c: &Credentials) -> Result<Sandbox> {
        self.api.get(self.api.url(&["sandboxes", id])?, c).await
    }
    /// A terminated sandbox, which Tensorlake keeps by id for its retention window.
    async fn archived(&self, id: &str, c: &Credentials) -> Result<Option<Sandbox>> {
        self.api.find(self.api.url(&["archived-sandboxes", id])?, c).await
    }
    async fn snapshots(&self, sandbox_id: &str, c: &Credentials) -> Result<Vec<Snapshot>> {
        let rows = match self.paged(&["sandboxes", sandbox_id, "snapshots"], "snapshots", c).await {
            Err(ProtocolError::NotFound { .. }) => self.paged(&["snapshots"], "snapshots", c).await?,
            rows => rows?,
        };
        Ok(rows.into_iter().filter(|s: &Snapshot| s.sandbox_id.as_deref() == Some(sandbox_id)).collect())
    }
    fn tags(&self, name: Option<&str>) -> Option<BTreeMap<String, String>> {
        tags(&self.name, name?)
    }
    fn environment(&self, v: Sandbox) -> Result<Environment> {
        let whole = |n: Amount| (n.get().fract() == 0.0 && n.get() <= u32::MAX as f64).then_some(n.get() as u64);
        let r = v.resources.as_ref();
        let granted_size = kit::granted(
            TENSORLAKE,
            r.and_then(|r| whole(r.cpus)),
            r.and_then(|r| whole(r.memory_mb)),
            MIB,
            r.and_then(|r| whole(r.disk_mb)),
            MIB,
        )?;
        let tags = self.tags(v.name.as_deref());
        Ok(Environment {
            label: tags.as_ref().and_then(|t| t.get(LABEL_TAG).cloned()),
            id: v.id.to_string(),
            provider: self.name.clone(),
            state: kit::observe(STATES, &v.status),
            granted_size,
            // No claim: drydockd's conformance verdict says whether the policy holds.
            egress: Enforcement::Advisory,
            // Tensorlake states no platform for a sandbox.
            platform: None,
            egress_measured: false,
            egress_policy: Some(Policy::read(v.network_policy.as_ref()).fingerprint()),
            // Tensorlake's rows say when the sandbox was made, not when it got to its state.
            timestamp: None,
            vendor: Some(VendorState { state: v.status.into(), reason: reason(v.outcome, v.termination_reason), tags }),
        })
    }
    // The SDK reads a 400 from the name lookup as "not registered", as it does a 404.
    async fn image_exists(&self, name: &str, c: &Credentials) -> Result<bool> {
        let url = self.api.url(&["images", "v4", "images", "name", name])?;
        let operation = kit::api::operation(&Method::GET, &url);
        let response = self.api.send(Method::GET, url, Body::None, c, true, &[]).await?;
        match response.status().as_u16() {
            400 | 404 => Ok(false),
            _ => self.api.answer::<IgnoredAny>(&operation, &response).map(|_| true),
        }
    }
    async fn build(&self, r: &PrepareRequest, base: &ImageRef, name: &str, c: &Credentials) -> Result<()> {
        let context = build_context(&platform_dockerfile(&r.image_digest, &platform()))?;
        let body = CreateBuild {
            kind: "dockerfile",
            dockerfile_path: "Dockerfile",
            parents: [],
            build_args: BTreeMap::new(),
            name,
            disk_mb: *DISK_MB.start(),
            registry_credentials_json: r.image_pull.as_ref().map(|pull| registry_credentials(&base.registry, pull)).transpose()?,
        };
        let attempt = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
        let key = &kit::digest(&format!("{name}\0{attempt}"))[..32];
        let headers = [(HeaderName::from_static("idempotency-key"), HeaderValue::from_str(key).map_err(|_| TENSORLAKE.bad_response())?)];
        let url = self.api.url(&["images", "v4", "builds"])?;
        let operation = kit::api::operation(&Method::POST, &url);
        let response = self.api.send(Method::POST, url, Body::json(&body)?, c, true, &headers).await?;
        let (id, upload) = if response.status() == 409 {
            match serde_json::from_slice::<BuildConflict>(response.body()) {
                Ok(BuildConflict { code: Some(code), active_build_id: Some(active) }) if code == "image_build_in_progress" => {
                    (active, None)
                }
                _ => return Err(self.api.failure(&operation, &response)),
            }
        } else {
            let build: Build = self.api.answer(&operation, &response)?;
            (build.build_id, build.context_upload)
        };
        if let Some(upload) = upload {
            let url = Url::parse(&upload.url).ok().filter(|u| u.scheme() == "https").ok_or_else(|| TENSORLAKE.bad_response())?;
            let seal = Seal { digest: format!("{:x}", Sha256::digest(&context)) };
            // The presigned URL carries its own authorization.
            let response = self.api.send(Method::PUT, url, Body::Bytes(context.into(), "application/octet-stream"), c, false, &[]).await?;
            self.api.answer::<IgnoredAny>("PUT build context", &response)?;
            let url = self.api.url(&["images", "v4", "builds", &id, "context", "seal"])?;
            self.api.call::<IgnoredAny>(Method::POST, url, Body::json(&seal)?, c).await?;
        }
        // Tensorlake offers no other way to learn that a build finished, and
        // nothing of drydockd's observes prepared forms: prepare waits here.
        let (polls, interval) = (self.settings.build_polls, Duration::from_secs(self.settings.build_poll_seconds));
        let built = kit::poll(polls, interval, async || {
            let build: BuildState = self.api.get(self.api.url(&["images", "v4", "builds", &id])?, c).await?;
            match &*build.status {
                "succeeded" => Ok(Some(())),
                "failed" => Err(refused(match build.error {
                    Some(error) => format!("Tensorlake image build {id} failed: {error}"),
                    None => format!("Tensorlake image build {id} failed"),
                })),
                "cancelled" => Err(ProtocolError::unavailable(format!("Tensorlake image build {id} was cancelled"), None)),
                _ => Ok(None),
            }
        })
        .await?;
        built.ok_or_else(|| ProtocolError::unavailable(format!("Tensorlake image build {id} is still running"), Some(30)))
    }
    fn resources(&self, size: &Size) -> Result<SizeRequest> {
        let (memory_mb, disk_mb, cpus) = (size.memory_bytes / MIB, size.disk_bytes / MIB, size.cpus);
        let limit = |what: &str| refused(format!("Tensorlake sandbox size: {what}"));
        if !cpus.is_finite() || cpus.fract() != 0.0 || cpus < 1.0 || cpus > f64::from(self.settings.max_cpus) {
            return Err(limit(&format!("1 to {} whole vCPUs", self.settings.max_cpus)));
        }
        let whole = cpus as u64;
        if !size.memory_bytes.is_multiple_of(MIB)
            || memory_mb < MEMORY_MB_PER_CPU.start() * whole
            || memory_mb > MEMORY_MB_PER_CPU.end() * whole
            || size.memory_bytes > self.settings.max_memory
        {
            return Err(limit(&format!("whole MiB of RAM, 1 to 8 GiB per vCPU and at most {} MiB", self.settings.max_memory / MIB)));
        }
        if !size.disk_bytes.is_multiple_of(MIB) || !DISK_MB.contains(&disk_mb) {
            return Err(limit("whole MiB of disk, 10 to 100 GiB"));
        }
        Ok(SizeRequest { cpus, memory_mb, disk_mb })
    }
}

// processes/run streams output as server-sent events of UTF-8 lines, other
// bytes replaced; POST /processes echoes args unescaped, so it is not used.
fn guest_output(events: &[u8]) -> Result<GuestOutput> {
    let mut output = GuestOutput::default();
    let text = String::from_utf8_lossy(events);
    for event in text.lines().filter_map(|l| serde_json::from_str::<RunEvent>(l.strip_prefix("data:")?.trim()).ok()) {
        if let Some(line) = event.line {
            output.chunks.push((event.stream.as_deref() == Some("stderr"), format!("{line}\n").into_bytes()));
        }
        let exit = match (event.exit_code, event.signal) {
            (Some(code), _) => Some(i32::try_from(code).ok()),
            (None, Some(signal)) => Some(i32::try_from(signal).ok().filter(|s| (1..128).contains(s)).map(|s| 128 + s)),
            _ => None,
        };
        if let Some(exit) = exit {
            output.exit = Some(exit.ok_or_else(|| TENSORLAKE.bad_response())?);
        }
    }
    Ok(output)
}
/// Tensorlake's outcome and its reason, or its termination reason, verbatim.
fn reason(outcome: Option<String>, reason: Option<String>) -> Option<String> {
    match (outcome, reason) {
        (Some(outcome), Some(reason)) => Some(format!("{outcome}: {reason}")),
        (outcome, reason) => outcome.or(reason),
    }
}
// The builder decodes every numeric tar header field; ustar leaves uid and gid NUL.
fn build_context(dockerfile: &str) -> Result<Vec<u8>> {
    let mut archive = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_ustar();
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    let internal = |e: std::io::Error| ProtocolError::Internal { reason: "build context".into(), provider_error: e.to_string() };
    archive.append_data(&mut header, "Dockerfile", dockerfile.as_bytes()).map_err(internal)?;
    archive.into_inner().map_err(internal)
}
fn registry_credentials(registry: &str, pull: &RegistryCredential) -> Result<String> {
    use base64::Engine;
    #[derive(Serialize)]
    struct DockerConfig<'a> {
        auths: BTreeMap<&'a str, DockerAuth>,
    }
    #[derive(Serialize)]
    struct DockerAuth {
        auth: String,
    }
    let server = if registry == "docker.io" { "https://index.docker.io/v1/" } else { registry };
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", pull.username, pull.secret.expose()));
    serde_json::to_string(&DockerConfig { auths: BTreeMap::from([(server, DockerAuth { auth })]) })
        .map_err(|e| ProtocolError::Internal { reason: "registry credentials".into(), provider_error: e.to_string() })
}

#[derive(Debug, Clone, PartialEq)]
struct Policy(Option<Rules>);
#[derive(Debug, Clone, PartialEq)]
struct Rules {
    /// Absent when Tensorlake's policy leaves it out.
    allow_internet_access: Option<bool>,
    allow_out: BTreeSet<String>,
}
impl Policy {
    // Hostname rules resolve only with allow_internet_access, which with an
    // empty list would be open: https://docs.tensorlake.ai/sandboxes/networking#network-configuration-summary
    fn request(request: &EgressRequest) -> Result<Self> {
        let EgressRequest::DenyAll { direct } = request else { return Ok(Self(None)) };
        let (mut addresses, mut names) = (BTreeSet::new(), BTreeSet::new());
        for destination in direct {
            match destination {
                Destination::HostPort { .. } => return Err(refused("Tensorlake egress rules cannot restrict ports")),
                Destination::Cidr { cidr } => {
                    addresses.insert(normal_cidr(cidr.as_str()).ok_or_else(|| refused("Tensorlake egress takes IPv4 CIDRs only"))?);
                }
                Destination::Host { host } => {
                    let host = normal_host(host.as_str());
                    if ipv6(&host) {
                        return Err(refused("Tensorlake egress takes no IPv6 destinations"));
                    }
                    if host.parse::<Ipv4Addr>().is_ok() {
                        addresses.insert(host)
                    } else {
                        names.insert(host)
                    };
                }
            }
        }
        Ok(Self(Some(Rules { allow_internet_access: Some(!names.is_empty()), allow_out: addresses.into_iter().chain(names).collect() })))
    }
    fn wire(&self) -> Option<Network> {
        let rules = self.0.as_ref()?;
        Some(Network {
            allow_internet_access: rules.allow_internet_access,
            allow_out: rules.allow_out.iter().cloned().collect(),
            deny_out: vec![],
        })
    }
    /// A policy as Tensorlake reports it: none is open egress, and a policy
    /// leaving `allow_internet_access` out is kept apart from one stating it.
    fn read(network: Option<&Network>) -> Self {
        let Some(network) = network else { return Self(None) };
        let normal = |item: &String| {
            let item = normal_host(item);
            normal_cidr(&item).filter(|_| item.contains('/')).unwrap_or(item)
        };
        let allow_internet_access = network.allow_internet_access;
        let mut allow_out: BTreeSet<String> = network.allow_out.iter().map(normal).collect();
        allow_out.extend(network.deny_out.iter().map(|d| format!("!{}", normal(d))));
        if allow_internet_access == Some(true) && allow_out.is_empty() {
            return Self(None);
        }
        Self(Some(Rules { allow_internet_access, allow_out }))
    }
    fn fingerprint(&self) -> String {
        kit::digest(&match &self.0 {
            None => "open".to_owned(),
            Some(rules) => {
                let internet = rules.allow_internet_access.map_or("unstated".to_owned(), |allowed| allowed.to_string());
                format!("{internet}\0{}", rules.allow_out.iter().cloned().collect::<Vec<_>>().join("\0"))
            }
        })
    }
}

// Sandboxes carry no labels, so the name holds the label: as itself, as
// base32, or as a digest that can't be read back.
fn sandbox_prefix(instance: &str) -> String {
    format!("dd-{}-", &kit::digest(instance)[..8])
}
const NAME_LIMIT: usize = 63;
fn sandbox_name(instance: &str, label: &str) -> String {
    let prefix = sandbox_prefix(instance);
    let room = NAME_LIMIT - prefix.len() - 2;
    if !label.is_empty()
        && label.len() <= room
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.ends_with('-')
    {
        return format!("{prefix}r-{label}");
    }
    let encoded = base32(label.as_bytes());
    if !label.is_empty() && encoded.len() <= room {
        return format!("{prefix}b-{encoded}");
    }
    format!("{prefix}h-{}", &kit::digest(&format!("{instance}\0{label}"))[..40])
}
/// Sandboxes carry no labels or metadata: the name an instance gave a sandbox
/// is the only mark that it is that instance's, and holds its label. Tags are
/// reported only for a name `instance`'s prefix starts (the owner's decision
/// on drydock#287). drydock#296, snapshots left on a shared account, is about
/// drydockd's guard, not these tags.
fn tags(instance: &str, name: &str) -> Option<BTreeMap<String, String>> {
    let prefix = sandbox_prefix(instance);
    name.starts_with(&prefix).then(|| {
        let label = label_of(&prefix, name).map(|label| (LABEL_TAG.to_owned(), label));
        [(OWNER_TAG.to_owned(), instance.to_owned())].into_iter().chain(label).collect()
    })
}
fn label_of(prefix: &str, name: &str) -> Option<String> {
    let rest = name.strip_prefix(prefix)?;
    if let Some(label) = rest.strip_prefix("r-") {
        return Some(label.to_owned());
    }
    String::from_utf8(unbase32(rest.strip_prefix("b-")?)?).ok()
}
fn name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_LIMIT
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.ends_with('-')
}
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
fn base32(bytes: &[u8]) -> String {
    let mut text = String::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for byte in bytes {
        buffer = buffer << 8 | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            text.push(BASE32[(buffer >> bits & 31) as usize] as char);
        }
    }
    if bits > 0 {
        text.push(BASE32[(buffer << (5 - bits) & 31) as usize] as char);
    }
    text
}
fn unbase32(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for c in text.bytes() {
        buffer = buffer << 5 | BASE32.iter().position(|b| *b == c)? as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits & 0xff) as u8);
        }
    }
    (buffer & ((1 << bits) - 1) == 0).then_some(bytes)
}
fn image_name(image: &str, platform: &Platform) -> String {
    content_name("dd-", 40, &[image, &platform.to_string()])
}

fn egress_model() -> EgressModel {
    const NETWORKING: &str = "https://docs.tensorlake.ai/sandboxes/networking";
    use EgressShape::*;
    EgressModel {
        shapes: vec![Open, DenyAll, AllowAddresses, AllowDomains],
        enforced: EnforcementSite::OutsideGuest,
        side_effects: vec![EgressSideEffect {
            shapes: vec![AllowDomains],
            opens: vec![],
            note: "Hostname entries need allow_internet_access, which also allows DNS to the sandbox's resolvers.".into(),
        }],
        mutable_while_running: true,
        sources: vec![
            format!("{NETWORKING}#outbound-internet-access"),
            format!("{NETWORKING}#network-configuration-summary"),
            format!("{NETWORKING}#update-the-policy-on-a-running-sandbox"),
        ],
    }
}

#[async_trait]
impl Provider for Tensorlake {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            material_modes: vec![MaterialMode::Frozen],
            checkout_strategies: vec![CheckoutStrategy::CloneInVessel],
            workspace_root: "/workspace".into(),
            suspend_resume: true,
            suspend_preserves_memory: Some(true),
            export: false,
            egress: EgressCapability {
                routes: vec![EgressRoute::None, EgressRoute::ExplicitProxy, EgressRoute::Open],
                model: egress_model(),
            },
            fallback_runner: true,
            bootstrap: BootstrapRoute::Upload,
            agent: true,
            agent_tcp_port: Some(self.settings.tunnel_port),
            // A name Tensorlake already holds is refused, not returned.
            exclusive_label: false,
            platforms: vec![platform()],
            image_routes: vec![ImageRoute::RegistryPull {
                auth: RegistryAuthKind::Basic,
                registration: CredentialRegistration::PerRequest,
                digest_references: true,
                tools_layer: ToolsLayer::Upload,
            }],
            // Usage is to be read as Tensorlake gives it (drydock#257).
            usage: false,
            quota: false,
            host_filesystem: false,
            host_processes: false,
            // The agent carries outward exposures; the sandbox has no network of drydockd's.
            reach_ways: vec![ReachWay::OutwardExposure],
            // Create, suspend and resume answer once Tensorlake accepted them,
            // a second create of a name is refused (409), list and delete
            // reach the whole project, and resume needs only the id.
            semantics: Semantics { settles: false, idempotent: false, owner_scoped: false, token_is_id: true },
        }
    }
    /// Tensorlake's webhooks are registered in its dashboard, per project, and
    /// signed through Svix. Reading them needs `project_id`.
    fn ways_in(&self) -> Vec<WayIn> {
        let poll = WayIn::Poll { interval_ms: self.settings.poll_interval_ms };
        let webhook = self.settings.project_id.is_some().then(|| WayIn::Webhook {
            registration: vec![WebhookRegistration::Dashboard],
            events: EVENTS.iter().map(|e| (*e).to_owned()).collect(),
            delivery: DeliveryGuarantee::AtLeastOnce,
        });
        [poll].into_iter().chain(webhook).collect()
    }
    fn operations(&self) -> Operations<'_> {
        Operations {
            exec: Some(self),
            files: Some(self),
            suspend_resume: Some(self),
            events: self.settings.project_id.is_some().then_some(self as &dyn VendorEvents),
            ..Operations::default()
        }
    }
    async fn prepare(&self, r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
        let (_, platform) = check_prepare(TENSORLAKE, &r, &[ImageRouteKind::RegistryPull], &self::platform())?;
        let base = ImageRef::parse(&r.image_digest)?;
        if let Some(private) = private_host(&base.registry) {
            return Err(refused(format!(
                "Tensorlake's builders cannot reach the private registry {}{}; stage the image in a registry they can reach",
                base.registry,
                private.detail()
            )));
        }
        self.resources(&r.size)?;
        let name = image_name(&r.image_digest, &platform);
        if !self.image_exists(&name, c).await? {
            self.build(&r, &base, &name, c).await?;
        }
        Ok(Prepared { provider: self.name.clone(), id: name, platform, image_digest: r.image_digest, tools_digest: r.tools_digest })
    }
    /// One create, answered with what Tensorlake's answer states. Tensorlake
    /// refuses a name it already holds (409), in its own words.
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        check_prepared(TENSORLAKE, &self.name, &r.prepared, &image_name(&r.prepared.image_digest, &r.prepared.platform))?;
        let policy = Policy::request(&r.egress)?;
        let name = sandbox_name(&self.name, &r.label);
        let body = CreateSandbox {
            name: &name,
            image: &r.prepared.id,
            resources: self.resources(&r.size)?,
            timeout_secs: 0,
            // A suspended sandbox stays so until resumed: proxy traffic, such
            // as a relay or a command, does not wake it.
            auto_resume: false,
            wait: false,
            network: policy.wire(),
        };
        let v: Created = self.api.call(Method::POST, self.api.url(&["sandboxes"])?, Body::json(&body)?, c).await?;
        Ok(Provisioned::Created(Environment {
            id: v.sandbox_id.to_string(),
            label: Some(r.label),
            provider: self.name.clone(),
            state: kit::observe(STATES, &v.status),
            granted_size: None,
            egress: Enforcement::Advisory,
            platform: None,
            egress_measured: false,
            egress_policy: None,
            timestamp: None,
            vendor: Some(VendorState { state: v.status.into(), reason: None, tags: self.tags(Some(&name)) }),
        }))
    }
    /// Every sandbox Tensorlake lists, in whatever state it reports.
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        let rows: Vec<Sandbox> = self.paged(&["sandboxes"], "sandboxes", c).await?;
        rows.into_iter().map(|row| self.environment(row)).collect()
    }
    /// One read by id; a sandbox Tensorlake no longer lists is read from its archive.
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        match self.sandbox(id, c).await {
            Err(ProtocolError::NotFound { reason }) => match self.archived(id, c).await? {
                Some(row) => self.environment(row),
                None => Err(ProtocolError::NotFound { reason }),
            },
            row => self.environment(row?),
        }
    }
    /// The delete, then the snapshot sweep: a Tensorlake sandbox leaves
    /// snapshots (one per suspend) that its delete does not remove and that
    /// bill until deleted, so destroy needs this second call. A sandbox
    /// Tensorlake no longer knows is not found, after the sweep: a retry
    /// after a sweep that failed still finishes it.
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        let deleted = self.api.call::<IgnoredAny>(Method::DELETE, self.api.url(&["sandboxes", id])?, Body::None, c).await;
        let deleted = absent_on_not_found(deleted)?;
        for snapshot in self.snapshots(id, c).await? {
            if snapshot.status.as_deref() == Some("deleting") {
                continue;
            }
            let snapshot_id = snapshot.snapshot_id.or(snapshot.id).ok_or_else(|| TENSORLAKE.bad_response())?;
            // A snapshot already gone is what the sweep is for.
            absent_on_not_found(
                self.api.call::<IgnoredAny>(Method::DELETE, self.api.url(&["snapshots", &snapshot_id])?, Body::None, c).await,
            )?;
        }
        deleted.map(drop).ok_or_else(|| ProtocolError::NotFound { reason: format!("Tensorlake has no sandbox {id}") })
    }
    async fn reach(&self, id: &str, _: &Credentials) -> Result<Reach> {
        Ok(Reach::relay(&self.name, id))
    }
    /// A dial to a sandbox that isn't running fails with Tensorlake's answer.
    async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream> {
        let url = self.guest(id, &["tunnels", "tcp"])?;
        let host = url.host_str().ok_or_else(|| TENSORLAKE.bad_response())?;
        let url = format!("wss://{host}{}?port={}", url.path(), self.settings.tunnel_port);
        let headers = HeaderMap::from_iter([(http::header::AUTHORIZATION, self.api.key(c)?)]);
        let token = Token::parse(self.agent_token(id, c).await?.expose()).map_err(|_| TENSORLAKE.bad_response())?;
        let socket = self.dialer.dial(&url, headers).await.map_err(|error| match error {
            DialError::Refused { status, body } => {
                classify(&Failure { vendor: TENSORLAKE, operation: "tunnel", status, body: body.as_bytes(), retry_after: None })
            }
            DialError::Io(error) => ProtocolError::Unavailable {
                reason: "Tensorlake tunnel transport failed".into(),
                retry_after: None,
                provider_error: Some(error.to_string()),
            },
        })?;
        let connected = tcp::connect(websocket::stream(socket, TUNNEL_FRAME), &token).await;
        connected.map(|stream| Box::new(stream) as ByteStream).map_err(|error| ProtocolError::Unavailable {
            reason: "the agent's TCP listener did not accept the tunnel".into(),
            retry_after: None,
            provider_error: Some(error.to_string()),
        })
    }
}

/// Suspend and resume. Tensorlake resumes by id alone, so the token is the id.
#[async_trait]
impl SuspendResume for Tensorlake {
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        self.api.call::<IgnoredAny>(Method::POST, self.api.url(&["sandboxes", id, "suspend"])?, Body::None, c).await?;
        Ok(ResumeToken { token: Secret::new(id) })
    }
    async fn resume(&self, id: &str, _: ResumeToken, c: &Credentials) -> Result<()> {
        self.api.call::<IgnoredAny>(Method::POST, self.api.url(&["sandboxes", id, "resume"])?, Body::None, c).await.map(drop)
    }
}

const EVENTS: [&str; 6] = [
    "tensorlake.sandbox.created",
    "tensorlake.sandbox.running",
    "tensorlake.sandbox.suspended",
    "tensorlake.sandbox.resumed",
    "tensorlake.sandbox.terminated",
    "tensorlake.sandbox.failed",
];
/// A sandbox event's envelope, as recorded from Tensorlake on 2026-11-06,
/// only the fields read. Deliveries are not ordered: drydockd's comparison of
/// `occurred_at` with what it holds keeps a late one from overtaking a newer
/// one, so `source_revision` and `source_ordinal` are not read.
#[derive(Deserialize)]
struct Delivered {
    project_id: String,
    occurred_at: DateTime<Utc>,
    data: DeliveredData,
}
#[derive(Deserialize)]
struct DeliveredData {
    sandbox: DeliveredSandbox,
}
#[derive(Deserialize)]
struct DeliveredSandbox {
    id: Text,
    name: Option<String>,
    status: Text,
    outcome: Option<String>,
    outcome_reason: Option<String>,
}
/// Each sandbox event states the sandbox, Tensorlake's status for it, and its
/// outcome once it terminated. Any other event, or one for another project,
/// says nothing drydock follows.
#[async_trait]
impl VendorEvents for Tensorlake {
    async fn event(&self, delivery: VendorDelivery) -> Result<Vec<VendorObservation>> {
        let event = delivery.event.as_str();
        if !EVENTS.contains(&event) {
            return Ok(vec![]);
        }
        let project = self.settings.project_id.as_deref().ok_or_else(|| refused("Tensorlake events need project_id"))?;
        let v: Delivered = serde_json::from_value(delivery.body).map_err(|e| refused(format!("Tensorlake {event} body: {e}")))?;
        if v.project_id != project {
            return Ok(vec![]);
        }
        let s = v.data.sandbox;
        Ok(vec![VendorObservation {
            id: s.id.to_string(),
            state: Some(kit::observe(STATES, &s.status)),
            vendor: VendorState { tags: self.tags(s.name.as_deref()), reason: reason(s.outcome, s.outcome_reason), state: s.status.into() },
            timestamp: Some(v.occurred_at.into()),
        }])
    }
}

#[async_trait]
impl Guest for Tensorlake {
    fn vendor(&self) -> Vendor {
        TENSORLAKE
    }
    async fn run(&self, id: &str, script: &str, env: BTreeMap<&str, String>, c: &Credentials) -> Result<GuestOutput> {
        // A run's `timeout` kills its whole process tree when it expires, even
        // after the call has returned, so a detached agent would die with it:
        // https://docs.tensorlake.ai/api-reference/openapi.yaml (SandboxRunProcessRequest)
        let body = RunRequest { command: "sh", args: ["-c", script], user: "root", env };
        let url = self.guest(id, &["processes", "run"])?;
        let operation = kit::api::operation(&Method::POST, &url);
        let response = self.api.send(Method::POST, url, Body::json(&body)?, c, true, &[]).await?;
        if !response.status().is_success() {
            return Err(self.api.failure(&operation, &response));
        }
        guest_output(response.body())
    }
}
#[async_trait]
impl Exec for Tensorlake {
    async fn exec(&self, id: &str, r: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        Guest::exec(self, id, r, c).await
    }
}
// The file API writes as the image's user and sets no mode, so the file is
// staged and installed as root: https://docs.tensorlake.ai/api-reference/openapi.yaml (PUT /api/v1/files)
#[async_trait]
impl GuestFiles for Tensorlake {
    async fn put(&self, id: &str, file: GuestFile, bytes: Bytes, c: &Credentials) -> Result<()> {
        let staging = format!("/tmp/drydock-upload-{}", &kit::digest(&file.path)[..16]);
        let mut url = self.guest(id, &["files"])?;
        url.query_pairs_mut().append_pair("path", &staging);
        let deadline = Duration::from_secs(self.settings.upload_seconds);
        self.api.call_within::<IgnoredAny>(Method::PUT, url, Body::Bytes(bytes, "application/octet-stream"), c, deadline).await?;
        let install =
            kit::shell_command(&["install".into(), "-D".into(), "-m".into(), format!("{:04o}", file.mode), staging.clone(), file.path]);
        let remove = kit::shell_command(&["rm".into(), "-f".into(), staging]);
        self.run(id, &format!("{install}; status=$?; {remove}; exit $status"), BTreeMap::new(), c).await?.success(TENSORLAKE).map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rigging_http_client::ChannelLabel;
    use std::sync::Mutex;

    /// Answers each request with the next scripted (status, body), keeping
    /// each request's method and path.
    #[derive(Default)]
    struct Script {
        answers: Mutex<Vec<(u16, &'static str)>>,
        asked: Mutex<Vec<(String, String)>>,
    }
    #[async_trait]
    impl HttpClient for Script {
        async fn execute(&self, request: reqwest::Request, _: &ChannelLabel) -> std::result::Result<http::Response<Bytes>, String> {
            self.asked.lock().unwrap().push((request.method().to_string(), request.url().path().to_owned()));
            let (status, body) = {
                let mut answers = self.answers.lock().unwrap();
                assert!(!answers.is_empty(), "unscripted request {} {}", request.method(), request.url());
                answers.remove(0)
            };
            Ok(http::Response::builder().status(status).body(Bytes::from_static(body.as_bytes())).unwrap())
        }
    }
    fn script(answers: &[(u16, &'static str)]) -> Arc<Script> {
        Arc::new(Script { answers: Mutex::new(answers.to_vec()), ..Script::default() })
    }
    async fn configure(settings: serde_json::Value, script: Arc<Script>) -> Result<Arc<dyn Provider>> {
        let config = ProviderConfiguration {
            module: "tensorlake".into(),
            settings: serde_json::from_value(settings).unwrap(),
            ..Default::default()
        };
        TensorlakeModule::with_dialer(Arc::new(TlsDialer::new().unwrap())).configure("lab", &config, script).await
    }
    fn credentials() -> Credentials {
        Credentials::new(Some(Secret::new("tl_apiKey_test")))
    }

    // Every setting has a default; zeroes, a project id with spaces around
    // it and keys the module no longer reads are refused.
    #[tokio::test]
    async fn settings_refuse_zeroes_and_unknown_keys() {
        assert!(configure(serde_json::json!({}), Arc::default()).await.is_ok());
        for refused in [
            serde_json::json!({"project_id": ""}),
            serde_json::json!({"project_id": " project_123"}),
            serde_json::json!({"build_polls": 0}),
            serde_json::json!({"build_poll_seconds": 0}),
            serde_json::json!({"upload_seconds": 0}),
            serde_json::json!({"poll_interval_ms": 0}),
            serde_json::json!({"organization_id": "org"}),
        ] {
            let result = configure(refused.clone(), Arc::default()).await;
            assert!(matches!(result, Err(ProtocolError::Refused { .. })), "{refused}");
        }
    }
    // The webhook way in, and the port that reads it, need the project id:
    // without it no delivery could be told from another project's.
    #[tokio::test]
    async fn webhooks_need_the_project_id() {
        let webhook = |p: &Arc<dyn Provider>| p.ways_in().iter().any(|w| matches!(w, WayIn::Webhook { .. }));
        let without = configure(serde_json::json!({}), Arc::default()).await.unwrap();
        assert!(!webhook(&without) && without.operations().events.is_none());
        let with = configure(serde_json::json!({"project_id": "project_1"}), Arc::default()).await.unwrap();
        assert!(webhook(&with) && with.operations().events.is_some());
    }
    // An event the module does not read says nothing; a sandbox event whose
    // body is not Tensorlake's envelope is refused, and drydockd skips it.
    #[tokio::test]
    async fn events_outside_the_sandbox_envelope() {
        let provider = configure(serde_json::json!({"project_id": "project_1"}), Arc::default()).await.unwrap();
        let events = provider.operations().events.unwrap();
        let delivery = |event: &str, body: serde_json::Value| VendorDelivery {
            event: event.into(),
            delivery_id: "evt_1".into(),
            received_at: "2026-11-06T17:07:15Z".parse().unwrap(),
            body,
        };
        let other = events.event(delivery("tensorlake.application.created", serde_json::json!({"project_id": "project_1"}))).await;
        assert_eq!(other.unwrap(), vec![]);
        let malformed = events.event(delivery("tensorlake.sandbox.running", serde_json::json!({"project_id": "project_1"}))).await;
        assert!(matches!(malformed, Err(ProtocolError::Refused { .. })), "{malformed:?}");
    }
    // Provision is one create, answered with what Tensorlake's answer states;
    // a name Tensorlake already holds is refused in its words.
    #[tokio::test]
    async fn provision_is_one_create() {
        let script = script(&[(202, r#"{"sandbox_id":"sbx1","name":"n","state":"pending"}"#), (409, "sandbox name already exists")]);
        let provider = configure(serde_json::json!({}), script.clone()).await.unwrap();
        let prepared = Prepared {
            provider: "lab".into(),
            id: image_name("image@sha256:aa", &platform()),
            platform: platform(),
            image_digest: "image@sha256:aa".into(),
            tools_digest: "tools".into(),
        };
        let request = ProvisionRequest {
            label: "crew-1".into(),
            prepared,
            size: Size { cpus: 1.0, memory_bytes: GIB, disk_bytes: 10 * GIB },
            egress: EgressRequest::Open,
            ssh_public_key: None,
        };
        let made = provider.provision(request.clone(), &credentials()).await.unwrap().into_inner();
        assert_eq!((made.id.as_str(), made.label.as_deref(), &made.state), ("sbx1", Some("crew-1"), &kit::starting()));
        let vendor = made.vendor.unwrap();
        assert_eq!((vendor.state.as_str(), vendor.tags), ("pending", tags("lab", &sandbox_name("lab", "crew-1"))));
        let refused = provider.provision(request, &credentials()).await;
        assert!(matches!(&refused, Err(ProtocolError::Refused { reason }) if reason.contains("already exists")), "{refused:?}");
        assert_eq!(*script.asked.lock().unwrap(), [("POST".into(), "/sandboxes".into()), ("POST".into(), "/sandboxes".into())]);
    }
    // Destroy deletes, then sweeps the snapshots the delete leaves. A retry
    // once Tensorlake has forgotten the sandbox still sweeps, then answers not found.
    #[tokio::test]
    async fn destroy_sweeps_snapshots_even_when_the_sandbox_is_gone() {
        let snapshots = r#"{"snapshots":[{"snapshot_id":"snap1","sandbox_id":"sbx1"},{"snapshot_id":"snap2","sandbox_id":"sbx1","status":"deleting"}]}"#;
        let script = script(&[(200, ""), (200, snapshots), (200, "{}"), (404, "Sandbox not found"), (200, snapshots), (404, "gone")]);
        let provider = configure(serde_json::json!({}), script.clone()).await.unwrap();
        provider.destroy("sbx1", &credentials()).await.unwrap();
        assert!(matches!(provider.destroy("sbx1", &credentials()).await, Err(ProtocolError::NotFound { .. })));
        let sweep = [
            ("DELETE".to_owned(), "/sandboxes/sbx1".to_owned()),
            ("GET".into(), "/sandboxes/sbx1/snapshots".into()),
            ("DELETE".into(), "/snapshots/snap1".into()),
        ];
        assert_eq!(*script.asked.lock().unwrap(), [sweep.clone(), sweep].concat());
    }

    // Output lines keep their stream; a signal is 128 plus its number, and an
    // exit status outside what a process can have is a bad response.
    #[test]
    fn run_events() {
        let events = "event: output\ndata: {\"line\":\"out\",\"stream\":\"stdout\"}\n\ndata: {\"line\":\"err\",\"stream\":\"stderr\"}\n\ndata: {\"exit_code\":null,\"signal\":9}\n";
        let output = guest_output(events.as_bytes()).unwrap();
        assert_eq!((output.stdout(), output.bytes(None), output.exit_code()), (b"out\n".to_vec(), b"out\nerr\n".to_vec(), 137));
        assert!(guest_output(b"data: {\"exit_code\":4294967296}\n").is_err());
        assert!(guest_output(b"data: {\"signal\":-1}\n").is_err());
        assert!(guest_output(b"data: {\"signal\":0}\n").is_err());
    }
    // A name this instance made carries its owner tag and the label it holds,
    // even one only a digest keeps; another instance's names carry none.
    #[test]
    fn names_carry_their_instance_and_label() {
        let tagged = |instance: &str, label: &str| tags(instance, &sandbox_name(instance, label));
        let expect = |label: Option<&str>| {
            let label = label.map(|l| (LABEL_TAG.to_owned(), l.to_owned()));
            Some([(OWNER_TAG.to_owned(), "lab".to_owned())].into_iter().chain(label).collect())
        };
        assert_eq!(tagged("lab", "crew-1"), expect(Some("crew-1")));
        assert_eq!(tagged("lab", "Crew/1"), expect(Some("Crew/1")));
        assert_eq!(tagged("lab", &"x".repeat(80)), expect(None));
        assert_eq!(tags("lab", &sandbox_name("other", "crew-1")), None);
        assert_eq!(tags("lab", "build-runner"), None);
    }
    // A policy leaving allow_internet_access out is not the one stating it,
    // and none at all is open.
    #[test]
    fn egress_fingerprint_keeps_unstated_apart() {
        let read = |v: serde_json::Value| Policy::read(Some(&serde_json::from_value(v).unwrap())).fingerprint();
        let open = Policy::read(None).fingerprint();
        assert_eq!(read(serde_json::json!({"allow_internet_access": true})), open);
        assert_ne!(read(serde_json::json!({})), open);
        assert_ne!(
            read(serde_json::json!({"allow_out": ["10.0.0.0/8"]})),
            read(serde_json::json!({"allow_internet_access": true, "allow_out": ["10.0.0.0/8"]}))
        );
        let request = Policy::request(&EgressRequest::DenyAll { direct: vec![] }).unwrap();
        assert_eq!(Policy::read(request.wire().as_ref()), request);
    }
}

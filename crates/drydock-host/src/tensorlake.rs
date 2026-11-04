//! Tensorlake sandboxes, reached through the sandbox proxy's TCP tunnel to the
//! agent's token-gated listener. API: https://docs.tensorlake.ai/api-reference/openapi.yaml;
//! the Image Service, snapshots and usage follow the SDK
//! (https://github.com/tensorlakeai/tensorlake, crates/cloud-sdk).
use crate::{
    kit::{
        self, GIB, MIB, StateTable, Vendor,
        api::{Amount, Api, Auth, Body, Failure, Next, Paging, Text, absent_on_not_found},
        egress::{ipv6, normal_cidr, normal_host, private_host},
        guest::{Guest, GuestOutput},
        image::{check_prepare, check_prepared, content_name, platform_dockerfile},
    },
    module::*,
    oci::ImageRef,
};
use async_trait::async_trait;
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
    collections::{BTreeMap, BTreeSet, HashMap},
    net::Ipv4Addr,
    num::NonZeroU16,
    sync::{Arc, Mutex},
    time::Duration,
};

const TENSORLAKE: Vendor = Vendor("Tensorlake");
// The tunnel proxy drops a connection that carries a frame over 64 KiB.
const TUNNEL_FRAME: usize = 64 << 10;
const DISK_MB: std::ops::RangeInclusive<u64> = 10_240..=102_400;
const MEMORY_MB_PER_CPU: std::ops::RangeInclusive<u64> = 1024..=8192;
const TOKEN_FILE: &str = "/run/drydock/tcp-token";
const AGENT: &str = "/opt/drydock/drydock-agent";
const BUILD_POLL: Duration = Duration::from_secs(3);
const BUILD_POLLS: u32 = 150;
const STATE_POLL: Duration = Duration::from_secs(1);
const STATE_POLLS: u32 = 120;
const UPLOAD_DEADLINE: Duration = Duration::from_secs(300);
const RESUME: &str = "tensorlake-resume-";
const STATES: StateTable = &[
    ("pending", kit::starting()),
    ("running", Observation::Running),
    ("snapshotting", Observation::Transitioning { phase: TransitionPhase::Reconfiguring }),
    ("suspending", kit::stopping()),
    ("suspended", kit::stopped(StopCause::SuspendedByRequest)),
    ("terminated", Observation::Gone { cause: GoneCause::DestroyedAtProvider }),
    ("resume_failed", Observation::Unknown { reason: UnknownReason::ProviderApiError }),
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default = "api_url")]
    api_url: String,
    #[serde(default = "sandbox_domain")]
    sandbox_domain: String,
    #[serde(default = "tunnel_port")]
    tunnel_port: NonZeroU16,
    #[serde(default = "max_cpus")]
    max_cpus: u32,
    #[serde(default = "max_memory")]
    max_memory: u64,
    #[serde(default = "poll_interval_ms")]
    poll_interval_ms: u64,
}
fn api_url() -> String {
    "https://api.tensorlake.ai/".into()
}
fn sandbox_domain() -> String {
    "sandbox.tensorlake.ai".into()
}
fn tunnel_port() -> NonZeroU16 {
    const { NonZeroU16::new(7811).unwrap() }
}
fn max_cpus() -> u32 {
    4
}
fn max_memory() -> u64 {
    16 * GIB
}
fn poll_interval_ms() -> u64 {
    30_000
}

#[derive(Deserialize)]
struct Sandbox {
    id: Text,
    name: Option<Text>,
    status: Text,
    resources: Option<Resources>,
    network_policy: Option<Network>,
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
#[derive(Deserialize)]
struct CreateFailure {
    status: Option<String>,
    termination_reason: Option<String>,
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
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum UsageRecord {
    Window {
        #[serde(rename = "attributedUsageCharge")]
        charge: Option<Charge>,
    },
    Sandbox {
        resources: BTreeMap<String, UsageQuantity>,
    },
    End {
        count: u64,
    },
    #[serde(other)]
    Other,
}
#[derive(Deserialize)]
struct UsageQuantity {
    quantity: String,
    unit: String,
}
#[derive(Deserialize)]
struct Charge {
    currency: String,
    #[serde(rename = "amountMinor")]
    amount_minor: String,
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
        if settings.organization_id.as_deref().is_some_and(str::is_empty)
            || settings.max_cpus == 0
            || settings.max_memory < GIB
            || settings.poll_interval_ms == 0
            || settings.sandbox_domain.is_empty()
            || !settings.sandbox_domain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(refused(
                "Tensorlake requires a sandbox_domain host name, a tunnel port, and positive max_cpus, max_memory and poll_interval_ms",
            ));
        }
        Ok(Arc::new(Tensorlake { name: name.to_owned(), settings, api, dialer: self.dialer.clone(), tokens: Mutex::default() }))
    }
}

pub struct Tensorlake {
    name: String,
    settings: Settings,
    api: Api,
    dialer: Arc<dyn WebSocketDialer>,
    tokens: Mutex<HashMap<String, Token>>,
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
fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Tensorlake {
    fn guest(&self, id: &str, segments: &[&str]) -> Result<Url> {
        if !name_valid(id) {
            return Err(ProtocolError::NotFound { reason: "not a Tensorlake sandbox name".into() });
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
    async fn status(&self, id: &str, c: &Credentials) -> Result<String> {
        Ok(self.sandbox(id, c).await?.status.into())
    }
    // Archived records are addressed by id in the SDK; a name the direct
    // lookup doesn't know is found in the archive list.
    async fn archived(&self, id: &str, c: &Credentials) -> Result<Option<Sandbox>> {
        if let Some(row) = self.api.find(self.api.url(&["archived-sandboxes", id])?, c).await? {
            return Ok(Some(row));
        }
        let rows: Vec<Sandbox> = self.paged(&["archived-sandboxes"], "sandboxes", c).await?;
        Ok(rows.into_iter().find(|row| row.name.as_deref() == Some(id)))
    }
    async fn snapshots(&self, sandbox_id: &str, c: &Credentials) -> Result<Vec<Snapshot>> {
        let rows = match self.paged(&["sandboxes", sandbox_id, "snapshots"], "snapshots", c).await {
            Err(ProtocolError::NotFound { .. }) => self.paged(&["snapshots"], "snapshots", c).await?,
            rows => rows?,
        };
        Ok(rows.into_iter().filter(|s: &Snapshot| s.sandbox_id.as_deref() == Some(sandbox_id)).collect())
    }
    fn environment(&self, v: &Sandbox) -> Result<Environment> {
        let name = v.name.as_deref().ok_or_else(|| TENSORLAKE.bad_response())?;
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
        Ok(Environment {
            label: label_of(&sandbox_prefix(&self.name), name),
            id: name.to_owned(),
            provider: self.name.clone(),
            state: kit::observe(STATES, &v.status),
            granted_size,
            egress: Enforcement::Advisory,
            platform: Some(platform()),
            egress_measured: false,
            egress_policy: Some(Policy::read(v.network_policy.as_ref()).fingerprint()),
            timestamp: None,
        })
    }
    async fn token(&self, id: &str, c: &Credentials) -> Result<Token> {
        if let Some(token) = locked(&self.tokens).get(id) {
            return Ok(token.clone());
        }
        let output = self.run(id, &format!("{AGENT} --print-token --tcp-token-file {TOKEN_FILE}"), BTreeMap::new(), c).await?;
        let stdout = String::from_utf8_lossy(&output.success(TENSORLAKE)?.stdout()).into_owned();
        let token =
            stdout.lines().find_map(|line| line.strip_prefix("drydock-tcp-token ")).and_then(|line| Token::parse(line).ok()).ok_or_else(
                || ProtocolError::Internal { reason: "the agent's TCP token was not read back".into(), provider_error: String::new() },
            )?;
        locked(&self.tokens).insert(id.to_owned(), token.clone());
        Ok(token)
    }
    async fn wait_running(&self, id: &str, c: &Credentials) -> Result<()> {
        let running = kit::poll(STATE_POLLS, STATE_POLL, async || match self.status(id, c).await?.as_str() {
            "running" => Ok(Some(())),
            "terminated" | "resume_failed" => Err(refused(format!("Tensorlake sandbox {id} stopped before it ran"))),
            _ => Ok(None),
        })
        .await?;
        running.ok_or_else(|| ProtocolError::unavailable("Tensorlake sandbox has not started", Some(5)))
    }
    async fn adopt(&self, row: Sandbox, size: &Size, policy: &Policy, c: &Credentials) -> Result<Environment> {
        let existing = self.environment(&row)?;
        if existing.granted_size.as_ref() != Some(size) || &Policy::read(row.network_policy.as_ref()) != policy {
            return Err(refused(
                "an existing Tensorlake sandbox holds this label with a different size or egress policy; provision a new label",
            ));
        }
        if &*row.status == "pending" {
            self.wait_running(&existing.id, c).await?;
            return self.inspect(&existing.id, c).await;
        }
        Ok(existing)
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
        let built = kit::poll(BUILD_POLLS, BUILD_POLL, async || {
            let build: BuildState = self.api.get(self.api.url(&["images", "v4", "builds", &id])?, c).await?;
            match &*build.status {
                "succeeded" => Ok(Some(())),
                "failed" => {
                    Err(refused(format!("Tensorlake image build {id} failed: {}", build.error.as_deref().unwrap_or("no error recorded"))))
                }
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
fn guest_output(events: &[u8]) -> GuestOutput {
    let mut output = GuestOutput::default();
    let text = String::from_utf8_lossy(events);
    for event in text.lines().filter_map(|l| serde_json::from_str::<RunEvent>(l.strip_prefix("data:")?.trim()).ok()) {
        if let Some(line) = event.line {
            output.chunks.push((event.stream.as_deref() == Some("stderr"), format!("{line}\n").into_bytes()));
        }
        match (event.exit_code, event.signal) {
            (Some(code), _) => output.exit = Some(i32::try_from(code).unwrap_or(-1)),
            (None, Some(signal)) => output.exit = Some(128 + i32::try_from(signal).unwrap_or(0)),
            _ => {}
        }
    }
    output
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
    allow_internet_access: bool,
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
        Ok(Self(Some(Rules { allow_internet_access: !names.is_empty(), allow_out: addresses.into_iter().chain(names).collect() })))
    }
    fn wire(&self) -> Option<Network> {
        let rules = self.0.as_ref()?;
        Some(Network {
            allow_internet_access: Some(rules.allow_internet_access),
            allow_out: rules.allow_out.iter().cloned().collect(),
            deny_out: vec![],
        })
    }
    fn read(network: Option<&Network>) -> Self {
        let Some(network) = network else { return Self(None) };
        let normal = |item: &String| {
            let item = normal_host(item);
            normal_cidr(&item).filter(|_| item.contains('/')).unwrap_or(item)
        };
        let allow_internet_access = network.allow_internet_access.unwrap_or(true);
        let mut allow_out: BTreeSet<String> = network.allow_out.iter().map(normal).collect();
        allow_out.extend(network.deny_out.iter().map(|d| format!("!{}", normal(d))));
        if allow_internet_access && allow_out.is_empty() {
            return Self(None);
        }
        Self(Some(Rules { allow_internet_access, allow_out }))
    }
    fn fingerprint(&self) -> String {
        kit::digest(&match &self.0 {
            None => "open".to_owned(),
            Some(rules) => format!("{}\0{}", rules.allow_internet_access, rules.allow_out.iter().cloned().collect::<Vec<_>>().join("\0")),
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
            exclusive_label: true,
            platforms: vec![platform()],
            image_routes: vec![ImageRoute::RegistryPull {
                auth: RegistryAuthKind::Basic,
                registration: CredentialRegistration::PerRequest,
                digest_references: true,
                tools_layer: ToolsLayer::Upload,
            }],
            usage: self.settings.organization_id.is_some(),
            quota: false,
            host_filesystem: false,
        }
    }
    fn observation(&self) -> ObservationMode {
        ObservationMode::Poll { interval_ms: self.settings.poll_interval_ms }
    }
    fn operations(&self) -> Operations<'_> {
        Operations {
            exec: Some(self),
            files: Some(self),
            suspend_resume: Some(self),
            usage: self.settings.organization_id.is_some().then_some(self as &dyn UsageOperation),
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
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        check_prepared(TENSORLAKE, &self.name, &r.prepared, &image_name(&r.prepared.image_digest, &r.prepared.platform))?;
        let policy = Policy::request(&r.egress)?;
        let name = sandbox_name(&self.name, &r.label);
        let body = CreateSandbox {
            name: &name,
            image: &r.prepared.id,
            resources: self.resources(&r.size)?,
            timeout_secs: 0,
            auto_resume: true,
            wait: true,
            network: policy.wire(),
        };
        let url = self.api.url(&["sandboxes"])?;
        let operation = kit::api::operation(&Method::POST, &url);
        let response = self.api.send(Method::POST, url, Body::json(&body)?, c, true, &[]).await?;
        match response.status().as_u16() {
            409 => return Ok(Provisioned::Existing(self.adopt(self.sandbox(&name, c).await?, &r.size, &policy, c).await?)),
            422 => {
                if let Ok(CreateFailure { status: Some(status), termination_reason }) = serde_json::from_slice(response.body())
                    && status == "failed"
                {
                    let reason = termination_reason.as_deref().unwrap_or("unknown");
                    return Err(refused(format!("Tensorlake sandbox failed to start: {reason}")));
                }
                return Err(self.api.failure(&operation, &response));
            }
            200..=299 | 504 => {}
            _ => return Err(self.api.failure(&operation, &response)),
        }
        self.wait_running(&name, c).await?;
        Ok(Provisioned::Created(self.inspect(&name, c).await?))
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        let prefix = sandbox_prefix(&self.name);
        let rows: Vec<Sandbox> = self.paged(&["sandboxes"], "sandboxes", c).await?;
        rows.iter()
            .filter(|row| row.name.as_deref().is_some_and(|name| name.starts_with(&prefix)))
            .map(|row| self.environment(row))
            .filter(|row| !matches!(row, Ok(Environment { state: Observation::Gone { .. }, .. })))
            .collect()
    }
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        match self.sandbox(id, c).await {
            Err(ProtocolError::NotFound { reason }) => match self.archived(id, c).await? {
                Some(mut row) => {
                    row.status = Text::try_from("terminated".to_owned()).map_err(|_| TENSORLAKE.bad_response())?;
                    self.environment(&row)
                }
                None => Err(ProtocolError::NotFound { reason }),
            },
            row => self.environment(&row?),
        }
    }
    // Every suspend leaves a snapshot that outlives the sandbox and bills until deleted.
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        let sandbox_id = match self.sandbox(id, c).await {
            Err(ProtocolError::NotFound { .. }) => self.archived(id, c).await?.map(|row| row.id.to_string()),
            row => Some(row?.id.to_string()),
        };
        absent_on_not_found(self.api.call::<IgnoredAny>(Method::DELETE, self.api.url(&["sandboxes", id])?, Body::None, c).await)?;
        locked(&self.tokens).remove(id);
        let Some(sandbox_id) = sandbox_id else { return Ok(()) };
        let mut remaining = 0;
        for snapshot in self.snapshots(&sandbox_id, c).await? {
            if snapshot.status.as_deref() == Some("deleting") {
                continue;
            }
            let snapshot_id = snapshot.snapshot_id.or(snapshot.id).ok_or_else(|| TENSORLAKE.bad_response())?;
            let url = self.api.url(&["snapshots", &snapshot_id])?;
            if absent_on_not_found(self.api.call::<IgnoredAny>(Method::DELETE, url, Body::None, c).await).is_err() {
                remaining += 1;
            }
        }
        if remaining > 0 {
            return Err(ProtocolError::unavailable(format!("{remaining} Tensorlake snapshots of {id} remain; retry destroy"), Some(10)));
        }
        Ok(())
    }
    async fn reach(&self, id: &str, _: &Credentials) -> Result<Reach> {
        Ok(Reach::relay(&self.name, id))
    }
    // A tunnel to a suspended sandbox would wake it.
    async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream> {
        if self.status(id, c).await? != "running" {
            return Err(refused(format!("Tensorlake sandbox {id} is not running; resume it first")));
        }
        let url = self.guest(id, &["tunnels", "tcp"])?;
        let host = url.host_str().ok_or_else(|| TENSORLAKE.bad_response())?;
        let url = format!("wss://{host}{}?port={}", url.path(), self.settings.tunnel_port);
        let headers = HeaderMap::from_iter([(http::header::AUTHORIZATION, self.api.key(c)?)]);
        let (url, headers) = (&url, &headers);
        let connect = |token: Token| async move {
            let socket = self.dialer.dial(url, headers.clone()).await.map_err(|error| match error {
                DialError::Refused { status, body } => {
                    classify(&Failure { vendor: TENSORLAKE, operation: "tunnel", status, body: body.as_bytes(), retry_after: None })
                }
                DialError::Io(error) => ProtocolError::Unavailable {
                    reason: "Tensorlake tunnel transport failed".into(),
                    retry_after: None,
                    provider_error: Some(error.to_string()),
                },
            })?;
            Ok::<_, ProtocolError>(tcp::connect(websocket::stream(socket, TUNNEL_FRAME), &token).await)
        };
        let mut connected = connect(self.token(id, c).await?).await?;
        if connected.as_ref().is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied) {
            locked(&self.tokens).remove(id);
            connected = connect(self.token(id, c).await?).await?;
        }
        connected.map(|stream| Box::new(stream) as ByteStream).map_err(|error| ProtocolError::Unavailable {
            reason: "the agent's TCP listener did not accept the tunnel".into(),
            retry_after: None,
            provider_error: Some(error.to_string()),
        })
    }
}

#[async_trait]
impl SuspendResume for Tensorlake {
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        let status = self.status(id, c).await?;
        if matches!(status.as_str(), "pending" | "resuming") {
            return Err(ProtocolError::unavailable(format!("Tensorlake sandbox {id} is {status}"), Some(5)));
        }
        if status == "running" {
            self.api.call::<IgnoredAny>(Method::POST, self.api.url(&["sandboxes", id, "suspend"])?, Body::None, c).await?;
        }
        let suspended = kit::poll(STATE_POLLS, STATE_POLL, async || match self.status(id, c).await?.as_str() {
            "suspended" => Ok(Some(TENSORLAKE.resume_marker(RESUME, &self.name, id))),
            "suspending" | "snapshotting" | "running" => Ok(None),
            other => Err(refused(format!("Tensorlake sandbox {id} is {other}, not suspending"))),
        })
        .await?;
        suspended.ok_or_else(|| ProtocolError::unavailable("Tensorlake sandbox has not suspended", Some(5)))
    }
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()> {
        TENSORLAKE.check_resume(RESUME, &self.name, id, &token)?;
        locked(&self.tokens).remove(id);
        if self.status(id, c).await? != "running" {
            let mut url = self.api.url(&["sandboxes", id, "resume"])?;
            url.query_pairs_mut().append_pair("wait_ms", "30000");
            self.api.call::<IgnoredAny>(Method::POST, url, Body::None, c).await?;
            self.wait_running(id, c).await?;
        }
        Ok(())
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
        Ok(guest_output(response.body()))
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
        self.api.call_within::<IgnoredAny>(Method::PUT, url, Body::Bytes(bytes, "application/octet-stream"), c, UPLOAD_DEADLINE).await?;
        let install =
            kit::shell_command(&["install".into(), "-D".into(), "-m".into(), format!("{:04o}", file.mode), staging.clone(), file.path]);
        let remove = kit::shell_command(&["rm".into(), "-f".into(), staging]);
        self.run(id, &format!("{install}; status=$?; {remove}; exit $status"), BTreeMap::new(), c).await?.success(TENSORLAKE).map(drop)
    }
}

#[async_trait]
impl UsageOperation for Tensorlake {
    async fn usage(&self, period: Period, c: &Credentials) -> Result<Usage> {
        let organization = self.settings.organization_id.as_deref().ok_or_else(|| refused("Tensorlake usage needs organization_id"))?;
        let stamp = |t: &Timestamp| t.instant().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut url = self.api.url(&["platform", "v1", "organizations", organization, "sandbox-usage", "sandboxes", "export"])?;
        url.query_pairs_mut().append_pair("fromDate", &stamp(period.start())).append_pair("toDate", &stamp(period.end()));
        let operation = kit::api::operation(&Method::GET, &url);
        let response = self.api.send(Method::GET, url, Body::None, c, true, &[]).await?;
        if !response.status().is_success() {
            return Err(self.api.failure(&operation, &response));
        }
        let (resources, cost) = usage_export(response.body())?;
        Ok(Usage {
            period,
            environment_hours: vec![],
            measurements: Some(UsageMeasurements { scope: UsageScope::Organization { id: organization.to_owned() }, resources, cost }),
        })
    }
}
// The export is NDJSON: a window, one record per sandbox, then an end record
// with the count; a missing or disagreeing end is a truncated export.
fn usage_export(body: &[u8]) -> Result<(BTreeMap<ResourceKind, Quantity>, Option<Cost>)> {
    let mut resources: BTreeMap<ResourceKind, Quantity> = BTreeMap::new();
    let mut add = |kind, unit: &str, amount: f64| {
        resources.entry(kind).or_insert_with(|| Quantity { amount: 0.0, unit: unit.into() }).amount += amount
    };
    let (mut charge, mut sandboxes, mut end) = (None, 0u64, None);
    for line in String::from_utf8_lossy(body).lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<UsageRecord>(line).map_err(|_| TENSORLAKE.bad_response())? {
            UsageRecord::Window { charge: window } => charge = Some(window),
            UsageRecord::Sandbox { resources: quantities } => {
                sandboxes += 1;
                for (key, kind, unit, expected, factor) in [
                    ("cpu", ResourceKind::Cpu, "{vCPU}.s", "vCPU-hour", 3600.0),
                    ("memory", ResourceKind::Memory, "By.s", "GiB-hour", GIB as f64 * 3600.0),
                    ("sandboxStorage", ResourceKind::Disk, "By.s", "GiB-hour", GIB as f64 * 3600.0),
                    ("snapshotStorage", ResourceKind::SnapshotStorage, "By.s", "GiB-hour", GIB as f64 * 3600.0),
                ] {
                    let Some(q) = quantities.get(key) else { continue };
                    let amount = q.quantity.parse::<f64>().ok().filter(|a| a.is_finite() && *a >= 0.0 && q.unit == expected);
                    add(kind, unit, amount.ok_or_else(|| TENSORLAKE.bad_response())? * factor);
                }
            }
            UsageRecord::End { count } => end = Some(count),
            UsageRecord::Other => {}
        }
    }
    if end != Some(sandboxes) {
        return Err(ProtocolError::unavailable("Tensorlake usage export ended early", Some(30)));
    }
    add(ResourceKind::Environments, "1", sandboxes as f64);
    let cost = charge.ok_or_else(|| TENSORLAKE.bad_response())?.map(minor_to_cost).transpose()?;
    Ok((resources, cost))
}
fn minor_to_cost(charge: Charge) -> Result<Cost> {
    let currency = charge.currency.to_ascii_uppercase();
    let minor = &charge.amount_minor;
    if !["USD", "EUR", "GBP"].contains(&currency.as_str()) || minor.is_empty() || !minor.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TENSORLAKE.bad_response());
    }
    let minor = format!("{minor:0>3}");
    let (major, cents) = minor.split_at(minor.len() - 2);
    let major = major.trim_start_matches('0');
    Ok(Cost { amount: format!("{}.{cents}", if major.is_empty() { "0" } else { major }), currency })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_events() {
        let events = "event: output\ndata: {\"line\":\"out\",\"stream\":\"stdout\"}\n\ndata: {\"line\":\"err\",\"stream\":\"stderr\"}\n\ndata: {\"exit_code\":null,\"signal\":9}\n";
        let output = guest_output(events.as_bytes());
        assert_eq!((output.stdout(), output.bytes(None), output.exit_code()), (b"out\n".to_vec(), b"out\nerr\n".to_vec(), 137));
    }
    #[test]
    fn usage_export_lines() {
        let window = r#"{"type":"window","attributedUsageCharge":{"currency":"usd","amountMinor":"1234"}}"#;
        let sandbox =
            r#"{"type":"sandbox","resources":{"cpu":{"quantity":"1.5","unit":"vCPU-hour"},"networkEgress":{"quantity":"1","unit":"GiB"}}}"#;
        let (resources, cost) = usage_export(format!("{window}\n{sandbox}\n{{\"type\":\"end\",\"count\":1}}\n").as_bytes()).unwrap();
        assert_eq!(resources[&ResourceKind::Cpu].amount, 5400.0);
        assert_eq!(cost.unwrap().amount, "12.34");
        assert!(usage_export(format!("{window}\n{sandbox}\n").as_bytes()).is_err());
    }
}

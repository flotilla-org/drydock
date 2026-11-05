//! E2B translator: each verb is E2B's own operation, and each answer is what
//! E2B said. Waiting, idempotence and ownership are drydockd's, as the
//! declared [`Semantics`] leave them (see `capabilities`).
//! API contract: https://github.com/e2b-dev/infra (spec/openapi.yml; packages/envd/spec).
use crate::{
    kit::{
        self, LABEL_TAG, MIB, PROVIDER_TAG, SizeLimits, Vendor,
        api::{Api, Auth, Body, EXPLANATION_CHARS, Failure, Next, Paging, Text, absent_on_not_found, cut, sensitive},
        egress::{Resolver, SystemResolver, ipv6, normal_cidr, normal_host, private_registry},
        guest::{Guest, GuestOutput},
        image::{check_prepare, content_name},
    },
    module::*,
    oci::{ImageRef, Registry},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use drydock_protocol::*;
use drydock_transport::tcp::CONNECT_PATH;
use reqwest::{
    Method, Url,
    header::{AUTHORIZATION, HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned, de::IgnoredAny};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

const E2B: Vendor = Vendor("E2B");
const ENVD_PORT: u16 = 49983;
const AGENT_PORT: u16 = 7811;
const PRINT_TOKEN: &str = "/opt/drydock/drydock-agent --print-token --tcp-token-file /run/drydock/tcp-token";
const TOKEN_LINE: &str = "drydock-tcp-token ";
const TRAFFIC_HEADER: &str = "e2b-traffic-access-token";
const SANDBOX_PAGES: Paging = Paging { rows: None, cursor: "nextToken", next: Next::Header("x-next-token") };

#[derive(Serialize)]
struct NewTemplate<'a> {
    name: &'a str,
    #[serde(rename = "cpuCount")]
    cpus: u64,
    #[serde(rename = "memoryMB")]
    memory_mb: u64,
}
#[derive(Deserialize)]
struct TemplateCreated {
    #[serde(rename = "templateID")]
    template: Text,
    #[serde(rename = "buildID")]
    build: Text,
}
#[derive(Deserialize)]
struct Alias {
    #[serde(rename = "templateID")]
    template: Text,
}
#[derive(Deserialize)]
struct Template {
    #[serde(rename = "templateID")]
    id: Text,
    #[serde(default)]
    builds: Vec<TemplateBuild>,
}
#[derive(Deserialize)]
struct TemplateBuild {
    #[serde(rename = "buildID")]
    id: Text,
    status: Text,
}
#[derive(Serialize)]
struct BuildStart<'a> {
    #[serde(rename = "fromImage")]
    from_image: &'a str,
    #[serde(rename = "fromImageRegistry", skip_serializing_if = "Option::is_none")]
    registry: Option<RegistryLogin<'a>>,
    steps: Vec<Step>,
}
#[derive(Serialize)]
struct RegistryLogin<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    username: &'a str,
    password: &'a str,
}
#[derive(Serialize)]
struct Step {
    #[serde(rename = "type")]
    kind: &'static str,
    args: Vec<String>,
}
#[derive(Deserialize)]
struct BuildStatus {
    status: Text,
    reason: Option<BuildMessage>,
    #[serde(rename = "logEntries", default)]
    logs: Vec<BuildMessage>,
}
#[derive(Deserialize)]
struct BuildMessage {
    message: String,
}
#[derive(Deserialize)]
struct ImageConfig {
    config: Option<ImageEnv>,
}
#[derive(Deserialize)]
struct ImageEnv {
    #[serde(rename = "Env", default)]
    env: Vec<String>,
}
#[derive(Serialize)]
struct NewSandbox<'a> {
    #[serde(rename = "templateID")]
    template: &'a str,
    timeout: u32,
    #[serde(rename = "autoPause")]
    auto_pause: bool,
    metadata: &'a BTreeMap<String, String>,
    network: Network,
}
#[derive(Serialize, Deserialize)]
struct Network {
    #[serde(rename = "allowPublicTraffic", skip_serializing_if = "Option::is_none")]
    public_traffic: Option<bool>,
    #[serde(rename = "denyOut", default, skip_serializing_if = "Vec::is_empty")]
    deny_out: Vec<String>,
    #[serde(rename = "allowOut", default, skip_serializing_if = "Vec::is_empty")]
    allow_out: Vec<String>,
}
/// A sandbox as E2B answers it: its detail, a listed row, or a create or
/// connect answer, which carries the tokens and no state.
#[derive(Deserialize)]
struct Sandbox {
    #[serde(rename = "sandboxID")]
    id: Text,
    state: Option<Text>,
    #[serde(rename = "endAt")]
    end_at: Option<DateTime<Utc>>,
    #[serde(rename = "cpuCount")]
    cpus: Option<u64>,
    #[serde(rename = "memoryMB")]
    memory_mb: Option<u64>,
    #[serde(rename = "diskSizeMB")]
    disk_mb: Option<u64>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
    network: Option<Network>,
    #[serde(rename = "envdAccessToken")]
    envd_token: Option<String>,
    #[serde(rename = "trafficAccessToken")]
    traffic_token: Option<String>,
}
#[derive(Serialize)]
struct Connect {
    timeout: u32,
}
#[derive(Deserialize)]
struct Metric {
    #[serde(rename = "timestampUnix")]
    at: i64,
    #[serde(rename = "concurrentSandboxes")]
    concurrent: u64,
}
#[derive(Serialize)]
struct ProcessStart<'a> {
    process: Process<'a>,
    stdin: bool,
}
#[derive(Serialize)]
struct Process<'a> {
    cmd: &'static str,
    args: [&'a str; 2],
    envs: BTreeMap<&'a str, String>,
}
#[derive(Deserialize)]
struct StreamMessage {
    event: Option<ProcessEvent>,
    error: Option<ConnectError>,
}
#[derive(Deserialize)]
struct ProcessEvent {
    data: Option<ProcessData>,
    end: Option<ProcessEnd>,
}
#[derive(Deserialize)]
struct ProcessData {
    stdout: Option<String>,
    stderr: Option<String>,
    pty: Option<String>,
}
#[derive(Deserialize)]
struct ProcessEnd {
    #[serde(rename = "exitCode", default)]
    exit_code: i64,
    error: Option<String>,
}
#[derive(Deserialize)]
struct ConnectError {
    code: Option<String>,
    message: Option<String>,
}

pub struct E2bModule {
    resolver: Arc<dyn Resolver>,
}
impl E2bModule {
    pub fn new() -> Self {
        Self::with_resolver(Arc::new(SystemResolver))
    }
    pub fn with_resolver(resolver: Arc<dyn Resolver>) -> Self {
        Self { resolver }
    }
}
impl Default for E2bModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Every key but `team_id` has a default.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Settings {
    team_id: String,
    api_url: String,
    sandbox_url: String,
    lifetime_seconds: u32,
    disk_mb: u64,
    concurrency_limit: Option<u64>,
    rate_limits: Option<Vec<RateLimit>>,
    /// How often drydockd lists sandboxes.
    poll_interval_ms: u64,
    /// How often prepare reads a template build's status, and how many times
    /// before it answers unavailable.
    build_poll_seconds: u64,
    build_polls: u32,
    /// envd's limit on one command (`connect-timeout-ms`).
    exec_timeout_ms: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            team_id: String::new(),
            api_url: "https://api.e2b.app/".into(),
            sandbox_url: "https://{port}-{id}.e2b.app".into(),
            lifetime_seconds: 3600,
            disk_mb: 10_240,
            concurrency_limit: None,
            rate_limits: None,
            poll_interval_ms: 30_000,
            build_poll_seconds: 3,
            build_polls: 150,
            exec_timeout_ms: 25_000,
        }
    }
}
fn sandbox_url_valid(template: &str) -> bool {
    if !template.contains("{port}") || !template.contains("{id}") {
        return false;
    }
    let Ok(url) = Url::parse(&template.replace("{port}", "1").replace("{id}", "a")) else { return false };
    let loopback = url
        .host_str()
        .and_then(|h| h.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    (url.scheme() == "https" && url.host_str().is_some() || url.scheme() == "http" && loopback)
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

#[async_trait]
impl Module for E2bModule {
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn smallest_size(&self) -> Size {
        Size { cpus: 1.0, memory_bytes: 512 * MIB, disk_bytes: 1 << 30 }
    }
    async fn configure(&self, name: &str, config: &ProviderConfiguration, http: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
        let settings: Settings =
            serde_json::from_value(serde_json::json!(config.settings)).map_err(|e| refused(format!("invalid E2B settings: {e}")))?;
        let positive = [settings.disk_mb, settings.poll_interval_ms, settings.build_poll_seconds, settings.exec_timeout_ms];
        if settings.team_id.is_empty()
            || !(1..=86_400).contains(&settings.lifetime_seconds)
            || positive.contains(&0)
            || settings.build_polls == 0
            || !sandbox_url_valid(&settings.sandbox_url)
        {
            return Err(refused(
                "E2B requires team_id, a sandbox_url holding {port} and {id} (HTTPS, or HTTP to a loopback address), \
                 lifetime_seconds 1..86400, and positive disk_mb, poll_interval_ms, build_poll_seconds, build_polls \
                 and exec_timeout_ms",
            ));
        }
        let api = Api::new(E2B, &settings.api_url, Auth::Header(HeaderName::from_static("x-api-key")), http)?.classify(classify);
        Ok(Arc::new(E2b {
            name: name.to_owned(),
            ownership: config.ownership,
            settings,
            api,
            resolver: self.resolver.clone(),
            access: Mutex::default(),
            suspended: Mutex::default(),
        }))
    }
}

fn classify(f: &Failure) -> ProtocolError {
    let message = f.message();
    if f.status == 429 && message.to_ascii_lowercase().contains("concurrent") {
        return ProtocolError::QuotaExhausted { reason: f.reason(&message) };
    }
    f.standard(f.reason(&message))
}

#[derive(Clone, Default)]
struct Access {
    envd: Option<String>,
    traffic: Option<String>,
}

pub struct E2b {
    name: String,
    ownership: Ownership,
    settings: Settings,
    api: Api,
    resolver: Arc<dyn Resolver>,
    /// The tokens E2B hands out at create and connect. A detail read gives
    /// the envd token again; only connect gives the traffic token again.
    access: Mutex<HashMap<String, Access>>,
    /// Sandboxes this host paused. E2B names both its own pause and ours
    /// `paused`; this tells them apart.
    suspended: Mutex<HashSet<String>>,
}

trait Recover<T> {
    fn recover(&self) -> std::sync::MutexGuard<'_, T>;
}
impl<T> Recover<T> for Mutex<T> {
    fn recover(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn platform() -> Platform {
    Platform::new("linux", "amd64")
}
fn sandbox_id_valid(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}
fn template_name(image: &str, platform: &Platform, size: &Size) -> String {
    let (platform, cpus, memory) = (platform.to_string(), (size.cpus as u64).to_string(), (size.memory_bytes / MIB).to_string());
    content_name("drydock-", 40, &["e2b-template", image, &platform, &cpus, &memory])
}

/// `id`, refused as not found unless it has the shape of E2B's sandbox ids.
fn checked(id: &str) -> Result<&str> {
    if !sandbox_id_valid(id) {
        return Err(ProtocolError::NotFound { reason: "not an E2B sandbox id".into() });
    }
    Ok(id)
}

impl E2b {
    fn port_url(&self, id: &str, port: u16, path: &str) -> Result<Url> {
        let id = checked(id)?;
        let base = self.settings.sandbox_url.replace("{port}", &port.to_string()).replace("{id}", id);
        Url::parse(&format!("{}{path}", base.trim_end_matches('/'))).map_err(|_| E2B.bad_response())
    }
    async fn get<T: DeserializeOwned>(&self, segments: &[&str], c: &Credentials) -> Result<T> {
        self.api.get(self.api.url(segments)?, c).await
    }
    async fn post<T: DeserializeOwned>(&self, segments: &[&str], body: &impl Serialize, c: &Credentials) -> Result<T> {
        self.api.call(Method::POST, self.api.url(segments)?, Body::json(body)?, c).await
    }
    fn keep_tokens(&self, v: &Sandbox) {
        let mut access = self.access.recover();
        let access = access.entry(v.id.to_string()).or_default();
        access.envd = v.envd_token.clone().or(access.envd.take());
        access.traffic = v.traffic_token.clone().or(access.traffic.take());
    }
    fn cached(&self, id: &str) -> Access {
        self.access.recover().get(id).cloned().unwrap_or_default()
    }
    async fn sandbox(&self, id: &str, c: &Credentials) -> Result<Sandbox> {
        let v: Sandbox = self.get(&["sandboxes", checked(id)?], c).await?;
        self.keep_tokens(&v);
        Ok(v)
    }
    /// E2B's connect: resumes a paused sandbox, and answers with its tokens.
    async fn connect(&self, id: &str, c: &Credentials) -> Result<Sandbox> {
        let body = Connect { timeout: self.settings.lifetime_seconds };
        let v: Sandbox = self.post(&["v2", "sandboxes", checked(id)?, "connect"], &body, c).await?;
        self.keep_tokens(&v);
        Ok(v)
    }
    fn environment(&self, v: Sandbox) -> Result<Environment> {
        let state = match v.state.as_deref() {
            Some("running") => Observation::Running,
            Some("paused") if self.suspended.recover().contains(&*v.id) => kit::stopped(StopCause::SuspendedByRequest),
            Some("paused") => kit::stopped(StopCause::PausedByProvider),
            // A create answer carries no state.
            _ => Observation::Unknown { reason: UnknownReason::ProviderStateUnknown },
        };
        Ok(Environment {
            label: v.metadata.get(LABEL_TAG).cloned(),
            id: v.id.to_string(),
            provider: self.name.clone(),
            state,
            granted_size: kit::granted(E2B, v.cpus, v.memory_mb, MIB, v.disk_mb, MIB)?,
            egress: Enforcement::Advisory,
            platform: Some(platform()),
            egress_measured: false,
            // Only a detail read carries the network.
            egress_policy: v.network.as_ref().map(|n| Policy::read(n).fingerprint()),
            timestamp: None,
            vendor: Some(VendorState { state: v.state.map(String::from).unwrap_or_default(), reason: None, tags: Some(v.metadata) }),
        })
    }
    async fn template(&self, name: &str, c: &Credentials) -> Result<Option<Template>> {
        let Some(alias) = absent_on_not_found(self.get::<Alias>(&["templates", "aliases", name], c).await)? else { return Ok(None) };
        self.get(&["templates", &alias.template], c).await.map(Some)
    }
    async fn build(&self, r: &PrepareRequest, base: &ImageRef, name: &str, existing: Option<&Template>, c: &Credentials) -> Result<()> {
        if let Some(t) = existing
            && let Some(b) = t.builds.iter().find(|b| &*b.status == "building")
        {
            return self.await_build(&t.id, &b.id, c).await;
        }
        let registry = Registry::new(self.api.http().clone(), &base.registry, r.image_pull.clone(), None)?;
        let manifest = registry.platform_manifest(base, &platform()).await?;
        let config: ImageConfig =
            serde_json::from_slice(&registry.config(&base.repository, &manifest).await?).map_err(|_| E2B.bad_response())?;
        let body = NewTemplate { name, cpus: r.size.cpus as u64, memory_mb: r.size.memory_bytes / MIB };
        let created: TemplateCreated = self.post(&["v3", "templates"], &body, c).await?;
        let env: Vec<String> = config
            .config
            .map(|c| c.env)
            .unwrap_or_default()
            .iter()
            .filter_map(|pair| pair.split_once('='))
            .flat_map(|(k, v)| [k.to_owned(), v.to_owned()])
            .collect();
        let steps = if env.is_empty() { vec![] } else { vec![Step { kind: "ENV", args: env }] };
        let registry =
            r.image_pull.as_ref().map(|p| RegistryLogin { kind: "registry", username: &p.username, password: p.secret.expose() });
        let start = BuildStart { from_image: &r.image_digest, registry, steps };
        self.post::<IgnoredAny>(&["v2", "templates", &created.template, "builds", &created.build], &start, c).await?;
        self.await_build(&created.template, &created.build, c).await
    }
    /// The one wait this module keeps: E2B offers no other way to learn that
    /// a template build finished than reading its status, and nothing of
    /// drydockd's observes prepared forms.
    async fn await_build(&self, template: &str, build: &str, c: &Credentials) -> Result<()> {
        let interval = Duration::from_secs(self.settings.build_poll_seconds);
        kit::poll(self.settings.build_polls, interval, async || {
            let status: BuildStatus = self.get(&["templates", template, "builds", build, "status"], c).await?;
            match &*status.status {
                "ready" => Ok(Some(())),
                "error" => {
                    let reason = status.reason.map_or_else(|| "no reason recorded".into(), |r| r.message);
                    let tail: Vec<&str> = status.logs.iter().rev().take(5).rev().map(|e| e.message.as_str()).collect();
                    let text = format!("E2B template build {build} failed: {reason}\n{}", tail.join("\n"));
                    Err(refused(cut(text.trim_end(), EXPLANATION_CHARS)))
                }
                _ => Ok(None),
            }
        })
        .await?
        .ok_or_else(|| ProtocolError::unavailable(format!("E2B template build {build} is still running"), Some(30)))
    }
    fn sizes(&self) -> SizeLimits {
        SizeLimits {
            cpus: (1, 64),
            memory: (512 * MIB, u64::MAX),
            memory_step: 2 * MIB,
            disk: (1, self.settings.disk_mb * MIB),
            disk_step: 1,
        }
    }
    async fn envd(&self, id: &str, url: &Url, body: impl Fn() -> Body, c: &Credentials) -> Result<http::Response<bytes::Bytes>> {
        let operation = kit::api::operation(&Method::POST, url);
        for refreshed in [false, true] {
            let envd = match self.cached(id).envd {
                Some(token) if !refreshed => Some(token),
                _ => self.sandbox(id, c).await?.envd_token,
            };
            let mut headers = vec![
                (AUTHORIZATION, HeaderValue::from_static("Basic cm9vdDo=")),
                (HeaderName::from_static("connect-timeout-ms"), HeaderValue::from(self.settings.exec_timeout_ms)),
            ];
            if let Some(token) = envd {
                headers.push((HeaderName::from_static("x-access-token"), sensitive(&token).map_err(|_| E2B.bad_response())?));
            }
            let response = self.api.send(Method::POST, url.clone(), body(), c, false, &headers).await?;
            if response.status().is_success() {
                return Ok(response);
            }
            if response.status() != 401 || refreshed {
                return Err(self.api.failure(&operation, &response));
            }
        }
        unreachable!()
    }
    async fn agent_token(&self, id: &str, c: &Credentials) -> Result<String> {
        let run = self.run(id, PRINT_TOKEN, BTreeMap::new(), c).await?.success(E2B)?;
        let stdout = String::from_utf8_lossy(&run.stdout()).into_owned();
        stdout.lines().find_map(|line| line.strip_prefix(TOKEN_LINE)).filter(|t| !t.is_empty()).map(str::to_owned).ok_or_else(|| {
            ProtocolError::Internal { reason: "the agent's TCP token was not read back".into(), provider_error: String::new() }
        })
    }
}

#[async_trait]
impl Guest for E2b {
    fn vendor(&self) -> Vendor {
        E2B
    }
    async fn run(&self, id: &str, script: &str, envs: BTreeMap<&str, String>, c: &Credentials) -> Result<GuestOutput> {
        let message = serde_json::to_vec(&ProcessStart { process: Process { cmd: "/bin/sh", args: ["-c", script], envs }, stdin: false })
            .map_err(|_| E2B.bad_response())?;
        let url = self.port_url(id, ENVD_PORT, "/process.Process/Start")?;
        let framed = bytes::Bytes::from(envelope(0, &message));
        let response = self.envd(id, &url, || Body::Bytes(framed.clone(), "application/connect+json"), c).await?;
        parse_run(response.body())
    }
}

fn envelope(flags: u8, message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(message.len() + 5);
    framed.push(flags);
    framed.extend_from_slice(&(message.len() as u32).to_be_bytes());
    framed.extend_from_slice(message);
    framed
}
// Connect server streaming with the JSON codec: https://connectrpc.com/docs/protocol/#streaming-response
fn parse_run(mut body: &[u8]) -> Result<GuestOutput> {
    use base64::Engine;
    let decode = |chunk: &str| base64::engine::general_purpose::STANDARD.decode(chunk).map_err(|_| E2B.bad_response());
    let mut run = GuestOutput::default();
    let mut error = None;
    let mut ended = false;
    while !body.is_empty() {
        let [flags, a, b, c, d, rest @ ..] = body else { return Err(E2B.bad_response()) };
        let length = u32::from_be_bytes([*a, *b, *c, *d]) as usize;
        if flags & 1 != 0 || rest.len() < length {
            return Err(E2B.bad_response());
        }
        let message: StreamMessage = serde_json::from_slice(&rest[..length]).map_err(|_| E2B.bad_response())?;
        body = &rest[length..];
        ended |= flags & 2 != 0;
        if let Some(e) = message.error {
            error = Some(format!("{}: {}", e.code.unwrap_or_default(), e.message.unwrap_or_default()));
        }
        let Some(event) = message.event else { continue };
        if let Some(data) = event.data {
            for (stderr, chunk) in [(false, data.stdout), (true, data.stderr), (false, data.pty)] {
                if let Some(chunk) = chunk {
                    run.chunks.push((stderr, decode(&chunk)?));
                }
            }
        }
        if let Some(end) = event.end {
            run.exit = Some(i32::try_from(end.exit_code).unwrap_or(-1));
            error = error.or(end.error.filter(|e| !e.is_empty()));
        }
    }
    if !ended && run.exit.is_none() {
        return Err(ProtocolError::unavailable("E2B process stream ended early", None));
    }
    run.note = error.map(|e| format!("[envd: {e}]"));
    Ok(run)
}

struct Policy {
    deny_out: BTreeSet<String>,
    allow_out: BTreeSet<String>,
    public_traffic: bool,
}
impl Policy {
    fn request(request: &EgressRequest) -> Result<Self> {
        let mut policy = Self { deny_out: BTreeSet::new(), allow_out: BTreeSet::new(), public_traffic: false };
        let EgressRequest::DenyAll { direct } = request else { return Ok(policy) };
        policy.deny_out.insert("0.0.0.0/0".into());
        for destination in direct {
            match destination {
                Destination::HostPort { .. } => return Err(refused("E2B egress rules cannot restrict ports")),
                Destination::Cidr { cidr } => {
                    policy.allow_out.insert(normal_cidr(cidr.as_str()).ok_or_else(|| refused("E2B egress takes IPv4 CIDRs only"))?);
                }
                Destination::Host { host } if ipv6(host.as_str()) => return Err(refused("E2B egress takes no IPv6 destinations")),
                Destination::Host { host } => {
                    let host = normal_host(host.as_str());
                    policy.allow_out.insert(normal_cidr(&host).unwrap_or(host));
                }
            }
        }
        Ok(policy)
    }
    fn network(&self) -> Network {
        Network {
            public_traffic: Some(self.public_traffic),
            deny_out: self.deny_out.iter().cloned().collect(),
            allow_out: self.allow_out.iter().cloned().collect(),
        }
    }
    fn read(network: &Network) -> Self {
        let normal = |entries: &[String]| -> BTreeSet<String> {
            entries
                .iter()
                .map(|e| {
                    let e = normal_host(e);
                    normal_cidr(&e).unwrap_or(e)
                })
                .collect()
        };
        Self {
            deny_out: normal(&network.deny_out),
            allow_out: normal(&network.allow_out),
            public_traffic: network.public_traffic.unwrap_or(true),
        }
    }
    fn fingerprint(&self) -> String {
        kit::digest(&format!("{:?}", (&self.deny_out, &self.allow_out, self.public_traffic)))
    }
}

fn egress_model() -> EgressModel {
    const ACCESS: &str = "https://docs.e2b.dev/network/internet-access";
    use EgressShape::*;
    EgressModel {
        shapes: vec![Open, DenyAll, AllowAddresses, AllowDomains],
        enforced: EnforcementSite::OutsideGuest,
        side_effects: vec![
            EgressSideEffect {
                shapes: vec![AllowDomains],
                opens: vec![Destination::Cidr { cidr: "8.8.8.8/32".parse().expect("a CIDR") }],
                note: "With domains listed, E2B also allows Google's public resolver so the guest can look names up. \
                       Domain entries filter only HTTP on port 80 (Host) and TLS on 443 (SNI)."
                    .into(),
            },
            EgressSideEffect {
                shapes: vec![DenyAll, AllowAddresses, AllowDomains],
                opens: vec![],
                note: "A blocked connection may appear to succeed from inside the guest: the firewall accepts it before it decides.".into(),
            },
        ],
        mutable_while_running: true,
        sources: vec![
            format!("{ACCESS}#allow-and-deny-lists"),
            format!("{ACCESS}#domain-based-filtering"),
            format!("{ACCESS}#dns-when-you-filter-by-domain"),
            format!("{ACCESS}#updating-network-settings-on-a-running-sandbox"),
        ],
    }
}

#[async_trait]
impl Provider for E2b {
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
            platforms: vec![platform()],
            image_routes: vec![ImageRoute::RegistryPull {
                auth: RegistryAuthKind::Basic,
                registration: CredentialRegistration::PerRequest,
                digest_references: true,
                tools_layer: ToolsLayer::Upload,
            }],
            // E2B reports execution records and concurrency samples, which
            // Usage cannot carry as given (drydock#257); no figure is derived.
            usage: false,
            quota: true,
            host_filesystem: false,
            host_processes: false,
            agent_tcp_port: std::num::NonZeroU16::new(AGENT_PORT),
            exclusive_label: false,
            // The agent carries outward exposures; the sandbox has no network of drydockd's.
            reach_ways: vec![ReachWay::OutwardExposure],
            // Create and pause answer once E2B accepted them, a second pause
            // is E2B's conflict, list and kill reach the whole team, and
            // connect resumes by id alone.
            semantics: Semantics { token_is_id: true, ..Semantics::default() },
        }
    }
    fn ways_in(&self) -> Vec<WayIn> {
        vec![WayIn::Poll { interval_ms: self.settings.poll_interval_ms }]
    }
    fn operations(&self) -> Operations<'_> {
        Operations { exec: Some(self), suspend_resume: Some(self), quota: Some(self), files: Some(self), ..Operations::default() }
    }
    fn rate_limits(&self) -> Vec<RateLimit> {
        self.settings.rate_limits.clone().unwrap_or_default()
    }
    async fn prepare(&self, r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
        let (_, platform) = check_prepare(E2B, &r, &[ImageRouteKind::RegistryPull], &self::platform())?;
        self.sizes().check(E2B, &r.size)?;
        let base = ImageRef::parse(&r.image_digest)?;
        if let Some(private) = private_registry(&base.registry, self.resolver.as_ref()).await {
            return Err(refused(format!(
                "E2B pulls images over the public internet and cannot reach the private registry {}{}; stage the image in a registry it can reach",
                base.registry,
                private.detail()
            )));
        }
        let name = template_name(&r.image_digest, &platform, &r.size);
        let template = self.template(&name, c).await?;
        if !template.as_ref().is_some_and(|t| t.builds.iter().any(|b| &*b.status == "ready")) {
            self.build(&r, &base, &name, template.as_ref(), c).await?;
        }
        Ok(Prepared { provider: self.name.clone(), id: name, platform, image_digest: r.image_digest, tools_digest: r.tools_digest })
    }
    /// One create, answered with the row E2B returns: its id and tokens, no
    /// state, and the metadata it was given.
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        let mut metadata = BTreeMap::from([(LABEL_TAG.to_owned(), r.label.clone())]);
        if self.ownership == Ownership::SharedAccount {
            metadata.insert(PROVIDER_TAG.to_owned(), self.name.clone());
        }
        let body = NewSandbox {
            template: &r.prepared.id,
            timeout: self.settings.lifetime_seconds,
            auto_pause: true,
            metadata: &metadata,
            network: Policy::request(&r.egress)?.network(),
        };
        let mut created: Sandbox = self.post(&["v2", "sandboxes"], &body, c).await?;
        self.keep_tokens(&created);
        created.metadata = metadata;
        Ok(Provisioned::Created(self.environment(created)?))
    }
    /// Every sandbox E2B lists for the team, in one paged list.
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        let mut url = self.api.url(&["v2", "sandboxes"])?;
        url.query_pairs_mut().append_pair("state", "running,paused").append_pair("limit", "100");
        self.api.paged::<Sandbox>(url, &SANDBOX_PAGES, c).await?.into_iter().map(|v| self.environment(v)).collect()
    }
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        self.environment(self.sandbox(id, c).await?)
    }
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        let killed = self.api.call::<IgnoredAny>(Method::DELETE, self.api.url(&["sandboxes", checked(id)?])?, Body::None, c).await;
        if killed.is_ok() {
            self.access.recover().remove(id);
            self.suspended.recover().remove(id);
        }
        killed.map(drop)
    }
    /// The dial address of the agent's port at E2B's proxy. The detail read
    /// stays because the proxy needs the traffic token for a sandbox closed to
    /// public traffic, and only connect gives that token again, which would
    /// resume a paused sandbox: the read says whether the token is needed and
    /// that the sandbox runs.
    async fn reach(&self, id: &str, c: &Credentials) -> Result<Reach> {
        let v = self.sandbox(id, c).await?;
        if v.state.as_deref() != Some("running") {
            return Err(refused(format!("E2B sandbox {id} is not running; resume it first")));
        }
        let mut headers = BTreeMap::new();
        if !v.network.as_ref().is_some_and(|n| n.public_traffic.unwrap_or(true)) {
            let traffic = match self.cached(id).traffic {
                Some(token) => token,
                None => self.connect(id, c).await?.traffic_token.ok_or_else(|| E2B.bad_response())?,
            };
            headers.insert(TRAFFIC_HEADER.to_owned(), Secret::new(traffic));
        }
        let token = self.agent_token(id, c).await?;
        let expires_at = v.end_at.unwrap_or_else(|| Utc::now() + chrono::TimeDelta::seconds(self.settings.lifetime_seconds.into()));
        Ok(Reach::Dial {
            url: self.port_url(id, AGENT_PORT, CONNECT_PATH)?.to_string(),
            token: Secret::new(token),
            headers,
            expires_at: expires_at.into(),
        })
    }
    async fn relay(&self, _: &str, _: &Credentials) -> Result<ByteStream> {
        Err(refused("drydockd dials E2B's proxy from the reach"))
    }
}

/// Pause and connect. E2B resumes by id alone, so the token is the id.
#[async_trait]
impl SuspendResume for E2b {
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        // Marked first, so an observation of the pause never reads as E2B's own.
        let url = self.api.url(&["sandboxes", checked(id)?, "pause"])?;
        let marked = self.suspended.recover().insert(id.to_owned());
        let paused = self.api.call::<IgnoredAny>(Method::POST, url, Body::None, c).await;
        if paused.is_err() && marked {
            self.suspended.recover().remove(id);
        }
        paused.map(|_| ResumeToken { token: Secret::new(id) })
    }
    async fn resume(&self, id: &str, _: ResumeToken, c: &Credentials) -> Result<()> {
        self.connect(id, c).await?;
        self.suspended.recover().remove(id);
        Ok(())
    }
}

#[async_trait]
impl Exec for E2b {
    async fn exec(&self, id: &str, r: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        Guest::exec(self, id, r, c).await
    }
}

#[async_trait]
impl GuestFiles for E2b {
    // envd's upload sets no mode: https://github.com/e2b-dev/infra/blob/main/packages/envd/spec/envd.yaml
    async fn put(&self, id: &str, file: GuestFile, bytes: Bytes, c: &Credentials) -> Result<()> {
        let mut url = self.port_url(id, ENVD_PORT, "/files")?;
        url.query_pairs_mut().append_pair("path", &file.path).append_pair("username", "root");
        self.envd(id, &url, || Body::Bytes(bytes.clone(), "application/octet-stream"), c).await?;
        let chmod = format!("chmod {:o} {}", file.mode, kit::shell_command(std::slice::from_ref(&file.path)));
        self.run(id, &chmod, BTreeMap::new(), c).await?.success(E2B).map(drop)
    }
}

#[async_trait]
impl QuotaOperation for E2b {
    async fn quota(&self, c: &Credentials) -> Result<Quota> {
        let metrics: Vec<Metric> = self.get(&["teams", &self.settings.team_id, "metrics"], c).await?;
        Ok(Quota {
            resources: vec![],
            credits_remaining: None,
            credit_unit: None,
            concurrency_in_use: Some(metrics.iter().max_by_key(|m| m.at).map_or(0, |m| m.concurrent)),
            concurrency_limit: self.settings.concurrency_limit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rigging_http_client::ChannelLabel;

    /// Answers each request with the next scripted (status, body), keeping
    /// each request's method, path and body.
    #[derive(Default)]
    struct Script {
        answers: Mutex<Vec<(u16, &'static str)>>,
        asked: Mutex<Vec<(String, String, serde_json::Value)>>,
    }
    #[async_trait]
    impl HttpClient for Script {
        async fn execute(&self, request: reqwest::Request, _: &ChannelLabel) -> std::result::Result<http::Response<Bytes>, String> {
            let body = request.body().and_then(|b| b.as_bytes()).and_then(|b| serde_json::from_slice(b).ok()).unwrap_or_default();
            self.asked.lock().unwrap().push((request.method().to_string(), request.url().path().to_owned(), body));
            let (status, body) = self.answers.lock().unwrap().remove(0);
            Ok(http::Response::builder().status(status).body(Bytes::from_static(body.as_bytes())).unwrap())
        }
    }
    impl Script {
        fn asked(&self) -> Vec<(String, String)> {
            self.asked.lock().unwrap().iter().map(|(m, p, _)| (m.clone(), p.clone())).collect()
        }
    }
    async fn e2b(ownership: Ownership, answers: Vec<(u16, &'static str)>) -> (Arc<dyn Provider>, Arc<Script>) {
        let script = Arc::new(Script { answers: Mutex::new(answers), ..Script::default() });
        let settings = BTreeMap::from([("team_id".to_owned(), serde_json::json!("team"))]);
        let config = ProviderConfiguration { module: "e2b".into(), settings, ownership, ..Default::default() };
        (E2bModule::new().configure("e2b-a", &config, script.clone()).await.unwrap(), script)
    }
    fn key() -> Credentials {
        Credentials::new(Some(Secret::new("k")))
    }
    fn asked(method: &str, path: &str) -> (String, String) {
        (method.to_owned(), path.to_owned())
    }
    const CREATED: &str =
        r#"{"templateID":"t","sandboxID":"sbx1","clientID":"c","envdVersion":"0.2","envdAccessToken":"e","trafficAccessToken":"x"}"#;

    // Provision is one create. The owner tag goes on only on a shared
    // account; the answer is E2B's create row, which carries no state.
    #[tokio::test]
    async fn provision_is_one_create_tagged_by_ownership() {
        for (ownership, tags) in [(Ownership::SharedAccount, 2), (Ownership::OwnedAccount, 1)] {
            let (e2b, script) = e2b(ownership, vec![(201, CREATED)]).await;
            let prepared = Prepared {
                provider: "e2b-a".into(),
                id: "drydock-tmpl".into(),
                platform: platform(),
                image_digest: "img".into(),
                tools_digest: "tools".into(),
            };
            let size = Size { cpus: 1.0, memory_bytes: 1 << 30, disk_bytes: 1 << 30 };
            let request = ProvisionRequest { label: "crew-1".into(), prepared, size, egress: EgressRequest::Open, ssh_public_key: None };
            let Provisioned::Created(e) = e2b.provision(request, &key()).await.unwrap() else { panic!("not created") };
            assert_eq!(
                (e.id.as_str(), e.label.as_deref(), &e.state),
                ("sbx1", Some("crew-1"), &Observation::Unknown { reason: UnknownReason::ProviderStateUnknown })
            );
            let asked = script.asked.lock().unwrap();
            assert_eq!(asked.len(), 1);
            let (method, path, body) = &asked[0];
            assert_eq!((method.as_str(), path.as_str()), ("POST", "/v2/sandboxes"));
            let metadata = body["metadata"].as_object().unwrap();
            assert_eq!(metadata.len(), tags);
            assert_eq!(metadata[LABEL_TAG], "crew-1");
            assert_eq!(metadata.get(OWNER_TAG).is_some(), ownership == Ownership::SharedAccount);
            assert_eq!(e.vendor.unwrap().tags.unwrap().len(), tags);
        }
    }

    // List is one call, and reports every row E2B lists, another owner's
    // included, with E2B's state name and metadata beside the coarse state.
    #[tokio::test]
    async fn list_reports_every_row_as_e2b_gives_it() {
        let rows = r#"[
            {"sandboxID":"sbx1","state":"running","cpuCount":1,"memoryMB":1024,"diskSizeMB":1024,"metadata":{"drydock.provider":"e2b-a","flotilla.label":"l"}},
            {"sandboxID":"sbx2","state":"paused","cpuCount":2,"memoryMB":2048,"diskSizeMB":1024,"metadata":{"drydock.provider":"other"}}
        ]"#;
        let (e2b, script) = e2b(Ownership::SharedAccount, vec![(200, rows)]).await;
        let listed = e2b.list(&key()).await.unwrap();
        assert_eq!(script.asked(), [asked("GET", "/v2/sandboxes")]);
        let seen: Vec<_> = listed.iter().map(|e| (e.id.as_str(), e.label.as_deref(), e.state.clone())).collect();
        assert_eq!(seen, [("sbx1", Some("l"), Observation::Running), ("sbx2", None, kit::stopped(StopCause::PausedByProvider))]);
        let vendor = listed[1].vendor.as_ref().unwrap();
        assert_eq!((vendor.state.as_str(), vendor.tags.as_ref().unwrap()[OWNER_TAG].as_str()), ("paused", "other"));
    }

    // Suspend is one pause and answers the id as the token; the pause then
    // reads as this host's. Resume is one connect, whatever the token.
    #[tokio::test]
    async fn suspend_and_resume_are_one_call_each() {
        let paused = r#"{"sandboxID":"sbx1","state":"paused","metadata":{}}"#;
        let (e2b, script) = e2b(Ownership::OwnedAccount, vec![(204, ""), (200, paused), (201, CREATED)]).await;
        let port = e2b.operations().suspend_resume.unwrap();
        assert_eq!(port.suspend("sbx1", &key()).await.unwrap(), ResumeToken { token: Secret::new("sbx1") });
        assert_eq!(e2b.inspect("sbx1", &key()).await.unwrap().state, kit::stopped(StopCause::SuspendedByRequest));
        port.resume("sbx1", ResumeToken { token: Secret::new("anything") }, &key()).await.unwrap();
        assert_eq!(
            script.asked(),
            [asked("POST", "/sandboxes/sbx1/pause"), asked("GET", "/sandboxes/sbx1"), asked("POST", "/v2/sandboxes/sbx1/connect")]
        );
    }

    // Destroy is one kill; E2B's answers pass through, not found included.
    #[tokio::test]
    async fn destroy_is_one_kill() {
        let (e2b, script) = e2b(Ownership::SharedAccount, vec![(204, ""), (404, r#"{"message":"sandbox not found"}"#)]).await;
        e2b.destroy("sbx1", &key()).await.unwrap();
        assert!(matches!(e2b.destroy("sbx1", &key()).await, Err(ProtocolError::NotFound { .. })));
        assert_eq!(script.asked(), [asked("DELETE", "/sandboxes/sbx1"), asked("DELETE", "/sandboxes/sbx1")]);
    }

    #[test]
    fn connect_streams_parse() {
        let event = |e: &str| envelope(0, format!("{{\"event\":{e}}}").as_bytes());
        let body = [
            event(r#"{"start":{"pid":7}}"#),
            event(r#"{"data":{"stdout":"aGVs"}}"#),
            event(r#"{"data":{"stderr":"/w=="}}"#),
            event(r#"{"end":{"exited":true}}"#),
            envelope(2, br#"{"error":{"code":"deadline_exceeded","message":"timed out"}}"#),
        ]
        .concat();
        let run = parse_run(&body).unwrap();
        assert_eq!(
            (run.exit_code(), run.bytes(None), run.note.as_deref()),
            (0, b"hel\xff".to_vec(), Some("[envd: deadline_exceeded: timed out]"))
        );
        assert!(matches!(parse_run(&event(r#"{"start":{"pid":7}}"#)), Err(ProtocolError::Unavailable { .. })));
        assert!(parse_run(&body[..body.len() - 1]).is_err());
    }
}

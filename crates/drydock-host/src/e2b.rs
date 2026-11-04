//! E2B: https://github.com/e2b-dev/infra (spec/openapi.yml; packages/envd/spec).
use crate::{
    kit::{
        self, LABEL_TAG, MIB, PROVIDER_TAG, SizeLimits, Vendor,
        api::{Api, Auth, Body, EXPLANATION_CHARS, Failure, Next, Paging, Text, absent_on_not_found, cut, sensitive},
        egress::{Resolver, SystemResolver, ipv6, normal_cidr, normal_host, private_registry},
        guest::{Guest, GuestOutput},
        image::{check_prepare, check_prepared, content_name},
    },
    module::*,
    oci::{ImageRef, Registry},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use drydock_protocol::*;
use drydock_transport::tcp::CONNECT_PATH;
use futures::{StreamExt, TryStreamExt};
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
const RUN_TIMEOUT_MS: u64 = 25_000;
const BUILD_POLL: Duration = Duration::from_secs(3);
const BUILD_POLLS: u32 = 150;
const STATE_POLL: Duration = Duration::from_secs(1);
const STATE_POLLS: u32 = 60;
const DETAIL_READS: usize = 8;
const EVENT_PAGE: usize = 100;
const EVENT_PAGES: usize = 100;
const SANDBOX_PAGES: Paging = Paging { rows: None, cursor: "nextToken", next: Next::Header("x-next-token") };
const BUILD_PAGES: Paging = Paging { rows: Some("builds"), cursor: "nextToken", next: Next::Header("x-next-token") };
const RESUME_PREFIX: &str = "e2b-resume-";

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
    #[serde(rename = "cpuCount")]
    cpus: u64,
    #[serde(rename = "memoryMB")]
    memory_mb: u64,
    #[serde(rename = "diskSizeMB")]
    disk_mb: Option<u64>,
    #[serde(default)]
    builds: Vec<TemplateBuild>,
}
#[derive(Deserialize)]
struct TemplateBuild {
    #[serde(rename = "buildID")]
    id: Text,
    status: Text,
    #[serde(rename = "diskSizeMB")]
    disk_mb: Option<u64>,
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
    metadata: BTreeMap<&'static str, &'a str>,
    network: Network,
}
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
struct Network {
    #[serde(rename = "allowPublicTraffic", skip_serializing_if = "Option::is_none")]
    public_traffic: Option<bool>,
    #[serde(rename = "denyOut", default, skip_serializing_if = "Vec::is_empty")]
    deny_out: Vec<String>,
    #[serde(rename = "allowOut", default, skip_serializing_if = "Vec::is_empty")]
    allow_out: Vec<String>,
}
#[derive(Deserialize, Clone)]
struct Sandbox {
    #[serde(rename = "sandboxID")]
    id: Text,
    state: Option<Text>,
    #[serde(rename = "startedAt")]
    started_at: Option<DateTime<Utc>>,
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
struct Event {
    id: Text,
    timestamp: DateTime<Utc>,
    #[serde(rename = "sandboxId")]
    sandbox: Text,
    #[serde(rename = "sandboxTemplateId")]
    template: Text,
    #[serde(rename = "sandboxBuildId")]
    build: Text,
    #[serde(rename = "eventData")]
    data: EventData,
}
#[derive(Deserialize)]
struct EventData {
    #[serde(default)]
    sandbox_metadata: BTreeMap<String, String>,
    execution: Option<Execution>,
}
#[derive(Deserialize)]
struct Execution {
    started_at: DateTime<Utc>,
    vcpu_count: u64,
    memory_mb: u64,
}
#[derive(Clone)]
enum Disk {
    Granted(u64),
    Build(String, String),
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    team_id: String,
    #[serde(default = "api_url")]
    api_url: String,
    #[serde(default = "sandbox_url")]
    sandbox_url: String,
    #[serde(default = "lifetime_seconds")]
    lifetime_seconds: u32,
    #[serde(default = "disk_mb")]
    disk_mb: u64,
    #[serde(default)]
    concurrency_limit: Option<u64>,
    #[serde(default)]
    rate_limits: Option<Vec<RateLimit>>,
    #[serde(default = "poll_interval_ms")]
    poll_interval_ms: u64,
}
fn api_url() -> String {
    "https://api.e2b.app/".into()
}
fn sandbox_url() -> String {
    "https://{port}-{id}.e2b.app".into()
}
fn lifetime_seconds() -> u32 {
    3600
}
fn disk_mb() -> u64 {
    10_240
}
fn poll_interval_ms() -> u64 {
    30_000
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
        if settings.team_id.is_empty()
            || !(1..=86_400).contains(&settings.lifetime_seconds)
            || settings.disk_mb == 0
            || settings.poll_interval_ms == 0
            || !sandbox_url_valid(&settings.sandbox_url)
        {
            return Err(refused(
                "E2B requires team_id, a sandbox_url holding {port} and {id} (HTTPS, or HTTP to a loopback address), \
                 lifetime_seconds 1..86400, a positive disk_mb and a positive poll_interval_ms",
            ));
        }
        let api = Api::new(E2B, &settings.api_url, Auth::Header(HeaderName::from_static("x-api-key")), http)?.classify(classify);
        Ok(Arc::new(E2b {
            name: name.to_owned(),
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
    settings: Settings,
    api: Api,
    resolver: Arc<dyn Resolver>,
    access: Mutex<HashMap<String, Access>>,
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

impl E2b {
    fn port_url(&self, id: &str, port: u16, path: &str) -> Result<Url> {
        if !sandbox_id_valid(id) {
            return Err(ProtocolError::NotFound { reason: "not an E2B sandbox id".into() });
        }
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
        if !sandbox_id_valid(id) {
            return Err(ProtocolError::NotFound { reason: "not an E2B sandbox id".into() });
        }
        let v: Sandbox = self.get(&["sandboxes", id], c).await?;
        self.keep_tokens(&v);
        Ok(v)
    }
    async fn connect(&self, id: &str, c: &Credentials) -> Result<Sandbox> {
        let v: Sandbox = self.post(&["v2", "sandboxes", id, "connect"], &Connect { timeout: self.settings.lifetime_seconds }, c).await?;
        self.keep_tokens(&v);
        Ok(v)
    }
    fn label(&self, v: &Sandbox) -> Option<String> {
        kit::ours(&v.metadata, &self.name)
    }
    fn state<'a>(&self, v: &'a Sandbox) -> &'a str {
        v.state.as_deref().unwrap_or("")
    }
    fn environment(&self, v: &Sandbox) -> Result<Environment> {
        let state = match self.state(v) {
            "running" => Observation::Running,
            "paused" if self.suspended.recover().contains(&*v.id) => kit::stopped(StopCause::SuspendedByRequest),
            "paused" => kit::stopped(StopCause::PausedByProvider),
            _ => Observation::Unknown { reason: UnknownReason::ProviderStateUnknown },
        };
        Ok(Environment {
            label: self.label(v),
            id: v.id.to_string(),
            provider: self.name.clone(),
            state,
            granted_size: kit::granted(E2B, v.cpus, v.memory_mb, MIB, v.disk_mb, MIB)?,
            egress: Enforcement::Advisory,
            platform: Some(platform()),
            egress_measured: false,
            egress_policy: v.network.as_ref().map(|n| Policy::read(n).fingerprint()),
            timestamp: None,
        })
    }
    fn gone(&self, id: &str) -> Environment {
        Environment {
            id: id.to_owned(),
            label: None,
            provider: self.name.clone(),
            state: Observation::Gone { cause: GoneCause::DestroyedAtProvider },
            granted_size: None,
            egress: Enforcement::Advisory,
            platform: Some(platform()),
            egress_measured: false,
            egress_policy: None,
            timestamp: None,
        }
    }
    async fn wait_state(&self, id: &str, wanted: &str, c: &Credentials) -> Result<()> {
        kit::poll(STATE_POLLS, STATE_POLL, async || Ok((self.state(&self.sandbox(id, c).await?) == wanted).then_some(())))
            .await?
            .ok_or_else(|| ProtocolError::unavailable(format!("E2B sandbox {id} is not {wanted} yet"), Some(5)))
    }
    async fn listed(&self, label: Option<&str>, c: &Credentials) -> Result<Vec<Sandbox>> {
        let filter = {
            let mut filter = url::form_urlencoded::Serializer::new(String::new());
            filter.append_pair(PROVIDER_TAG, &self.name);
            if let Some(label) = label {
                filter.append_pair(LABEL_TAG, label);
            }
            filter.finish()
        };
        let mut url = self.api.url(&["v2", "sandboxes"])?;
        url.query_pairs_mut().append_pair("metadata", &filter).append_pair("state", "running,paused").append_pair("limit", "100");
        let rows: Vec<Sandbox> = self.api.paged(url, &SANDBOX_PAGES, c).await?;
        Ok(rows.into_iter().filter(|v| self.label(v).is_some_and(|held| label.is_none_or(|l| held == l))).collect())
    }
    async fn ours_listed(&self, label: Option<&str>, c: &Credentials) -> Result<Vec<Sandbox>> {
        let reads = self.listed(label, c).await?.into_iter().map(|v| async move { absent_on_not_found(self.sandbox(&v.id, c).await) });
        let details: Vec<Option<Sandbox>> = futures::stream::iter(reads).buffered(DETAIL_READS).try_collect().await?;
        Ok(details.into_iter().flatten().collect())
    }
    async fn builds(&self, template: &str, c: &Credentials) -> Result<BTreeMap<String, u64>> {
        let mut url = self.api.url(&["templates", template])?;
        url.query_pairs_mut().append_pair("limit", "100");
        let builds: Vec<TemplateBuild> = absent_on_not_found(self.api.paged(url, &BUILD_PAGES, c).await)?
            .ok_or_else(|| refused(format!("E2B template {template} is gone, so its sandboxes' disk is unknown")))?;
        Ok(builds.into_iter().filter_map(|b| Some((b.id.to_string(), b.disk_mb?))).collect())
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
    async fn await_build(&self, template: &str, build: &str, c: &Credentials) -> Result<()> {
        kit::poll(BUILD_POLLS, BUILD_POLL, async || {
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
                (HeaderName::from_static("connect-timeout-ms"), HeaderValue::from(RUN_TIMEOUT_MS)),
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

#[derive(Debug, Clone, PartialEq)]
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
            usage: true,
            quota: true,
            host_filesystem: false,
            agent_tcp_port: std::num::NonZeroU16::new(AGENT_PORT),
            exclusive_label: false,
        }
    }
    fn observation(&self) -> ObservationMode {
        ObservationMode::Poll { interval_ms: self.settings.poll_interval_ms }
    }
    fn operations(&self) -> Operations<'_> {
        Operations {
            exec: Some(self),
            suspend_resume: Some(self),
            quota: Some(self),
            usage: Some(self),
            files: Some(self),
            ..Operations::default()
        }
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
        let template = self.template(&name, c).await?.ok_or_else(|| E2B.bad_response())?;
        if template.cpus != r.size.cpus as u64 || template.memory_mb != r.size.memory_bytes / MIB {
            return Err(refused(format!("E2B template {name} has another size than its name holds")));
        }
        if let Some(disk) = template.disk_mb.filter(|disk| r.size.disk_bytes > disk * MIB) {
            return Err(refused(format!("E2B template {name} has {disk} MiB of disk, less than requested")));
        }
        Ok(Prepared { provider: self.name.clone(), id: name, platform, image_digest: r.image_digest, tools_digest: r.tools_digest })
    }
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        self.sizes().check(E2B, &r.size)?;
        let p = &r.prepared;
        check_prepared(E2B, &self.name, p, &template_name(&p.image_digest, &p.platform, &r.size))?;
        let policy = Policy::request(&r.egress)?;
        if let Some(v) = self.ours_listed(Some(&r.label), c).await?.into_iter().next() {
            let existing = self.environment(&v)?;
            let same_size = existing
                .granted_size
                .as_ref()
                .is_some_and(|g| g.cpus == r.size.cpus && g.memory_bytes == r.size.memory_bytes && r.size.disk_bytes <= g.disk_bytes);
            if !same_size || v.network.as_ref().map(Policy::read) != Some(policy) {
                return Err(refused(
                    "an existing E2B sandbox holds this label with a different size or egress policy; provision a new label",
                ));
            }
            return Ok(Provisioned::Existing(existing));
        }
        let body = NewSandbox {
            template: &p.id,
            timeout: self.settings.lifetime_seconds,
            auto_pause: true,
            metadata: BTreeMap::from([(PROVIDER_TAG, self.name.as_str()), (LABEL_TAG, r.label.as_str())]),
            network: policy.network(),
        };
        let created: Sandbox = self.post(&["v2", "sandboxes"], &body, c).await?;
        self.keep_tokens(&created);
        Ok(Provisioned::Created(self.inspect(&created.id, c).await?))
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        self.ours_listed(None, c).await?.iter().map(|v| self.environment(v)).collect()
    }
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        match absent_on_not_found(self.sandbox(id, c).await)? {
            Some(v) => self.environment(&v),
            None => Ok(self.gone(id)),
        }
    }
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        if let Some(v) = absent_on_not_found(self.sandbox(id, c).await)? {
            if self.label(&v).is_none() {
                return Err(refused(format!("E2B sandbox {id} is not this provider's")));
            }
            absent_on_not_found(self.api.call::<IgnoredAny>(Method::DELETE, self.api.url(&["sandboxes", id])?, Body::None, c).await)?;
        }
        self.access.recover().remove(id);
        self.suspended.recover().remove(id);
        Ok(())
    }
    async fn reach(&self, id: &str, c: &Credentials) -> Result<Reach> {
        let v = self.sandbox(id, c).await?;
        if self.state(&v) != "running" {
            return Err(refused(format!("E2B sandbox {id} is not running; resume it first")));
        }
        if self.label(&v).is_none() {
            return Err(refused(format!("E2B sandbox {id} is not this provider's")));
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

#[async_trait]
impl SuspendResume for E2b {
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        if self.state(&self.sandbox(id, c).await?) == "running" {
            let url = self.api.url(&["sandboxes", id, "pause"])?;
            let operation = kit::api::operation(&Method::POST, &url);
            let response = self.api.send(Method::POST, url, Body::None, c, true, &[]).await?;
            if !response.status().is_success() && response.status() != 409 {
                return Err(self.api.failure(&operation, &response));
            }
        }
        self.wait_state(id, "paused", c).await?;
        self.suspended.recover().insert(id.to_owned());
        Ok(E2B.resume_marker(RESUME_PREFIX, &self.name, id))
    }
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()> {
        E2B.check_resume(RESUME_PREFIX, &self.name, id, &token)?;
        self.connect(id, c).await?;
        self.wait_state(id, "running", c).await?;
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

#[async_trait]
impl UsageOperation for E2b {
    async fn usage(&self, period: Period, c: &Credentials) -> Result<Usage> {
        let (from, to) = (period.start().instant(), period.end().instant());
        let mut executions: BTreeMap<(String, DateTime<Utc>), (DateTime<Utc>, u64, u64, Disk)> = BTreeMap::new();
        let mut seen = BTreeSet::new();
        let mut complete = false;
        'pages: for page in 0..EVENT_PAGES {
            let mut url = self.api.url(&["events", "sandboxes"])?;
            url.query_pairs_mut()
                .append_pair("offset", &(page * EVENT_PAGE).to_string())
                .append_pair("limit", &EVENT_PAGE.to_string())
                .append_pair("orderAsc", "false")
                .append_pair("types", "sandbox.lifecycle.paused")
                .append_pair("types", "sandbox.lifecycle.killed");
            let events: Vec<Event> = self.api.get(url, c).await?;
            for event in &events {
                if event.timestamp < from {
                    complete = true;
                    break 'pages;
                }
                if !seen.insert(event.id.to_string()) || event.data.sandbox_metadata.get(PROVIDER_TAG) != Some(&self.name) {
                    continue;
                }
                let Some(x) = &event.data.execution else { continue };
                let row = (event.timestamp, x.vcpu_count, x.memory_mb, Disk::Build(event.template.to_string(), event.build.to_string()));
                let entry = executions.entry((event.sandbox.to_string(), x.started_at)).or_insert_with(|| row.clone());
                if event.timestamp < entry.0 {
                    *entry = row;
                }
            }
            if events.len() < EVENT_PAGE {
                complete = true;
                break;
            }
        }
        if !complete {
            return Err(refused(format!(
                "the period holds more than {} of E2B's sandbox events; ask for a shorter one",
                EVENT_PAGES * EVENT_PAGE
            )));
        }
        let now = Utc::now();
        for v in self.listed(None, c).await? {
            if let (Some(started), Some(cpus), Some(memory), Some(disk), "running") =
                (v.started_at, v.cpus, v.memory_mb, v.disk_mb, self.state(&v))
            {
                executions.entry((v.id.to_string(), started)).or_insert((now, cpus, memory, Disk::Granted(disk)));
            }
        }
        executions.retain(|(_, started), (ended, ..)| (*ended).min(to) > (*started).max(from));
        let mut builds = BTreeMap::new();
        for (_, _, _, disk) in executions.values() {
            if let Disk::Build(template, _) = disk
                && !builds.contains_key(template)
            {
                builds.insert(template.clone(), self.builds(template, c).await?);
            }
        }
        let mut sizes: BTreeMap<(u64, u64, u64), f64> = BTreeMap::new();
        let (mut cpu_seconds, mut memory_byte_seconds) = (0.0, 0.0);
        let mut sandboxes = BTreeSet::new();
        for ((sandbox, started), (ended, cpus, memory, disk)) in executions {
            let disk = match disk {
                Disk::Granted(disk) => disk,
                Disk::Build(template, build) => builds[&template].get(&build).copied().ok_or_else(|| {
                    refused(format!("E2B reports no disk for build {build} of template {template}, which sandbox {sandbox} ran"))
                })?,
            };
            let (start, end) = (started.max(from), ended.min(to));
            let seconds = (end - start).num_milliseconds() as f64 / 1000.0;
            *sizes.entry((cpus, memory, disk)).or_default() += seconds / 3600.0;
            cpu_seconds += cpus as f64 * seconds;
            memory_byte_seconds += (memory * MIB) as f64 * seconds;
            sandboxes.insert(sandbox);
        }
        Ok(Usage {
            period,
            environment_hours: sizes
                .into_iter()
                .map(|((cpus, memory, disk), hours)| SizeUsage {
                    size: Size { cpus: cpus as f64, memory_bytes: memory * MIB, disk_bytes: disk * MIB },
                    hours,
                })
                .collect(),
            measurements: Some(UsageMeasurements {
                scope: UsageScope::Organization { id: self.settings.team_id.clone() },
                resources: BTreeMap::from([
                    (ResourceKind::Cpu, Quantity { amount: cpu_seconds, unit: "{vCPU}.s".into() }),
                    (ResourceKind::Memory, Quantity { amount: memory_byte_seconds, unit: "By.s".into() }),
                    (ResourceKind::Environments, Quantity { amount: sandboxes.len() as f64, unit: "1".into() }),
                ]),
                cost: None,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

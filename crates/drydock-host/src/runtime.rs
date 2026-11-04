//! Runtime (withruntime.com) microVM sandboxes, reached by a dial to a private
//! preview of the agent's port. API: https://api.withruntime.com/v1/openapi.json
use crate::{
    kit::{
        self, GIB, LABEL_TAG, MIB, PROVIDER_TAG, SizeLimits, StateTable, Vendor, Verdict, Wait,
        api::{Api, Auth, Body, EXPLANATION_CHARS, Failure, Next, Paging, Text, absent_on_not_found, cut, sensitive},
        egress::normal_host,
        guest::{AgentTokens, Guest, GuestOutput},
        image::{check_prepare, check_prepared, content_name, platform_dockerfile, sandbox_name},
    },
    module::*,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use drydock_protocol::*;
use reqwest::{
    Method, Url,
    header::{HeaderName, HeaderValue},
};
use serde::{Deserialize, Deserializer, Serialize, de::IgnoredAny};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    num::NonZeroU16,
    sync::Arc,
    time::Duration,
};

const RUNTIME: Vendor = Vendor("Runtime");
const SIZES: SizeLimits =
    SizeLimits { cpus: (1, 16), memory: (128 * MIB, 64 * GIB), memory_step: MIB, disk: (3 * GIB, 400 * GIB), disk_step: MIB };
const PAGED: Paging = Paging { rows: Some("data"), cursor: "cursor", next: Next::Body(&["nextCursor"]) };
const POLICY_LABEL: &str = "drydock.egress";
const ENFORCED_LABEL: &str = "drydock.enforced";
const LABEL_LIMIT: usize = 256;
const WAIT_SECONDS: u64 = 25;
const PREFER_WAIT: &str = "wait=25";
const STATE_WAIT: Wait = Wait { attempts: 120, interval: Duration::from_secs(1), retry_after: 5 };
const ENFORCE_WAIT: Wait = Wait { interval: Duration::from_millis(500), ..STATE_WAIT };
const BUILD_WAIT: Wait = Wait { attempts: 150, interval: Duration::from_secs(3), retry_after: 30 };
const PREVIEW_TOKEN_HEADER: &str = "x-runtime-preview-token";
const PREVIEW_TTL_SECONDS: u32 = 86_400;
const EVENT_DAYS: i64 = 14;

const STATES: StateTable = &[
    ("starting", kit::starting()),
    ("resuming", kit::starting()),
    ("running", Observation::Running),
    ("pausing", kit::stopping()),
    ("stopping", kit::stopping()),
    ("paused", kit::stopped(StopCause::SuspendedByRequest)),
    ("stopped", kit::stopped(StopCause::GuestHalted)),
];

#[derive(Deserialize)]
struct Sandbox {
    id: Text,
    #[serde(default)]
    name: String,
    state: Text,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    vcpu: Option<u64>,
    #[serde(rename = "memoryMiB")]
    memory: Option<u64>,
    #[serde(rename = "diskMiB")]
    disk: Option<u64>,
    #[serde(default, rename = "readyAt")]
    ready_at: Option<DateTime<Utc>>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSandbox<'a> {
    name: String,
    labels: BTreeMap<&'static str, String>,
    image: &'a str,
    vcpu: u64,
    #[serde(rename = "memoryMiB")]
    memory: u64,
    #[serde(rename = "diskMiB")]
    disk: u64,
    network: &'a Policy,
    persistent: bool,
    idle_pause_seconds: u32,
}
#[derive(Serialize)]
struct Relabel<'a> {
    labels: &'a BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Network {
    #[serde(flatten)]
    rules: Policy,
    version: Option<u64>,
    enforced: Option<bool>,
    enforced_version: Option<u64>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Image {
    id: Text,
    #[serde(default)]
    name: String,
    state: Text,
    error: Option<String>,
}
#[derive(Serialize)]
struct BuildImage<'a> {
    name: &'a str,
    dockerfile: String,
}
#[derive(Deserialize)]
struct Limits {
    #[serde(default)]
    account: Vec<Limit>,
    credit: Credit,
}
#[derive(Deserialize)]
struct Limit {
    limit: String,
    used: u64,
    max: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Credit {
    state: Option<String>,
    available_micros: Micros,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Execute<'a> {
    argv: [&'a str; 3],
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    env: BTreeMap<&'a str, String>,
    user: &'static str,
    timeout_ms: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Executed {
    exit_code: Option<i64>,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
    #[serde(default)]
    timed_out: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SharePreview {
    port: u16,
    visibility: &'static str,
    ttl_seconds: u32,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Preview {
    url: Text,
    visibility: Text,
    token: Option<String>,
    token_expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    disabled: bool,
}
#[derive(Serialize)]
struct BeginUpload<'a> {
    path: &'a str,
    user: &'static str,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Upload {
    upload_id: Text,
    chunk_bytes: usize,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Charge {
    kind: String,
    resource_id: Text,
    charged_micros: Micros,
    starts_at: DateTime<Utc>,
    ends_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Event {
    #[serde(rename = "type")]
    kind: String,
    created_at: DateTime<Utc>,
    #[serde(default)]
    data: EventData,
}
#[derive(Deserialize, Default)]
struct EventData {
    sandbox: Option<Sandbox>,
}
#[derive(Deserialize, Default)]
struct ErrorBody {
    #[serde(default)]
    error: ErrorDetail,
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ErrorDetail {
    #[serde(default)]
    code: String,
    message: Option<String>,
    hint: Option<String>,
    retry_after_ms: Option<u64>,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(try_from = "String")]
struct Micros(u128);
impl TryFrom<String> for Micros {
    type Error = std::num::ParseIntError;
    fn try_from(text: String) -> std::result::Result<Self, Self::Error> {
        text.parse().map(Self)
    }
}
impl Micros {
    fn usd(self) -> String {
        format!("{}.{:06}", self.0 / 1_000_000, self.0 % 1_000_000)
    }
}

pub struct RuntimeModule;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    #[serde(default = "api_url")]
    api_url: String,
    #[serde(default = "agent_port")]
    agent_port: NonZeroU16,
    #[serde(default)]
    rate_limits: Option<Vec<RateLimit>>,
}
fn api_url() -> String {
    "https://api.withruntime.com/v1".into()
}
fn agent_port() -> NonZeroU16 {
    NonZeroU16::new(7811).expect("non-zero")
}

#[async_trait]
impl Module for RuntimeModule {
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn smallest_size(&self) -> Size {
        Size { cpus: 1.0, memory_bytes: GIB, disk_bytes: SIZES.disk.0 }
    }
    async fn configure(&self, name: &str, config: &ProviderConfiguration, http: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
        let settings: Settings =
            serde_json::from_value(json!(config.settings)).map_err(|e| refused(format!("invalid Runtime settings: {e}")))?;
        if name.contains(':') || name.len() > LABEL_LIMIT {
            return Err(refused("a Runtime provider's name becomes a label value: no ':' and at most 256 characters"));
        }
        let api = Api::new(RUNTIME, &settings.api_url, Auth::Bearer, http)?.classify(classify).retry_after(retry_hint);
        Ok(Arc::new(Runtime { name: name.to_owned(), settings, api, agents: AgentTokens::default() }))
    }
}

pub struct Runtime {
    name: String,
    settings: Settings,
    api: Api,
    agents: AgentTokens,
}

// The header, else the body's `retryAfterMs` (whole seconds, rounded up).
fn retry_hint(headers: &reqwest::header::HeaderMap, body: &[u8]) -> Option<u64> {
    kit::api::retry_after_header(headers)
        .or_else(|| serde_json::from_slice::<ErrorBody>(body).ok()?.error.retry_after_ms.map(|ms| ms.div_ceil(1000)))
}
// Runtime marks a refusal that may succeed when sent again (`retryable` with
// `retryAfterMs`): https://withruntime.com/docs/api
fn classify(f: &Failure) -> ProtocolError {
    let error = serde_json::from_slice::<ErrorBody>(f.body).unwrap_or_default().error;
    let message = match (error.message, error.hint.filter(|h| !h.is_empty())) {
        (Some(message), Some(hint)) => cut(&format!("{message} ({hint})"), EXPLANATION_CHARS),
        (Some(message), None) => cut(&message, EXPLANATION_CHARS),
        (None, _) => f.message(),
    };
    let code = error.code;
    let retry_after = f.retry_after;
    let reason = f.reason(&if code.is_empty() { message } else { format!("{code}: {message}") });
    let quota = code == "quota_exceeded" || code.starts_with("no_credit_") || code.ends_with("_limit_reached") || code == "daily_limit";
    match f.status {
        410 => ProtocolError::NotFound { reason },
        409 | 429 if quota => ProtocolError::QuotaExhausted { reason },
        429 => ProtocolError::RateLimited { reason, retry_after },
        400..=499 if retry_after.is_some() && ![401, 402, 403, 404].contains(&f.status) => {
            ProtocolError::Unavailable { reason, retry_after, provider_error: None }
        }
        _ => f.standard(reason),
    }
}
fn platform() -> Platform {
    Platform::new("linux", "amd64")
}
fn is_uuid(id: &str) -> bool {
    id.len() == 36
        && id
            .bytes()
            .enumerate()
            .all(|(i, b)| if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_digit() || (b'a'..=b'f').contains(&b) })
}
fn trial(limits: &Limits) -> bool {
    limits.credit.state.as_deref() == Some("empty")
}
fn size(v: &Sandbox) -> Result<Option<Size>> {
    kit::granted(RUNTIME, v.vcpu, v.memory, MIB, v.disk, MIB)
}

impl Runtime {
    fn sandbox_url(&self, id: &str, action: Option<&str>, rest: &[&str]) -> Result<Url> {
        if !is_uuid(id) {
            return Err(ProtocolError::NotFound { reason: "not a Runtime sandbox id".into() });
        }
        let segment = match action {
            Some(action) => format!("{id}:{action}"),
            None => id.to_owned(),
        };
        self.api.url(&[&["sandboxes", segment.as_str()][..], rest].concat())
    }
    async fn sandbox(&self, id: &str, c: &Credentials) -> Result<Sandbox> {
        self.api.get(self.sandbox_url(id, None, &[])?, c).await
    }
    async fn ours(&self, id: &str, c: &Credentials) -> Result<Sandbox> {
        let v = self.sandbox(id, c).await?;
        kit::require_ours(RUNTIME, id, &v.labels, &self.name)?;
        Ok(v)
    }
    async fn listed(&self, c: &Credentials) -> Result<Vec<Sandbox>> {
        let mut url = self.api.url(&["sandboxes"])?;
        url.query_pairs_mut()
            .append_pair("label", &format!("{PROVIDER_TAG}:{}", self.name))
            .append_pair("includeStopped", "true")
            .append_pair("limit", "100");
        Ok(self.api.paged::<Sandbox>(url, &PAGED, c).await?.into_iter().filter(|v| kit::ours(&v.labels, &self.name).is_some()).collect())
    }
    async fn network(&self, id: &str, c: &Credentials) -> Result<Network> {
        self.api.get(self.sandbox_url(id, None, &["network"])?, c).await
    }
    async fn limits(&self, c: &Credentials) -> Result<Limits> {
        self.api.get(self.api.url(&["limits"])?, c).await
    }
    async fn act(&self, method: Method, url: Url, body: Body, c: &Credentials, wait: bool) -> Result<()> {
        let prefer = [(HeaderName::from_static("prefer"), HeaderValue::from_static(PREFER_WAIT))];
        self.api.call_with::<IgnoredAny>(method, url, body, c, if wait { &prefer } else { &[] }).await.map(drop)
    }
    fn environment(&self, v: &Sandbox) -> Result<Environment> {
        Ok(Environment {
            id: v.id.to_string(),
            provider: self.name.clone(),
            label: v.labels.get(LABEL_TAG).cloned(),
            state: kit::observe(STATES, &v.state),
            granted_size: size(v)?,
            egress: if v.labels.get(ENFORCED_LABEL).is_some_and(|e| v.labels.get(POLICY_LABEL) == Some(e)) {
                Enforcement::Enforced
            } else {
                Enforcement::Advisory
            },
            platform: Some(platform()),
            egress_measured: false,
            egress_policy: v.labels.get(POLICY_LABEL).cloned(),
            timestamp: None,
            vendor: None,
        })
    }
    async fn wait_running(&self, id: &str, c: &Credentials) -> Result<Sandbox> {
        // The vendor's own long-poll (waitFor) holds each look for up to 20 s.
        let read = async || {
            let mut url = self.sandbox_url(id, None, &[])?;
            url.query_pairs_mut().append_pair("waitFor", "running").append_pair("timeoutSeconds", "20");
            self.api.get::<Sandbox>(url, c).await
        };
        STATE_WAIT
            .until("Runtime sandbox has not started", read, |v| match &*v.state {
                "running" => Verdict::Done(v),
                state @ ("stopped" | "paused") => Verdict::Failed(refused(format!("Runtime sandbox {id} is {state} instead of running"))),
                _ => Verdict::Pending,
            })
            .await
    }
    async fn wait_enforced(&self, id: &str, c: &Credentials) -> Result<Network> {
        let read = async || self.network(id, c).await;
        ENFORCE_WAIT
            .until("Runtime has not yet enforced the sandbox's network rules", read, |network| {
                if network.enforced != Some(false) && network.enforced_version == network.version {
                    Verdict::Done(network)
                } else {
                    Verdict::Pending
                }
            })
            .await
    }
    async fn by_name(&self, name: &str, c: &Credentials) -> Result<Option<Sandbox>> {
        let mut url = self.api.url(&["sandboxes"])?;
        url.query_pairs_mut().append_pair("name", name).append_pair("includeStopped", "true");
        Ok(self.api.paged::<Sandbox>(url, &PAGED, c).await?.into_iter().find(|v| v.name == name))
    }
    fn check_existing(&self, v: &Sandbox, label: &str, size: &Size, policy: &Policy) -> Result<()> {
        if kit::ours(&v.labels, &self.name).as_deref() != Some(label) {
            return Err(refused(format!(
                "a Runtime sandbox named {} exists but is not provider {}'s for label {label}; it is left alone",
                v.name, self.name
            )));
        }
        kit::check_readopt(RUNTIME, &self.environment(v)?, size, &policy.fingerprint(), kit::DiskMatch::Exact)
    }
    async fn confirm(&self, id: &str, policy: &Policy, c: &Credentials) -> Result<()> {
        let network = self.wait_enforced(id, c).await?;
        if network.rules.normal() != *policy {
            return Err(ProtocolError::Internal {
                reason: format!("Runtime sandbox {id} holds other network rules than drydock asked for"),
                provider_error: format!("{:?}", network.rules),
            });
        }
        let mut labels = self.ours(id, c).await?.labels;
        labels.insert(ENFORCED_LABEL.into(), policy.fingerprint());
        self.act(Method::POST, self.sandbox_url(id, Some("update"), &[])?, Body::json(&Relabel { labels: &labels })?, c, false).await
    }
    async fn adopt(&self, v: Sandbox, policy: &Policy, c: &Credentials) -> Result<Environment> {
        let v = match &*v.state {
            "starting" | "resuming" => self.wait_running(&v.id, c).await?,
            _ => v,
        };
        if self.environment(&v)?.egress != Enforcement::Enforced {
            if &*v.state != "running" {
                return Err(refused(format!(
                    "Runtime sandbox {} is {} and its network rules were never confirmed; destroy it and provision again",
                    &*v.id, &*v.state
                )));
            }
            self.confirm(&v.id, policy, c).await?;
        }
        self.inspect(&v.id, c).await
    }

    async fn image(&self, name: &str, c: &Credentials) -> Result<Option<Image>> {
        let mut url = self.api.url(&["images"])?;
        url.query_pairs_mut().append_pair("name", name);
        let mut versions: Vec<Image> = self.api.paged::<Image>(url, &PAGED, c).await?.into_iter().filter(|v| v.name == name).collect();
        if let Some(at) = versions.iter().position(|v| &*v.state == "ready") {
            return Ok(Some(versions.swap_remove(at)));
        }
        match versions.iter().find(|v| matches!(&*v.state, "building" | "queued")) {
            Some(building) => self.await_build(&building.id, c).await.map(Some),
            None => Ok(None),
        }
    }
    async fn await_build(&self, id: &str, c: &Credentials) -> Result<Image> {
        let read = async || self.api.get::<Image>(self.api.url(&["images", id])?, c).await;
        BUILD_WAIT
            .until(format!("Runtime image build {id} is still running"), read, |image| match &*image.state {
                "ready" => Verdict::Done(image),
                "failed" => {
                    let error = image.error.as_deref().unwrap_or("no error recorded");
                    Verdict::Failed(refused(format!("Runtime image build {id} failed: {error}")))
                }
                "deleting" | "deleted" => {
                    Verdict::Failed(ProtocolError::unavailable(format!("Runtime image {id} was deleted while building"), None))
                }
                _ => Verdict::Pending,
            })
            .await
    }
    async fn create(&self, body: &CreateSandbox<'_>, c: &Credentials) -> Result<http::Response<bytes::Bytes>> {
        let prefer = [(HeaderName::from_static("prefer"), HeaderValue::from_static(PREFER_WAIT))];
        self.api.send(Method::POST, self.api.url(&["sandboxes"])?, Body::json(body)?, c, true, &prefer).await
    }
    async fn share(&self, id: &str, c: &Credentials) -> Result<Preview> {
        let body = SharePreview { port: self.settings.agent_port.get(), visibility: "private", ttl_seconds: PREVIEW_TTL_SECONDS };
        self.api.call(Method::POST, self.sandbox_url(id, None, &["previews"])?, Body::json(&body)?, c).await
    }
    async fn preview(&self, id: &str, c: &Credentials) -> Result<Preview> {
        let mut url = self.sandbox_url(id, None, &["previews", &self.settings.agent_port.to_string()])?;
        url.query_pairs_mut().append_pair("ttlSeconds", &PREVIEW_TTL_SECONDS.to_string());
        let preview = match self.api.find::<Preview>(url, c).await? {
            Some(preview) if &*preview.visibility == "private" => preview,
            _ => self.share(id, c).await?,
        };
        if preview.disabled {
            return Err(refused(format!("Runtime turned off sandbox {id}'s agent preview after a report; contact Runtime support")));
        }
        if &*preview.visibility != "private" || !preview.url.starts_with("https://") || preview.url.contains(['?', '#']) {
            return Err(RUNTIME.bad_response());
        }
        Ok(preview)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Policy {
    internet: bool,
    #[serde(default, deserialize_with = "nullable", skip_serializing_if = "BTreeSet::is_empty")]
    allow: BTreeSet<String>,
    #[serde(default, deserialize_with = "nullable", skip_serializing_if = "BTreeSet::is_empty")]
    deny: BTreeSet<String>,
    #[serde(default, deserialize_with = "nullable", skip_serializing_if = "BTreeSet::is_empty")]
    connect: BTreeSet<String>,
}
fn nullable<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<BTreeSet<String>, D::Error> {
    Ok(Option::<BTreeSet<String>>::deserialize(d)?.unwrap_or_default())
}
impl Policy {
    fn request(request: &EgressRequest) -> Result<Self> {
        let direct = match request {
            EgressRequest::Open => {
                return Ok(Self { internet: true, allow: BTreeSet::new(), deny: BTreeSet::new(), connect: BTreeSet::new() });
            }
            EgressRequest::DenyAll { direct } => direct,
        };
        let mut allow = BTreeSet::new();
        let mut connect = BTreeSet::new();
        for destination in direct {
            match destination {
                Destination::Host { host } => {
                    allow.insert(host_entry(host.as_str())?);
                }
                Destination::HostPort { host, port } => {
                    connect.insert(format!("{}:{}", host_entry(host.as_str())?, port.get()));
                }
                Destination::Cidr { cidr } => {
                    let Some(ip) = cidr.as_str().strip_suffix("/32").and_then(|ip| ip.parse::<Ipv4Addr>().ok()) else {
                        return Err(refused("Runtime egress rules take single IPv4 addresses, not CIDR ranges"));
                    };
                    allow.insert(host_entry(&ip.to_string())?);
                }
            }
        }
        Ok(Self { internet: !allow.is_empty(), allow, deny: BTreeSet::new(), connect })
    }
    // Runtime stores an allow list with `internet: true` whatever was sent:
    // https://withruntime.com/docs/api
    fn normal(&self) -> Self {
        let list = |entries: &BTreeSet<String>| entries.iter().map(|entry| normal_host(entry)).collect::<BTreeSet<_>>();
        let allow = list(&self.allow);
        Self { internet: self.internet || !allow.is_empty(), allow, deny: list(&self.deny), connect: list(&self.connect) }
    }
    fn fingerprint(&self) -> String {
        kit::fingerprint(&(self.internet, &self.allow, &self.deny, &self.connect))
    }
}
fn host_entry(host: &str) -> Result<String> {
    if host.contains(':') {
        return Err(refused("Runtime egress takes no IPv6 destinations"));
    }
    Ok(normal_host(host))
}

fn egress_model() -> EgressModel {
    use EgressShape::*;
    EgressModel {
        shapes: vec![Open, DenyAll, AllowAddresses, AllowDomains],
        enforced: EnforcementSite::OutsideGuest,
        side_effects: vec![EgressSideEffect {
            shapes: vec![Open, AllowAddresses, AllowDomains],
            opens: vec![],
            note: "Private addresses are always refused; a sandbox without credit reaches ports 80 and 443 only; \
                   telnet, SMB, IRC and mail ports are never reachable."
                .into(),
        }],
        mutable_while_running: true,
        sources: vec![
            "https://api.withruntime.com/v1/openapi.json#/paths/~1v1~1sandboxes~1{id}~1network".into(),
            "https://withruntime.com/docs/api".into(),
        ],
    }
}

fn image_name(image: &str, platform: &Platform) -> String {
    content_name("dd-", 40, &[image, &platform.to_string()])
}

#[async_trait]
impl Guest for Runtime {
    fn vendor(&self) -> Vendor {
        RUNTIME
    }
    async fn run(&self, id: &str, script: &str, env: BTreeMap<&str, String>, c: &Credentials) -> Result<GuestOutput> {
        let body = Execute { argv: ["sh", "-c", script], env, user: "root", timeout_ms: WAIT_SECONDS * 1000 };
        let v: Executed = self.api.call(Method::POST, self.sandbox_url(id, Some("exec"), &[])?, Body::json(&body)?, c).await?;
        Ok(GuestOutput { timed_out: v.timed_out, ..GuestOutput::from_text(&v.stdout, &v.stderr, v.exit_code) })
    }
}

#[async_trait]
impl Provider for Runtime {
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
            agent_tcp_port: Some(self.settings.agent_port),
            platforms: vec![platform()],
            image_routes: vec![ImageRoute::RegistryPull {
                auth: RegistryAuthKind::Basic,
                registration: CredentialRegistration::ProviderApi,
                digest_references: true,
                tools_layer: ToolsLayer::Upload,
            }],
            usage: true,
            quota: true,
            host_filesystem: false,
            host_processes: false,
            exclusive_label: true,
            // The agent carries outward exposures; the sandbox has no network of drydockd's.
            reach_ways: vec![ReachWay::OutwardExposure],
            semantics: Semantics { settles: true, idempotent: true, owner_scoped: true, token_is_id: false },
        }
    }
    fn observation(&self) -> ObservationMode {
        ObservationMode::Poll { interval_ms: 30_000 }
    }
    fn operations(&self) -> Operations<'_> {
        Operations {
            exec: Some(self),
            files: Some(self),
            suspend_resume: Some(self),
            usage: Some(self),
            quota: Some(self),
            ..Operations::default()
        }
    }
    fn rate_limits(&self) -> Vec<RateLimit> {
        self.settings.rate_limits.clone().unwrap_or_else(|| vec![RateLimit { operation: "*".into(), requests: 3000, period_seconds: 60 }])
    }
    async fn prepare(&self, r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
        let (_, platform) = check_prepare(RUNTIME, &r, &[ImageRouteKind::RegistryPull], &platform())?;
        let name = image_name(&r.image_digest, &platform);
        if self.image(&name, c).await?.is_none() {
            let body = BuildImage { name: &name, dockerfile: platform_dockerfile(&r.image_digest, &platform) };
            let image: Image = self.api.call(Method::POST, self.api.url(&["images"])?, Body::json(&body)?, c).await?;
            self.await_build(&image.id, c).await?;
        }
        Ok(Prepared { provider: self.name.clone(), id: name, platform, image_digest: r.image_digest, tools_digest: r.tools_digest })
    }
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        check_prepared(RUNTIME, &self.name, &r.prepared, &image_name(&r.prepared.image_digest, &r.prepared.platform))?;
        if r.label.len() > LABEL_LIMIT {
            return Err(refused("Runtime labels hold at most 256 characters"));
        }
        SIZES.check(RUNTIME, &r.size)?;
        let policy = Policy::request(&r.egress)?;
        let paid = !trial(&self.limits(c).await?);
        let body = CreateSandbox {
            name: sandbox_name("dd-", &self.name, &r.label),
            labels: BTreeMap::from([(PROVIDER_TAG, self.name.clone()), (LABEL_TAG, r.label.clone()), (POLICY_LABEL, policy.fingerprint())]),
            image: &r.prepared.id,
            vcpu: r.size.cpus as u64,
            memory: r.size.memory_bytes / MIB,
            disk: r.size.disk_bytes / MIB,
            network: &policy,
            // Runtime refuses persistent sandboxes without credit: https://withruntime.com/docs/api
            persistent: paid,
            idle_pause_seconds: 0,
        };
        let response = self.create(&body, c).await?;
        if response.status() == 409 && serde_json::from_slice::<ErrorBody>(response.body()).is_ok_and(|e| e.error.code == "name_taken") {
            let v = self
                .by_name(&body.name, c)
                .await?
                .ok_or_else(|| ProtocolError::unavailable("Runtime reports the name taken but lists no sandbox by it", Some(2)))?;
            self.check_existing(&v, &r.label, &r.size, &policy)?;
            return Ok(Provisioned::Existing(self.adopt(v, &policy, c).await?));
        }
        let created: Sandbox = self.api.answer("POST /v1/sandboxes", &response)?;
        if &*created.state != "running" {
            self.wait_running(&created.id, c).await?;
        }
        self.confirm(&created.id, &policy, c).await?;
        Ok(Provisioned::Created(self.inspect(&created.id, c).await?))
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        self.listed(c).await?.iter().map(|v| self.environment(v)).collect()
    }
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        self.environment(&self.ours(id, c).await?)
    }
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        let Some(v) = absent_on_not_found(self.sandbox(id, c).await)? else { return Ok(()) };
        kit::require_ours(RUNTIME, id, &v.labels, &self.name)?;
        self.agents.forget(id);
        let port = self.settings.agent_port.to_string();
        for url in [self.sandbox_url(id, None, &["previews", &port])?, self.sandbox_url(id, None, &[])?] {
            absent_on_not_found(self.act(Method::DELETE, url, Body::None, c, false).await)?;
        }
        Ok(())
    }
    // A preview's edge takes its token in its own header and strips it,
    // passing `Authorization` to the guest: https://withruntime.com/docs/api
    async fn reach(&self, id: &str, c: &Credentials) -> Result<Reach> {
        let v = self.ours(id, c).await?;
        if &*v.state != "running" {
            return Err(refused(format!("Runtime sandbox {id} is {}, not running; resume it first", &*v.state)));
        }
        let token = Secret::new(self.agents.get(self, id, c).await?.secret());
        let preview = self.preview(id, c).await?;
        let Some(preview_token) = preview.token.filter(|token| !token.is_empty() && sensitive(token).is_ok()) else {
            return Err(refused("Runtime signs no preview token for this key: it needs the right to run commands in the sandbox"));
        };
        let expires_at = preview.token_expires_at.ok_or_else(|| RUNTIME.bad_response())?;
        Ok(Reach::Dial {
            url: format!("{}{}", preview.url.trim_end_matches('/'), drydock_transport::tcp::CONNECT_PATH),
            token,
            headers: BTreeMap::from([(PREVIEW_TOKEN_HEADER.to_owned(), Secret::new(preview_token))]),
            expires_at: expires_at.into(),
        })
    }
    async fn relay(&self, _: &str, _: &Credentials) -> Result<ByteStream> {
        Err(refused("Runtime is reached by a dial reach to its preview edge"))
    }
}

#[async_trait]
impl SuspendResume for Runtime {
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        let state = self.ours(id, c).await?.state;
        if matches!(&*state, "starting" | "resuming") {
            return Err(ProtocolError::unavailable(format!("Runtime sandbox {id} is {state}"), Some(5)));
        }
        if &*state == "running" {
            self.act(Method::POST, self.sandbox_url(id, Some("pause"), &[])?, Body::None, c, true).await?;
        }
        self.agents.forget(id);
        let read = async || Ok(self.sandbox(id, c).await?.state);
        STATE_WAIT
            .until("Runtime sandbox has not paused", read, |state| match &*state {
                "paused" | "stopped" => Verdict::Done(RUNTIME.resume_marker("runtime-resume-", &self.name, id)),
                "pausing" | "running" => Verdict::Pending,
                other => Verdict::Failed(refused(format!("Runtime sandbox {id} is {other}, not pausing"))),
            })
            .await
    }
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()> {
        RUNTIME.check_resume("runtime-resume-", &self.name, id, &token)?;
        self.agents.forget(id);
        let action = match &*self.ours(id, c).await?.state {
            "paused" | "pausing" => Some("wake"),
            "stopped" => Some("restart"),
            _ => None,
        };
        if let Some(action) = action {
            self.act(Method::POST, self.sandbox_url(id, Some(action), &[])?, Body::None, c, true).await?;
        }
        self.wait_running(id, c).await.map(drop)
    }
}

#[async_trait]
impl Exec for Runtime {
    async fn exec(&self, id: &str, r: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        self.ours(id, c).await?;
        Guest::exec(self, id, r, c).await
    }
}

// The file API writes as the sandbox user, one request of at most 1 MiB; a
// chunked archive upload unpacks as root at any size:
// https://withruntime.com/docs/api
#[async_trait]
impl GuestFiles for Runtime {
    async fn put(&self, id: &str, file: GuestFile, bytes: Bytes, c: &Credentials) -> Result<()> {
        let path = std::path::Path::new(&file.path);
        let (Some(folder), Some(name)) = (path.parent().and_then(|p| p.to_str()), path.file_name()) else {
            return Err(refused(format!("{} names no file", file.path)));
        };
        let internal = |e: std::io::Error| ProtocolError::Internal { reason: "the upload's archive".into(), provider_error: e.to_string() };
        let mut header = tar::Header::new_ustar();
        header.set_path(name).map_err(internal)?;
        header.set_size(bytes.len() as u64);
        header.set_mode(file.mode);
        header.set_cksum();
        let mut archive = tar::Builder::new(Vec::new());
        archive.append(&header, &bytes[..]).map_err(internal)?;
        let archive = archive.into_inner().map_err(internal)?;
        let begin = BeginUpload { path: folder, user: "root" };
        let upload: Upload =
            self.api.call(Method::POST, self.sandbox_url(id, None, &["files", "archive", "uploads"])?, Body::json(&begin)?, c).await?;
        let chunk_bytes = upload.chunk_bytes.clamp(1, MIB as usize);
        for (index, chunk) in archive.chunks(chunk_bytes).enumerate() {
            let mut url = self.sandbox_url(id, None, &["files", "archive", "uploads", &upload.upload_id])?;
            url.query_pairs_mut().append_pair("offset", &(index * chunk_bytes).to_string());
            self.act(Method::PUT, url, Body::Bytes(Bytes::copy_from_slice(chunk), "application/octet-stream"), c, false).await?;
        }
        let commit = format!("{}:commit", &*upload.upload_id);
        self.act(Method::POST, self.sandbox_url(id, None, &["files", "archive", "uploads", &commit])?, Body::None, c, false).await
    }
}

#[async_trait]
impl QuotaOperation for Runtime {
    async fn quota(&self, c: &Credentials) -> Result<Quota> {
        let limits = self.limits(c).await?;
        let mut resources = Vec::new();
        let (mut in_use, mut limit) = (None, None);
        for row in &limits.account {
            let (resource, unit, factor) = match row.limit.as_str() {
                "sandbox.count" => {
                    (in_use, limit) = (Some(row.used), Some(row.max));
                    (ResourceKind::Environments, "1", 1.0)
                }
                "sandbox.vcpu" => (ResourceKind::Cpu, "{vCPU}", 1.0),
                "sandbox.memory_mib" => (ResourceKind::Memory, "By", MIB as f64),
                "sandbox.disk_mib" => (ResourceKind::Disk, "By", MIB as f64),
                _ => continue,
            };
            resources.push(ResourceQuota {
                key: QuotaKey { region: None, class: None, resource },
                unit: unit.into(),
                in_use: row.used as f64 * factor,
                limit: Some(row.max as f64 * factor),
            });
        }
        Ok(Quota {
            resources,
            credits_remaining: Some(limits.credit.available_micros.0 as f64 / 1e6),
            credit_unit: Some("USD".into()),
            concurrency_in_use: in_use,
            concurrency_limit: limit,
        })
    }
}

// The usage export holds settled charges only, without sizes or a running
// sandbox's last minute; lifecycle events, kept 14 days, carry each sandbox as
// it was: https://withruntime.com/docs/api
#[async_trait]
impl UsageOperation for Runtime {
    async fn usage(&self, period: Period, c: &Credentials) -> Result<Usage> {
        let (from, to, now) = (period.start().instant(), period.end().instant(), Utc::now());
        if now - from > chrono::Duration::days(EVENT_DAYS) {
            return Err(refused(format!("Runtime keeps sandbox events {EVENT_DAYS} days; ask for usage since then")));
        }
        let live: BTreeMap<String, Sandbox> = self.listed(c).await?.into_iter().map(|v| (v.id.to_string(), v)).collect();
        let mut seen: BTreeMap<String, Vec<Event>> = live.keys().map(|id| (id.clone(), Vec::new())).collect();
        for event in self.events(None, from, c).await? {
            let Some(v) = event.data.sandbox.as_ref().filter(|v| kit::ours(&v.labels, &self.name).is_some()) else { continue };
            let id = v.id.to_string();
            if event.created_at >= from || seen.contains_key(&id) {
                seen.entry(id).or_default().push(event);
            }
        }
        let mut runs = Vec::new();
        for (id, events) in &mut seen {
            let oldest = events.iter().filter(|e| is_lifecycle(e)).min_by_key(|e| e.created_at);
            let known = oldest
                .map_or(live.contains_key(id), |e| e.created_at < from || matches!(e.kind.as_str(), "sandbox.running" | "sandbox.woken"));
            let events = if known { std::mem::take(events) } else { self.events(Some(id), from, c).await? };
            let mut found = runs_of(events, from, now)?;
            if let Some(v) = live.get(id).filter(|v| found.is_empty() && &*v.state == "running") {
                found.extend(v.ready_at.zip(size(v)?).map(|(ready, size)| (ready.max(from), now, size)));
            }
            runs.extend(found.into_iter().map(|run| (id.clone(), run)));
        }
        let mut environment_hours: Vec<SizeUsage> = Vec::new();
        let mut environments = BTreeSet::new();
        for (id, (start, end, size)) in runs {
            let millis = overlap(start, end, from, to);
            if millis > 0 {
                environments.insert(id);
                match environment_hours.iter_mut().find(|row| row.size == size) {
                    Some(row) => row.hours += millis as f64 / 3_600_000.0,
                    None => environment_hours.push(SizeUsage { size, hours: millis as f64 / 3_600_000.0 }),
                }
            }
        }
        let stamp = |t: DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut url = self.api.url(&["usage", "export"])?;
        url.query_pairs_mut().append_pair("since", &stamp(from)).append_pair("until", &stamp(now.max(to))).append_pair("limit", "500");
        let mut charged: u128 = 0;
        for row in self.api.paged::<Charge>(url, &PAGED, c).await? {
            let part = overlap(row.starts_at, row.ends_at, from, to);
            if row.kind == "sandbox" && part > 0 && seen.contains_key(&*row.resource_id) {
                charged += row.charged_micros.0 * part as u128 / (row.ends_at - row.starts_at).num_milliseconds().max(1) as u128;
                environments.insert(row.resource_id.to_string());
            }
        }
        Ok(Usage {
            period,
            environment_hours,
            measurements: Some(UsageMeasurements {
                scope: UsageScope::Provider,
                resources: BTreeMap::from([(ResourceKind::Environments, Quantity { amount: environments.len() as f64, unit: "1".into() })]),
                cost: Some(Cost { amount: Micros(charged).usd(), currency: "USD".into() }),
            }),
        })
    }
}
impl Runtime {
    // Events come newest first: https://withruntime.com/docs/api
    async fn events(&self, resource: Option<&str>, from: DateTime<Utc>, c: &Credentials) -> Result<Vec<Event>> {
        let mut url = self.api.url(&["events"])?;
        url.query_pairs_mut().append_pair("limit", "100");
        if let Some(id) = resource {
            url.query_pairs_mut().append_pair("resourceId", id);
        }
        // Read back to the first page that reaches `from`.
        let reached = |page: &[Event]| page.last().is_none_or(|e| e.created_at < from);
        match self.api.paged_until(url, &PAGED, kit::api::MAX_PAGES, c, reached).await? {
            (events, true) => Ok(events),
            _ => Err(RUNTIME.bad_response()),
        }
    }
}
fn is_lifecycle(e: &Event) -> bool {
    matches!(e.kind.as_str(), "sandbox.running" | "sandbox.woken" | "sandbox.paused" | "sandbox.stopped")
}
type Run = (DateTime<Utc>, DateTime<Utc>, Size);
fn runs_of(mut events: Vec<Event>, from: DateTime<Utc>, now: DateTime<Utc>) -> Result<Vec<Run>> {
    events.retain(is_lifecycle);
    events.sort_by_key(|e| e.created_at);
    let first = events.iter().rposition(|e| e.created_at < from).unwrap_or(0);
    let (mut runs, mut open) = (Vec::new(), None);
    for event in &events[first..] {
        let Some(v) = &event.data.sandbox else { continue };
        match (event.kind.as_str(), open.take()) {
            ("sandbox.running" | "sandbox.woken", None) => {
                open = Some((event.created_at.max(from), size(v)?.ok_or_else(|| RUNTIME.bad_response())?))
            }
            ("sandbox.running" | "sandbox.woken", started) => open = started,
            (_, Some((start, size))) => runs.push((start, event.created_at, size)),
            (_, None) => {}
        }
    }
    runs.extend(open.map(|(start, size)| (start, now, size)));
    Ok(runs)
}
fn overlap(start: DateTime<Utc>, end: DateTime<Utc>, from: DateTime<Utc>, to: DateTime<Utc>) -> i64 {
    (end.min(to) - start.max(from)).num_milliseconds().max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_formats() {
        assert_eq!(Micros(1_234_567).usd(), "1.234567");
        let stored: Network = serde_json::from_str(r#"{"internet":false,"allow":["GitHub.com."],"deny":null,"version":1}"#).unwrap();
        let asked = Policy::request(&EgressRequest::DenyAll { direct: vec![Destination::Host { host: "github.com".parse().unwrap() }] });
        assert_eq!(stored.rules.normal(), asked.unwrap());
        let sandbox = r#"{"id":"7f3a2c10-58d4-4b9e-9c61-0a2b3c4d5e6f","state":"running","vcpu":2,"memoryMiB":4096,"diskMiB":10240}"#;
        let event = |kind: &str, at: &str| -> Event {
            serde_json::from_str(&format!(r#"{{"type":"{kind}","createdAt":"{at}","data":{{"sandbox":{sandbox}}}}}"#)).unwrap()
        };
        let at = |t: &str| t.parse::<DateTime<Utc>>().unwrap();
        let events = vec![
            event("sandbox.paused", "2026-09-23T15:30:00Z"),
            event("sandbox.running", "2026-09-23T15:00:00Z"),
            event("sandbox.woken", "2026-09-23T16:00:00Z"),
        ];
        let runs = runs_of(events, at("2026-09-23T15:10:00Z"), at("2026-09-23T16:15:00Z")).unwrap();
        let spans: Vec<_> = runs.iter().map(|(start, end, _)| (*end - *start).num_minutes()).collect();
        assert_eq!(spans, [20, 15]);
        assert_eq!(runs[0].2, Size { cpus: 2.0, memory_bytes: 4 * GIB, disk_bytes: 10 * GIB });
    }
}

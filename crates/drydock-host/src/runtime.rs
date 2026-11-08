//! Runtime (withruntime.com) translator: each verb is Runtime's own
//! operation, and each answer is what Runtime said. Waiting, idempotence and
//! ownership are drydockd's, as the declared [`Semantics`] leave them (see
//! `capabilities`). A vessel is reached by a dial to a private preview of the
//! agent's port. API contract: https://api.withruntime.com/v1/openapi.json
use crate::{
    kit::{
        self, GIB, LABEL_TAG, MIB, SizeLimits, StateTable, Vendor,
        api::{Api, Auth, Body, EXPLANATION_CHARS, Failure, Next, Paging, Text, absent_on_not_found, cut, sensitive},
        guest::{Guest, GuestOutput},
        image::{check_prepare, check_prepared, content_name, platform_dockerfile},
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
use serde::{Deserialize, Serialize, de::IgnoredAny};
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
const LABEL_LIMIT: usize = 256;
/// Runtime's own wait inside one call: the answer comes once the sandbox
/// settled, or after this many seconds, inside drydock's HTTP deadline.
const PREFER_WAIT: &str = "wait=25";
const PREVIEW_TOKEN_HEADER: &str = "x-runtime-preview-token";

/// Runtime does not say whether a client or Runtime paused or stopped a
/// sandbox in its state; `stopReason`, reported beside it, does.
const STATES: StateTable = &[
    ("starting", kit::starting()),
    ("resuming", kit::starting()),
    ("running", Observation::Running),
    ("pausing", kit::stopping()),
    ("stopping", kit::stopping()),
    ("paused", Observation::Stopped { cause: None }),
    ("stopped", Observation::Stopped { cause: None }),
];

// Runtime's wire types (see the API contract above), only the fields read.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Sandbox {
    id: Text,
    state: Text,
    labels: Option<BTreeMap<String, String>>,
    vcpu: Option<u64>,
    #[serde(rename = "memoryMiB")]
    memory: Option<u64>,
    #[serde(rename = "diskMiB")]
    disk: Option<u64>,
    stop_reason: Option<String>,
    /// When its current run became ready.
    ready_at: Option<DateTime<Utc>>,
    /// When its last run ended.
    ended_at: Option<DateTime<Utc>>,
}
/// A sandbox's network as Runtime reads it back: the rules it holds, and the
/// version its host confirmed.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Network {
    internet: Option<bool>,
    allow: Option<Vec<String>>,
    deny: Option<Vec<String>>,
    connect: Option<Vec<String>>,
    #[serde(skip_serializing)]
    version: Option<u64>,
    #[serde(skip_serializing)]
    enforced: Option<bool>,
    #[serde(skip_serializing)]
    enforced_version: Option<u64>,
}
#[derive(Deserialize)]
struct Image {
    id: Text,
    name: Option<String>,
    state: Text,
    error: Option<String>,
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
    available_micros: Micros,
}
/// Runtime states all four, `exitCode` null after a timeout.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Executed {
    exit_code: Option<i64>,
    stdout: String,
    stderr: String,
    timed_out: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Preview {
    url: Text,
    visibility: Text,
    token: Option<String>,
    token_expires_at: Option<DateTime<Utc>>,
    disabled: Option<bool>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Upload {
    upload_id: Text,
    chunk_bytes: usize,
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

pub struct RuntimeModule;

/// Every key has a default.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Settings {
    api_url: String,
    agent_port: NonZeroU16,
    rate_limits: Option<Vec<RateLimit>>,
    /// Sandboxes have no time limit. Runtime refuses this on an account
    /// without credit, which sets it false.
    persistent: bool,
    /// How often drydockd lists sandboxes.
    poll_seconds: u64,
    /// How often prepare reads an image build's state, and how many times
    /// before it answers unavailable.
    build_poll_seconds: u64,
    build_polls: u32,
    /// How long a preview token reach signs lasts.
    preview_ttl_seconds: u32,
    /// Runtime's limit on one command.
    exec_seconds: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            api_url: "https://api.withruntime.com/v1".into(),
            agent_port: NonZeroU16::new(7811).expect("non-zero"),
            rate_limits: None,
            persistent: true,
            poll_seconds: 30,
            build_poll_seconds: 3,
            build_polls: 150,
            preview_ttl_seconds: 86_400,
            exec_seconds: 25,
        }
    }
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
        if [settings.poll_seconds, settings.build_poll_seconds, settings.exec_seconds].contains(&0)
            || settings.build_polls == 0
            || settings.preview_ttl_seconds == 0
        {
            return Err(refused("Runtime's poll, build, preview and exec settings must be positive"));
        }
        if name.contains(':') || name.len() > LABEL_LIMIT {
            return Err(refused("a Runtime provider's name becomes a label value: no ':' and at most 256 characters"));
        }
        let api = Api::new(RUNTIME, &settings.api_url, Auth::Bearer, http)?.classify(classify);
        Ok(Arc::new(Runtime { name: name.to_owned(), ownership: config.ownership, settings, api }))
    }
}

pub struct Runtime {
    name: String,
    ownership: Ownership,
    settings: Settings,
    api: Api,
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
    let retry_after = f.retry_after.or(error.retry_after_ms.map(|ms| ms.div_ceil(1000)));
    let reason = f.reason(&if code.is_empty() { message } else { format!("{code}: {message}") });
    let quota = code == "quota_exceeded" || code.starts_with("no_credit_") || code.ends_with("_limit_reached") || code == "daily_limit";
    match f.status {
        410 => ProtocolError::NotFound { reason },
        409 | 429 if quota => ProtocolError::QuotaExhausted { reason },
        429 => ProtocolError::RateLimited { reason, retry_after },
        400..=499 if retry_after.is_some() && ![401, 402, 403, 404].contains(&f.status) => {
            ProtocolError::Unavailable { reason, retry_after, provider_error: None }
        }
        _ => Failure { retry_after, ..*f }.standard(reason),
    }
}
/// Every Runtime sandbox is an x86_64 microVM.
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
    /// A POST that Runtime answers once the sandbox settled, or at its wait.
    async fn act(&self, id: &str, action: &str, c: &Credentials) -> Result<()> {
        let prefer = [(HeaderName::from_static("prefer"), HeaderValue::from_static(PREFER_WAIT))];
        let url = self.sandbox_url(id, Some(action), &[])?;
        self.api.call_with::<IgnoredAny>(Method::POST, url, Body::None, c, &prefer).await.map(drop)
    }
    /// A row as Runtime gives it. No row carries the network, so its egress
    /// is advisory and its policy unstated; inspect reads both.
    fn environment(&self, v: Sandbox) -> Result<Environment> {
        let timestamp = match &*v.state {
            "running" => v.ready_at,
            "stopped" => v.ended_at,
            _ => None,
        };
        Ok(Environment {
            id: v.id.to_string(),
            provider: self.name.clone(),
            label: v.labels.as_ref().and_then(|l| l.get(LABEL_TAG)).cloned(),
            state: kit::observe(STATES, &v.state),
            granted_size: kit::granted(RUNTIME, v.vcpu, v.memory, MIB, v.disk, MIB)?,
            egress: Enforcement::Advisory,
            // Runtime states no platform per sandbox; drydockd takes the one declared.
            platform: None,
            egress_measured: false,
            egress_policy: None,
            timestamp: timestamp.map(Into::into),
            vendor: Some(VendorState { state: v.state.into(), reason: v.stop_reason, tags: v.labels }),
        })
    }
    async fn image(&self, name: &str, c: &Credentials) -> Result<Option<Image>> {
        let mut url = self.api.url(&["images"])?;
        url.query_pairs_mut().append_pair("name", name);
        let mut versions: Vec<Image> =
            self.api.paged::<Image>(url, &PAGED, c).await?.into_iter().filter(|v| v.name.as_deref() == Some(name)).collect();
        if let Some(at) = versions.iter().position(|v| &*v.state == "ready") {
            return Ok(Some(versions.swap_remove(at)));
        }
        match versions.iter().find(|v| matches!(&*v.state, "building" | "queued")) {
            Some(building) => self.await_build(&building.id, c).await.map(Some),
            None => Ok(None),
        }
    }
    /// Runtime offers no other way to learn that a build ended.
    async fn await_build(&self, id: &str, c: &Credentials) -> Result<Image> {
        let interval = Duration::from_secs(self.settings.build_poll_seconds);
        kit::poll(self.settings.build_polls, interval, async || {
            let image: Image = self.api.get(self.api.url(&["images", id])?, c).await?;
            match &*image.state {
                "ready" => Ok(Some(image)),
                "failed" => Err(refused(match image.error {
                    Some(error) => format!("Runtime image build {id} failed: {error}"),
                    None => format!("Runtime image build {id} failed"),
                })),
                "deleting" | "deleted" => Err(ProtocolError::unavailable(format!("Runtime image {id} was deleted while building"), None)),
                _ => Ok(None),
            }
        })
        .await?
        .ok_or_else(|| ProtocolError::unavailable(format!("Runtime image build {id} is still running"), Some(30)))
    }
    async fn share(&self, id: &str, c: &Credentials) -> Result<Preview> {
        let body = json!({"port": self.settings.agent_port, "visibility": "private", "ttlSeconds": self.settings.preview_ttl_seconds});
        self.api.call(Method::POST, self.sandbox_url(id, None, &["previews"])?, Body::json(&body)?, c).await
    }
    async fn preview(&self, id: &str, c: &Credentials) -> Result<Preview> {
        let mut url = self.sandbox_url(id, None, &["previews", &self.settings.agent_port.to_string()])?;
        url.query_pairs_mut().append_pair("ttlSeconds", &self.settings.preview_ttl_seconds.to_string());
        let preview = match self.api.find::<Preview>(url, c).await? {
            Some(preview) if &*preview.visibility == "private" => preview,
            _ => self.share(id, c).await?,
        };
        if preview.disabled == Some(true) {
            return Err(refused(format!("Runtime turned off sandbox {id}'s agent preview after a report; contact Runtime support")));
        }
        if &*preview.visibility != "private" || !preview.url.starts_with("https://") || preview.url.contains(['?', '#']) {
            return Err(RUNTIME.bad_response());
        }
        Ok(preview)
    }
}

/// Runtime's network rules, as created.
#[derive(Debug, PartialEq, Serialize)]
struct Policy {
    internet: bool,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    allow: BTreeSet<String>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    connect: BTreeSet<String>,
}
impl Policy {
    fn request(request: &EgressRequest) -> Result<Self> {
        let direct = match request {
            EgressRequest::Open => return Ok(Self { internet: true, allow: BTreeSet::new(), connect: BTreeSet::new() }),
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
                    allow.insert(ip.to_string());
                }
            }
        }
        // Runtime stores an allow list with `internet: true` whatever was
        // sent: https://withruntime.com/docs/api
        Ok(Self { internet: !allow.is_empty(), allow, connect })
    }
}
fn host_entry(host: &str) -> Result<String> {
    if host.contains(':') {
        return Err(refused("Runtime egress takes no IPv6 destinations"));
    }
    Ok(host.to_owned())
}
/// The rules as Runtime stated them: a field it left out stays apart from an
/// empty one.
fn fingerprint(network: &Network) -> String {
    kit::digest(&json!(network).to_string())[..32].to_owned()
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

/// Runtime refuses a second sandbox by a name it holds, so one label of an
/// instance has one sandbox at a time.
fn sandbox_name(instance: &str, label: &str) -> String {
    content_name("dd-", 40, &[instance, label])
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
        let mut body = json!({"argv": ["sh", "-c", script], "user": "root", "timeoutMs": self.settings.exec_seconds.saturating_mul(1000)});
        if !env.is_empty() {
            body["env"] = json!(env);
        }
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
            // Runtime's usage export and event log are its sources, to be
            // collected as Runtime gives them (drydock#257); no figure is derived.
            usage: false,
            quota: true,
            host_filesystem: false,
            host_processes: false,
            // A second provision of a label is Runtime's refusal of the name,
            // not the sandbox that holds it.
            exclusive_label: false,
            // The agent carries outward exposures; the sandbox has no network of drydockd's.
            reach_ways: vec![ReachWay::OutwardExposure],
            // Create, pause, wake and restart answer at Runtime's wait, settled
            // or not; a repeated one is Runtime's to answer; list and delete
            // reach the whole account; and Runtime resumes by id alone.
            semantics: Semantics { token_is_id: true, ..Semantics::default() },
        }
    }
    fn ways_in(&self) -> Vec<WayIn> {
        vec![WayIn::Poll { interval_ms: self.settings.poll_seconds.saturating_mul(1000) }]
    }
    fn operations(&self) -> Operations<'_> {
        Operations { exec: Some(self), files: Some(self), suspend_resume: Some(self), quota: Some(self), ..Operations::default() }
    }
    fn rate_limits(&self) -> Vec<RateLimit> {
        self.settings.rate_limits.clone().unwrap_or_else(|| vec![RateLimit { operation: "*".into(), requests: 3000, period_seconds: 60 }])
    }
    async fn prepare(&self, r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
        let (_, platform) = check_prepare(RUNTIME, &r, &[ImageRouteKind::RegistryPull], &platform())?;
        let name = image_name(&r.image_digest, &platform);
        if self.image(&name, c).await?.is_none() {
            let body = json!({"name": name, "dockerfile": platform_dockerfile(&r.image_digest, &platform)});
            let image: Image = self.api.call(Method::POST, self.api.url(&["images"])?, Body::json(&body)?, c).await?;
            self.await_build(&image.id, c).await?;
        }
        Ok(Prepared { provider: self.name.clone(), id: name, platform, image_digest: r.image_digest, tools_digest: r.tools_digest })
    }
    /// One create, answered with Runtime's row. The owner tag goes on only on
    /// a shared account.
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        check_prepared(RUNTIME, &self.name, &r.prepared, &image_name(&r.prepared.image_digest, &r.prepared.platform))?;
        if r.label.len() > LABEL_LIMIT {
            return Err(refused("Runtime labels hold at most 256 characters"));
        }
        SIZES.check(RUNTIME, &r.size)?;
        let policy = Policy::request(&r.egress)?;
        let mut labels = BTreeMap::from([(LABEL_TAG, r.label.as_str())]);
        if self.ownership == Ownership::SharedAccount {
            labels.insert(OWNER_TAG, &self.name);
        }
        let body = json!({
            "name": sandbox_name(&self.name, &r.label),
            "labels": labels,
            "image": r.prepared.id,
            "vcpu": r.size.cpus as u64,
            "memoryMiB": r.size.memory_bytes / MIB,
            "diskMiB": r.size.disk_bytes / MIB,
            "network": policy,
            "persistent": self.settings.persistent,
            "idlePauseSeconds": 0,
        });
        let prefer = [(HeaderName::from_static("prefer"), HeaderValue::from_static(PREFER_WAIT))];
        let created: Sandbox = self.api.call_with(Method::POST, self.api.url(&["sandboxes"])?, Body::json(&body)?, c, &prefer).await?;
        Ok(Provisioned::Created(self.environment(created)?))
    }
    /// Every sandbox Runtime lists, stopped ones included: on a shared
    /// account, those carrying this instance's owner tag, as Runtime filters.
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        let mut url = self.api.url(&["sandboxes"])?;
        url.query_pairs_mut().append_pair("includeStopped", "true").append_pair("limit", "100");
        if self.ownership == Ownership::SharedAccount {
            url.query_pairs_mut().append_pair("label", &format!("{OWNER_TAG}:{}", self.name));
        }
        self.api.paged::<Sandbox>(url, &PAGED, c).await?.into_iter().map(|v| self.environment(v)).collect()
    }
    /// The sandbox and its network. Egress is enforced when Runtime says its
    /// host confirmed the version of the rules it holds.
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        let mut environment = self.environment(self.sandbox(id, c).await?)?;
        let network: Network = self.api.get(self.sandbox_url(id, None, &["network"])?, c).await?;
        if network.enforced == Some(true) && network.version.is_some() && network.enforced_version == network.version {
            environment.egress = Enforcement::Enforced;
        }
        environment.egress_policy = Some(fingerprint(&network));
        Ok(environment)
    }
    /// Two deletes: Runtime keeps a sandbox's preview after the sandbox goes,
    /// so the agent's preview goes first. A sandbox that never had one has
    /// none to delete.
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        let preview = self.sandbox_url(id, None, &["previews", &self.settings.agent_port.to_string()])?;
        absent_on_not_found(self.api.call::<IgnoredAny>(Method::DELETE, preview, Body::None, c).await)?;
        self.api.call::<IgnoredAny>(Method::DELETE, self.sandbox_url(id, None, &[])?, Body::None, c).await.map(drop)
    }
    /// The agent's private preview, shared when it has none, and the agent's
    /// token. A preview's edge takes its token in its own header and strips
    /// it, passing `Authorization` to the guest: https://withruntime.com/docs/api
    async fn reach(&self, id: &str, c: &Credentials) -> Result<Reach> {
        let token = self.agent_token(id, c).await?;
        let preview = self.preview(id, c).await?;
        let Some(preview_token) = preview.token.filter(|token| !token.is_empty() && sensitive(token).is_ok()) else {
            return Err(refused("Runtime signs no preview token for this key: it needs the right to run commands in the sandbox"));
        };
        let expires_at = preview.token_expires_at.ok_or_else(|| RUNTIME.bad_response())?;
        Ok(Reach::Dial {
            url: format!("{}{}", preview.url.trim_end_matches('/'), drydock_transport::tcp::CONNECT_PATH),
            token,
            headers: BTreeMap::from([(PREVIEW_TOKEN_HEADER.to_owned(), Secret::new(preview_token))]),
            expires_at: Some(expires_at.into()),
        })
    }
    async fn relay(&self, _: &str, _: &Credentials) -> Result<ByteStream> {
        Err(refused("Runtime is reached by a dial reach to its preview edge"))
    }
}

/// Pause, and wake or restart. Runtime resumes by id alone, so the token is
/// the id.
#[async_trait]
impl SuspendResume for Runtime {
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        self.act(id, "pause", c).await?;
        Ok(ResumeToken { token: Secret::new(id) })
    }
    /// Runtime wakes a paused sandbox and restarts a stopped one, two
    /// operations: the one state read picks between them. Any other state is
    /// Runtime's to answer, to a wake.
    async fn resume(&self, id: &str, _: ResumeToken, c: &Credentials) -> Result<()> {
        let action = if &*self.sandbox(id, c).await?.state == "stopped" { "restart" } else { "wake" };
        self.act(id, action, c).await
    }
}

#[async_trait]
impl Exec for Runtime {
    async fn exec(&self, id: &str, r: ExecRequest, c: &Credentials) -> Result<ByteStream> {
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
        let begin = json!({"path": folder, "user": "root"});
        let upload: Upload =
            self.api.call(Method::POST, self.sandbox_url(id, None, &["files", "archive", "uploads"])?, Body::json(&begin)?, c).await?;
        let chunk_bytes = upload.chunk_bytes.clamp(1, MIB as usize);
        for (index, chunk) in archive.chunks(chunk_bytes).enumerate() {
            let mut url = self.sandbox_url(id, None, &["files", "archive", "uploads", &upload.upload_id])?;
            url.query_pairs_mut().append_pair("offset", &(index * chunk_bytes).to_string());
            let body = Body::Bytes(Bytes::copy_from_slice(chunk), "application/octet-stream");
            self.api.call::<IgnoredAny>(Method::PUT, url, body, c).await?;
        }
        let commit = format!("{}:commit", &*upload.upload_id);
        let url = self.sandbox_url(id, None, &["files", "archive", "uploads", &commit])?;
        self.api.call::<IgnoredAny>(Method::POST, url, Body::None, c).await.map(drop)
    }
}

#[async_trait]
impl QuotaOperation for Runtime {
    async fn quota(&self, c: &Credentials) -> Result<Quota> {
        let limits: Limits = self.api.get(self.api.url(&["limits"])?, c).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use rigging_http_client::ChannelLabel;
    use std::sync::Mutex;

    /// Answers each request with the next scripted (status, body), keeping
    /// each request's method, path and query, and body.
    #[derive(Default)]
    struct Script {
        answers: Mutex<Vec<(u16, &'static str)>>,
        asked: Mutex<Vec<(String, String, serde_json::Value)>>,
    }
    #[async_trait]
    impl HttpClient for Script {
        async fn execute(&self, request: reqwest::Request, _: &ChannelLabel) -> std::result::Result<http::Response<Bytes>, String> {
            let body = request.body().and_then(|b| b.as_bytes()).and_then(|b| serde_json::from_slice(b).ok()).unwrap_or_default();
            let url = request.url();
            let target = url.query().map_or_else(|| url.path().to_owned(), |q| format!("{}?{q}", url.path()));
            self.asked.lock().unwrap().push((request.method().to_string(), target, body));
            let (status, body) = {
                let mut answers = self.answers.lock().unwrap();
                assert!(!answers.is_empty(), "unscripted request {} {}", request.method(), request.url());
                answers.remove(0)
            };
            Ok(http::Response::builder().status(status).body(Bytes::from_static(body.as_bytes())).unwrap())
        }
    }
    impl Script {
        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().iter().map(|(m, target, _)| format!("{m} {target}")).collect()
        }
    }
    async fn configure(ownership: Ownership, settings: serde_json::Value, script: Arc<Script>) -> Result<Arc<dyn Provider>> {
        let settings = serde_json::from_value(settings).unwrap();
        let config = ProviderConfiguration { module: "runtime".into(), settings, ownership, ..Default::default() };
        RuntimeModule.configure("rt", &config, script).await
    }
    async fn runtime(ownership: Ownership, answers: Vec<(u16, &'static str)>) -> (Arc<dyn Provider>, Arc<Script>) {
        let script = Arc::new(Script { answers: Mutex::new(answers), ..Script::default() });
        (configure(ownership, json!({}), script.clone()).await.unwrap(), script)
    }
    fn key() -> Credentials {
        Credentials::new(Some(Secret::new("k")))
    }
    const ID: &str = "7f3a2c10-58d4-4b9e-9c61-0a2b3c4d5e6f";
    const STARTING: &str = r#"{"id":"7f3a2c10-58d4-4b9e-9c61-0a2b3c4d5e6f","state":"starting","vcpu":1,"memoryMiB":1024,"diskMiB":4096,
        "labels":{"flotilla.label":"crew-1"}}"#;

    // Provision is one create, answered with Runtime's row as it stands. The
    // owner tag goes on only on a shared account; persistence is the setting.
    #[tokio::test]
    async fn provision_is_one_create_tagged_by_ownership() {
        for (ownership, tags) in [(Ownership::SharedAccount, 2), (Ownership::OwnedAccount, 1)] {
            let (runtime, script) = runtime(ownership, vec![(201, STARTING)]).await;
            let digest = "registry.example/base@sha256:0000000000000000000000000000000000000000000000000000000000000000";
            let prepared = Prepared {
                provider: "rt".into(),
                id: image_name(digest, &platform()),
                platform: platform(),
                image_digest: digest.into(),
                tools_digest: "tools".into(),
            };
            let size = Size { cpus: 1.0, memory_bytes: GIB, disk_bytes: 4 * GIB };
            let request = ProvisionRequest { label: "crew-1".into(), prepared, size, egress: EgressRequest::Open, ssh_public_key: None };
            let Provisioned::Created(e) = runtime.provision(request, &key()).await.unwrap() else { panic!("not created") };
            assert_eq!((e.id.as_str(), e.label.as_deref(), &e.state), (ID, Some("crew-1"), &kit::starting()));
            assert_eq!(e.vendor.unwrap().state, "starting");
            let asked = script.asked.lock().unwrap();
            assert_eq!(asked.len(), 1);
            let (method, target, body) = &asked[0];
            assert_eq!((method.as_str(), target.as_str()), ("POST", "/v1/sandboxes"));
            let labels = body["labels"].as_object().unwrap();
            assert_eq!((labels.len(), labels[LABEL_TAG].as_str()), (tags, Some("crew-1")));
            assert_eq!(labels.get(OWNER_TAG).is_some(), ownership == Ownership::SharedAccount);
            assert_eq!((&body["persistent"], &body["network"]), (&json!(true), &json!({"internet": true})));
        }
    }

    // List is one call, filtered by Runtime to the owner tag on a shared
    // account only. A pause or a stop has no cause: Runtime's stopReason is
    // reported beside its state. A row without labels has no tags or label.
    #[tokio::test]
    async fn list_reports_rows_as_runtime_gives_them() {
        let rows = r#"{"data":[
            {"id":"7f3a2c10-58d4-4b9e-9c61-0a2b3c4d5e6f","state":"paused","stopReason":"idle","labels":{"drydock.provider":"rt","flotilla.label":"l"}},
            {"id":"7f3a2c10-58d4-4b9e-9c61-0a2b3c4d5e70","state":"stopped","endedAt":"2026-11-01T00:00:00Z"}
        ],"nextCursor":null}"#;
        let (shared, script) = runtime(Ownership::SharedAccount, vec![(200, rows)]).await;
        let listed = shared.list(&key()).await.unwrap();
        assert_eq!(script.asked(), ["GET /v1/sandboxes?includeStopped=true&limit=100&label=drydock.provider%3Art"]);
        let seen: Vec<_> = listed.iter().map(|e| (e.label.as_deref(), e.state.clone(), e.timestamp.is_some())).collect();
        assert_eq!(seen, [(Some("l"), Observation::Stopped { cause: None }, false), (None, Observation::Stopped { cause: None }, true)]);
        let vendor = listed[0].vendor.as_ref().unwrap();
        assert_eq!(
            (vendor.state.as_str(), vendor.reason.as_deref(), vendor.tags.as_ref().unwrap()[OWNER_TAG].as_str()),
            ("paused", Some("idle"), "rt")
        );
        assert_eq!(listed[1].vendor.as_ref().unwrap().tags, None);
        let (owned, script) = runtime(Ownership::OwnedAccount, vec![(200, rows)]).await;
        owned.list(&key()).await.unwrap();
        assert_eq!(script.asked(), ["GET /v1/sandboxes?includeStopped=true&limit=100"]);
    }

    // Inspect reads the sandbox and its network: egress is enforced only when
    // Runtime says its host holds the current version of the rules. The
    // policy's digest keeps a field Runtime left out apart from an empty one.
    #[tokio::test]
    async fn inspect_reports_enforcement_from_runtimes_network_read() {
        let running = r#"{"id":"7f3a2c10-58d4-4b9e-9c61-0a2b3c4d5e6f","state":"running"}"#;
        let (runtime, script) = runtime(
            Ownership::OwnedAccount,
            vec![
                (200, running),
                (200, r#"{"internet":false,"allow":[],"version":2,"enforced":true,"enforcedVersion":2}"#),
                (200, running),
                (200, r#"{"internet":false,"version":2,"enforced":true,"enforcedVersion":1}"#),
                (200, running),
                (200, r#"{"internet":false,"version":2}"#),
            ],
        )
        .await;
        let mut seen = Vec::new();
        for _ in 0..3 {
            let e = runtime.inspect(ID, &key()).await.unwrap();
            seen.push((e.egress, e.egress_policy.unwrap()));
        }
        assert_eq!(
            seen.iter().map(|(egress, _)| egress.clone()).collect::<Vec<_>>(),
            [Enforcement::Enforced, Enforcement::Advisory, Enforcement::Advisory]
        );
        assert_ne!(seen[0].1, seen[1].1);
        assert_eq!(seen[1].1, seen[2].1);
        assert_eq!(script.asked()[..2], [format!("GET /v1/sandboxes/{ID}"), format!("GET /v1/sandboxes/{ID}/network")]);
    }

    // Destroy deletes the agent's preview, absent or not, then the sandbox;
    // Runtime's answer to that passes through, not found included.
    #[tokio::test]
    async fn destroy_deletes_the_preview_then_the_sandbox() {
        let gone = r#"{"error":{"code":"not_found","message":"no such sandbox"}}"#;
        let (runtime, script) = runtime(Ownership::SharedAccount, vec![(204, ""), (204, ""), (404, gone), (404, gone)]).await;
        runtime.destroy(ID, &key()).await.unwrap();
        assert!(matches!(runtime.destroy(ID, &key()).await, Err(ProtocolError::NotFound { .. })));
        let (preview, sandbox) = (format!("DELETE /v1/sandboxes/{ID}/previews/7811"), format!("DELETE /v1/sandboxes/{ID}"));
        assert_eq!(script.asked(), [preview.clone(), sandbox.clone(), preview, sandbox]);
    }

    // Suspend is one pause, its token the id. Resume reads the state once to
    // pick Runtime's operation: restart for a stopped sandbox, else wake.
    #[tokio::test]
    async fn suspend_pauses_and_resume_picks_wake_or_restart() {
        let paused = r#"{"id":"7f3a2c10-58d4-4b9e-9c61-0a2b3c4d5e6f","state":"paused"}"#;
        let stopped = r#"{"id":"7f3a2c10-58d4-4b9e-9c61-0a2b3c4d5e6f","state":"stopped"}"#;
        let (runtime, script) =
            runtime(Ownership::OwnedAccount, vec![(200, paused), (200, paused), (200, STARTING), (200, stopped), (200, STARTING)]).await;
        let port = runtime.operations().suspend_resume.unwrap();
        assert_eq!(port.suspend(ID, &key()).await.unwrap(), ResumeToken { token: Secret::new(ID) });
        for _ in 0..2 {
            port.resume(ID, ResumeToken { token: Secret::new("anything") }, &key()).await.unwrap();
        }
        let read = format!("GET /v1/sandboxes/{ID}");
        let act = |action: &str| format!("POST /v1/sandboxes/{ID}:{action}");
        assert_eq!(script.asked(), [act("pause"), read.clone(), act("wake"), read, act("restart")]);
    }

    // Reach makes no state read: the agent's token, then its preview.
    #[tokio::test]
    async fn reach_dials_the_agents_preview() {
        let token = r#"{"exitCode":0,"stdout":"drydock-tcp-token t\n","stderr":"","timedOut":false}"#;
        let preview = r#"{"url":"https://p.example/","visibility":"private","token":"pt","tokenExpiresAt":"2026-11-09T00:00:00Z"}"#;
        let (runtime, script) = runtime(Ownership::OwnedAccount, vec![(200, token), (200, preview)]).await;
        let Reach::Dial { url, headers, .. } = runtime.reach(ID, &key()).await.unwrap() else { panic!("not a dial") };
        assert_eq!(
            (url.as_str(), headers[PREVIEW_TOKEN_HEADER].expose()),
            (format!("https://p.example{}", drydock_transport::tcp::CONNECT_PATH).as_str(), "pt")
        );
        assert_eq!(
            script.asked(),
            [format!("POST /v1/sandboxes/{ID}:exec"), format!("GET /v1/sandboxes/{ID}/previews/7811?ttlSeconds=86400")]
        );
    }

    // An exec answer missing a field Runtime states is a bad response, not
    // empty output.
    #[tokio::test]
    async fn exec_answers_are_taken_as_stated() {
        let (runtime, _) = runtime(Ownership::OwnedAccount, vec![(200, r#"{"exitCode":0,"stdout":"","timedOut":false}"#)]).await;
        let request = ExecRequest { command: vec!["true".into()] };
        assert!(matches!(runtime.operations().exec.unwrap().exec(ID, request, &key()).await, Err(ProtocolError::Internal { .. })));
    }

    // A failed build without Runtime's error says only that it failed.
    #[tokio::test]
    async fn a_failed_build_names_no_error_runtime_did_not_give() {
        let images = r#"{"data":[],"nextCursor":null}"#;
        let (runtime, _) = runtime(
            Ownership::OwnedAccount,
            vec![(200, images), (201, r#"{"id":"img1","state":"queued"}"#), (200, r#"{"id":"img1","state":"failed"}"#)],
        )
        .await;
        let request = PrepareRequest {
            size: Size { cpus: 1.0, memory_bytes: GIB, disk_bytes: 4 * GIB },
            platform: Some(platform()),
            route: Some(ImageRouteKind::RegistryPull),
            image_pull: None,
            image_digest: "registry.example/base@sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
            tools_digest: "registry.example/tools@sha256:1111111111111111111111111111111111111111111111111111111111111111".into(),
        };
        let Err(ProtocolError::Refused { reason }) = runtime.prepare(request, &key()).await else { panic!("not refused") };
        assert_eq!(reason, "Runtime image build img1 failed");
    }

    // A request becomes Runtime's rules as asked; what Runtime cannot hold is refused.
    #[test]
    fn egress_translation() {
        let host = |h: &str| Destination::Host { host: serde_json::from_value(json!(h)).unwrap() };
        let deny = |direct| Policy::request(&EgressRequest::DenyAll { direct });
        assert_eq!(json!(deny(vec![]).unwrap()), json!({"internet": false}));
        let port = Destination::HostPort { host: "db.example".parse().unwrap(), port: serde_json::from_value(json!(5432)).unwrap() };
        let address = Destination::Cidr { cidr: "192.0.2.5/32".parse().unwrap() };
        assert_eq!(
            json!(deny(vec![host("example.com"), address, port]).unwrap()),
            json!({"internet": true, "allow": ["192.0.2.5", "example.com"], "connect": ["db.example:5432"]})
        );
        assert!(deny(vec![Destination::Cidr { cidr: "192.0.2.0/24".parse().unwrap() }]).is_err());
        assert!(deny(vec![host("::1")]).is_err());
    }

    // Settings take the old constants as defaults; a zero or an unknown key
    // is refused.
    #[tokio::test]
    async fn settings_refuse_zeroes_and_unknown_keys() {
        assert!(configure(Ownership::SharedAccount, json!({}), Arc::default()).await.is_ok());
        for refused in [
            json!({"poll_seconds": 0}),
            json!({"build_poll_seconds": 0}),
            json!({"build_polls": 0}),
            json!({"preview_ttl_seconds": 0}),
            json!({"exec_seconds": 0}),
            json!({"poll_every": 5}),
        ] {
            let result = configure(Ownership::SharedAccount, refused.clone(), Arc::default()).await;
            assert!(matches!(result, Err(ProtocolError::Refused { .. })), "{refused}");
        }
    }
}

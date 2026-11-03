//! Stateless Daytona REST translator. The host owns inventory, event diffs and retries.
//! API contract: https://www.daytona.io/docs/openapi.json (2026-10-20).
use crate::{
    kit::{
        self, GIB, LABEL_TAG, SizeLimits, StateTable, Vendor,
        api::{Amount, Api, Auth, Body, Failure, Next, Paging, Text, absent_on_not_found, https_base, join},
        egress::normal_cidr,
        guest::{Guest, GuestOutput, SUPERVISE},
        image::{check_prepare, check_prepared, content_name, tools_dockerfile},
    },
    module::*,
    oci::{self, ImageRef, Registry},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use drydock_protocol::*;
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned, de::IgnoredAny};
use serde_json::{json, value::RawValue};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

const DAYTONA: Vendor = Vendor("Daytona");
pub struct DaytonaModule;
const SSH_TOKEN_TTL_MINUTES: &str = "5";
/// Container sandboxes: whole vCPUs and GiB.
const SIZES: SizeLimits = SizeLimits { cpus: (1, 4), memory: (GIB, 8 * GIB), memory_step: GIB, disk: (GIB, 10 * GIB), disk_step: GIB };
const PAGED: Paging = Paging { rows: Some("items"), cursor: "cursor", next: Next::Body(&["nextCursor"]) };
/// Bounds destroy's wait for an in-progress state change to about 8s (4 sleeps), long
/// enough for a just-resumed sandbox to settle without stalling the caller.
const DESTROY_ATTEMPTS: u32 = 5;
const DESTROY_RETRY_DELAY: Duration = Duration::from_secs(2);

const STATES: StateTable = &[
    ("started", Observation::Running),
    ("creating", Observation::Transitioning { phase: TransitionPhase::Preparing }),
    ("pulling_snapshot", Observation::Transitioning { phase: TransitionPhase::Preparing }),
    ("pending_build", Observation::Transitioning { phase: TransitionPhase::Preparing }),
    ("building_snapshot", Observation::Transitioning { phase: TransitionPhase::Preparing }),
    ("starting", kit::starting()),
    ("restoring", kit::starting()),
    ("resuming", kit::starting()),
    ("stopping", kit::stopping()),
    ("archiving", kit::stopping()),
    ("pausing", kit::stopping()),
    ("resizing", Observation::Transitioning { phase: TransitionPhase::Reconfiguring }),
    ("snapshotting", Observation::Transitioning { phase: TransitionPhase::Reconfiguring }),
    ("forking", Observation::Transitioning { phase: TransitionPhase::Reconfiguring }),
    ("destroying", Observation::Transitioning { phase: TransitionPhase::Destroying }),
    ("stopped", kit::stopped(StopCause::SuspendedByRequest)),
    ("archived", kit::stopped(StopCause::SuspendedByRequest)),
    ("paused", kit::stopped(StopCause::PausedByProvider)),
];

// Daytona's wire types (see the API contract above), only the fields read.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Sandbox {
    id: Text,
    state: Text,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    cpu: Option<u64>,
    memory: Option<u64>,
    disk: Option<u64>,
    spot_evicted_at: Option<String>,
    error_reason: Option<String>,
    updated_at: Option<DateTime<Utc>>,
    created_at: Option<DateTime<Utc>>,
    toolbox_proxy_url: Option<Text>,
    #[serde(flatten)]
    policy: Policy,
}
/// A sandbox's network policy, as created and as read back: one of the
/// three, or none.
#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(rename_all = "camelCase")]
struct Policy {
    #[serde(skip_serializing_if = "Option::is_none")]
    network_block_all: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_allow_list: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_allow_list: Option<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSandbox<'a> {
    name: String,
    snapshot: &'a str,
    labels: BTreeMap<&'static str, &'a str>,
    target: &'a str,
    auto_stop_interval: u32,
    auto_pause_interval: u32,
    auto_delete_interval: i32,
    public: bool,
    #[serde(flatten)]
    policy: &'a Policy,
}
#[derive(Deserialize)]
struct Snapshot {
    id: Text,
    state: Text,
    cpu: Amount,
    /// RAM, unlike CreateSnapshot's `memory`.
    mem: Amount,
    disk: Amount,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSnapshot<'a> {
    name: &'a str,
    region_id: &'a str,
    sandbox_class: &'static str,
    cpu: u64,
    memory: u64,
    disk: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    image_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    build_info: Option<BuildInfo>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BuildInfo {
    dockerfile_content: String,
}
#[derive(Serialize)]
struct Execute<'a> {
    command: &'a str,
    timeout: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Executed {
    exit_code: i32,
    /// The command's merged output; empty is valid.
    result: String,
}
#[derive(Deserialize)]
struct SshAccess {
    token: Text,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushAccess {
    expires_at: DateTime<Utc>,
    registry_url: Text,
    username: Text,
    secret: Text,
    project: Text,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationUsage {
    region_usage: Vec<RegionUsage>,
    current_snapshot_usage: Amount,
    total_snapshot_quota: Amount,
    current_volume_usage: Amount,
    total_volume_quota: Amount,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegionUsage {
    region_id: Text,
    sandbox_class: Text,
    current_cpu_usage: Amount,
    total_cpu_quota: Amount,
    current_memory_usage: Amount,
    total_memory_quota: Amount,
    current_disk_usage: Amount,
    total_disk_quota: Amount,
}
#[derive(Deserialize)]
struct AggregatedUsage {
    #[serde(rename = "totalCPUSeconds")]
    cpu: Amount,
    #[serde(rename = "totalRAMGBSeconds")]
    memory: Amount,
    #[serde(rename = "totalDiskGBSeconds")]
    disk: Amount,
    #[serde(rename = "totalGPUSeconds")]
    gpu: Amount,
    #[serde(rename = "sandboxCount")]
    sandboxes: Amount,
    /// The vendor's decimal lexeme: money never passes through f64.
    #[serde(rename = "totalPrice")]
    price: Box<RawValue>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SandboxUsage {
    sandbox_id: Text,
}
#[derive(Deserialize)]
struct UsagePeriod {
    cpu: Amount,
    #[serde(rename = "startAt")]
    start: Option<DateTime<Utc>>,
    #[serde(rename = "endAt")]
    end: Option<DateTime<Utc>>,
    #[serde(rename = "ramGB")]
    memory: Option<u64>,
    #[serde(rename = "diskGB")]
    disk: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    organization_id: String,
    /// Pinned out of band: the REST API supplies no gateway host public key.
    ssh_host_key: String,
    #[serde(default = "api_url")]
    api_url: String,
    #[serde(default)]
    toolbox_url: Option<String>,
    /// Explicit organization limits, including Enterprise custom contracts.
    #[serde(default)]
    rate_limits: Option<Vec<RateLimit>>,
    #[serde(default = "ssh_endpoint")]
    ssh_endpoint: String,
    #[serde(default = "region")]
    region: String,
    #[serde(default = "tier")]
    tier: u8,
    #[serde(default = "analytics_url")]
    analytics_url: String,
    /// Largest image a snapshot may hold, in GiB: Daytona's default snapshot
    /// maximum is 20. Organizations with a raised limit configure it.
    #[serde(default = "max_image_gib")]
    max_image_gib: u64,
    /// Bytes per blob request on the push route. Each request must finish
    /// inside the host's HTTP deadline, so slow links want smaller chunks.
    #[serde(default = "push_chunk_bytes")]
    push_chunk_bytes: u64,
}
fn max_image_gib() -> u64 {
    20
}
fn push_chunk_bytes() -> u64 {
    16 << 20
}
fn analytics_url() -> String {
    "https://analytics.app.daytona.io/".into()
}
fn api_url() -> String {
    "https://app.daytona.io/api/".into()
}
fn ssh_endpoint() -> String {
    "ssh.app.daytona.io:22".into()
}
fn region() -> String {
    "eu".into()
}
fn tier() -> u8 {
    1
}

#[async_trait]
impl Module for DaytonaModule {
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    async fn configure(&self, name: &str, config: &ProviderConfiguration, http: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
        let settings: Settings = serde_json::from_value(json!(config.settings)).map_err(|_| refused("invalid Daytona settings"))?;
        if !(1..=4).contains(&settings.tier)
            || settings.organization_id.is_empty()
            || settings.ssh_host_key.is_empty()
            || settings.region.is_empty()
            || settings.max_image_gib == 0
            || settings.push_chunk_bytes == 0
        {
            return Err(refused("Daytona requires organization_id, ssh_host_key, region, tier 1..4 and positive image limits"));
        }
        for endpoint in [&settings.api_url, &settings.analytics_url].into_iter().chain(settings.toolbox_url.iter()) {
            if !https_base(DAYTONA, endpoint)?.path().ends_with('/') {
                return Err(refused("Daytona's configured bases must end in /"));
            }
        }
        let api = Api::new(DAYTONA, &settings.api_url, Auth::Bearer, http.clone())?.classify(classify).retry_after(retry_delay);
        let analytics = Api::new(DAYTONA, &settings.analytics_url, Auth::Bearer, http)?.classify(classify).retry_after(retry_delay);
        Ok(Arc::new(Daytona { name: name.to_owned(), settings, api, analytics }))
    }
}
pub struct Daytona {
    name: String,
    settings: Settings,
    api: Api,
    analytics: Api,
}
/// Daytona's statuses, its whole body kept as the explanation (the host
/// masks credential echoes before limiting it). A 4xx the table does not
/// name (400, 409, 422) is a request drydock should never have made:
/// Internal, never a refusal the caller might act on.
fn classify(f: &Failure) -> ProtocolError {
    let raw = String::from_utf8_lossy(f.body).into_owned();
    match f.status {
        408 => ProtocolError::unavailable(f.reason(&raw), None),
        401..=404 | 429 | 500..=599 => f.standard(f.reason(&raw)),
        status => ProtocolError::Internal { reason: format!("unexpected Daytona {} HTTP {status}", f.operation), provider_error: raw },
    }
}
impl Daytona {
    fn sandbox_url(&self, id: &str, action: Option<&str>) -> Result<Url> {
        self.api.url(&[&["sandbox", id][..], action.as_slice()].concat())
    }
    async fn sandbox(&self, id: &str, c: &Credentials) -> Result<Sandbox> {
        self.api.get(self.sandbox_url(id, None)?, c).await
    }
    /// A POST whose answer drydock does not read (it must still be JSON).
    async fn post(&self, url: Url, c: &Credentials) -> Result<()> {
        self.api.call::<IgnoredAny>(Method::POST, url, Body::None, c).await.map(drop)
    }
    /// None represents a provider uniqueness conflict (409), for
    /// look-up-or-create and destroy's wait only.
    async fn unless_conflict<T: DeserializeOwned>(&self, method: Method, url: Url, body: Body, c: &Credentials) -> Result<Option<T>> {
        let operation = kit::api::operation(&method, &url);
        let response = self.api.send(method, url, body, c, true, &[]).await?;
        if response.status() == 409 {
            return Ok(None);
        }
        self.api.answer(&operation, &response).map(Some)
    }
    /// Daytona's `GET /sandbox/{idOrName}` accepts the name derived from a label.
    async fn by_label_name(&self, label: &str, c: &Credentials) -> Result<Option<Sandbox>> {
        // Anything but a 404 fails provision; the caller retries it.
        let Some(v) = self.api.find::<Sandbox>(self.sandbox_url(&name("environment", label), None)?, c).await? else { return Ok(None) };
        if v.labels.get(LABEL_TAG).map(String::as_str) != Some(label) {
            return Err(refused("Daytona sandbox name belongs to a different label"));
        }
        Ok(Some(v))
    }
    fn environment(&self, v: &Sandbox) -> Result<Environment> {
        let state = match &*v.state {
            "destroyed" if v.spot_evicted_at.is_some() => Observation::Gone { cause: GoneCause::EvictedByProvider },
            "destroyed" => Observation::Gone { cause: GoneCause::DestroyedAtProvider },
            "error" | "build_failed" => error_state(v.error_reason.as_deref().unwrap_or("")),
            state => kit::observe(STATES, state),
        };
        let p = &v.policy;
        let policy = json!({"block":p.network_block_all,"cidrs":p.network_allow_list,"domains":p.domain_allow_list});
        Ok(Environment {
            id: v.id.to_string(),
            provider: self.name.clone(),
            label: v.labels.get(LABEL_TAG).cloned(),
            state,
            granted_size: kit::granted(DAYTONA, v.cpu, v.memory, GIB, v.disk, GIB)?,
            egress: Enforcement::Advisory,
            // Every Daytona sandbox runs on x86_64 (see `platform`).
            platform: Some(platform()),
            egress_measured: false,
            egress_policy: Some(kit::digest(&policy.to_string())),
            timestamp: v.updated_at.or(v.created_at).map(Into::into),
        })
    }
    fn check_existing_request(&self, v: &Sandbox, size: &Size, policy: &Policy) -> Result<()> {
        let row = self.environment(v)?;
        if row.granted_size.as_ref() != Some(size) || !policy_matches(&v.policy, policy) {
            return Err(refused("existing Daytona label has a different or unknown size/egress policy; provision a new label"));
        }
        Ok(())
    }
    async fn execute(&self, id: &str, command: &str, timeout: u64, c: &Credentials) -> Result<GuestOutput> {
        let base = match &self.settings.toolbox_url {
            Some(base) => base.clone(),
            None => {
                // Fetch the canonical route per call so resume/migration cannot
                // leave a cached runner URL stale. This extra GET is intentional;
                // individual-call admission accounting is tracked in drydock#35.
                // The control plane is trusted to delegate bearer authentication
                // to this proxy host. Pin toolbox_url when that delegation is not
                // acceptable; HTTPS validation alone is not a host allowlist.
                self.sandbox(id, c).await?.toolbox_proxy_url.ok_or_else(|| DAYTONA.bad_response())?.into()
            }
        };
        let base = https_base(DAYTONA, &base).map_err(|_| DAYTONA.bad_response())?;
        let url = join(&base, &[id, "process", "execute"]).map_err(|_| DAYTONA.bad_response())?;
        let v: Executed = self.api.call(Method::POST, url, Body::json(&Execute { command, timeout })?, c).await?;
        Ok(GuestOutput::from_text(&v.result, "", Some(v.exit_code.into())))
    }
    /// The baked executable owns detachment, singleton locking and crash
    /// recovery. Guest packages and a socket inode are not readiness proof;
    /// the daemon waits for the agent client's normal hello handshake.
    async fn bootstrap(&self, id: &str, c: &Credentials) -> Result<()> {
        self.execute(id, SUPERVISE, 25, c).await?.success(DAYTONA).map(drop)
    }
    // Lifecycle state checks deliberately avoid explicit inspect's root probe.
    async fn lifecycle_state(&self, id: &str, c: &Credentials) -> Result<Observation> {
        Ok(self.environment(&self.sandbox(id, c).await?)?.state)
    }
    /// Observes only successful asynchronous operations: a failed GET ends
    /// the wait. A successful async start may briefly still report stopped,
    /// so stopped alone is not terminal here; conflict re-adoption handles
    /// stopped rows.
    async fn wait_started(&self, id: &str, c: &Credentials) -> Result<Environment> {
        kit::poll(60, Duration::from_secs(2), async || {
            let v = self.sandbox(id, c).await?;
            match &*v.state {
                "started" => self.environment(&v).map(Some),
                "error" | "build_failed" | "destroyed" | "destroying" => {
                    Err(refused("Daytona sandbox entered a terminal state before startup"))
                }
                _ => Ok(None),
            }
        })
        .await?
        .ok_or_else(|| ProtocolError::unavailable("Daytona sandbox has not started", Some(5)))
    }
    /// Push route: append the tools layer to the base image's manifest here,
    /// upload the result into Daytona's registry with minted push access, and
    /// wait until a pull by digest succeeds. Returns the digest reference.
    async fn push(&self, r: &PrepareRequest, platform: &Platform, tag: &str, c: &Credentials) -> Result<String> {
        let http = self.api.http();
        let base = ImageRef::parse(&r.image_digest)?;
        let tools = ImageRef::parse(&r.tools_digest)?;
        // The pull credential belongs to the base's registry and goes nowhere else.
        let base_registry = Registry::new(http.clone(), &base.registry, r.image_pull.clone(), None)?;
        let tools_credential = if tools.registry == base.registry { r.image_pull.clone() } else { None };
        let tools_registry = Registry::new(http.clone(), &tools.registry, tools_credential, None)?;
        let base_manifest = base_registry.platform_manifest(&base, platform).await?;
        let base_config = base_registry.config(&base.repository, &base_manifest).await?;
        let tools_manifest = tools_registry.platform_manifest(&tools, platform).await?;
        let tools_config = tools_registry.config(&tools.repository, &tools_manifest).await?;
        let composed = oci::compose(&base_manifest, &base_config, &tools_manifest, &tools_config, platform)?;
        fits_snapshot(composed.bytes(), self.settings.max_image_gib)?;
        // Daytona resolves `regionId` here only among the organisation's own regions and
        // answers 404 "Region not found" for the shared ones (eu, us), so none is sent.
        let access: PushAccess = self.api.get(self.api.url(&["docker-registry", "registry-push-access"])?, c).await?;
        let bad = || DAYTONA.bad_response();
        let host = access.registry_url.strip_prefix("https://").unwrap_or(&access.registry_url).trim_end_matches('/');
        if !oci::registry_host_valid(host) {
            return Err(bad());
        }
        let credential = RegistryCredential { username: access.username.into(), secret: Secret::new(String::from(access.secret)) };
        let target = Registry::new(http.clone(), host, Some(credential), Some(access.expires_at)).map_err(|_| bad())?;
        let repository = format!("{}/drydock-vessel", access.project);
        for (source, layer) in &composed.layers {
            let (registry, from) = match source {
                oci::Source::Base => (&base_registry, &base.repository),
                oci::Source::Tools => (&tools_registry, &tools.repository),
            };
            oci::copy_blob(registry, from, &target, &repository, layer, self.settings.push_chunk_bytes).await?;
        }
        target.put_blob(&repository, &composed.config_digest, composed.config.clone().into()).await?;
        // Tagged so the registry retains it; Daytona itself is given the digest.
        target.put_manifest(&repository, tag, &composed.media_type, composed.manifest.clone().into()).await?;
        // Daytona's registry serves a new manifest only after a delay, and its
        // builder pulls once at snapshot creation (cf. `daytona snapshot push`).
        kit::poll(60, Duration::from_secs(1), async || {
            Ok(target.manifest_visible(&repository, &composed.digest).await?.then(|| format!("{host}/{repository}@{}", composed.digest)))
        })
        .await?
        .ok_or_else(|| ProtocolError::unavailable("pushed image is not yet visible in Daytona's registry", Some(5)))
    }
    fn analytics_url(&self, segments: &[&str], from: &str, to: &str) -> Result<Url> {
        let mut url = self.analytics.url(&[&["organization", self.settings.organization_id.as_str()], segments].concat())?;
        url.query_pairs_mut().append_pair("from", from).append_pair("to", to);
        Ok(url)
    }
    async fn analytics<T: DeserializeOwned>(&self, segments: &[&str], from: &str, to: &str, c: &Credentials) -> Result<T> {
        self.analytics.get(self.analytics_url(segments, from, to)?, c).await
    }
}

#[async_trait]
impl Guest for Daytona {
    fn vendor(&self) -> Vendor {
        DAYTONA
    }
    /// Runs through the toolbox's process API, whose answer merges the
    /// command's output. Daytona's toolbox carries no environment, so `env`
    /// must be empty: Daytona starts its agent without a TCP token.
    async fn run(&self, id: &str, script: &str, env: BTreeMap<&str, String>, c: &Credentials) -> Result<GuestOutput> {
        if !env.is_empty() {
            return Err(refused("Daytona's toolbox passes no environment to a command"));
        }
        self.execute(id, script, 20, c).await
    }
}

/// An error state's cause, from Daytona's free-text reason.
fn error_state(reason: &str) -> Observation {
    match reason.to_ascii_lowercase().as_str() {
        reason if reason.contains("out of memory") || reason.split(|c: char| !c.is_ascii_alphanumeric()).any(|word| word == "oom") => {
            Observation::Gone { cause: GoneCause::HostOutOfMemory }
        }
        reason if reason.contains("evict") => Observation::Gone { cause: GoneCause::EvictedByProvider },
        reason if reason.contains("unreachable") => Observation::Unknown { reason: UnknownReason::HostUnreachable },
        _ => Observation::Unknown { reason: UnknownReason::ProviderApiError },
    }
}
/// An image fills a snapshot exactly at the limit; one byte more is refused.
fn fits_snapshot(bytes: u64, max_gib: u64) -> Result<()> {
    let limit_bytes = max_gib.saturating_mul(GIB);
    if bytes <= limit_bytes {
        return Ok(());
    }
    Err(ProtocolError::ImageRefused {
        reason: format!("image needs at least {bytes} bytes; Daytona snapshots hold {limit_bytes}"),
        refusal: ImageRefusal::TooLarge { bytes, limit_bytes },
    })
}
fn name(prefix: &str, input: &str) -> String {
    // Keep vendor names below 63 bytes, with 160 bits of digest identity.
    content_name(&format!("drydock-{prefix}-"), 40, &[input])
}
fn policy_matches(row: &Policy, policy: &Policy) -> bool {
    // Compare stable requested destinations, never a DNS resolution at retry.
    fn set(list: &Option<String>, normal: fn(&str) -> String) -> BTreeSet<String> {
        list.as_deref().unwrap_or("").split(',').filter(|s| !s.is_empty()).map(|s| normal(s.trim())).collect()
    }
    let cidr = |s: &str| normal_cidr(s).unwrap_or_else(|| s.into());
    row.network_block_all.unwrap_or(false) == policy.network_block_all.unwrap_or(false)
        && set(&row.network_allow_list, cidr) == set(&policy.network_allow_list, cidr)
        && set(&row.domain_allow_list, kit::egress::normal_host) == set(&policy.domain_allow_list, kit::egress::normal_host)
}
fn allowlist(request: EgressRequest) -> Result<Policy> {
    match request {
        EgressRequest::Open => Ok(Policy { network_allow_list: Some("0.0.0.0/0".into()), ..Policy::default() }),
        EgressRequest::DenyAll { direct } => {
            let mut cidrs = BTreeSet::new();
            let mut hosts = BTreeSet::new();
            for entry in direct {
                match entry {
                    Destination::HostPort { .. } => return Err(refused("Daytona allowlists cannot restrict ports")),
                    Destination::Cidr { cidr } => {
                        if cidr.as_str().contains(':') {
                            return Err(refused("Daytona does not support IPv6 CIDRs"));
                        }
                        cidrs.insert(cidr.as_str().to_owned());
                    }
                    // Daytona resolves native domain rules as addresses change.
                    Destination::Host { host } => {
                        if host.as_str().contains(':') {
                            return Err(refused("Daytona does not support IPv6 destinations"));
                        }
                        if host.as_str().parse::<std::net::Ipv4Addr>().is_ok() {
                            cidrs.insert(format!("{}/32", host.as_str()));
                        } else {
                            hosts.insert(kit::egress::normal_host(host.as_str()));
                        }
                    }
                }
            }
            if !cidrs.is_empty() && !hosts.is_empty() {
                return Err(refused("Daytona cannot combine domain names with CIDRs or IPv4 literals"));
            }
            let join = |set: BTreeSet<String>| Some(set.into_iter().collect::<Vec<_>>().join(","));
            Ok(if !hosts.is_empty() {
                Policy { domain_allow_list: join(hosts), ..Policy::default() }
            } else if !cidrs.is_empty() {
                Policy { network_allow_list: join(cidrs), ..Policy::default() }
            } else {
                Policy { network_block_all: Some(true), ..Policy::default() }
            })
        }
    }
}

#[async_trait]
impl Provider for Daytona {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            material_modes: vec![MaterialMode::Frozen],
            checkout_strategies: vec![CheckoutStrategy::CloneInVessel],
            workspace_root: "/workspace".into(),
            suspend_resume: true,
            suspend_preserves_memory: Some(false),
            export: false,
            egress: EgressCapability {
                routes: vec![EgressRoute::None, EgressRoute::ExplicitProxy, EgressRoute::Open],
                enforcement: Enforcement::Advisory,
            },
            fallback_runner: true,
            bootstrap: BootstrapRoute::Bake,
            agent: true,
            platforms: vec![platform()],
            image_routes: vec![
                // Default: our own images live in registries Daytona cannot reach.
                ImageRoute::ProviderPush {
                    protocol: PushProtocol::OciDistribution,
                    credential_lifetime_seconds: Some(3600),
                    tools_layer: ToolsLayer::Host,
                },
                // Daytona's builder pulls the base and tools itself, from a
                // registry the organization registered via POST /docker-registry.
                ImageRoute::RegistryPull {
                    auth: RegistryAuthKind::Basic,
                    registration: CredentialRegistration::ProviderApi,
                    digest_references: true,
                    tools_layer: ToolsLayer::Provider,
                },
            ],
            usage: true,
            quota: true,
            host_filesystem: false,
        }
    }
    fn observation(&self) -> ObservationMode {
        ObservationMode::Poll { interval_ms: 30_000 }
    }
    fn operations(&self) -> Operations<'_> {
        Operations { exec: Some(self), suspend_resume: Some(self), quota: Some(self), usage: Some(self), ..Operations::default() }
    }
    fn rate_limits(&self) -> Vec<RateLimit> {
        if let Some(limits) = &self.settings.rate_limits {
            return limits.clone();
        }
        let (general, create) = match self.settings.tier {
            2 => (20_000, 400),
            3 => (40_000, 500),
            4 => (50_000, 600),
            _ => (10_000, 300),
        };
        vec![
            RateLimit { operation: "*".into(), requests: general, period_seconds: 60 },
            RateLimit { operation: "provision".into(), requests: create, period_seconds: 60 },
            RateLimit { operation: "suspend".into(), requests: general, period_seconds: 60 },
            RateLimit { operation: "resume".into(), requests: general, period_seconds: 60 },
        ]
    }
    async fn prepare(&self, r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
        // The references become Dockerfile instructions: pinned, no extra tokens.
        let routes = [ImageRouteKind::ProviderPush, ImageRouteKind::RegistryPull];
        let (route, platform) = check_prepare(DAYTONA, &r, &routes, &platform())?;
        SIZES.check(DAYTONA, &r.size)?;
        // CreateSnapshot labels memory/disk "GB", but the resource guide and
        // default snapshot table specify GiB for the resulting sandbox:
        // https://www.daytona.io/docs/en/sandboxes/#resources (checked 2026-10-21).
        // Keep binary units consistent with sandbox readback; decimal conversion
        // would also produce fractions rejected by CreateSnapshot's integer fields.
        // Both routes produce the same filesystem, so the route is not part of
        // the key; nor is the tools image, whose agent is only a cache that
        // the host upgrades to its own build at the first hello.
        let snapshot_name = snapshot_name(&r.image_digest, &platform, &r.size);
        let snapshot = match self.api.find::<Snapshot>(self.api.url(&["snapshots", &snapshot_name])?, c).await? {
            Some(v) => v,
            None => {
                let mut body = CreateSnapshot {
                    name: &snapshot_name,
                    region_id: &self.settings.region,
                    sandbox_class: "container",
                    cpu: r.size.cpus as u64,
                    memory: r.size.memory_bytes / GIB,
                    disk: r.size.disk_bytes / GIB,
                    image_name: None,
                    build_info: None,
                };
                match route {
                    ImageRouteKind::ProviderPush => body.image_name = Some(self.push(&r, &platform, &snapshot_name, c).await?),
                    ImageRouteKind::RegistryPull => {
                        // Daytona's snapshot API takes no platform; pin both multi-arch
                        // references in the build so the snapshot matches the prepared form.
                        let dockerfile_content = tools_dockerfile(&r.image_digest, &r.tools_digest, &platform);
                        body.build_info = Some(BuildInfo { dockerfile_content });
                    }
                    ImageRouteKind::RemoteBuild => unreachable!("check_prepare admits declared routes only"),
                }
                match self.unless_conflict(Method::POST, self.api.url(&["snapshots"])?, Body::json(&body)?, c).await? {
                    Some(snapshot) => snapshot,
                    None => self.api.get(self.api.url(&["snapshots", &snapshot_name])?, c).await?,
                }
            }
        };
        let id = snapshot.id.clone();
        let mut snapshot = snapshot;
        let mut activation_submitted = false;
        for _ in 0..120 {
            match &*snapshot.state {
                "active" => {
                    if snapshot.cpu.get() != r.size.cpus
                        || snapshot.mem.get() != (r.size.memory_bytes / GIB) as f64
                        || snapshot.disk.get() != (r.size.disk_bytes / GIB) as f64
                    {
                        return Err(refused("Daytona snapshot resources do not match the requested size"));
                    }
                    return Ok(Prepared {
                        provider: self.name.clone(),
                        id: snapshot_name,
                        platform,
                        image_digest: r.image_digest,
                        tools_digest: r.tools_digest,
                    });
                }
                "inactive" if !activation_submitted => {
                    // A successful activation response can lag at inactive.
                    // Submit once; all subsequent observations use paced GETs.
                    self.post(self.api.url(&["snapshots", &id, "activate"])?, c).await?;
                    activation_submitted = true;
                }
                "error" | "build_failed" => return Err(refused("Daytona snapshot build failed")),
                _ => {}
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            snapshot = self.api.get(self.api.url(&["snapshots", &id])?, c).await?;
        }
        Err(ProtocolError::unavailable("Daytona snapshot is still building", Some(5)))
    }
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        let policy = allowlist(r.egress)?;
        let size = &r.size;
        SIZES.check(DAYTONA, size)?;
        check_prepared(DAYTONA, &self.name, &r.prepared, &snapshot_name(&r.prepared.image_digest, &r.prepared.platform, size))?;
        // The sandbox name derives from the label, so re-adoption is a direct read:
        // the list lags creation by seconds, so a quick retry must not rely on it.
        if let Some(v) = self.by_label_name(&r.label, c).await? {
            self.check_existing_request(&v, size, &policy)?;
            // Re-adoption returns the observed stopped/error state unchanged;
            // provision does not implicitly resume an existing label. A sandbox still
            // starting is likewise returned as observed (unlike the create-conflict
            // path below, which waits): the caller polls it.
            let mut row = self.environment(&v)?;
            if matches!(row.state, Observation::Running) {
                // Every Running re-adoption bootstraps; the guest supervisor's
                // lock makes this idempotent even across concurrent hosts.
                self.bootstrap(&row.id, c).await?;
                row = self.inspect(&row.id, c).await?;
            }
            return Ok(Provisioned::Existing(row));
        }
        let body = CreateSandbox {
            name: name("environment", &r.label),
            snapshot: &r.prepared.id,
            labels: BTreeMap::from([(LABEL_TAG, r.label.as_str())]),
            target: &self.settings.region,
            auto_stop_interval: 0,
            auto_pause_interval: 0,
            auto_delete_interval: -1,
            public: false,
            policy: &policy,
        };
        let created: Option<Sandbox> = self.unless_conflict(Method::POST, self.api.url(&["sandbox"])?, Body::json(&body)?, c).await?;
        let v = match created {
            None => {
                let v = self
                    .by_label_name(&r.label, c)
                    .await?
                    .ok_or_else(|| ProtocolError::NotFound { reason: "Daytona sandbox vanished after a name conflict".into() })?;
                self.check_existing_request(&v, size, &policy)?;
                let existing = self.environment(&v)?;
                if matches!(existing.state, Observation::Stopped { .. } | Observation::Unknown { .. } | Observation::Gone { .. }) {
                    return Ok(Provisioned::Existing(existing));
                }

                let row = self.wait_started(&v.id, c).await?;
                self.bootstrap(&row.id, c).await?;
                return Ok(Provisioned::Existing(self.inspect(&row.id, c).await?));
            }
            Some(v) => v,
        };
        let row = self.wait_started(&v.id, c).await?;
        self.bootstrap(&row.id, c).await?;
        Ok(Provisioned::Created(self.inspect(&row.id, c).await?))
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        // Daytona keeps a deleted sandbox listed as destroying/destroyed for a while;
        // once destroy has returned it must not read as present. Intended contract: a
        // sandbox mid-destroy is absent from `list`, while `inspect` still reports
        // `Destroying`.
        let mut rows = Vec::new();
        let mut url = self.api.url(&["sandbox"])?;
        url.query_pairs_mut().append_pair("limit", "200");
        for v in self.api.paged::<Sandbox>(url, &PAGED, c).await? {
            let row = self.environment(&v)?;
            if !matches!(
                row.state,
                Observation::Transitioning { phase: TransitionPhase::Destroying }
                    | Observation::Gone { cause: GoneCause::DestroyedAtProvider }
            ) {
                rows.push(row);
            }
        }
        Ok(rows)
    }
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        self.environment(&self.sandbox(id, c).await?)
    }
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        // Daytona answers 409 while a state change is in progress; wait it out briefly,
        // then surface the retryable `unavailable` error.
        for attempt in 1..=DESTROY_ATTEMPTS {
            let url = self.sandbox_url(id, None)?;
            match absent_on_not_found(self.unless_conflict::<IgnoredAny>(Method::DELETE, url, Body::None, c).await) {
                Ok(None | Some(Some(_))) => return Ok(()),
                Ok(Some(None)) if attempt < DESTROY_ATTEMPTS => tokio::time::sleep(DESTROY_RETRY_DELAY).await,
                Ok(Some(None)) => break,
                Err(e) => return Err(e),
            }
        }
        Err(ProtocolError::unavailable("Daytona sandbox state change still in progress; retry destroy", None))
    }
    async fn reach(&self, id: &str, c: &Credentials) -> Result<Reach> {
        let mut url = self.sandbox_url(id, Some("ssh-access"))?;
        url.query_pairs_mut().append_pair("expiresInMinutes", SSH_TOKEN_TTL_MINUTES);
        let access: SshAccess = self.api.call(Method::POST, url, Body::None, c).await?;
        Ok(Reach::Ssh {
            endpoint: self.settings.ssh_endpoint.clone(),
            user: Secret::new(String::from(access.token)),
            host_key: self.settings.ssh_host_key.clone(),
            // The gateway refuses remote port forwarding.
            reverse_forwards: false,
        })
    }
    async fn relay(&self, _: &str, _: &Credentials) -> Result<ByteStream> {
        Err(refused("Daytona uses the SSH gateway"))
    }
}
#[async_trait]
impl SuspendResume for Daytona {
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        if !matches!(
            self.lifecycle_state(id, c).await?,
            Observation::Stopped { .. } | Observation::Transitioning { phase: TransitionPhase::Stopping }
        ) {
            self.post(self.sandbox_url(id, Some("stop"))?, c).await?;
        }
        kit::poll(60, Duration::from_secs(2), async || {
            Ok(matches!(self.lifecycle_state(id, c).await?, Observation::Stopped { .. })
                .then(|| DAYTONA.resume_marker("drydock-resume-", &self.name, id)))
        })
        .await?
        .ok_or_else(|| ProtocolError::unavailable("Daytona sandbox has not stopped", Some(5)))
    }
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()> {
        DAYTONA.check_resume("drydock-resume-", &self.name, id, &token)?;
        let state = self.lifecycle_state(id, c).await?;
        if matches!(state, Observation::Running) {
            return self.bootstrap(id, c).await;
        }
        if !matches!(state, Observation::Transitioning { phase: TransitionPhase::Starting }) {
            self.post(self.sandbox_url(id, Some("start"))?, c).await?;
        }
        self.wait_started(id, c).await?;
        self.bootstrap(id, c).await?;
        Ok(())
    }
}
#[async_trait]
impl Exec for Daytona {
    async fn exec(&self, id: &str, r: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        Guest::exec(self, id, r, c).await
    }
}
#[async_trait]
impl QuotaOperation for Daytona {
    async fn quota(&self, c: &Credentials) -> Result<Quota> {
        let v: OrganizationUsage = self.api.get(self.api.url(&["organizations", &self.settings.organization_id, "usage"])?, c).await?;
        let mut resources = Vec::new();
        for region in &v.region_usage {
            for (resource, unit, factor, in_use, limit) in [
                (ResourceKind::Cpu, "{vCPU}", 1.0, region.current_cpu_usage, region.total_cpu_quota),
                (ResourceKind::Memory, "By", GIB as f64, region.current_memory_usage, region.total_memory_quota),
                (ResourceKind::Disk, "By", GIB as f64, region.current_disk_usage, region.total_disk_quota),
            ] {
                resources.push(ResourceQuota {
                    key: QuotaKey { region: Some(region.region_id.to_string()), class: Some(region.sandbox_class.to_string()), resource },
                    unit: unit.into(),
                    in_use: in_use.get() * factor,
                    limit: Some(limit.get() * factor),
                });
            }
        }
        for (resource, in_use, limit) in [
            (ResourceKind::SnapshotStorage, v.current_snapshot_usage, v.total_snapshot_quota),
            (ResourceKind::VolumeStorage, v.current_volume_usage, v.total_volume_quota),
        ] {
            resources.push(ResourceQuota {
                key: QuotaKey { region: None, class: None, resource },
                unit: "By".into(),
                in_use: in_use.get() * GIB as f64,
                limit: Some(limit.get() * GIB as f64),
            });
        }
        Ok(Quota { resources, credits_remaining: None, credit_unit: None, concurrency_in_use: None, concurrency_limit: None })
    }
}
#[async_trait]
impl UsageOperation for Daytona {
    async fn usage(&self, period: Period, c: &Credentials) -> Result<Usage> {
        let bad = || DAYTONA.bad_response();
        let from_text = String::from(period.start().clone());
        let to_text = String::from(period.end().clone());
        let from = from_text.parse::<chrono::DateTime<chrono::Utc>>().map_err(|_| refused("invalid usage period start"))?;
        let to = to_text.parse::<chrono::DateTime<chrono::Utc>>().map_err(|_| refused("invalid usage period end"))?;
        // Sample once before the reads; ongoing usage conservatively excludes time spent querying analytics.
        let ongoing_end = to.min(chrono::Utc::now());
        let v: AggregatedUsage = self.analytics(&["usage", "aggregated"], &from_text, &to_text, c).await?;
        // Daytona's reserved memory/disk quantities are GiB:
        // https://www.daytona.io/docs/en/sandboxes/#resources
        // Interpret analytics' GBSeconds as the integral of those same reserved
        // quantities. This naming assumption is part of live metering acceptance.
        let resources = [
            (ResourceKind::Cpu, "{vCPU}.s", v.cpu, 1.0),
            (ResourceKind::Memory, "By.s", v.memory, GIB as f64),
            (ResourceKind::Disk, "By.s", v.disk, GIB as f64),
            (ResourceKind::Gpu, "{GPU}.s", v.gpu, 1.0),
            (ResourceKind::Environments, "1", v.sandboxes, 1.0),
        ]
        .into_iter()
        .map(|(resource, unit, amount, factor)| (resource, Quantity { amount: amount.get() * factor, unit: unit.into() }))
        .collect();
        let price = price(&v.price)?;
        // Analytics prices are denominated in USD; there is no currency field.
        let mut environment_hours = Vec::new();
        let totals: Vec<SandboxUsage> = self.analytics(&["usage", "sandbox"], &from_text, &to_text, c).await?;
        let mut seen = BTreeSet::new();
        for sandbox in &totals {
            if !seen.insert(&sandbox.sandbox_id) {
                continue;
            }
            let periods: Vec<UsagePeriod> = self.analytics(&["sandbox", &sandbox.sandbox_id, "usage"], &from_text, &to_text, c).await?;
            for row in periods {
                let cpus = row.cpu.get();
                // Zero-CPU records contribute no size-hours, even with
                // their other fields absent.
                if cpus == 0.0 {
                    continue;
                }
                let start = row.start.ok_or_else(bad)?;
                let end = match row.end {
                    None => ongoing_end,
                    Some(end) if end < start => return Err(bad()),
                    Some(end) => end,
                };
                let start = start.max(from);
                let end = end.min(to);
                if end <= start {
                    continue;
                }
                let seconds = (end - start).num_milliseconds() as f64 / 1000.0;
                let bytes = |n: Option<u64>| n.and_then(|v| v.checked_mul(GIB)).ok_or_else(bad);
                environment_hours.push(SizeUsage {
                    size: Size { cpus, memory_bytes: bytes(row.memory)?, disk_bytes: bytes(row.disk)? },
                    hours: seconds / 3600.0,
                });
            }
        }
        Ok(Usage {
            period,
            environment_hours,
            measurements: Some(UsageMeasurements {
                scope: UsageScope::Organization { id: self.settings.organization_id.clone() },
                resources,
                cost: Some(Cost { amount: price, currency: "USD".into() }),
            }),
        })
    }
}

/// The analytics price as a decimal lexeme, never through f64.
fn price(raw: &RawValue) -> Result<String> {
    decimal_lexeme(raw.get())
        .ok_or_else(|| ProtocolError::Internal { reason: "invalid Daytona price".into(), provider_error: raw.get().to_owned() })
}

// JSON permits scientific notation. Expand it using decimal digits alone,
// bounding the output so a malformed vendor response cannot allocate unboundedly.
fn decimal_lexeme(raw: &str) -> Option<String> {
    let (mantissa, exponent) = raw.split_once(['e', 'E']).unwrap_or((raw, "0"));
    if !valid_decimal(mantissa) {
        return None;
    }
    let exponent: i32 = exponent.parse().ok()?;
    if exponent.unsigned_abs() > 1024 {
        return None;
    }
    let point = mantissa.find('.').unwrap_or(mantissa.len()) as i32 + exponent;
    let digits = mantissa.replace('.', "");
    let expanded = if point <= 0 {
        format!("0.{}{}", "0".repeat((-point) as usize), digits)
    } else if point as usize >= digits.len() {
        format!("{}{}", digits, "0".repeat(point as usize - digits.len()))
    } else {
        format!("{}.{}", &digits[..point as usize], &digits[point as usize..])
    };
    let (integer, fraction) = expanded.split_once('.').unwrap_or((&expanded, ""));
    let integer = integer.trim_start_matches('0');
    let integer = if integer.is_empty() { "0" } else { integer };
    Some(if fraction.is_empty() { integer.into() } else { format!("{integer}.{fraction}") })
}

// Prefer the exceeded throttler's documented delay; otherwise use an exhausted
// bucket's remaining window seconds. Unknown/malformed counters do not invent a delay.
fn retry_delay(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let seconds = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    headers
        .keys()
        .filter_map(|key| key.as_str().strip_prefix("retry-after-").and_then(|_| seconds(key.as_str())))
        .max()
        .or_else(|| seconds("retry-after"))
        .or_else(|| {
            headers
                .keys()
                .filter_map(|key| {
                    let bucket = key.as_str().strip_prefix("x-ratelimit-remaining-")?;
                    (seconds(key.as_str()) == Some(0)).then(|| seconds(&format!("x-ratelimit-reset-{bucket}"))).flatten()
                })
                .max()
        })
}
// The provider records the prepared form under this deterministic resource key.
// Call only after validate_size: whole positive CPUs make the integer cast lossless.
/// The prepared form's key. "frozen-agent" sets apart snapshots made since
/// the agent's upgrade path was frozen: those made before carry an agent
/// that predates it, so they are prepared again, once.
fn snapshot_name(image: &str, platform: &Platform, size: &Size) -> String {
    name("snapshot", &format!("frozen-agent\0{image}\0{platform}\0{}\0{}\0{}", size.cpus as u64, size.memory_bytes, size.disk_bytes))
}
/// Daytona runs x86_64 sandboxes only: "Daytona expects the local image to be
/// built for AMD64 architecture" (docs, per the sandbox survey, 2026-10).
fn platform() -> Platform {
    Platform::new("linux", "amd64")
}

#[cfg(test)]
mod tests {
    use super::*;
    // The snapshot limit is inclusive: an image of exactly max_image_gib fits.
    #[test]
    fn snapshot_limit_boundary() {
        assert!(fits_snapshot(20 * GIB, 20).is_ok());
        assert!(matches!(
            fits_snapshot(20 * GIB + 1, 20),
            Err(ProtocolError::ImageRefused { refusal: ImageRefusal::TooLarge { bytes, limit_bytes }, .. }) if bytes == 20 * GIB + 1 && limit_bytes == 20 * GIB
        ));
    }
    // Vendor decimal lexemes retain all digits, beyond binary64's exact range.
    #[test]
    fn exact_vendor_money_and_complete_errors() {
        let v: AggregatedUsage = serde_json::from_slice(
            br#"{"totalPrice":9007199254740993.00000001,"sandboxCount":1,"totalCPUSeconds":0,"totalRAMGBSeconds":0,"totalDiskGBSeconds":0,"totalGPUSeconds":0}"#,
        )
        .unwrap();
        assert_eq!(price(&v.price).unwrap(), "9007199254740993.00000001");
        assert_eq!(decimal_lexeme("1.23e-7").as_deref(), Some("0.000000123"));
        assert_eq!(decimal_lexeme("1.23e+5").as_deref(), Some("123000"));
        assert_eq!(decimal_lexeme("0.5e1").as_deref(), Some("5"));
        assert_eq!(decimal_lexeme("0.001e2").as_deref(), Some("0.1"));
        assert_eq!(decimal_lexeme("0e3").as_deref(), Some("0"));
        assert!(decimal_lexeme("1e99999").is_none());
        for invalid in ["-1e2", ".5e1", "1.e2", "1ee2", "1e", "NaN", "", "1e-99999"] {
            assert!(decimal_lexeme(invalid).is_none(), "{invalid}");
        }
    }
    // The snapshot is built for one platform, so the platform is part of its name.
    #[test]
    fn snapshot_name_includes_platform() {
        let size = Size { cpus: 2.0, memory_bytes: 4 << 30, disk_bytes: 10 << 30 };
        let amd = snapshot_name("image", &Platform::new("linux", "amd64"), &size);
        assert_eq!(amd, snapshot_name("image", &platform(), &size));
        assert_ne!(amd, snapshot_name("image", &Platform::new("linux", "arm64"), &size));
    }
    // Vendor normalization must not break an exact label retry.
    #[test]
    fn normalized_policy_identity() {
        let policy = |v: serde_json::Value| serde_json::from_value::<Policy>(v).unwrap();
        assert!(policy_matches(
            &policy(json!({"domainAllowList":"EXAMPLE.COM.,other.test"})),
            &policy(json!({"domainAllowList":"other.test,example.com"}))
        ));
        assert!(policy_matches(
            &policy(json!({"networkAllowList":"192.0.2.5,10.0.0.12/24"})),
            &policy(json!({"networkAllowList":"10.0.0.0/24,192.0.2.5/32"}))
        ));
        assert!(!policy_matches(&policy(json!({"networkAllowList":"192.0.2.5"})), &policy(json!({"networkAllowList":"192.0.2.6/32"}))));
    }
    // Retry headers use named throttlers; reset fallback applies only to an
    // exhausted bucket. Reset is a duration, not a Unix epoch.
    #[test]
    fn vendor_retry_headers() {
        let mut headers = reqwest::header::HeaderMap::new();
        assert_eq!(retry_delay(&headers), None);
        headers.insert("x-ratelimit-remaining-authenticated", "1".parse().unwrap());
        headers.insert("x-ratelimit-reset-authenticated", "200".parse().unwrap());
        assert_eq!(retry_delay(&headers), None);
        headers.insert("x-ratelimit-remaining-sandbox-create", "0".parse().unwrap());
        headers.insert("x-ratelimit-reset-sandbox-create", "17".parse().unwrap());
        assert_eq!(retry_delay(&headers), Some(17));
        headers.insert("retry-after-sandbox-create", "23".parse().unwrap());
        assert_eq!(retry_delay(&headers), Some(23));
        headers.insert("retry-after-sandbox-lifecycle", "31".parse().unwrap());
        assert_eq!(retry_delay(&headers), Some(31));
    }
}

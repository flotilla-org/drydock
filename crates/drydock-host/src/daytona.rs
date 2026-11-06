//! Daytona REST translator: each verb is Daytona's own operation, and each
//! answer is what Daytona said. Waiting, idempotence and ownership are
//! drydockd's, as the declared [`Semantics`] leave them (see `capabilities`).
//! API contract: https://www.daytona.io/docs/openapi.json (2026-10-20).
use crate::{
    kit::{
        self, GIB, LABEL_TAG, SizeLimits, StateTable, Vendor,
        api::{Amount, Api, Auth, Body, Failure, Next, Paging, Text, https_base, join},
        guest::{Guest, GuestOutput},
        image::{check_prepare, content_name, platform_dockerfile},
    },
    module::*,
    oci,
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
    // Daytona's errorReason, reported beside it, says why.
    ("error", Observation::Unknown { reason: UnknownReason::ProviderApiError }),
    ("build_failed", Observation::Unknown { reason: UnknownReason::ProviderApiError }),
];

// Daytona's wire types (see the API contract above), only the fields read.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Sandbox {
    id: Text,
    state: Text,
    labels: Option<BTreeMap<String, String>>,
    cpu: Option<u64>,
    memory: Option<u64>,
    disk: Option<u64>,
    spot_evicted_at: Option<String>,
    error_reason: Option<String>,
    updated_at: Option<DateTime<Utc>>,
    created_at: Option<DateTime<Utc>>,
    #[serde(flatten)]
    policy: Policy,
}
/// A sandbox's network policy, as created and as read back: one of the
/// three, or none.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Policy {
    #[serde(skip_serializing_if = "Option::is_none")]
    network_block_all: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_allow_list: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_allow_list: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    id: Text,
    state: Text,
    error_reason: Option<String>,
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
struct RegistryPushAccess {
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
    /// Daytona's number text, passed through: money never passes through f64.
    #[serde(rename = "totalPrice")]
    price: Box<RawValue>,
}

/// Every key but the two Daytona names alone has a default.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Settings {
    organization_id: String,
    /// Pinned out of band: the REST API supplies no gateway host public key.
    ssh_host_key: String,
    api_url: String,
    analytics_url: String,
    /// The region's toolbox proxy, which Daytona also reports on each sandbox.
    /// The control plane is trusted to delegate bearer authentication to it.
    toolbox_url: String,
    ssh_endpoint: String,
    /// Where sandboxes and snapshots are made; set `toolbox_url` to match.
    region: String,
    /// Container sandboxes take whole vCPUs and GiB, up to these.
    max_cpus: u64,
    max_memory_gib: u64,
    max_disk_gib: u64,
    /// The organization's limits. The default is Tier 1's; Tier 2 is 20,000
    /// and 400, Tier 3 40,000 and 500, Tier 4 50,000 and 600.
    rate_limits: Vec<RateLimit>,
    /// Largest image a snapshot may hold, in GiB: Daytona's default snapshot
    /// maximum is 20. Organizations with a raised limit configure it.
    max_image_gib: u64,
    /// Bytes per blob request drydockd sends on the push route. Each request
    /// must finish inside drydockd's HTTP deadline, so slow links want smaller chunks.
    push_chunk_bytes: u64,
    /// How long minted registry push access lasts, as Daytona mints it.
    push_credential_seconds: u64,
    /// How long an SSH gateway token lasts.
    ssh_token_minutes: u64,
    /// A file upload is one toolbox request: an agent build (about 12 MB)
    /// needs longer than an ordinary call on a slow link.
    upload_seconds: u64,
    /// Daytona's limit on one toolbox command.
    exec_seconds: u64,
    /// How often drydockd lists sandboxes.
    poll_seconds: u64,
    page_size: u32,
}
impl Default for Settings {
    fn default() -> Self {
        let limit = |operation: &str, requests| RateLimit { operation: operation.into(), requests, period_seconds: 60 };
        Self {
            organization_id: String::new(),
            ssh_host_key: String::new(),
            api_url: "https://app.daytona.io/api/".into(),
            analytics_url: "https://analytics.app.daytona.io/".into(),
            toolbox_url: "https://proxy.app-eu.daytona.io/toolbox/".into(),
            ssh_endpoint: "ssh.app.daytona.io:22".into(),
            region: "eu".into(),
            max_cpus: 4,
            max_memory_gib: 8,
            max_disk_gib: 10,
            rate_limits: vec![limit("*", 10_000), limit("provision", 300), limit("suspend", 10_000), limit("resume", 10_000)],
            max_image_gib: 20,
            push_chunk_bytes: 16 << 20,
            push_credential_seconds: 3600,
            ssh_token_minutes: 5,
            upload_seconds: 300,
            exec_seconds: 20,
            poll_seconds: 30,
            page_size: 200,
        }
    }
}
impl Settings {
    fn sizes(&self) -> SizeLimits {
        SizeLimits {
            cpus: (1, self.max_cpus),
            memory: (GIB, self.max_memory_gib.saturating_mul(GIB)),
            memory_step: GIB,
            disk: (GIB, self.max_disk_gib.saturating_mul(GIB)),
            disk_step: GIB,
        }
    }
}

#[async_trait]
impl Module for DaytonaModule {
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    async fn configure(&self, name: &str, config: &ProviderConfiguration, http: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
        let settings: Settings = serde_json::from_value(json!(config.settings)).map_err(|_| refused("invalid Daytona settings"))?;
        let positive =
            [settings.max_cpus, settings.max_memory_gib, settings.max_disk_gib, settings.max_image_gib, settings.push_chunk_bytes];
        if settings.organization_id.is_empty()
            || settings.ssh_host_key.is_empty()
            || settings.region.is_empty()
            || positive.contains(&0)
            || [settings.ssh_token_minutes, settings.upload_seconds, settings.exec_seconds, settings.poll_seconds].contains(&0)
            || settings.page_size == 0
        {
            return Err(refused("Daytona requires organization_id, ssh_host_key, region and positive limits"));
        }
        for endpoint in [&settings.api_url, &settings.analytics_url, &settings.toolbox_url] {
            if !https_base(DAYTONA, endpoint)?.path().ends_with('/') {
                return Err(refused("Daytona's configured bases must end in /"));
            }
        }
        let api = Api::new(DAYTONA, &settings.api_url, Auth::Bearer, http.clone())?.classify(classify).retry_after(retry_delay);
        let analytics = Api::new(DAYTONA, &settings.analytics_url, Auth::Bearer, http)?.classify(classify).retry_after(retry_delay);
        Ok(Arc::new(Daytona { name: name.to_owned(), ownership: config.ownership, settings, api, analytics }))
    }
}
pub struct Daytona {
    name: String,
    ownership: Ownership,
    settings: Settings,
    api: Api,
    analytics: Api,
}
/// Daytona's statuses, its whole body kept as the explanation (the host
/// masks credential echoes before limiting it). Daytona answers 409 while a
/// sandbox's state change is in progress: retryable. 400 is Daytona refusing
/// the request in the sandbox's state, in its own words.
fn classify(f: &Failure) -> ProtocolError {
    let reason = f.reason(&String::from_utf8_lossy(f.body));
    match f.status {
        409 => ProtocolError::Unavailable { reason, retry_after: f.retry_after, provider_error: None },
        _ => f.standard(reason),
    }
}
impl Daytona {
    fn sandbox_url(&self, id: &str, action: Option<&str>) -> Result<Url> {
        self.api.url(&[&["sandbox", id][..], action.as_slice()].concat())
    }
    /// A POST answered with the sandbox, which drydock does not read.
    async fn post(&self, url: Url, c: &Credentials) -> Result<()> {
        self.api.call::<IgnoredAny>(Method::POST, url, Body::None, c).await.map(drop)
    }
    fn environment(&self, v: Sandbox) -> Result<Environment> {
        let state = observe(&v.state, v.spot_evicted_at.is_some());
        let p = &v.policy;
        let policy = json!({"block":p.network_block_all,"cidrs":p.network_allow_list,"domains":p.domain_allow_list});
        Ok(Environment {
            id: v.id.to_string(),
            provider: self.name.clone(),
            label: v.labels.as_ref().and_then(|l| l.get(LABEL_TAG)).cloned(),
            state,
            granted_size: kit::granted(DAYTONA, v.cpu, v.memory, GIB, v.disk, GIB)?,
            egress: Enforcement::Advisory,
            // Every Daytona sandbox runs on x86_64 (see `platform`).
            platform: Some(platform()),
            egress_measured: false,
            egress_policy: Some(kit::digest(&policy.to_string())),
            timestamp: v.updated_at.or(v.created_at).map(Into::into),
            vendor: Some(VendorState { state: v.state.into(), reason: v.error_reason, tags: v.labels }),
        })
    }
    /// A route on the region's toolbox.
    fn toolbox(&self, id: &str, segments: &[&str]) -> Result<Url> {
        let base = https_base(DAYTONA, &self.settings.toolbox_url)?;
        join(&base, &[&[id], segments].concat())
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
        let body = Body::json(&json!({"command": script, "timeout": self.settings.exec_seconds}))?;
        let v: Executed = self.api.call(Method::POST, self.toolbox(id, &["process", "execute"])?, body, c).await?;
        Ok(GuestOutput::from_text(&v.result, "", Some(v.exit_code.into())))
    }
}

fn observe(state: &str, spot_evicted: bool) -> Observation {
    match (state, spot_evicted) {
        ("destroyed", true) => Observation::Gone { cause: Some(GoneCause::EvictedByProvider) },
        ("destroyed", false) => Observation::Gone { cause: Some(GoneCause::DestroyedAtProvider) },
        (state, _) => kit::observe(STATES, state),
    }
}
const CREATED: &str = "sandbox.created";
const STATE_UPDATED: &str = "sandbox.state.updated";
/// The bodies of `sandbox.created` and `sandbox.state.updated`, as recorded
/// from Daytona on 2026-11-05 and 2026-11-06, only the fields read.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Delivered {
    id: Text,
    organization_id: String,
    /// The state a created sandbox starts in.
    state: Option<Text>,
    new_state: Option<Text>,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
    timestamp: Option<DateTime<Utc>>,
}
/// A creation states the sandbox and Daytona's own state for it, which
/// drydock does not class; an update states the sandbox in its new state.
/// Neither gives a cause for a stop or a destruction, nor labels. Any other
/// event, or one for another organization, says nothing drydock follows.
#[async_trait]
impl VendorEvents for Daytona {
    async fn event(&self, delivery: VendorDelivery) -> Result<Vec<VendorObservation>> {
        let event = delivery.event.as_str();
        if event != CREATED && event != STATE_UPDATED {
            return Ok(vec![]);
        }
        let v: Delivered = serde_json::from_value(delivery.body).map_err(|e| refused(format!("Daytona {event} body: {e}")))?;
        if v.organization_id != self.settings.organization_id {
            return Ok(vec![]);
        }
        let (vendor, state, timestamp) = if event == CREATED {
            (v.state, None, v.created_at)
        } else {
            let state = v.new_state.as_deref().map(|s| match observe(s, false) {
                Observation::Stopped { .. } => Observation::Stopped { cause: None },
                Observation::Gone { .. } => Observation::Gone { cause: None },
                state => state,
            });
            (v.new_state, state, v.updated_at.or(v.timestamp))
        };
        let vendor = vendor.ok_or_else(|| refused(format!("Daytona {event} body names no state")))?;
        Ok(vec![VendorObservation {
            id: v.id.to_string(),
            state,
            vendor: VendorState { state: vendor.into(), reason: None, tags: None },
            timestamp: timestamp.map(Into::into),
        }])
    }
}

fn name(prefix: &str, input: &str) -> String {
    // Keep vendor names below 63 bytes, with 160 bits of digest identity.
    content_name(&format!("drydock-{prefix}-"), 40, &[input])
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

/// Daytona's egress as its documentation states it (2026-11-03). The module
/// applies one control per request (see `policy`); it never sets
/// `outboundProxyUrl`, whose `HTTP_PROXY` route works inside the guest.
fn egress_model() -> EgressModel {
    const LIMITS: &str = "https://www.daytona.io/docs/en/network-limits";
    use EgressShape::*;
    EgressModel {
        shapes: vec![Open, DenyAll, AllowAddresses, AllowDomains],
        // "Each sandbox runs behind a firewall" and updates change "outbound network
        // policy on the runner": outside the guest. The docs do not say whether guest
        // root can bypass it; drydockd's verdict settles that, not this claim.
        enforced: EnforcementSite::OutsideGuest,
        side_effects: vec![EgressSideEffect {
            shapes: vec![DenyAll, AllowAddresses, AllowDomains],
            opens: vec![],
            note: "On Tier 1 and 2, organization-level restrictions take precedence over the sandbox's \
                   policy and essential services remain reachable."
                .into(),
        }],
        // Tier 3 and 4 only; lower tiers refuse the update. Declared false
        // because the module cannot see the organization's tier.
        mutable_while_running: false,
        sources: vec![
            LIMITS.into(),
            format!("{LIMITS}#tier-based-network-restrictions"),
            format!("{LIMITS}#update-network-settings-while-a-sandbox-is-running"),
            "https://www.daytona.io/docs/en/isolation#network-isolation".into(),
        ],
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
            egress: EgressCapability {
                routes: vec![EgressRoute::None, EgressRoute::ExplicitProxy, EgressRoute::Open],
                model: egress_model(),
            },
            fallback_runner: true,
            // The toolbox writes files, so drydock puts the agent in each sandbox.
            bootstrap: BootstrapRoute::Upload,
            agent: true,
            platforms: vec![platform()],
            image_routes: vec![
                // Default: our own images live in registries Daytona cannot
                // reach, so drydockd copies them into Daytona's own.
                ImageRoute::ProviderPush {
                    protocol: PushProtocol::OciDistribution,
                    credential_lifetime_seconds: Some(self.settings.push_credential_seconds),
                    tools_layer: ToolsLayer::Upload,
                    max_image_bytes: Some(self.settings.max_image_gib.saturating_mul(GIB)),
                    chunk_bytes: Some(self.settings.push_chunk_bytes),
                },
                // Daytona pulls the base itself, from a registry the
                // organization registered via POST /docker-registry.
                ImageRoute::RegistryPull {
                    auth: RegistryAuthKind::Basic,
                    registration: CredentialRegistration::ProviderApi,
                    digest_references: true,
                    tools_layer: ToolsLayer::Upload,
                },
            ],
            usage: true,
            quota: true,
            // The agent carries outward exposures; the sandbox has no network of drydockd's.
            reach_ways: vec![ReachWay::OutwardExposure],
            // Create, start and stop answer once Daytona accepted them; a second
            // stop is refused (400), a delete mid-change conflicts (409), list
            // and delete reach the whole account, and start needs no token.
            semantics: Semantics { token_is_id: true, ..Semantics::default() },
            ..Capabilities::default()
        }
    }
    /// Daytona's webhooks are registered in its dashboard, through Svix.
    fn ways_in(&self) -> Vec<WayIn> {
        vec![
            WayIn::Poll { interval_ms: self.settings.poll_seconds.saturating_mul(1000) },
            WayIn::Webhook {
                registration: WebhookRegistration::Dashboard,
                events: vec![CREATED.into(), STATE_UPDATED.into()],
                delivery: DeliveryGuarantee::AtLeastOnce,
            },
        ]
    }
    fn operations(&self) -> Operations<'_> {
        Operations {
            exec: Some(self),
            files: Some(self),
            push_access: Some(self),
            events: Some(self),
            suspend_resume: Some(self),
            quota: Some(self),
            usage: Some(self),
            ..Operations::default()
        }
    }
    fn rate_limits(&self) -> Vec<RateLimit> {
        self.settings.rate_limits.clone()
    }
    /// Looks the snapshot up by its content name and creates it when absent;
    /// unavailable while Daytona builds it.
    async fn prepare(&self, r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
        let routes = [ImageRouteKind::ProviderPush, ImageRouteKind::RegistryPull];
        let (route, platform) = check_prepare(DAYTONA, &r, &routes, &platform())?;
        self.settings.sizes().check(DAYTONA, &r.size)?;
        // CreateSnapshot labels memory/disk "GB", but the resource guide and
        // default snapshot table specify GiB for the resulting sandbox:
        // https://www.daytona.io/docs/en/sandboxes/#resources (checked 2026-10-21).
        // Both routes produce the same filesystem, the base's, so the route
        // is not part of the key; nor is the tools image, which no snapshot
        // holds: drydock uploads the agent to each sandbox.
        let snapshot_name = snapshot_name(&r.image_digest, &platform, &r.size);
        let snapshot = match self.api.find::<Snapshot>(self.api.url(&["snapshots", &snapshot_name])?, c).await? {
            Some(v) => v,
            None => {
                let mut body = json!({
                    "name": snapshot_name,
                    "regionId": self.settings.region,
                    "sandboxClass": "container",
                    "cpu": r.size.cpus as u64,
                    "memory": r.size.memory_bytes / GIB,
                    "disk": r.size.disk_bytes / GIB,
                });
                match route {
                    // drydockd has put the amd64 image in Daytona's registry.
                    ImageRouteKind::ProviderPush => body["imageName"] = json!(r.image_digest),
                    // Daytona's snapshot API takes no platform; pin the
                    // multi-arch base in the build so the snapshot
                    // matches the prepared form.
                    ImageRouteKind::RegistryPull => {
                        body["buildInfo"] = json!({"dockerfileContent": platform_dockerfile(&r.image_digest, &platform)})
                    }
                    ImageRouteKind::RemoteBuild => unreachable!("check_prepare admits declared routes only"),
                }
                self.api.call(Method::POST, self.api.url(&["snapshots"])?, Body::json(&body)?, c).await?
            }
        };
        match &*snapshot.state {
            "active" => Ok(Prepared {
                provider: self.name.clone(),
                id: snapshot_name,
                platform,
                image_digest: r.image_digest,
                tools_digest: r.tools_digest,
            }),
            "error" | "build_failed" => Err(refused(format!(
                "Daytona snapshot {snapshot_name} is {}: {}",
                &*snapshot.state,
                snapshot.error_reason.as_deref().unwrap_or("no reason given")
            ))),
            state => {
                // Daytona keeps an unused snapshot inactive until activated.
                if state == "inactive" {
                    self.post(self.api.url(&["snapshots", &snapshot.id, "activate"])?, c).await?;
                }
                Err(ProtocolError::unavailable(format!("Daytona snapshot {snapshot_name} is {state}"), None))
            }
        }
    }
    /// One create. The sandbox is named by Daytona, not by the label.
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        let mut labels = BTreeMap::from([(LABEL_TAG, r.label.as_str())]);
        if self.ownership == Ownership::SharedAccount {
            labels.insert(OWNER_TAG, &self.name);
        }
        let mut body = json!({
            "snapshot": r.prepared.id,
            "labels": labels,
            "target": self.settings.region,
            "autoStopInterval": 0,
            "autoPauseInterval": 0,
            "autoDeleteInterval": -1,
            "public": false,
        });
        if let (Some(body), serde_json::Value::Object(policy)) = (body.as_object_mut(), json!(allowlist(r.egress)?)) {
            body.extend(policy);
        }
        let v: Sandbox = self.api.call(Method::POST, self.api.url(&["sandbox"])?, Body::json(&body)?, c).await?;
        Ok(Provisioned::Created(self.environment(v)?))
    }
    /// Every sandbox Daytona lists, in whatever state it reports.
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        const PAGED: Paging = Paging { rows: Some("items"), cursor: "cursor", next: Next::Body(&["nextCursor"]) };
        let mut url = self.api.url(&["sandbox"])?;
        url.query_pairs_mut().append_pair("limit", &self.settings.page_size.to_string());
        self.api.paged::<Sandbox>(url, &PAGED, c).await?.into_iter().map(|v| self.environment(v)).collect()
    }
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        self.environment(self.api.get(self.sandbox_url(id, None)?, c).await?)
    }
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        self.api.call::<IgnoredAny>(Method::DELETE, self.sandbox_url(id, None)?, Body::None, c).await.map(drop)
    }
    async fn reach(&self, id: &str, c: &Credentials) -> Result<Reach> {
        let mut url = self.sandbox_url(id, Some("ssh-access"))?;
        url.query_pairs_mut().append_pair("expiresInMinutes", &self.settings.ssh_token_minutes.to_string());
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
/// Stop and start. Daytona resumes by id alone, so the token is the id.
#[async_trait]
impl SuspendResume for Daytona {
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        self.post(self.sandbox_url(id, Some("stop"))?, c).await?;
        Ok(ResumeToken { token: Secret::new(id) })
    }
    async fn resume(&self, id: &str, _: ResumeToken, c: &Credentials) -> Result<()> {
        self.post(self.sandbox_url(id, Some("start"))?, c).await
    }
}
#[async_trait]
impl Exec for Daytona {
    async fn exec(&self, id: &str, r: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        Guest::exec(self, id, r, c).await
    }
}
/// Daytona's registry, with push access minted for it. Daytona resolves
/// `regionId` here only among the organisation's own regions and answers 404
/// "Region not found" for the shared ones (eu, us), so none is sent.
#[async_trait]
impl PushAccessOperation for Daytona {
    async fn push_access(&self, c: &Credentials) -> Result<PushAccess> {
        let access: RegistryPushAccess = self.api.get(self.api.url(&["docker-registry", "registry-push-access"])?, c).await?;
        let host = access.registry_url.strip_prefix("https://").unwrap_or(&access.registry_url).trim_end_matches('/');
        if !oci::registry_host_valid(host) {
            return Err(DAYTONA.bad_response());
        }
        Ok(PushAccess {
            repository: format!("{host}/{}/drydock-vessel", access.project),
            credential: RegistryCredential { username: access.username.into(), secret: Secret::new(String::from(access.secret)) },
            expires_at: Some(access.expires_at.into()),
        })
    }
}
/// The toolbox writes the file whole (making its parents), then sets its
/// mode: an upload carries none.
#[async_trait]
impl GuestFiles for Daytona {
    async fn put(&self, id: &str, file: GuestFile, bytes: Bytes, c: &Credentials) -> Result<()> {
        let mut url = self.toolbox(id, &["files", "upload-v2"])?;
        url.query_pairs_mut().append_pair("path", &file.path);
        let deadline = Duration::from_secs(self.settings.upload_seconds);
        self.api.call_within::<IgnoredAny>(Method::POST, url, Body::Bytes(bytes, "application/octet-stream"), c, deadline).await?;
        let mut url = self.toolbox(id, &["files", "permissions"])?;
        url.query_pairs_mut().append_pair("path", &file.path).append_pair("mode", &format!("{:04o}", file.mode));
        self.post(url, c).await
    }
}
#[async_trait]
impl QuotaOperation for Daytona {
    async fn quota(&self, c: &Credentials) -> Result<Quota> {
        let v: OrganizationUsage = self.api.get(self.api.url(&["organizations", &self.settings.organization_id, "usage"])?, c).await?;
        let gib = GIB as f64;
        let row = |region: Option<&RegionUsage>, resource, unit: &str, factor: f64, in_use: Amount, limit: Amount| ResourceQuota {
            key: QuotaKey { region: region.map(|r| r.region_id.to_string()), class: region.map(|r| r.sandbox_class.to_string()), resource },
            unit: unit.into(),
            in_use: in_use.get() * factor,
            limit: Some(limit.get() * factor),
        };
        let mut resources = Vec::new();
        for r in &v.region_usage {
            resources.push(row(Some(r), ResourceKind::Cpu, "{vCPU}", 1.0, r.current_cpu_usage, r.total_cpu_quota));
            resources.push(row(Some(r), ResourceKind::Memory, "By", gib, r.current_memory_usage, r.total_memory_quota));
            resources.push(row(Some(r), ResourceKind::Disk, "By", gib, r.current_disk_usage, r.total_disk_quota));
        }
        resources.push(row(None, ResourceKind::SnapshotStorage, "By", gib, v.current_snapshot_usage, v.total_snapshot_quota));
        resources.push(row(None, ResourceKind::VolumeStorage, "By", gib, v.current_volume_usage, v.total_volume_quota));
        Ok(Quota { resources, ..Quota::default() })
    }
}
/// The organization's aggregate for the period, as Daytona's analytics
/// reports it, in one call. No per-size hours: Daytona reports none.
#[async_trait]
impl UsageOperation for Daytona {
    async fn usage(&self, period: Period, c: &Credentials) -> Result<Usage> {
        let (from, to) = (String::from(period.start().clone()), String::from(period.end().clone()));
        let v: AggregatedUsage = self.analytics(&["usage", "aggregated"], &from, &to, c).await?;
        // Daytona's reserved memory/disk quantities are GiB:
        // https://www.daytona.io/docs/en/sandboxes/#resources
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
        Ok(Usage {
            period,
            environment_hours: vec![],
            measurements: Some(UsageMeasurements {
                scope: UsageScope::Organization { id: self.settings.organization_id.clone() },
                resources,
                // Analytics prices are denominated in USD; there is no currency field.
                cost: Some(Cost { amount: v.price.get().to_owned(), currency: "USD".into() }),
            }),
        })
    }
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
/// The prepared form's key: the base image, the platform and the size, which
/// a Daytona snapshot fixes. "base-only" sets apart snapshots of the base
/// alone from older ones carrying a baked agent. Call after the size check:
/// whole positive CPUs make the integer cast lossless.
fn snapshot_name(image: &str, platform: &Platform, size: &Size) -> String {
    name("snapshot", &format!("base-only\0{image}\0{platform}\0{}\0{}\0{}", size.cpus as u64, size.memory_bytes, size.disk_bytes))
}
/// Daytona runs x86_64 sandboxes only: "Daytona expects the local image to be
/// built for AMD64 architecture" (docs, per the sandbox survey, 2026-10).
fn platform() -> Platform {
    Platform::new("linux", "amd64")
}

#[cfg(test)]
mod tests {
    use super::*;
    // The snapshot is built for one platform, so the platform is part of its name.
    #[test]
    fn snapshot_name_includes_platform() {
        let size = Size { cpus: 2.0, memory_bytes: 4 << 30, disk_bytes: 10 << 30 };
        let amd = snapshot_name("image", &Platform::new("linux", "amd64"), &size);
        assert_eq!(amd, snapshot_name("image", &platform(), &size));
        assert_ne!(amd, snapshot_name("image", &Platform::new("linux", "arm64"), &size));
    }
    // One Daytona control per request: domains, addresses, or block-all.
    #[test]
    fn egress_translation() {
        let host = |h: &str| Destination::Host { host: serde_json::from_value(json!(h)).unwrap() };
        let deny = |direct| allowlist(EgressRequest::DenyAll { direct }).unwrap();
        assert_eq!(deny(vec![]), Policy { network_block_all: Some(true), ..Policy::default() });
        assert_eq!(deny(vec![host("Example.COM."), host("a.test")]).domain_allow_list.as_deref(), Some("a.test,example.com"));
        assert_eq!(deny(vec![host("192.0.2.5")]).network_allow_list.as_deref(), Some("192.0.2.5/32"));
        assert!(allowlist(EgressRequest::DenyAll { direct: vec![host("a.test"), host("192.0.2.5")] }).is_err());
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

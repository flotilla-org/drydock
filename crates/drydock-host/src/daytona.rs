//! Stateless Daytona REST translator. The host owns inventory, event diffs and retries.
//! API contract: https://www.daytona.io/docs/openapi.json (2026-10-20).
use crate::{
    kit::{
        self, GIB, LABEL_TAG, SizeLimits, StateTable, Vendor,
        api::{Api, Auth, Body, Failure, Next, Paging, absent_on_not_found, https_base, join},
        egress::normal_cidr,
        guest::{self, Guest, GuestOutput, SUPERVISE},
        image::{check_prepare, check_prepared, content_name},
    },
    module::*,
    oci::{self, ImageRef, Registry},
};
use async_trait::async_trait;
use drydock_protocol::*;
use reqwest::{Method, Url};
use serde::Deserialize;
use serde_json::{Value, json};
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
    /// Operator-supplied conformance command, executed as root. No declaration
    /// alone upgrades the claim: provision/resume/explicit inspect measure it.
    #[serde(default)]
    egress_probe: Option<ExecRequest>,
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
    async fn call(&self, method: Method, url: Url, body: Option<Value>, c: &Credentials) -> Result<Value> {
        self.api.call(method, url, body, c).await
    }
    /// None represents a provider uniqueness conflict (409), for
    /// look-up-or-create and destroy's wait only.
    async fn unless_conflict(&self, method: Method, url: Url, body: Option<Value>, c: &Credentials) -> Result<Option<Value>> {
        let operation = kit::api::operation(&method, &url);
        let response = self.api.send(method, url, body, c, true, &[]).await?;
        if response.status() == 409 {
            return Ok(None);
        }
        self.api.answer(&operation, &response).map(Some)
    }
    /// Daytona's `GET /sandbox/{idOrName}` accepts the name derived from a label.
    async fn by_label_name(&self, label: &str, c: &Credentials) -> Result<Option<Value>> {
        // Anything but a 404 fails provision; the caller retries it.
        let Some(v) = self.api.find(self.sandbox_url(&name("environment", label), None)?, c).await? else { return Ok(None) };
        if v["labels"][LABEL_TAG].as_str() != Some(label) {
            return Err(refused("Daytona sandbox name belongs to a different label"));
        }
        Ok(Some(v))
    }
    fn environment(&self, v: Value) -> Result<Environment> {
        let state = match DAYTONA.text(&v, "state")? {
            "destroyed" if v.get("spotEvictedAt").and_then(Value::as_str).is_some() => {
                Observation::Gone { cause: GoneCause::EvictedByProvider }
            }
            "destroyed" => Observation::Gone { cause: GoneCause::DestroyedAtProvider },
            "error" | "build_failed" => error_state(v.get("errorReason").and_then(Value::as_str).unwrap_or("")),
            state => kit::observe(STATES, state),
        };
        let number = |key| v.get(key).and_then(Value::as_u64);
        let timestamp = v
            .get("updatedAt")
            .or_else(|| v.get("createdAt"))
            .and_then(Value::as_str)
            .map(|s| s.parse::<chrono::DateTime<chrono::Utc>>().map_err(|_| DAYTONA.bad_response()))
            .transpose()?;
        let policy = json!({"block":v.get("networkBlockAll"),"cidrs":v.get("networkAllowList"),"domains":v.get("domainAllowList")});
        Ok(Environment {
            id: DAYTONA.text(&v, "id")?.into(),
            provider: self.name.clone(),
            label: v["labels"][LABEL_TAG].as_str().map(str::to_owned),
            state,
            granted_size: kit::granted(number("cpu"), number("memory"), GIB, number("disk"), GIB),
            egress: Enforcement::Advisory,
            // Every Daytona sandbox runs on x86_64 (see `platform`).
            platform: Some(platform()),
            egress_measured: false,
            egress_policy: Some(kit::digest(&policy.to_string())),
            timestamp: timestamp.map(Into::into),
        })
    }
    fn check_existing_request(&self, v: &Value, size: &Size, policy: &Value) -> Result<()> {
        let row = self.environment(v.clone())?;
        if row.granted_size.as_ref() != Some(size) || !policy_matches(v, policy) {
            return Err(refused("existing Daytona label has a different or unknown size/egress policy; provision a new label"));
        }
        Ok(())
    }
    /// The row, its advisory egress claim measured by the probe as root when
    /// the sandbox runs under a restricted policy. The image probe receives
    /// the policy mode, so deny-all needs no listed destination to succeed.
    async fn observed(&self, v: Value, c: &Credentials) -> Result<Environment> {
        let deny_all = v.get("networkBlockAll").and_then(Value::as_bool) == Some(true);
        let restricted = deny_all
            || v.get("domainAllowList").and_then(Value::as_str).is_some_and(|s| !s.is_empty())
            || v.get("networkAllowList").and_then(Value::as_str).is_some_and(|s| !s.is_empty() && s != "0.0.0.0/0");
        let mut row = self.environment(v)?;
        if restricted
            && matches!(row.state, Observation::Running)
            && let Some(probe) = &self.settings.egress_probe
        {
            guest::measure_egress(self, &mut row, probe, deny_all, c).await;
        }
        Ok(row)
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
                let row = self.call(Method::GET, self.sandbox_url(id, None)?, None, c).await?;
                DAYTONA.text(&row, "toolboxProxyUrl")?.to_owned()
            }
        };
        let base = https_base(DAYTONA, &base).map_err(|_| DAYTONA.bad_response())?;
        let url = join(&base, &[id, "process", "execute"]).map_err(|_| DAYTONA.bad_response())?;
        let v = self.call(Method::POST, url, Some(json!({"command": command, "timeout": timeout})), c).await?;
        let exit = v.get("exitCode").and_then(Value::as_i64).filter(|v| i32::try_from(*v).is_ok()).ok_or_else(|| DAYTONA.bad_response())?;
        // Empty output is valid for a successful command (or a failing command).
        let output = v.get("result").and_then(Value::as_str).ok_or_else(|| DAYTONA.bad_response())?;
        Ok(GuestOutput::from_text(output, "", Some(exit)))
    }
    /// The baked executable owns detachment, singleton locking and crash
    /// recovery. Guest packages and a socket inode are not readiness proof;
    /// the daemon waits for the agent client's normal hello handshake.
    async fn bootstrap(&self, id: &str, c: &Credentials) -> Result<()> {
        self.execute(id, SUPERVISE, 25, c).await?.success(DAYTONA).map(drop)
    }
    // Lifecycle state checks deliberately avoid explicit inspect's root probe.
    async fn lifecycle_state(&self, id: &str, c: &Credentials) -> Result<Observation> {
        Ok(self.environment(self.call(Method::GET, self.sandbox_url(id, None)?, None, c).await?)?.state)
    }
    /// Observes only successful asynchronous operations: a failed GET ends
    /// the wait. A successful async start may briefly still report stopped,
    /// so stopped alone is not terminal here; conflict re-adoption handles
    /// stopped rows.
    async fn wait_started(&self, id: &str, c: &Credentials) -> Result<Environment> {
        kit::poll(60, Duration::from_secs(2), async || {
            let raw = self.call(Method::GET, self.sandbox_url(id, None)?, None, c).await?;
            match DAYTONA.text(&raw, "state")? {
                "started" => self.environment(raw).map(Some),
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
        let access = self.call(Method::GET, self.api.url(&["docker-registry", "registry-push-access"])?, None, c).await?;
        let bad = || DAYTONA.bad_response();
        let expires_at = DAYTONA.text(&access, "expiresAt")?.parse::<chrono::DateTime<chrono::Utc>>().map_err(|_| bad())?;
        let host = DAYTONA.text(&access, "registryUrl")?;
        let host = host.strip_prefix("https://").unwrap_or(host).trim_end_matches('/');
        if !oci::registry_host_valid(host) {
            return Err(bad());
        }
        let credential = RegistryCredential {
            username: DAYTONA.text(&access, "username")?.into(),
            secret: Secret::new(DAYTONA.text(&access, "secret")?),
        };
        let target = Registry::new(http.clone(), host, Some(credential), Some(expires_at)).map_err(|_| bad())?;
        let repository = format!("{}/drydock-vessel", DAYTONA.text(&access, "project")?);
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
    async fn analytics_json(&self, segments: &[&str], from: &str, to: &str, c: &Credentials) -> Result<Value> {
        self.analytics.call(Method::GET, self.analytics_url(segments, from, to)?, None, c).await
    }
    /// One analytics read, its price kept as the vendor's decimal lexeme.
    async fn analytics(&self, segments: &[&str], from: &str, to: &str, c: &Credentials) -> Result<Value> {
        let url = self.analytics_url(segments, from, to)?;
        let operation = kit::api::operation(&Method::GET, &url);
        let response = self.analytics.send(Method::GET, url, Body::None, c, true, &[]).await?;
        if !response.status().is_success() {
            return Err(self.analytics.failure(&operation, &response));
        }
        parse_analytics(response.body())
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
fn policy_matches(row: &Value, policy: &Value) -> bool {
    // Compare stable requested destinations, never a DNS resolution at retry.
    let set = |key: &str, v: &Value| {
        let entries = v.as_str().unwrap_or("").split(',').filter(|s| !s.is_empty()).map(str::trim);
        if key == "domainAllowList" {
            entries.map(kit::egress::normal_host).collect::<BTreeSet<_>>()
        } else {
            entries.map(|s| normal_cidr(s).unwrap_or_else(|| s.into())).collect()
        }
    };
    row["networkBlockAll"].as_bool().unwrap_or(false) == policy["networkBlockAll"].as_bool().unwrap_or(false)
        && ["networkAllowList", "domainAllowList"].iter().all(|key| set(key, &row[*key]) == set(key, &policy[*key]))
}
fn allowlist(request: EgressRequest) -> Result<Value> {
    match request {
        EgressRequest::Open => Ok(json!({"networkAllowList":"0.0.0.0/0"})),
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
            if !hosts.is_empty() {
                Ok(json!({"domainAllowList":hosts.into_iter().collect::<Vec<_>>().join(",")}))
            } else if !cidrs.is_empty() {
                Ok(json!({"networkAllowList":cidrs.into_iter().collect::<Vec<_>>().join(",")}))
            } else {
                Ok(json!({"networkBlockAll":true}))
            }
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
        let snapshot = match self.api.find(self.api.url(&["snapshots", &snapshot_name])?, c).await? {
            Some(v) => v,
            None => {
                let mut body = json!({"name":snapshot_name,"regionId":self.settings.region,"sandboxClass":"container","cpu":r.size.cpus as u64,"memory":r.size.memory_bytes/GIB,"disk":r.size.disk_bytes/GIB});
                match route {
                    ImageRouteKind::ProviderPush => body["imageName"] = json!(self.push(&r, &platform, &snapshot_name, c).await?),
                    ImageRouteKind::RegistryPull => {
                        // Daytona's snapshot API takes no platform; pin both multi-arch
                        // references in the build so the snapshot matches the prepared form.
                        let dockerfile = format!(
                            "FROM --platform={platform} {} AS drydock_tools\nFROM --platform={platform} {}\nCOPY --from=drydock_tools /opt/drydock/ /opt/drydock/\n",
                            r.tools_digest, r.image_digest
                        );
                        body["buildInfo"] = json!({"dockerfileContent":dockerfile});
                    }
                    ImageRouteKind::RemoteBuild => unreachable!("check_prepare admits declared routes only"),
                }
                match self.unless_conflict(Method::POST, self.api.url(&["snapshots"])?, Some(body), c).await? {
                    Some(snapshot) => snapshot,
                    None => self.call(Method::GET, self.api.url(&["snapshots", &snapshot_name])?, None, c).await?,
                }
            }
        };
        let id = DAYTONA.text(&snapshot, "id")?.to_owned();
        let mut snapshot = snapshot;
        let mut activation_submitted = false;
        for _ in 0..120 {
            match DAYTONA.text(&snapshot, "state")? {
                "active" => {
                    // SnapshotDto uses `mem` for RAM, unlike CreateSnapshot's `memory`.
                    if DAYTONA.number(&snapshot, "cpu")? != r.size.cpus
                        || DAYTONA.number(&snapshot, "mem")? != (r.size.memory_bytes / GIB) as f64
                        || DAYTONA.number(&snapshot, "disk")? != (r.size.disk_bytes / GIB) as f64
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
                    self.call(Method::POST, self.api.url(&["snapshots", &id, "activate"])?, None, c).await?;
                    activation_submitted = true;
                }
                "error" | "build_failed" => return Err(refused("Daytona snapshot build failed")),
                _ => {}
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            snapshot = self.call(Method::GET, self.api.url(&["snapshots", &id])?, None, c).await?;
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
            let mut row = self.environment(v)?;
            if matches!(row.state, Observation::Running) {
                // Every Running re-adoption bootstraps; the guest supervisor's
                // lock makes this idempotent even across concurrent hosts.
                self.bootstrap(&row.id, c).await?;
                row = self.inspect(&row.id, c).await?;
            }
            return Ok(Provisioned::Existing(row));
        }
        let mut body = json!({
            "name":name("environment", &r.label), "snapshot":r.prepared.id, "labels":{LABEL_TAG:r.label.clone()},
            "target":self.settings.region,
            "autoStopInterval":0, "autoPauseInterval":0, "autoDeleteInterval":-1, "public":false
        });
        body.as_object_mut().unwrap().extend(policy.as_object().unwrap().clone());
        let created = self.unless_conflict(Method::POST, self.api.url(&["sandbox"])?, Some(body), c).await?;
        let v = match created {
            None => {
                let v = self
                    .by_label_name(&r.label, c)
                    .await?
                    .ok_or_else(|| ProtocolError::NotFound { reason: "Daytona sandbox vanished after a name conflict".into() })?;
                self.check_existing_request(&v, size, &policy)?;
                let existing = self.environment(v.clone())?;
                if matches!(existing.state, Observation::Stopped { .. } | Observation::Unknown { .. } | Observation::Gone { .. }) {
                    return Ok(Provisioned::Existing(existing));
                }

                let row = self.wait_started(DAYTONA.text(&v, "id")?, c).await?;
                self.bootstrap(&row.id, c).await?;
                return Ok(Provisioned::Existing(self.inspect(&row.id, c).await?));
            }
            Some(v) => v,
        };
        let row = self.wait_started(DAYTONA.text(&v, "id")?, c).await?;
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
        for v in self.api.paged(url, &PAGED, c).await? {
            let row = self.environment(v)?;
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
        let value = self.call(Method::GET, self.sandbox_url(id, None)?, None, c).await?;
        self.observed(value, c).await
    }
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        // Daytona answers 409 while a state change is in progress; wait it out briefly,
        // then surface the retryable `unavailable` error.
        for attempt in 1..=DESTROY_ATTEMPTS {
            let url = self.sandbox_url(id, None)?;
            match absent_on_not_found(self.unless_conflict(Method::DELETE, url, None, c).await) {
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
        let v = self.call(Method::POST, url, None, c).await?;
        Ok(Reach::Ssh {
            endpoint: self.settings.ssh_endpoint.clone(),
            user: Secret::new(DAYTONA.text(&v, "token")?),
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
            self.call(Method::POST, self.sandbox_url(id, Some("stop"))?, None, c).await?;
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
            self.call(Method::POST, self.sandbox_url(id, Some("start"))?, None, c).await?;
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
        let v = self.call(Method::GET, self.api.url(&["organizations", &self.settings.organization_id, "usage"])?, None, c).await?;
        let mut resources = Vec::new();
        for region in v.get("regionUsage").and_then(Value::as_array).ok_or_else(|| DAYTONA.bad_response())? {
            for (resource, unit, factor, current, total) in [
                (ResourceKind::Cpu, "{vCPU}", 1.0, "currentCpuUsage", "totalCpuQuota"),
                (ResourceKind::Memory, "By", GIB as f64, "currentMemoryUsage", "totalMemoryQuota"),
                (ResourceKind::Disk, "By", GIB as f64, "currentDiskUsage", "totalDiskQuota"),
            ] {
                resources.push(ResourceQuota {
                    key: QuotaKey {
                        region: Some(DAYTONA.text(region, "regionId")?.into()),
                        class: Some(DAYTONA.text(region, "sandboxClass")?.into()),
                        resource,
                    },
                    unit: unit.into(),
                    in_use: DAYTONA.number(region, current)? * factor,
                    limit: Some(DAYTONA.number(region, total)? * factor),
                });
            }
        }
        for (resource, current, total) in [
            (ResourceKind::SnapshotStorage, "currentSnapshotUsage", "totalSnapshotQuota"),
            (ResourceKind::VolumeStorage, "currentVolumeUsage", "totalVolumeQuota"),
        ] {
            resources.push(ResourceQuota {
                key: QuotaKey { region: None, class: None, resource },
                unit: "By".into(),
                in_use: DAYTONA.number(&v, current)? * GIB as f64,
                limit: Some(DAYTONA.number(&v, total)? * GIB as f64),
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
        let v = self.analytics(&["usage", "aggregated"], &from_text, &to_text, c).await?;
        // Daytona's reserved memory/disk quantities are GiB:
        // https://www.daytona.io/docs/en/sandboxes/#resources
        // Interpret analytics' GBSeconds as the integral of those same reserved
        // quantities. This naming assumption is part of live metering acceptance.
        let resources = [
            (ResourceKind::Cpu, "{vCPU}.s", "totalCPUSeconds", 1.0),
            (ResourceKind::Memory, "By.s", "totalRAMGBSeconds", GIB as f64),
            (ResourceKind::Disk, "By.s", "totalDiskGBSeconds", GIB as f64),
            (ResourceKind::Gpu, "{GPU}.s", "totalGPUSeconds", 1.0),
            (ResourceKind::Environments, "1", "sandboxCount", 1.0),
        ]
        .into_iter()
        .map(|(resource, unit, key, factor)| Ok((resource, Quantity { amount: DAYTONA.number(&v, key)? * factor, unit: unit.into() })))
        .collect::<Result<_>>()?;
        // The analytics parser retains the vendor's decimal lexeme;
        // money never passes through f64, including during parsing.
        let price = DAYTONA.text(&v, "totalPrice")?.to_owned();
        if !valid_decimal(&price) {
            return Err(DAYTONA.bad_response());
        }
        // Analytics prices are denominated in USD; there is no currency field.
        let mut environment_hours = Vec::new();
        let totals = self.analytics_json(&["usage", "sandbox"], &from_text, &to_text, c).await?;
        let mut seen = BTreeSet::new();
        for sandbox in totals.as_array().ok_or_else(bad)? {
            let id = DAYTONA.text(sandbox, "sandboxId")?;
            if !seen.insert(id) {
                continue;
            }
            let periods = self.analytics_json(&["sandbox", id, "usage"], &from_text, &to_text, c).await?;
            for row in periods.as_array().ok_or_else(bad)? {
                let cpus = DAYTONA.number(row, "cpu")?;
                // Zero-CPU records contribute no size-hours, even if other
                // optional fields are absent or malformed.
                if cpus == 0.0 {
                    continue;
                }
                let start = DAYTONA.text(row, "startAt")?.parse::<chrono::DateTime<chrono::Utc>>().map_err(|_| bad())?;
                let end = match row.get("endAt") {
                    None => ongoing_end,
                    Some(value) => {
                        let end = value.as_str().ok_or_else(bad)?.parse::<chrono::DateTime<chrono::Utc>>().map_err(|_| bad())?;
                        if end < start {
                            return Err(bad());
                        }
                        end
                    }
                };
                let start = start.max(from);
                let end = end.min(to);
                if end <= start {
                    continue;
                }
                let seconds = (end - start).num_milliseconds() as f64 / 1000.0;
                let bytes = |key| -> Result<u64> { row.get(key).and_then(Value::as_u64).and_then(|v| v.checked_mul(GIB)).ok_or_else(bad) };
                environment_hours.push(SizeUsage {
                    size: Size { cpus, memory_bytes: bytes("ramGB")?, disk_bytes: bytes("diskGB")? },
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

// Parse money as a raw JSON decimal lexeme before any numeric conversion.
// Keeping raw_value local avoids changing serde's flattened event decoding.
fn parse_analytics(bytes: &[u8]) -> Result<Value> {
    let fields: std::collections::BTreeMap<String, Box<serde_json::value::RawValue>> = serde_json::from_slice(bytes).map_err(|_| {
        ProtocolError::Internal { reason: "invalid Daytona analytics".into(), provider_error: String::from_utf8_lossy(bytes).into_owned() }
    })?;
    let mut result = serde_json::Map::new();
    for (key, value) in fields {
        let parsed = if key == "totalPrice" {
            Value::String(decimal_lexeme(value.get()).ok_or_else(|| ProtocolError::Internal {
                reason: "invalid Daytona price".into(),
                provider_error: String::from_utf8_lossy(bytes).into_owned(),
            })?)
        } else {
            serde_json::from_str(value.get()).map_err(|_| DAYTONA.bad_response())?
        };
        result.insert(key, parsed);
    }
    Ok(Value::Object(result))
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
        let v = parse_analytics(br#"{"totalPrice":9007199254740993.00000001,"sandboxCount":1}"#).unwrap();
        assert_eq!(v["totalPrice"], "9007199254740993.00000001");
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
        assert!(policy_matches(
            &json!({"domainAllowList":"EXAMPLE.COM.,other.test"}),
            &json!({"domainAllowList":"other.test,example.com"})
        ));
        assert!(policy_matches(
            &json!({"networkAllowList":"192.0.2.5,10.0.0.12/24"}),
            &json!({"networkAllowList":"10.0.0.0/24,192.0.2.5/32"})
        ));
        assert!(!policy_matches(&json!({"networkAllowList":"192.0.2.5"}), &json!({"networkAllowList":"192.0.2.6/32"})));
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

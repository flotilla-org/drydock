//! Stateless Daytona REST translator. The host owns inventory, event diffs and retries.
//! API contract: https://www.daytona.io/docs/openapi.json (2026-10-20).
use crate::module::*;
use async_trait::async_trait;
use drydock_protocol::*;
use reqwest::{Method, Url};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;

pub struct DaytonaModule;
const SSH_TOKEN_TTL_MINUTES: &str = "5";
#[derive(Clone, Copy)]
enum ResponseFormat {
    Json,
    Analytics,
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
    /// Operator-supplied conformance command, executed as root. No declaration
    /// alone upgrades the claim: provision/resume/explicit inspect measure it.
    #[serde(default)]
    egress_probe: Option<ExecRequest>,
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
    async fn configure(&self, config: &ProviderConfiguration, http: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
        let settings: Settings = serde_json::from_value(json!(config.settings)).map_err(|_| refused("invalid Daytona settings"))?;
        if !(1..=4).contains(&settings.tier)
            || settings.organization_id.is_empty()
            || settings.ssh_host_key.is_empty()
            || settings.region.is_empty()
        {
            return Err(refused("Daytona requires organization_id, ssh_host_key, region and tier 1..4"));
        }
        for endpoint in [&settings.api_url, &settings.analytics_url].into_iter().chain(settings.toolbox_url.iter()) {
            endpoint_url(endpoint, true)?;
        }
        Ok(Arc::new(Daytona { name: config.name.clone(), settings, http }))
    }
}
pub struct Daytona {
    name: String,
    settings: Settings,
    http: Arc<dyn HttpClient>,
}
impl Daytona {
    fn path(&self, base: &str, segments: &[&str]) -> Result<Url> {
        let mut url = Url::parse(base).map_err(|_| refused("invalid Daytona URL"))?;
        url.path_segments_mut().map_err(|_| refused("invalid Daytona base URL"))?.pop_if_empty().extend(segments);
        Ok(url)
    }
    fn sandbox_url(&self, id: &str, action: Option<&str>) -> Result<Url> {
        let mut segments = vec!["sandbox", id];
        if let Some(action) = action {
            segments.push(action);
        }
        self.path(&self.settings.api_url, &segments)
    }
    async fn call(&self, method: Method, url: Url, body: Option<Value>, c: &Credentials) -> Result<Value> {
        self.request(method, url, body, c, false, ResponseFormat::Json).await?.ok_or_else(bad_response)
    }
    /// None represents a provider uniqueness conflict for look-up-or-create only.
    /// Keep status branching here, independent of user-facing error wording.
    async fn create(&self, url: Url, body: Value, c: &Credentials) -> Result<Option<Value>> {
        self.request(Method::POST, url, Some(body), c, true, ResponseFormat::Json).await
    }
    async fn request(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
        c: &Credentials,
        accept_conflict: bool,
        response_format: ResponseFormat,
    ) -> Result<Option<Value>> {
        let token = c.token().ok_or_else(|| ProtocolError::CredentialRejected { reason: "Daytona API key not delivered".into() })?;
        let operation = format!("{method} {}", url.path());
        let mut request = reqwest::Request::new(method, url);
        let mut auth = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.expose()))
            .map_err(|_| refused("invalid Daytona API key header"))?;
        auth.set_sensitive(true);
        request.headers_mut().insert(reqwest::header::AUTHORIZATION, auth);
        if let Some(body) = body {
            request.headers_mut().insert(reqwest::header::CONTENT_TYPE, reqwest::header::HeaderValue::from_static("application/json"));
            *request.body_mut() = Some(body.to_string().into());
        }
        let response = rigging_http_client::http_execute!(self.http, request).map_err(|error| ProtocolError::Unavailable {
            provider_error: Some(diagnostic_text(error.as_bytes())),
            reason: format!("Daytona {operation} transport failed"),
            retry_after: None,
        })?;
        let retry_after = retry_delay(response.headers());
        let status = response.status().as_u16();
        if status == 409 && accept_conflict {
            return Ok(None);
        }
        let raw = diagnostic_text(response.body());
        if !(200..300).contains(&status) {
            // Keep upstream status and explanation for every category.
            // No SDK retry is involved.
            let reason = format!("Daytona {operation} HTTP {status}: {raw}");
            return Err(match status {
                401 => ProtocolError::CredentialRejected { reason: reason.clone() },
                403 => ProtocolError::Refused { reason: format!("permission denied; {reason}") },
                404 => ProtocolError::NotFound { reason: reason.clone() },
                402 => ProtocolError::QuotaExhausted { reason: reason.clone() },
                429 => ProtocolError::RateLimited { reason: reason.clone(), retry_after },
                408 => ProtocolError::unavailable(reason.clone(), None),
                500..=599 => ProtocolError::unavailable(reason.clone(), retry_after),
                _ => ProtocolError::Internal { reason: format!("unexpected Daytona {operation} HTTP {status}"), provider_error: raw },
            });
        }
        if response.body().is_empty() {
            return Ok(Some(Value::Null));
        }
        if matches!(response_format, ResponseFormat::Analytics) {
            return parse_analytics(response.body()).map(Some);
        }
        serde_json::from_slice(response.body()).map(Some).map_err(|_| ProtocolError::Internal {
            reason: "invalid Daytona response".into(),
            provider_error: "response was not valid JSON".into(),
        })
    }
    async fn inventory(&self, label: Option<&str>, c: &Credentials) -> Result<Vec<Value>> {
        let mut rows = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen = BTreeSet::new();
        loop {
            let mut url = self.path(&self.settings.api_url, &["sandbox"])?;
            url.query_pairs_mut().append_pair("limit", "200");
            if let Some(label) = label {
                url.query_pairs_mut().append_pair("labels", &json!({"flotilla.label":label}).to_string());
            }
            if let Some(cursor) = &cursor {
                url.query_pairs_mut().append_pair("cursor", cursor);
            }
            let page = self.call(Method::GET, url, None, c).await?;
            rows.extend(page.get("items").and_then(Value::as_array).ok_or_else(bad_response)?.iter().cloned());
            match page.get("nextCursor").and_then(Value::as_str).filter(|v| !v.is_empty()) {
                None => return Ok(rows),
                Some(next) if seen.insert(next.to_owned()) => cursor = Some(next.to_owned()),
                _ => return Err(bad_response()),
            }
        }
    }
    fn environment(&self, v: Value) -> Result<ObservedEnvironment> {
        let state = match text(&v, "state")? {
            "started" => Observation::Running,
            "creating" | "pulling_snapshot" | "pending_build" | "building_snapshot" => {
                Observation::Transitioning { phase: TransitionPhase::Preparing }
            }
            "starting" | "restoring" | "resuming" => Observation::Transitioning { phase: TransitionPhase::Starting },
            "stopping" | "archiving" | "pausing" => Observation::Transitioning { phase: TransitionPhase::Stopping },
            "resizing" | "snapshotting" | "forking" => Observation::Transitioning { phase: TransitionPhase::Reconfiguring },
            "destroying" => Observation::Transitioning { phase: TransitionPhase::Destroying },
            "stopped" | "archived" => Observation::Stopped { cause: StopCause::SuspendedByRequest },
            "paused" => Observation::Stopped { cause: StopCause::PausedByProvider },
            "destroyed" if v.get("spotEvictedAt").and_then(Value::as_str).is_some() => {
                Observation::Gone { cause: GoneCause::EvictedByProvider }
            }
            "destroyed" => Observation::Gone { cause: GoneCause::DestroyedAtProvider },
            "error" | "build_failed" => match v.get("errorReason").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase().as_str() {
                reason
                    if reason.contains("out of memory") || reason.split(|c: char| !c.is_ascii_alphanumeric()).any(|word| word == "oom") =>
                {
                    Observation::Gone { cause: GoneCause::HostOutOfMemory }
                }
                reason if reason.contains("evict") => Observation::Gone { cause: GoneCause::EvictedByProvider },
                reason if reason.contains("unreachable") => Observation::Unknown { reason: UnknownReason::HostUnreachable },
                _ => Observation::Unknown { reason: UnknownReason::ProviderApiError },
            },
            _ => Observation::Unknown { reason: UnknownReason::ProviderStateUnknown },
        };
        let size =
            match (v.get("cpu").and_then(Value::as_u64), v.get("memory").and_then(Value::as_u64), v.get("disk").and_then(Value::as_u64)) {
                (Some(cpu), Some(memory), Some(disk)) if cpu > 0 => Some(Size {
                    cpus: cpu as f64,
                    memory_bytes: memory.checked_mul(GIB).ok_or_else(bad_response)?,
                    disk_bytes: disk.checked_mul(GIB).ok_or_else(bad_response)?,
                }),
                _ => None,
            };
        let timestamp = v
            .get("updatedAt")
            .or_else(|| v.get("createdAt"))
            .and_then(Value::as_str)
            .map(|s| s.parse::<chrono::DateTime<chrono::Utc>>().map_err(|_| bad_response()))
            .transpose()?;
        let policy = json!({"block":v.get("networkBlockAll"),"cidrs":v.get("networkAllowList"),"domains":v.get("domainAllowList")});
        let fingerprint = format!("{:x}", Sha256::digest(policy.to_string().as_bytes()));
        Ok(ObservedEnvironment {
            egress_policy: Some(fingerprint),
            egress_measured: false,
            environment: Environment {
                id: text(&v, "id")?.into(),
                provider: self.name.clone(),
                label: v.pointer("/labels/flotilla.label").and_then(Value::as_str).map(str::to_owned),
                state,
                granted_size: size,
                egress: Enforcement::Advisory,
            },
            timestamp,
        })
    }
    fn check_existing_request(&self, v: &Value, size: &Size, policy: &Value) -> Result<()> {
        let row = self.environment(v.clone())?;
        if row.environment.granted_size.as_ref() != Some(size) || !policy_matches(v, policy) {
            return Err(refused("existing Daytona label has a different or unknown size/egress policy; provision a new label"));
        }
        Ok(())
    }
    async fn observed(&self, v: Value, c: &Credentials) -> Result<ObservedEnvironment> {
        let deny_all = v.get("networkBlockAll").and_then(Value::as_bool) == Some(true);
        let restricted = deny_all
            || v.get("domainAllowList").and_then(Value::as_str).is_some_and(|s| !s.is_empty())
            || v.get("networkAllowList").and_then(Value::as_str).is_some_and(|s| !s.is_empty() && s != "0.0.0.0/0");
        let mut row = self.environment(v)?;
        if restricted
            && matches!(row.environment.state, Observation::Running)
            && let Some(probe) = &self.settings.egress_probe
        {
            // The image probe receives policy mode, so deny-all does not need a
            // listed destination to succeed. Root is checked independently.
            let command = format!(
                "test \"$(id -u)\" = 0 && DRYDOCK_PROBE_DENY_ALL={} {}",
                if deny_all { "1" } else { "0" },
                shell_command(&probe.command)
            );
            let output = self.execute(&row.environment.id, &command, 20, c).await?;
            let proof: Value = serde_json::from_str(&output).map_err(|_| ProtocolError::Internal {
                reason: "invalid Daytona egress probe response".into(),
                provider_error: "probe output omitted".into(),
            })?;
            if proof["uid"].as_u64().is_none()
                || proof["unlisted_canary"].as_bool().is_none()
                || proof["raw_dns"].as_bool().is_none()
                || (!deny_all && proof["listed_direct"].as_bool().is_none())
            {
                return Err(ProtocolError::Internal {
                    reason: "incomplete Daytona egress proof".into(),
                    provider_error: "probe output omitted".into(),
                });
            }
            if proof["uid"] == 0
                && proof["unlisted_canary"] == false
                && proof["raw_dns"] == false
                && (deny_all || proof["listed_direct"] == true)
            {
                row.environment.egress = Enforcement::Enforced;
            }
            row.egress_measured = true;
        }
        Ok(row)
    }
    async fn execute(&self, id: &str, command: &str, timeout: u64, c: &Credentials) -> Result<String> {
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
                text(&row, "toolboxProxyUrl")?.to_owned()
            }
        };
        let mut base = endpoint_url(&base, false).map_err(|_| bad_response())?;
        base.path_segments_mut().map_err(|_| bad_response())?.pop_if_empty().extend([id, "process", "execute"]);
        let url = base;
        let v = self.call(Method::POST, url, Some(json!({"command": command, "timeout": timeout})), c).await?;
        let exit_code = v.get("exitCode").and_then(Value::as_i64).and_then(|v| i32::try_from(v).ok()).ok_or_else(bad_response)?;
        // Empty output is valid for a successful command (or a failing command).
        let output = v.get("result").and_then(Value::as_str).ok_or_else(bad_response)?;
        if exit_code != 0 {
            return Err(ProtocolError::CommandFailed {
                reason: "Daytona guest command failed".into(),
                exit_code,
                output: Secret::new(output),
            });
        }
        Ok(output.into())
    }
    async fn bootstrap(&self, id: &str, c: &Credentials) -> Result<()> {
        // The baked executable owns detachment, singleton locking and crash
        // recovery. Guest packages and a socket inode are not readiness proof;
        // the daemon waits for the agent client's normal hello handshake.
        self.execute(id, "/opt/drydock/drydock-agent --supervise --socket /run/drydock/agent.sock", 25, c).await?;
        Ok(())
    }
    // Lifecycle state checks deliberately avoid explicit inspect's root probe.
    async fn lifecycle_state(&self, id: &str, c: &Credentials) -> Result<Observation> {
        Ok(self.environment(self.call(Method::GET, self.sandbox_url(id, None)?, None, c).await?)?.environment.state)
    }
    async fn wait_started(&self, id: &str, c: &Credentials) -> Result<Environment> {
        // Observe only successful asynchronous operations. Any failed GET exits
        // immediately; retrying failures is the caller's policy, not this loop's.
        // A successful async start may briefly still report stopped, so stopped
        // alone is not terminal here. Conflict re-adoption handles stopped rows.
        for _ in 0..60 {
            let raw = self.call(Method::GET, self.sandbox_url(id, None)?, None, c).await?;
            match text(&raw, "state")? {
                "started" => return Ok(self.environment(raw)?.environment),
                "error" | "build_failed" | "destroyed" | "destroying" => {
                    return Err(refused("Daytona sandbox entered a terminal state before startup"));
                }
                _ => {}
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Err(ProtocolError::unavailable("Daytona sandbox has not started", Some(5)))
    }
}
const GIB: u64 = 1 << 30;
fn endpoint_url(endpoint: &str, trailing_slash: bool) -> Result<Url> {
    let url = Url::parse(endpoint).map_err(|_| refused("invalid Daytona endpoint"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (trailing_slash && !url.path().ends_with('/'))
    {
        return Err(refused("Daytona endpoints must be HTTPS without credentials, query or fragment; configured bases must end in /"));
    }
    Ok(url)
}
// Successful responses can contain reach recipes and guest output. Their
// contents are never diagnostic text, even when validation fails.
fn bad_response() -> ProtocolError {
    ProtocolError::Internal { reason: "incomplete Daytona response".into(), provider_error: "required field missing or invalid".into() }
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(bad_response)
}
fn name(prefix: &str, input: &str) -> String {
    // Keep vendor names below 63 bytes, with 160 bits of digest identity.
    format!("drydock-{prefix}-{}", &format!("{:x}", Sha256::digest(input.as_bytes()))[..40])
}
fn diagnostic_text(bytes: &[u8]) -> String {
    // The host must mask complete credential echoes before limiting diagnostics.
    String::from_utf8_lossy(bytes).into_owned()
}
fn policy_matches(row: &Value, policy: &Value) -> bool {
    // Compare stable requested destinations, never a DNS resolution at retry.
    let set = |key: &str, v: &Value| {
        v.as_str()
            .unwrap_or("")
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| {
                let s = s.trim();
                if key == "domainAllowList" {
                    return s.trim_end_matches('.').to_ascii_lowercase();
                }
                let (ip, bits) = s.split_once('/').unwrap_or((s, "32"));
                match (ip.parse::<std::net::Ipv4Addr>(), bits.parse::<u32>()) {
                    (Ok(ip), Ok(bits)) if bits <= 32 => {
                        let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
                        format!("{}/{}", std::net::Ipv4Addr::from(u32::from(ip) & mask), bits)
                    }
                    _ => s.into(),
                }
            })
            .collect::<BTreeSet<_>>()
    };
    ["networkAllowList", "domainAllowList", "networkBlockAll"].iter().all(|key| {
        if *key == "networkBlockAll" {
            row[*key].as_bool().unwrap_or(false) == policy[*key].as_bool().unwrap_or(false)
        } else {
            set(key, &row[*key]) == set(key, &policy[*key])
        }
    })
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
                            hosts.insert(host.as_str().trim_end_matches('.').to_ascii_lowercase());
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
            usage: true,
            quota: true,
        }
    }
    fn observation(&self) -> ObservationMode {
        ObservationMode::Poll { interval: Duration::from_secs(30) }
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
        if !r
            .image_digest
            .split_once("@sha256:")
            .is_some_and(|(image, digest)| !image.is_empty() && digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(refused("Daytona requires an image reference pinned by sha256 digest"));
        }
        if !r.tools_digest.split_once("@sha256:").is_some_and(|(image, digest)| {
            !image.is_empty()
                && digest.len() == 64
                && digest.bytes().all(|b| b.is_ascii_hexdigit())
                && !image.contains(['\n', '\r', ' ', '\t'])
        }) {
            return Err(refused("Daytona requires a published tools image pinned by sha256 digest"));
        }
        // These references become Dockerfile instructions; refuse extra tokens.
        if r.image_digest.contains(['\n', '\r', ' ', '\t']) {
            return Err(refused("invalid Daytona base image reference"));
        }
        let dockerfile = format!(
            "FROM {} AS drydock_tools\nFROM {}\nCOPY --from=drydock_tools /opt/drydock/ /opt/drydock/\n",
            r.tools_digest, r.image_digest
        );
        validate_size(&r.size)?;
        // CreateSnapshot labels memory/disk "GB", but the resource guide and
        // default snapshot table specify GiB for the resulting sandbox:
        // https://www.daytona.io/docs/en/sandboxes/#resources (checked 2026-10-21).
        // Keep binary units consistent with sandbox readback; decimal conversion
        // would also produce fractions rejected by CreateSnapshot's integer fields.
        let snapshot_name = snapshot_name(&r.image_digest, &r.tools_digest, &r.size);
        let url = self.path(&self.settings.api_url, &["snapshots", &snapshot_name])?;
        let snapshot = match self.call(Method::GET, url, None, c).await {
            Ok(v) => v,
            Err(ProtocolError::NotFound { .. }) => {
                match self
                    .create(
                        self.path(&self.settings.api_url, &["snapshots"])?,
                        json!({"name":snapshot_name,"buildInfo":{"dockerfileContent":dockerfile},"regionId":self.settings.region,"sandboxClass":"container","cpu":r.size.cpus as u64,"memory":r.size.memory_bytes/GIB,"disk":r.size.disk_bytes/GIB}),
                        c,
                    )
                    .await?
                {
                    Some(snapshot) => snapshot,
                    None => self.call(Method::GET, self.path(&self.settings.api_url, &["snapshots", &snapshot_name])?, None, c).await?,
                }
            }
            Err(e) => return Err(e),
        };
        let id = text(&snapshot, "id")?.to_owned();
        let mut snapshot = snapshot;
        let mut activation_submitted = false;
        for _ in 0..120 {
            match text(&snapshot, "state")? {
                "active" => {
                    // SnapshotDto uses `mem` for RAM, unlike CreateSnapshot's `memory`.
                    if number(&snapshot, "cpu")? != r.size.cpus
                        || number(&snapshot, "mem")? != (r.size.memory_bytes / GIB) as f64
                        || number(&snapshot, "disk")? != (r.size.disk_bytes / GIB) as f64
                    {
                        return Err(refused("Daytona snapshot resources do not match the requested size"));
                    }
                    return Ok(Prepared {
                        provider: self.name.clone(),
                        id: snapshot_name,
                        image_digest: r.image_digest,
                        tools_digest: r.tools_digest,
                    });
                }
                "inactive" if !activation_submitted => {
                    // A successful activation response can lag at inactive.
                    // Submit once; all subsequent observations use paced GETs.
                    self.call(Method::POST, self.path(&self.settings.api_url, &["snapshots", &id, "activate"])?, None, c).await?;
                    activation_submitted = true;
                }
                "error" | "build_failed" => return Err(refused("Daytona snapshot build failed")),
                _ => {}
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            snapshot = self.call(Method::GET, self.path(&self.settings.api_url, &["snapshots", &id])?, None, c).await?;
        }
        Err(ProtocolError::unavailable("Daytona snapshot is still building", Some(5)))
    }
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        if r.prepared.provider != self.name {
            return Err(refused("prepared snapshot belongs to another provider"));
        }
        let policy = allowlist(r.egress)?;
        let size = &r.size;
        validate_size(size)?;
        if r.prepared.id != snapshot_name(&r.prepared.image_digest, &r.prepared.tools_digest, size) {
            return Err(refused("Daytona size does not match the prepared snapshot"));
        }
        if let Some(v) = self
            .inventory(Some(&r.label), c)
            .await?
            .into_iter()
            .find(|v| v.pointer("/labels/flotilla.label").and_then(Value::as_str) == Some(&r.label))
        {
            self.check_existing_request(&v, size, &policy)?;
            // Re-adoption returns the observed stopped/error state unchanged;
            // provision does not implicitly resume an existing label.
            let mut row = self.environment(v)?;
            if matches!(row.environment.state, Observation::Running) {
                self.bootstrap(&row.environment.id, c).await?;
                row = self.inspect_after_lifecycle(&row.environment.id, c).await?;
            }
            return Ok(Provisioned::Existing(row));
        }
        let mut body = json!({
            "name":name("environment", &r.label), "snapshot":r.prepared.id, "labels":{"flotilla.label":r.label.clone()},
            "target":self.settings.region,
            "autoStopInterval":0, "autoPauseInterval":0, "autoDeleteInterval":-1, "public":false
        });
        body.as_object_mut().unwrap().extend(policy.as_object().unwrap().clone());
        let created = self.create(self.path(&self.settings.api_url, &["sandbox"])?, body, c).await?;
        let v = match created {
            None => {
                let v = self.call(Method::GET, self.sandbox_url(&name("environment", &r.label), None)?, None, c).await?;
                if v.pointer("/labels/flotilla.label").and_then(Value::as_str) != Some(&r.label) {
                    return Err(refused("Daytona sandbox name belongs to a different label"));
                }
                self.check_existing_request(&v, size, &policy)?;
                let existing = self.environment(v.clone())?;
                if matches!(
                    existing.environment.state,
                    Observation::Stopped { .. } | Observation::Unknown { .. } | Observation::Gone { .. }
                ) {
                    return Ok(Provisioned::Existing(existing));
                }

                let row = self.wait_started(text(&v, "id")?, c).await?;
                self.bootstrap(&row.id, c).await?;
                return Ok(Provisioned::Existing(self.inspect_after_lifecycle(&row.id, c).await?));
            }
            Some(v) => v,
        };
        let row = self.wait_started(text(&v, "id")?, c).await?;
        self.bootstrap(&row.id, c).await?;
        Ok(Provisioned::Created(self.inspect_after_lifecycle(&row.id, c).await?))
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<ObservedEnvironment>> {
        self.inventory(None, c).await?.into_iter().map(|v| self.environment(v)).collect()
    }
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<ObservedEnvironment> {
        self.observed(self.call(Method::GET, self.sandbox_url(id, None)?, None, c).await?, c).await
    }
    async fn inspect_after_lifecycle(&self, id: &str, c: &Credentials) -> Result<ObservedEnvironment> {
        let value = self.call(Method::GET, self.sandbox_url(id, None)?, None, c).await?;
        let fallback = self.environment(value.clone())?;
        match self.observed(value, c).await {
            Ok(row) => Ok(row),
            Err(error) => {
                // This fallback bypasses host error masking: log only its category.
                tracing::warn!(provider = %self.name, environment = %id, error_class = error.class(), "lifecycle succeeded; egress measurement failed");
                Ok(fallback)
            }
        }
    }
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        match self.call(Method::DELETE, self.sandbox_url(id, None)?, None, c).await {
            Ok(_) | Err(ProtocolError::NotFound { .. }) => Ok(()),
            Err(e) => Err(e),
        }
    }
    async fn reach(&self, id: &str, c: &Credentials) -> Result<Connection> {
        let mut url = self.sandbox_url(id, Some("ssh-access"))?;
        url.query_pairs_mut().append_pair("expiresInMinutes", SSH_TOKEN_TTL_MINUTES);
        let v = self.call(Method::POST, url, None, c).await?;
        Ok(Connection::Ssh {
            endpoint: self.settings.ssh_endpoint.clone(),
            user: Secret::new(text(&v, "token")?),
            host_key: self.settings.ssh_host_key.clone(),
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
        // This deterministic continuation marker binds provider and id; it is
        // not an access credential. Every resume still requires the API key.
        for _ in 0..60 {
            if matches!(self.lifecycle_state(id, c).await?, Observation::Stopped { .. }) {
                return Ok(ResumeToken { token: Secret::new(name("resume", &format!("{}\0{id}", self.name))) });
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Err(ProtocolError::unavailable("Daytona sandbox has not stopped", Some(5)))
    }
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()> {
        if token.token.expose() != name("resume", &format!("{}\0{id}", self.name)) {
            return Err(refused("resume token belongs to another environment"));
        }
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
        let command = shell_command(&r.command);
        let output = self.execute(id, &command, 20, c).await?;
        let (client, mut server) = tokio::io::duplex(65536);
        tokio::spawn(async move {
            let _ = server.write_all(output.as_bytes()).await;
        });
        Ok(Box::new(client))
    }
}
#[async_trait]
impl QuotaOperation for Daytona {
    async fn quota(&self, c: &Credentials) -> Result<Quota> {
        let v = self
            .call(Method::GET, self.path(&self.settings.api_url, &["organizations", &self.settings.organization_id, "usage"])?, None, c)
            .await?;
        let mut resources = Vec::new();
        for region in v.get("regionUsage").and_then(Value::as_array).ok_or_else(bad_response)? {
            for (resource, unit, factor, current, total) in [
                (ResourceKind::Cpu, "{vCPU}", 1.0, "currentCpuUsage", "totalCpuQuota"),
                (ResourceKind::Memory, "By", GIB as f64, "currentMemoryUsage", "totalMemoryQuota"),
                (ResourceKind::Disk, "By", GIB as f64, "currentDiskUsage", "totalDiskQuota"),
            ] {
                resources.push(ResourceQuota {
                    key: QuotaKey {
                        region: Some(text(region, "regionId")?.into()),
                        class: Some(text(region, "sandboxClass")?.into()),
                        resource,
                    },
                    unit: unit.into(),
                    in_use: number(region, current)? * factor,
                    limit: Some(number(region, total)? * factor),
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
                in_use: number(&v, current)? * GIB as f64,
                limit: Some(number(&v, total)? * GIB as f64),
            });
        }
        Ok(Quota { resources, credits_remaining: None, credit_unit: None, concurrency_in_use: None, concurrency_limit: None })
    }
}
fn number(v: &Value, key: &str) -> Result<f64> {
    v.get(key).and_then(Value::as_f64).filter(|n| n.is_finite() && *n >= 0.0).ok_or_else(bad_response)
}
#[async_trait]
impl UsageOperation for Daytona {
    async fn usage(&self, period: Period, c: &Credentials) -> Result<Usage> {
        let from_text = String::from(period.start().clone());
        let to_text = String::from(period.end().clone());
        let from = from_text.parse::<chrono::DateTime<chrono::Utc>>().map_err(|_| refused("invalid usage period start"))?;
        let to = to_text.parse::<chrono::DateTime<chrono::Utc>>().map_err(|_| refused("invalid usage period end"))?;
        // Sample once before the reads; ongoing usage conservatively excludes time spent querying analytics.
        let ongoing_end = to.min(chrono::Utc::now());
        let mut url = self.path(&self.settings.analytics_url, &["organization", &self.settings.organization_id, "usage", "aggregated"])?;
        url.query_pairs_mut().append_pair("from", &from_text).append_pair("to", &to_text);
        let v = self.request(Method::GET, url, None, c, false, ResponseFormat::Analytics).await?.ok_or_else(bad_response)?;
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
        .map(|(resource, unit, key, factor)| Ok((resource, Quantity { amount: number(&v, key)? * factor, unit: unit.into() })))
        .collect::<Result<_>>()?;
        // The analytics parser retains the vendor's decimal lexeme;
        // money never passes through f64, including during parsing.
        let price = text(&v, "totalPrice")?.to_owned();
        if !valid_decimal(&price) {
            return Err(bad_response());
        }
        // Analytics prices are denominated in USD; there is no currency field.
        let mut environment_hours = Vec::new();
        let mut sandboxes =
            self.path(&self.settings.analytics_url, &["organization", &self.settings.organization_id, "usage", "sandbox"])?;
        sandboxes.query_pairs_mut().append_pair("from", &from_text).append_pair("to", &to_text);
        let totals = self.call(Method::GET, sandboxes, None, c).await?;
        let mut seen = BTreeSet::new();
        for sandbox in totals.as_array().ok_or_else(bad_response)? {
            let id = text(sandbox, "sandboxId")?;
            if !seen.insert(id) {
                continue;
            }
            let mut url =
                self.path(&self.settings.analytics_url, &["organization", &self.settings.organization_id, "sandbox", id, "usage"])?;
            url.query_pairs_mut().append_pair("from", &from_text).append_pair("to", &to_text);
            let periods = self.call(Method::GET, url, None, c).await?;
            for row in periods.as_array().ok_or_else(bad_response)? {
                let cpus = number(row, "cpu")?;
                // Zero-CPU records contribute no size-hours, even if other
                // optional fields are absent or malformed.
                if cpus == 0.0 {
                    continue;
                }
                let start = text(row, "startAt")?.parse::<chrono::DateTime<chrono::Utc>>().map_err(|_| bad_response())?;
                let end = match row.get("endAt") {
                    None => ongoing_end,
                    Some(value) => {
                        let end = value
                            .as_str()
                            .ok_or_else(bad_response)?
                            .parse::<chrono::DateTime<chrono::Utc>>()
                            .map_err(|_| bad_response())?;
                        if end < start {
                            return Err(bad_response());
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
                let bytes =
                    |key| -> Result<u64> { row.get(key).and_then(Value::as_u64).and_then(|v| v.checked_mul(GIB)).ok_or_else(bad_response) };
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

fn shell_command(command: &[String]) -> String {
    command.iter().map(|s| format!("'{}'", s.replace('\'', "'\\''"))).collect::<Vec<_>>().join(" ")
}

// Parse money as a raw JSON decimal lexeme before any numeric conversion.
// Keeping raw_value local avoids changing serde's flattened event decoding.
fn parse_analytics(bytes: &[u8]) -> Result<Value> {
    let fields: std::collections::BTreeMap<String, Box<serde_json::value::RawValue>> = serde_json::from_slice(bytes)
        .map_err(|_| ProtocolError::Internal { reason: "invalid Daytona analytics".into(), provider_error: diagnostic_text(bytes) })?;
    let mut result = serde_json::Map::new();
    for (key, value) in fields {
        let parsed = if key == "totalPrice" {
            Value::String(decimal_lexeme(value.get()).ok_or_else(|| ProtocolError::Internal {
                reason: "invalid Daytona price".into(),
                provider_error: diagnostic_text(bytes),
            })?)
        } else {
            serde_json::from_str(value.get()).map_err(|_| bad_response())?
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
fn snapshot_name(image: &str, tools: &str, size: &Size) -> String {
    name("snapshot", &format!("{image}\0{tools}\0{}\0{}\0{}", size.cpus as u64, size.memory_bytes, size.disk_bytes))
}
fn validate_size(size: &Size) -> Result<()> {
    if !size.cpus.is_finite()
        || size.cpus.fract() != 0.0
        || !(1.0..=4.0).contains(&size.cpus)
        || size.memory_bytes == 0
        || size.memory_bytes > 8 * GIB
        || !size.memory_bytes.is_multiple_of(GIB)
        || size.disk_bytes == 0
        || size.disk_bytes > 10 * GIB
        || !size.disk_bytes.is_multiple_of(GIB)
    {
        return Err(refused("Daytona container size requires 1..4 whole vCPU, 1..8 GiB RAM, 1..10 GiB disk"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Vendor decimal lexemes retain all digits, beyond binary64's exact range.
    #[test]
    fn exact_vendor_money_and_complete_errors() {
        let v = parse_analytics(br#"{"totalPrice":9007199254740993.00000001,"sandboxCount":1}"#).unwrap();
        assert_eq!(v["totalPrice"], "9007199254740993.00000001");
        assert_eq!(diagnostic_text(&vec![b'x'; 20000]).len(), 20000);
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

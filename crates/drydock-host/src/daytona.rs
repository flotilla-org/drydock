//! Stateless Daytona REST translator. The host owns inventory, event diffs and retries.
//! API contract: https://www.daytona.io/docs/openapi.json (2026-10-20).
use crate::module::*;
use async_trait::async_trait;
use drydock_protocol::*;
use reqwest::{Method, Url};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::AsyncWriteExt;

pub struct DaytonaModule;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    organization_id: String,
    /// Pinned out of band: the REST API supplies no gateway host public key.
    ssh_host_key: String,
    #[serde(default = "api_url")]
    api_url: String,
    #[serde(default = "toolbox_url")]
    toolbox_url: String,
    #[serde(default = "ssh_endpoint")]
    ssh_endpoint: String,
    #[serde(default = "region")]
    region: String,
    #[serde(default = "tier")]
    tier: u8,
    /// Fixed image contract, shared by every sandbox; no per-vessel arguments.
    agent_command: String,
    #[serde(default = "analytics_url")]
    analytics_url: String,
    /// Operator-supplied conformance command, executed as root. No declaration
    /// alone upgrades the claim: every returned sandbox is probed again.
    #[serde(default)]
    egress_probe: Option<ExecRequest>,
}
fn analytics_url() -> String {
    "https://analytics.app.daytona.io/".into()
}
fn api_url() -> String {
    "https://app.daytona.io/api/".into()
}
fn toolbox_url() -> String {
    "https://proxy.app.daytona.io/toolbox/".into()
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
            || settings.agent_command.is_empty()
            || settings.region.is_empty()
        {
            return Err(refused("Daytona requires organization_id, ssh_host_key, agent_command, region and tier 1..4"));
        }
        for endpoint in [&settings.api_url, &settings.toolbox_url, &settings.analytics_url] {
            let url = Url::parse(endpoint).map_err(|_| refused("invalid Daytona endpoint"))?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || !url.path().ends_with('/')
            {
                return Err(refused("Daytona endpoints must be HTTPS base URLs ending in / without credentials, query or fragment"));
            }
        }
        Ok(Arc::new(Daytona {
            name: config.name.clone(),
            settings,
            http,
            rates: Mutex::new(Vec::new()),
            creation: tokio::sync::Mutex::new(()),
        }))
    }
}
/// A vendor response's organization-scoped counters. Exposed for diagnostics;
/// tokens and response bodies are never retained or traced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateWindow {
    pub bucket: String,
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    pub reset: Option<u64>,
}
pub struct Daytona {
    name: String,
    settings: Settings,
    http: Arc<dyn HttpClient>,
    rates: Mutex<Vec<RateWindow>>,
    // Serialize only look-up/create/bootstrap, to make concurrent label retries
    // within this provider atomic. Deterministic names cover independent hosts.
    creation: tokio::sync::Mutex<()>,
}
impl Daytona {
    pub fn rate_windows(&self) -> Vec<RateWindow> {
        self.rates.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
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
        let token = c.token().ok_or_else(|| ProtocolError::CredentialRejected { reason: "Daytona API key not delivered".into() })?;
        let mut request = reqwest::Request::new(method, url);
        let mut auth = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.expose()))
            .map_err(|_| refused("invalid Daytona API key header"))?;
        auth.set_sensitive(true);
        request.headers_mut().insert(reqwest::header::AUTHORIZATION, auth);
        if let Some(body) = body {
            request.headers_mut().insert(reqwest::header::CONTENT_TYPE, reqwest::header::HeaderValue::from_static("application/json"));
            *request.body_mut() = Some(body.to_string().into());
        }
        let response = rigging_http_client::http_execute!(self.http, request)
            .map_err(|_| ProtocolError::Unavailable { reason: "Daytona transport failed".into(), retry_after: None })?;
        let mut windows = Vec::new();
        for bucket in ["authenticated", "sandbox-create", "sandbox-lifecycle"] {
            let get = |field| {
                response.headers().get(format!("x-ratelimit-{field}-{bucket}")).and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok())
            };
            let row = RateWindow { bucket: bucket.into(), limit: get("limit"), remaining: get("remaining"), reset: get("reset") };
            if row.limit.is_some() || row.remaining.is_some() || row.reset.is_some() {
                windows.push(row);
            }
        }
        if !windows.is_empty() {
            *self.rates.lock().unwrap_or_else(|e| e.into_inner()) = windows;
        }
        let retry_after = response.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            // Never echo an untrusted provider body: it may contain an SSH token
            // or the API key. No SDK retry is involved.
            return Err(match status {
                401 | 403 => ProtocolError::CredentialRejected { reason: "Daytona rejected the credential or account permission".into() },
                404 => ProtocolError::NotFound { reason: "Daytona resource not found".into() },
                402 => ProtocolError::QuotaExhausted { reason: "Daytona quota exhausted".into() },
                429 => ProtocolError::RateLimited { reason: "Daytona organization rate limit".into(), retry_after },
                400 | 409 | 422 => refused(format!("Daytona refused request (HTTP {status})")),
                500..=599 => ProtocolError::Unavailable { reason: "Daytona API unavailable".into(), retry_after },
                _ => ProtocolError::Internal {
                    reason: format!("unexpected Daytona HTTP {status}"),
                    provider_error: Secret::new("response withheld"),
                },
            });
        }
        if response.body().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(response.body()).map_err(|_| ProtocolError::Internal {
            reason: "invalid Daytona response".into(),
            provider_error: Secret::new("response withheld"),
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
            "stopped" | "archived" => Observation::Stopped { cause: StopCause::SuspendedByRequest },
            "paused" => Observation::Stopped { cause: StopCause::PausedByProvider },
            "destroyed" if v.get("spotEvictedAt").and_then(Value::as_str).is_some() => {
                Observation::Gone { cause: GoneCause::EvictedByProvider }
            }
            "destroyed" => Observation::Gone { cause: GoneCause::GuestPoweredOff },
            "error" | "build_failed" => match v.get("errorReason").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase().as_str() {
                reason if reason.contains("out of memory") || reason.contains("oom") => {
                    Observation::Gone { cause: GoneCause::HostOutOfMemory }
                }
                reason if reason.contains("evict") => Observation::Gone { cause: GoneCause::EvictedByProvider },
                reason if reason.contains("unreachable") => Observation::Unknown { reason: UnknownReason::HostUnreachable },
                _ => Observation::Unknown { reason: UnknownReason::ProviderApiError },
            },
            _ => Observation::Unknown { reason: UnknownReason::ProviderApiError },
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
        Ok(ObservedEnvironment {
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
    async fn observed(&self, v: Value, c: &Credentials) -> Result<ObservedEnvironment> {
        let restricted = v.get("networkAllowList").and_then(Value::as_str).is_some_and(|v| !v.is_empty() && v != "0.0.0.0/0");
        let mut row = self.environment(v)?;
        if restricted
            && matches!(row.environment.state, Observation::Running)
            && let Some(probe) = &self.settings.egress_probe
        {
            let command = format!("test \"$(id -u)\" = 0 && {}", shell_command(&probe.command));
            let output = self.execute(&row.environment.id, &command, c).await?;
            let result: Value = serde_json::from_str(&output).map_err(|_| refused("invalid root egress probe output"))?;
            if result == json!({"uid":0,"listed_direct":true,"unlisted_canary":false,"raw_dns":false}) {
                row.environment.egress = Enforcement::Enforced;
            }
        }
        Ok(row)
    }
    async fn execute(&self, id: &str, command: &str, c: &Credentials) -> Result<String> {
        let url = self.path(&self.settings.toolbox_url, &[id, "process", "execute"])?;
        let v = self.call(Method::POST, url, Some(json!({"command": command, "timeout": 10})), c).await?;
        if v.get("exitCode").and_then(Value::as_i64) != Some(0) {
            return Err(ProtocolError::Unavailable { reason: "Daytona guest command failed".into(), retry_after: None });
        }
        Ok(text(&v, "result")?.into())
    }
    async fn bootstrap(&self, id: &str, c: &Credentials) -> Result<()> {
        let start = format!(
            "test -S /run/drydock/agent.sock || (nohup {} </dev/null >/tmp/drydock-agent.log 2>&1 &); for i in 1 2 3 4 5; do test -S /run/drydock/agent.sock && exit 0; sleep 1; done; exit 1",
            self.settings.agent_command
        );
        let command =
            format!("mkdir -p /run/drydock && flock --close --wait 8 /run/drydock/bootstrap.lock sh -c {}", shell_command(&[start]));
        self.execute(id, &command, c).await?;
        Ok(())
    }
    async fn wait_started(&self, id: &str, c: &Credentials) -> Result<Environment> {
        // Observe an asynchronous operation, never retry a failed vendor request.
        for _ in 0..60 {
            let row = self.inspect(id, c).await?.environment;
            if matches!(row.state, Observation::Running) {
                return Ok(row);
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Err(ProtocolError::Unavailable { reason: "Daytona sandbox has not started".into(), retry_after: Some(5) })
    }
}
const GIB: u64 = 1 << 30;
fn bad_response() -> ProtocolError {
    ProtocolError::Internal { reason: "incomplete Daytona response".into(), provider_error: Secret::new("response withheld") }
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(bad_response)
}
fn name(prefix: &str, input: &str) -> String {
    // Keep vendor names below 63 bytes, with 160 bits of digest identity.
    format!("drydock-{prefix}-{}", &format!("{:x}", Sha256::digest(input.as_bytes()))[..40])
}
async fn allowlist(request: EgressRequest) -> Result<(String, bool)> {
    match request {
        EgressRequest::Open => Ok(("0.0.0.0/0".into(), false)),
        EgressRequest::DenyAll { direct } => {
            let mut cidrs = BTreeSet::new();
            for entry in direct {
                match entry {
                    Destination::HostPort { .. } => return Err(refused("Daytona CIDR rules cannot restrict ports")),
                    Destination::Cidr { cidr } => {
                        if cidr.as_str().contains(':') {
                            return Err(refused("Daytona does not support IPv6 egress rules"));
                        }
                        cidrs.insert(cidr.as_str().to_owned());
                    }
                    Destination::Host { host } => {
                        // Resolution is pinned at provision; no background DNS
                        // reconciliation can silently widen a running policy.
                        let addresses = tokio::net::lookup_host((host.as_str(), 0))
                            .await
                            .map_err(|_| refused("Daytona destination DNS resolution failed"))?;
                        let mut found = false;
                        for address in addresses {
                            if !address.is_ipv4() {
                                return Err(refused("Daytona destination resolves to IPv6"));
                            }
                            found = true;
                            cidrs.insert(format!("{}/32", address.ip()));
                        }
                        if !found {
                            return Err(refused("Daytona destination has no addresses"));
                        }
                    }
                }
            }
            let blocked = cidrs.is_empty();
            Ok((cidrs.into_iter().collect::<Vec<_>>().join(","), blocked))
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
                enforcement: if self.settings.egress_probe.is_some() { Enforcement::Enforced } else { Enforcement::Advisory },
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
        let snapshot_name = name("snapshot", &format!("{}\0{}", r.image_digest, r.tools_digest));
        let url = self.path(&self.settings.api_url, &["snapshots", &snapshot_name])?;
        let snapshot = match self.call(Method::GET, url, None, c).await {
            Ok(v) => v,
            Err(ProtocolError::NotFound { .. }) => {
                match self.call(
                    Method::POST,
                    self.path(&self.settings.api_url, &["snapshots"])?,
                    Some(json!({"name":snapshot_name,"imageName":r.image_digest,"regionId":self.settings.region,"sandboxClass":"container"})), c,
                ).await {
                    Err(ProtocolError::Refused { reason }) if reason == "Daytona refused request (HTTP 409)" =>
                        self.call(Method::GET, self.path(&self.settings.api_url, &["snapshots", &snapshot_name])?, None, c).await?,
                    result => result?,
                }
            }
            Err(e) => return Err(e),
        };
        let id = text(&snapshot, "id")?.to_owned();
        let mut snapshot = snapshot;
        for _ in 0..120 {
            match text(&snapshot, "state")? {
                "active" => {
                    return Ok(Prepared {
                        provider: self.name.clone(),
                        id: snapshot_name,
                        image_digest: r.image_digest,
                        tools_digest: r.tools_digest,
                    });
                }
                "inactive" => {
                    snapshot =
                        self.call(Method::POST, self.path(&self.settings.api_url, &["snapshots", &id, "activate"])?, None, c).await?;
                    continue;
                }
                "error" | "build_failed" => return Err(refused("Daytona snapshot build failed")),
                _ => {}
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            snapshot = self.call(Method::GET, self.path(&self.settings.api_url, &["snapshots", &id])?, None, c).await?;
        }
        Err(ProtocolError::Unavailable { reason: "Daytona snapshot is still building".into(), retry_after: Some(5) })
    }
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        if r.prepared.provider != self.name {
            return Err(refused("prepared snapshot belongs to another provider"));
        }
        let (allow, block) = allowlist(r.egress).await?;
        let size = &r.size;
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
        let _guard = self.creation.lock().await;
        if let Some(v) = self
            .inventory(Some(&r.label), c)
            .await?
            .into_iter()
            .find(|v| v.pointer("/labels/flotilla.label").and_then(Value::as_str) == Some(&r.label))
        {
            let row = self.observed(v, c).await?.environment;
            if matches!(row.state, Observation::Running) {
                self.bootstrap(&row.id, c).await?;
            }
            return Ok(Provisioned::Existing(row));
        }
        let created = self.call(Method::POST, self.path(&self.settings.api_url, &["sandbox"])?, Some(json!({
            "name":name("environment", &r.label), "snapshot":r.prepared.id, "labels":{"flotilla.label":r.label.clone()},
            "target":self.settings.region, "cpu":size.cpus as u64, "memory":size.memory_bytes/GIB, "disk":size.disk_bytes/GIB,
            "networkAllowList":allow, "networkBlockAll":block, "autoStopInterval":0, "autoPauseInterval":0, "autoDeleteInterval":-1, "public":false
        })), c).await;
        let v = match created {
            Err(ProtocolError::Refused { reason }) if reason == "Daytona refused request (HTTP 409)" => {
                let v = self.call(Method::GET, self.sandbox_url(&name("environment", &r.label), None)?, None, c).await?;
                if v.pointer("/labels/flotilla.label").and_then(Value::as_str) != Some(&r.label) {
                    return Err(refused("Daytona sandbox name belongs to a different label"));
                }
                let row = self.wait_started(text(&v, "id")?, c).await?;
                self.bootstrap(&row.id, c).await?;
                return Ok(Provisioned::Existing(row));
            }
            result => result?,
        };
        let row = self.wait_started(text(&v, "id")?, c).await?;
        self.bootstrap(&row.id, c).await?;
        Ok(Provisioned::Created(row))
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<ObservedEnvironment>> {
        let mut rows = Vec::new();
        for v in self.inventory(None, c).await? {
            rows.push(self.observed(v, c).await?);
        }
        Ok(rows)
    }
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<ObservedEnvironment> {
        self.observed(self.call(Method::GET, self.sandbox_url(id, None)?, None, c).await?, c).await
    }
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        match self.call(Method::DELETE, self.sandbox_url(id, None)?, None, c).await {
            Ok(_) | Err(ProtocolError::NotFound { .. }) => Ok(()),
            Err(e) => Err(e),
        }
    }
    async fn reach(&self, id: &str, c: &Credentials) -> Result<Connection> {
        let mut url = self.sandbox_url(id, Some("ssh-access"))?;
        url.query_pairs_mut().append_pair("expiresInMinutes", "5");
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
        if !matches!(self.inspect(id, c).await?.environment.state, Observation::Stopped { .. }) {
            self.call(Method::POST, self.sandbox_url(id, Some("stop"))?, None, c).await?;
        }
        for _ in 0..60 {
            if matches!(self.inspect(id, c).await?.environment.state, Observation::Stopped { .. }) {
                return Ok(ResumeToken { token: Secret::new(name("resume", &format!("{}\0{id}", self.name))) });
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Err(ProtocolError::Unavailable { reason: "Daytona sandbox has not stopped".into(), retry_after: Some(5) })
    }
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()> {
        if token.token.expose() != name("resume", &format!("{}\0{id}", self.name)) {
            return Err(refused("resume token belongs to another environment"));
        }
        if matches!(self.inspect(id, c).await?.environment.state, Observation::Running) {
            return self.bootstrap(id, c).await;
        }
        self.call(Method::POST, self.sandbox_url(id, Some("start"))?, None, c).await?;
        self.wait_started(id, c).await?;
        self.execute(id, "rm -f /run/drydock/agent.sock", c).await?;
        self.bootstrap(id, c).await
    }
}
#[async_trait]
impl Exec for Daytona {
    async fn exec(&self, id: &str, r: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        let command = shell_command(&r.command);
        let output = self.execute(id, &command, c).await?;
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
            let prefix = format!("{}/{}", text(region, "regionId")?, text(region, "sandboxClass")?);
            for (resource, unit, current, total) in [
                ("cpu", "vCPU", "currentCpuUsage", "totalCpuQuota"),
                ("memory", "GiB", "currentMemoryUsage", "totalMemoryQuota"),
                ("disk", "GiB", "currentDiskUsage", "totalDiskQuota"),
            ] {
                resources.push(ResourceQuota {
                    resource: format!("{prefix}/{resource}"),
                    unit: unit.into(),
                    in_use: number(region, current)?,
                    limit: number(region, total)?,
                });
            }
        }
        for (resource, current, total) in
            [("snapshots", "currentSnapshotUsage", "totalSnapshotQuota"), ("volumes", "currentVolumeUsage", "totalVolumeQuota")]
        {
            resources.push(ResourceQuota {
                resource: resource.into(),
                unit: "GiB".into(),
                in_use: number(&v, current)?,
                limit: number(&v, total)?,
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
        let mut url = self.path(&self.settings.analytics_url, &["organization", &self.settings.organization_id, "usage", "aggregated"])?;
        url.query_pairs_mut()
            .append_pair("from", &String::from(period.start().clone()))
            .append_pair("to", &String::from(period.end().clone()));
        let v = self.call(Method::GET, url, None, c).await?;
        let integer = |key| v.get(key).and_then(Value::as_u64).ok_or_else(bad_response);
        let totals = UsageTotals {
            cpu_seconds: integer("totalCPUSeconds")?,
            memory_gib_seconds: integer("totalRAMGBSeconds")?,
            disk_gib_seconds: integer("totalDiskGBSeconds")?,
            gpu_seconds: integer("totalGPUSeconds")?,
            cost_usd: number(&v, "totalPrice")?,
            environments: integer("sandboxCount")?,
        };
        Ok(Usage { period, environment_hours: vec![], totals: Some(totals) })
    }
}

fn shell_command(command: &[String]) -> String {
    command.iter().map(|s| format!("'{}'", s.replace('\'', "'\\''"))).collect::<Vec<_>>().join(" ")
}

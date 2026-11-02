//! Stateless Tensorlake translator: Firecracker sandboxes from images the
//! Image Service builds, reached through Tensorlake's TCP tunnel to the
//! agent's token-gated TCP listener. The host owns inventory and retries.
//! API contract: https://docs.tensorlake.ai/api-reference/openapi.yaml for
//! sandboxes and the guest plane; the Image Service, snapshots and usage
//! follow the Apache-licensed SDK (github.com/tensorlakeai/tensorlake,
//! crates/cloud-sdk, 2026-10-29), which documents them in code alone.
use crate::{module::*, oci::ImageRef};
use async_trait::async_trait;
use drydock_protocol::*;
use drydock_transport::{
    tcp::{self, Token},
    websocket::{self, DialError, TlsDialer, WebSocketDialer, tungstenite::http::HeaderMap},
};
use reqwest::{Method, Url};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;
/// Tensorlake's tunnel proxy drops a connection carrying a larger frame.
const TUNNEL_FRAME: usize = 64 << 10;
/// Sandbox disks are 10 to 100 GiB; images are built at the smallest.
const DISK_MB: std::ops::RangeInclusive<u64> = 10_240..=102_400;
/// RAM per vCPU.
const MEMORY_MB_PER_CPU: std::ops::RangeInclusive<u64> = 1024..=8192;
const TOKEN_FILE: &str = "/run/drydock/tcp.token";
const TOKEN_LINE: &str = "drydock-tcp-token ";
/// The Image Service has no rate limits on record; the SDK polls every 3 s.
/// The daemon gives prepare 600 s, so a build still running after about
/// 7.5 minutes is Unavailable: the retried prepare rejoins it (409
/// `image_build_in_progress`) rather than starting another.
const BUILD_POLL: Duration = Duration::from_secs(3);
const BUILD_POLLS: u32 = 150;
const STATE_POLL: Duration = Duration::from_secs(1);
const STATE_POLLS: u32 = 120;
/// Guest commands must finish inside the host's 30-second HTTP deadline.
const RUN_TIMEOUT_SECS: u64 = 25;
/// How much of a failed bootstrap's output its error carries.
const OUTPUT_CAUSE_CHARS: usize = 500;

/// The module, with the WebSocket dialer its tunnels use: TLS in production,
/// an in-process stand-in in tests.
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
    /// Usage is read per organization; without it the usage port is absent.
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default = "api_url")]
    api_url: String,
    #[serde(default = "sandbox_domain")]
    sandbox_domain: String,
    /// The guest port the agent's TCP listener binds on loopback.
    #[serde(default = "tunnel_port")]
    tunnel_port: u16,
    /// The plan's per-sandbox limits: 4 vCPU and 16 GiB on Usage Credits.
    #[serde(default = "max_cpus")]
    max_cpus: u32,
    #[serde(default = "max_memory")]
    max_memory: ByteQuantity,
    /// Operator-supplied egress conformance command, run as root; see Daytona's.
    #[serde(default)]
    egress_probe: Option<ExecRequest>,
}
fn api_url() -> String {
    "https://api.tensorlake.ai/".into()
}
fn sandbox_domain() -> String {
    "sandbox.tensorlake.ai".into()
}
fn tunnel_port() -> u16 {
    7811
}
fn max_cpus() -> u32 {
    4
}
fn max_memory() -> ByteQuantity {
    ByteQuantity(16 * GIB)
}
/// Bytes, or a whole number of MiB or GiB such as "16GiB".
struct ByteQuantity(u64);
impl<'de> Deserialize<'de> for ByteQuantity {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Bytes(u64),
            Text(String),
        }
        let invalid = || serde::de::Error::custom("expected bytes, or a whole number of MiB or GiB");
        match Raw::deserialize(d)? {
            Raw::Bytes(bytes) => Ok(Self(bytes)),
            Raw::Text(text) => {
                let (number, unit) = match (text.strip_suffix("GiB"), text.strip_suffix("MiB")) {
                    (Some(n), _) => (n, GIB),
                    (_, Some(n)) => (n, MIB),
                    _ => (text.as_str(), 1),
                };
                number.trim().parse::<u64>().ok().and_then(|n| n.checked_mul(unit)).map(Self).ok_or_else(invalid)
            }
        }
    }
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
            serde_json::from_value(json!(config.settings)).map_err(|e| refused(format!("invalid Tensorlake settings: {e}")))?;
        let api = Url::parse(&settings.api_url).ok().filter(|u| u.scheme() == "https" && u.host_str().is_some() && u.query().is_none());
        if api.is_none()
            || settings.organization_id.as_deref().is_some_and(str::is_empty)
            || settings.max_cpus == 0
            || settings.max_memory.0 < GIB
            || settings.tunnel_port == 0
            || !settings.sandbox_domain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            || settings.sandbox_domain.is_empty()
        {
            return Err(refused(
                "Tensorlake requires an HTTPS api_url, a sandbox_domain host name, a tunnel port, and positive max_cpus and max_memory",
            ));
        }
        Ok(Arc::new(Tensorlake { name: name.to_owned(), settings, http, dialer: self.dialer.clone(), tokens: Mutex::default() }))
    }
}

pub struct Tensorlake {
    name: String,
    settings: Settings,
    http: Arc<dyn HttpClient>,
    dialer: Arc<dyn WebSocketDialer>,
    /// Each sandbox's agent TCP token, as read back at its bootstrap. A cache
    /// only: a missing or stale entry is read from the guest again.
    tokens: Mutex<HashMap<String, Token>>,
}

enum Body {
    Json(Value),
    Bytes(Vec<u8>),
}

/// The most of a refusal's text kept in an error, so a proxy's HTML page
/// does not fill one.
const EXPLANATION_CHARS: usize = 500;
/// The text of a refusal: a guest-plane or Image Service JSON `error` or
/// `message`, else the control plane's plain text, cut to its start.
fn explanation(body: &[u8]) -> String {
    let text = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("error").or_else(|| v.get("message")).and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| String::from_utf8_lossy(body).trim().to_owned());
    match text.char_indices().nth(EXPLANATION_CHARS) {
        Some((cut, _)) => format!("{}…", &text[..cut]),
        None => text,
    }
}
/// The status's protocol error. Plan limits arrive as 400 text: a project
/// at its quota or capacity is QuotaExhausted, any other 400 a refusal.
fn failure(operation: &str, status: u16, body: &[u8], retry_after: Option<u64>) -> ProtocolError {
    let text = explanation(body);
    let reason = format!("Tensorlake {operation} HTTP {status}: {text}");
    let lower = text.to_ascii_lowercase();
    match status {
        400 if lower.contains("quota") || lower.contains("capacity") => ProtocolError::QuotaExhausted { reason },
        400 | 409 | 422 => ProtocolError::Refused { reason },
        401 => ProtocolError::CredentialRejected { reason },
        403 => ProtocolError::Refused { reason: format!("permission denied; {reason}") },
        404 => ProtocolError::NotFound { reason },
        429 => ProtocolError::RateLimited { reason, retry_after },
        408 | 500..=599 => ProtocolError::Unavailable { reason, retry_after, provider_error: None },
        _ => ProtocolError::Internal { reason: format!("unexpected Tensorlake {operation} HTTP {status}"), provider_error: text },
    }
}
fn bad_response() -> ProtocolError {
    ProtocolError::Internal { reason: "incomplete Tensorlake response".into(), provider_error: "required field missing or invalid".into() }
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(bad_response)
}
fn digest(input: &str) -> String {
    format!("{:x}", Sha256::digest(input.as_bytes()))
}
fn platform() -> Platform {
    Platform::new("linux", "amd64")
}

impl Tensorlake {
    fn api(&self, segments: &[&str]) -> Result<Url> {
        let mut url = Url::parse(&self.settings.api_url).map_err(|_| refused("invalid Tensorlake api_url"))?;
        url.path_segments_mut().map_err(|_| refused("invalid Tensorlake api_url"))?.pop_if_empty().extend(segments);
        Ok(url)
    }
    /// A sandbox's management plane, addressed by its name.
    fn guest(&self, id: &str, segments: &[&str]) -> Result<Url> {
        if !name_valid(id) {
            return Err(ProtocolError::NotFound { reason: "not a Tensorlake sandbox name".into() });
        }
        let mut url = Url::parse(&format!("https://{id}.{}/api/v1", self.settings.sandbox_domain)).map_err(|_| bad_response())?;
        url.path_segments_mut().map_err(|_| bad_response())?.extend(segments);
        Ok(url)
    }
    fn key<'c>(&self, c: &'c Credentials) -> Result<&'c Secret> {
        c.token().ok_or_else(|| ProtocolError::CredentialRejected { reason: "Tensorlake API key not delivered".into() })
    }
    /// One request with the key, whatever its status. `bearer` is false only
    /// for presigned upload URLs, which carry their own authorization.
    async fn send(
        &self,
        method: Method,
        url: Url,
        body: Option<Body>,
        c: &Credentials,
        bearer: bool,
    ) -> Result<http::Response<bytes::Bytes>> {
        self.send_with(method, url, body, c, bearer, reqwest::header::HeaderMap::new()).await
    }
    /// [`Self::send`], with `extra` headers such as an idempotency key.
    async fn send_with(
        &self,
        method: Method,
        url: Url,
        body: Option<Body>,
        c: &Credentials,
        bearer: bool,
        extra: reqwest::header::HeaderMap,
    ) -> Result<http::Response<bytes::Bytes>> {
        let operation = format!("{method} {}", url.path());
        let mut request = reqwest::Request::new(method, url);
        let headers = request.headers_mut();
        headers.extend(extra);
        if bearer {
            let mut auth = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", self.key(c)?.expose()))
                .map_err(|_| refused("invalid Tensorlake API key header"))?;
            auth.set_sensitive(true);
            headers.insert(reqwest::header::AUTHORIZATION, auth);
        }
        match body {
            Some(Body::Json(value)) => {
                headers.insert(reqwest::header::CONTENT_TYPE, reqwest::header::HeaderValue::from_static("application/json"));
                *request.body_mut() = Some(value.to_string().into());
            }
            Some(Body::Bytes(bytes)) => {
                headers.insert(reqwest::header::CONTENT_TYPE, reqwest::header::HeaderValue::from_static("application/octet-stream"));
                *request.body_mut() = Some(bytes.into());
            }
            None => {}
        }
        rigging_http_client::http_execute!(self.http, request).map_err(|error| ProtocolError::Unavailable {
            provider_error: Some(error),
            reason: format!("Tensorlake {operation} transport failed"),
            retry_after: None,
        })
    }
    /// The JSON of a 2xx answer (Null when empty); any other status as its error.
    fn answer(operation: &str, response: &http::Response<bytes::Bytes>) -> Result<Value> {
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            let retry_after = response.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
            return Err(failure(operation, status, response.body(), retry_after));
        }
        if response.body().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(response.body()).map_err(|_| bad_response())
    }
    async fn call(&self, method: Method, url: Url, body: Option<Value>, c: &Credentials) -> Result<Value> {
        let operation = format!("{method} {}", url.path());
        let response = self.send(method, url, body.map(Body::Json), c, true).await?;
        Self::answer(&operation, &response)
    }
    /// Every row of a cursor-paged list. The OpenAPI document names the cursor
    /// `next_cursor`, the SDK `cursor`; either is followed, never twice.
    async fn paged(&self, segments: &[&str], rows: &str, c: &Credentials) -> Result<Vec<Value>> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen = BTreeSet::new();
        loop {
            let mut url = self.api(segments)?;
            url.query_pairs_mut().append_pair("limit", "100");
            if let Some(cursor) = &cursor {
                url.query_pairs_mut().append_pair("cursor", cursor);
            }
            let page = self.call(Method::GET, url, None, c).await?;
            all.extend(page.get(rows).and_then(Value::as_array).ok_or_else(bad_response)?.iter().cloned());
            let next = ["next_cursor", "cursor"].iter().find_map(|k| page.get(*k).and_then(Value::as_str).filter(|s| !s.is_empty()));
            match next {
                None => return Ok(all),
                Some(next) if seen.insert(next.to_owned()) => cursor = Some(next.to_owned()),
                Some(_) => return Err(bad_response()),
            }
        }
    }
    async fn sandbox(&self, id: &str, c: &Credentials) -> Result<Value> {
        self.call(Method::GET, self.api(&["sandboxes", id])?, None, c).await
    }
    /// A terminated sandbox's record, kept by Tensorlake for 48 hours. It is
    /// read directly; only when that lookup does not know the name (the
    /// SDK addresses archived records by id) is the archive listed.
    async fn archived(&self, id: &str, c: &Credentials) -> Result<Option<Value>> {
        match self.call(Method::GET, self.api(&["archived-sandboxes", id])?, None, c).await {
            Ok(row) => return Ok(Some(row)),
            Err(ProtocolError::NotFound { .. }) => {}
            Err(error) => return Err(error),
        }
        let rows = self.paged(&["archived-sandboxes"], "sandboxes", c).await?;
        Ok(rows.into_iter().find(|row| row.get("name").and_then(Value::as_str) == Some(id)))
    }
    /// The snapshots `sandbox_id` left: its own list, or, where Tensorlake no
    /// longer serves that, the project's filtered to it.
    async fn snapshots(&self, sandbox_id: &str, c: &Credentials) -> Result<Vec<Value>> {
        let rows = match self.paged(&["sandboxes", sandbox_id, "snapshots"], "snapshots", c).await {
            Ok(rows) => rows,
            Err(ProtocolError::NotFound { .. }) => self.paged(&["snapshots"], "snapshots", c).await?,
            Err(error) => return Err(error),
        };
        Ok(rows.into_iter().filter(|s| s.get("sandbox_id").and_then(Value::as_str) == Some(sandbox_id)).collect())
    }

    fn environment(&self, v: &Value) -> Result<Environment> {
        Ok(self.environment_and_policy(v)?.0)
    }
    fn environment_and_policy(&self, v: &Value) -> Result<(Environment, Policy)> {
        let id = text(v, "name")?.to_owned();
        let state = match text(v, "status")? {
            "pending" => Observation::Transitioning { phase: TransitionPhase::Starting },
            "running" => Observation::Running,
            "snapshotting" => Observation::Transitioning { phase: TransitionPhase::Reconfiguring },
            "suspending" => Observation::Transitioning { phase: TransitionPhase::Stopping },
            "suspended" => Observation::Stopped { cause: StopCause::SuspendedByRequest },
            "terminated" => Observation::Gone { cause: GoneCause::DestroyedAtProvider },
            "resume_failed" => Observation::Unknown { reason: UnknownReason::ProviderApiError },
            _ => Observation::Unknown { reason: UnknownReason::ProviderStateUnknown },
        };
        let resources = v.get("resources").ok_or_else(bad_response)?;
        let number = |key| resources.get(key).and_then(Value::as_f64).filter(|n| n.is_finite() && *n > 0.0);
        let granted_size = match (number("cpus"), number("memory_mb"), number("disk_mb")) {
            (Some(cpus), Some(memory), Some(disk)) => Some(Size { cpus, memory_bytes: memory as u64 * MIB, disk_bytes: disk as u64 * MIB }),
            _ => None,
        };
        let policy = Policy::read(v.get("network_policy"))?;
        let environment = Environment {
            label: label_of(&sandbox_prefix(&self.name), &id),
            id,
            provider: self.name.clone(),
            state,
            granted_size,
            egress: Enforcement::Enforced,
            platform: Some(platform()),
            egress_measured: false,
            egress_policy: Some(policy.fingerprint()),
            timestamp: None,
        };
        Ok((environment, policy))
    }
    /// The environment, with its egress claim measured when a probe is
    /// configured and the sandbox runs under a restricted policy.
    async fn observed(&self, v: &Value, c: &Credentials) -> Result<Environment> {
        let (mut row, policy) = self.environment_and_policy(v)?;
        let (Some(probe), Some(policy), Observation::Running) = (&self.settings.egress_probe, &policy.0, &row.state) else {
            return Ok(row);
        };
        let deny_all = policy.allow_out.is_empty();
        let script = format!("test \"$(id -u)\" = 0 && DRYDOCK_PROBE_DENY_ALL={} {}", u8::from(deny_all), shell_command(&probe.command));
        let proof = match self.run(&row.id, &script, BTreeMap::new(), c).await.and_then(Run::success) {
            Ok(output) => serde_json::from_str::<Value>(&output.stdout()).unwrap_or(Value::Null),
            Err(error) => {
                tracing::warn!(provider = %self.name, environment = %row.id, error_class = error.class(), "egress measurement failed");
                return Ok(row);
            }
        };
        let confined = proof["uid"] == 0
            && proof["unlisted_canary"] == false
            && proof["raw_dns"] == false
            && (deny_all || proof["listed_direct"] == true);
        row.egress = if confined { Enforcement::Enforced } else { Enforcement::Advisory };
        row.egress_measured = true;
        Ok(row)
    }

    /// Runs `sh -c script` in the guest as root, stdin closed. Tensorlake
    /// streams its output as server-sent events of UTF-8 lines (other bytes
    /// arrive replaced), then its exit status.
    /// (`POST /processes` echoes args unescaped in its 201 answer; this
    /// endpoint streams events instead, so any args are safe here.)
    async fn run(&self, id: &str, script: &str, env: BTreeMap<&str, String>, c: &Credentials) -> Result<Run> {
        let body = json!({"command":"sh","args":["-c",script],"user":"root","env":env,"timeout":RUN_TIMEOUT_SECS});
        let url = self.guest(id, &["processes", "run"])?;
        let operation = format!("POST {}", url.path());
        let response = self.send(Method::POST, url, Some(Body::Json(body)), c, true).await?;
        if !response.status().is_success() {
            return Err(failure(&operation, response.status().as_u16(), response.body(), None));
        }
        let mut run = Run::default();
        for line in String::from_utf8_lossy(response.body()).lines() {
            let Some(event) = line.strip_prefix("data:").and_then(|data| serde_json::from_str::<Value>(data.trim()).ok()) else {
                continue;
            };
            if let Some(text) = event.get("line").and_then(Value::as_str) {
                run.lines.push((event.get("stream").and_then(Value::as_str) == Some("stderr"), text.to_owned()));
            }
            if event.get("exit_code").is_some() || event.get("signal").is_some() {
                run.exit = Some((event["exit_code"].as_i64(), event["signal"].as_i64()));
            }
        }
        Ok(run)
    }
    /// Starts the agent as root, supervised, listening on the guest's
    /// loopback for the tunnel, with a token only root can read. A token file
    /// already there is kept when it holds a token, so a running agent (after
    /// resume, or another host's bootstrap) keeps answering to it; whichever
    /// token the file holds is read back. One that holds no token would stop
    /// every agent start, so it is replaced. The write is exclusive
    /// (`set -C`): of two concurrent bootstraps one token wins and both read
    /// it back. Replacing a file that holds no token is not atomic, so two
    /// bootstraps racing on one can leave the agent on a token the file no
    /// longer holds; reach then fails with the agent's refusal, and a
    /// relaunch recovers (`flock` may be missing from the user's image).
    /// The supervisor's lock makes this idempotent. `--supervise` returns at
    /// once: it spawns the supervisor in its own process group with stdin
    /// closed and output to its log (drydock-agent's supervisor.rs, `start`),
    /// so the run ends with it. Its argv ends with `--socket`, as the
    /// supervisor requires.
    async fn bootstrap(&self, id: &str, c: &Credentials) -> Result<Token> {
        let fresh = Token::generate().map_err(|e| ProtocolError::Internal { reason: "TCP token".into(), provider_error: e.to_string() })?;
        let port = self.settings.tunnel_port;
        let script = format!(
            "mkdir -p /run/drydock /workspace && chmod 0700 /run/drydock && \
             if [ -e {TOKEN_FILE} ] && ! grep -Eqx '[A-Za-z0-9_-]{{43,}}={{0,2}}' {TOKEN_FILE}; then rm -f {TOKEN_FILE}; fi && \
             {{ (umask 077; set -C; printf %s \"$DRYDOCK_TCP_TOKEN\" > {TOKEN_FILE}) 2>/dev/null || true; }} && \
             echo \"{TOKEN_LINE}$(cat {TOKEN_FILE})\" && \
             exec env -u DRYDOCK_TCP_TOKEN /opt/drydock/drydock-agent --supervise \
             --tcp 127.0.0.1:{port} --tcp-token-file {TOKEN_FILE} --socket /run/drydock/agent.sock"
        );
        let run =
            self.run(id, &script, BTreeMap::from([("DRYDOCK_TCP_TOKEN", fresh.secret().to_owned())]), c).await?.started("bootstrap")?;
        let token = run.token()?;
        self.tokens.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(id.to_owned(), token.clone());
        Ok(token)
    }
    async fn token(&self, id: &str, c: &Credentials) -> Result<Token> {
        if let Some(token) = self.tokens.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(id) {
            return Ok(token.clone());
        }
        let token =
            self.run(id, &format!("echo \"{TOKEN_LINE}$(cat {TOKEN_FILE})\""), BTreeMap::new(), c).await?.started("token read")?.token()?;
        self.tokens.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(id.to_owned(), token.clone());
        Ok(token)
    }
    async fn wait_running(&self, id: &str, c: &Credentials) -> Result<Value> {
        for _ in 0..STATE_POLLS {
            let row = self.sandbox(id, c).await?;
            match text(&row, "status")? {
                "running" => return Ok(row),
                "terminated" | "resume_failed" => return Err(refused(format!("Tensorlake sandbox {id} stopped before it ran"))),
                _ => tokio::time::sleep(STATE_POLL).await,
            }
        }
        Err(ProtocolError::unavailable("Tensorlake sandbox has not started", Some(5)))
    }
    /// An existing sandbox matches only the size and egress policy asked for.
    fn check_existing(&self, row: &Value, size: &Size, policy: &Policy) -> Result<()> {
        let existing = self.environment(row)?;
        if existing.granted_size.as_ref() != Some(size) || &Policy::read(row.get("network_policy"))? != policy {
            return Err(refused(
                "an existing Tensorlake sandbox holds this label with a different size or egress policy; provision a new label",
            ));
        }
        Ok(())
    }
    /// Returns an existing sandbox as observed; a running one is bootstrapped
    /// again, and one still starting is awaited. Suspended ones stay so.
    async fn adopt(&self, row: Value, c: &Credentials) -> Result<Environment> {
        let id = text(&row, "name")?.to_owned();
        let row = match text(&row, "status")? {
            "pending" => self.wait_running(&id, c).await?,
            _ => row,
        };
        if text(&row, "status")? == "running" {
            self.bootstrap(&id, c).await?;
            return self.inspect(&id, c).await;
        }
        self.environment(&row)
    }

    async fn image(&self, name: &str, c: &Credentials) -> Result<Option<Value>> {
        let response = self.send(Method::GET, self.api(&["images", "v4", "images", "name", name])?, None, c, true).await?;
        match response.status().as_u16() {
            // The SDK reads 400 from this lookup as "not registered" too.
            400 | 404 => Ok(None),
            _ => Self::answer("GET /images/v4/images/name", &response).map(Some),
        }
    }
    /// Builds `name` with the Image Service from a multi-stage Dockerfile that
    /// copies the tools image's /opt/drydock onto the base, then waits for a
    /// terminal state. The build context is that Dockerfile alone.
    async fn build(&self, r: &PrepareRequest, base: &ImageRef, name: &str, c: &Credentials) -> Result<()> {
        let dockerfile = format!(
            "FROM --platform={platform} {} AS drydock_tools\nFROM --platform={platform} {}\nCOPY --from=drydock_tools /opt/drydock/ /opt/drydock/\n",
            r.tools_digest,
            r.image_digest,
            platform = platform()
        );
        let context = build_context(&dockerfile)?;
        let mut body =
            json!({"kind":"dockerfile","dockerfile_path":"Dockerfile","parents":[],"build_args":{},"name":name,"disk_mb":DISK_MB.start()});
        if let Some(pull) = &r.image_pull {
            body["registry_credentials_json"] = json!(registry_credentials(&base.registry, pull));
        }
        // A fresh key per attempt: a key that already failed would rejoin its failure.
        let attempt = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
        let key = &digest(&format!("{name}\0{}\0{attempt}", r.tools_digest))[..32];
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("idempotency-key", reqwest::header::HeaderValue::from_str(key).map_err(|_| bad_response())?);
        let response =
            self.send_with(Method::POST, self.api(&["images", "v4", "builds"])?, Some(Body::Json(body)), c, true, headers).await?;
        let build = if response.status() == 409 {
            // Another prepare of the same image is building it: wait for that one.
            let conflict: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
            match (conflict["code"].as_str(), conflict["active_build_id"].as_str()) {
                (Some("image_build_in_progress"), Some(active)) => json!({"build_id": active}),
                _ => return Err(failure("POST /images/v4/builds", 409, response.body(), None)),
            }
        } else {
            Self::answer("POST /images/v4/builds", &response)?
        };
        let id = text(&build, "build_id")?.to_owned();
        if let Some(upload) = build.pointer("/context_upload/url").and_then(Value::as_str) {
            let upload = Url::parse(upload).ok().filter(|u| u.scheme() == "https").ok_or_else(bad_response)?;
            let operation = "PUT build context";
            let response = self.send(Method::PUT, upload, Some(Body::Bytes(context.clone())), c, false).await?;
            Self::answer(operation, &response)?;
            let seal = json!({"digest": format!("{:x}", Sha256::digest(&context))});
            self.call(Method::POST, self.api(&["images", "v4", "builds", &id, "context", "seal"])?, Some(seal), c).await?;
        }
        for _ in 0..BUILD_POLLS {
            let build = self.call(Method::GET, self.api(&["images", "v4", "builds", &id])?, None, c).await?;
            match text(&build, "status")? {
                "succeeded" => return Ok(()),
                "failed" => {
                    let error = build["error"].as_str().unwrap_or("no error recorded");
                    return Err(refused(format!("Tensorlake image build {id} failed: {error}")));
                }
                "cancelled" => return Err(ProtocolError::unavailable(format!("Tensorlake image build {id} was cancelled"), None)),
                _ => tokio::time::sleep(BUILD_POLL).await,
            }
        }
        Err(ProtocolError::unavailable(format!("Tensorlake image build {id} is still running"), Some(30)))
    }
    fn resources(&self, size: &Size) -> Result<Value> {
        let memory_mb = size.memory_bytes / MIB;
        let disk_mb = size.disk_bytes / MIB;
        let cpus = size.cpus;
        let limit = |what: &str| refused(format!("Tensorlake sandbox size: {what}"));
        if !cpus.is_finite() || cpus.fract() != 0.0 || cpus < 1.0 || cpus > f64::from(self.settings.max_cpus) {
            return Err(limit(&format!("1 to {} whole vCPUs", self.settings.max_cpus)));
        }
        let cpus_whole = cpus as u64;
        if !size.memory_bytes.is_multiple_of(MIB)
            || memory_mb < MEMORY_MB_PER_CPU.start() * cpus_whole
            || memory_mb > MEMORY_MB_PER_CPU.end() * cpus_whole
            || size.memory_bytes > self.settings.max_memory.0
        {
            return Err(limit(&format!("whole MiB of RAM, 1 to 8 GiB per vCPU and at most {} MiB", self.settings.max_memory.0 / MIB)));
        }
        if !size.disk_bytes.is_multiple_of(MIB) || !DISK_MB.contains(&disk_mb) {
            return Err(limit("whole MiB of disk, 10 to 100 GiB"));
        }
        Ok(json!({"cpus": cpus, "memory_mb": memory_mb, "disk_mb": disk_mb}))
    }
}

/// Output of one guest command: (stderr, line) in order, and how it ended.
#[derive(Default)]
struct Run {
    lines: Vec<(bool, String)>,
    exit: Option<(Option<i64>, Option<i64>)>,
}
impl Run {
    fn output(&self) -> String {
        self.lines.iter().map(|(_, line)| line.as_str()).collect::<Vec<_>>().join("\n")
    }
    fn stdout(&self) -> String {
        self.lines.iter().filter(|(stderr, _)| !stderr).map(|(_, line)| line.as_str()).collect::<Vec<_>>().join("\n")
    }
    /// Exit 0, or CommandFailed with the merged output.
    fn success(self) -> Result<Self> {
        if self.exit_code() == 0 {
            return Ok(self);
        }
        Err(ProtocolError::CommandFailed {
            reason: "Tensorlake guest command failed".into(),
            exit_code: self.exit_code(),
            output: Secret::new(self.output()),
        })
    }
    /// The shell's convention: the code, 128 + a signal, or -1 when the stream ended without either.
    fn exit_code(&self) -> i32 {
        match self.exit {
            Some((Some(code), _)) => i32::try_from(code).unwrap_or(-1),
            Some((None, Some(signal))) => 128 + i32::try_from(signal).unwrap_or(0),
            _ => -1,
        }
    }
    /// Exit 0, or for the module's own guest commands an Internal error
    /// whose cause is the output's tail, so drydockd's log shows why. Token
    /// lines are left out.
    fn started(self, what: &str) -> Result<Self> {
        if self.exit_code() == 0 {
            return Ok(self);
        }
        let output: Vec<_> =
            self.lines.iter().map(|(_, line)| line.as_str()).filter(|line| !line.contains(TOKEN_LINE.trim_end())).collect();
        let output = output.join("\n");
        let tail: String = output.chars().rev().take(OUTPUT_CAUSE_CHARS).collect::<Vec<_>>().into_iter().rev().collect();
        Err(ProtocolError::Internal {
            reason: format!("Tensorlake guest {what} exited {}", self.exit_code()),
            provider_error: if tail.is_empty() { "no output".into() } else { tail },
        })
    }
    fn token(&self) -> Result<Token> {
        let line = self.lines.iter().find_map(|(stderr, line)| line.strip_prefix(TOKEN_LINE).filter(|_| !stderr));
        line.and_then(|line| Token::parse(line).ok()).ok_or_else(|| ProtocolError::Internal {
            reason: "the agent's TCP token was not read back".into(),
            provider_error: String::new(),
        })
    }
}

/// A plain tar holding only `Dockerfile`, the Image Service's build context.
fn build_context(dockerfile: &str) -> Result<Vec<u8>> {
    let mut archive = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_ustar();
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o644);
    // Tensorlake's builder decodes every numeric field; ustar leaves these NUL.
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    let internal = |e: std::io::Error| ProtocolError::Internal { reason: "build context".into(), provider_error: e.to_string() };
    archive.append_data(&mut header, "Dockerfile", dockerfile.as_bytes()).map_err(internal)?;
    archive.into_inner().map_err(internal)
}
/// A Docker `config.json` naming the base's registry alone.
fn registry_credentials(registry: &str, pull: &RegistryCredential) -> String {
    use base64::Engine;
    let server = if registry == "docker.io" { "https://index.docker.io/v1/" } else { registry };
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", pull.username, pull.secret.expose()));
    json!({"auths": {server: {"auth": auth}}}).to_string()
}
/// Whether a registry host is plainly private: loopback, private, shared or
/// link-local IPv4, a bracketed IPv6 literal, `localhost`, a single-label
/// name, or a name under a suffix no public resolver answers. Names that
/// resolve to private addresses are not looked up; they fail at the build.
fn private_registry(registry: &str) -> bool {
    let host = registry.rsplit_once(':').filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit())).map_or(registry, |(h, _)| h);
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        let [a, b, ..] = ip.octets();
        return ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || (a == 100 && (64..128).contains(&b));
    }
    let host = host.to_ascii_lowercase();
    host.starts_with('[')
        || !host.contains('.')
        || [".localhost", ".local", ".internal", ".lan", ".home.arpa", ".test", ".invalid"].iter().any(|s| host.ends_with(s))
}

/// Tensorlake's egress policy: None is unrestricted.
#[derive(Debug, Clone, PartialEq)]
struct Policy(Option<Network>);
#[derive(Debug, Clone, PartialEq)]
struct Network {
    /// True lets hostname entries resolve (scoped DNS); false blocks DNS.
    allow_internet_access: bool,
    allow_out: BTreeSet<String>,
}
impl Policy {
    /// The request as Tensorlake's `network`, refusing what it cannot hold:
    /// ports and IPv6. Hostname entries need `allow_internet_access: true`,
    /// which with an empty list would be open, so that is never sent.
    fn request(request: &EgressRequest) -> Result<Self> {
        let EgressRequest::DenyAll { direct } = request else { return Ok(Self(None)) };
        let mut addresses = BTreeSet::new();
        let mut names = BTreeSet::new();
        for destination in direct {
            match destination {
                Destination::HostPort { .. } => return Err(refused("Tensorlake egress rules cannot restrict ports")),
                Destination::Cidr { cidr } => {
                    addresses.insert(normal_cidr(cidr.as_str()).ok_or_else(|| refused("Tensorlake egress takes IPv4 CIDRs only"))?)
                }
                Destination::Host { host } => {
                    let host = host.as_str().trim_end_matches('.').to_ascii_lowercase();
                    if host.contains(':') {
                        return Err(refused("Tensorlake egress takes no IPv6 destinations"));
                    }
                    if host.parse::<Ipv4Addr>().is_ok() { addresses.insert(host) } else { names.insert(host) }
                }
            };
        }
        let allow_internet_access = !names.is_empty();
        Ok(Self(Some(Network { allow_internet_access, allow_out: addresses.into_iter().chain(names).collect() })))
    }
    fn body(&self) -> Option<Value> {
        let network = self.0.as_ref()?;
        let mut body = json!({"allow_internet_access": network.allow_internet_access});
        if !network.allow_out.is_empty() {
            body["allow_out"] = json!(network.allow_out);
        }
        Some(body)
    }
    /// A sandbox's `network_policy`, normalised as requests are. Null, or
    /// internet access with nothing listed or denied, is unrestricted.
    fn read(policy: Option<&Value>) -> Result<Self> {
        let Some(policy) = policy.filter(|p| !p.is_null()) else { return Ok(Self(None)) };
        let list = |key| -> Result<BTreeSet<String>> {
            match policy.get(key) {
                None | Some(Value::Null) => Ok(BTreeSet::new()),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|item| {
                        let item = item.as_str().ok_or_else(bad_response)?.trim_end_matches('.').to_ascii_lowercase();
                        Ok(normal_cidr(&item).filter(|_| item.contains('/')).unwrap_or(item))
                    })
                    .collect(),
                Some(_) => Err(bad_response()),
            }
        };
        let allow_internet_access = policy.get("allow_internet_access").and_then(Value::as_bool).unwrap_or(true);
        let (allow_out, deny_out) = (list("allow_out")?, list("deny_out")?);
        if !deny_out.is_empty() {
            // Drydock never denies; a policy with denials is not one of ours.
            return Ok(Self(Some(Network {
                allow_internet_access,
                allow_out: allow_out.into_iter().chain(deny_out.into_iter().map(|d| format!("!{d}"))).collect(),
            })));
        }
        if allow_internet_access && allow_out.is_empty() {
            return Ok(Self(None));
        }
        Ok(Self(Some(Network { allow_internet_access, allow_out })))
    }
    fn fingerprint(&self) -> String {
        let canonical = match &self.0 {
            None => json!("open"),
            Some(network) => json!([network.allow_internet_access, network.allow_out]),
        };
        digest(&canonical.to_string())
    }
}
fn normal_cidr(cidr: &str) -> Option<String> {
    let (ip, bits) = cidr.split_once('/').unwrap_or((cidr, "32"));
    let (ip, bits) = (ip.parse::<Ipv4Addr>().ok()?, bits.parse::<u32>().ok().filter(|b| *b <= 32)?);
    let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
    Some(format!("{}/{bits}", Ipv4Addr::from(u32::from(ip) & mask)))
}

/// Sandbox names: Tensorlake has no labels, so a sandbox's name is drydock's
/// only handle on it. Every name of one instance starts `dd-<8 hex>-`. The
/// label follows as itself (`r-`) when it is short lowercase name text, as
/// base32 (`b-`) when that fits, and otherwise as a digest (`h-`), which
/// cannot be read back. Names are at most 63 characters, lowercase, never
/// end in `-`, and never look like a 21-character Tensorlake id.
fn sandbox_prefix(instance: &str) -> String {
    format!("dd-{}-", &digest(instance)[..8])
}
const NAME_LIMIT: usize = 63;
fn sandbox_name(instance: &str, label: &str) -> String {
    let prefix = sandbox_prefix(instance);
    let room = NAME_LIMIT - prefix.len() - 2;
    let raw = !label.is_empty()
        && label.len() <= room
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.ends_with('-');
    if raw {
        return format!("{prefix}r-{label}");
    }
    let encoded = base32(label.as_bytes());
    if !label.is_empty() && encoded.len() <= room {
        return format!("{prefix}b-{encoded}");
    }
    format!("{prefix}h-{}", &digest(&format!("{instance}\0{label}"))[..40])
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
    // Leftover bits are padding, and must be zero, so each text has one decoding.
    (buffer & ((1 << bits) - 1) == 0).then_some(bytes)
}
/// The prepared image's name: one per base image, tools image and
/// platform, so a new tools pin builds a new image rather than reusing one
/// baked with the old tools layer. Unlike Daytona's, the baked agent is no
/// mere cache: the first hello arrives through its TCP listener, so an agent
/// too old to listen can't be reached to be upgraded.
fn image_name(image: &str, tools: &str, platform: &Platform) -> String {
    format!("dd-{}", &digest(&format!("{image}\0{tools}\0{platform}"))[..40])
}
fn shell_command(command: &[String]) -> String {
    command.iter().map(|s| format!("'{}'", s.replace('\'', "'\"'\"'"))).collect::<Vec<_>>().join(" ")
}
fn pinned(reference: &str) -> bool {
    reference.split_once("@sha256:").is_some_and(|(image, digest)| {
        !image.is_empty()
            && digest.len() == 64
            && digest.bytes().all(|b| b.is_ascii_hexdigit())
            && !reference.contains(|c: char| c.is_whitespace() || c == '\\')
    })
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
                enforcement: Enforcement::Enforced,
            },
            fallback_runner: true,
            bootstrap: BootstrapRoute::Bake,
            agent: true,
            platforms: vec![platform()],
            image_routes: vec![ImageRoute::RegistryPull {
                auth: RegistryAuthKind::Basic,
                registration: CredentialRegistration::PerRequest,
                digest_references: true,
                tools_layer: ToolsLayer::Provider,
            }],
            usage: self.settings.organization_id.is_some(),
            quota: false,
            host_filesystem: false,
        }
    }
    fn observation(&self) -> ObservationMode {
        ObservationMode::Poll { interval_ms: 30_000 }
    }
    fn operations(&self) -> Operations<'_> {
        Operations {
            exec: Some(self),
            suspend_resume: Some(self),
            usage: self.settings.organization_id.is_some().then_some(self as &dyn UsageOperation),
            ..Operations::default()
        }
    }
    async fn prepare(&self, r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
        if prepare_route(&r)? != ImageRouteKind::RegistryPull {
            return Err(refused("Tensorlake prepares by registry pull only"));
        }
        if !pinned(&r.image_digest) || !pinned(&r.tools_digest) {
            return Err(refused("Tensorlake requires base and tools images pinned by sha256 digest"));
        }
        let platform = prepare_platform(&r)?;
        let supported = self::platform();
        if platform != supported {
            return Err(ProtocolError::ImageRefused {
                reason: format!("Tensorlake runs only {supported} sandboxes"),
                refusal: ImageRefusal::UnsupportedPlatform { platform },
            });
        }
        let base = ImageRef::parse(&r.image_digest)?;
        // The build pulls both stages, so neither may sit on a private host.
        for registry in [&base.registry, &ImageRef::parse(&r.tools_digest)?.registry] {
            if private_registry(registry) {
                return Err(refused(format!(
                    "Tensorlake's builders cannot reach the private registry {registry}; stage the image in a registry they can reach"
                )));
            }
        }
        self.resources(&r.size)?;
        let name = image_name(&r.image_digest, &r.tools_digest, &platform);
        if self.image(&name, c).await?.is_none() {
            self.build(&r, &base, &name, c).await?;
        }
        Ok(Prepared { provider: self.name.clone(), id: name, platform, image_digest: r.image_digest, tools_digest: r.tools_digest })
    }
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        if r.prepared.provider != self.name {
            return Err(refused("prepared image belongs to another provider"));
        }
        if r.prepared.id != image_name(&r.prepared.image_digest, &r.prepared.tools_digest, &r.prepared.platform) {
            return Err(refused("prepared image is not this provider's"));
        }
        let resources = self.resources(&r.size)?;
        let policy = Policy::request(&r.egress)?;
        let name = sandbox_name(&self.name, &r.label);
        let mut body = json!({
            "name": name, "image": r.prepared.id, "resources": resources,
            // The plan's longest idle timeout; it suspends a named sandbox.
            "timeout_secs": 0, "auto_resume": true, "wait": true,
        });
        if let Some(network) = policy.body() {
            body["network"] = network;
        }
        let response = self.send(Method::POST, self.api(&["sandboxes"])?, Some(Body::Json(body)), c, true).await?;
        let created: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
        match response.status().as_u16() {
            409 => {
                let row = self.sandbox(&name, c).await?;
                self.check_existing(&row, &r.size, &policy)?;
                return Ok(Provisioned::Existing(self.adopt(row, c).await?));
            }
            // The sandbox failed before it ran.
            422 if created["status"] == "failed" => {
                let reason = created["termination_reason"].as_str().unwrap_or("unknown");
                return Err(refused(format!("Tensorlake sandbox failed to start: {reason}")));
            }
            // The server's own wait ran out; the sandbox is still queued.
            200..=299 | 504 => {}
            status => return Err(failure("POST /sandboxes", status, response.body(), None)),
        }
        self.wait_running(&name, c).await?;
        self.bootstrap(&name, c).await?;
        Ok(Provisioned::Created(self.inspect(&name, c).await?))
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        let prefix = sandbox_prefix(&self.name);
        let rows = self.paged(&["sandboxes"], "sandboxes", c).await?;
        rows.iter()
            .filter(|row| row.get("name").and_then(Value::as_str).is_some_and(|name| name.starts_with(&prefix)))
            .map(|row| self.environment(row))
            .filter(|row| !matches!(row, Ok(Environment { state: Observation::Gone { .. }, .. })))
            .collect()
    }
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        match self.sandbox(id, c).await {
            Ok(row) => self.observed(&row, c).await,
            Err(ProtocolError::NotFound { reason }) => match self.archived(id, c).await? {
                Some(mut row) => {
                    row["status"] = json!("terminated");
                    self.environment(&row)
                }
                None => Err(ProtocolError::NotFound { reason }),
            },
            Err(error) => Err(error),
        }
    }
    /// Deletes the sandbox, then every snapshot it left (each suspend leaves
    /// one, and they bill until deleted). Snapshots that cannot be deleted
    /// yet make destroy Unavailable, so the host retries it.
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        let sandbox_id = match self.sandbox(id, c).await {
            Ok(row) => Some(text(&row, "id")?.to_owned()),
            Err(ProtocolError::NotFound { .. }) => {
                self.archived(id, c).await?.map(|row| text(&row, "id").map(str::to_owned)).transpose()?
            }
            Err(error) => return Err(error),
        };
        match self.call(Method::DELETE, self.api(&["sandboxes", id])?, None, c).await {
            Ok(_) | Err(ProtocolError::NotFound { .. }) => {}
            Err(error) => return Err(error),
        }
        self.tokens.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(id);
        let Some(sandbox_id) = sandbox_id else { return Ok(()) };
        let mut remaining = 0;
        for snapshot in self.snapshots(&sandbox_id, c).await? {
            if snapshot["status"] == "deleting" {
                continue;
            }
            let snapshot_id =
                snapshot.get("snapshot_id").or_else(|| snapshot.get("id")).and_then(Value::as_str).ok_or_else(bad_response)?;
            match self.call(Method::DELETE, self.api(&["snapshots", snapshot_id])?, None, c).await {
                Ok(_) | Err(ProtocolError::NotFound { .. }) => {}
                Err(error) => {
                    tracing::warn!(provider = %self.name, environment = %id, error_class = error.class(), "snapshot delete failed");
                    remaining += 1;
                }
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
    /// The agent's connection through Tensorlake's tunnel. A suspended sandbox
    /// is refused: the tunnel would wake it, and reach never resumes.
    async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream> {
        let row = self.sandbox(id, c).await?;
        if text(&row, "status")? != "running" {
            return Err(refused(format!("Tensorlake sandbox {id} is not running; resume it first")));
        }
        let url = self.guest(id, &["tunnels", "tcp"])?;
        let url = format!("wss://{}{}?port={}", url.host_str().ok_or_else(bad_response)?, url.path(), self.settings.tunnel_port);
        let mut auth = format!("Bearer {}", self.key(c)?.expose())
            .parse::<http::HeaderValue>()
            .map_err(|_| refused("invalid Tensorlake API key header"))?;
        auth.set_sensitive(true);
        let headers = HeaderMap::from_iter([(http::header::AUTHORIZATION, auth)]);
        let (url, headers) = (&url, &headers);
        let connect = |token: Token| async move {
            let socket = self.dialer.dial(url, headers.clone()).await.map_err(|error| match error {
                DialError::Refused { status, body } => failure("tunnel", status, body.as_bytes(), None),
                DialError::Io(error) => ProtocolError::Unavailable {
                    reason: "Tensorlake tunnel transport failed".into(),
                    retry_after: None,
                    provider_error: Some(error.to_string()),
                },
            })?;
            Ok::<_, ProtocolError>(tcp::connect(websocket::stream(socket, TUNNEL_FRAME), &token).await)
        };
        let mut connected = connect(self.token(id, c).await?).await?;
        // A token cached before another bootstrap replaced the file: read it again, once.
        if connected.as_ref().is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied) {
            self.tokens.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(id);
            connected = connect(self.token(id, c).await?).await?;
        }
        // drydock-transport's stream, as the provider interface's.
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
        let status = text(&self.sandbox(id, c).await?, "status")?.to_owned();
        if matches!(status.as_str(), "pending" | "resuming") {
            return Err(ProtocolError::unavailable(format!("Tensorlake sandbox {id} is {status}"), Some(5)));
        }
        if status == "running" {
            self.call(Method::POST, self.api(&["sandboxes", id, "suspend"])?, None, c).await?;
        }
        for _ in 0..STATE_POLLS {
            match text(&self.sandbox(id, c).await?, "status")? {
                "suspended" => return Ok(ResumeToken { token: Secret::new(resume_marker(&self.name, id)) }),
                "suspending" | "snapshotting" | "running" => tokio::time::sleep(STATE_POLL).await,
                other => return Err(refused(format!("Tensorlake sandbox {id} is {other}, not suspending"))),
            }
        }
        Err(ProtocolError::unavailable("Tensorlake sandbox has not suspended", Some(5)))
    }
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()> {
        if token.token.expose() != resume_marker(&self.name, id) {
            return Err(refused("resume token belongs to another environment"));
        }
        if text(&self.sandbox(id, c).await?, "status")? != "running" {
            let mut url = self.api(&["sandboxes", id, "resume"])?;
            url.query_pairs_mut().append_pair("wait_ms", "30000");
            self.call(Method::POST, url, None, c).await?;
            self.wait_running(id, c).await?;
        }
        self.bootstrap(id, c).await?;
        Ok(())
    }
}
/// A deterministic continuation marker binding instance and sandbox; not a
/// credential, since every resume still needs the key.
fn resume_marker(instance: &str, id: &str) -> String {
    format!("tensorlake-resume-{}", &digest(&format!("{instance}\0{id}"))[..40])
}

#[async_trait]
impl Exec for Tensorlake {
    /// Text output only: Tensorlake returns UTF-8 lines, stdout and stderr
    /// merged in order, with other bytes replaced.
    async fn exec(&self, id: &str, r: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        let output = self.run(id, &shell_command(&r.command), BTreeMap::new(), c).await?.success()?.output();
        Ok(Box::new(std::io::Cursor::new(output.into_bytes())))
    }
}

#[async_trait]
impl UsageOperation for Tensorlake {
    /// The organization's sandbox usage export over the period: summed
    /// resource quantities and the attributed charge. Network egress has no
    /// protocol resource and is left out; sizes are not reported, so no
    /// environment hours are inferred.
    async fn usage(&self, period: Period, c: &Credentials) -> Result<Usage> {
        let organization = self.settings.organization_id.as_deref().ok_or_else(|| refused("Tensorlake usage needs organization_id"))?;
        let stamp = |t: &Timestamp| t.instant().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut url = self.api(&["platform", "v1", "organizations", organization, "sandbox-usage", "sandboxes", "export"])?;
        url.query_pairs_mut().append_pair("fromDate", &stamp(period.start())).append_pair("toDate", &stamp(period.end()));
        let response = self.send(Method::GET, url, None, c, true).await?;
        if !response.status().is_success() {
            return Err(failure("GET sandbox usage export", response.status().as_u16(), response.body(), None));
        }
        let mut resources: BTreeMap<ResourceKind, Quantity> = BTreeMap::new();
        let mut add = |kind, unit: &str, amount: f64| {
            resources.entry(kind).or_insert_with(|| Quantity { amount: 0.0, unit: unit.into() }).amount += amount;
        };
        let (mut window, mut sandboxes, mut end) = (None, 0u64, None);
        for line in String::from_utf8_lossy(response.body()).lines().filter(|l| !l.trim().is_empty()) {
            let record: Value = serde_json::from_str(line).map_err(|_| bad_response())?;
            match record["type"].as_str() {
                Some("window") => window = Some(record),
                Some("sandbox") => {
                    sandboxes += 1;
                    for (key, kind, unit, expected, factor) in [
                        ("cpu", ResourceKind::Cpu, "{vCPU}.s", "vCPU-hour", 3600.0),
                        ("memory", ResourceKind::Memory, "By.s", "GiB-hour", GIB as f64 * 3600.0),
                        ("sandboxStorage", ResourceKind::Disk, "By.s", "GiB-hour", GIB as f64 * 3600.0),
                        ("snapshotStorage", ResourceKind::SnapshotStorage, "By.s", "GiB-hour", GIB as f64 * 3600.0),
                    ] {
                        let Some(resource) = record.pointer(&format!("/resources/{key}")) else { continue };
                        if resource["unit"] != expected {
                            return Err(bad_response());
                        }
                        let quantity =
                            resource["quantity"].as_str().and_then(|q| q.parse::<f64>().ok()).filter(|q| q.is_finite() && *q >= 0.0);
                        add(kind, unit, quantity.ok_or_else(bad_response)? * factor);
                    }
                }
                Some("end") => end = record["count"].as_u64(),
                _ => {}
            }
        }
        // A missing end record, or a count that disagrees, is a truncated export.
        if end != Some(sandboxes) {
            return Err(ProtocolError::unavailable("Tensorlake usage export ended early", Some(30)));
        }
        add(ResourceKind::Environments, "1", sandboxes as f64);
        let cost = window.ok_or_else(bad_response)?.get("attributedUsageCharge").filter(|v| !v.is_null()).map(minor_to_cost).transpose()?;
        Ok(Usage {
            period,
            environment_hours: vec![],
            measurements: Some(UsageMeasurements { scope: UsageScope::Organization { id: organization.to_owned() }, resources, cost }),
        })
    }
}
/// `{currency, amountMinor}` in a two-decimal currency as an exact amount.
fn minor_to_cost(charge: &Value) -> Result<Cost> {
    let currency = text(charge, "currency")?.to_ascii_uppercase();
    let minor = text(charge, "amountMinor")?;
    if !["USD", "EUR", "GBP"].contains(&currency.as_str()) || !minor.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad_response());
    }
    let minor = format!("{minor:0>3}");
    let (major, cents) = minor.split_at(minor.len() - 2);
    let major = major.trim_start_matches('0');
    Ok(Cost { amount: format!("{}.{cents}", if major.is_empty() { "0" } else { major }), currency })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::generators as gs;

    // Every label gets a name Tensorlake accepts, distinct per (instance,
    // label), starting with the instance's prefix; a raw or base32 name
    // reads back to its label, and a digest name reads back to none.
    // Labels span empty, short lowercase, UUID-like, uppercase, Unicode,
    // trailing-hyphen and over-long text.
    #[hegel::test]
    fn sandbox_names_hold_their_labels(tc: hegel::TestCase) {
        let pick = tc.draw(gs::sampled_from(vec![
            "",
            "a",
            "vessel-1",
            "4f3b2a9c-0d1e-4f5a-8b6c-7d8e9f0a1b2c",
            "Vessel",
            "ünïcode",
            "trailing-",
            "x--y",
        ]));
        let extra = tc.draw(gs::text().max_size(80));
        let label = if tc.draw(gs::booleans()) { pick.to_owned() } else { format!("{pick}{extra}") };
        let name = sandbox_name("tensorlake", &label);
        assert!(name_valid(&name) && name.len() <= NAME_LIMIT, "{name}");
        assert!(name.contains('-'), "never an id's 21 alphanumerics");
        assert!(name.starts_with(&sandbox_prefix("tensorlake")));
        match label_of(&sandbox_prefix("tensorlake"), &name) {
            Some(read) => assert_eq!(read, label),
            None => assert!(name.contains("-h-"), "{name}"),
        }
        assert_ne!(name, sandbox_name("tensorlake-2", &label));
        assert_ne!(name, sandbox_name("tensorlake", &format!("{label}x")));
    }
    // A request's network reads back as the same policy, so re-adoption
    // matches it: CIDRs are masked, IPv4 literals stay addresses, names are
    // lowercased without a final dot, and any name brings internet access.
    // Entries span names, literals, CIDRs with host bits set, and duplicates.
    #[hegel::test]
    fn network_policies_read_back_as_requested(tc: hegel::TestCase) {
        let pool = ["example.com", "Example.COM.", "192.0.2.7", "10.1.2.3/8", "10.0.0.0/8", "172.16.5.4/12", "api.github.com"];
        let picks = tc.draw(gs::vecs(gs::integers::<usize>().max_value(pool.len() - 1)).max_size(5));
        let direct: Vec<Destination> = picks
            .iter()
            .map(|i| match pool[*i] {
                entry if entry.contains('/') => Destination::Cidr { cidr: serde_json::from_value(json!(entry)).unwrap() },
                entry => Destination::Host { host: serde_json::from_value(json!(entry)).unwrap() },
            })
            .collect();
        let request = Policy::request(&EgressRequest::DenyAll { direct }).unwrap();
        let body = request.body().unwrap();
        let names = picks.iter().any(|i| pool[*i].contains("com"));
        assert_eq!(body["allow_internet_access"], names);
        assert_eq!(body.get("allow_out").is_some(), !picks.is_empty());
        let allow_out: Vec<String> = serde_json::from_value(body.get("allow_out").cloned().unwrap_or(json!([]))).unwrap();
        assert!(allow_out.iter().all(|e| e == &e.to_ascii_lowercase() && !e.ends_with('.')));
        assert!(!allow_out.contains(&"10.1.2.3/8".to_owned()) && !allow_out.contains(&"172.16.5.4/12".to_owned()), "{allow_out:?}");
        let sandbox = json!({"allow_internet_access": body["allow_internet_access"], "allow_out": body.get("allow_out"), "deny_out": []});
        assert_eq!(Policy::read(Some(&sandbox)).unwrap(), request);
        assert_eq!(Policy::read(Some(&sandbox)).unwrap().fingerprint(), request.fingerprint());
        assert_eq!(Policy::request(&EgressRequest::Open).unwrap(), Policy::read(None).unwrap());
        // A denial drydock never makes keeps the policy distinct from the request.
        let denied =
            json!({"allow_internet_access": body["allow_internet_access"], "allow_out": body.get("allow_out"), "deny_out": ["evil.test"]});
        assert_ne!(Policy::read(Some(&denied)).unwrap(), request);
    }
    // Byte quantities: plain bytes, or whole MiB or GiB; anything else, and
    // overflow, is refused.
    #[test]
    fn byte_quantities_parse() {
        let parse = |v: Value| serde_json::from_value::<ByteQuantity>(v).map(|q| q.0).ok();
        assert_eq!(parse(json!(1024)), Some(1024));
        assert_eq!(parse(json!("16GiB")), Some(16 << 30));
        assert_eq!(parse(json!("512MiB")), Some(512 << 20));
        assert_eq!(parse(json!("512 MiB")), Some(512 << 20));
        assert_eq!(parse(json!("2048")), Some(2048));
        for invalid in [json!("16GB"), json!("1.5GiB"), json!("GiB"), json!("-1GiB"), json!(format!("{}GiB", u64::MAX)), json!(-1)] {
            assert_eq!(parse(invalid.clone()), None, "{invalid}");
        }
    }
    // Private registries are known without DNS; public names, and digest
    // pins without whitespace or backslashes, pass.
    #[test]
    fn private_registries_and_pins() {
        for private in [
            "10.0.0.1",
            "10.0.0.1:5000",
            "172.20.1.1",
            "192.168.0.9",
            "127.0.0.1:5000",
            "169.254.1.1",
            "100.100.1.1",
            "0.0.0.0",
            "[::1]:5000",
            "localhost",
            "localhost:5000",
            "registry:5000",
            "lab.local",
            "forgejo.internal",
            "x.home.arpa",
            "box.lan",
        ] {
            assert!(private_registry(private), "{private}");
        }
        for public in ["ghcr.io", "docker.io", "registry.example.com:443", "8.8.8.8", "100.128.0.1", "172.32.0.1"] {
            assert!(!private_registry(public), "{public}");
        }
        let hex = "a".repeat(64);
        assert!(pinned(&format!("ghcr.io/x/y@sha256:{hex}")));
        for unpinned in [
            format!("ghcr.io/x/y:{hex}"),
            format!("@sha256:{hex}"),
            format!("x@sha256:{}", &hex[1..]),
            format!("x y@sha256:{hex}"),
            format!("x\\y@sha256:{hex}"),
            format!("x@sha256:{}g", &hex[1..]),
        ] {
            assert!(!pinned(&unpinned), "{unpinned}");
        }
    }
    // A command's end: exit 0 succeeds; another code is that code; a signal
    // is 128 plus it, as a shell reports; no exit at all is -1.
    #[test]
    fn guest_command_ends() {
        let run = |exit| Run { lines: vec![(false, "out".into()), (true, "err".into())], exit };
        assert!(run(Some((Some(0), None))).success().is_ok());
        let code = |exit| match run(exit).success() {
            Err(ProtocolError::CommandFailed { exit_code, output, .. }) => {
                assert_eq!(output.expose(), "out\nerr");
                exit_code
            }
            other => panic!("{:?}", other.map(|_| ())),
        };
        assert_eq!(code(Some((Some(3), None))), 3);
        assert_eq!(code(Some((None, Some(9)))), 137);
        assert_eq!(code(None), -1);
    }
    // base32 decodes exactly what it encodes, and refuses non-zero padding.
    #[hegel::test]
    fn base32_round_trips(tc: hegel::TestCase) {
        let bytes = tc.draw(gs::vecs(gs::integers::<u8>()).max_size(40));
        assert_eq!(unbase32(&base32(&bytes)).unwrap(), bytes);
        assert!(unbase32("ab").is_none() || base32(&unbase32("ab").unwrap()) == "ab");
    }
    // Two-decimal minor units become exact major amounts, leading zeros and all.
    #[test]
    fn minor_units_become_exact_amounts() {
        for (minor, amount) in [("0", "0.00"), ("05", "0.05"), ("7", "0.07"), ("123", "1.23"), ("00123", "1.23"), ("100000", "1000.00")] {
            assert_eq!(minor_to_cost(&json!({"currency":"usd","amountMinor":minor})).unwrap().amount, amount);
        }
        assert!(minor_to_cost(&json!({"currency":"jpy","amountMinor":"5"})).is_err());
        assert!(minor_to_cost(&json!({"currency":"usd","amountMinor":"-5"})).is_err());
    }
}

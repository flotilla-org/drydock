//! Stateless Runtime (withruntime.com) translator: microVM sandboxes from
//! images Runtime builds from a Dockerfile, reached through Runtime's
//! sandbox tunnel to the agent's token-gated TCP listener on the guest's
//! loopback. Egress is enforced by Runtime's host proxy, outside the guest.
//! The host owns inventory and retries.
//! API contract: https://api.withruntime.com/v1/openapi.json (0.2.0) and
//! https://withruntime.com/docs/api, read 2026-11-03, with what the live
//! probe of 2026-11-01 found (drydock#193).
mod tunnel;

use crate::{module::*, oci::ImageRef};
use async_trait::async_trait;
use drydock_protocol::*;
use drydock_transport::{
    tcp::{self, Token},
    websocket::{DialError, TlsDialer, WebSocketDialer, tungstenite::http::HeaderMap},
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
/// Runtime's create limits, in MiB and vCPUs (paid funding; trial is lower,
/// and Runtime refuses past it with its own reason).
const VCPU: std::ops::RangeInclusive<u64> = 1..=16;
const MEMORY_MIB: std::ops::RangeInclusive<u64> = 128..=65_536;
const DISK_MIB: std::ops::RangeInclusive<u64> = 3072..=409_600;
const TOKEN_FILE: &str = "/run/drydock/tcp.token";
const TOKEN_LINE: &str = "drydock-tcp-token ";
/// Labels on every sandbox drydock makes: the provider instance, the
/// vessel's label, and the prepared image it started from (Runtime's
/// sandboxes do not report their image; prepare's slot management reads it).
const PROVIDER_LABEL: &str = "drydock.provider";
const VESSEL_LABEL: &str = "flotilla.label";
const IMAGE_LABEL: &str = "drydock.image";
/// Label values are at most 256 characters.
const LABEL_LIMIT: usize = 256;
/// Each request must be answered inside the host's 30-second HTTP
/// deadline, so no server-side wait or guest command in one request may
/// run longer than this. An operation polls across many requests, bounded
/// by the daemon's own per-operation deadline.
const WAIT_SECONDS: u64 = 25;
const STATE_POLL: Duration = Duration::from_secs(1);
const STATE_POLLS: u32 = 120;
/// A build is polled every 3 s; the daemon gives prepare 600 s, so a build
/// still running after 7.5 minutes is Unavailable and the retried prepare
/// finds it by name and waits on it again.
const BUILD_POLL: Duration = Duration::from_secs(3);
const BUILD_POLLS: u32 = 150;
/// How much of a failed build's log, or a failed bootstrap's output, an error carries.
const LOG_TAIL_LINES: usize = 20;
const OUTPUT_CAUSE_CHARS: usize = 800;
/// Ports Runtime never lets a sandbox reach (telnet, SMTP and submission, SMB, IRC).
const FORBIDDEN_PORTS: &[u16] = &[23, 25, 139, 445, 465, 587, 6667];

/// The module, with the WebSocket dialer its tunnels use: TLS in production,
/// an in-process stand-in in tests.
pub struct RuntimeModule {
    dialer: Arc<dyn WebSocketDialer>,
}
impl RuntimeModule {
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
    #[serde(default = "api_url")]
    api_url: String,
    /// The guest port the agent's TCP listener binds on loopback.
    #[serde(default = "tunnel_port")]
    tunnel_port: u16,
    /// Explicit limits; otherwise an ordinary key's 50 requests a second.
    #[serde(default)]
    rate_limits: Option<Vec<RateLimit>>,
    /// Operator-supplied egress conformance command, run as root; see Daytona's.
    #[serde(default)]
    egress_probe: Option<ExecRequest>,
}
fn api_url() -> String {
    "https://api.withruntime.com/v1".into()
}
fn tunnel_port() -> u16 {
    7811
}

#[async_trait]
impl Module for RuntimeModule {
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn smallest_size(&self) -> Size {
        Size { cpus: 1.0, memory_bytes: GIB, disk_bytes: DISK_MIB.start() * MIB }
    }
    async fn configure(&self, name: &str, config: &ProviderConfiguration, http: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
        let settings: Settings =
            serde_json::from_value(json!(config.settings)).map_err(|e| refused(format!("invalid Runtime settings: {e}")))?;
        let api = Url::parse(&settings.api_url).ok().filter(|u| u.scheme() == "https" && u.host_str().is_some() && u.query().is_none());
        if api.is_none() || settings.tunnel_port == 0 {
            return Err(refused("Runtime requires an HTTPS api_url and a tunnel port"));
        }
        if name.contains(':') || name.len() > LABEL_LIMIT {
            return Err(refused("a Runtime provider's name becomes a label value: no ':' and at most 256 characters"));
        }
        Ok(Arc::new(Runtime {
            name: name.to_owned(),
            settings,
            http,
            dialer: self.dialer.clone(),
            tokens: Mutex::default(),
            trial: Mutex::default(),
        }))
    }
}

pub struct Runtime {
    name: String,
    settings: Settings,
    http: Arc<dyn HttpClient>,
    dialer: Arc<dyn WebSocketDialer>,
    /// Each sandbox's agent TCP token, as read back at its bootstrap. A cache
    /// only: a missing or stale entry is read from the guest again.
    tokens: Mutex<HashMap<String, Token>>,
    /// Whether `/v1/limits` last showed the account without credit.
    trial: Mutex<Option<bool>>,
}

/// The most of a refusal's text kept in an error.
const EXPLANATION_CHARS: usize = 500;
fn cut(text: &str, chars: usize) -> String {
    match text.char_indices().nth(chars) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text.to_owned(),
    }
}
/// Runtime's error body: its code, its message (with its hint), and its retry delay.
fn explanation(body: &[u8]) -> (String, String, Option<u64>) {
    let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let error = &value["error"];
    match error["code"].as_str() {
        Some(code) => {
            let mut message = error["message"].as_str().unwrap_or_default().to_owned();
            if let Some(hint) = error["hint"].as_str().filter(|h| !h.is_empty()) {
                message = format!("{message} ({hint})");
            }
            let retry = error["retryAfterMs"].as_u64().map(|ms| ms.div_ceil(1000));
            (code.to_owned(), cut(&message, EXPLANATION_CHARS), retry)
        }
        None => (String::new(), cut(String::from_utf8_lossy(body).trim(), EXPLANATION_CHARS), None),
    }
}
/// Runtime's error as the protocol's. Runtime marks what may succeed when
/// sent again unchanged (`retryable`, with `Retry-After`); those become
/// Unavailable or RateLimited so the host retries, the rest refusals.
fn failure(operation: &str, status: u16, body: &[u8], retry_after: Option<u64>) -> ProtocolError {
    let (code, message, retry) = explanation(body);
    let retry_after = retry_after.or(retry);
    let reason = if code.is_empty() {
        format!("Runtime {operation} HTTP {status}: {message}")
    } else {
        format!("Runtime {operation} HTTP {status} {code}: {message}")
    };
    let quota = code == "quota_exceeded" || code.starts_with("no_credit_") || code.ends_with("_limit_reached") || code == "daily_limit";
    match status {
        401 => ProtocolError::CredentialRejected { reason },
        402 => ProtocolError::QuotaExhausted { reason },
        403 => ProtocolError::Refused { reason: format!("permission denied; {reason}") },
        404 | 410 => ProtocolError::NotFound { reason },
        409 | 429 if quota => ProtocolError::QuotaExhausted { reason },
        429 => ProtocolError::RateLimited { reason, retry_after },
        _ if retry_after.is_some() && (400..500).contains(&status) => {
            ProtocolError::Unavailable { reason, retry_after, provider_error: None }
        }
        400..=499 => ProtocolError::Refused { reason },
        500..=599 => ProtocolError::Unavailable { reason, retry_after, provider_error: None },
        _ => ProtocolError::Internal { reason: format!("unexpected Runtime {operation} HTTP {status}"), provider_error: message },
    }
}
fn bad_response() -> ProtocolError {
    ProtocolError::Internal { reason: "incomplete Runtime response".into(), provider_error: "required field missing or invalid".into() }
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
/// Runtime's ids are UUIDs; anything else names no sandbox.
fn is_uuid(id: &str) -> bool {
    id.len() == 36
        && id
            .bytes()
            .enumerate()
            .all(|(i, b)| if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_digit() || (b'a'..=b'f').contains(&b) })
}
/// Integer microdollars as an exact USD amount.
fn micros_to_usd(micros: u128) -> String {
    format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000)
}
fn micros(v: &Value) -> Option<u128> {
    v.as_str().and_then(|s| s.parse().ok())
}

impl Runtime {
    fn api(&self, segments: &[&str]) -> Result<Url> {
        let mut url = Url::parse(&self.settings.api_url).map_err(|_| refused("invalid Runtime api_url"))?;
        url.path_segments_mut().map_err(|_| refused("invalid Runtime api_url"))?.pop_if_empty().extend(segments);
        Ok(url)
    }
    /// A sandbox's URL, with an optional `:action` on its id.
    fn sandbox_url(&self, id: &str, action: Option<&str>, rest: &[&str]) -> Result<Url> {
        if !is_uuid(id) {
            return Err(ProtocolError::NotFound { reason: "not a Runtime sandbox id".into() });
        }
        let segment = match action {
            Some(action) => format!("{id}:{action}"),
            None => id.to_owned(),
        };
        let mut url = self.api(&["sandboxes", &segment])?;
        url.path_segments_mut().map_err(|_| bad_response())?.extend(rest);
        Ok(url)
    }
    fn key<'c>(&self, c: &'c Credentials) -> Result<&'c Secret> {
        c.token().ok_or_else(|| ProtocolError::CredentialRejected { reason: "Runtime API key not delivered".into() })
    }
    fn authorization(&self, c: &Credentials) -> Result<http::HeaderValue> {
        let mut auth = http::HeaderValue::from_str(&format!("Bearer {}", self.key(c)?.expose()))
            .map_err(|_| refused("invalid Runtime API key header"))?;
        auth.set_sensitive(true);
        Ok(auth)
    }
    /// One request with the key and `extra` headers, whatever its status.
    async fn send(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
        c: &Credentials,
        extra: &[(&'static str, String)],
    ) -> Result<http::Response<bytes::Bytes>> {
        let operation = format!("{method} {}", url.path());
        let mut request = reqwest::Request::new(method, url);
        let headers = request.headers_mut();
        headers.insert(reqwest::header::AUTHORIZATION, self.authorization(c)?);
        for (name, value) in extra {
            headers.insert(*name, reqwest::header::HeaderValue::from_str(value).map_err(|_| bad_response())?);
        }
        if let Some(body) = body {
            headers.insert(reqwest::header::CONTENT_TYPE, reqwest::header::HeaderValue::from_static("application/json"));
            *request.body_mut() = Some(body.to_string().into());
        }
        rigging_http_client::http_execute!(self.http, request).map_err(|error| ProtocolError::Unavailable {
            provider_error: Some(error),
            reason: format!("Runtime {operation} transport failed"),
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
    async fn call_with(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
        c: &Credentials,
        extra: &[(&'static str, String)],
    ) -> Result<Value> {
        let operation = format!("{method} {}", url.path());
        let response = self.send(method, url, body, c, extra).await?;
        Self::answer(&operation, &response)
    }
    async fn call(&self, method: Method, url: Url, body: Option<Value>, c: &Credentials) -> Result<Value> {
        self.call_with(method, url, body, c, &[]).await
    }
    /// Every row of a `{data, nextCursor}` list, following each cursor once.
    async fn paged(&self, url: Url, c: &Credentials) -> Result<Vec<Value>> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen = BTreeSet::new();
        loop {
            let mut page_url = url.clone();
            if let Some(cursor) = &cursor {
                page_url.query_pairs_mut().append_pair("cursor", cursor);
            }
            let page = self.call(Method::GET, page_url, None, c).await?;
            all.extend(page.get("data").and_then(Value::as_array).ok_or_else(bad_response)?.iter().cloned());
            match page.get("nextCursor").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                None => return Ok(all),
                Some(next) if seen.insert(next.to_owned()) => cursor = Some(next.to_owned()),
                Some(_) => return Err(bad_response()),
            }
        }
    }
    async fn sandbox(&self, id: &str, c: &Credentials) -> Result<Value> {
        self.call(Method::GET, self.sandbox_url(id, None, &[])?, None, c).await
    }
    /// A sandbox of this instance, or NotFound: another instance's, or one
    /// without drydock's labels, is never touched.
    async fn ours(&self, id: &str, c: &Credentials) -> Result<Value> {
        let row = self.sandbox(id, c).await?;
        if row["labels"][PROVIDER_LABEL] != self.name.as_str() || row["labels"][VESSEL_LABEL].as_str().is_none() {
            return Err(ProtocolError::NotFound { reason: format!("Runtime sandbox {id} is not one of provider {}'s", self.name) });
        }
        Ok(row)
    }
    async fn network(&self, id: &str, c: &Credentials) -> Result<Value> {
        self.call(Method::GET, self.sandbox_url(id, None, &["network"])?, None, c).await
    }
    async fn limits(&self, c: &Credentials) -> Result<Value> {
        let limits = self.call(Method::GET, self.api(&["limits"])?, None, c).await?;
        *self.trial.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(trial(&limits));
        Ok(limits)
    }

    fn environment(&self, v: &Value) -> Result<Environment> {
        let id = text(v, "id")?.to_owned();
        let state = match text(v, "state")? {
            "starting" | "resuming" => Observation::Transitioning { phase: TransitionPhase::Starting },
            "running" => Observation::Running,
            "pausing" | "stopping" => Observation::Transitioning { phase: TransitionPhase::Stopping },
            "paused" => Observation::Stopped { cause: StopCause::SuspendedByRequest },
            // Stopped keeps at most the disk: every process, the agent's too, is gone.
            "stopped" => Observation::Stopped { cause: StopCause::GuestHalted },
            _ => Observation::Unknown { reason: UnknownReason::ProviderStateUnknown },
        };
        let number = |key| v.get(key).and_then(Value::as_u64).filter(|n| *n > 0);
        let granted_size = match (number("vcpu"), number("memoryMiB"), number("diskMiB")) {
            (Some(cpus), Some(memory), Some(disk)) => Some(Size { cpus: cpus as f64, memory_bytes: memory * MIB, disk_bytes: disk * MIB }),
            _ => None,
        };
        Ok(Environment {
            label: v["labels"][VESSEL_LABEL].as_str().map(str::to_owned),
            id,
            provider: self.name.clone(),
            state,
            granted_size,
            egress: Enforcement::Enforced,
            platform: Some(platform()),
            egress_measured: false,
            // The policy drydock asked for, recorded at create; inspect compares the sandbox's own.
            egress_policy: v["labels"][POLICY_LABEL].as_str().map(str::to_owned),
            timestamp: None,
        })
    }
    /// The environment as inspect reports it: the sandbox's network read
    /// back, measured when Runtime enforces the version in force and it is the
    /// one drydock asked for, and (with a probe configured) proven in the guest.
    async fn observed(&self, v: &Value, c: &Credentials) -> Result<Environment> {
        let mut row = self.environment(v)?;
        if !matches!(row.state, Observation::Running) {
            return Ok(row);
        }
        let network = match self.network(&row.id, c).await {
            Ok(network) => network,
            Err(error) => {
                tracing::warn!(provider = %self.name, environment = %row.id, error_class = error.class(), "network rules read failed");
                return Ok(row);
            }
        };
        let policy = Policy::read(&network)?;
        let enforced = network["enforced"] != false && network["enforcedVersion"].as_u64() == network["version"].as_u64();
        row.egress_policy = Some(policy.fingerprint());
        row.egress_measured = enforced;
        row.egress = if enforced { Enforcement::Enforced } else { Enforcement::Advisory };
        let Some(probe) = &self.settings.egress_probe else { return Ok(row) };
        if !enforced || policy.open() {
            return Ok(row);
        }
        let deny_all = policy.allow.is_empty() && policy.connect.is_empty();
        let script = format!("test \"$(id -u)\" = 0 && DRYDOCK_PROBE_DENY_ALL={} {}", u8::from(deny_all), shell_command(&probe.command));
        let proof = match self.run(&row.id, &script, BTreeMap::new(), c).await.and_then(Run::success) {
            Ok(output) => serde_json::from_str::<Value>(&output.stdout).unwrap_or(Value::Null),
            Err(error) => {
                tracing::warn!(provider = %self.name, environment = %row.id, error_class = error.class(), "egress measurement failed");
                row.egress_measured = false;
                return Ok(row);
            }
        };
        let confined = proof["uid"] == 0
            && proof["unlisted_canary"] == false
            && proof["raw_dns"] == false
            && (deny_all || proof["listed_direct"] == true);
        row.egress = if confined { Enforcement::Enforced } else { Enforcement::Advisory };
        Ok(row)
    }

    /// Runs `sh -c script` in the guest as root through Runtime's exec, with
    /// `env` in its environment (never echoed back) and stdin closed.
    async fn run(&self, id: &str, script: &str, env: BTreeMap<&str, String>, c: &Credentials) -> Result<Run> {
        let body = json!({"argv": ["sh", "-c", script], "user": "root", "env": env, "timeoutMs": WAIT_SECONDS * 1000});
        let v = self.call(Method::POST, self.sandbox_url(id, Some("exec"), &[])?, Some(body), c).await?;
        Ok(Run {
            exit: v.get("exitCode").and_then(Value::as_i64),
            timed_out: v["timedOut"] == true,
            stdout: v["stdout"].as_str().unwrap_or_default().to_owned(),
            stderr: v["stderr"].as_str().unwrap_or_default().to_owned(),
        })
    }
    /// Starts the agent as root, supervised, listening on the guest's
    /// loopback for the tunnel, with a token only root can read. A token
    /// file already there is kept when it holds a token, so a running agent
    /// (after a pause, or another host's bootstrap) keeps answering to it;
    /// after a stop or restart /run/drydock is gone and a fresh token is
    /// written. Whichever token the file holds is read back. The write is
    /// exclusive (`set -C`), so of two concurrent bootstraps one token wins.
    /// The token travels in the exec's environment, which Runtime never
    /// echoes, and never on an argv; the agent's environment loses it, and
    /// Runtime's identity-token credential (`RUNTIME_ID_TOKEN_REQUEST_*`),
    /// so neither the agent nor what it starts can mint Runtime identities.
    /// `--supervise` returns at once, its supervisor detached; the
    /// supervisor's lock makes this idempotent. Its argv ends with
    /// `--socket`, as the supervisor requires.
    async fn bootstrap(&self, id: &str, c: &Credentials) -> Result<Token> {
        let fresh = Token::generate().map_err(|e| ProtocolError::Internal { reason: "TCP token".into(), provider_error: e.to_string() })?;
        let script = bootstrap_script(self.settings.tunnel_port);
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
    fn forget_token(&self, id: &str) {
        self.tokens.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(id);
    }
    /// The sandbox once it runs; Runtime holds each read up to 20 s.
    async fn wait_running(&self, id: &str, c: &Credentials) -> Result<Value> {
        for _ in 0..STATE_POLLS {
            let mut url = self.sandbox_url(id, None, &[])?;
            url.query_pairs_mut().append_pair("waitFor", "running").append_pair("timeoutSeconds", "20");
            let row = self.call(Method::GET, url, None, c).await?;
            match text(&row, "state")? {
                "running" => return Ok(row),
                state @ ("stopped" | "paused") => return Err(refused(format!("Runtime sandbox {id} is {state} instead of running"))),
                _ => tokio::time::sleep(STATE_POLL).await,
            }
        }
        Err(ProtocolError::unavailable("Runtime sandbox has not started", Some(5)))
    }
    /// The egress policy Runtime holds once it enforces it.
    async fn wait_enforced(&self, id: &str, c: &Credentials) -> Result<Value> {
        for _ in 0..STATE_POLLS {
            let network = self.network(id, c).await?;
            if network["enforced"] != false && network["enforcedVersion"].as_u64() == network["version"].as_u64() {
                return Ok(network);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(ProtocolError::unavailable("Runtime has not yet enforced the sandbox's network rules", Some(5)))
    }
    /// The sandbox named `name`, stopped ones included.
    async fn by_name(&self, name: &str, c: &Credentials) -> Result<Option<Value>> {
        let mut url = self.api(&["sandboxes"])?;
        url.query_pairs_mut().append_pair("name", name).append_pair("includeStopped", "true");
        Ok(self.paged(url, c).await?.into_iter().find(|row| row["name"] == name))
    }
    /// An existing sandbox under this label is adopted only when it is this
    /// instance's, for this label, of the size and egress policy asked for.
    async fn check_existing(&self, row: &Value, label: &str, size: &Size, policy: &Policy, c: &Credentials) -> Result<()> {
        if row["labels"][PROVIDER_LABEL] != self.name.as_str() || row["labels"][VESSEL_LABEL] != label {
            return Err(refused(format!(
                "a Runtime sandbox named {} exists but is not provider {}'s for label {label}; it is left alone",
                row["name"], self.name
            )));
        }
        let existing = self.environment(row)?;
        if existing.granted_size.as_ref() != Some(size) {
            return Err(refused("an existing Runtime sandbox holds this label with a different size; provision a new label"));
        }
        let id = text(row, "id")?;
        // A stopped sandbox's rules can't be read until it runs again, so
        // its create-time policy label stands in for them.
        let same = if text(row, "state")? == "stopped" {
            row["labels"][POLICY_LABEL] == policy.fingerprint().as_str()
        } else {
            &Policy::read(&self.network(id, c).await?)? == policy
        };
        if !same {
            return Err(refused("an existing Runtime sandbox holds this label with a different egress policy; provision a new label"));
        }
        Ok(())
    }
    /// An existing sandbox as observed: one still starting is awaited and a
    /// running one bootstrapped again. Paused and stopped ones stay so.
    async fn adopt(&self, row: Value, c: &Credentials) -> Result<Environment> {
        let id = text(&row, "id")?.to_owned();
        let row = match text(&row, "state")? {
            "starting" | "resuming" => self.wait_running(&id, c).await?,
            _ => row,
        };
        if text(&row, "state")? == "running" {
            self.bootstrap(&id, c).await?;
            return self.inspect(&id, c).await;
        }
        self.environment(&row)
    }

    /// The prepared image's ready version, waiting on one still building. A
    /// failed one is reported with the tail of its build log.
    async fn image(&self, name: &str, c: &Credentials) -> Result<Option<Value>> {
        let mut url = self.api(&["images"])?;
        url.query_pairs_mut().append_pair("name", name);
        let versions = self.paged(url, c).await?;
        let mine = |state: &str| versions.iter().find(|v| v["name"] == name && v["state"] == state).cloned();
        if let Some(ready) = mine("ready") {
            return Ok(Some(ready));
        }
        match mine("building").or_else(|| mine("queued")) {
            Some(building) => self.await_build(text(&building, "id")?, c).await.map(Some),
            None => Ok(None),
        }
    }
    async fn await_build(&self, id: &str, c: &Credentials) -> Result<Value> {
        for _ in 0..BUILD_POLLS {
            let image = self.call(Method::GET, self.api(&["images", id])?, None, c).await?;
            match text(&image, "state")? {
                "ready" => return Ok(image),
                "failed" => {
                    let error = image["error"].as_str().unwrap_or("no error recorded").to_owned();
                    let log = self.build_log(id, c).await;
                    return Err(refused(format!("Runtime image build {id} failed: {error}; its build log ends:\n{log}")));
                }
                "deleting" | "deleted" => {
                    return Err(ProtocolError::unavailable(format!("Runtime image {id} was deleted while building"), None));
                }
                _ => tokio::time::sleep(BUILD_POLL).await,
            }
        }
        Err(ProtocolError::unavailable(format!("Runtime image build {id} is still running"), Some(30)))
    }
    /// The last lines of a build's log. Runtime's own error can blame its
    /// builder for a registry it could not reach; the log says what failed.
    async fn build_log(&self, id: &str, c: &Credentials) -> String {
        let mut lines: Vec<String> = Vec::new();
        let mut after = 0u64;
        for _ in 0..50 {
            let Ok(mut url) = self.api(&["images", id, "logs"]) else { break };
            url.query_pairs_mut().append_pair("after", &after.to_string()).append_pair("limit", "1000");
            let Ok(page) = self.call(Method::GET, url, None, c).await else { break };
            for line in page["lines"].as_array().into_iter().flatten() {
                lines.push(line["text"].as_str().unwrap_or_default().to_owned());
            }
            let next = page["nextAfter"].as_u64().unwrap_or(after);
            if page["done"] != false || next <= after {
                break;
            }
            after = next;
        }
        let start = lines.len().saturating_sub(LOG_TAIL_LINES);
        if lines.is_empty() { "(no build log)".into() } else { lines[start..].join("\n") }
    }
    /// Makes room for one more image when the account is at its image limit:
    /// deletes the oldest `dd-` image no visible sandbox started from, or
    /// refuses when every one is in use. Images are keyed by base image, not
    /// provider instance, so every `dd-` image this key sees qualifies,
    /// whichever instance built it. One built in the last 30 minutes is
    /// spared, as is one without a creation time: a concurrent prepare's
    /// image has no sandbox yet, and its provision would find it gone. The
    /// grace runs from `createdAt`, so a build slower than it could still be
    /// taken once ready, before its provision; that is accepted as unlikely.
    /// Eviction is best-effort: two prepares can both see room and both
    /// build, and Runtime refuses the one past the limit (409
    /// `quota_exceeded`, QuotaExhausted).
    async fn image_slot(&self, c: &Credentials) -> Result<()> {
        let limits = self.limits(c).await?;
        let Some(row) = limits["account"].as_array().into_iter().flatten().find(|row| row["limit"] == "image.count") else {
            return Ok(());
        };
        let (used, max) = (row["used"].as_u64().ok_or_else(bad_response)?, row["max"].as_u64().ok_or_else(bad_response)?);
        if used < max {
            return Ok(());
        }
        let mut url = self.api(&["sandboxes"])?;
        url.query_pairs_mut().append_pair("includeStopped", "true").append_pair("limit", "100");
        let in_use: BTreeSet<String> =
            self.paged(url, c).await?.iter().filter_map(|row| row["labels"][IMAGE_LABEL].as_str().map(str::to_owned)).collect();
        let spared_since = chrono::Utc::now() - IMAGE_GRACE;
        let mut url = self.api(&["images"])?;
        url.query_pairs_mut().append_pair("limit", "100");
        let mut candidates: Vec<Value> = self
            .paged(url, c)
            .await?
            .into_iter()
            .filter(|image| {
                image["name"].as_str().is_some_and(|name| name.starts_with("dd-") && !in_use.contains(name))
                    && matches!(image["state"].as_str(), Some("ready" | "failed"))
                    && created_at(image).is_some_and(|created| created < spared_since)
            })
            .collect();
        candidates.sort_by_key(created_at);
        let Some(oldest) = candidates.first() else {
            return Err(ProtocolError::QuotaExhausted {
                reason: format!(
                    "Runtime's account holds its limit of {max} images and every drydock image is in use or new; destroy a vessel or raise the limit"
                ),
            });
        };
        let id = text(oldest, "id")?;
        tracing::info!(provider = %self.name, image = %oldest["name"], "deleting the oldest unused prepared image to make room");
        match self.call(Method::POST, self.api(&["images", &format!("{id}:delete")])?, None, c).await {
            Ok(_) | Err(ProtocolError::NotFound { .. }) => Ok(()),
            Err(error) => Err(error),
        }
    }
    /// Builds `name` from a multi-stage Dockerfile that copies the tools
    /// image's /opt/drydock onto the base, and waits for it.
    async fn build(&self, r: &PrepareRequest, name: &str, c: &Credentials) -> Result<()> {
        self.image_slot(c).await?;
        let body = json!({"name": name, "dockerfile": dockerfile(&r.image_digest, &r.tools_digest)});
        let image = self.call(Method::POST, self.api(&["images"])?, Some(body), c).await?;
        self.await_build(text(&image, "id")?, c).await.map(drop)
    }

    fn resources(size: &Size) -> Result<(u64, u64, u64)> {
        let limit = |what: &str| refused(format!("Runtime sandbox size: {what}"));
        let cpus = size.cpus;
        if !cpus.is_finite() || cpus.fract() != 0.0 || !VCPU.contains(&(cpus as u64)) {
            return Err(limit("1 to 16 whole vCPUs"));
        }
        if !size.memory_bytes.is_multiple_of(MIB) || !MEMORY_MIB.contains(&(size.memory_bytes / MIB)) {
            return Err(limit("whole MiB of memory, 128 MiB to 64 GiB"));
        }
        if !size.disk_bytes.is_multiple_of(MIB) || !DISK_MIB.contains(&(size.disk_bytes / MIB)) {
            return Err(limit("whole MiB of disk, 3 GiB to 400 GiB"));
        }
        Ok((cpus as u64, size.memory_bytes / MIB, size.disk_bytes / MIB))
    }
    /// A create body, and its idempotency key: one per instance, label and
    /// request, so a retried provision replays its own create.
    fn create_request(&self, r: &ProvisionRequest, policy: &Policy, paid: bool) -> Result<(Value, String)> {
        let (vcpu, memory, disk) = Self::resources(&r.size)?;
        let body = json!({
            "name": sandbox_name(&self.name, &r.label),
            "labels": {
                PROVIDER_LABEL: self.name, VESSEL_LABEL: r.label, IMAGE_LABEL: r.prepared.id,
                POLICY_LABEL: policy.fingerprint(),
            },
            "image": r.prepared.id,
            "vcpu": vcpu, "memoryMiB": memory, "diskMiB": disk,
            "network": policy.body(),
            // Without credit Runtime refuses persistent sandboxes; those
            // run until the free usage ends and keep no disk once stopped.
            "persistent": paid,
            // Only drydock's suspend pauses a vessel.
            "idlePauseSeconds": 0,
        });
        let key = format!("dd-{}", &digest(&format!("{}\0{}\0{body}", self.name, r.label))[..48]);
        Ok((body, key))
    }
    async fn create(&self, body: &Value, key: &str, c: &Credentials) -> Result<http::Response<bytes::Bytes>> {
        let headers = [("idempotency-key", key.to_owned()), ("prefer", format!("wait={WAIT_SECONDS}"))];
        self.send(Method::POST, self.api(&["sandboxes"])?, Some(body.clone()), c, &headers).await
    }
}

/// The policy drydock asked for, as a fingerprint label on the sandbox.
const POLICY_LABEL: &str = "drydock.egress";

/// The bootstrap's shell script, run as root with the fresh token in
/// `DRYDOCK_TCP_TOKEN`: everything before `exec` is the token file's
/// handling, then the agent's supervisor with `--socket` last.
fn bootstrap_script(port: u16) -> String {
    format!(
        "mkdir -p /run/drydock && chmod 0700 /run/drydock && \
         if [ -e {TOKEN_FILE} ] && ! grep -Eqx '[A-Za-z0-9_-]{{43,}}={{0,2}}' {TOKEN_FILE}; then rm -f {TOKEN_FILE}; fi && \
         {{ (umask 077; set -C; printf %s \"$DRYDOCK_TCP_TOKEN\" > {TOKEN_FILE}) 2>/dev/null || true; }} && \
         echo \"{TOKEN_LINE}$(cat {TOKEN_FILE})\" && \
         exec env -u DRYDOCK_TCP_TOKEN -u RUNTIME_ID_TOKEN_REQUEST_TOKEN -u RUNTIME_ID_TOKEN_REQUEST_URL \
         /opt/drydock/drydock-agent --supervise --tcp 127.0.0.1:{port} --tcp-token-file {TOKEN_FILE} --socket /run/drydock/agent.sock"
    )
}
/// The prepared image's Dockerfile: the base, with the tools image's
/// /opt/drydock copied in, both pinned to linux/amd64.
fn dockerfile(base: &str, tools: &str) -> String {
    format!(
        "FROM --platform={platform} {tools} AS drydock_tools\nFROM --platform={platform} {base}\nCOPY --from=drydock_tools /opt/drydock/ /opt/drydock/\n",
        platform = platform()
    )
}
/// How long a freshly built image is spared from slot eviction.
const IMAGE_GRACE: chrono::TimeDelta = chrono::TimeDelta::minutes(30);
fn created_at(image: &Value) -> Option<chrono::DateTime<chrono::Utc>> {
    image["createdAt"].as_str()?.parse().ok()
}
/// The account runs without credit: `/v1/limits` says its credit is empty.
fn trial(limits: &Value) -> bool {
    limits["credit"]["state"] == "empty"
}

/// Output of one guest command.
struct Run {
    exit: Option<i64>,
    timed_out: bool,
    stdout: String,
    stderr: String,
}
impl Run {
    fn exit_code(&self) -> i32 {
        match self.exit {
            Some(code) if !self.timed_out => i32::try_from(code).unwrap_or(-1),
            _ => -1,
        }
    }
    /// Exit 0, or CommandFailed with stdout then stderr.
    fn success(self) -> Result<Self> {
        if self.exit_code() == 0 {
            return Ok(self);
        }
        Err(ProtocolError::CommandFailed {
            reason: if self.timed_out { "Runtime guest command timed out".into() } else { "Runtime guest command failed".into() },
            exit_code: self.exit_code(),
            output: Secret::new(format!("{}{}", self.stdout, self.stderr)),
        })
    }
    /// Exit 0, or for the module's own guest commands an Internal error
    /// whose cause is the output's tail, so drydockd's log shows why. Token
    /// lines are left out.
    fn started(self, what: &str) -> Result<Self> {
        if self.exit_code() == 0 {
            return Ok(self);
        }
        let output: Vec<&str> =
            self.stdout.lines().chain(self.stderr.lines()).filter(|line| !line.contains(TOKEN_LINE.trim_end())).collect();
        let output = output.join("\n");
        let tail: String = output.chars().rev().take(OUTPUT_CAUSE_CHARS).collect::<Vec<_>>().into_iter().rev().collect();
        let ended = if self.timed_out { "timed out".to_owned() } else { format!("exited {}", self.exit_code()) };
        Err(ProtocolError::Internal {
            reason: format!("Runtime guest {what} {ended}"),
            provider_error: if tail.is_empty() { "no output".into() } else { tail },
        })
    }
    fn token(&self) -> Result<Token> {
        let line = self.stdout.lines().find_map(|line| line.strip_prefix(TOKEN_LINE));
        line.and_then(|line| Token::parse(line).ok()).ok_or_else(|| ProtocolError::Internal {
            reason: "the agent's TCP token was not read back".into(),
            provider_error: String::new(),
        })
    }
}

/// Whether a registry host is plainly private: loopback, private, shared or
/// link-local IPv4, a bracketed IPv6 literal, `localhost`, a single-label
/// name, or a name under a suffix no public resolver answers. Runtime's
/// builders refuse every private address; names that resolve to one are not
/// looked up here, and fail at the build.
fn private_registry(registry: &str) -> bool {
    let host = registry.rsplit_once(':').filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit())).map_or(registry, |(h, _)| h);
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return private_ipv4(ip);
    }
    let host = host.to_ascii_lowercase();
    host.starts_with('[')
        || !host.contains('.')
        || [".localhost", ".local", ".internal", ".lan", ".home.arpa", ".test", ".invalid"].iter().any(|s| host.ends_with(s))
}
fn private_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || (a == 100 && (64..128).contains(&b))
}
/// Registry hosts as Runtime's stored logins may spell Docker Hub.
fn same_registry(stored: &str, registry: &str) -> bool {
    let normal = |r: &str| {
        let r = r.trim_start_matches("https://").trim_end_matches('/').to_ascii_lowercase();
        match r.as_str() {
            "index.docker.io" | "registry-1.docker.io" | "index.docker.io/v1" => "docker.io".to_owned(),
            _ => r,
        }
    };
    normal(stored) == normal(registry)
}

/// Runtime's network rules, in the form Runtime stores them: an allow list
/// implies `internet` (allow-only), entries lowercased without a final dot.
#[derive(Debug, Clone, PartialEq)]
struct Policy {
    internet: bool,
    allow: BTreeSet<String>,
    deny: BTreeSet<String>,
    connect: BTreeSet<String>,
}
impl Policy {
    /// The request as Runtime's rules, refusing what they cannot hold: CIDRs
    /// other than single IPv4 addresses, IPv6, private addresses, and ports
    /// Runtime never opens. A host is reachable on every port the sandbox
    /// may use (only 80 and 443 without credit); a host and port becomes a
    /// `connect` pair.
    fn request(request: &EgressRequest) -> Result<Self> {
        let EgressRequest::DenyAll { direct } = request else {
            return Ok(Self { internet: true, allow: BTreeSet::new(), deny: BTreeSet::new(), connect: BTreeSet::new() });
        };
        let mut allow = BTreeSet::new();
        let mut connect = BTreeSet::new();
        for destination in direct {
            match destination {
                Destination::Host { host } => {
                    allow.insert(host_entry(host.as_str())?);
                }
                Destination::HostPort { host, port } => {
                    if FORBIDDEN_PORTS.contains(&port.get()) {
                        return Err(refused(format!("Runtime never lets a sandbox reach port {}", port.get())));
                    }
                    connect.insert(format!("{}:{}", host_entry(host.as_str())?, port.get()));
                }
                Destination::Cidr { cidr } => {
                    let single = cidr.as_str().strip_suffix("/32").and_then(|ip| ip.parse::<Ipv4Addr>().ok());
                    let Some(ip) = single else {
                        return Err(refused("Runtime egress rules take single IPv4 addresses, not CIDR ranges"));
                    };
                    allow.insert(host_entry(&ip.to_string())?);
                }
            }
        }
        Ok(Self { internet: !allow.is_empty(), allow, deny: BTreeSet::new(), connect })
    }
    fn open(&self) -> bool {
        self.internet && self.allow.is_empty() && self.deny.is_empty()
    }
    fn body(&self) -> Value {
        let mut body = json!({"internet": self.internet});
        for (key, list) in [("allow", &self.allow), ("deny", &self.deny), ("connect", &self.connect)] {
            if !list.is_empty() {
                body[key] = json!(list);
            }
        }
        body
    }
    /// A sandbox's rules (`GET …/network`), normalised as requests are.
    fn read(network: &Value) -> Result<Self> {
        let list = |key| -> Result<BTreeSet<String>> {
            match network.get(key) {
                None | Some(Value::Null) => Ok(BTreeSet::new()),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|item| Ok(item.as_str().ok_or_else(bad_response)?.trim_end_matches('.').to_ascii_lowercase()))
                    .collect(),
                Some(_) => Err(bad_response()),
            }
        };
        let (allow, deny, connect) = (list("allow")?, list("deny")?, list("connect")?);
        let internet = network.get("internet").and_then(Value::as_bool).ok_or_else(bad_response)? || !allow.is_empty();
        Ok(Self { internet, allow, deny, connect })
    }
    fn fingerprint(&self) -> String {
        let canonical = json!([self.internet, self.allow, self.deny, self.connect]);
        digest(&canonical.to_string())[..32].to_owned()
    }
}
/// A destination host as an allow entry: a public name or IPv4 address.
fn host_entry(host: &str) -> Result<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.contains(':') || host.starts_with('[') {
        return Err(refused("Runtime egress takes no IPv6 destinations"));
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        if private_ipv4(ip) {
            return Err(refused(format!("Runtime always refuses private addresses such as {ip}")));
        }
    } else if private_registry(&host) {
        return Err(refused(format!("{host} is not a public name, and Runtime always refuses private addresses")));
    }
    Ok(host)
}

/// A vessel's sandbox name: deterministic per instance and label, so a
/// repeated provision finds the sandbox it made.
fn sandbox_name(instance: &str, label: &str) -> String {
    format!("dd-{}", &digest(&format!("{instance}\0{label}"))[..40])
}
/// The prepared image's name: one per base image and platform. The tools
/// image is not part of it: the agent in the image is a cache, upgraded by
/// the host at the first hello.
fn image_name(image: &str, platform: &Platform) -> String {
    format!("dd-{}", &digest(&format!("{image}\0{platform}"))[..40])
}
fn shell_command(command: &[String]) -> String {
    command.iter().map(|s| format!("'{}'", s.replace('\'', "'\\''"))).collect::<Vec<_>>().join(" ")
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
                enforcement: Enforcement::Enforced,
            },
            fallback_runner: true,
            bootstrap: BootstrapRoute::Bake,
            agent: true,
            platforms: vec![platform()],
            image_routes: vec![ImageRoute::RegistryPull {
                auth: RegistryAuthKind::Basic,
                registration: CredentialRegistration::ProviderApi,
                digest_references: true,
                tools_layer: ToolsLayer::Provider,
            }],
            usage: true,
            quota: true,
            host_filesystem: false,
        }
    }
    fn observation(&self) -> ObservationMode {
        ObservationMode::Poll { interval_ms: 30_000 }
    }
    fn operations(&self) -> Operations<'_> {
        Operations { exec: Some(self), suspend_resume: Some(self), usage: Some(self), quota: Some(self), ..Operations::default() }
    }
    fn rate_limits(&self) -> Vec<RateLimit> {
        // An ordinary key's bucket: 50 requests a second, in bursts of 200.
        self.settings.rate_limits.clone().unwrap_or_else(|| vec![RateLimit { operation: "*".into(), requests: 3000, period_seconds: 60 }])
    }
    /// An empty credit state stays Ready: the key works, and provision
    /// refuses what only paid funding allows, saying so.
    async fn refresh_readiness(&self, c: &Credentials) {
        if c.token().is_some()
            && let Err(error) = self.limits(c).await
        {
            tracing::warn!(provider = %self.name, error_class = error.class(), "Runtime limits read failed");
        }
    }
    async fn prepare(&self, r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
        if prepare_route(&r)? != ImageRouteKind::RegistryPull {
            return Err(refused("Runtime prepares by registry pull only"));
        }
        if !pinned(&r.image_digest) || !pinned(&r.tools_digest) {
            return Err(refused("Runtime requires base and tools images pinned by sha256 digest"));
        }
        let platform = prepare_platform(&r)?;
        let supported = self::platform();
        if platform != supported {
            return Err(ProtocolError::ImageRefused {
                reason: format!("Runtime runs only {supported} sandboxes"),
                refusal: ImageRefusal::UnsupportedPlatform { platform },
            });
        }
        let base = ImageRef::parse(&r.image_digest)?;
        // The build pulls both stages, so neither may sit on a private host.
        for registry in [&base.registry, &ImageRef::parse(&r.tools_digest)?.registry] {
            if private_registry(registry) {
                return Err(refused(format!(
                    "{registry} looks private (a private, loopback or link-local address, a single-label name or a non-public suffix), and Runtime's builders refuse private addresses; stage the image in a public registry"
                )));
            }
        }
        Self::resources(&r.size)?;
        let name = image_name(&r.image_digest, &platform);
        if self.image(&name, c).await?.is_none() {
            // A private base pulls with a login stored once in the account.
            if r.image_pull.is_some() {
                let stored = self.call(Method::GET, self.api(&["images", "registries"])?, None, c).await?;
                let known = stored["data"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|row| row["registry"].as_str().is_some_and(|s| same_registry(s, &base.registry)));
                if !known {
                    return Err(refused(format!(
                        "{} needs a pull login, and Runtime pulls only with logins stored in the account; store one with POST /v1/images/registries",
                        base.registry
                    )));
                }
            }
            self.build(&r, &name, c).await?;
        }
        Ok(Prepared { provider: self.name.clone(), id: name, platform, image_digest: r.image_digest, tools_digest: r.tools_digest })
    }
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        if r.prepared.provider != self.name {
            return Err(refused("prepared image belongs to another provider"));
        }
        if r.prepared.id != image_name(&r.prepared.image_digest, &r.prepared.platform) {
            return Err(refused("prepared image is not this provider's"));
        }
        if r.label.len() > LABEL_LIMIT {
            return Err(refused("Runtime labels hold at most 256 characters"));
        }
        let policy = Policy::request(&r.egress)?;
        let paid = !trial(&self.limits(c).await?);
        if !paid && !policy.connect.is_empty() {
            return Err(refused(
                "Runtime's account has no credit (trial funding): host:port egress rules (connect_not_allowed) need credit; sandboxes without it reach ports 80 and 443 only",
            ));
        }
        let (body, key) = self.create_request(&r, &policy, paid)?;
        let mut response = self.create(&body, &key, c).await?;
        let created: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
        // Runtime replays a create's first answer for 24 hours: the sandbox a
        // retried provision already made is adopted as any existing one, and
        // one since deleted is created again under a fresh key.
        if created["replayed"] == true
            && let Some(id) = created["id"].as_str()
        {
            match self.sandbox(id, c).await {
                Ok(row) => {
                    self.check_existing(&row, &r.label, &r.size, &policy, c).await?;
                    return Ok(Provisioned::Existing(self.adopt(row, c).await?));
                }
                Err(ProtocolError::NotFound { .. }) => {
                    let attempt = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
                    response = self.create(&body, &format!("{key}-{attempt:x}"), c).await?;
                }
                Err(error) => return Err(error),
            }
        }
        let status = response.status().as_u16();
        let created: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
        if status == 409 && created["error"]["code"] == "name_taken" {
            let name = text(&body, "name")?;
            let row = self
                .by_name(name, c)
                .await?
                .ok_or_else(|| ProtocolError::unavailable("Runtime reports the name taken but lists no sandbox by it", Some(2)))?;
            self.check_existing(&row, &r.label, &r.size, &policy, c).await?;
            return Ok(Provisioned::Existing(self.adopt(row, c).await?));
        }
        let created = Self::answer("POST /v1/sandboxes", &response)?;
        let id = text(&created, "id")?.to_owned();
        if text(&created, "state")? != "running" {
            self.wait_running(&id, c).await?;
        }
        let network = self.wait_enforced(&id, c).await?;
        if Policy::read(&network)? != policy {
            return Err(ProtocolError::Internal {
                reason: format!("Runtime sandbox {id} holds other network rules than drydock asked for"),
                provider_error: network.to_string(),
            });
        }
        self.bootstrap(&id, c).await?;
        Ok(Provisioned::Created(self.inspect(&id, c).await?))
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        let mut url = self.api(&["sandboxes"])?;
        url.query_pairs_mut()
            .append_pair("label", &format!("{PROVIDER_LABEL}:{}", self.name))
            .append_pair("includeStopped", "true")
            .append_pair("limit", "100");
        self.paged(url, c)
            .await?
            .iter()
            .filter(|row| row["labels"][PROVIDER_LABEL] == self.name.as_str() && row["labels"][VESSEL_LABEL].is_string())
            .map(|row| self.environment(row))
            .collect()
    }
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        let row = self.ours(id, c).await?;
        self.observed(&row, c).await
    }
    /// Deletes the sandbox once its labels show it is this instance's; one
    /// already gone is success. Its prepared image stays for later vessels.
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        let row = match self.sandbox(id, c).await {
            Ok(row) => row,
            Err(ProtocolError::NotFound { .. }) => {
                self.forget_token(id);
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if row["labels"][PROVIDER_LABEL] != self.name.as_str() || row["labels"][VESSEL_LABEL].as_str().is_none() {
            return Err(refused(format!("Runtime sandbox {id} is not one of provider {}'s; it is left alone", self.name)));
        }
        match self.call(Method::DELETE, self.sandbox_url(id, None, &[])?, None, c).await {
            Ok(_) | Err(ProtocolError::NotFound { .. }) => {}
            Err(error) => return Err(error),
        }
        self.forget_token(id);
        Ok(())
    }
    async fn reach(&self, id: &str, _: &Credentials) -> Result<Reach> {
        Ok(Reach::relay(&self.name, id))
    }
    /// The agent's connection through Runtime's tunnel. A sandbox that is not
    /// running is refused: the tunnel would wake a paused one, and reach
    /// never resumes. When nothing listens on the agent's port (its sandbox
    /// restarted underneath), the agent is bootstrapped again, once.
    async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream> {
        let row = match self.ours(id, c).await {
            Ok(row) => row,
            Err(error @ ProtocolError::NotFound { .. }) => {
                self.forget_token(id);
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let state = text(&row, "state")?;
        if state != "running" {
            return Err(refused(format!("Runtime sandbox {id} is {state}, not running; resume it first")));
        }
        let mut url = self.sandbox_url(id, None, &["tunnel"])?;
        let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
        url.set_scheme(scheme).map_err(|_| bad_response())?;
        let headers = HeaderMap::from_iter([(http::header::AUTHORIZATION, self.authorization(c)?)]);
        let (url, headers) = (url.to_string(), &headers);
        let connect = |token: Token| {
            let url = url.clone();
            async move {
                let stream = tunnel::open(self.dialer.clone(), url, headers.clone(), self.settings.tunnel_port).await;
                match stream {
                    Ok(stream) => Ok(Ok(tcp::connect(stream, &token).await)),
                    Err(tunnel::OpenError::NotOpened { reason }) => Ok(Err(reason)),
                    Err(error) => Err(tunnel_failure(error)),
                }
            }
        };
        let mut connected = match connect(self.token(id, c).await?).await? {
            Ok(connected) => connected,
            Err(reason) => {
                tracing::info!(provider = %self.name, environment = %id, %reason, "nothing listens on the agent's port; bootstrapping again");
                self.forget_token(id);
                let token = self.bootstrap(id, c).await?;
                connect(token).await?.map_err(|reason| ProtocolError::Unavailable {
                    reason: "nothing listens on the agent's TCP port after a fresh bootstrap".into(),
                    retry_after: Some(5),
                    provider_error: Some(reason),
                })?
            }
        };
        // A token cached before another bootstrap replaced the file: read it again, once.
        if connected.as_ref().is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied) {
            self.forget_token(id);
            connected = connect(self.token(id, c).await?).await?.unwrap_or_else(|reason| Err(std::io::Error::other(reason)));
        }
        connected.map(|stream| Box::new(stream) as ByteStream).map_err(|error| ProtocolError::Unavailable {
            reason: "the agent's TCP listener did not accept the tunnel".into(),
            retry_after: None,
            provider_error: Some(error.to_string()),
        })
    }
}
/// A tunnel that did not open, as the protocol's error.
fn tunnel_failure(error: tunnel::OpenError) -> ProtocolError {
    match error {
        tunnel::OpenError::Dial(DialError::Refused { status, body }) => failure("tunnel", status, body.as_bytes(), None),
        tunnel::OpenError::Refused { code, message }
            if matches!(code.as_str(), "sandbox_not_running" | "sandbox_paused" | "sandbox_stopped") =>
        {
            refused(format!("Runtime tunnel {code}: {message}"))
        }
        error => ProtocolError::Unavailable {
            reason: "Runtime tunnel failed".into(),
            retry_after: None,
            provider_error: Some(error.to_string()),
        },
    }
}

#[async_trait]
impl SuspendResume for Runtime {
    /// Pauses the sandbox, keeping its memory and processes, the agent's
    /// included, and returns the deterministic marker.
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        let state = text(&self.ours(id, c).await?, "state")?.to_owned();
        if matches!(state.as_str(), "starting" | "resuming") {
            return Err(ProtocolError::unavailable(format!("Runtime sandbox {id} is {state}"), Some(5)));
        }
        if state == "running" {
            let headers = [("prefer", format!("wait={WAIT_SECONDS}"))];
            self.call_with(Method::POST, self.sandbox_url(id, Some("pause"), &[])?, None, c, &headers).await?;
        }
        for _ in 0..STATE_POLLS {
            match text(&self.sandbox(id, c).await?, "state")? {
                "paused" | "stopped" => return Ok(ResumeToken { token: Secret::new(resume_marker(&self.name, id)) }),
                "pausing" | "running" => tokio::time::sleep(STATE_POLL).await,
                other => return Err(refused(format!("Runtime sandbox {id} is {other}, not pausing"))),
            }
        }
        Err(ProtocolError::unavailable("Runtime sandbox has not paused", Some(5)))
    }
    /// Wakes a paused sandbox (or restarts a stopped one from its disk),
    /// then bootstraps: a no-op for an agent the pause kept, a fresh token
    /// and agent after a stop.
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()> {
        if token.token.expose() != resume_marker(&self.name, id) {
            return Err(refused("resume token belongs to another environment"));
        }
        let state = text(&self.ours(id, c).await?, "state")?.to_owned();
        let action = match state.as_str() {
            "paused" | "pausing" => Some("wake"),
            "stopped" => Some("restart"),
            _ => None,
        };
        if let Some(action) = action {
            if action == "restart" {
                self.forget_token(id);
            }
            let headers = [("prefer", format!("wait={WAIT_SECONDS}"))];
            self.call_with(Method::POST, self.sandbox_url(id, Some(action), &[])?, None, c, &headers).await?;
        }
        self.wait_running(id, c).await?;
        self.bootstrap(id, c).await?;
        Ok(())
    }
}
/// A deterministic continuation marker binding instance and sandbox; not a
/// credential, since every resume still needs the key.
fn resume_marker(instance: &str, id: &str) -> String {
    format!("runtime-resume-{}", &digest(&format!("{instance}\0{id}"))[..40])
}

#[async_trait]
impl Exec for Runtime {
    /// Stdout then stderr, as text, at most 64 KiB of each (Runtime's limit
    /// for an unstreamed command).
    async fn exec(&self, id: &str, r: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        self.ours(id, c).await?;
        let run = self.run(id, &shell_command(&r.command), BTreeMap::new(), c).await?.success()?;
        Ok(Box::new(std::io::Cursor::new(format!("{}{}", run.stdout, run.stderr).into_bytes())))
    }
}

#[async_trait]
impl QuotaOperation for Runtime {
    /// The account's limits on what runs at once, and its credit.
    async fn quota(&self, c: &Credentials) -> Result<Quota> {
        let limits = self.limits(c).await?;
        let mut resources = Vec::new();
        let (mut in_use, mut limit) = (None, None);
        for row in limits["account"].as_array().into_iter().flatten() {
            let (Some(used), Some(max)) = (row["used"].as_u64(), row["max"].as_u64()) else { return Err(bad_response()) };
            let (resource, unit, factor) = match row["limit"].as_str() {
                Some("sandbox.count") => {
                    (in_use, limit) = (Some(used), Some(max));
                    (ResourceKind::Environments, "1", 1.0)
                }
                Some("sandbox.vcpu") => (ResourceKind::Cpu, "{vCPU}", 1.0),
                Some("sandbox.memory_mib") => (ResourceKind::Memory, "By", MIB as f64),
                Some("sandbox.disk_mib") => (ResourceKind::Disk, "By", MIB as f64),
                _ => continue,
            };
            resources.push(ResourceQuota {
                key: QuotaKey { region: None, class: None, resource },
                unit: unit.into(),
                in_use: used as f64 * factor,
                limit: Some(max as f64 * factor),
            });
        }
        let credit = micros(&limits["credit"]["availableMicros"]).ok_or_else(bad_response)?;
        Ok(Quota {
            resources,
            credits_remaining: Some(credit as f64 / 1e6),
            credit_unit: Some("USD".into()),
            concurrency_in_use: in_use,
            concurrency_limit: limit,
        })
    }
}

#[async_trait]
impl UsageOperation for Runtime {
    /// Settled charges over the period, from Runtime's usage export: the
    /// cost in USD from charged microdollars and the sandboxes charged.
    /// Rows carry no sizes, so no environment hours are inferred; pending
    /// holds are not settled and are left out.
    async fn usage(&self, period: Period, c: &Credentials) -> Result<Usage> {
        let stamp = |t: &Timestamp| t.instant().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut url = self.api(&["usage", "export"])?;
        url.query_pairs_mut()
            .append_pair("since", &stamp(period.start()))
            .append_pair("until", &stamp(period.end()))
            .append_pair("limit", "500");
        let rows = self.paged(url, c).await?;
        let mut charged = 0u128;
        let mut sandboxes = BTreeSet::new();
        for row in &rows {
            charged += micros(&row["chargedMicros"]).ok_or_else(bad_response)?;
            if row["kind"] == "sandbox" {
                sandboxes.insert(text(row, "resourceId")?.to_owned());
            }
        }
        let resources = BTreeMap::from([(ResourceKind::Environments, Quantity { amount: sandboxes.len() as f64, unit: "1".into() })]);
        Ok(Usage {
            period,
            environment_hours: vec![],
            measurements: Some(UsageMeasurements {
                scope: UsageScope::Provider,
                resources,
                cost: Some(Cost { amount: micros_to_usd(charged), currency: "USD".into() }),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::generators as gs;

    // Names are what Runtime accepts (letters, digits, dot, dash, underscore,
    // at most 128) and distinct per instance and label; image names per base and platform.
    #[hegel::test]
    fn names_are_runtime_handles(tc: hegel::TestCase) {
        let label = tc.draw(gs::text().max_size(80));
        let name = sandbox_name("runtime", &label);
        assert!(name.len() <= 128 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        assert_ne!(name, sandbox_name("runtime-2", &label));
        assert_ne!(name, sandbox_name("runtime", &format!("{label}x")));
        assert_ne!(image_name("a", &platform()), image_name("a", &Platform::new("linux", "arm64")));
    }
    // A request's rules read back equal from Runtime's stored form, so
    // re-adoption matches: an allow list implies internet, names lose case
    // and a final dot, a /32 is its address. Open is internet with nothing listed.
    #[hegel::test]
    fn policies_read_back_as_requested(tc: hegel::TestCase) {
        let pool = ["example.com", "Example.COM.", "192.0.2.7", "198.51.100.9/32", "api.github.com"];
        let picks = tc.draw(gs::vecs(gs::integers::<usize>().max_value(pool.len() - 1)).max_size(4));
        let port = tc.draw(gs::booleans());
        let mut direct: Vec<Destination> = picks
            .iter()
            .map(|i| match pool[*i] {
                entry if entry.contains('/') => Destination::Cidr { cidr: entry.parse().unwrap() },
                entry => Destination::Host { host: entry.parse().unwrap() },
            })
            .collect();
        if port {
            direct.push(Destination::HostPort { host: "db.example.com".parse().unwrap(), port: Port::new(5432).unwrap() });
        }
        let request = Policy::request(&EgressRequest::DenyAll { direct }).unwrap();
        let body = request.body();
        assert_eq!(body["internet"], !picks.is_empty());
        assert_eq!(body.get("connect").is_some(), port);
        let stored =
            json!({"internet": body["internet"], "allow": body.get("allow"), "deny": [], "connect": body.get("connect"), "version": 1});
        assert_eq!(Policy::read(&stored).unwrap(), request);
        assert_eq!(Policy::read(&stored).unwrap().fingerprint(), request.fingerprint());
        // Runtime stores `internet: false` with an allow list as internet true.
        let mut flipped = stored.clone();
        flipped["internet"] = json!(false);
        assert_eq!(Policy::read(&flipped).unwrap(), request);
        let open = Policy::request(&EgressRequest::Open).unwrap();
        assert!(open.open() && open.body() == json!({"internet": true}));
    }
    // Ranges, IPv6, private addresses and never-open ports are refused rather than widened.
    #[test]
    fn unrepresentable_destinations_are_refused() {
        for destination in [
            Destination::Cidr { cidr: "10.0.0.0/8".parse().unwrap() },
            Destination::Cidr { cidr: "203.0.113.0/24".parse().unwrap() },
            Destination::Cidr { cidr: "2001:db8::/32".parse().unwrap() },
            Destination::Host { host: "2001:db8::1".parse().unwrap() },
            Destination::Host { host: "10.1.2.3".parse().unwrap() },
            Destination::Host { host: "forgejo.lab.internal".parse().unwrap() },
            Destination::HostPort { host: "mail.example.com".parse().unwrap(), port: Port::new(25).unwrap() },
        ] {
            assert!(Policy::request(&EgressRequest::DenyAll { direct: vec![destination.clone()] }).is_err(), "{destination:?}");
        }
    }
    // Runtime's errors become the protocol's by status and code, keeping its
    // message; retryable refusals carry their delay.
    #[test]
    fn errors_map_by_status_and_code() {
        let body = |code: &str, retry: Option<u64>| {
            json!({"error": {"code": code, "status": 0, "message": "m", "requestId": "r", "hint": "h", "retryable": retry.is_some(), "retryAfterMs": retry}})
                .to_string()
        };
        let map = |status, code: &str, retry| failure("op", status, body(code, retry).as_bytes(), None);
        assert!(matches!(map(401, "unauthorized", None), ProtocolError::CredentialRejected { .. }));
        assert!(matches!(map(402, "spending_limit_reached", None), ProtocolError::QuotaExhausted { .. }));
        assert!(matches!(map(409, "quota_exceeded", None), ProtocolError::QuotaExhausted { .. }));
        assert!(matches!(map(429, "rate_limited", Some(1500)), ProtocolError::RateLimited { retry_after: Some(2), .. }));
        assert!(matches!(map(503, "no_capacity", Some(1000)), ProtocolError::Unavailable { retry_after: Some(1), .. }));
        assert!(matches!(map(409, "image_building", Some(5000)), ProtocolError::Unavailable { retry_after: Some(5), .. }));
        assert!(matches!(map(409, "name_taken", None), ProtocolError::Refused { .. }));
        match map(403, "connect_not_allowed", None) {
            ProtocolError::Refused { reason } => assert!(reason.contains("connect_not_allowed: m (h)"), "{reason}"),
            other => panic!("{other:?}"),
        }
    }
    #[test]
    fn micros_are_exact_dollars() {
        assert_eq!(micros_to_usd(0), "0.000000");
        assert_eq!(micros_to_usd(1_234_567), "1.234567");
        assert_eq!(micros_to_usd(50_000_000), "50.000000");
    }
}

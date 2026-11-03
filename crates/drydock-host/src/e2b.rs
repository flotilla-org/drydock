//! Stateless E2B translator: Firecracker sandboxes from templates E2B builds
//! from our image by digest, reached through E2B's port proxy to the agent's
//! token-gated TCP listener. The host owns inventory and retries.
//! API contract: https://github.com/e2b-dev/infra (spec/openapi.yml for the
//! control plane; packages/envd/spec for the in-guest daemon, whose process
//! service is Connect-RPC with JSON bodies), checked 2026-11-03, and the live
//! probe of 2026-11-01 (drydock#191).
use crate::{
    module::*,
    oci::{ImageRef, Registry},
};
use async_trait::async_trait;
use drydock_protocol::*;
use drydock_transport::{
    tcp::{self, CONNECT_PATH, Token},
    websocket::{StreamDialer, TlsDialer},
};
use reqwest::{Method, Url};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    time::Duration,
};

const MIB: u64 = 1 << 20;
/// envd's port in every sandbox.
const ENVD_PORT: u16 = 49983;
/// The guest port the agent's TCP listener binds, published by E2B's proxy.
const AGENT_PORT: u16 = 7811;
const TOKEN_FILE: &str = "/run/drydock/tcp.token";
const TOKEN_LINE: &str = "drydock-tcp-token ";
/// The proxy's own gate in front of every published port but envd's.
const TRAFFIC_HEADER: &str = "e2b-traffic-access-token";
/// Sandbox metadata naming the drydock instance and the vessel's label. A
/// sandbox is ours only when it carries both (drydock#168).
const PROVIDER_TAG: &str = "drydock.provider";
const LABEL_TAG: &str = "flotilla.label";
/// Guest commands must finish inside the host's 30-second HTTP deadline;
/// envd kills a process whose stream outlives its Connect deadline.
const RUN_TIMEOUT_MS: u64 = 25_000;
/// Builds took 13 to 36 s in the probe. The daemon gives prepare 600 s, so a
/// build still running after about 7.5 minutes is Unavailable, and the
/// retried prepare rejoins it rather than starting another.
const BUILD_POLL: Duration = Duration::from_secs(3);
const BUILD_POLLS: u32 = 150;
const STATE_POLL: Duration = Duration::from_secs(1);
const STATE_POLLS: u32 = 60;
/// The largest tools layer uploaded as a build's COPY context.
const TOOLS_LAYER_LIMIT: u64 = 256 << 20;
/// How much of a failed command's or build's output an error carries.
const OUTPUT_CAUSE_CHARS: usize = 500;
/// The most of a refusal's text kept in an error.
const EXPLANATION_CHARS: usize = 500;
/// Pages of sandbox events read for one usage period.
const EVENT_PAGES: usize = 100;

/// Resolves a registry's host name, so prepare can refuse one E2B's builders
/// cannot reach before any build starts.
#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}
/// The system resolver, bounded to five seconds.
pub struct SystemResolver;
#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        let lookup = tokio::net::lookup_host((host, 443));
        match tokio::time::timeout(Duration::from_secs(5), lookup).await {
            Ok(addresses) => Ok(addresses?.map(|a| a.ip()).collect()),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "lookup timed out")),
        }
    }
}

/// The module, with the dialer its relays open (TLS in production, an
/// in-process stand-in in tests) and the resolver prepare checks registry
/// hosts with.
pub struct E2bModule {
    dialer: Arc<dyn StreamDialer>,
    resolver: Arc<dyn Resolver>,
}
impl E2bModule {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self::with_parts(Arc::new(TlsDialer::new()?), Arc::new(SystemResolver)))
    }
    pub fn with_parts(dialer: Arc<dyn StreamDialer>, resolver: Arc<dyn Resolver>) -> Self {
        Self { dialer, resolver }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// The team the key belongs to, for its concurrency metrics.
    team_id: String,
    #[serde(default = "api_url")]
    api_url: String,
    /// Sandbox ports are published at `<port>-<sandbox>.<domain>`.
    #[serde(default = "domain")]
    domain: String,
    /// Each sandbox's timeout, after which it pauses. Hobby caps running at
    /// one hour and refuses a longer timeout at create; Pro allows 24 hours.
    #[serde(default = "lifetime_seconds")]
    lifetime_seconds: u32,
    /// The plan's sandbox disk, which E2B sets per team, not per sandbox.
    #[serde(default = "disk_mb")]
    disk_mb: u64,
    /// The team's concurrent sandbox limit: an API key cannot read it.
    #[serde(default)]
    concurrency_limit: Option<u64>,
    /// E2B publishes no per-team rate limits.
    #[serde(default)]
    rate_limits: Option<Vec<RateLimit>>,
    /// Operator-supplied egress conformance command, run as root; see Daytona's.
    #[serde(default)]
    egress_probe: Option<ExecRequest>,
}
fn api_url() -> String {
    "https://api.e2b.app/".into()
}
fn domain() -> String {
    "e2b.app".into()
}
fn lifetime_seconds() -> u32 {
    3600
}
fn disk_mb() -> u64 {
    10_240
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
            serde_json::from_value(json!(config.settings)).map_err(|e| refused(format!("invalid E2B settings: {e}")))?;
        let api = Url::parse(&settings.api_url).ok().filter(|u| {
            u.scheme() == "https" && u.host_str().is_some() && u.query().is_none() && u.username().is_empty() && u.password().is_none()
        });
        if api.is_none()
            || settings.team_id.is_empty()
            || !(1..=86_400).contains(&settings.lifetime_seconds)
            || settings.disk_mb == 0
            || settings.domain.is_empty()
            || !settings.domain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(refused(
                "E2B requires team_id, an HTTPS api_url, a domain host name, lifetime_seconds 1..86400 and a positive disk_mb",
            ));
        }
        Ok(Arc::new(E2b {
            name: name.to_owned(),
            settings,
            http,
            dialer: self.dialer.clone(),
            resolver: self.resolver.clone(),
            access: Mutex::default(),
            suspended: Mutex::default(),
        }))
    }
}

/// What reaching one sandbox takes. E2B hands the envd and traffic tokens to
/// whoever creates or connects to the sandbox; the agent's token is read from
/// the guest. All are kept in this host's memory only, never in a record or
/// a log; a missing one is fetched again.
#[derive(Clone, Default)]
struct Access {
    envd: Option<String>,
    traffic: Option<String>,
    agent: Option<Token>,
}

pub struct E2b {
    name: String,
    settings: Settings,
    http: Arc<dyn HttpClient>,
    dialer: Arc<dyn StreamDialer>,
    resolver: Arc<dyn Resolver>,
    access: Mutex<HashMap<String, Access>>,
    /// Sandboxes this host paused, so their pause reads as requested; E2B
    /// records no cause, and any other pause is its lifetime cap's.
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

enum Auth<'a> {
    /// The team API key, for the control plane.
    Key,
    /// envd's token and the root user, for the in-guest daemon.
    Envd(Option<&'a str>),
    /// A signed upload URL carries its own authorization.
    Signed(&'a BTreeMap<String, String>),
}

/// The text of a refusal: E2B's JSON `message`, else the body, cut to its start.
fn explanation(body: &[u8]) -> String {
    let text = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| String::from_utf8_lossy(body).trim().to_owned());
    cut(&text)
}
fn cut(text: &str) -> String {
    match text.char_indices().nth(EXPLANATION_CHARS) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text.to_owned(),
    }
}
/// The status's protocol error, keeping what E2B said.
fn failure(operation: &str, status: u16, body: &[u8], retry_after: Option<u64>) -> ProtocolError {
    let text = explanation(body);
    let reason = format!("E2B {operation} HTTP {status}: {text}");
    match status {
        // The team's concurrency limit is a quota, not a request rate.
        429 if text.to_ascii_lowercase().contains("concurrent") => ProtocolError::QuotaExhausted { reason },
        400 | 409 | 422 => ProtocolError::Refused { reason },
        401 => ProtocolError::CredentialRejected { reason },
        402 => ProtocolError::QuotaExhausted { reason },
        403 => ProtocolError::Refused { reason: format!("permission denied; {reason}") },
        404 => ProtocolError::NotFound { reason },
        429 => ProtocolError::RateLimited { reason, retry_after },
        408 | 500..=599 => ProtocolError::Unavailable { reason, retry_after, provider_error: None },
        _ => ProtocolError::Internal { reason: format!("unexpected E2B {operation} HTTP {status}"), provider_error: text },
    }
}
fn bad_response() -> ProtocolError {
    ProtocolError::Internal { reason: "incomplete E2B response".into(), provider_error: "required field missing or invalid".into() }
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
/// Sandbox ids are lowercase alphanumerics; anything else never names one,
/// and must not reach a host name.
fn sandbox_id_valid(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

impl E2b {
    fn api(&self, segments: &[&str]) -> Result<Url> {
        let mut url = Url::parse(&self.settings.api_url).map_err(|_| refused("invalid E2B api_url"))?;
        url.path_segments_mut().map_err(|_| refused("invalid E2B api_url"))?.pop_if_empty().extend(segments);
        Ok(url)
    }
    /// A published port of a sandbox: `https://<port>-<id>.<domain>`.
    fn port_url(&self, id: &str, port: u16, path: &str) -> Result<Url> {
        if !sandbox_id_valid(id) {
            return Err(ProtocolError::NotFound { reason: "not an E2B sandbox id".into() });
        }
        Url::parse(&format!("https://{port}-{id}.{}{path}", self.settings.domain)).map_err(|_| bad_response())
    }
    async fn send(
        &self,
        method: Method,
        url: Url,
        body: Option<(Vec<u8>, &str)>,
        c: &Credentials,
        auth: Auth<'_>,
    ) -> Result<http::Response<bytes::Bytes>> {
        use reqwest::header::{HeaderName, HeaderValue};
        let operation = format!("{method} {}", url.path());
        let mut request = reqwest::Request::new(method, url);
        let headers = request.headers_mut();
        let secret = |value: &str| {
            let mut value = HeaderValue::from_str(value).map_err(|_| refused("invalid E2B credential header"))?;
            value.set_sensitive(true);
            Ok::<_, ProtocolError>(value)
        };
        match auth {
            Auth::Key => {
                let key = c.token().ok_or_else(|| ProtocolError::CredentialRejected { reason: "E2B API key not delivered".into() })?;
                headers.insert("x-api-key", secret(key.expose())?);
            }
            Auth::Envd(token) => {
                if let Some(token) = token {
                    headers.insert("x-access-token", secret(token)?);
                }
                // envd picks the process's user from Basic `user:`; root has
                // every capability.
                headers.insert(reqwest::header::AUTHORIZATION, HeaderValue::from_static("Basic cm9vdDo="));
                headers.insert("connect-timeout-ms", HeaderValue::from(RUN_TIMEOUT_MS));
            }
            Auth::Signed(extra) => {
                for (name, value) in extra {
                    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| bad_response())?;
                    headers.insert(name, HeaderValue::from_str(value).map_err(|_| bad_response())?);
                }
            }
        }
        if let Some((bytes, content_type)) = body {
            if !content_type.is_empty() {
                headers.insert(reqwest::header::CONTENT_TYPE, HeaderValue::from_str(content_type).map_err(|_| bad_response())?);
            }
            *request.body_mut() = Some(bytes.into());
        }
        rigging_http_client::http_execute!(self.http, request).map_err(|error| ProtocolError::Unavailable {
            provider_error: Some(error),
            reason: format!("E2B {operation} transport failed"),
            retry_after: None,
        })
    }
    /// The JSON of a 2xx answer (Null when empty); any other status as its error.
    fn answer(operation: &str, response: &http::Response<bytes::Bytes>) -> Result<Value> {
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            let retry_after = response.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse().ok());
            return Err(failure(operation, status, response.body(), retry_after));
        }
        if response.body().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(response.body()).map_err(|_| bad_response())
    }
    async fn call(&self, method: Method, url: Url, body: Option<Value>, c: &Credentials) -> Result<Value> {
        let operation = format!("{method} {}", url.path());
        let body = body.map(|b| (b.to_string().into_bytes(), "application/json"));
        let response = self.send(method, url, body, c, Auth::Key).await?;
        Self::answer(&operation, &response)
    }
    fn remember(&self, id: &str, update: impl FnOnce(&mut Access)) {
        update(self.access.recover().entry(id.to_owned()).or_default());
    }
    fn cached(&self, id: &str) -> Access {
        self.access.recover().get(id).cloned().unwrap_or_default()
    }
    /// Keeps the tokens a create or connect answer carries.
    fn keep_tokens(&self, id: &str, sandbox: &Value) {
        let envd = sandbox.get("envdAccessToken").and_then(Value::as_str).map(str::to_owned);
        let traffic = sandbox.get("trafficAccessToken").and_then(Value::as_str).map(str::to_owned);
        self.remember(id, |access| {
            access.envd = envd.or(access.envd.take());
            access.traffic = traffic.or(access.traffic.take());
        });
    }
    /// The sandbox's detail; its envd token is kept.
    async fn detail(&self, id: &str, c: &Credentials) -> Result<Value> {
        if !sandbox_id_valid(id) {
            return Err(ProtocolError::NotFound { reason: "not an E2B sandbox id".into() });
        }
        let detail = self.call(Method::GET, self.api(&["sandboxes", id])?, None, c).await?;
        if let Some(envd) = detail.get("envdAccessToken").and_then(Value::as_str) {
            let envd = envd.to_owned();
            self.remember(id, |access| access.envd = Some(envd));
        }
        Ok(detail)
    }
    fn ours(&self, row: &Value) -> bool {
        row["metadata"][PROVIDER_TAG].as_str() == Some(&self.name)
    }
    fn label(&self, row: &Value) -> Option<String> {
        self.ours(row).then(|| row.get("metadata")?.get(LABEL_TAG)?.as_str().map(str::to_owned)).flatten()
    }
    fn environment(&self, v: &Value) -> Result<Environment> {
        let id = text(v, "sandboxID")?.to_owned();
        let state = match text(v, "state")? {
            "running" => Observation::Running,
            "paused" if self.suspended.recover().contains(&id) => Observation::Stopped { cause: StopCause::SuspendedByRequest },
            // The lifetime cap pauses rather than kills (autoPause).
            "paused" => Observation::Stopped { cause: StopCause::PausedByProvider },
            _ => Observation::Unknown { reason: UnknownReason::ProviderStateUnknown },
        };
        let number = |key| v.get(key).and_then(Value::as_u64).filter(|n| *n > 0);
        let granted_size = match (number("cpuCount"), number("memoryMB"), number("diskSizeMB")) {
            (Some(cpus), Some(memory), Some(disk)) => Some(Size { cpus: cpus as f64, memory_bytes: memory * MIB, disk_bytes: disk * MIB }),
            _ => None,
        };
        // A listed row carries no network; the caller reads the detail for it.
        let egress_policy = v.get("network").map(|network| Policy::read(network).fingerprint());
        Ok(Environment {
            label: self.label(v),
            id,
            provider: self.name.clone(),
            state,
            granted_size,
            egress: Enforcement::Enforced,
            platform: Some(platform()),
            egress_measured: false,
            egress_policy,
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
            egress: Enforcement::Enforced,
            platform: Some(platform()),
            egress_measured: false,
            egress_policy: None,
            timestamp: None,
        }
    }
    /// The environment, with its egress claim measured when a probe is
    /// configured and the sandbox runs under a restricted policy.
    async fn observed(&self, v: &Value, c: &Credentials) -> Result<Environment> {
        let mut row = self.environment(v)?;
        let policy = Policy::read(v.get("network").unwrap_or(&Value::Null));
        let (Some(probe), false, Observation::Running) = (&self.settings.egress_probe, policy.open(), &row.state) else {
            return Ok(row);
        };
        let deny_all = policy.allow_out.is_empty();
        let script = format!("test \"$(id -u)\" = 0 && DRYDOCK_PROBE_DENY_ALL={} {}", u8::from(deny_all), shell_command(&probe.command));
        let proof = match self.run(&row.id, &script, BTreeMap::new(), c).await.and_then(Run::success) {
            Ok(run) => serde_json::from_slice::<Value>(&run.stdout()).unwrap_or(Value::Null),
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

    /// Runs `sh -c script` in the guest as root through envd's process
    /// service (Connect-RPC, server streaming, JSON envelopes), stdin closed.
    /// `env` rides in the request, never on argv.
    async fn run(&self, id: &str, script: &str, env: BTreeMap<&str, String>, c: &Credentials) -> Result<Run> {
        let message = json!({"process": {"cmd": "/bin/sh", "args": ["-c", script], "envs": env}, "stdin": false});
        let url = self.port_url(id, ENVD_PORT, "/process.Process/Start")?;
        let operation = format!("POST {}", url.path());
        for attempt in 0..2 {
            // A token held from before may be refused: the sandbox's is read again, once.
            let envd = match self.cached(id).envd {
                Some(token) if attempt == 0 => Some(token),
                _ => {
                    self.detail(id, c).await?;
                    self.cached(id).envd
                }
            };
            let body = (envelope(0, &message), "application/connect+json");
            let response = self.send(Method::POST, url.clone(), Some(body), c, Auth::Envd(envd.as_deref())).await?;
            if response.status().is_success() {
                return Run::parse(response.body());
            }
            if response.status() != 401 || attempt == 1 {
                return Err(failure(&operation, response.status().as_u16(), response.body(), None));
            }
        }
        unreachable!("the second attempt always returns")
    }
    /// Starts the agent as root, supervised, listening on the guest's
    /// interface for E2B's proxy, with a token only root can read. A token
    /// file already there is kept when it holds a token, so a running agent
    /// (after resume, or another host's bootstrap) keeps answering to it;
    /// whichever token the file holds is read back. The write is exclusive
    /// (`set -C`): of two concurrent bootstraps one token wins and both read
    /// it back. `--supervise` returns at once, its supervisor detached with
    /// output to its log; the supervisor's lock makes a rerun idempotent. Its
    /// argv ends with `--socket`, as the supervisor requires.
    async fn bootstrap(&self, id: &str, c: &Credentials) -> Result<Token> {
        let fresh = Token::generate().map_err(|e| ProtocolError::Internal { reason: "TCP token".into(), provider_error: e.to_string() })?;
        let script = format!(
            "mkdir -p /run/drydock /workspace && chmod 0700 /run/drydock && \
             if [ -e {TOKEN_FILE} ] && ! grep -Eqx '[A-Za-z0-9_-]{{43,}}={{0,2}}' {TOKEN_FILE}; then rm -f {TOKEN_FILE}; fi && \
             {{ (umask 077; set -C; printf %s \"$DRYDOCK_TCP_TOKEN\" > {TOKEN_FILE}) 2>/dev/null || true; }} && \
             echo \"{TOKEN_LINE}$(cat {TOKEN_FILE})\" && \
             exec env -u DRYDOCK_TCP_TOKEN /opt/drydock/drydock-agent --supervise \
             --tcp 0.0.0.0:{AGENT_PORT} --tcp-token-file {TOKEN_FILE} --socket /run/drydock/agent.sock"
        );
        let run =
            self.run(id, &script, BTreeMap::from([("DRYDOCK_TCP_TOKEN", fresh.secret().to_owned())]), c).await?.started("bootstrap")?;
        let token = run.token()?;
        self.remember(id, |access| access.agent = Some(token.clone()));
        Ok(token)
    }
    async fn agent_token(&self, id: &str, refresh: bool, c: &Credentials) -> Result<Token> {
        if !refresh && let Some(token) = self.cached(id).agent {
            return Ok(token);
        }
        let run = self.run(id, &format!("echo \"{TOKEN_LINE}$(cat {TOKEN_FILE})\""), BTreeMap::new(), c).await?.started("token read")?;
        let token = run.token()?;
        self.remember(id, |access| access.agent = Some(token.clone()));
        Ok(token)
    }
    /// The proxy's traffic token: the one create handed over, or, after a
    /// host restart, a running sandbox's connect answer (which extends its
    /// timeout, never shortens it). None when the sandbox admits public
    /// traffic.
    async fn traffic_token(&self, id: &str, refresh: bool, c: &Credentials) -> Result<Option<String>> {
        if !refresh && let Some(token) = self.cached(id).traffic {
            return Ok(Some(token));
        }
        let sandbox = self.connect(id, c).await?;
        Ok(sandbox.get("trafficAccessToken").and_then(Value::as_str).map(str::to_owned))
    }
    /// `POST /v2/sandboxes/{id}/connect`: resumes a paused sandbox, extends a
    /// running one's timeout to the configured lifetime, and answers its tokens.
    async fn connect(&self, id: &str, c: &Credentials) -> Result<Value> {
        let url = self.api(&["v2", "sandboxes", id, "connect"])?;
        let sandbox = self.call(Method::POST, url, Some(json!({"timeout": self.settings.lifetime_seconds})), c).await?;
        self.keep_tokens(id, &sandbox);
        Ok(sandbox)
    }
    async fn wait_state(&self, id: &str, wanted: &str, c: &Credentials) -> Result<Value> {
        for _ in 0..STATE_POLLS {
            let detail = self.detail(id, c).await?;
            if text(&detail, "state")? == wanted {
                return Ok(detail);
            }
            tokio::time::sleep(STATE_POLL).await;
        }
        Err(ProtocolError::unavailable(format!("E2B sandbox {id} is not {wanted} yet"), Some(5)))
    }
    /// Our sandboxes, optionally only the one holding `label`, with their
    /// details (a listed row carries no network policy).
    async fn ours_listed(&self, label: Option<&str>, c: &Credentials) -> Result<Vec<Value>> {
        let filter = {
            let mut filter = url::form_urlencoded::Serializer::new(String::new());
            filter.append_pair(PROVIDER_TAG, &self.name);
            if let Some(label) = label {
                filter.append_pair(LABEL_TAG, label);
            }
            filter.finish()
        };
        let mut rows = Vec::new();
        let mut next: Option<String> = None;
        let mut seen = BTreeSet::new();
        loop {
            let mut url = self.api(&["v2", "sandboxes"])?;
            url.query_pairs_mut().append_pair("metadata", &filter).append_pair("state", "running,paused").append_pair("limit", "100");
            if let Some(token) = &next {
                url.query_pairs_mut().append_pair("nextToken", token);
            }
            let operation = "GET /v2/sandboxes";
            let response = self.send(Method::GET, url, None, c, Auth::Key).await?;
            let page = Self::answer(operation, &response)?;
            rows.extend(page.as_array().ok_or_else(bad_response)?.iter().cloned());
            match response.headers().get("x-next-token").and_then(|v| v.to_str().ok()).filter(|v| !v.is_empty()) {
                None => break,
                Some(token) if seen.insert(token.to_owned()) => next = Some(token.to_owned()),
                Some(_) => return Err(bad_response()),
            }
        }
        let mut details = Vec::new();
        for row in rows {
            // The server filters by metadata; both tags are checked again here.
            if !self.ours(&row) || label.is_some_and(|l| self.label(&row).as_deref() != Some(l)) {
                continue;
            }
            match self.detail(text(&row, "sandboxID")?, c).await {
                Ok(detail) => details.push(detail),
                // Killed between the list and the read.
                Err(ProtocolError::NotFound { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(details)
    }
    /// An existing sandbox matches only the size and egress policy asked for.
    fn check_existing(&self, row: &Value, size: &Size, policy: &Policy) -> Result<()> {
        let existing = self.environment(row)?;
        let same_size = existing.granted_size.as_ref().is_some_and(|granted| {
            granted.cpus == size.cpus && granted.memory_bytes == size.memory_bytes && size.disk_bytes <= granted.disk_bytes
        });
        if !same_size || &Policy::read(row.get("network").unwrap_or(&Value::Null)) != policy {
            return Err(refused("an existing E2B sandbox holds this label with a different size or egress policy; provision a new label"));
        }
        Ok(())
    }

    /// The team's template named `name`: its id and builds, or None.
    async fn template(&self, name: &str, c: &Credentials) -> Result<Option<Value>> {
        let alias = match self.call(Method::GET, self.api(&["templates", "aliases", name])?, None, c).await {
            Ok(alias) => alias,
            Err(ProtocolError::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(error),
        };
        let id = text(&alias, "templateID")?;
        self.call(Method::GET, self.api(&["templates", id])?, None, c).await.map(Some)
    }
    /// Builds `name` from the base image by digest, the tools layer copied
    /// to /opt/drydock and the base's environment restored, then waits for
    /// the build to end. An existing build in progress is awaited instead.
    async fn build(&self, r: &PrepareRequest, base: &ImageRef, name: &str, existing: Option<&Value>, c: &Credentials) -> Result<()> {
        if let Some(template) = existing {
            let building = template["builds"].as_array().into_iter().flatten().find(|b| b["status"] == "building");
            if let Some(build) = building {
                return self.await_build(text(template, "templateID")?, text(build, "buildID")?, c).await;
            }
        }
        let platform = platform();
        // The pull credential belongs to the base's registry and goes nowhere else.
        let base_registry = Registry::new(self.http.clone(), &base.registry, r.image_pull.clone(), None)?;
        let base_manifest = base_registry.platform_manifest(base, &platform).await?;
        let config: Value =
            serde_json::from_slice(&base_registry.config(&base.repository, &base_manifest).await?).map_err(|_| bad_response())?;
        let tools = ImageRef::parse(&r.tools_digest)?;
        let tools_credential = if tools.registry == base.registry { r.image_pull.clone() } else { None };
        let tools_registry = Registry::new(self.http.clone(), &tools.registry, tools_credential, None)?;
        let tools_manifest = tools_registry.platform_manifest(&tools, &platform).await?;
        let layers = tools_manifest.layers()?;
        if layers.is_empty() {
            return Err(refused("the tools image has no layers"));
        }

        let size = json!({"name": name, "cpuCount": r.size.cpus as u64, "memoryMB": r.size.memory_bytes / MIB});
        let created = self.call(Method::POST, self.api(&["v3", "templates"])?, Some(size), c).await?;
        let (template_id, build_id) = (text(&created, "templateID")?.to_owned(), text(&created, "buildID")?.to_owned());
        // E2B drops the image's ENV, so the build sets it again.
        let mut steps = Vec::new();
        let env: Vec<String> = config
            .pointer("/config/Env")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter_map(|pair| pair.split_once('='))
            .flat_map(|(key, value)| [key.to_owned(), value.to_owned()])
            .collect();
        if !env.is_empty() {
            steps.push(json!({"type": "ENV", "args": env}));
        }
        // Each tools layer is a gzip tar holding opt/drydock/…; it is the
        // COPY context as is, cached by E2B under its own digest, so a later
        // prepare finds it present and uploads nothing.
        for layer in &layers {
            let hash = layer.digest.strip_prefix("sha256:").ok_or_else(bad_response)?;
            let upload = self.call(Method::GET, self.api(&["templates", &template_id, "files", hash])?, None, c).await?;
            if upload["present"] != true {
                let url =
                    upload["url"].as_str().and_then(|u| Url::parse(u).ok()).filter(|u| u.scheme() == "https").ok_or_else(bad_response)?;
                let headers: BTreeMap<String, String> =
                    serde_json::from_value(upload.get("headers").cloned().unwrap_or(json!({}))).map_err(|_| bad_response())?;
                let blob = tools_registry.blob(&tools.repository, layer, TOOLS_LAYER_LIMIT).await?;
                let response = self.send(Method::PUT, url, Some((blob.to_vec(), "")), c, Auth::Signed(&headers)).await?;
                Self::answer("PUT tools layer upload", &response)?;
            }
            steps.push(json!({"type": "COPY", "args": ["opt/drydock", "/opt/drydock", "root", ""], "filesHash": hash}));
        }
        let mut start = json!({"fromImage": r.image_digest, "steps": steps});
        if let Some(pull) = &r.image_pull {
            start["fromImageRegistry"] = json!({"type": "registry", "username": pull.username, "password": pull.secret.expose()});
        }
        self.call(Method::POST, self.api(&["v2", "templates", &template_id, "builds", &build_id])?, Some(start), c).await?;
        self.await_build(&template_id, &build_id, c).await
    }
    async fn await_build(&self, template: &str, build: &str, c: &Credentials) -> Result<()> {
        for _ in 0..BUILD_POLLS {
            let status = self.call(Method::GET, self.api(&["templates", template, "builds", build, "status"])?, None, c).await?;
            match text(&status, "status")? {
                "ready" => return Ok(()),
                "error" => {
                    let reason = status.pointer("/reason/message").and_then(Value::as_str).unwrap_or("no reason recorded");
                    let logs: Vec<&str> =
                        status["logEntries"].as_array().into_iter().flatten().filter_map(|e| e["message"].as_str()).collect();
                    let tail = logs[logs.len().saturating_sub(5)..].join("\n");
                    return Err(refused(cut(format!("E2B template build {build} failed: {reason}\n{tail}").trim_end())));
                }
                _ => tokio::time::sleep(BUILD_POLL).await,
            }
        }
        Err(ProtocolError::unavailable(format!("E2B template build {build} is still running"), Some(30)))
    }
    /// The private address a registry host is or resolves to, if any. E2B's
    /// builders pull over the public internet.
    async fn private_registry(&self, registry: &str) -> Option<IpAddr> {
        let host = registry.rsplit_once(':').filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit())).map_or(registry, |(h, _)| h);
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = host.parse::<IpAddr>() {
            return private(ip).then_some(ip);
        }
        let lower = host.to_ascii_lowercase();
        if lower == "localhost"
            || !lower.contains('.')
            || [".localhost", ".local", ".internal", ".lan", ".home.arpa"].iter().any(|s| lower.ends_with(s))
        {
            return Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        }
        // A name that does not resolve here is left to E2B's builder.
        self.resolver.resolve(host).await.ok()?.into_iter().find(|ip| private(*ip))
    }
    fn validate_size(&self, size: &Size) -> Result<()> {
        if !size.cpus.is_finite()
            || size.cpus.fract() != 0.0
            || !(1.0..=64.0).contains(&size.cpus)
            || !size.memory_bytes.is_multiple_of(2 * MIB)
            || size.memory_bytes < 512 * MIB
            || size.disk_bytes == 0
            || size.disk_bytes > self.settings.disk_mb * MIB
        {
            return Err(refused(format!(
                "E2B sandbox size: whole vCPUs, an even number of MiB of RAM from 512, and at most the plan's {} MiB of disk",
                self.settings.disk_mb
            )));
        }
        Ok(())
    }
}

fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.is_unspecified() || (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}
/// One Connect envelope: a flags byte, the length, the JSON message.
fn envelope(flags: u8, message: &Value) -> Vec<u8> {
    let bytes = message.to_string().into_bytes();
    let mut framed = Vec::with_capacity(bytes.len() + 5);
    framed.push(flags);
    framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(&bytes);
    framed
}

/// Output of one guest command: (stderr, bytes) in order, and its end.
#[derive(Default)]
struct Run {
    output: Vec<(bool, Vec<u8>)>,
    exit: Option<i32>,
    /// envd's or Connect's own error, when the process didn't run to its end.
    error: Option<String>,
}
impl Run {
    /// A Connect server stream: messages `{"event": {start|data|end|keepalive}}`
    /// and a closing end-stream envelope (flag 2) that may carry an error.
    /// Protobuf JSON omits zero values, so an end without `exitCode` exited 0.
    fn parse(mut body: &[u8]) -> Result<Self> {
        use base64::Engine;
        let mut run = Run::default();
        let mut ended = false;
        while !body.is_empty() {
            let [flags, a, b, c, d, rest @ ..] = body else { return Err(bad_response()) };
            let length = u32::from_be_bytes([*a, *b, *c, *d]) as usize;
            if rest.len() < length || flags & 1 != 0 {
                return Err(bad_response());
            }
            let message: Value = serde_json::from_slice(&rest[..length]).map_err(|_| bad_response())?;
            body = &rest[length..];
            if flags & 2 != 0 {
                ended = true;
                if let Some(error) = message.get("error") {
                    let code = error["code"].as_str().unwrap_or("unknown");
                    run.error = Some(format!("{code}: {}", error["message"].as_str().unwrap_or("")));
                }
                continue;
            }
            let event = &message["event"];
            if let Some(data) = event.get("data") {
                for (stderr, key) in [(false, "stdout"), (true, "stderr"), (false, "pty")] {
                    if let Some(chunk) = data.get(key).and_then(Value::as_str) {
                        let bytes = base64::engine::general_purpose::STANDARD.decode(chunk).map_err(|_| bad_response())?;
                        run.output.push((stderr, bytes));
                    }
                }
            }
            if let Some(end) = event.get("end") {
                run.exit = Some(end.get("exitCode").and_then(Value::as_i64).and_then(|c| i32::try_from(c).ok()).unwrap_or(0));
                if let Some(error) = end.get("error").and_then(Value::as_str).filter(|e| !e.is_empty()) {
                    run.error.get_or_insert_with(|| error.to_owned());
                }
            }
        }
        if !ended && run.exit.is_none() {
            return Err(ProtocolError::unavailable("E2B process stream ended early", None));
        }
        Ok(run)
    }
    fn bytes(&self, stderr: Option<bool>) -> Vec<u8> {
        self.output.iter().filter(|(e, _)| stderr.is_none_or(|s| s == *e)).flat_map(|(_, b)| b.iter().copied()).collect()
    }
    fn stdout(&self) -> Vec<u8> {
        self.bytes(Some(false))
    }
    /// -1 when the stream ended without an exit, as at a Connect deadline.
    fn exit_code(&self) -> i32 {
        self.exit.unwrap_or(-1)
    }
    /// Exit 0, or CommandFailed with the merged output.
    fn success(self) -> Result<Self> {
        if self.exit_code() == 0 {
            return Ok(self);
        }
        let mut output = String::from_utf8_lossy(&self.bytes(None)).into_owned();
        if let Some(error) = &self.error {
            output.push_str(&format!("\n[envd: {error}]"));
        }
        Err(ProtocolError::CommandFailed {
            reason: "E2B guest command failed".into(),
            exit_code: self.exit_code(),
            output: Secret::new(output),
        })
    }
    /// Exit 0, or for the module's own guest commands an Internal error whose
    /// cause is the output's tail, so drydockd's log shows why. Token lines
    /// are left out.
    fn started(self, what: &str) -> Result<Self> {
        if self.exit_code() == 0 {
            return Ok(self);
        }
        let output = String::from_utf8_lossy(&self.bytes(None)).into_owned();
        let mut output: Vec<&str> = output.lines().filter(|line| !line.contains(TOKEN_LINE.trim_end())).collect();
        let error = self.error.as_deref().map(|e| format!("[envd: {e}]"));
        output.extend(error.as_deref());
        let output = output.join("\n");
        let tail: String = output.chars().rev().take(OUTPUT_CAUSE_CHARS).collect::<Vec<_>>().into_iter().rev().collect();
        Err(ProtocolError::Internal {
            reason: format!("E2B guest {what} exited {}", self.exit_code()),
            provider_error: if tail.is_empty() { "no output".into() } else { tail },
        })
    }
    fn token(&self) -> Result<Token> {
        let stdout = String::from_utf8_lossy(&self.stdout()).into_owned();
        let line = stdout.lines().find_map(|line| line.strip_prefix(TOKEN_LINE));
        line.and_then(|line| Token::parse(line).ok()).ok_or_else(|| ProtocolError::Internal {
            reason: "the agent's TCP token was not read back".into(),
            provider_error: String::new(),
        })
    }
}

/// E2B's egress configuration, as drydock asks for it and reads it back:
/// denied CIDRs, allowed CIDRs and domains, and whether the proxy admits
/// traffic without the sandbox's traffic token.
#[derive(Debug, Clone, PartialEq)]
struct Policy {
    deny_out: BTreeSet<String>,
    allow_out: BTreeSet<String>,
    public_traffic: bool,
}
impl Policy {
    /// The request as E2B's `network`, refusing what it cannot hold: ports
    /// and IPv6. Deny-all denies 0.0.0.0/0 and allows what is listed; allowed
    /// entries take precedence. The proxy always requires the traffic token.
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
                Destination::Host { host } => {
                    let host = host.as_str().trim_end_matches('.').to_ascii_lowercase();
                    if host.contains(':') {
                        return Err(refused("E2B egress takes no IPv6 destinations"));
                    }
                    // A name is a domain entry, which E2B resolves itself.
                    policy.allow_out.insert(normal_cidr(&host).unwrap_or(host));
                }
            }
        }
        Ok(policy)
    }
    fn body(&self) -> Value {
        let mut network = json!({"allowPublicTraffic": self.public_traffic});
        if !self.deny_out.is_empty() {
            network["denyOut"] = json!(self.deny_out);
        }
        if !self.allow_out.is_empty() {
            network["allowOut"] = json!(self.allow_out);
        }
        network
    }
    /// A sandbox's `network`, normalised as requests are. A missing
    /// `allowPublicTraffic` is E2B's default, which admits public traffic.
    fn read(network: &Value) -> Self {
        let list = |key: &str| -> BTreeSet<String> {
            network[key]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|entry| {
                    let entry = entry.trim_end_matches('.').to_ascii_lowercase();
                    normal_cidr(&entry).unwrap_or(entry)
                })
                .collect()
        };
        Self {
            deny_out: list("denyOut"),
            allow_out: list("allowOut"),
            public_traffic: network["allowPublicTraffic"].as_bool().unwrap_or(true),
        }
    }
    fn open(&self) -> bool {
        self.deny_out.is_empty()
    }
    fn fingerprint(&self) -> String {
        digest(&json!([self.deny_out, self.allow_out, self.public_traffic]).to_string())
    }
}
fn normal_cidr(cidr: &str) -> Option<String> {
    let (ip, bits) = cidr.split_once('/').unwrap_or((cidr, "32"));
    let (ip, bits) = (ip.parse::<Ipv4Addr>().ok()?, bits.parse::<u32>().ok().filter(|b| *b <= 32)?);
    let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
    Some(format!("{}/{bits}", Ipv4Addr::from(u32::from(ip) & mask)))
}

/// The prepared template's name. E2B sizes the template, not the sandbox, so
/// the size is part of it. The tools image is not: the agent baked in is a
/// cache the host upgrades at the first hello. A content-addressed name never
/// changes content, so prepare never rebuilds a ready one.
fn template_name(image: &str, platform: &Platform, size: &Size) -> String {
    format!("drydock-{}", &digest(&format!("e2b-template\0{image}\0{platform}\0{}\0{}", size.cpus as u64, size.memory_bytes / MIB))[..40])
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
/// A deterministic continuation marker binding instance and sandbox; not a
/// credential, since every resume still needs the key.
fn resume_marker(instance: &str, id: &str) -> String {
    format!("e2b-resume-{}", &digest(&format!("{instance}\0{id}"))[..40])
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
        self.settings.rate_limits.clone().unwrap_or_default()
    }
    async fn prepare(&self, r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
        if prepare_route(&r)? != ImageRouteKind::RegistryPull {
            return Err(refused("E2B prepares by registry pull only"));
        }
        if !pinned(&r.image_digest) || !pinned(&r.tools_digest) {
            return Err(refused("E2B requires base and tools images pinned by sha256 digest"));
        }
        let platform = prepare_platform(&r)?;
        let supported = self::platform();
        if platform != supported {
            return Err(ProtocolError::ImageRefused {
                reason: format!("E2B runs only {supported} sandboxes"),
                refusal: ImageRefusal::UnsupportedPlatform { platform },
            });
        }
        self.validate_size(&r.size)?;
        let base = ImageRef::parse(&r.image_digest)?;
        if let Some(address) = self.private_registry(&base.registry).await {
            let address = if address.is_unspecified() { String::new() } else { format!(" ({address})") };
            return Err(refused(format!(
                "E2B pulls images over the public internet and cannot reach the private registry {}{address}; stage the image in a registry it can reach",
                base.registry
            )));
        }
        let name = template_name(&r.image_digest, &platform, &r.size);
        let template = self.template(&name, c).await?;
        let ready = template.as_ref().is_some_and(|t| t["builds"].as_array().into_iter().flatten().any(|b| b["status"] == "ready"));
        if !ready {
            self.build(&r, &base, &name, template.as_ref(), c).await?;
        }
        let template = self.template(&name, c).await?.ok_or_else(bad_response)?;
        if template["cpuCount"].as_u64() != Some(r.size.cpus as u64) || template["memoryMB"].as_u64() != Some(r.size.memory_bytes / MIB) {
            return Err(refused(format!("E2B template {name} has another size than its name holds")));
        }
        if let Some(disk) = template["diskSizeMB"].as_u64().filter(|disk| r.size.disk_bytes > disk * MIB) {
            return Err(refused(format!("E2B template {name} has {disk} MiB of disk, less than requested")));
        }
        Ok(Prepared { provider: self.name.clone(), id: name, platform, image_digest: r.image_digest, tools_digest: r.tools_digest })
    }
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        if r.prepared.provider != self.name {
            return Err(refused("prepared template belongs to another provider"));
        }
        self.validate_size(&r.size)?;
        if r.prepared.id != template_name(&r.prepared.image_digest, &r.prepared.platform, &r.size) {
            return Err(refused("E2B size does not match the prepared template"));
        }
        let policy = Policy::request(&r.egress)?;
        if let Some(row) = self.ours_listed(Some(&r.label), c).await?.into_iter().next() {
            self.check_existing(&row, &r.size, &policy)?;
            let id = text(&row, "sandboxID")?.to_owned();
            // A paused sandbox stays so: provision never resumes one.
            if text(&row, "state")? == "running" {
                self.bootstrap(&id, c).await?;
                return Ok(Provisioned::Existing(self.inspect(&id, c).await?));
            }
            return Ok(Provisioned::Existing(self.environment(&row)?));
        }
        // Nothing secret rides the create request (drydock#167): no envVars.
        let body = json!({
            "templateID": r.prepared.id,
            "timeout": self.settings.lifetime_seconds,
            "autoPause": true,
            "metadata": {PROVIDER_TAG: self.name, LABEL_TAG: r.label},
            "network": policy.body(),
        });
        let created = self.call(Method::POST, self.api(&["v2", "sandboxes"])?, Some(body), c).await?;
        let id = text(&created, "sandboxID")?.to_owned();
        self.keep_tokens(&id, &created);
        self.bootstrap(&id, c).await?;
        Ok(Provisioned::Created(self.inspect(&id, c).await?))
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        self.ours_listed(None, c).await?.iter().map(|row| self.environment(row)).collect()
    }
    /// Killed sandboxes leave E2B's records at once, so an id it does not
    /// know reads as gone.
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        match self.detail(id, c).await {
            Ok(row) => self.observed(&row, c).await,
            Err(ProtocolError::NotFound { .. }) => Ok(self.gone(id)),
            Err(error) => Err(error),
        }
    }
    /// Kills our sandbox; one already gone is destroyed. Templates stay: they
    /// are retired only by a retention decision (drydock#61).
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        let result = match self.detail(id, c).await {
            Ok(row) if !self.ours(&row) => return Err(refused(format!("E2B sandbox {id} is not this provider's"))),
            Ok(_) => match self.call(Method::DELETE, self.api(&["sandboxes", id])?, None, c).await {
                Ok(_) | Err(ProtocolError::NotFound { .. }) => Ok(()),
                Err(error) => Err(error),
            },
            Err(ProtocolError::NotFound { .. }) => Ok(()),
            Err(error) => Err(error),
        };
        if result.is_ok() {
            self.access.recover().remove(id);
            self.suspended.recover().remove(id);
        }
        result
    }
    async fn reach(&self, id: &str, _: &Credentials) -> Result<Reach> {
        Ok(Reach::relay(&self.name, id))
    }
    /// The agent's connection through E2B's proxy: a WebSocket upgrade (the
    /// only kind its front end passes) to the agent's port, with the
    /// sandbox's traffic token for the proxy and the agent's token for the
    /// agent; after the agent's 101 the bytes are its socket's. A paused
    /// sandbox is refused: reach never resumes. A token refused once is
    /// fetched again, once.
    async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream> {
        let row = self.detail(id, c).await?;
        if text(&row, "state")? != "running" {
            return Err(refused(format!("E2B sandbox {id} is not running; resume it first")));
        }
        let gated = !Policy::read(row.get("network").unwrap_or(&Value::Null)).public_traffic;
        let url = self.port_url(id, AGENT_PORT, CONNECT_PATH)?.to_string();
        let attempt = |traffic: Option<String>, agent: Token| {
            let url = url.clone();
            async move {
                let mut headers = http::HeaderMap::new();
                if let Some(traffic) = traffic {
                    let mut value = http::HeaderValue::from_str(&traffic).map_err(|_| bad_response())?;
                    value.set_sensitive(true);
                    headers.insert(TRAFFIC_HEADER, value);
                }
                let stream = self.dialer.connect(&url).await.map_err(|error| ProtocolError::Unavailable {
                    reason: "E2B proxy connection failed".into(),
                    retry_after: None,
                    provider_error: Some(error.to_string()),
                })?;
                Ok::<_, ProtocolError>(tcp::connect_at_with(stream, &url, &agent, headers).await)
            }
        };
        let traffic = if gated { self.traffic_token(id, false, c).await? } else { None };
        let mut result = attempt(traffic.clone(), self.agent_token(id, false, c).await?).await?;
        if let Err(error) = &result {
            let text = error.to_string();
            if text.contains("HTTP 403") && gated {
                // The proxy refused the traffic token: one held from before a rotation.
                result = attempt(self.traffic_token(id, true, c).await?, self.agent_token(id, false, c).await?).await?;
            } else if text.contains("HTTP 401") {
                // The agent refused its token: another bootstrap replaced the file.
                result = attempt(traffic, self.agent_token(id, true, c).await?).await?;
            }
        }
        // drydock-transport's stream, as the provider interface's.
        result.map(|stream| Box::new(stream) as ByteStream).map_err(|error| ProtocolError::Unavailable {
            reason: "the agent's TCP listener did not accept the connection through E2B's proxy".into(),
            retry_after: None,
            provider_error: Some(error.to_string()),
        })
    }
}

#[async_trait]
impl SuspendResume for E2b {
    /// Pauses with memory: processes, the agent among them, survive. Open
    /// relays end, and reconnect after resume.
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        if text(&self.detail(id, c).await?, "state")? == "running" {
            match self.call(Method::POST, self.api(&["sandboxes", id, "pause"])?, None, c).await {
                // 409: a pause already under way.
                Ok(_) | Err(ProtocolError::Refused { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        self.wait_state(id, "paused", c).await?;
        self.suspended.recover().insert(id.to_owned());
        Ok(ResumeToken { token: Secret::new(resume_marker(&self.name, id)) })
    }
    /// Connect resumes the sandbox and restarts its lifetime; the agent is
    /// bootstrapped again, which its supervisor's lock makes a no-op.
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()> {
        if token.token.expose() != resume_marker(&self.name, id) {
            return Err(refused("resume token belongs to another environment"));
        }
        self.connect(id, c).await?;
        self.wait_state(id, "running", c).await?;
        self.suspended.recover().remove(id);
        self.bootstrap(id, c).await?;
        Ok(())
    }
}

#[async_trait]
impl Exec for E2b {
    /// stdout and stderr merged in arrival order, bytes intact.
    async fn exec(&self, id: &str, r: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        let output = self.run(id, &shell_command(&r.command), BTreeMap::new(), c).await?.success()?.bytes(None);
        Ok(Box::new(std::io::Cursor::new(output)))
    }
}

#[async_trait]
impl QuotaOperation for E2b {
    /// Concurrency in use from the team's latest metric. The limit comes from
    /// settings: an API key cannot read the team's limits.
    async fn quota(&self, c: &Credentials) -> Result<Quota> {
        let metrics = self.call(Method::GET, self.api(&["teams", &self.settings.team_id, "metrics"])?, None, c).await?;
        let latest = metrics.as_array().ok_or_else(bad_response)?.iter().max_by_key(|m| m["timestampUnix"].as_i64().unwrap_or(i64::MIN));
        let in_use = match latest {
            Some(metric) => metric["concurrentSandboxes"].as_u64().ok_or_else(bad_response)?,
            None => 0,
        };
        Ok(Quota {
            resources: vec![],
            credits_remaining: None,
            credit_unit: None,
            concurrency_in_use: Some(in_use),
            concurrency_limit: self.settings.concurrency_limit,
        })
    }
}

#[async_trait]
impl UsageOperation for E2b {
    /// Each execution of our sandboxes that overlaps the period, from the
    /// pause and kill events that end one: they carry its start, vCPUs and
    /// memory. Executions still running are counted once they end. Disk is
    /// the plan's; E2B gives an API key no spend.
    async fn usage(&self, period: Period, c: &Credentials) -> Result<Usage> {
        let parse = |t: &str| t.parse::<chrono::DateTime<chrono::Utc>>().map_err(|_| bad_response());
        let (from, to) = (period.start().instant(), period.end().instant());
        let mut sizes: BTreeMap<(u64, u64), f64> = BTreeMap::new();
        let (mut cpu_seconds, mut memory_byte_seconds) = (0.0, 0.0);
        let mut sandboxes = BTreeSet::new();
        let mut seen = BTreeSet::new();
        'pages: for page in 0..EVENT_PAGES {
            let mut url = self.api(&["events", "sandboxes"])?;
            url.query_pairs_mut()
                .append_pair("offset", &(page * 100).to_string())
                .append_pair("limit", "100")
                .append_pair("orderAsc", "false")
                .append_pair("types", "sandbox.lifecycle.paused")
                .append_pair("types", "sandbox.lifecycle.killed");
            let events = self.call(Method::GET, url, None, c).await?;
            let events = events.as_array().ok_or_else(bad_response)?;
            for event in events {
                let ended = parse(text(event, "timestamp")?)?;
                if ended < from {
                    // Newest first: every later event ended earlier still.
                    break 'pages;
                }
                if !seen.insert(text(event, "id")?.to_owned()) {
                    continue;
                }
                let data = &event["eventData"];
                if data["sandbox_metadata"][PROVIDER_TAG].as_str() != Some(&self.name) {
                    continue;
                }
                let execution = &data["execution"];
                let Some(started) = execution["started_at"].as_str() else { continue };
                let started = parse(started)?;
                let (start, end) = (started.max(from), ended.min(to));
                if end <= start {
                    continue;
                }
                let seconds = (end - start).num_milliseconds() as f64 / 1000.0;
                let cpus = execution["vcpu_count"].as_u64().ok_or_else(bad_response)?;
                let memory = execution["memory_mb"].as_u64().ok_or_else(bad_response)?;
                *sizes.entry((cpus, memory)).or_default() += seconds / 3600.0;
                cpu_seconds += cpus as f64 * seconds;
                memory_byte_seconds += (memory * MIB) as f64 * seconds;
                sandboxes.insert(text(event, "sandboxId")?.to_owned());
            }
            if events.len() < 100 {
                break;
            }
        }
        let disk_bytes = self.settings.disk_mb * MIB;
        Ok(Usage {
            period,
            environment_hours: sizes
                .into_iter()
                .map(|((cpus, memory), hours)| SizeUsage {
                    size: Size { cpus: cpus as f64, memory_bytes: memory * MIB, disk_bytes },
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
    use hegel::generators as gs;

    // A Connect stream parses to its output and exit: base64 data events in
    // order, an end without exitCode as 0 (protobuf JSON omits zeros), the
    // end-stream envelope's error kept, and a stream cut before its end is
    // Unavailable.
    #[test]
    fn connect_streams_parse() {
        let event = |e: Value| envelope(0, &json!({"event": e}));
        let mut body = event(json!({"start": {"pid": 7}}));
        body.extend(event(json!({"data": {"stdout": "aGVs"}})));
        body.extend(event(json!({"data": {"stderr": "/w=="}})));
        body.extend(event(json!({"data": {"stdout": "bG8="}})));
        body.extend(event(json!({"end": {"exited": true, "status": "exit status 0"}})));
        body.extend(envelope(2, &json!({})));
        let run = Run::parse(&body).unwrap();
        assert_eq!((run.exit_code(), run.stdout(), run.bytes(None)), (0, b"hello".to_vec(), b"hel\xfflo".to_vec()));
        let mut failed = event(json!({"end": {"exitCode": 3, "exited": true}}));
        failed.extend(envelope(2, &json!({"error": {"code": "deadline_exceeded", "message": "timed out"}})));
        let run = Run::parse(&failed).unwrap();
        assert_eq!(run.exit_code(), 3);
        assert_eq!(run.error.as_deref(), Some("deadline_exceeded: timed out"));
        assert!(Run::parse(&envelope(2, &json!({"error": {"code": "unavailable", "message": "x"}}))).unwrap().exit_code() == -1);
        assert!(matches!(Run::parse(&event(json!({"start": {"pid": 7}}))), Err(ProtocolError::Unavailable { .. })));
        assert!(Run::parse(&body[..body.len() - 1]).is_err());
    }

    // Every request policy reads back from E2B's echo of it, in any order and
    // spelling (a bare IP, a trailing dot, upper case), as the same policy
    // with the same fingerprint; another policy has another.
    #[hegel::test]
    fn policies_read_back_as_requested(tc: hegel::TestCase) {
        let octets = gs::vecs(gs::integers::<u8>()).min_size(4).max_size(4);
        let entries = tc.draw(gs::vecs(octets).max_size(4));
        let names = tc.draw(gs::vecs(gs::sampled_from(vec!["github.com", "Crates.IO.", "example.org"])).max_size(3));
        let mut direct: Vec<Destination> = entries
            .iter()
            .map(|o| serde_json::from_value(json!({"kind": "host", "host": format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])})).unwrap())
            .collect();
        direct.extend(names.iter().map(|n| serde_json::from_value(json!({"kind": "host", "host": n})).unwrap()));
        let deny = tc.draw(gs::booleans());
        let request = if deny { EgressRequest::DenyAll { direct } } else { EgressRequest::Open };
        let policy = Policy::request(&request).unwrap();
        let mut echoed = policy.body();
        if let Some(allow) = echoed.get_mut("allowOut").and_then(Value::as_array_mut) {
            allow.reverse();
            for entry in allow.iter_mut() {
                let text = entry.as_str().unwrap().to_owned();
                *entry = json!(text.strip_suffix("/32").map(str::to_owned).unwrap_or_else(|| text.to_ascii_uppercase() + "."));
            }
        }
        let read = Policy::read(&echoed);
        assert_eq!(read, policy);
        assert_eq!(read.fingerprint(), policy.fingerprint());
        assert_eq!(read.open(), !deny);
        assert_ne!(Policy::read(&json!({})).fingerprint(), policy.fingerprint(), "E2B's default admits public traffic");
    }

    // The template name holds the image, platform, vCPUs and memory, not the
    // disk or the tools image; it is a valid E2B name.
    #[test]
    fn template_names() {
        let size = |cpus: f64, memory: u64, disk: u64| Size { cpus, memory_bytes: memory * MIB, disk_bytes: disk * MIB };
        let amd = platform();
        let name = template_name("image", &amd, &size(2.0, 2048, 10_240));
        assert!(name.len() <= 128 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'), "{name}");
        assert_eq!(name, template_name("image", &amd, &size(2.0, 2048, 1024)));
        for other in [
            template_name("other", &amd, &size(2.0, 2048, 10_240)),
            template_name("image", &Platform::new("linux", "arm64"), &size(2.0, 2048, 10_240)),
            template_name("image", &amd, &size(4.0, 2048, 10_240)),
            template_name("image", &amd, &size(2.0, 4096, 10_240)),
        ] {
            assert_ne!(other, name);
        }
    }
}

//! Stateless E2B translator: Firecracker sandboxes from templates E2B builds
//! from our image by digest, reached through E2B's port proxy to the agent's
//! token-gated TCP listener. The host owns inventory and retries.
//! API contract: https://github.com/e2b-dev/infra (spec/openapi.yml for the
//! control plane; packages/envd/spec for the in-guest daemon, whose process
//! service is Connect-RPC with JSON bodies), checked 2026-11-03, and the live
//! probe of 2026-11-01 (drydock#191).
use crate::{
    kit::{
        self, LABEL_TAG, MIB, PROVIDER_TAG, SizeLimits, Vendor,
        api::{Api, Auth, Body, Failure, Next, Paging, cut, sensitive},
        egress::{normal_cidr, normal_host, private_registry},
        guest::{self, Agent, Bootstrap, Guest, GuestOutput},
        image::{check_prepare, check_prepared, content_name},
    },
    module::*,
    oci::{ImageRef, Registry},
};
use async_trait::async_trait;
use drydock_protocol::*;
use drydock_transport::{
    tcp::{self, CONNECT_PATH, Token},
    websocket::{StreamDialer, TlsDialer},
};
use futures::{StreamExt, TryStreamExt};
use reqwest::{Method, Url, header::HeaderName};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

pub use crate::kit::egress::{Resolver, SystemResolver};

const E2B: Vendor = Vendor("E2B");
/// envd's port in every sandbox.
const ENVD_PORT: u16 = 49983;
/// The guest port the agent's TCP listener binds, published by E2B's proxy.
const AGENT_PORT: u16 = 7811;
/// The proxy's own gate in front of every published port but envd's.
const TRAFFIC_HEADER: &str = "e2b-traffic-access-token";
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
/// How many sandbox details a listing reads at once.
const DETAIL_READS: usize = 8;
/// The largest tools layer uploaded as a build's COPY context. Its download
/// and its upload each fit the host's 30-second HTTP deadline, which at 64
/// MiB needs about 20 Mbit/s; the layer holds one agent binary, far smaller.
const TOOLS_LAYER_LIMIT: u64 = 64 << 20;
/// Pages of sandbox events read for one usage period.
const EVENT_PAGES: usize = 100;

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
        let settings: Settings = E2B.settings(config)?;
        if settings.team_id.is_empty()
            || !(1..=86_400).contains(&settings.lifetime_seconds)
            || settings.disk_mb == 0
            || settings.domain.is_empty()
            || !settings.domain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(refused("E2B requires team_id, a domain host name, lifetime_seconds 1..86400 and a positive disk_mb"));
        }
        let api = Api::new(E2B, &settings.api_url, Auth::Header(HeaderName::from_static("x-api-key")), http)?.classify(classify);
        Ok(Arc::new(E2b {
            name: name.to_owned(),
            settings,
            api,
            dialer: self.dialer.clone(),
            resolver: self.resolver.clone(),
            agent: Agent::new(Bootstrap { listen: format!("0.0.0.0:{AGENT_PORT}"), precheck: None, unset: &[], workspace: true }),
            access: Mutex::default(),
            suspended: Mutex::default(),
        }))
    }
}
/// E2B's statuses: the team's concurrency limit is a quota, not a rate.
fn classify(f: &Failure) -> ProtocolError {
    let text = f.message();
    let reason = f.reason(&text);
    if f.status == 429 && text.to_ascii_lowercase().contains("concurrent") {
        return ProtocolError::QuotaExhausted { reason };
    }
    f.standard(reason)
}

/// The proxy's tokens for one sandbox. E2B hands the envd and traffic tokens
/// to whoever creates or connects to the sandbox; they are kept in this
/// host's memory only, never in a record or a log; a missing one is fetched
/// again.
#[derive(Clone, Default)]
struct Access {
    envd: Option<String>,
    traffic: Option<String>,
}

pub struct E2b {
    name: String,
    settings: Settings,
    api: Api,
    dialer: Arc<dyn StreamDialer>,
    resolver: Arc<dyn Resolver>,
    agent: Agent,
    access: Mutex<HashMap<String, Access>>,
    /// Sandboxes this host paused, so their pause reads as requested; E2B
    /// records no cause, and any other pause is its lifetime cap's.
    suspended: Mutex<HashSet<String>>,
}
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
fn platform() -> Platform {
    Platform::new("linux", "amd64")
}
/// Sandbox ids are lowercase alphanumerics; anything else never names one,
/// and must not reach a host name.
fn sandbox_id_valid(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}
fn not_a_sandbox() -> ProtocolError {
    ProtocolError::NotFound { reason: "not an E2B sandbox id".into() }
}

impl E2b {
    /// A published port of a sandbox: `https://<port>-<id>.<domain>`.
    fn port_url(&self, id: &str, port: u16, path: &str) -> Result<Url> {
        if !sandbox_id_valid(id) {
            return Err(not_a_sandbox());
        }
        Url::parse(&format!("https://{port}-{id}.{}{path}", self.settings.domain)).map_err(|_| E2B.bad_response())
    }
    fn remember(&self, id: &str, update: impl FnOnce(&mut Access)) {
        update(lock(&self.access).entry(id.to_owned()).or_default());
    }
    fn cached(&self, id: &str) -> Access {
        lock(&self.access).get(id).cloned().unwrap_or_default()
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
            return Err(not_a_sandbox());
        }
        let detail = self.api.call(Method::GET, self.api.url(&["sandboxes", id])?, None, c).await?;
        if let Some(envd) = detail.get("envdAccessToken").and_then(Value::as_str) {
            let envd = envd.to_owned();
            self.remember(id, |access| access.envd = Some(envd));
        }
        Ok(detail)
    }
    fn ours(&self, row: &Value) -> bool {
        row["metadata"][PROVIDER_TAG].as_str() == Some(&self.name)
    }
    fn environment(&self, v: &Value) -> Result<Environment> {
        let id = E2B.text(v, "sandboxID")?.to_owned();
        let state = match E2B.text(v, "state")? {
            "running" => Observation::Running,
            "paused" if lock(&self.suspended).contains(&id) => Observation::Stopped { cause: StopCause::SuspendedByRequest },
            // The lifetime cap pauses rather than kills (autoPause).
            "paused" => Observation::Stopped { cause: StopCause::PausedByProvider },
            _ => Observation::Unknown { reason: UnknownReason::ProviderStateUnknown },
        };
        let number = |key| v.get(key).and_then(Value::as_u64);
        Ok(Environment {
            label: kit::ours(&v["metadata"], &self.name),
            id,
            provider: self.name.clone(),
            state,
            granted_size: kit::granted(number("cpuCount"), number("memoryMB"), MIB, number("diskSizeMB"), MIB),
            egress: Enforcement::Enforced,
            platform: Some(platform()),
            egress_measured: false,
            // A listed row carries no network; the caller reads the detail for it.
            egress_policy: v.get("network").map(|network| Policy::read(network).fingerprint()),
            timestamp: None,
        })
    }
    /// The environment, with its egress claim measured when a probe is
    /// configured and the sandbox runs under a restricted policy.
    async fn observed(&self, v: &Value, c: &Credentials) -> Result<Environment> {
        let mut row = self.environment(v)?;
        let policy = Policy::read(v.get("network").unwrap_or(&Value::Null));
        if let (Some(probe), false, Observation::Running) = (&self.settings.egress_probe, policy.open(), &row.state) {
            guest::measure_egress(self, &mut row, probe, policy.allow_out.is_empty(), c).await;
        }
        Ok(row)
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
        let url = self.api.url(&["v2", "sandboxes", id, "connect"])?;
        let sandbox = self.api.call(Method::POST, url, Some(json!({"timeout": self.settings.lifetime_seconds})), c).await?;
        self.keep_tokens(id, &sandbox);
        Ok(sandbox)
    }
    async fn wait_state(&self, id: &str, wanted: &str, c: &Credentials) -> Result<Value> {
        kit::poll(STATE_POLLS, STATE_POLL, async || {
            let detail = self.detail(id, c).await?;
            Ok((E2B.text(&detail, "state")? == wanted).then_some(detail))
        })
        .await?
        .ok_or_else(|| ProtocolError::unavailable(format!("E2B sandbox {id} is not {wanted} yet"), Some(5)))
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
        let mut url = self.api.url(&["v2", "sandboxes"])?;
        url.query_pairs_mut().append_pair("metadata", &filter).append_pair("state", "running,paused").append_pair("limit", "100");
        let paging = Paging { rows: None, cursor: "nextToken", next: Next::Header("x-next-token") };
        let rows = self.api.paged(url, &paging, c).await?;
        // The server filters by metadata; both tags are checked again here.
        // Each row's detail (for its network policy) is read a few at a time.
        let ids = rows
            .iter()
            .filter(|row| kit::ours(&row["metadata"], &self.name).is_some_and(|l| label.is_none_or(|label| l == label)))
            .map(|row| E2B.text(row, "sandboxID").map(str::to_owned))
            .collect::<Result<Vec<String>>>()?;
        let reads = ids.into_iter().map(|id| async move { kit::api::absent_on_not_found(self.detail(&id, c).await) });
        let details: Vec<Option<Value>> = futures::stream::iter(reads).buffered(DETAIL_READS).try_collect().await?;
        Ok(details.into_iter().flatten().collect())
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
        let Some(alias) = self.api.find(self.api.url(&["templates", "aliases", name])?, c).await? else { return Ok(None) };
        let id = E2B.text(&alias, "templateID")?;
        self.api.call(Method::GET, self.api.url(&["templates", id])?, None, c).await.map(Some)
    }
    /// Builds `name` from the base image by digest, the tools layer copied
    /// to /opt/drydock and the base's environment restored, then waits for
    /// the build to end. An existing build in progress is awaited instead.
    async fn build(&self, r: &PrepareRequest, base: &ImageRef, name: &str, existing: Option<&Value>, c: &Credentials) -> Result<()> {
        if let Some(template) = existing {
            let building = template["builds"].as_array().into_iter().flatten().find(|b| b["status"] == "building");
            if let Some(build) = building {
                return self.await_build(E2B.text(template, "templateID")?, E2B.text(build, "buildID")?, c).await;
            }
        }
        let platform = platform();
        // The pull credential belongs to the base's registry and goes nowhere else.
        let http = self.api.http().clone();
        let base_registry = Registry::new(http.clone(), &base.registry, r.image_pull.clone(), None)?;
        let base_manifest = base_registry.platform_manifest(base, &platform).await?;
        let config: Value =
            serde_json::from_slice(&base_registry.config(&base.repository, &base_manifest).await?).map_err(|_| E2B.bad_response())?;
        let tools = ImageRef::parse(&r.tools_digest)?;
        let tools_credential = if tools.registry == base.registry { r.image_pull.clone() } else { None };
        let tools_registry = Registry::new(http, &tools.registry, tools_credential, None)?;
        let tools_manifest = tools_registry.platform_manifest(&tools, &platform).await?;
        // The tools image is one layer holding opt/drydock/ (its Dockerfile
        // copies the agent onto scratch); a layer without it would fail the
        // build with an opaque COPY error, so any other shape is refused here.
        let layers = tools_manifest.layers()?;
        let [layer] = layers.as_slice() else {
            return Err(refused(format!(
                "the tools image has {} layers; E2B's prepare copies exactly one, holding opt/drydock/",
                layers.len()
            )));
        };
        if layer.size > TOOLS_LAYER_LIMIT {
            return Err(refused(format!(
                "the tools layer holds {} bytes, more than the {TOOLS_LAYER_LIMIT} that fit the host's HTTP deadline",
                layer.size
            )));
        }

        let size = json!({"name": name, "cpuCount": r.size.cpus as u64, "memoryMB": r.size.memory_bytes / MIB});
        let created = self.api.call(Method::POST, self.api.url(&["v3", "templates"])?, Some(size), c).await?;
        let (template_id, build_id) = (E2B.text(&created, "templateID")?.to_owned(), E2B.text(&created, "buildID")?.to_owned());
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
        // The tools layer is a gzip tar holding opt/drydock/…; it is the COPY
        // context as is, cached by E2B under its own digest, so a later
        // prepare finds it present and uploads nothing.
        let hash = layer.digest.strip_prefix("sha256:").ok_or_else(|| E2B.bad_response())?;
        let upload = self.api.call(Method::GET, self.api.url(&["templates", &template_id, "files", hash])?, None, c).await?;
        if upload["present"] != true {
            let url = upload["url"]
                .as_str()
                .and_then(|u| Url::parse(u).ok())
                .filter(|u| u.scheme() == "https")
                .ok_or_else(|| E2B.bad_response())?;
            let signed: BTreeMap<String, String> =
                serde_json::from_value(upload.get("headers").cloned().unwrap_or(json!({}))).map_err(|_| E2B.bad_response())?;
            let headers = signed
                .iter()
                .map(|(name, value)| Some((HeaderName::from_bytes(name.as_bytes()).ok()?, value.parse().ok()?)))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| E2B.bad_response())?;
            let blob = tools_registry.blob(&tools.repository, layer, TOOLS_LAYER_LIMIT).await?;
            // A signed upload URL carries its own authorization: never the key.
            let response = self.api.send(Method::PUT, url, Body::Bytes(blob, ""), c, false, &headers).await?;
            self.api.answer("PUT tools layer upload", &response)?;
        }
        steps.push(json!({"type": "COPY", "args": ["opt/drydock", "/opt/drydock", "root", ""], "filesHash": hash}));
        let mut start = json!({"fromImage": r.image_digest, "steps": steps});
        if let Some(pull) = &r.image_pull {
            start["fromImageRegistry"] = json!({"type": "registry", "username": pull.username, "password": pull.secret.expose()});
        }
        self.api.call(Method::POST, self.api.url(&["v2", "templates", &template_id, "builds", &build_id])?, Some(start), c).await?;
        self.await_build(&template_id, &build_id, c).await
    }
    async fn await_build(&self, template: &str, build: &str, c: &Credentials) -> Result<()> {
        let url = self.api.url(&["templates", template, "builds", build, "status"])?;
        kit::poll(BUILD_POLLS, BUILD_POLL, async || {
            let status = self.api.call(Method::GET, url.clone(), None, c).await?;
            match E2B.text(&status, "status")? {
                "ready" => Ok(Some(())),
                "error" => {
                    let reason = status.pointer("/reason/message").and_then(Value::as_str).unwrap_or("no reason recorded");
                    let logs: Vec<&str> =
                        status["logEntries"].as_array().into_iter().flatten().filter_map(|e| e["message"].as_str()).collect();
                    let tail = logs[logs.len().saturating_sub(5)..].join("\n");
                    Err(refused(cut(format!("E2B template build {build} failed: {reason}\n{tail}").trim_end(), 500)))
                }
                _ => Ok(None),
            }
        })
        .await?
        .ok_or_else(|| ProtocolError::unavailable(format!("E2B template build {build} is still running"), Some(30)))
    }
    fn size_limits(&self) -> SizeLimits {
        SizeLimits {
            cpus: (1, 64),
            memory: (512 * MIB, u64::MAX),
            memory_step: 2 * MIB,
            disk: (1, self.settings.disk_mb * MIB),
            disk_step: 1,
        }
    }
}

#[async_trait]
impl Guest for E2b {
    fn vendor(&self) -> Vendor {
        E2B
    }
    /// Runs `sh -c script` in the guest as root through envd's process
    /// service (Connect-RPC, server streaming, JSON envelopes), stdin closed.
    /// `env` rides in the request, never on argv. envd picks the process's
    /// user from Basic `user:`; root has every capability.
    async fn run(&self, id: &str, script: &str, env: BTreeMap<&str, String>, c: &Credentials) -> Result<GuestOutput> {
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
            let mut headers = vec![
                (reqwest::header::AUTHORIZATION, reqwest::header::HeaderValue::from_static("Basic cm9vdDo=")),
                (HeaderName::from_static("connect-timeout-ms"), RUN_TIMEOUT_MS.into()),
            ];
            if let Some(envd) = envd {
                headers.push((HeaderName::from_static("x-access-token"), sensitive(&envd).map_err(|_| E2B.bad_response())?));
            }
            let body = Body::Bytes(envelope(0, &message).into(), "application/connect+json");
            let response = self.api.send(Method::POST, url.clone(), body, c, false, &headers).await?;
            if response.status().is_success() {
                return connect_output(response.body());
            }
            if response.status() != 401 || attempt == 1 {
                return Err(self.api.failure(&operation, &response));
            }
        }
        unreachable!("the second attempt always returns")
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
/// A Connect server stream: messages `{"event": {start|data|end|keepalive}}`
/// and a closing end-stream envelope (flag 2) that may carry an error.
/// Protobuf JSON omits zero values, so an end without `exitCode` exited 0.
fn connect_output(mut body: &[u8]) -> Result<GuestOutput> {
    use base64::Engine;
    let mut run = GuestOutput::default();
    let mut ended = false;
    let mut error = None;
    while !body.is_empty() {
        let [flags, a, b, c, d, rest @ ..] = body else { return Err(E2B.bad_response()) };
        let length = u32::from_be_bytes([*a, *b, *c, *d]) as usize;
        if rest.len() < length || flags & 1 != 0 {
            return Err(E2B.bad_response());
        }
        let message: Value = serde_json::from_slice(&rest[..length]).map_err(|_| E2B.bad_response())?;
        body = &rest[length..];
        if flags & 2 != 0 {
            ended = true;
            if let Some(e) = message.get("error") {
                error = Some(format!("{}: {}", e["code"].as_str().unwrap_or("unknown"), e["message"].as_str().unwrap_or("")));
            }
            continue;
        }
        let event = &message["event"];
        if let Some(data) = event.get("data") {
            for (stderr, key) in [(false, "stdout"), (true, "stderr"), (false, "pty")] {
                if let Some(chunk) = data.get(key).and_then(Value::as_str) {
                    let bytes = base64::engine::general_purpose::STANDARD.decode(chunk).map_err(|_| E2B.bad_response())?;
                    run.chunks.push((stderr, bytes));
                }
            }
        }
        if let Some(end) = event.get("end") {
            run.exit = Some(end.get("exitCode").and_then(Value::as_i64).and_then(|c| i32::try_from(c).ok()).unwrap_or(0));
            if let Some(e) = end.get("error").and_then(Value::as_str).filter(|e| !e.is_empty()) {
                error.get_or_insert_with(|| e.to_owned());
            }
        }
    }
    if !ended && run.exit.is_none() {
        return Err(ProtocolError::unavailable("E2B process stream ended early", None));
    }
    run.note = error.map(|e| format!("[envd: {e}]"));
    Ok(run)
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
            let entry = match destination {
                Destination::HostPort { .. } => return Err(refused("E2B egress rules cannot restrict ports")),
                Destination::Cidr { cidr } => normal_cidr(cidr.as_str()).ok_or_else(|| refused("E2B egress takes IPv4 CIDRs only"))?,
                Destination::Host { host } if host.as_str().contains(':') => return Err(refused("E2B egress takes no IPv6 destinations")),
                // A name is a domain entry, which E2B resolves itself.
                Destination::Host { host } => normal_cidr(host.as_str()).unwrap_or_else(|| normal_host(host.as_str())),
            };
            policy.allow_out.insert(entry);
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
            let entries = network[key].as_array().into_iter().flatten().filter_map(Value::as_str);
            entries.map(|entry| normal_cidr(entry).unwrap_or_else(|| normal_host(entry))).collect()
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
        kit::digest(&json!([self.deny_out, self.allow_out, self.public_traffic]).to_string())
    }
}

/// The prepared template's name: one per base image, tools image, platform
/// and size. E2B sizes the template, not the sandbox, so the size is part of
/// it; the tools image is too, so a new agent gets a new template rather than
/// the one baked into a template already ready.
fn template_name(image: &str, tools: &str, platform: &Platform, size: &Size) -> String {
    let (platform, cpus, memory) = (platform.to_string(), (size.cpus as u64).to_string(), (size.memory_bytes / MIB).to_string());
    content_name("drydock-", 40, &["e2b-template", image, tools, &platform, &cpus, &memory])
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
        let (_, platform) = check_prepare(E2B, &r, &[ImageRouteKind::RegistryPull], &platform())?;
        self.size_limits().check(E2B, &r.size)?;
        let base = ImageRef::parse(&r.image_digest)?;
        if let Some(private) = private_registry(&base.registry, &*self.resolver).await {
            return Err(refused(format!(
                "E2B pulls images over the public internet and cannot reach the private registry {}{}; stage the image in a registry it can reach",
                base.registry,
                private.detail()
            )));
        }
        let name = template_name(&r.image_digest, &r.tools_digest, &platform, &r.size);
        let template = self.template(&name, c).await?;
        let ready = template.as_ref().is_some_and(|t| t["builds"].as_array().into_iter().flatten().any(|b| b["status"] == "ready"));
        if !ready {
            self.build(&r, &base, &name, template.as_ref(), c).await?;
        }
        let template = self.template(&name, c).await?.ok_or_else(|| E2B.bad_response())?;
        if template["cpuCount"].as_u64() != Some(r.size.cpus as u64) || template["memoryMB"].as_u64() != Some(r.size.memory_bytes / MIB) {
            return Err(refused(format!("E2B template {name} has another size than its name holds")));
        }
        if let Some(disk) = template["diskSizeMB"].as_u64().filter(|disk| r.size.disk_bytes > disk * MIB) {
            return Err(refused(format!("E2B template {name} has {disk} MiB of disk, less than requested")));
        }
        Ok(Prepared { provider: self.name.clone(), id: name, platform, image_digest: r.image_digest, tools_digest: r.tools_digest })
    }
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        self.size_limits().check(E2B, &r.size)?;
        let p = &r.prepared;
        check_prepared(E2B, &self.name, p, &template_name(&p.image_digest, &p.tools_digest, &p.platform, &r.size))?;
        let policy = Policy::request(&r.egress)?;
        if let Some(row) = self.ours_listed(Some(&r.label), c).await?.into_iter().next() {
            self.check_existing(&row, &r.size, &policy)?;
            let id = E2B.text(&row, "sandboxID")?.to_owned();
            // A paused sandbox stays so: provision never resumes one.
            if E2B.text(&row, "state")? == "running" {
                self.agent.start(self, &id, c).await?;
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
        let created = self.api.call(Method::POST, self.api.url(&["v2", "sandboxes"])?, Some(body), c).await?;
        let id = E2B.text(&created, "sandboxID")?.to_owned();
        self.keep_tokens(&id, &created);
        self.agent.start(self, &id, c).await?;
        Ok(Provisioned::Created(self.inspect(&id, c).await?))
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        self.ours_listed(None, c).await?.iter().map(|row| self.environment(row)).collect()
    }
    /// Killed sandboxes leave E2B's records at once, so an id it does not
    /// know reads as gone.
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        match kit::api::absent_on_not_found(self.detail(id, c).await)? {
            Some(row) => self.observed(&row, c).await,
            None => Ok(kit::gone(&self.name, id, Enforcement::Enforced, platform())),
        }
    }
    /// Kills our sandbox; one already gone is destroyed. Templates stay: they
    /// are retired only by a retention decision (drydock#61).
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        match kit::api::absent_on_not_found(self.detail(id, c).await)? {
            Some(row) if !self.ours(&row) => return Err(refused(format!("E2B sandbox {id} is not this provider's"))),
            Some(_) => {
                kit::api::absent_on_not_found(self.api.call(Method::DELETE, self.api.url(&["sandboxes", id])?, None, c).await)?;
            }
            None => {}
        }
        lock(&self.access).remove(id);
        lock(&self.suspended).remove(id);
        self.agent.forget(id);
        Ok(())
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
        if E2B.text(&row, "state")? != "running" {
            return Err(refused(format!("E2B sandbox {id} is not running; resume it first")));
        }
        let gated = !Policy::read(row.get("network").unwrap_or(&Value::Null)).public_traffic;
        let url = self.port_url(id, AGENT_PORT, CONNECT_PATH)?.to_string();
        let attempt = async |traffic: Option<String>, agent: Token| {
            let mut headers = http::HeaderMap::new();
            if let Some(traffic) = traffic {
                headers.insert(TRAFFIC_HEADER, sensitive(&traffic).map_err(|_| E2B.bad_response())?);
            }
            let stream = self.dialer.connect(&url).await.map_err(|error| ProtocolError::Unavailable {
                reason: "E2B proxy connection failed".into(),
                retry_after: None,
                provider_error: Some(error.to_string()),
            })?;
            Ok::<_, ProtocolError>(tcp::connect_at_with(stream, &url, &agent, headers).await)
        };
        let traffic = if gated { self.traffic_token(id, false, c).await? } else { None };
        let mut result = attempt(traffic.clone(), self.agent.token(self, id, false, c).await?).await?;
        // Which side refused shows in the status: the proxy's 403, the agent's 401.
        match result.as_ref().err().and_then(tcp::Refusal::of).map(|r| r.status) {
            // The proxy refused the traffic token: one held from before a rotation.
            Some(403) if gated => {
                result = attempt(self.traffic_token(id, true, c).await?, self.agent.token(self, id, false, c).await?).await?;
            }
            // The agent refused its token: another bootstrap replaced the file.
            Some(401) => result = attempt(traffic, self.agent.token(self, id, true, c).await?).await?,
            _ => {}
        }
        result.map(|stream| Box::new(stream) as ByteStream).map_err(|error| guest::unaccepted(E2B, "proxy", error))
    }
}

#[async_trait]
impl SuspendResume for E2b {
    /// Pauses with memory: processes, the agent among them, survive. Open
    /// relays end, and reconnect after resume.
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        if E2B.text(&self.detail(id, c).await?, "state")? == "running" {
            match self.api.call(Method::POST, self.api.url(&["sandboxes", id, "pause"])?, None, c).await {
                // 409: a pause already under way.
                Ok(_) | Err(ProtocolError::Refused { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        self.wait_state(id, "paused", c).await?;
        lock(&self.suspended).insert(id.to_owned());
        Ok(E2B.resume_marker("e2b-resume-", &self.name, id))
    }
    /// Connect resumes the sandbox and restarts its lifetime; the agent is
    /// bootstrapped again, which its supervisor's lock makes a no-op.
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()> {
        E2B.check_resume("e2b-resume-", &self.name, id, &token)?;
        self.connect(id, c).await?;
        self.wait_state(id, "running", c).await?;
        lock(&self.suspended).remove(id);
        self.agent.start(self, id, c).await?;
        Ok(())
    }
}

#[async_trait]
impl Exec for E2b {
    /// stdout and stderr merged in arrival order, bytes intact.
    async fn exec(&self, id: &str, r: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        Guest::exec(self, id, r, c).await
    }
}

#[async_trait]
impl QuotaOperation for E2b {
    /// Concurrency in use from the team's latest metric. The limit comes from
    /// settings: an API key cannot read the team's limits.
    async fn quota(&self, c: &Credentials) -> Result<Quota> {
        let metrics = self.api.call(Method::GET, self.api.url(&["teams", &self.settings.team_id, "metrics"])?, None, c).await?;
        let metrics = metrics.as_array().ok_or_else(|| E2B.bad_response())?;
        let latest = metrics.iter().max_by_key(|m| m["timestampUnix"].as_i64().unwrap_or(i64::MIN));
        let in_use = match latest {
            Some(metric) => metric["concurrentSandboxes"].as_u64().ok_or_else(|| E2B.bad_response())?,
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
        let bad = || E2B.bad_response();
        let parse = |t: &str| t.parse::<chrono::DateTime<chrono::Utc>>().map_err(|_| bad());
        let (from, to) = (period.start().instant(), period.end().instant());
        let mut sizes: BTreeMap<(u64, u64), f64> = BTreeMap::new();
        let (mut cpu_seconds, mut memory_byte_seconds) = (0.0, 0.0);
        let mut sandboxes = BTreeSet::new();
        let mut seen = BTreeSet::new();
        'pages: for page in 0..EVENT_PAGES {
            let mut url = self.api.url(&["events", "sandboxes"])?;
            url.query_pairs_mut()
                .append_pair("offset", &(page * 100).to_string())
                .append_pair("limit", "100")
                .append_pair("orderAsc", "false")
                .append_pair("types", "sandbox.lifecycle.paused")
                .append_pair("types", "sandbox.lifecycle.killed");
            let events = self.api.call(Method::GET, url, None, c).await?;
            let events = events.as_array().ok_or_else(bad)?;
            for event in events {
                let ended = parse(E2B.text(event, "timestamp")?)?;
                if ended < from {
                    // Newest first: every later event ended earlier still.
                    break 'pages;
                }
                if !seen.insert(E2B.text(event, "id")?.to_owned()) {
                    continue;
                }
                let data = &event["eventData"];
                if data["sandbox_metadata"][PROVIDER_TAG].as_str() != Some(&self.name) {
                    continue;
                }
                let execution = &data["execution"];
                let Some(started) = execution["started_at"].as_str() else { continue };
                let (start, end) = (parse(started)?.max(from), ended.min(to));
                if end <= start {
                    continue;
                }
                let seconds = (end - start).num_milliseconds() as f64 / 1000.0;
                let cpus = execution["vcpu_count"].as_u64().ok_or_else(bad)?;
                let memory = execution["memory_mb"].as_u64().ok_or_else(bad)?;
                *sizes.entry((cpus, memory)).or_default() += seconds / 3600.0;
                cpu_seconds += cpus as f64 * seconds;
                memory_byte_seconds += (memory * MIB) as f64 * seconds;
                sandboxes.insert(E2B.text(event, "sandboxId")?.to_owned());
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
        let run = connect_output(&body).unwrap();
        assert_eq!((run.exit_code(), run.stdout(), run.bytes(None)), (0, b"hello".to_vec(), b"hel\xfflo".to_vec()));
        let mut failed = event(json!({"end": {"exitCode": 3, "exited": true}}));
        failed.extend(envelope(2, &json!({"error": {"code": "deadline_exceeded", "message": "timed out"}})));
        let run = connect_output(&failed).unwrap();
        assert_eq!(run.exit_code(), 3);
        assert_eq!(run.note.as_deref(), Some("[envd: deadline_exceeded: timed out]"));
        assert!(connect_output(&envelope(2, &json!({"error": {"code": "unavailable", "message": "x"}}))).unwrap().exit_code() == -1);
        assert!(matches!(connect_output(&event(json!({"start": {"pid": 7}}))), Err(ProtocolError::Unavailable { .. })));
        assert!(connect_output(&body[..body.len() - 1]).is_err());
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

    // The template name holds the base and tools images, platform, vCPUs and
    // memory, not the disk; it is a valid E2B name.
    #[test]
    fn template_names() {
        let size = |cpus: f64, memory: u64, disk: u64| Size { cpus, memory_bytes: memory * MIB, disk_bytes: disk * MIB };
        let amd = platform();
        let name = template_name("image", "tools", &amd, &size(2.0, 2048, 10_240));
        assert!(name.len() <= 128 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'), "{name}");
        assert_eq!(name, template_name("image", "tools", &amd, &size(2.0, 2048, 1024)));
        for other in [
            template_name("other", "tools", &amd, &size(2.0, 2048, 10_240)),
            template_name("image", "tools", &Platform::new("linux", "arm64"), &size(2.0, 2048, 10_240)),
            template_name("image", "other", &amd, &size(2.0, 2048, 10_240)),
            template_name("image", "tools", &amd, &size(4.0, 2048, 10_240)),
            template_name("image", "tools", &amd, &size(2.0, 4096, 10_240)),
        ] {
            assert_ne!(other, name);
        }
    }
}

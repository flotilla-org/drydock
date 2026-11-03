//! The Runtime module against an in-process stand-in at Runtime's HTTP and
//! WebSocket boundaries. The stand-in holds sandboxes, images, network rules
//! and usage in memory and enforces Runtime's documented requests (OpenAPI
//! 0.2.0 and https://withruntime.com/docs/api, 2026-11-03) and what the
//! live probe found (drydock#193): the Bearer key; Idempotency-Key replay,
//! deleted sandboxes included; create's fields, `diskMiB` of at least 3072
//! and no secrets; name uniqueness; label filters on sandboxes and their
//! refusal on images; UUID-only image and sandbox paths; the image limit;
//! builds that blame Runtime's builder for an unreachable registry while
//! their log says why; trial funding refusing `connect` and `persistent`;
//! `enforcedVersion` lagging a rules change; exec's fields and its 25 s
//! budget under the host's deadline. Its tunnel speaks Runtime's framing:
//! `ready`, `o "tcp PORT"` to the guest's loopback (`c closed` when nothing
//! listens), `d`/`e`/`c`, `a` acknowledgements on stream 0 with a client
//! disconnected past 1 MiB unacknowledged, `restart` and `resume` with close
//! 1012 and a one-use token, `replay` first on the resumed socket, and
//! `sandbox_not_running` with close 1011 once a sandbox pauses. Opening a
//! tunnel wakes a paused sandbox, as Runtime's does; that is recorded as a
//! violation. A real drydock agent answers behind each tunnel, started by
//! the bootstrap's own shell code run for real, its argv parsed by the
//! agent's own `--supervise` parser.
use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use drydock_agent::{Agent, Client, FileOptions, tcp::TokenListener};
use drydock_host::{module::*, runtime::RuntimeModule};
use drydock_protocol::*;
use drydock_transport::{
    ByteStream, Listener,
    tcp::Token,
    websocket::{
        tokio_tungstenite::{WebSocketStream, accept_hdr_async},
        tungstenite::{
            Message,
            handshake::server::{ErrorResponse, Request, Response},
            protocol::{CloseFrame, frame::coding::CloseCode},
        },
    },
};
use futures::{SinkExt, StreamExt};
use rigging_http_client::ChannelLabel;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::OwnedWriteHalf,
    sync::mpsc,
};

const KEY: &str = "rtcloud_test_key";
const API: &str = "api.withruntime.com";
const WINDOW: u64 = 1 << 20;
const BASE: &str = "ghcr.io/example/base@sha256:1111111111111111111111111111111111111111111111111111111111111111";
const TOOLS: &str = "ghcr.io/flotilla-org/drydock-tools@sha256:2222222222222222222222222222222222222222222222222222222222222222";
const CREATE_FIELDS: &[&str] = &["name", "labels", "image", "vcpu", "memoryMiB", "diskMiB", "network", "persistent", "idlePauseSeconds"];
/// Fields create documents but drydock must never send: no secrets or
/// environment in the create request (drydock#167).
const CREATE_DOCUMENTED: &[&str] = &[
    "env",
    "secrets",
    "funding",
    "region",
    "cpu",
    "cpuFloorMillis",
    "timeoutSeconds",
    "pausable",
    "autoWake",
    "wakeOnTimers",
    "user",
    "leaseSeconds",
    "maxTotalCostMicros",
    "getOrCreate",
    "onTimeout",
    "onLeaseEnd",
    "maxCostMicros",
    "snapshot",
    "tailscale",
    "volumes",
    "spreadFrom",
    "evictable",
];

/// A guest's drydock agent: really listening on loopback, as the
/// supervised agent would on the guest's.
struct Guest {
    address: SocketAddr,
    token: Token,
    task: tokio::task::JoinHandle<std::io::Result<std::path::PathBuf>>,
    _dir: tempfile::TempDir,
    _keep: drydock_transport::MemoryDialer,
}
impl Drop for Guest {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
struct Network {
    internet: bool,
    allow: Vec<String>,
    deny: Vec<String>,
    connect: Vec<String>,
    version: u64,
    enforced_version: u64,
    /// Reads left before the version in force catches up.
    lag: u32,
}
impl Network {
    fn info(&self, id: &str, paid: bool) -> Value {
        json!({
            "sandboxId": id, "internet": self.internet, "allow": self.allow, "deny": self.deny, "connect": self.connect,
            "version": self.version, "enforced": true, "enforcedVersion": self.enforced_version, "ports": [80, 443],
            "openPorts": paid, "connectAllowed": paid, "forbiddenPorts": [23, 25, 139, 445, 465, 587, 6667],
        })
    }
}

#[derive(Default)]
struct Sandbox {
    id: String,
    name: String,
    labels: Value,
    state: String,
    vcpu: u64,
    memory: u64,
    disk: u64,
    persistent: bool,
    idle_pause: u64,
    network: Network,
    /// /run/drydock/tcp.token in the guest.
    token_file: Option<String>,
    /// The `--tcp` port the agent was started with.
    agent_port: Option<u16>,
    guest: Option<Guest>,
    created: u64,
}
impl Sandbox {
    fn info(&self, paid: bool) -> Value {
        let status = match self.state.as_str() {
            "starting" => "pending",
            "running" | "resuming" => "active",
            "paused" | "pausing" => "paused",
            other => other,
        };
        json!({
            "id": self.id, "kind": "sandbox", "name": self.name, "labels": self.labels, "status": status, "state": self.state,
            "region": "eu-1", "funding": if paid { "paid" } else { "trial" }, "vcpu": self.vcpu, "memoryMiB": self.memory,
            "diskMiB": self.disk, "persistent": self.persistent, "idlePauseSeconds": self.idle_pause,
            "createdAt": format!("2026-11-03T00:00:{:02}.000Z", self.created % 60), "expiresAt": "2026-11-03T01:00:00.000Z",
            "envNames": [],
        })
    }
}

#[derive(Default, Clone)]
struct Image {
    id: String,
    name: String,
    state: String,
    dockerfile: String,
    error: Option<String>,
    log: Vec<String>,
    polls_left: u32,
    created: u64,
}
impl Image {
    fn info(&self) -> Value {
        json!({"id": self.id, "kind": "image", "status": self.state, "state": self.state, "name": self.name, "version": 1,
            "tags": ["latest"], "error": self.error, "createdAt": format!("2026-11-0{}T00:00:00.000Z", 1 + self.created % 8)})
    }
}

/// A tunnel upgrade's sandbox id and resume token.
type Upgrade = (String, Option<String>);

/// A tunnel's helper in the guest: its TCP connections and counts, which
/// outlive one socket when Runtime's API restarts.
struct Helper {
    writers: HashMap<u32, OwnedWriteHalf>,
    readers: Vec<tokio::task::JoinHandle<()>>,
    down_tx: mpsc::UnboundedSender<(u8, u32, Bytes)>,
    down_rx: mpsc::UnboundedReceiver<(u8, u32, Bytes)>,
    /// Data bytes the client sent, those written to the guest, and the last count acknowledged.
    received: u64,
    taken: u64,
    acked: u64,
}
impl Helper {
    fn new() -> Self {
        let (down_tx, down_rx) = mpsc::unbounded_channel();
        Self { writers: HashMap::new(), readers: vec![], down_tx, down_rx, received: 0, taken: 0, acked: 0 }
    }
}
impl Drop for Helper {
    fn drop(&mut self) {
        for reader in &self.readers {
            reader.abort();
        }
    }
}

#[derive(Default)]
struct State {
    sandboxes: BTreeMap<String, Sandbox>,
    deleted: Vec<String>,
    images: BTreeMap<String, Image>,
    registries: Vec<String>,
    /// Idempotency-Key → (request body, status, answer).
    replays: HashMap<String, (Value, u16, Value)>,
    creates: Vec<Value>,
    execs: Vec<Value>,
    /// The environment each bootstrap's agent was started with.
    agent_envs: Vec<BTreeMap<String, String>>,
    violations: Vec<String>,
    requests: Vec<String>,
    /// Trial funding: no credit.
    trial: bool,
    image_limit: u64,
    /// Polls a build stays building; tests of prepare itself run on paused time.
    build_polls: u32,
    /// Builds end failed with this error and log.
    build_failure: Option<(String, Vec<String>)>,
    /// The tools layer is missing from the image, so the bootstrap's exec fails.
    agent_missing: bool,
    exec_output: String,
    exec_exit: i64,
    usage: Vec<Value>,
    usage_query: Option<(String, String)>,
    /// Every request answers this status, error code and Retry-After, as an outage would.
    outage: Option<(u16, String, Option<u64>)>,
    /// Network rules lag this many reads before Runtime enforces them.
    enforce_lag: u32,
    tunnels: Vec<tokio::task::JoinHandle<()>>,
    parked: HashMap<String, (String, Helper, Vec<u8>)>,
    used_tokens: Vec<String>,
    /// A restart begins once a socket has received this many data bytes.
    restart_after: Option<u64>,
    resumes: u32,
    replays_sent: usize,
    /// Acknowledge only once the client has paused sending.
    lazy_acks: bool,
    most_unacked: u64,
    /// Kinds of client frames seen, in order.
    frames: Vec<u8>,
    next: u64,
}
impl State {
    fn uuid(&mut self) -> String {
        self.next += 1;
        format!("00000000-0000-4000-8000-{:012x}", self.next)
    }
    fn paid(&self) -> bool {
        !self.trial
    }
}

#[derive(Clone)]
struct StandIn(Arc<Mutex<State>>);
impl Default for StandIn {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(State { image_limit: 20, ..State::default() })))
    }
}

fn reply(status: u16, body: Value) -> http::Response<Bytes> {
    http::Response::builder().status(status).header("content-type", "application/json").body(Bytes::from(body.to_string())).unwrap()
}
/// Runtime's error shape; retryable codes carry Retry-After.
fn error(status: u16, code: &str, message: &str) -> http::Response<Bytes> {
    error_after(status, code, message, None)
}
fn error_after(status: u16, code: &str, message: &str, retry_after: Option<u64>) -> http::Response<Bytes> {
    let body = json!({"error": {"code": code, "status": status, "message": message, "requestId": "req_1", "hint": "see the docs",
        "retryable": retry_after.is_some(), "retryAfterMs": retry_after.map(|s| s * 1000)}});
    let mut response = reply(status, body);
    if let Some(seconds) = retry_after {
        response.headers_mut().insert("retry-after", seconds.into());
    }
    response
}
fn query(request: &reqwest::Request) -> Vec<(String, String)> {
    request.url().query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect()
}
fn first(query: &[(String, String)], key: &str) -> Option<String> {
    query.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}
fn body(request: &reqwest::Request) -> Value {
    request.body().and_then(|b| b.as_bytes()).filter(|b| !b.is_empty()).map(|b| serde_json::from_slice(b).unwrap()).unwrap_or(Value::Null)
}
fn uuid_shaped(id: &str) -> bool {
    id.len() == 36 && id.bytes().enumerate().all(|(i, b)| if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() })
}
fn name_shaped(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
/// A page of rows two at a time, so paging is exercised.
fn page(rows: Vec<Value>, query: &[(String, String)]) -> http::Response<Bytes> {
    let start: usize = first(query, "cursor").map(|c| c.parse().unwrap()).unwrap_or(0);
    let end = (start + 2).min(rows.len());
    let next = (end < rows.len()).then(|| end.to_string());
    reply(200, json!({"data": rows[start.min(rows.len())..end].to_vec(), "nextCursor": next}))
}
fn private(host: &str) -> bool {
    let host = host.split(':').next().unwrap_or(host);
    host.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| ip.is_private() || ip.is_loopback()) || !host.contains('.')
}

impl StandIn {
    /// A failed assertion can hold the lock as it panics; the state is still sound.
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn respond(&self, request: &reqwest::Request) -> http::Response<Bytes> {
        let mut s = self.state();
        let host = request.url().host_str().unwrap_or_default().to_owned();
        let method = request.method().as_str().to_owned();
        let path = request.url().path().to_owned();
        s.requests.push(format!("{method} {path}"));
        if host != API {
            s.violations.push(format!("request to an unknown host {host}"));
            return error(400, "invalid_host", "unknown host");
        }
        if request.headers().get("authorization").and_then(|v| v.to_str().ok()) != Some(&format!("Bearer {KEY}")) {
            return error(401, "unauthorized", "a valid API key is required");
        }
        if let Some((status, code, retry_after)) = s.outage.clone() {
            return error_after(status, &code, "outage", retry_after);
        }
        let key = request.headers().get("idempotency-key").and_then(|v| v.to_str().ok()).map(str::to_owned);
        if let Some(key) = &key {
            let valid = key.len() <= 128
                && key.as_bytes()[0].is_ascii_alphanumeric()
                && key.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b));
            if !valid {
                s.violations.push(format!("Idempotency-Key {key} breaks Runtime's pattern"));
                return error(400, "invalid_request", "Idempotency-Key");
            }
        }
        if let Some(prefer) = request.headers().get("prefer").and_then(|v| v.to_str().ok()) {
            let wait = prefer.strip_prefix("wait=").and_then(|w| w.parse::<u64>().ok());
            if wait.is_none_or(|w| w > 25) {
                s.violations.push(format!("Prefer {prefer} outlasts the host's 30 s deadline"));
            }
        }
        let q = query(request);
        let segments: Vec<&str> = path.trim_start_matches("/v1/").split('/').collect();
        let (id, action) = match segments.get(1) {
            Some(segment) => segment.split_once(':').map_or((*segment, None), |(id, action)| (id, Some(action))),
            None => ("", None),
        };
        let paid = s.paid();
        match (method.as_str(), segments[0], segments.len(), action) {
            ("POST", "sandboxes", 1, _) => {
                let body = body(request);
                if let Some(key) = &key
                    && let Some((first_body, status, answer)) = s.replays.get(key).cloned()
                {
                    if first_body != body {
                        return error(422, "idempotency_key_reused", "this key was used with another request");
                    }
                    let mut answer = answer;
                    answer["replayed"] = json!(true);
                    return reply(status, answer);
                }
                let response = create(&mut s, body.clone());
                if let Some(key) = key
                    && response.status().is_success()
                {
                    let answer: Value = serde_json::from_slice(response.body()).unwrap();
                    s.replays.insert(key, (body, response.status().as_u16(), answer));
                }
                response
            }
            ("GET", "sandboxes", 1, _) => {
                let include_stopped = first(&q, "includeStopped").as_deref() == Some("true");
                let labels: Vec<(String, String)> = q
                    .iter()
                    .filter(|(k, _)| k == "label")
                    .filter_map(|(_, v)| v.split_once(':').map(|(a, b)| (a.to_owned(), b.to_owned())))
                    .collect();
                if q.iter().filter(|(k, _)| k == "label").count() != labels.len() {
                    return error(400, "invalid_request", "label is key:value");
                }
                let name = first(&q, "name");
                let rows = s
                    .sandboxes
                    .values()
                    .filter(|sb| include_stopped || sb.state != "stopped" || sb.persistent)
                    .filter(|sb| labels.iter().all(|(k, v)| sb.labels[k.as_str()] == v.as_str()))
                    .filter(|sb| name.as_ref().is_none_or(|n| &sb.name == n))
                    .map(|sb| sb.info(paid))
                    .collect();
                page(rows, &q)
            }
            (_, "sandboxes", _, _) if !uuid_shaped(id) => error(400, "invalid_request", "id: not a UUID"),
            (_, "sandboxes", _, _) if !s.sandboxes.contains_key(id) => error(404, "not_found", "no such sandbox"),
            ("GET", "sandboxes", 2, None) => {
                let sandbox = s.sandboxes.get_mut(id).unwrap();
                if sandbox.state == "starting" {
                    sandbox.state = "running".into();
                }
                reply(200, sandbox.info(paid))
            }
            ("DELETE", "sandboxes", 2, None) => {
                let sandbox = s.sandboxes.remove(id).unwrap();
                s.deleted.push(sandbox.id.clone());
                reply(200, json!({"id": id, "deleted": true}))
            }
            ("POST", "sandboxes", 2, Some("pause")) => {
                let sandbox = s.sandboxes.get_mut(id).unwrap();
                match sandbox.state.as_str() {
                    "running" | "paused" => {
                        sandbox.state = "paused".into();
                        reply(200, sandbox.info(paid))
                    }
                    other => error(409, "not_pausable", &format!("sandbox is {other}")),
                }
            }
            ("POST", "sandboxes", 2, Some("wake")) => {
                let sandbox = s.sandboxes.get_mut(id).unwrap();
                match sandbox.state.as_str() {
                    "paused" => {
                        sandbox.state = "running".into();
                        reply(200, sandbox.info(paid))
                    }
                    _ => error(409, "sandbox_not_paused", "wake is for paused sandboxes"),
                }
            }
            ("POST", "sandboxes", 2, Some("restart")) => {
                let sandbox = s.sandboxes.get_mut(id).unwrap();
                // Memory is not kept: every process and /run/drydock are gone.
                sandbox.state = "running".into();
                sandbox.guest = None;
                sandbox.token_file = None;
                sandbox.agent_port = None;
                reply(200, sandbox.info(paid))
            }
            ("POST", "sandboxes", 2, Some("exec")) => exec(&mut s, id, body(request)),
            ("GET", "sandboxes", 3, None) if segments[2] == "network" => {
                let sandbox = s.sandboxes.get_mut(id).unwrap();
                if sandbox.network.lag > 0 {
                    sandbox.network.lag -= 1;
                } else {
                    sandbox.network.enforced_version = sandbox.network.version;
                }
                reply(200, sandbox.network.info(id, paid))
            }
            ("POST", "images", 1, _) => build(&mut s, body(request)),
            ("GET", "images", 1, _) => {
                if first(&q, "label").is_some() {
                    // Documented, but refused live.
                    return error(400, "invalid_request", "label is not a filter here");
                }
                let name = first(&q, "name");
                let mut rows: Vec<&Image> = s.images.values().filter(|i| name.as_ref().is_none_or(|n| &i.name == n)).collect();
                rows.sort_by_key(|i| std::cmp::Reverse(i.created));
                let rows = rows.into_iter().map(Image::info).collect();
                page(rows, &q)
            }
            ("GET", "images", 2, None) if id == "registries" => reply(
                200,
                json!({"data": s.registries.iter().map(|r| json!({"id": "reg", "registry": r, "kind": "basic", "username": "robot"})).collect::<Vec<_>>()}),
            ),
            (_, "images", _, _) if !uuid_shaped(id) => error(400, "invalid_request", "id: not a UUID"),
            (_, "images", _, _) if !s.images.contains_key(id) => error(404, "image_not_found", "no such image"),
            ("GET", "images", 2, None) => {
                let failure = s.build_failure.clone();
                let image = s.images.get_mut(id).unwrap();
                if matches!(image.state.as_str(), "queued" | "building") {
                    if image.polls_left > 0 {
                        image.polls_left -= 1;
                        image.state = "building".into();
                    } else if let Some((message, log)) = failure {
                        image.state = "failed".into();
                        image.error = Some(message);
                        image.log.extend(log);
                    } else {
                        image.state = "ready".into();
                    }
                }
                reply(200, image.info())
            }
            ("GET", "images", 3, None) if segments[2] == "logs" => {
                let image = &s.images[id];
                let after: usize = first(&q, "after").map(|a| a.parse().unwrap()).unwrap_or(0);
                let lines: Vec<Value> = image
                    .log
                    .iter()
                    .enumerate()
                    .skip(after)
                    .map(|(seq, text)| json!({"seq": seq, "stream": "build", "text": text}))
                    .collect();
                reply(200, json!({"lines": lines, "nextAfter": image.log.len(), "state": image.state, "done": image.state != "building"}))
            }
            ("POST", "images", 2, Some("delete")) => {
                s.images.remove(id);
                reply(200, json!({"id": id, "deleted": true}))
            }
            ("GET", "limits", 1, _) => {
                let running: Vec<&Sandbox> = s.sandboxes.values().filter(|sb| sb.state != "stopped").collect();
                let account = json!([
                    {"limit": "sandbox.count", "label": "Sandboxes at once", "unit": "count", "max": 10, "used": running.len()},
                    {"limit": "sandbox.vcpu", "label": "vCPUs", "unit": "count", "max": 32, "used": running.iter().map(|sb| sb.vcpu).sum::<u64>()},
                    {"limit": "sandbox.memory_mib", "label": "Memory", "unit": "mib", "max": 65536, "used": running.iter().map(|sb| sb.memory).sum::<u64>()},
                    {"limit": "image.count", "label": "Images", "unit": "count", "max": s.image_limit, "used": s.images.len()},
                ]);
                let credit = if paid { "50000000" } else { "0" };
                reply(
                    200,
                    json!({"access": "full", "daily": {"limitMicros": "10000000", "usedMicros": "0", "remainingMicros": "10000000", "window": "24h"},
                    "trial": null, "account": account,
                    "credit": {"availableMicros": credit, "dailyPaceMicros": null, "runwayDays": null, "lowBelowDays": 7,
                        "state": if paid { "ok" } else { "empty" }, "addedBy": "owner"}}),
                )
            }
            ("GET", "usage", 2, None) if id == "export" => {
                let stamp = |key: &str| {
                    first(&q, key)
                        .filter(|v| (20..=24).contains(&v.len()) && v.ends_with('Z') && chrono::DateTime::parse_from_rfc3339(v).is_ok())
                };
                let (Some(since), Some(until)) = (stamp("since"), stamp("until")) else {
                    s.violations.push("usage export bounds are UTC ISO timestamps with Z".into());
                    return error(400, "invalid_request", "since/until");
                };
                s.usage_query = Some((since, until));
                page(s.usage.clone(), &q)
            }
            _ => {
                s.violations.push(format!("unexpected request {method} {path}"));
                error(404, "route_not_found", "no such route")
            }
        }
    }
}

fn create(s: &mut State, body: Value) -> http::Response<Bytes> {
    s.creates.push(body.clone());
    for key in body.as_object().unwrap().keys() {
        if !CREATE_FIELDS.contains(&key.as_str()) {
            s.violations.push(format!("create sends {key}"));
            if !CREATE_DOCUMENTED.contains(&key.as_str()) {
                return error(400, "invalid_request", &format!("unknown field {key}"));
            }
        }
    }
    let name = body["name"].as_str().unwrap_or_default().to_owned();
    if !name_shaped(&name) {
        return error(400, "invalid_request", "name: letters, digits, dot, dash, underscore");
    }
    let labels = body["labels"].clone();
    if labels.as_object().is_some_and(|l| l.len() > 32 || l.values().any(|v| v.as_str().is_none_or(|v| v.len() > 256))) {
        return error(400, "invalid_request", "labels: at most 32 strings of at most 256 characters");
    }
    let (vcpu, memory, disk) =
        (body["vcpu"].as_u64().unwrap_or(2), body["memoryMiB"].as_u64().unwrap_or(4096), body["diskMiB"].as_u64().unwrap_or(4096));
    if !(1..=16).contains(&vcpu) || !(128..=65536).contains(&memory) {
        return error(400, "invalid_request", "vcpu 1 to 16, memoryMiB 128 to 65536");
    }
    if !(3072..=409600).contains(&disk) {
        return error(400, "invalid_request", "diskMiB: at least 3072");
    }
    let image = body["image"].as_str().unwrap_or_default();
    match s.images.values().find(|i| i.name == image) {
        None => return error(404, "image_not_found", &format!("no image {image}")),
        Some(i) if i.state != "ready" => return error_after(409, "image_not_ready", "the image is still building", Some(5)),
        Some(_) => {}
    }
    let persistent = body["persistent"] == true;
    if persistent && s.trial {
        return error(402, "payment_required", "persistent sandboxes are paid only: add credit");
    }
    let network = &body["network"];
    let list = |key: &str| -> Vec<String> {
        network[key].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_owned)).collect()
    };
    if !network.is_null() {
        if network["internet"].as_bool().is_none()
            || network.as_object().unwrap().keys().any(|k| !["internet", "allow", "deny", "connect"].contains(&k.as_str()))
        {
            return error(400, "invalid_request", "network: internet is required; allow, deny and connect only");
        }
        if s.trial && !list("connect").is_empty() {
            return error(403, "connect_not_allowed", "host:port rules need credit");
        }
        for entry in list("allow").iter().chain(list("connect").iter()) {
            if private(entry) {
                s.violations.push(format!("a private address {entry} in the rules: Runtime always refuses those"));
            }
        }
        if network["internet"] == false && !list("allow").is_empty() {
            s.violations.push("internet false with an allow list is stored as internet true; send the stored form".into());
        }
    }
    if s.sandboxes.values().any(|sb| sb.name == name) {
        return error(409, "name_taken", &format!("a sandbox is already named {name}"));
    }
    if body["idlePauseSeconds"] != 0 {
        s.violations.push("a vessel must never pause on idle under drydock".into());
    }
    let allow = list("allow");
    let id = s.uuid();
    let created = s.next;
    let lag = s.enforce_lag;
    let sandbox = Sandbox {
        id: id.clone(),
        name,
        labels,
        state: "running".into(),
        vcpu,
        memory,
        disk,
        persistent,
        idle_pause: body["idlePauseSeconds"].as_u64().unwrap_or(300),
        network: Network {
            // Without rules, the public web on 80 and 443; with an allow list, internet is stored true.
            internet: network["internet"].as_bool().unwrap_or(true) || !allow.is_empty(),
            allow,
            deny: list("deny"),
            connect: list("connect"),
            version: 1,
            enforced_version: 0,
            lag,
        },
        created,
        ..Sandbox::default()
    };
    let info = sandbox.info(s.paid());
    s.sandboxes.insert(id, sandbox);
    reply(200, info)
}

fn build(s: &mut State, body: Value) -> http::Response<Bytes> {
    for key in body.as_object().unwrap().keys() {
        if !["name", "dockerfile", "labels"].contains(&key.as_str()) {
            s.violations.push(format!("unexpected build field {key}"));
        }
    }
    let name = body["name"].as_str().unwrap_or_default().to_owned();
    if !name_shaped(&name) {
        return error(400, "invalid_request", "name");
    }
    if s.images.len() as u64 >= s.image_limit {
        return error(409, "quota_exceeded", "the account holds its limit of images");
    }
    let dockerfile = body["dockerfile"].as_str().unwrap_or_default().to_owned();
    let froms: Vec<String> = dockerfile.lines().filter_map(|l| l.strip_prefix("FROM ").map(str::to_owned)).collect();
    if froms.len() != 2 || !dockerfile.contains("COPY --from=drydock_tools /opt/drydock/ /opt/drydock/") {
        s.violations.push(format!("unexpected Dockerfile {dockerfile}"));
    }
    let id = s.uuid();
    let created = s.next;
    let mut image =
        Image { id: id.clone(), name, state: "queued".into(), dockerfile, polls_left: s.build_polls, created, ..Image::default() };
    // Runtime's builders refuse private addresses, and blame themselves.
    if let Some(from) = froms
        .iter()
        .filter_map(|f| f.split_whitespace().find(|w| w.contains('@')))
        .find(|f| private(f.split('/').next().unwrap_or_default()))
    {
        image.state = "failed".into();
        image.error = Some("A fault in our builder stopped this build; try again.".into());
        image.log = vec!["#1 resolve".into(), format!("ERROR: failed to resolve {from}: dial tcp: connect: connection refused")];
    }
    let info = image.info();
    s.images.insert(id, image);
    reply(200, info)
}

/// Exec: recognises the module's own scripts. The bootstrap reaches here
/// once StandIn::bootstrap has run it for real.
fn exec(s: &mut State, id: &str, body: Value) -> http::Response<Bytes> {
    s.execs.push(body.clone());
    for key in body.as_object().unwrap().keys() {
        if !["argv", "command", "cwd", "env", "stdin", "user", "timeoutMs"].contains(&key.as_str()) {
            s.violations.push(format!("unexpected exec field {key}"));
        }
    }
    if body["timeoutMs"].as_u64().is_none_or(|t| t > 25_000) {
        s.violations.push("exec must end inside the host's 30 s deadline".into());
    }
    let sandbox = s.sandboxes.get(id).unwrap();
    if sandbox.state != "running" {
        s.violations.push(format!("exec on a {} sandbox would wake it", sandbox.state));
        return error(409, "sandbox_not_running", "not running");
    }
    let argv: Vec<String> = serde_json::from_value(body["argv"].clone()).unwrap_or_default();
    let script = argv.get(2).cloned().unwrap_or_default();
    if argv.len() != 3 || argv[0] != "sh" || argv[1] != "-c" {
        s.violations.push(format!("unexpected argv {argv:?}"));
    }
    let root = body["user"] == "root";
    let (stdout, stderr, code): (String, String, i64) = if script.starts_with("echo \"drydock-tcp-token $(cat /run/drydock/tcp.token)\"") {
        match (&sandbox.token_file, root) {
            (Some(token), true) => (format!("drydock-tcp-token {token}\n"), String::new(), 0),
            _ => ("drydock-tcp-token \n".into(), "cat: /run/drydock/tcp.token: No such file or directory\n".into(), 1),
        }
    } else if script.starts_with("test \"$(id -u)\" = 0") {
        (json!({"uid": 0, "unlisted_canary": false, "raw_dns": false, "listed_direct": true}).to_string(), String::new(), 0)
    } else if script.contains("--supervise") {
        let token = format!("drydock-tcp-token {}\n", sandbox.token_file.clone().unwrap_or_default());
        if s.agent_missing {
            (token, "env: '/opt/drydock/drydock-agent': No such file or directory\n".into(), 127)
        } else {
            match supervise(&script) {
                Ok(_) => (token, String::new(), 0),
                Err(output) => (token, output, 1),
            }
        }
    } else {
        (s.exec_output.clone(), String::new(), s.exec_exit)
    };
    reply(200, json!({"exitCode": code, "stdout": stdout, "stderr": stderr, "timedOut": false, "durationMs": 12}))
}

const AGENT: &str = "/opt/drydock/drydock-agent";
/// What the guest's `drydock-agent --supervise` makes of the bootstrap's
/// argv, through the supervisor's own parser.
fn supervise(script: &str) -> std::result::Result<Vec<String>, String> {
    let Some((_, argv)) = script.split_once(&format!("{AGENT} --supervise ")) else {
        return Err(format!("sh: unexpected bootstrap {script}"));
    };
    let argv: Vec<std::ffi::OsString> = argv.split_whitespace().map(Into::into).collect();
    drydock_agent::socket::supervised(&argv).map_err(|e| e.to_string())?;
    Ok(argv.iter().map(|a| a.to_string_lossy().into_owned()).collect())
}
/// The bootstrap run for real by `sh`, with /run/drydock moved to a
/// temporary directory, Runtime's identity variables in its environment and
/// a stub in the agent's place recording the environment it gets. Returns
/// the token file afterwards and that environment.
fn run_bootstrap(script: &str, existing: Option<&str>, token: Option<&str>) -> (Option<String>, BTreeMap<String, String>) {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path().join("run");
    let stub = dir.path().join("agent");
    let recorded = dir.path().join("env");
    std::fs::write(&stub, format!("#!/bin/sh\nenv > {}\n", recorded.display())).unwrap();
    std::fs::set_permissions(&stub, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let script = script.replace("/run/drydock", run.to_str().unwrap()).replace(AGENT, stub.to_str().unwrap());
    if let Some(existing) = existing {
        std::fs::create_dir(&run).unwrap();
        std::fs::write(run.join("tcp.token"), existing).unwrap();
    }
    let status = std::process::Command::new("sh")
        .args(["-c", &script])
        .env("DRYDOCK_TCP_TOKEN", token.unwrap_or_default())
        .env("RUNTIME_ID_TOKEN_REQUEST_TOKEN", "rt-identity-secret")
        .env("RUNTIME_ID_TOKEN_REQUEST_URL", "http://169.254.169.254/token")
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "bootstrap's shell code failed: {script}");
    let env = std::fs::read_to_string(&recorded)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
        .collect();
    (std::fs::read_to_string(run.join("tcp.token")).ok(), env)
}

impl StandIn {
    /// The bootstrap, run as root with the token in its environment: writes
    /// the token file unless one holds a token, then starts the agent unless
    /// the supervisor already runs one.
    async fn bootstrap(&self, request: &reqwest::Request) {
        let body = body(request);
        let id = request.url().path().trim_start_matches("/v1/sandboxes/").trim_end_matches(":exec").to_owned();
        let script = body["argv"][2].as_str().unwrap_or_default().to_owned();
        let start = {
            let mut s = self.state();
            if body["user"] != "root" {
                s.violations.push("the agent must start as root".into());
            }
            let token = body["env"]["DRYDOCK_TCP_TOKEN"].as_str().and_then(|t| Token::parse(t).ok());
            if token.as_ref().is_some_and(|t| script.contains(t.secret())) {
                s.violations.push("the token is on the agent's argv".into());
            }
            let argv = supervise(&script);
            let port = argv.as_ref().ok().and_then(|argv| {
                argv.iter()
                    .position(|a| a == "--tcp")
                    .and_then(|i| argv[i + 1].strip_prefix("127.0.0.1:"))
                    .and_then(|p| p.parse::<u16>().ok())
            });
            if argv.is_ok() && port.is_none() {
                s.violations.push(format!("the agent must listen on the guest's loopback, which the tunnel reaches: {script}"));
            }
            let missing = s.agent_missing;
            let Some(sandbox) = s.sandboxes.get(&id).filter(|sb| sb.state == "running") else { return };
            let existing = sandbox.token_file.clone();
            drop(s);
            let (token_file, env) = run_bootstrap(&script, existing.as_deref(), token.as_ref().map(Token::secret));
            let mut s = self.state();
            if !missing {
                s.agent_envs.push(env);
            }
            let sandbox = s.sandboxes.get_mut(&id).unwrap();
            sandbox.token_file = token_file;
            match (&sandbox.guest, sandbox.token_file.as_deref().map(Token::parse), port) {
                (None, Some(Ok(token)), Some(port)) if !missing => {
                    sandbox.agent_port = Some(port);
                    Some(token)
                }
                _ => None,
            }
        };
        if let Some(token) = start {
            let guest = start_guest(token).await;
            if let Some(sandbox) = self.state().sandboxes.get_mut(&id) {
                sandbox.guest = Some(guest);
            }
        }
    }
    /// Replaces a guest's agent and token, as another host's bootstrap after
    /// a restart would, so a module's cached token goes stale.
    async fn rotate_token(&self, id: &str) {
        let token = Token::generate().unwrap();
        let guest = start_guest(token.clone()).await;
        let mut s = self.state();
        let sandbox = s.sandboxes.get_mut(id).unwrap();
        sandbox.token_file = Some(token.secret().to_owned());
        sandbox.guest = Some(guest);
    }
    /// A restart from outside drydock: the sandbox runs again, but every
    /// process and /run/drydock are gone.
    fn restart_out_of_band(&self, id: &str, state: &str) {
        let mut s = self.state();
        let sandbox = s.sandboxes.get_mut(id).unwrap();
        sandbox.state = state.into();
        sandbox.guest = None;
        sandbox.token_file = None;
        sandbox.agent_port = None;
    }
    fn set_state(&self, id: &str, state: &str) {
        self.state().sandboxes.get_mut(id).unwrap().state = state.into();
    }

    async fn serve_tunnels(self, mut listener: drydock_transport::MemoryListener) {
        while let Ok(stream) = listener.accept().await {
            let stand_in = self.clone();
            let task = tokio::spawn(async move { stand_in.tunnel(stream).await });
            self.state().tunnels.push(task);
        }
    }
    /// One tunnel socket: the upgrade's key and path, a fresh helper or the
    /// parked one its resume token names, then `ready` and the session.
    async fn tunnel(&self, stream: ByteStream) {
        let found: Arc<Mutex<Option<Upgrade>>> = Arc::default();
        let target = found.clone();
        let stand_in = self.clone();
        #[allow(clippy::result_large_err)]
        let check = move |request: &Request, response: Response| -> std::result::Result<Response, ErrorResponse> {
            let refuse = |status: u16, code: &str| {
                let mut refusal = ErrorResponse::new(Some(json!({"error": {"code": code, "status": status, "message": code}}).to_string()));
                *refusal.status_mut() = http::StatusCode::from_u16(status).unwrap();
                Err(refusal)
            };
            if request.headers().get("authorization").and_then(|v| v.to_str().ok()) != Some(&format!("Bearer {KEY}")) {
                return refuse(401, "unauthorized");
            }
            let Some(id) = request.uri().path().strip_prefix("/v1/sandboxes/").and_then(|p| p.strip_suffix("/tunnel")) else {
                return refuse(404, "route_not_found");
            };
            let resume = match request.uri().query() {
                None => None,
                Some(q) => match q.strip_prefix("resume=") {
                    Some(token) if !token.contains('&') => Some(token.to_owned()),
                    _ => {
                        stand_in.state().violations.push(format!("a tunnel query other than resume alone: {q}"));
                        return refuse(400, "invalid_request");
                    }
                },
            };
            let mut s = stand_in.state();
            if let Some(token) = &resume {
                if s.used_tokens.contains(token) {
                    return refuse(409, "conflict");
                }
                if !s.parked.contains_key(token) {
                    return refuse(400, "invalid_request");
                }
            }
            let Some(sandbox) = s.sandboxes.get_mut(id) else { return refuse(404, "not_found") };
            if sandbox.state == "paused" {
                // Runtime wakes it; drydock must never let a relay do so.
                sandbox.state = "running".into();
                s.violations.push("a tunnel woke a paused sandbox".into());
            }
            *target.lock().unwrap() = Some((id.to_owned(), resume));
            Ok(response)
        };
        let Ok(mut socket) = accept_hdr_async(stream, check).await else { return };
        let Some((id, resume)) = found.lock().unwrap().take() else { return };
        let (helper, replay) = match &resume {
            Some(token) => {
                let mut s = self.state();
                s.used_tokens.push(token.clone());
                s.resumes += 1;
                let (_, helper, replay) = s.parked.remove(token).unwrap();
                (helper, replay)
            }
            None => (Helper::new(), vec![]),
        };
        let ready = if resume.is_some() { json!({"type": "ready", "resumed": true}) } else { json!({"type": "ready"}) };
        if socket.send(Message::Text(ready.to_string().into())).await.is_err() {
            return;
        }
        self.session(socket, id, helper, replay).await;
    }
    async fn session(&self, mut socket: WebSocketStream<ByteStream>, id: String, mut helper: Helper, mut replay: Vec<u8>) {
        let send = |kind: u8, stream: u32, payload: &[u8]| {
            let mut frame = vec![kind];
            frame.extend(stream.to_be_bytes());
            frame.extend(payload);
            Message::Binary(frame.into())
        };
        // A resumed socket must begin with the replay Runtime handed back.
        let mut expect_replay = !replay.is_empty();
        let mut restarting: Option<tokio::time::Instant> = None;
        let mut quiet = tokio::time::Instant::now();
        loop {
            let lazy = self.state().lazy_acks;
            let ack_due = lazy && helper.taken > helper.acked;
            let deadline = restarting.unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(3600));
            tokio::select! {
                message = socket.next() => {
                    let Some(Ok(message)) = message else { return };
                    match message {
                        Message::Text(text) => {
                            let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                            match value["type"].as_str() {
                                Some("restart") if restarting.is_some() => {
                                    let token = format!("rt_resume_{}", self.state().next);
                                    let mut resume = json!({"type": "resume", "token": token});
                                    if !replay.is_empty() {
                                        resume["replay"] = json!(base64::engine::general_purpose::STANDARD.encode(&replay));
                                        self.state().replays_sent += 1;
                                    }
                                    let _ = socket.send(Message::Text(resume.to_string().into())).await;
                                    let _ = socket.close(Some(CloseFrame { code: CloseCode::Restart, reason: "".into() })).await;
                                    self.state().next += 1;
                                    self.state().parked.insert(token, (id, helper, std::mem::take(&mut replay)));
                                    return;
                                }
                                Some("replay") if expect_replay => {
                                    expect_replay = false;
                                    let data = base64::engine::general_purpose::STANDARD.decode(value["data"].as_str().unwrap_or_default()).unwrap_or_default();
                                    if data != replay {
                                        self.state().violations.push("the replay came back altered".into());
                                    }
                                    let data = std::mem::take(&mut replay);
                                    if let Some(writer) = helper.writers.get_mut(&1) {
                                        let _ = writer.write_all(&data).await;
                                    }
                                    helper.taken += data.len() as u64;
                                    if !lazy {
                                        helper.acked = helper.taken;
                                        let _ = socket.send(send(b'a', 0, &helper.taken.to_be_bytes())).await;
                                    }
                                }
                                _ => self.state().violations.push(format!("unexpected text from the client: {text}")),
                            }
                        }
                        Message::Binary(frame) => {
                            if expect_replay {
                                self.state().violations.push("data before the replay on a resumed tunnel".into());
                                expect_replay = false;
                            }
                            if frame.len() < 5 {
                                self.state().violations.push("a frame shorter than its header".into());
                                return;
                            }
                            let (kind, stream, payload) = (frame[0], u32::from_be_bytes(frame[1..5].try_into().unwrap()), frame.slice(5..));
                            self.state().frames.push(kind);
                            let running = self.state().sandboxes.get(&id).is_some_and(|sb| sb.state == "running");
                            if !running {
                                let error = json!({"type": "error", "error": {"code": "sandbox_not_running", "status": 409, "message": "the sandbox paused"}});
                                let _ = socket.send(Message::Text(error.to_string().into())).await;
                                let _ = socket.close(Some(CloseFrame { code: CloseCode::Error, reason: "sandbox_not_running".into() })).await;
                                return;
                            }
                            match kind {
                                b'o' => {
                                    let port = std::str::from_utf8(&payload).ok().and_then(|p| p.strip_prefix("tcp ")).and_then(|p| p.parse::<u16>().ok());
                                    let Some(port) = port else {
                                        self.state().violations.push(format!("an open other than tcp PORT: {payload:?}"));
                                        let _ = socket.send(send(b'c', stream, b"invalid target")).await;
                                        continue;
                                    };
                                    // Loopback only: the agent the bootstrap started on this port, or nothing.
                                    let address = {
                                        let s = self.state();
                                        let sandbox = &s.sandboxes[&id];
                                        sandbox.guest.as_ref().filter(|_| sandbox.agent_port == Some(port)).map(|g| g.address)
                                    };
                                    let Some(Ok(tcp)) = (match address { Some(a) => Some(tokio::net::TcpStream::connect(a).await), None => None }) else {
                                        let _ = socket.send(send(b'c', stream, b"closed")).await;
                                        continue;
                                    };
                                    let (mut read, write) = tcp.into_split();
                                    helper.writers.insert(stream, write);
                                    let down = helper.down_tx.clone();
                                    helper.readers.push(tokio::spawn(async move {
                                        let mut buffer = vec![0; 16 << 10];
                                        while let Ok(n) = read.read(&mut buffer).await {
                                            if n == 0 {
                                                break;
                                            }
                                            let _ = down.send((b'd', stream, Bytes::copy_from_slice(&buffer[..n])));
                                        }
                                        let _ = down.send((b'e', stream, Bytes::new()));
                                        let _ = down.send((b'c', stream, Bytes::from_static(b"closed")));
                                    }));
                                    let _ = socket.send(send(b'o', stream, b"")).await;
                                }
                                b'd' => {
                                    quiet = tokio::time::Instant::now();
                                    helper.received += payload.len() as u64;
                                    let unacked = helper.received - helper.acked;
                                    {
                                        let mut s = self.state();
                                        s.most_unacked = s.most_unacked.max(unacked);
                                    }
                                    if unacked > WINDOW {
                                        self.state().violations.push(format!("{unacked} bytes sent beyond the last acknowledgement"));
                                        return;
                                    }
                                    let restart_now = self.state().restart_after.is_some_and(|n| helper.received >= n);
                                    if restart_now || restarting.is_some() {
                                        // Received, not yet delivered: handed back as the replay.
                                        replay.extend_from_slice(&payload);
                                        if restart_now {
                                            self.state().restart_after = None;
                                            restarting = Some(tokio::time::Instant::now() + Duration::from_secs(2));
                                            let _ = socket.send(Message::Text(json!({"type": "restart"}).to_string().into())).await;
                                        }
                                        continue;
                                    }
                                    let Some(writer) = helper.writers.get_mut(&stream) else {
                                        self.state().violations.push("data on a stream that is not open".into());
                                        continue;
                                    };
                                    if writer.write_all(&payload).await.is_err() {
                                        continue;
                                    }
                                    helper.taken += payload.len() as u64;
                                    if !lazy {
                                        helper.acked = helper.taken;
                                        let _ = socket.send(send(b'a', 0, &helper.taken.to_be_bytes())).await;
                                    }
                                }
                                b'e' => {
                                    if let Some(writer) = helper.writers.get_mut(&stream) {
                                        let _ = writer.shutdown().await;
                                    }
                                }
                                b'c' => {
                                    helper.writers.remove(&stream);
                                }
                                other => self.state().violations.push(format!("a client frame of kind {:?}", other as char)),
                            }
                        }
                        Message::Close(_) => return,
                        _ => {}
                    }
                }
                Some((kind, stream, payload)) = helper.down_rx.recv(), if restarting.is_none() => {
                    if socket.send(send(kind, stream, &payload)).await.is_err() {
                        return;
                    }
                }
                () = tokio::time::sleep_until(quiet + Duration::from_millis(50)), if ack_due => {
                    helper.acked = helper.taken;
                    let _ = socket.send(send(b'a', 0, &helper.taken.to_be_bytes())).await;
                }
                () = tokio::time::sleep_until(deadline), if restarting.is_some() => {
                    self.state().violations.push("no reply to restart within 2 seconds".into());
                    let _ = socket.close(Some(CloseFrame { code: CloseCode::Restart, reason: "".into() })).await;
                    return;
                }
            }
        }
    }
}
async fn start_guest(token: Token) -> Guest {
    let dir = tempfile::tempdir().unwrap();
    let (keep, control) = drydock_transport::memory();
    let listener = TokenListener::bind("127.0.0.1:0".parse().unwrap(), token.clone()).await.unwrap();
    let address = listener.local_addr();
    let mut agent = Agent::new(control, "test-build".into(), dir.path().join("agent"));
    agent.add_listener(listener);
    Guest { address, token, task: tokio::spawn(agent.run()), _dir: dir, _keep: keep }
}

/// The host's HTTP client, answered in process by the stand-in.
struct Wire(StandIn);
#[async_trait]
impl HttpClient for Wire {
    async fn execute(&self, request: reqwest::Request, _: &ChannelLabel) -> std::result::Result<http::Response<Bytes>, String> {
        let bootstrap = request.url().path().ends_with(":exec")
            && body(&request)["argv"][2].as_str().is_some_and(|s| s.contains("--supervise"))
            && request.headers().get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {KEY}"))
            && self.0.state().outage.is_none();
        if bootstrap {
            self.0.bootstrap(&request).await;
        }
        Ok(self.0.respond(&request))
    }
}

struct World {
    stand_in: StandIn,
    provider: Arc<dyn Provider>,
    credentials: Credentials,
}
impl Drop for World {
    fn drop(&mut self) {
        let violations = {
            let mut s = self.stand_in.state();
            for task in s.tunnels.drain(..) {
                task.abort();
            }
            s.parked.clear();
            s.sandboxes.clear();
            std::mem::take(&mut s.violations)
        };
        if !std::thread::panicking() {
            assert!(violations.is_empty(), "Runtime contract violations: {violations:?}");
        }
    }
}
async fn world_with(name: &str, stand_in: StandIn) -> World {
    let (dialer, listener) = drydock_transport::memory();
    tokio::spawn(stand_in.clone().serve_tunnels(listener));
    let config = ProviderConfiguration { module: "runtime".into(), settings: Default::default(), credential: None };
    let module = RuntimeModule::with_dialer(Arc::new(dialer));
    let provider = module.configure(name, &config, Arc::new(Wire(stand_in.clone()))).await.unwrap();
    World { stand_in, provider, credentials: Credentials::new(Some(Secret::new(KEY))) }
}
async fn world() -> World {
    world_with("runtime", StandIn::default()).await
}
fn size(cpus: f64, memory_gib: u64, disk_gib: u64) -> Size {
    Size { cpus, memory_bytes: memory_gib << 30, disk_bytes: disk_gib << 30 }
}
fn prepare_request(image_digest: &str, image_pull: Option<RegistryCredential>) -> PrepareRequest {
    PrepareRequest {
        size: size(1.0, 1, 4),
        platform: Some(Platform::new("linux", "amd64")),
        route: Some(ImageRouteKind::RegistryPull),
        image_pull,
        image_digest: image_digest.into(),
        tools_digest: TOOLS.into(),
    }
}
fn host(h: &str) -> Destination {
    Destination::Host { host: h.parse().unwrap() }
}
impl World {
    async fn prepared(&self) -> Prepared {
        self.provider.prepare(prepare_request(BASE, None), &self.credentials).await.unwrap()
    }
    async fn provision(&self, label: &str, size: Size, egress: EgressRequest) -> Result<Provisioned> {
        let prepared = self.prepared().await;
        self.provider
            .provision(ProvisionRequest { label: label.into(), prepared, size, egress, ssh_public_key: None }, &self.credentials)
            .await
    }
    async fn launched(&self, label: &str) -> Environment {
        self.provision(label, size(1.0, 1, 4), EgressRequest::Open).await.unwrap().into_inner()
    }
    /// The agent's hello through the provider's relay.
    async fn agent(&self, id: &str) -> Client {
        let stream = self.provider.relay(id, &self.credentials).await.unwrap();
        Client::connect(Box::new(stream), "test-build").await.unwrap()
    }
    fn image_requests(&self) -> usize {
        self.stand_in.state().requests.iter().filter(|r| r == &"POST /v1/images").count()
    }
}

// Prepare builds the image once from a Dockerfile copying the tools image's
// /opt/drydock onto the base (both pinned to linux/amd64), polls it ready,
// and names it by base and platform. A second prepare finds it by name.
// Image paths take UUIDs only, so the lookup lists by name.
#[tokio::test(start_paused = true)]
async fn prepare_builds_once_then_finds_the_image_by_name() {
    let w = world().await;
    w.stand_in.state().build_polls = 2;
    let first = w.prepared().await;
    assert!(first.id.starts_with("dd-"));
    {
        let s = w.stand_in.state();
        let image = s.images.values().next().unwrap();
        assert_eq!((image.name.as_str(), image.state.as_str()), (first.id.as_str(), "ready"));
        assert_eq!(
            image.dockerfile,
            format!(
                "FROM --platform=linux/amd64 {TOOLS} AS drydock_tools\nFROM --platform=linux/amd64 {BASE}\nCOPY --from=drydock_tools /opt/drydock/ /opt/drydock/\n"
            )
        );
    }
    assert_eq!(w.prepared().await.id, first.id);
    assert_eq!(w.image_requests(), 1, "found by name, not rebuilt");
}

// A failed build is refused with Runtime's error and the tail of its build
// log, which says what really failed when Runtime blames its builder.
#[tokio::test(start_paused = true)]
async fn a_failed_build_reports_its_log_tail() {
    let w = world().await;
    w.stand_in.state().build_failure = Some((
        "A fault in our builder stopped this build; try again.".into(),
        vec!["ERROR: ghcr.io/example/base: manifest unknown".into()],
    ));
    match w.provider.prepare(prepare_request(BASE, None), &w.credentials).await {
        Err(ProtocolError::Refused { reason }) => {
            assert!(reason.contains("fault in our builder") && reason.contains("manifest unknown"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
}

// A base or tools image on a private address is refused before any request;
// a private registry needs a login stored in the account, and builds once one is.
#[tokio::test(start_paused = true)]
async fn private_registries_are_refused_up_front() {
    let w = world().await;
    for registry in ["10.1.2.3:5000", "192.168.1.5", "127.0.0.1:5000", "localhost:5000", "forgejo.lab.internal", "registry:5000"] {
        let reference = format!("{registry}/lab/image@sha256:{}", "3".repeat(64));
        assert!(
            matches!(w.provider.prepare(prepare_request(&reference, None), &w.credentials).await, Err(ProtocolError::Refused { .. })),
            "{registry}"
        );
        let mut request = prepare_request(BASE, None);
        request.tools_digest = reference;
        assert!(matches!(w.provider.prepare(request, &w.credentials).await, Err(ProtocolError::Refused { .. })), "tools {registry}");
    }
    assert!(w.stand_in.state().requests.is_empty());
    let login = || Some(RegistryCredential { username: "robot".into(), secret: Secret::new("pull-secret") });
    let staged = format!("registry.example.com/team/base@sha256:{}", "4".repeat(64));
    match w.provider.prepare(prepare_request(&staged, login()), &w.credentials).await {
        Err(ProtocolError::Refused { reason }) => assert!(reason.contains("POST /v1/images/registries"), "{reason}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(w.image_requests(), 0);
    w.stand_in.state().registries.push("registry.example.com".into());
    w.provider.prepare(prepare_request(&staged, login()), &w.credentials).await.unwrap();
}

// At the account's image limit, prepare deletes the oldest drydock image no
// sandbox started from; when every one is in use it is QuotaExhausted.
#[tokio::test(start_paused = true)]
async fn prepare_frees_an_image_slot_or_refuses() {
    let w = world().await;
    let used = w.launched("vessel-1").await;
    let other = |n: char| format!("ghcr.io/example/other@sha256:{}", n.to_string().repeat(64));
    w.provider.prepare(prepare_request(&other('5'), None), &w.credentials).await.unwrap();
    w.stand_in.state().image_limit = 2;
    let third = w.provider.prepare(prepare_request(&other('6'), None), &w.credentials).await.unwrap();
    let names: Vec<String> = w.stand_in.state().images.values().map(|i| i.name.clone()).collect();
    let in_use = w.stand_in.state().sandboxes[&used.id].labels["drydock.image"].as_str().unwrap().to_owned();
    assert!(names.contains(&in_use) && names.contains(&third.id) && names.len() == 2, "{names:?}");
    // Both images now hold sandboxes: nothing may go.
    w.provider
        .provision(
            ProvisionRequest {
                label: "vessel-2".into(),
                prepared: third,
                size: size(1.0, 1, 4),
                egress: EgressRequest::Open,
                ssh_public_key: None,
            },
            &w.credentials,
        )
        .await
        .unwrap();
    assert!(matches!(
        w.provider.prepare(prepare_request(&other('7'), None), &w.credentials).await,
        Err(ProtocolError::QuotaExhausted { .. })
    ));
}

// Provision creates a persistent, never-idle-paused sandbox named for its
// label, labelled with the instance, label and image, with Prefer: wait and an
// idempotency key; then starts the agent as root with a fresh token in a
// root-only file, never on argv, and without the token or Runtime's identity
// variables in its environment. The agent answers hello through the tunnel.
#[tokio::test]
async fn provision_creates_bootstraps_and_reaches_the_agent() {
    let w = world().await;
    let provisioned = w.provision("vessel-1", size(2.0, 4, 20), EgressRequest::Open).await.unwrap();
    let Provisioned::Created(environment) = provisioned else { panic!("{provisioned:?}") };
    assert_eq!(environment.label.as_deref(), Some("vessel-1"));
    assert_eq!(environment.state, Observation::Running);
    assert_eq!(environment.granted_size, Some(size(2.0, 4, 20)));
    assert!(environment.egress_measured);
    {
        let s = w.stand_in.state();
        let create = &s.creates[0];
        assert_eq!((create["vcpu"].clone(), create["memoryMiB"].clone(), create["diskMiB"].clone()), (json!(2), json!(4096), json!(20480)));
        assert_eq!((create["persistent"].clone(), create["idlePauseSeconds"].clone()), (json!(true), json!(0)));
        assert_eq!(create["network"], json!({"internet": true}));
        assert_eq!(create["labels"]["drydock.provider"], "runtime");
        assert_eq!(create["labels"]["flotilla.label"], "vessel-1");
        let sandbox = &s.sandboxes[&environment.id];
        let guest = sandbox.guest.as_ref().expect("the agent runs");
        assert_eq!(sandbox.token_file.as_deref(), Some(guest.token.secret()));
        assert_eq!(sandbox.agent_port, Some(7811));
        let env = &s.agent_envs[0];
        for stripped in ["DRYDOCK_TCP_TOKEN", "RUNTIME_ID_TOKEN_REQUEST_TOKEN", "RUNTIME_ID_TOKEN_REQUEST_URL"] {
            assert!(!env.contains_key(stripped), "{stripped} reached the agent");
        }
        assert!(env.contains_key("PATH"), "the agent's environment was recorded");
    }
    let client = w.agent(&environment.id).await;
    assert_eq!(client.hello().fingerprint, "test-build");
}

// A repeated provision meets name_taken and adopts the sandbox by name; a
// replayed create of a sandbox since destroyed creates it afresh.
#[tokio::test]
async fn provision_readopts_by_name_and_survives_a_stale_replay() {
    let w = world().await;
    let first = w.launched("vessel-1").await;
    let again = w.provision("vessel-1", size(1.0, 1, 4), EgressRequest::Open).await.unwrap();
    let Provisioned::Existing(again) = again else { panic!("{again:?}") };
    assert_eq!(again.id, first.id);
    w.agent(&again.id).await;
    w.provider.destroy(&first.id, &w.credentials).await.unwrap();
    // The same create within 24 hours replays the deleted sandbox's answer.
    let fresh = w.launched("vessel-1").await;
    assert_ne!(fresh.id, first.id);
    w.agent(&fresh.id).await;
}

// Re-adoption refuses a sandbox of that name that is not this instance's for
// this label, and one of another size or egress policy.
#[tokio::test]
async fn readoption_refuses_another_owner_size_or_policy() {
    let w = world().await;
    let environment = w.launched("vessel-1").await;
    let refused = |r: Result<Provisioned>| matches!(r, Err(ProtocolError::Refused { .. }));
    assert!(refused(w.provision("vessel-1", size(2.0, 2, 4), EgressRequest::Open).await));
    assert!(refused(w.provision("vessel-1", size(1.0, 1, 4), EgressRequest::DenyAll { direct: vec![] }).await));
    w.stand_in.state().sandboxes.get_mut(&environment.id).unwrap().labels["drydock.provider"] = json!("someone-else");
    assert!(refused(w.provision("vessel-1", size(1.0, 1, 4), EgressRequest::Open).await));
}

// A bootstrap whose agent does not start fails provision with the guest's
// output as its cause, never the token.
#[tokio::test]
async fn a_failed_bootstrap_reports_the_guests_output() {
    let w = world().await;
    w.stand_in.state().agent_missing = true;
    let error = w.provision("vessel-1", size(1.0, 1, 4), EgressRequest::Open).await.unwrap_err();
    let token = w.stand_in.state().sandboxes.values().next().unwrap().token_file.clone().unwrap();
    let ProtocolError::Internal { provider_error, .. } = &error else { panic!("{error:?}") };
    assert!(provider_error.contains("drydock-agent': No such file or directory"), "{provider_error}");
    assert!(!format!("{error:?}").contains(&token), "{error:?}");
}

// A restart outside drydock loses every process and /run/drydock: the next
// relay finds nothing listening, bootstraps again with a fresh token and
// reaches the new agent. A stopped sandbox resumes by restart, bootstrapped.
#[tokio::test]
async fn bootstrap_runs_again_after_a_restart_or_stop() {
    let w = world().await;
    let environment = w.launched("vessel-1").await;
    let before = w.stand_in.state().sandboxes[&environment.id].token_file.clone();
    w.stand_in.restart_out_of_band(&environment.id, "running");
    w.agent(&environment.id).await;
    let after = w.stand_in.state().sandboxes[&environment.id].token_file.clone();
    assert!(after.is_some() && after != before, "a fresh token");
    w.stand_in.restart_out_of_band(&environment.id, "stopped");
    let inspected = w.provider.inspect(&environment.id, &w.credentials).await.unwrap();
    assert_eq!(inspected.state, Observation::Stopped { cause: StopCause::GuestHalted });
    let port = w.provider.operations();
    let token = port.suspend_resume.unwrap().suspend(&environment.id, &w.credentials).await.unwrap();
    port.suspend_resume.unwrap().resume(&environment.id, token, &w.credentials).await.unwrap();
    assert!(w.stand_in.state().requests.iter().any(|r| r.ends_with(":restart")));
    w.agent(&environment.id).await;
}

// When the guest's token changed under the module (another bootstrap), the
// agent's 401 makes relay read the token again and connect.
#[tokio::test]
async fn relay_recovers_from_a_stale_token() {
    let w = world().await;
    let environment = w.launched("vessel-1").await;
    w.agent(&environment.id).await;
    w.stand_in.rotate_token(&environment.id).await;
    w.agent(&environment.id).await;
}

// Ending our input sends `e`, and the guest connection sees its end: the
// agent closes, and the stream reads to its end without error.
#[tokio::test]
async fn relay_half_closes() {
    let w = world().await;
    let environment = w.launched("vessel-1").await;
    let mut stream = w.provider.relay(&environment.id, &w.credentials).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut rest)).await.unwrap().unwrap();
    assert_eq!(w.stand_in.state().frames, b"ode", "an open, the handshake, then the end of our input");
}

// Large transfers both ways stay within the 1 MiB acknowledgement window
// even when Runtime acknowledges only once the client has paused.
#[tokio::test]
async fn relay_keeps_within_the_ack_window() {
    let w = world().await;
    let environment = w.launched("vessel-1").await;
    w.stand_in.state().lazy_acks = true;
    let client = w.agent(&environment.id).await;
    let content: Vec<u8> = (0..3u32 << 20).map(|i| (i % 251) as u8).collect();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transfer");
    client.write_bytes(&path, content.clone(), &FileOptions::default()).await.unwrap();
    assert_eq!(client.read_bytes(&path, 4 << 20).await.unwrap(), content);
    let most = w.stand_in.state().most_unacked;
    assert!(most > WINDOW / 2 && most <= WINDOW, "{most}");
}

// When Runtime's API restarts mid-transfer the module replies, reopens with
// the resume token, sends the replay first, and the transfer completes intact.
#[tokio::test]
async fn relay_resumes_after_an_api_restart_mid_stream() {
    let w = world().await;
    let environment = w.launched("vessel-1").await;
    let client = w.agent(&environment.id).await;
    w.stand_in.state().restart_after = Some(256 << 10);
    let content: Vec<u8> = (0..1u32 << 20).map(|i| (i % 253) as u8).collect();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transfer");
    client.write_bytes(&path, content.clone(), &FileOptions::default()).await.unwrap();
    assert_eq!(client.read_bytes(&path, 2 << 20).await.unwrap(), content);
    let s = w.stand_in.state();
    assert_eq!((s.resumes, s.replays_sent), (1, 1));
}

// A sandbox paused mid-stream ends the stream with Runtime's
// sandbox_not_running; relay then refuses it rather than waking it.
#[tokio::test]
async fn a_pause_mid_stream_ends_it_with_an_error() {
    let w = world().await;
    let environment = w.launched("vessel-1").await;
    let mut stream = w.provider.relay(&environment.id, &w.credentials).await.unwrap();
    w.stand_in.set_state(&environment.id, "paused");
    let _ = stream.write_all(b"GET /hello HTTP/1.1\r\nHost: agent\r\n\r\n").await;
    let mut answer = Vec::new();
    let error = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer)).await.unwrap().unwrap_err();
    assert!(error.to_string().contains("sandbox_not_running"), "{error}");
    assert!(matches!(w.provider.relay(&environment.id, &w.credentials).await, Err(ProtocolError::Refused { .. })));
}

// Egress requests become Runtime's rules, in the form Runtime stores: open is
// internet; deny-all is no internet; hosts and single addresses are an allow
// list; a host and port is a connect pair. Each reads back equal, so the
// label re-adopts. Ranges, IPv6, private addresses and ports Runtime never
// opens are refused, and provision waits until Runtime enforces the rules.
#[tokio::test]
async fn egress_requests_map_to_network_rules() {
    let w = world().await;
    w.stand_in.state().enforce_lag = 2;
    let port = |h: &str, p| Destination::HostPort { host: h.parse().unwrap(), port: Port::new(p).unwrap() };
    let cases = [
        (vec![], json!({"internet": false})),
        (
            vec![host("GitHub.com."), Destination::Cidr { cidr: "203.0.113.7/32".parse().unwrap() }],
            json!({"internet": true, "allow": ["203.0.113.7", "github.com"]}),
        ),
        (
            vec![host("github.com"), port("db.example.com", 5432)],
            json!({"internet": true, "allow": ["github.com"], "connect": ["db.example.com:5432"]}),
        ),
    ];
    for (index, (direct, network)) in cases.into_iter().enumerate() {
        let label = format!("egress-{index}");
        let environment =
            w.provision(&label, size(1.0, 1, 4), EgressRequest::DenyAll { direct: direct.clone() }).await.unwrap().into_inner();
        assert_eq!(w.stand_in.state().creates.last().unwrap()["network"], network, "{label}");
        assert!(environment.egress_measured, "{label}");
        let again = w.provision(&label, size(1.0, 1, 4), EgressRequest::DenyAll { direct }).await.unwrap();
        assert!(matches!(again, Provisioned::Existing(_)), "{label} re-adopts");
        assert_eq!(again.into_inner().egress_policy, environment.egress_policy);
    }
    let creates = w.stand_in.state().creates.len();
    for destination in
        [Destination::Cidr { cidr: "203.0.113.0/24".parse().unwrap() }, host("2001:db8::1"), host("10.0.0.5"), port("mail.example.com", 25)]
    {
        let request = EgressRequest::DenyAll { direct: vec![destination.clone()] };
        assert!(matches!(w.provision("refused", size(1.0, 1, 4), request).await, Err(ProtocolError::Refused { .. })), "{destination:?}");
    }
    assert_eq!(w.stand_in.state().creates.len(), creates, "refused before any create");
}

// Without credit, host:port rules are refused before create, naming trial
// funding, and sandboxes are created without persistent, which Runtime refuses.
#[tokio::test]
async fn trial_funding_refuses_connect_and_skips_persistent() {
    let w = world().await;
    w.stand_in.state().trial = true;
    let request = EgressRequest::DenyAll {
        direct: vec![Destination::HostPort { host: "db.example.com".parse().unwrap(), port: Port::new(5432).unwrap() }],
    };
    match w.provision("db", size(1.0, 1, 4), request).await {
        Err(ProtocolError::Refused { reason }) => {
            assert!(reason.contains("trial funding") && reason.contains("connect_not_allowed"), "{reason}")
        }
        other => panic!("{other:?}"),
    }
    let environment =
        w.provision("web", size(1.0, 1, 4), EgressRequest::DenyAll { direct: vec![host("github.com")] }).await.unwrap().into_inner();
    assert_eq!(w.stand_in.state().creates.last().unwrap()["persistent"], false);
    w.agent(&environment.id).await;
    assert_eq!(w.provider.readiness(&w.credentials), Readiness::Ready);
}

// Suspend pauses (memory and the agent kept) and returns the deterministic
// marker; resume wakes it and bootstraps, keeping the agent's token; another
// marker is refused; a sandbox still resuming is Unavailable.
#[tokio::test]
async fn suspend_and_resume_keep_the_agent() {
    let w = world().await;
    let environment = w.launched("vessel-1").await;
    let token_before = w.stand_in.state().sandboxes[&environment.id].token_file.clone();
    let ports = w.provider.operations();
    let port = ports.suspend_resume.unwrap();
    let token = port.suspend(&environment.id, &w.credentials).await.unwrap();
    assert_eq!(
        w.provider.inspect(&environment.id, &w.credentials).await.unwrap().state,
        Observation::Stopped { cause: StopCause::SuspendedByRequest }
    );
    assert!(port.resume(&environment.id, ResumeToken { token: Secret::new("runtime-resume-other") }, &w.credentials).await.is_err());
    port.resume(&environment.id, token, &w.credentials).await.unwrap();
    assert_eq!(w.provider.inspect(&environment.id, &w.credentials).await.unwrap().state, Observation::Running);
    assert_eq!(w.stand_in.state().sandboxes[&environment.id].token_file, token_before, "the kept agent's token");
    w.agent(&environment.id).await;
    w.stand_in.set_state(&environment.id, "resuming");
    assert!(matches!(port.suspend(&environment.id, &w.credentials).await, Err(ProtocolError::Unavailable { .. })));
}

// Destroy deletes this instance's sandbox, and again is success; another
// instance's sandbox is left alone.
#[tokio::test]
async fn destroy_is_idempotent_and_spares_others() {
    let stand_in = StandIn::default();
    let ours = world_with("runtime", stand_in.clone()).await;
    let theirs = world_with("runtime-other", stand_in.clone()).await;
    let environment = ours.launched("vessel-1").await;
    let other = theirs.launched("vessel-1").await;
    ours.provider.destroy(&environment.id, &ours.credentials).await.unwrap();
    ours.provider.destroy(&environment.id, &ours.credentials).await.unwrap();
    assert!(matches!(ours.provider.inspect(&environment.id, &ours.credentials).await, Err(ProtocolError::NotFound { .. })));
    assert!(matches!(ours.provider.destroy(&other.id, &ours.credentials).await, Err(ProtocolError::Refused { .. })));
    assert!(stand_in.state().sandboxes.contains_key(&other.id));
    assert_eq!(stand_in.state().images.len(), 1, "the image stays for later vessels");
}

// List pages through this instance's sandboxes by label, stopped ones
// included, each with its label.
#[tokio::test]
async fn list_keeps_this_instances_sandboxes() {
    let stand_in = StandIn::default();
    let ours = world_with("runtime", stand_in.clone()).await;
    let theirs = world_with("runtime-other", stand_in.clone()).await;
    let mut ids = vec![];
    for label in ["a", "b", "c"] {
        ids.push(ours.launched(label).await.id);
    }
    theirs.launched("a").await;
    stand_in.restart_out_of_band(&ids[0], "stopped");
    stand_in.state().sandboxes.get_mut(&ids[0]).unwrap().persistent = false;
    let mut labels: Vec<_> = ours.provider.list(&ours.credentials).await.unwrap().into_iter().map(|e| e.label.unwrap()).collect();
    labels.sort();
    assert_eq!(labels, ["a", "b", "c"]);
    assert!(stand_in.state().requests.iter().any(|r| r == "GET /v1/sandboxes"));
}

// Quota reads /v1/limits: sandboxes, vCPU and memory with their limits,
// concurrency from the sandbox count, and the credit left in USD.
#[tokio::test]
async fn quota_reads_the_accounts_limits() {
    let w = world().await;
    w.launched("vessel-1").await;
    let quota = w.provider.operations().quota.unwrap().quota(&w.credentials).await.unwrap();
    assert_eq!((quota.concurrency_in_use, quota.concurrency_limit), (Some(1), Some(10)));
    assert_eq!((quota.credits_remaining, quota.credit_unit.as_deref()), (Some(50.0), Some("USD")));
    let memory = quota.resources.iter().find(|r| r.key.resource == ResourceKind::Memory).unwrap();
    assert_eq!((memory.in_use, memory.limit, memory.unit.as_str()), (1024.0 * (1 << 20) as f64, Some(65536.0 * (1 << 20) as f64), "By"));
    assert!(quota.resources.iter().all(|r| r.key.resource.accepts_unit(&r.unit)));
}

// Usage reads the settled export over the period with millisecond UTC
// bounds, through every page: the charge in exact USD and the sandboxes charged.
#[tokio::test]
async fn usage_sums_the_settled_export() {
    let w = world().await;
    let row = |id: &str, kind: &str, micros: &str| {
        json!({"intervalId": "00000000-0000-4000-8000-0000000000aa", "resourceId": id, "name": null, "kind": kind, "meter": "compute",
            "fundedBy": "credit", "startsAt": "", "endsAt": "", "settledAt": "", "billedMilliseconds": "1000", "chargedMicros": micros,
            "quotedRates": [], "measurementsJson": null, "evidence": "measured", "final": true})
    };
    let a = "00000000-0000-4000-8000-0000000000a1";
    w.stand_in.state().usage =
        vec![row(a, "sandbox", "1500000"), row(a, "sandbox", "250001"), row("00000000-0000-4000-8000-0000000000b1", "image", "3")];
    let period: Period = serde_json::from_value(json!({"start": "2026-11-01T00:00:00Z", "end": "2026-11-02T00:00:00Z"})).unwrap();
    let usage = w.provider.operations().usage.unwrap().usage(period, &w.credentials).await.unwrap();
    let measurements = usage.measurements.unwrap();
    assert_eq!(measurements.cost, Some(Cost { amount: "1.750004".into(), currency: "USD".into() }));
    assert_eq!(measurements.resources[&ResourceKind::Environments].amount, 1.0);
    assert_eq!(w.stand_in.state().usage_query, Some(("2026-11-01T00:00:00.000Z".into(), "2026-11-02T00:00:00.000Z".into())));
}

// Exec runs the command as root and returns its output; a failing command
// is CommandFailed with its exit code.
#[tokio::test]
async fn exec_returns_output_and_reports_failure() {
    let w = world().await;
    let environment = w.launched("vessel-1").await;
    w.stand_in.state().exec_output = "hello\n".into();
    let ports = w.provider.operations();
    let exec = ports.exec.unwrap();
    let mut stream = exec.exec(&environment.id, ExecRequest { command: vec!["echo".into(), "it's".into()] }, &w.credentials).await.unwrap();
    let mut output = String::new();
    stream.read_to_string(&mut output).await.unwrap();
    assert_eq!(output, "hello\n");
    assert_eq!(w.stand_in.state().execs.last().unwrap()["argv"][2], "'echo' 'it'\\''s'");
    w.stand_in.state().exec_exit = 3;
    match exec.exec(&environment.id, ExecRequest { command: vec!["false".into()] }, &w.credentials).await {
        Err(ProtocolError::CommandFailed { exit_code: 3, .. }) => {}
        other => panic!("{:?}", other.map(drop)),
    }
}

// Runtime's errors map by status and code: a rejected or missing key is
// CredentialRejected, rate limits RateLimited with Retry-After, a retryable
// 503 Unavailable with its delay, and quotas and spending limits QuotaExhausted.
#[tokio::test]
async fn vendor_errors_map_to_protocol_errors() {
    let w = world().await;
    let environment = w.launched("vessel-1").await;
    let wrong = Credentials::new(Some(Secret::new("rtcloud_wrong")));
    assert!(matches!(w.provider.list(&wrong).await, Err(ProtocolError::CredentialRejected { .. })));
    assert!(matches!(w.provider.list(&Credentials::default()).await, Err(ProtocolError::CredentialRejected { .. })));
    for (status, code, check) in [
        (
            429u16,
            "rate_limited",
            (|e: &ProtocolError| matches!(e, ProtocolError::RateLimited { retry_after: Some(7), .. })) as fn(&ProtocolError) -> bool,
        ),
        (503, "no_capacity", |e| matches!(e, ProtocolError::Unavailable { retry_after: Some(7), .. })),
        (429, "quota_exceeded", |e| matches!(e, ProtocolError::QuotaExhausted { .. })),
        (402, "spending_limit_reached", |e| matches!(e, ProtocolError::QuotaExhausted { .. })),
    ] {
        w.stand_in.state().outage = Some((status, code.into(), Some(7)));
        let error = w.provider.list(&w.credentials).await.unwrap_err();
        assert!(check(&error), "{status} {code}: {error:?}");
    }
    w.stand_in.state().outage = None;
    assert!(matches!(w.provider.relay(&environment.id, &wrong).await, Err(ProtocolError::CredentialRejected { .. })));
}

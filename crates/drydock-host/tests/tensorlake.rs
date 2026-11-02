//! The Tensorlake module against an in-process stand-in at the vendor's
//! HTTP and WebSocket boundaries. The stand-in holds sandboxes, snapshots,
//! images and builds in memory and enforces Tensorlake's documented
//! requests (and what the live probe found): the Bearer key on both planes,
//! name rules and 409 on a duplicate, the per-sandbox limit texts, the CAS
//! build lifecycle, suspend snapshots that outlive their sandbox, exec's
//! lossy UTF-8 lines, a tunnel that drops frames over 64 KiB and never
//! completes a close, and hostname rules that cannot resolve without
//! internet access. A real drydock agent answers behind each tunnel.
use async_trait::async_trait;
use bytes::Bytes;
use drydock_agent::{Agent, Client, FileOptions, tcp::TokenListener};
use drydock_host::{module::*, tensorlake::TensorlakeModule};
use drydock_protocol::*;
use drydock_transport::{
    ByteStream, Listener,
    tcp::Token,
    websocket::{
        tokio_tungstenite::{WebSocketStream, accept_hdr_async_with_config},
        tungstenite::{
            Message,
            handshake::server::{ErrorResponse, Request, Response},
            protocol::WebSocketConfig,
        },
    },
};
use futures::{SinkExt, StreamExt};
use rigging_http_client::ChannelLabel;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const KEY: &str = "tl_apiKey_test";
const API: &str = "api.tensorlake.ai";
const DOMAIN: &str = ".sandbox.tensorlake.ai";
const UPLOADS: &str = "uploads.invalid";
const PROXY_FRAME_LIMIT: usize = 64 << 10;
const BASE: &str = "ghcr.io/example/base@sha256:1111111111111111111111111111111111111111111111111111111111111111";
const TOOLS: &str = "ghcr.io/flotilla-org/drydock-tools@sha256:2222222222222222222222222222222222222222222222222222222222222222";

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
struct Sandbox {
    id: String,
    name: String,
    status: String,
    resources: Value,
    network: Value,
    image: String,
    /// Reads left before a pending sandbox runs.
    pending_reads: u32,
    /// /run/drydock/tcp.token in the guest.
    token_file: Option<String>,
    /// The `--tcp` port the agent was started with.
    agent_port: Option<u16>,
    guest: Option<Guest>,
}
impl Sandbox {
    fn info(&self) -> Value {
        json!({
            "id": self.id, "name": self.name, "namespace": "project-1", "status": self.status,
            "created_at": 1_793_000_000_000u64, "resources": self.resources, "timeout_secs": 86400,
            "allow_unauthenticated_access": false, "auto_resume": true, "image": self.image,
            "network_policy": self.network, "sandbox_url": format!("https://{}{DOMAIN}", self.name),
        })
    }
}

#[derive(Default)]
struct Build {
    name: String,
    status: String,
    dockerfile: Option<String>,
    sealed_digest: Option<String>,
    context: Option<Vec<u8>>,
    credentials: Option<Value>,
    polls_left: u32,
    error: Option<String>,
}

#[derive(Default)]
struct State {
    sandboxes: BTreeMap<String, Sandbox>,
    archived: Vec<Value>,
    snapshots: BTreeMap<String, Value>,
    images: BTreeMap<String, Value>,
    builds: BTreeMap<String, Build>,
    creates: Vec<Value>,
    violations: Vec<String>,
    requests: Vec<String>,
    /// Running sandboxes the project may hold; more is "at its quota".
    running_limit: Option<usize>,
    /// Builds end failed with this error.
    build_failure: Option<String>,
    /// Snapshot deletes that answer 500 before they succeed.
    snapshot_delete_failures: u32,
    /// Raw bytes an exec prints, and its exit code.
    exec_output: Vec<u8>,
    exec_exit: i64,
    /// The tools layer is missing from the image, so the bootstrap's exec fails.
    agent_missing: bool,
    /// Every image name asked for already exists, as after an earlier
    /// prepare; tests of prepare itself start without.
    images_exist: bool,
    /// The usage export's NDJSON body.
    usage: Option<String>,
    usage_query: Option<(String, String)>,
    /// Every request answers this status and text, as an outage would.
    outage: Option<(u16, String, Option<u64>)>,
    /// The next create answers 504 with status "timeout", the sandbox pending.
    create_times_out: bool,
    tunnels: Vec<tokio::task::JoinHandle<()>>,
    /// Tunnels in use, and a switch that drops them without a close frame.
    drop_tunnels: Option<tokio::sync::watch::Sender<bool>>,
    next: u64,
}
impl State {
    fn id(&mut self, prefix: &str) -> String {
        self.next += 1;
        format!("{prefix}{:0>width$}", self.next, width = 21 - prefix.len())
    }
}

#[derive(Clone, Default)]
struct StandIn(Arc<Mutex<State>>);

fn reply(status: u16, body: impl Into<Bytes>) -> http::Response<Bytes> {
    http::Response::builder().status(status).body(body.into()).unwrap()
}
fn json_reply(status: u16, body: Value) -> http::Response<Bytes> {
    http::Response::builder().status(status).header("content-type", "application/json").body(Bytes::from(body.to_string())).unwrap()
}
/// Guest-plane and Image Service errors are JSON; the control plane's are text.
fn proxy_error(status: u16, message: &str) -> http::Response<Bytes> {
    json_reply(status, json!({"error": message}))
}
fn query(request: &reqwest::Request) -> BTreeMap<String, String> {
    request.url().query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect()
}
fn body(request: &reqwest::Request) -> Value {
    request.body().and_then(|b| b.as_bytes()).filter(|b| !b.is_empty()).map(|b| serde_json::from_slice(b).unwrap()).unwrap_or(Value::Null)
}
/// Tensorlake's name rules: lowercase letters, digits and hyphens, at most 63,
/// not ending in a hyphen, and never 21 alphanumerics (an id's shape).
fn name_allowed(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.ends_with('-')
        && !(name.len() == 21 && name.bytes().all(|b| b.is_ascii_alphanumeric()))
}
/// A page of `rows` under `key`, two at a time so paging is exercised.
fn page(rows: Vec<Value>, request: &reqwest::Request, key: &str, cursor_key: &str) -> http::Response<Bytes> {
    let start: usize = query(request).get("cursor").map(|c| c.parse().unwrap()).unwrap_or(0);
    let end = (start + 2).min(rows.len());
    let next = (end < rows.len()).then(|| end.to_string());
    json_reply(200, json!({key: rows[start..end].to_vec(), cursor_key: next}))
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
        s.requests.push(format!("{method} {host}{path}"));
        let authorization = request.headers().get("authorization").and_then(|v| v.to_str().ok()).map(str::to_owned);
        if host == UPLOADS {
            // Presigned: the URL is the authorization, and a Bearer key must not travel to the store.
            if authorization.is_some() {
                s.violations.push("an API key was sent to the presigned upload URL".into());
            }
            let id = path.trim_start_matches("/context/");
            let bytes = request.body().and_then(|b| b.as_bytes()).unwrap_or_default().to_vec();
            return match s.builds.get_mut(id) {
                Some(build) => {
                    build.context = Some(bytes);
                    reply(200, "")
                }
                None => reply(403, "<Error>SignatureDoesNotMatch</Error>"),
            };
        }
        let guest = host.strip_suffix(DOMAIN).map(str::to_owned);
        if authorization.as_deref() != Some(&format!("Bearer {KEY}")) {
            return if guest.is_some() { proxy_error(401, "Unauthorized") } else { reply(401, "Unauthorized") };
        }
        if let Some((status, text, retry_after)) = s.outage.clone() {
            let mut response = reply(status, text);
            if let Some(seconds) = retry_after {
                response.headers_mut().insert("retry-after", seconds.into());
            }
            return response;
        }
        if let Some(name) = guest {
            return guest_plane(&mut s, &name, &method, &path, request);
        }
        if host != API {
            s.violations.push(format!("request to an unknown host {host}"));
            return reply(400, "unknown host");
        }
        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        match (method.as_str(), segments.as_slice()) {
            ("POST", ["sandboxes"]) => create(&mut s, body(request)),
            ("GET", ["sandboxes"]) => {
                let rows = s.sandboxes.values().map(Sandbox::info).collect();
                page(rows, request, "sandboxes", "next_cursor")
            }
            ("GET", ["archived-sandboxes"]) => page(s.archived.clone(), request, "sandboxes", "next_cursor"),
            // By id only, as the SDK addresses them: a name falls back to the list.
            ("GET", ["archived-sandboxes", id]) => match s.archived.iter().find(|row| row["id"] == *id) {
                Some(row) => json_reply(200, row.clone()),
                None => reply(404, "sandbox not found"),
            },
            // A sandbox's snapshots, for as long as its record lasts.
            ("GET", ["sandboxes", id, "snapshots"]) => {
                let known = s.sandboxes.values().any(|sb| sb.id == *id) || s.archived.iter().any(|row| row["id"] == *id);
                if !known {
                    return reply(404, "sandbox not found");
                }
                let rows = s.snapshots.values().filter(|snapshot| snapshot["sandbox_id"] == *id).cloned().collect();
                page(rows, request, "snapshots", "cursor")
            }
            ("GET", ["sandboxes", key]) => {
                let Some(sandbox) = find(&mut s, key) else { return reply(404, "sandbox not found") };
                if sandbox.status == "pending" {
                    if sandbox.pending_reads == 0 {
                        sandbox.status = "running".into();
                    } else {
                        sandbox.pending_reads -= 1;
                    }
                }
                json_reply(200, sandbox.info())
            }
            ("DELETE", ["sandboxes", key]) => {
                let Some(name) = find(&mut s, key).map(|sandbox| sandbox.name.clone()) else {
                    // Idempotent: an archived sandbox deletes again.
                    let known = s.archived.iter().any(|row| row["name"] == *key || row["id"] == *key);
                    return if known { reply(200, "") } else { reply(404, "sandbox not found") };
                };
                let sandbox = s.sandboxes.remove(&name).unwrap();
                let mut row = sandbox.info();
                row["status"] = json!("terminated");
                row["archived_at"] = json!(1_793_000_100_000u64);
                s.archived.push(row);
                reply(200, "")
            }
            ("POST", ["sandboxes", key, "suspend"]) => {
                let suspended = s.snapshots.len() + 1;
                let Some(sandbox) = find(&mut s, key) else { return reply(404, "sandbox not found") };
                match sandbox.status.as_str() {
                    "suspended" => reply(200, ""),
                    "running" => {
                        sandbox.status = "suspended".into();
                        let (id, sandbox_id) = (format!("suspend-{}-{suspended}", sandbox.id), sandbox.id.clone());
                        // Every suspend leaves a billed snapshot that outlives the sandbox.
                        s.snapshots.insert(id.clone(), json!({"snapshot_id": id, "namespace": "project-1", "sandbox_id": sandbox_id, "status": "completed", "snapshot_type": "memory"}));
                        reply(202, "")
                    }
                    status => reply(400, format!("sandbox cannot be suspended while {status}")),
                }
            }
            ("POST", ["sandboxes", key, "resume"]) => {
                let Some(sandbox) = find(&mut s, key) else { return reply(404, "sandbox not found") };
                match sandbox.status.as_str() {
                    "suspended" | "resume_failed" => {
                        sandbox.status = "running".into();
                        reply(200, "")
                    }
                    status => reply(400, format!("sandbox cannot be resumed while {status}")),
                }
            }
            ("PATCH", ["sandboxes", _]) => {
                s.violations.push("the module never updates a sandbox".into());
                reply(400, "unexpected")
            }
            ("GET", ["snapshots"]) => page(s.snapshots.values().cloned().collect(), request, "snapshots", "cursor"),
            ("DELETE", ["snapshots", id]) => {
                if s.snapshot_delete_failures > 0 {
                    s.snapshot_delete_failures -= 1;
                    return reply(500, "snapshot store unavailable");
                }
                match s.snapshots.remove(*id) {
                    Some(_) => reply(200, ""),
                    None => reply(404, "snapshot not found"),
                }
            }
            ("GET", ["images", "v4", "images", "name", name]) if s.images_exist => {
                let image = json!({"id": "image_seeded", "name": name, "snapshot_id": "snap-image", "global": false, "physical_size_bytes": 42, "logical_size_bytes": 10_737_418_240u64, "created_at": "2026-11-02T00:00:00.000Z", "updated_at": "2026-11-02T00:00:00.000Z"});
                s.images.insert((*name).to_owned(), image.clone());
                json_reply(200, image)
            }
            ("GET", ["images", "v4", "images", "name", name]) => match s.images.get(*name) {
                Some(image) => json_reply(200, image.clone()),
                None => proxy_error(404, "image not found"),
            },
            ("DELETE", ["images", "v4", "images", ..]) => proxy_error(403, "deleting images requires the 'admin' role"),
            ("POST", ["images", "v4", "builds"]) => admit(&mut s, request),
            ("POST", ["images", "v4", "builds", id, "context", "seal"]) => {
                let digest = body(request)["digest"].as_str().map(str::to_owned);
                let Some(build) = s.builds.get_mut(*id) else { return proxy_error(404, "build not found") };
                let Some(context) = &build.context else { return proxy_error(409, "context not uploaded") };
                let actual = format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(context));
                if digest.as_deref() != Some(&actual) {
                    return proxy_error(400, "context digest mismatch");
                }
                match dockerfile_in(context) {
                    Ok(dockerfile) => {
                        build.dockerfile = Some(dockerfile);
                        build.status = "running".into();
                    }
                    Err(error) => {
                        build.error = Some(error);
                        build.status = "failed".into();
                    }
                }
                build.sealed_digest = digest;
                json_reply(200, json!({"build_id": id, "status": "running"}))
            }
            ("GET", ["images", "v4", "builds", id]) => {
                let failure = s.build_failure.clone();
                let Some(build) = s.builds.get_mut(*id) else { return proxy_error(404, "build not found") };
                if build.status == "running" {
                    if build.polls_left > 0 {
                        build.polls_left -= 1;
                    } else if failure.is_some() {
                        build.status = "failed".into();
                    } else {
                        build.status = "succeeded".into();
                    }
                }
                let (name, status) = (build.name.clone(), build.status.clone());
                let failure = build.error.clone().or(failure);
                if status == "succeeded" && !s.images.contains_key(&name) {
                    let id = s.id("image_");
                    s.images.insert(name.clone(), json!({"id": id, "name": name, "snapshot_id": "snap-image", "global": false, "physical_size_bytes": 42, "logical_size_bytes": 10_737_418_240u64, "created_at": "2026-11-02T00:00:00.000Z", "updated_at": "2026-11-02T00:00:00.000Z"}));
                }
                json_reply(
                    200,
                    json!({"build_id": id, "name": name, "kind": "dockerfile", "status": status, "error": if status == "failed" { json!(failure) } else { Value::Null }}),
                )
            }
            ("GET", ["platform", "v1", "organizations", "org-1", "sandbox-usage", "sandboxes", "export"]) => {
                let q = query(request);
                let valid = |key: &str| {
                    q.get(key).is_some_and(|v| chrono::DateTime::parse_from_rfc3339(v).is_ok() && v.ends_with('Z') && v.contains('.'))
                };
                if !valid("fromDate") || !valid("toDate") {
                    s.violations.push("usage windows are RFC 3339 with milliseconds".into());
                    return reply(400, "invalid window");
                }
                s.usage_query = Some((q["fromDate"].clone(), q["toDate"].clone()));
                reply(200, s.usage.clone().unwrap_or_default())
            }
            _ => {
                s.violations.push(format!("unexpected request {method} {path}"));
                reply(404, "not found")
            }
        }
    }
}
fn find<'a>(s: &'a mut State, key: &str) -> Option<&'a mut Sandbox> {
    let name = s.sandboxes.values().find(|sandbox| sandbox.name == key || sandbox.id == key)?.name.clone();
    s.sandboxes.get_mut(&name)
}
/// The Dockerfile from a plain tar build context. Tensorlake's builder
/// decodes every entry's numeric fields, and fails the build on one that
/// isn't a number.
fn dockerfile_in(context: &[u8]) -> std::result::Result<String, String> {
    let mut archive = tar::Archive::new(context);
    let mut entries = archive.entries().unwrap();
    let mut entry = entries.next().expect("the context holds the Dockerfile").unwrap();
    for (field, value) in [("uid", entry.header().uid()), ("gid", entry.header().gid())] {
        if value.is_err() {
            return Err(format!("decode {field}: numeric field was not a number"));
        }
    }
    assert_eq!(entry.path().unwrap().to_str(), Some("Dockerfile"));
    let mut text = String::new();
    std::io::Read::read_to_string(&mut entry, &mut text).unwrap();
    assert!(entries.next().is_none(), "the context holds only the Dockerfile");
    Ok(text)
}
/// The guest's token file after the bootstrap's own shell code (everything
/// before it execs the agent) runs over it, with /run/drydock moved to a
/// temporary directory.
fn token_file_after(script: &str, existing: Option<&str>, token: Option<&Token>) -> Option<String> {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path().join("run");
    let (prefix, _) = script.split_once(" && exec ")?;
    let prefix = prefix.replace("/run/drydock", run.to_str()?).replace("/workspace", dir.path().join("workspace").to_str()?);
    if let Some(existing) = existing {
        std::fs::create_dir(&run).unwrap();
        std::fs::write(run.join("tcp.token"), existing).unwrap();
    }
    let status = std::process::Command::new("sh")
        .args(["-c", &prefix])
        .env("DRYDOCK_TCP_TOKEN", token.map(Token::secret).unwrap_or_default())
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "bootstrap's shell code failed: {prefix}");
    std::fs::read_to_string(run.join("tcp.token")).ok()
}
/// What the guest's `drydock-agent --supervise` makes of the bootstrap's
/// argv, through the supervisor's own parser: the agent's start, or the
/// output and exit status of its refusal.
fn supervise(script: &str) -> std::result::Result<(), (String, i64)> {
    const EXEC: &str = "exec env -u DRYDOCK_TCP_TOKEN /opt/drydock/drydock-agent --supervise ";
    let Some((_, argv)) = script.split_once(EXEC) else { return Err((format!("sh: unexpected bootstrap {script}"), 2)) };
    let argv: Vec<std::ffi::OsString> = argv.split_whitespace().map(Into::into).collect();
    drydock_agent::socket::supervised(&argv).map(drop).map_err(|e| (e.to_string(), 1))
}
fn create(s: &mut State, body: Value) -> http::Response<Bytes> {
    s.creates.push(body.clone());
    let allowed = ["name", "image", "resources", "timeout_secs", "network", "auto_resume", "wait"];
    for key in body.as_object().unwrap().keys() {
        if !allowed.contains(&key.as_str()) {
            // Notably env, secrets or entrypoint: no secrets in the create request.
            s.violations.push(format!("unexpected create field {key}"));
        }
    }
    let name = body["name"].as_str().unwrap_or_default().to_owned();
    if !name_allowed(&name) {
        return reply(400, "Invalid sandbox name");
    }
    if s.sandboxes.contains_key(&name) {
        return reply(409, format!("Sandbox with name '{name}' already exists"));
    }
    let image = body["image"].as_str().unwrap_or_default().to_owned();
    if !s.images.contains_key(&image) {
        return reply(404, "image not found");
    }
    let resources = &body["resources"];
    let (cpus, memory, disk) = (
        resources["cpus"].as_f64().unwrap_or(1.0),
        resources["memory_mb"].as_u64().unwrap_or(1024),
        resources["disk_mb"].as_u64().unwrap_or(10240),
    );
    if cpus > 4.0 {
        return reply(400, "Per-sandbox vCPU limit exceeded: the plan allows 4");
    }
    if memory > 16384 || (memory as f64) < cpus * 1024.0 || (memory as f64) > cpus * 8192.0 {
        return reply(400, "Per-sandbox memory limit exceeded: 1 to 8 GiB per vCPU, at most 16 GiB");
    }
    if !(10240..=102400).contains(&disk) {
        return reply(400, "disk_mb must be between 10240 and 102400");
    }
    if s.running_limit.is_some_and(|limit| s.sandboxes.values().filter(|sb| sb.status == "running").count() >= limit) {
        return reply(400, "project has reached its quota of running sandboxes");
    }
    if let Some(network) = body.get("network") {
        let names: Vec<&str> = network["allow_out"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|e| e.parse::<std::net::Ipv4Addr>().is_err() && !e.contains('/'))
            .collect();
        if network["allow_internet_access"] == false && !names.is_empty() {
            // Accepted by Tensorlake, but such names never resolve: DNS is blocked.
            s.violations.push(format!("hostname rules {names:?} cannot resolve without allow_internet_access"));
        }
        if network["allow_internet_access"] == true && network["allow_out"].as_array().is_none_or(Vec::is_empty) {
            s.violations.push("allow_internet_access with nothing listed is open".into());
        }
    }
    if body["timeout_secs"] != 0 || body["auto_resume"] != true || body["wait"] != true {
        s.violations.push(format!("create must set timeout_secs 0, auto_resume and wait: {body}"));
    }
    let id = s.id("sb");
    let timed_out = std::mem::take(&mut s.create_times_out);
    let sandbox = Sandbox {
        id: id.clone(),
        name: name.clone(),
        status: if timed_out { "pending".into() } else { "running".into() },
        pending_reads: if timed_out { 2 } else { 0 },
        resources: json!({"cpus": cpus, "memory_mb": memory, "disk_mb": disk}),
        network: body
            .get("network")
            .cloned()
            .map(|mut n| {
                n["deny_out"] = json!([]);
                n
            })
            .unwrap_or(Value::Null),
        image,
        ..Sandbox::default()
    };
    s.sandboxes.insert(name.clone(), sandbox);
    if timed_out {
        return json_reply(504, json!({"sandbox_id": id, "status": "timeout", "name": name}));
    }
    json_reply(200, json!({"sandbox_id": id, "status": "running", "name": name, "sandbox_url": format!("https://{name}{DOMAIN}")}))
}
fn admit(s: &mut State, request: &reqwest::Request) -> http::Response<Bytes> {
    if request.headers().get("idempotency-key").is_none() {
        return proxy_error(400, "Idempotency-Key header is required");
    }
    let body = body(request);
    let name = body["name"].as_str().unwrap_or_default().to_owned();
    if body["kind"] != "dockerfile" || body["dockerfile_path"] != "Dockerfile" || body["parents"] != json!([]) || body["disk_mb"] != 10240 {
        s.violations.push(format!("unexpected build request {body}"));
        return proxy_error(400, "invalid build");
    }
    if let Some((id, _)) =
        s.builds.iter().find(|(_, b)| b.name == name && !["succeeded", "failed", "cancelled"].contains(&b.status.as_str()))
    {
        return json_reply(
            409,
            json!({"error": format!("Image '{name}' already has an unfinished build '{id}'."), "code": "image_build_in_progress", "image_name": name, "active_build_id": id}),
        );
    }
    let credentials =
        body.get("registry_credentials_json").map(|c| serde_json::from_str::<Value>(c.as_str().expect("a JSON string")).unwrap());
    let id = s.id("build-");
    s.builds.insert(id.clone(), Build { name: name.clone(), status: "pending".into(), credentials, polls_left: 2, ..Build::default() });
    json_reply(
        201,
        json!({"build_id": id, "name": name, "kind": "dockerfile", "status": "pending", "phase": "awaiting_context", "context_upload": {"url": format!("https://{UPLOADS}/context/{id}?X-Amz-Signature=abc")}}),
    )
}
/// The sandbox proxy's `processes/run`: recognises the module's scripts and
/// streams SSE lines, as Tensorlake does, lossily as UTF-8.
fn guest_plane(s: &mut State, name: &str, method: &str, path: &str, request: &reqwest::Request) -> http::Response<Bytes> {
    let Some(sandbox) = s.sandboxes.get(name) else { return proxy_error(404, "sandbox not found") };
    if sandbox.status != "running" {
        return json_reply(409, json!({"error": format!("Sandbox '{name}' is {}", sandbox.status), "code": "SANDBOX_NOT_RUNNING"}));
    }
    if (method, path) != ("POST", "/api/v1/processes/run") {
        s.violations.push(format!("unexpected guest request {method} {path}"));
        return proxy_error(404, "not found");
    }
    let body = body(request);
    let script = body["args"][1].as_str().unwrap_or_default().to_owned();
    if body["command"] != "sh" || body["args"][0] != "-c" {
        s.violations.push(format!("unexpected command {body}"));
    }
    let root = body["user"] == "root";
    let (lines, code): (Vec<String>, i64) = if script.starts_with("echo \"drydock-tcp-token $(cat /run/drydock/tcp.token)\"") {
        match (&sandbox.token_file, root) {
            (Some(token), true) => (vec![format!("drydock-tcp-token {token}")], 0),
            _ => (vec!["cat: /run/drydock/tcp.token: Permission denied".into()], 1),
        }
    } else if script.starts_with("test \"$(id -u)\" = 0") {
        (vec![json!({"uid": 0, "unlisted_canary": false, "raw_dns": false, "listed_direct": true}).to_string()], 0)
    } else if script.contains("--supervise") {
        // Bootstrap reaches here only to report the token; StandIn::bootstrap starts the agent.
        let token = format!("drydock-tcp-token {}", sandbox.token_file.clone().unwrap_or_default());
        match supervise(&script) {
            _ if sandbox.token_file.as_deref().map(Token::parse).is_some_and(|t| t.is_err()) => {
                (vec![token, "drydock-agent: invalid TCP token file".into()], 1)
            }
            _ if s.agent_missing => (vec![token, "env: '/opt/drydock/drydock-agent': No such file or directory".into()], 127),
            Ok(()) => (vec![token], 0),
            Err((output, code)) => (vec![token, output], code),
        }
    } else {
        let output = String::from_utf8_lossy(&s.exec_output).into_owned();
        (output.lines().map(str::to_owned).collect(), s.exec_exit)
    };
    let mut events = format!("data: {}\n\n", json!({"handle": 1, "pid": 42, "started_at": 1_793_000_000_000u64}));
    for line in lines {
        events.push_str(&format!("data: {}\n\n", json!({"line": line, "timestamp": 1_793_000_000_001u64, "stream": "stdout"})));
    }
    events.push_str(&format!("data: {}\n\n", json!({"exit_code": code, "signal": null})));
    http::Response::builder().status(200).header("content-type", "text/event-stream").body(Bytes::from(events)).unwrap()
}

impl StandIn {
    /// The bootstrap script, run as root with the token in its environment:
    /// writes the token file unless it exists, then starts the agent unless
    /// the supervisor already runs one.
    async fn bootstrap(&self, request: &reqwest::Request) {
        let body = body(request);
        let name = request.url().host_str().unwrap().trim_end_matches(DOMAIN).to_owned();
        let script = body["args"][1].as_str().unwrap_or_default().to_owned();
        let port = script.split("--tcp 127.0.0.1:").nth(1).and_then(|rest| rest.split(' ').next()).and_then(|p| p.parse::<u16>().ok());
        let start = {
            let mut s = self.state();
            let mut problems = vec![];
            if body["user"] != "root" {
                problems.push("the agent must start as root".to_owned());
            }
            if !script.contains("--tcp-token-file /run/drydock/tcp.token")
                || !script.contains("--socket /run/drydock/agent.sock")
                || !script.contains("umask 077")
            {
                problems.push(format!("unexpected bootstrap {script}"));
            }
            let token = body["env"]["DRYDOCK_TCP_TOKEN"].as_str().and_then(|t| Token::parse(t).ok());
            if script.contains('\\') {
                // POST /processes echoes args unescaped; the bootstrap stays clear of it everywhere.
                problems.push("a backslash in the bootstrap".into());
            }
            if token.as_ref().is_some_and(|t| script.contains(t.secret())) {
                problems.push("the token is on the agent's argv".into());
            }
            s.violations.extend(problems);
            let starts = supervise(&script).is_ok() && !s.agent_missing;
            let Some(sandbox) = s.sandboxes.get_mut(&name).filter(|sb| sb.status == "running") else { return };
            sandbox.token_file = token_file_after(&script, sandbox.token_file.as_deref(), token.as_ref());
            sandbox.agent_port = port;
            match (&sandbox.guest, sandbox.token_file.as_deref().map(Token::parse)) {
                (None, Some(Ok(token))) if starts => Some(token),
                _ => None,
            }
        };
        if let Some(token) = start {
            let guest = start_guest(token).await;
            if let Some(sandbox) = self.state().sandboxes.get_mut(&name) {
                sandbox.guest = Some(guest);
            }
        }
    }
    /// Replaces a guest's agent and token, as a reboot and another host's
    /// bootstrap would, so a module's cached token goes stale.
    async fn rotate_token(&self, name: &str) {
        let token = Token::generate().unwrap();
        let guest = start_guest(token.clone()).await;
        let mut s = self.state();
        let sandbox = s.sandboxes.get_mut(name).unwrap();
        sandbox.token_file = Some(token.secret().to_owned());
        sandbox.guest = Some(guest);
    }
    /// The tunnel's provider side: the Bearer key on the upgrade, a running
    /// sandbox, then binary frames relayed to the agent's port. Frames over
    /// 64 KiB end the connection; ends never send a close frame (1006).
    async fn serve_tunnels(self, mut listener: drydock_transport::MemoryListener) {
        while let Ok(stream) = listener.accept().await {
            let stand_in = self.clone();
            let task = tokio::spawn(async move { stand_in.tunnel(stream).await });
            self.state().tunnels.push(task);
        }
    }
    async fn tunnel(&self, stream: ByteStream) {
        let target = Arc::new(Mutex::new(None));
        let found = target.clone();
        let stand_in = self.clone();
        #[allow(clippy::result_large_err)]
        let check = move |request: &Request, response: Response| -> std::result::Result<Response, ErrorResponse> {
            let refuse = |status: u16, error: &str| {
                let mut refusal = ErrorResponse::new(Some(json!({"error": error}).to_string()));
                *refusal.status_mut() = http::StatusCode::from_u16(status).unwrap();
                Err(refusal)
            };
            if request.headers().get("authorization").and_then(|v| v.to_str().ok()) != Some(&format!("Bearer {KEY}")) {
                return refuse(401, "Authenticated sandbox-proxy forwarding is required");
            }
            let host = request.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or_default();
            let name = host.trim_end_matches(DOMAIN).to_owned();
            let port = request.uri().query().and_then(|q| q.strip_prefix("port=")).and_then(|p| p.parse::<u16>().ok());
            if request.uri().path() != "/api/v1/tunnels/tcp" || port.is_none() {
                return refuse(400, "missing or invalid port");
            }
            let mut s = stand_in.state();
            let Some(sandbox) = s.sandboxes.get_mut(&name) else { return refuse(404, "sandbox not found") };
            if sandbox.status == "suspended" {
                // auto_resume wakes it: the module must never let this happen.
                sandbox.status = "running".into();
                s.violations.push("a tunnel resumed a suspended sandbox".into());
                return refuse(409, "resumed implicitly");
            }
            match (&sandbox.guest, sandbox.agent_port) {
                (Some(guest), Some(listening)) if Some(listening) == port => {
                    *found.lock().unwrap() = Some(guest.address);
                    Ok(response)
                }
                _ => refuse(502, "connection refused by the target"),
            }
        };
        let config = WebSocketConfig::default().max_frame_size(Some(PROXY_FRAME_LIMIT)).max_message_size(Some(PROXY_FRAME_LIMIT));
        let Ok(socket) = accept_hdr_async_with_config(stream, check, Some(config)).await else { return };
        let Some(address) = *target.lock().unwrap() else { return };
        let Ok(tcp) = tokio::net::TcpStream::connect(address).await else { return };
        let mut dropping = self.state().drop_tunnels.get_or_insert_with(|| tokio::sync::watch::channel(false).0).subscribe();
        tokio::select! {
            _ = relay(socket, tcp, self.clone()) => {}
            _ = dropping.wait_for(|drop| *drop) => {}
        }
    }
}
/// Bytes both ways until either end stops; then both drop, with no close frame.
async fn relay(socket: WebSocketStream<ByteStream>, tcp: tokio::net::TcpStream, stand_in: StandIn) {
    let (mut sink, mut source) = socket.split();
    let (mut read, mut write) = tcp.into_split();
    let up = async {
        while let Some(message) = source.next().await {
            let message = match message {
                Ok(message) => message,
                Err(error) => {
                    if matches!(error, drydock_transport::websocket::tungstenite::Error::Capacity(_)) {
                        // The live proxy killed the connection at a 256 KiB frame.
                        stand_in.state().violations.push(format!("a tunnel frame over 64 KiB: {error}"));
                    }
                    break;
                }
            };
            if let Message::Binary(bytes) = message
                && write.write_all(&bytes).await.is_err()
            {
                break;
            }
        }
    };
    let down = async {
        let mut buffer = vec![0; 16 << 10];
        while let Ok(n) = read.read(&mut buffer).await {
            if n == 0 || sink.send(Message::Binary(Bytes::copy_from_slice(&buffer[..n]))).await.is_err() {
                break;
            }
        }
    };
    tokio::select! { _ = up => {}, _ = down => {} }
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
        let bootstrap = request.url().host_str().is_some_and(|h| h.ends_with(DOMAIN))
            && request.url().path() == "/api/v1/processes/run"
            && body(&request)["args"][1].as_str().is_some_and(|s| s.contains("--supervise"))
            && request.headers().get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {KEY}"));
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
            s.sandboxes.clear();
            std::mem::take(&mut s.violations)
        };
        if !std::thread::panicking() {
            assert!(violations.is_empty(), "Tensorlake contract violations: {violations:?}");
        }
    }
}
async fn world_with(name: &str, settings: Value, stand_in: StandIn) -> World {
    let (dialer, listener) = drydock_transport::memory();
    tokio::spawn(stand_in.clone().serve_tunnels(listener));
    let config =
        ProviderConfiguration { module: "tensorlake".into(), settings: serde_json::from_value(settings).unwrap(), credential: None };
    let module = TensorlakeModule::with_dialer(Arc::new(dialer));
    let provider = module.configure(name, &config, Arc::new(Wire(stand_in.clone()))).await.unwrap();
    World { stand_in, provider, credentials: Credentials::new(Some(Secret::new(KEY))) }
}
/// A world whose images already exist, so provisions skip the build.
async fn world() -> World {
    world_with("tensorlake", json!({"organization_id": "org-1"}), prepared()).await
}
fn prepared() -> StandIn {
    let stand_in = StandIn::default();
    stand_in.state().images_exist = true;
    stand_in
}
/// A world with no images yet, for the tests of prepare.
async fn unprepared() -> World {
    world_with("tensorlake", json!({}), StandIn::default()).await
}
fn size(cpus: f64, memory_gib: u64, disk_gib: u64) -> Size {
    Size { cpus, memory_bytes: memory_gib << 30, disk_bytes: disk_gib << 30 }
}
fn prepare_request(image_pull: Option<RegistryCredential>) -> PrepareRequest {
    PrepareRequest {
        size: size(1.0, 1, 10),
        platform: Some(Platform::new("linux", "amd64")),
        route: Some(ImageRouteKind::RegistryPull),
        image_pull,
        image_digest: BASE.into(),
        tools_digest: TOOLS.into(),
    }
}
impl World {
    async fn prepared(&self) -> Prepared {
        self.provider.prepare(prepare_request(None), &self.credentials).await.unwrap()
    }
    async fn provision(&self, label: &str, size: Size, egress: EgressRequest) -> Result<Provisioned> {
        let prepared = self.prepared().await;
        self.provider
            .provision(ProvisionRequest { label: label.into(), prepared, size, egress, ssh_public_key: None }, &self.credentials)
            .await
    }
    async fn launched(&self, label: &str) -> Environment {
        self.provision(label, size(1.0, 1, 10), EgressRequest::Open).await.unwrap().into_inner()
    }
    /// The agent's hello through the provider's relay.
    async fn agent(&self, id: &str) -> Client {
        let stream = self.provider.relay(id, &self.credentials).await.unwrap();
        Client::connect(Box::new(stream), "test-build").await.unwrap()
    }
}

// Prepare builds the image once with the Image Service's CAS lifecycle:
// admission with an idempotency key, the context (a tar holding only the
// Dockerfile that copies the tools image's /opt/drydock onto the base) to the
// presigned URL without the key, sealed by its digest, then polled to
// success. A second prepare finds the image by name and builds nothing.
#[tokio::test(start_paused = true)]
async fn prepare_builds_once_then_finds_the_image_by_name() {
    let w = unprepared().await;
    let first = w.prepared().await;
    assert_eq!((first.provider.as_str(), first.platform.clone()), ("tensorlake", Platform::new("linux", "amd64")));
    {
        let s = w.stand_in.state();
        assert_eq!(s.builds.len(), 1);
        let build = s.builds.values().next().unwrap();
        assert_eq!(build.status, "succeeded");
        assert_eq!(build.name, first.id);
        assert_eq!(
            build.dockerfile.as_deref().unwrap(),
            format!(
                "FROM --platform=linux/amd64 {TOOLS} AS drydock_tools\nFROM --platform=linux/amd64 {BASE}\nCOPY --from=drydock_tools /opt/drydock/ /opt/drydock/\n"
            )
        );
        assert!(build.credentials.is_none(), "no pull credential, no registry credentials");
    }
    let again = w.prepared().await;
    assert_eq!(again.id, first.id);
    assert_eq!(w.stand_in.state().builds.len(), 1, "found by name, not rebuilt");
    // A new tools pin is a new image: one baked with the old tools layer is not reused.
    let mut retooled = prepare_request(None);
    retooled.tools_digest = format!("ghcr.io/flotilla-org/drydock-tools@sha256:{}", "5".repeat(64));
    let retooled = w.provider.prepare(retooled, &w.credentials).await.unwrap();
    assert_ne!(retooled.id, first.id);
    assert_eq!(w.stand_in.state().builds.len(), 2);
}

// A failed build is a refusal carrying the Image Service's error.
#[tokio::test(start_paused = true)]
async fn a_failed_build_is_refused_with_its_error() {
    let w = unprepared().await;
    w.stand_in.state().build_failure = Some("pull ghcr.io/example/base: manifest unknown".into());
    match w.provider.prepare(prepare_request(None), &w.credentials).await {
        Err(ProtocolError::Refused { reason }) => assert!(reason.contains("manifest unknown"), "{reason}"),
        other => panic!("{other:?}"),
    }
}

// A base image on a private address is refused before any request: no
// Tensorlake builder can reach it.
#[tokio::test]
async fn a_private_base_is_refused_up_front() {
    let w = unprepared().await;
    for base in [
        "10.1.2.3:5000/lab/image",
        "192.168.1.5/image",
        "127.0.0.1:5000/image",
        "100.64.0.9/image",
        "localhost:5000/image",
        "forgejo.lab.internal/image",
        "registry:5000/image",
    ] {
        let mut request = prepare_request(None);
        request.image_digest = format!("{base}@sha256:{}", "3".repeat(64));
        assert!(matches!(w.provider.prepare(request, &w.credentials).await, Err(ProtocolError::Refused { .. })), "{base}");
    }
    assert!(w.stand_in.state().requests.is_empty());
}

// The pull credential reaches the build as a Docker config.json naming only
// the base's registry, and never the tools image's.
#[tokio::test(start_paused = true)]
async fn the_pull_credential_names_only_the_base_registry() {
    use base64::Engine;
    let w = unprepared().await;
    let mut request = prepare_request(Some(RegistryCredential { username: "robot".into(), secret: Secret::new("pull-secret") }));
    request.image_digest = format!("registry.example.com/team/base@sha256:{}", "4".repeat(64));
    w.provider.prepare(request, &w.credentials).await.unwrap();
    let s = w.stand_in.state();
    let credentials = s.builds.values().next().unwrap().credentials.clone().unwrap();
    let auths = credentials["auths"].as_object().unwrap();
    assert_eq!(auths.keys().collect::<Vec<_>>(), ["registry.example.com"]);
    let auth = base64::engine::general_purpose::STANDARD.decode(auths["registry.example.com"]["auth"].as_str().unwrap()).unwrap();
    assert_eq!(auth, b"robot:pull-secret");
}

// A bootstrap whose agent doesn't start fails provision with the guest's
// output as its cause, so drydockd's log says why, and never the token.
#[tokio::test]
async fn a_failed_bootstrap_reports_the_guests_output() {
    let w = world().await;
    w.stand_in.state().agent_missing = true;
    let error = w.provision("vessel-1", size(1.0, 1, 10), EgressRequest::Open).await.unwrap_err();
    let token = w.stand_in.state().sandboxes.values().next().unwrap().token_file.clone().unwrap();
    let ProtocolError::Internal { provider_error, .. } = &error else { panic!("{error:?}") };
    assert!(provider_error.contains("drydock-agent': No such file or directory"), "{provider_error}");
    assert!(!error.to_string().contains(&token), "{error}");
}

// Provision creates a named sandbox with the plan's longest idle timeout,
// auto-resume and a blocking wait, then starts the agent as root with a
// fresh token in a root-only file, never on argv. The environment carries
// its label and size, and the agent answers hello through the relay.
#[tokio::test]
async fn provision_creates_bootstraps_and_reaches_the_agent() {
    let w = world().await;
    let provisioned = w.provision("vessel-1", size(2.0, 4, 20), EgressRequest::Open).await.unwrap();
    let Provisioned::Created(environment) = provisioned else { panic!("{provisioned:?}") };
    assert_eq!(environment.label.as_deref(), Some("vessel-1"));
    assert_eq!(environment.state, Observation::Running);
    assert_eq!(environment.granted_size, Some(size(2.0, 4, 20)));
    {
        let s = w.stand_in.state();
        let create = &s.creates[0];
        assert_eq!(create["resources"], json!({"cpus": 2.0, "memory_mb": 4096, "disk_mb": 20480}));
        assert!(create.get("network").is_none(), "open egress sends no network");
        let sandbox = &s.sandboxes[&environment.id];
        let guest = sandbox.guest.as_ref().expect("the agent runs");
        assert_eq!(sandbox.token_file.as_deref(), Some(guest.token.secret()));
        assert_eq!(sandbox.agent_port, Some(7811));
    }
    let client = w.agent(&environment.id).await;
    assert_eq!(client.hello().fingerprint, "test-build");
}

// A create for a label already provisioned meets Tensorlake's 409 and adopts
// the sandbox by name, bootstrapping it again, so provision is idempotent.
#[tokio::test]
async fn provision_readopts_by_name() {
    let w = world().await;
    let first = w.launched("vessel-1").await;
    let again = w.provision("vessel-1", size(1.0, 1, 10), EgressRequest::Open).await.unwrap();
    let Provisioned::Existing(again) = again else { panic!("{again:?}") };
    assert_eq!(again.id, first.id);
    assert_eq!(w.stand_in.state().sandboxes.len(), 1);
    w.agent(&again.id).await;
}

// Re-adoption refuses a sandbox whose size or egress policy differs from the
// request, rather than handing back something else.
#[tokio::test]
async fn readoption_refuses_another_size_or_policy() {
    let w = world().await;
    w.launched("vessel-1").await;
    let refused = |r: Result<Provisioned>| matches!(r, Err(ProtocolError::Refused { .. }));
    assert!(refused(w.provision("vessel-1", size(2.0, 2, 10), EgressRequest::Open).await));
    assert!(refused(w.provision("vessel-1", size(1.0, 1, 10), EgressRequest::DenyAll { direct: vec![] }).await));
}

// Sizes outside the configured limits are refused before any create, and
// Tensorlake's own 400 limit texts come back with its message: a per-sandbox
// limit as Refused, the project's quota as QuotaExhausted.
#[tokio::test]
async fn sizes_and_plan_limits_map_to_refusals_and_quota() {
    let w = world_with("tensorlake", json!({"max_cpus": 8, "max_memory": "32GiB"}), prepared()).await;
    assert!(matches!(w.provision("a", size(1.0, 9, 10), EgressRequest::Open).await, Err(ProtocolError::Refused { .. })), "9 GiB on 1 vCPU");
    assert!(w.stand_in.state().creates.is_empty());
    match w.provision("a", size(6.0, 8, 10), EgressRequest::Open).await {
        Err(ProtocolError::Refused { reason }) => assert!(reason.contains("Per-sandbox vCPU limit exceeded"), "{reason}"),
        other => panic!("{other:?}"),
    }
    w.stand_in.state().running_limit = Some(1);
    w.launched("b").await;
    match w.provision("c", size(1.0, 1, 10), EgressRequest::Open).await {
        Err(ProtocolError::QuotaExhausted { reason }) => assert!(reason.contains("quota"), "{reason}"),
        other => panic!("{other:?}"),
    }
}

// A create whose server-side wait ran out (504, status timeout) is awaited
// until the sandbox runs, then bootstrapped as usual.
#[tokio::test]
async fn a_timed_out_create_is_awaited() {
    let w = world().await;
    w.stand_in.state().create_times_out = true;
    let environment = w.launched("slow").await;
    assert_eq!(environment.state, Observation::Running);
    w.agent(&environment.id).await;
}

// When the guest's token changed under the module (another bootstrap after
// a restart), the agent's 401 makes relay read the token again and connect.
#[tokio::test]
async fn relay_recovers_from_a_stale_token() {
    let w = world().await;
    let environment = w.launched("vessel-1").await;
    w.agent(&environment.id).await;
    w.stand_in.rotate_token(&environment.id).await;
    w.agent(&environment.id).await;
}

// The tunnel carries a 1 MiB file each way, and a single 300 KiB write, in
// frames the proxy accepts (none over 64 KiB), and
// a tunnel the proxy drops without a close frame (1006) reads as EOF.
#[tokio::test]
async fn relay_carries_large_transfers_and_reads_a_dropped_tunnel_as_eof() {
    let w = world().await;
    let environment = w.launched("vessel-1").await;
    let client = w.agent(&environment.id).await;
    let content: Vec<u8> = (0..1u32 << 20).map(|i| (i % 251) as u8).collect();
    let path = Path::new("/tmp/tensorlake-transfer");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(path.file_name().unwrap());
    client.write_bytes(&path, content.clone(), &FileOptions::default()).await.unwrap();
    assert_eq!(client.read_bytes(&path, 2 << 20).await.unwrap(), content);
    // One large write, as any writer may make, still crosses in frames the proxy takes.
    let mut raw = w.provider.relay(&environment.id, &w.credentials).await.unwrap();
    // The agent refuses these bytes and closes, so only the first frames matter.
    let _ = raw.write_all(&vec![0u8; 300 << 10]).await;
    let _ = raw.flush().await;
    let mut stream = w.provider.relay(&environment.id, &w.credentials).await.unwrap();
    w.stand_in.state().drop_tunnels.as_ref().unwrap().send_replace(true);
    let mut rest = Vec::new();
    let end = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut rest)).await.unwrap();
    assert!(end.is_ok(), "{end:?}");
}

// Egress requests become Tensorlake's network: deny-all is no internet
// access, addresses and CIDRs stay without it, and any host name needs
// internet access (scoped DNS) with every entry listed, so a name never sits
// under a policy that cannot resolve it. Ports and IPv6 are refused. The
// sandbox's policy reads back equal, so re-adoption matches it.
#[tokio::test]
async fn egress_requests_map_to_network_policies() {
    let w = world().await;
    let host = |h: &str| Destination::Host { host: serde_json::from_value(json!(h)).unwrap() };
    let cidr = |c: &str| Destination::Cidr { cidr: serde_json::from_value(json!(c)).unwrap() };
    let cases = [
        (vec![], json!({"allow_internet_access": false})),
        (vec![cidr("10.0.0.0/8"), host("192.0.2.7")], json!({"allow_internet_access": false, "allow_out": ["10.0.0.0/8", "192.0.2.7"]})),
        (
            vec![host("Example.COM."), cidr("10.0.0.0/8")],
            json!({"allow_internet_access": true, "allow_out": ["10.0.0.0/8", "example.com"]}),
        ),
    ];
    for (index, (direct, network)) in cases.into_iter().enumerate() {
        let label = format!("egress-{index}");
        let environment =
            w.provision(&label, size(1.0, 1, 10), EgressRequest::DenyAll { direct: direct.clone() }).await.unwrap().into_inner();
        assert_eq!(w.stand_in.state().creates.last().unwrap()["network"], network, "{label}");
        let again = w.provision(&label, size(1.0, 1, 10), EgressRequest::DenyAll { direct }).await.unwrap();
        assert!(matches!(again, Provisioned::Existing(_)), "{label} re-adopts");
        assert_eq!(again.into_inner().egress_policy, environment.egress_policy);
    }
    let refused = [
        Destination::HostPort {
            host: serde_json::from_value(json!("example.com")).unwrap(),
            port: serde_json::from_value(json!(443)).unwrap(),
        },
        cidr("2001:db8::/32"),
        host("2001:db8::1"),
    ];
    for destination in refused {
        let request = EgressRequest::DenyAll { direct: vec![destination.clone()] };
        assert!(matches!(w.provision("refused", size(1.0, 1, 10), request).await, Err(ProtocolError::Refused { .. })), "{destination:?}");
    }
}

// Suspend waits for `suspended` and returns the deterministic marker; relay
// to a suspended sandbox is refused rather than waking it; resume runs it
// again, bootstraps, and the agent, its memory kept, answers. A token file
// holding no token is replaced at resume; a suspend while the sandbox is
// pending is Unavailable.
#[tokio::test]
async fn suspend_and_resume_keep_the_agent_without_implicit_wakes() {
    let w = world().await;
    let environment = w.launched("vessel-1").await;
    let ports = w.provider.operations();
    let port = ports.suspend_resume.unwrap();
    let token = port.suspend(&environment.id, &w.credentials).await.unwrap();
    assert_eq!(
        w.provider.inspect(&environment.id, &w.credentials).await.unwrap().state,
        Observation::Stopped { cause: StopCause::SuspendedByRequest }
    );
    assert!(matches!(w.provider.relay(&environment.id, &w.credentials).await, Err(ProtocolError::Refused { .. })));
    let other = ResumeToken { token: Secret::new("tensorlake-resume-other") };
    assert!(port.resume(&environment.id, other, &w.credentials).await.is_err());
    // A token file that holds no token, with its agent gone, is replaced
    // at resume: kept, it would stop every agent start.
    {
        let mut s = w.stand_in.state();
        let sandbox = s.sandboxes.get_mut(&environment.id).unwrap();
        sandbox.token_file = Some("not a token\n".into());
        sandbox.guest = None;
    }
    port.resume(&environment.id, token, &w.credentials).await.unwrap();
    assert_eq!(w.provider.inspect(&environment.id, &w.credentials).await.unwrap().state, Observation::Running);
    w.agent(&environment.id).await;
    // A sandbox still being created or resumed is only transitioning: retry later.
    {
        let mut s = w.stand_in.state();
        let sandbox = s.sandboxes.get_mut(&environment.id).unwrap();
        sandbox.status = "pending".into();
        sandbox.pending_reads = u32::MAX;
    }
    assert!(matches!(port.suspend(&environment.id, &w.credentials).await, Err(ProtocolError::Unavailable { .. })));
}

// Destroy deletes the sandbox and every snapshot it left; while a snapshot
// cannot be deleted, destroy is Unavailable, and a retry finishes the job.
// Afterwards inspect reads the archived record as Gone and list omits it.
#[tokio::test]
async fn destroy_removes_left_snapshots_and_retries() {
    let w = world().await;
    let environment = w.launched("vessel-1").await;
    let ports = w.provider.operations();
    ports.suspend_resume.unwrap().suspend(&environment.id, &w.credentials).await.unwrap();
    assert_eq!(w.stand_in.state().snapshots.len(), 1);
    w.stand_in.state().snapshot_delete_failures = 1;
    assert!(matches!(w.provider.destroy(&environment.id, &w.credentials).await, Err(ProtocolError::Unavailable { .. })));
    assert_eq!(w.stand_in.state().snapshots.len(), 1, "the suspend snapshot outlives its sandbox");
    w.provider.destroy(&environment.id, &w.credentials).await.unwrap();
    assert!(w.stand_in.state().snapshots.is_empty());
    let gone = w.provider.inspect(&environment.id, &w.credentials).await.unwrap();
    assert_eq!(gone.state, Observation::Gone { cause: GoneCause::DestroyedAtProvider });
    assert!(w.provider.list(&w.credentials).await.unwrap().is_empty());
    w.provider.destroy(&environment.id, &w.credentials).await.unwrap();
}

// List pages through every sandbox and keeps only this instance's, each with
// its label read back from its name.
#[tokio::test]
async fn list_keeps_this_instances_sandboxes() {
    let stand_in = prepared();
    let ours = world_with("tensorlake", json!({}), stand_in.clone()).await;
    let theirs = world_with("tensorlake-other", json!({}), stand_in.clone()).await;
    for label in ["a", "b", "c"] {
        ours.launched(label).await;
    }
    theirs.launched("a").await;
    let mut labels: Vec<_> = ours.provider.list(&ours.credentials).await.unwrap().into_iter().map(|e| e.label.unwrap()).collect();
    labels.sort();
    assert_eq!(labels, ["a", "b", "c"]);
    assert_eq!(theirs.provider.list(&theirs.credentials).await.unwrap().len(), 1);
}

// Usage reads the organization's export over the period, with millisecond
// RFC 3339 bounds, and sums its sandboxes' quantities into protocol units,
// with the attributed charge as an exact USD amount. A truncated export
// (no end record, or a count that disagrees) is Unavailable. Without an
// organization the usage port is absent.
#[tokio::test]
async fn usage_sums_the_export_and_refuses_a_truncated_one() {
    let w = world().await;
    let sandbox = |cpu: &str, memory: &str| {
        json!({"type":"sandbox","sandboxId":"sb1","project":null,"attributedAmountMinor":"12","resources":{
            "cpu":{"quantity":cpu,"unit":"vCPU-hour","attributedAmountMinor":"10"},
            "memory":{"quantity":memory,"unit":"GiB-hour","attributedAmountMinor":"2"},
            "networkEgress":{"quantity":"0.5","unit":"GiB","attributedAmountMinor":null}}})
        .to_string()
    };
    let window = json!({"type":"window","windowStart":"2026-11-01T00:00:00.000Z","windowEnd":"2026-11-02T00:00:00.000Z","attributedUsageCharge":{"currency":"usd","amountMinor":"1234","basis":"invoice"}}).to_string();
    let end = |n: u64| json!({"type":"end","count":n}).to_string();
    let period: Period = serde_json::from_value(json!({"start":"2026-11-01T00:00:00Z","end":"2026-11-02T00:00:00Z"})).unwrap();
    w.stand_in.state().usage = Some([window.clone(), sandbox("1.5", "3"), sandbox("0.5", "1"), end(2)].join("\n"));
    let ports = w.provider.operations();
    let usage = ports.usage.unwrap().usage(period.clone(), &w.credentials).await.unwrap();
    let measurements = usage.measurements.unwrap();
    assert_eq!(measurements.scope, UsageScope::Organization { id: "org-1".into() });
    assert_eq!(measurements.resources[&ResourceKind::Cpu], Quantity { amount: 2.0 * 3600.0, unit: "{vCPU}.s".into() });
    assert_eq!(measurements.resources[&ResourceKind::Memory], Quantity { amount: 4.0 * 3600.0 * (1u64 << 30) as f64, unit: "By.s".into() });
    assert_eq!(measurements.resources[&ResourceKind::Environments].amount, 2.0);
    assert_eq!(measurements.cost, Some(Cost { amount: "12.34".into(), currency: "USD".into() }));
    assert_eq!(w.stand_in.state().usage_query, Some(("2026-11-01T00:00:00.000Z".into(), "2026-11-02T00:00:00.000Z".into())));
    for truncated in [[window.clone(), sandbox("1", "1")].join("\n"), [window, sandbox("1", "1"), end(2)].join("\n")] {
        w.stand_in.state().usage = Some(truncated);
        assert!(matches!(ports.usage.unwrap().usage(period.clone(), &w.credentials).await, Err(ProtocolError::Unavailable { .. })));
    }
    let without = world_with("tensorlake", json!({}), prepared()).await;
    assert!(without.provider.operations().usage.is_none() && !without.provider.capabilities().usage);
}

// Exec is text only: the guest's output arrives as UTF-8 lines with other
// bytes replaced, and a failing command is CommandFailed with that output.
#[tokio::test]
async fn exec_returns_lossy_text_and_reports_failure() {
    let w = world().await;
    let environment = w.launched("vessel-1").await;
    w.stand_in.state().exec_output = b"caf\xc3\xa9\nraw \xff byte\n".to_vec();
    let ports = w.provider.operations();
    let exec = ports.exec.unwrap();
    // Arguments may hold any text, backslashes included.
    let mut stream =
        exec.exec(&environment.id, ExecRequest { command: vec!["printf".into(), "a\\nb".into()] }, &w.credentials).await.unwrap();
    let mut output = String::new();
    stream.read_to_string(&mut output).await.unwrap();
    assert_eq!(output, "café\nraw \u{fffd} byte");
    w.stand_in.state().exec_exit = 3;
    match exec.exec(&environment.id, ExecRequest { command: vec!["false".into()] }, &w.credentials).await {
        Err(ProtocolError::CommandFailed { exit_code: 3, .. }) => {}
        other => panic!("{:?}", other.map(drop)),
    }
}

// Vendor statuses map to protocol errors: a rejected key on either plane is
// CredentialRejected, 429 is RateLimited with its Retry-After, and 5xx is
// Unavailable. A missing key is rejected before any request, and a 403 on
// the image lookup stops prepare before any build.
#[tokio::test]
async fn vendor_errors_map_to_protocol_errors() {
    let w = world().await;
    let environment = w.launched("vessel-1").await;
    let wrong = Credentials::new(Some(Secret::new("tl_apiKey_wrong")));
    assert!(matches!(w.provider.list(&wrong).await, Err(ProtocolError::CredentialRejected { .. })));
    let exec = w.provider.operations().exec.unwrap();
    assert!(matches!(
        exec.exec(&environment.id, ExecRequest { command: vec!["true".into()] }, &wrong).await,
        Err(ProtocolError::CredentialRejected { .. })
    ));
    assert!(matches!(w.provider.list(&Credentials::default()).await, Err(ProtocolError::CredentialRejected { .. })));
    for (status, check) in [
        (429u16, (|e: &ProtocolError| matches!(e, ProtocolError::RateLimited { retry_after: Some(7), .. })) as fn(&ProtocolError) -> bool),
        (503, |e| matches!(e, ProtocolError::Unavailable { retry_after: Some(7), .. })),
        (500, |e| matches!(e, ProtocolError::Unavailable { .. })),
    ] {
        w.stand_in.state().outage = Some((status, "busy".into(), Some(7)));
        let error = w.provider.list(&w.credentials).await.unwrap_err();
        assert!(check(&error), "{status}: {error:?}");
    }
    // A permission error looking up the image is not "no image": prepare stops, building nothing.
    let w = unprepared().await;
    w.stand_in.state().outage = Some((403, "forbidden".into(), None));
    assert!(matches!(w.provider.prepare(prepare_request(None), &w.credentials).await, Err(ProtocolError::Refused { .. })));
    assert!(!w.stand_in.state().requests.iter().any(|r| r.contains("/builds")), "no build after a 403");
    w.stand_in.state().outage = None;
}

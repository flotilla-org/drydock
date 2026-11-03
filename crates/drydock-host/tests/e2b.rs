//! The E2B module against an in-process stand-in at the vendor's HTTP and
//! proxy boundaries. The stand-in holds templates, builds, the build file
//! cache, sandboxes and lifecycle events in memory and enforces E2B's
//! documented requests (spec/openapi.yml and envd's process service in
//! e2b-dev/infra) and what the live probe of 2026-11-01 found: the
//! `X-API-Key` header; the template and build bodies and their required
//! fields; the files/{hash} present-or-upload flow to a signed URL that must
//! never see the key; template name rules; Hobby's one-hour timeout, refused
//! at create and silently clamped on connect; `network` replaced whole;
//! envd's `X-Access-Token`, Basic user and Connect envelopes; and a proxy that
//! passes only WebSocket upgrades, refuses a missing or wrong
//! `e2b-traffic-access-token`, and reaches only listeners on the guest's
//! interface. A real drydock agent answers behind each sandbox's proxy.
use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use drydock_agent::{Agent, Client, tcp::TokenListener};
use drydock_host::{
    e2b::{E2bModule, Resolver},
    module::*,
};
use drydock_protocol::*;
use drydock_transport::{ByteStream, Listener, tcp::Token};
use rigging_http_client::ChannelLabel;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const KEY: &str = "e2b_0123456789abcdef";
const TEAM: &str = "team-1";
const API: &str = "api.e2b.app";
const DOMAIN: &str = "e2b.app";
const STORAGE: &str = "storage.googleapis.com";
const BASE_REGISTRY: &str = "registry.example.com";
const TOOLS_REGISTRY: &str = "ghcr.io";
/// Hobby's cap on a sandbox's continuous running.
const HOBBY_SECONDS: u64 = 3600;
const ENVD: &str = "49983";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const PULL: (&str, &str) = ("robot", "pull-secret");

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// The base image (one manifest, with ENV in its config) and the tools image
/// (an index whose amd64 image has one layer holding opt/drydock/), stored
/// as registries serve them.
struct Images {
    base: String,
    tools: String,
    layer: Bytes,
    layer_hash: String,
    blobs: BTreeMap<(String, String), (String, Bytes)>,
}
fn images() -> Images {
    let mut blobs = BTreeMap::new();
    let mut put = |host: &str, content_type: &str, bytes: Vec<u8>| {
        let digest = sha256(&bytes);
        blobs.insert((host.to_owned(), digest.clone()), (content_type.to_owned(), Bytes::from(bytes)));
        digest
    };
    let config = json!({"architecture": "amd64", "os": "linux", "config": {"Env": ["PATH=/usr/local/cargo/bin:/usr/bin:/bin", "CARGO_HOME=/usr/local/cargo"], "WorkingDir": "/src", "User": "rust"}, "rootfs": {"type": "layers", "diff_ids": [format!("sha256:{}", "a".repeat(64))]}});
    let config = serde_json::to_vec(&config).unwrap();
    let config_size = config.len();
    let config_digest = put(BASE_REGISTRY, "application/octet-stream", config);
    let manifest = json!({"schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_digest, "size": config_size},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": format!("sha256:{}", "b".repeat(64)), "size": 1}]});
    let base_digest = put(BASE_REGISTRY, OCI_MANIFEST, serde_json::to_vec(&manifest).unwrap());
    let layer: Vec<u8> = b"\x1f\x8b\x08\0 a gzip tar of opt/drydock/drydock-agent".to_vec();
    let layer_size = layer.len();
    let layer_digest = put(TOOLS_REGISTRY, "application/octet-stream", layer.clone());
    let tools_config = br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:cc"]}}"#.to_vec();
    let tools_config_size = tools_config.len();
    let tools_config_digest = put(TOOLS_REGISTRY, "application/octet-stream", tools_config);
    let tools_manifest = json!({"schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": tools_config_digest, "size": tools_config_size},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layer_digest, "size": layer_size}]});
    let tools_manifest = serde_json::to_vec(&tools_manifest).unwrap();
    let tools_manifest_size = tools_manifest.len();
    let tools_manifest_digest = put(TOOLS_REGISTRY, OCI_MANIFEST, tools_manifest);
    let index = json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": [
        {"mediaType": OCI_MANIFEST, "digest": tools_manifest_digest, "size": tools_manifest_size, "platform": {"os": "linux", "architecture": "amd64"}}]});
    let index_digest = put(TOOLS_REGISTRY, OCI_INDEX, serde_json::to_vec(&index).unwrap());
    Images {
        base: format!("{BASE_REGISTRY}/team/rust@{base_digest}"),
        tools: format!("{TOOLS_REGISTRY}/flotilla-org/drydock-tools@{index_digest}"),
        layer_hash: layer_digest.trim_start_matches("sha256:").to_owned(),
        layer: Bytes::from(layer),
        blobs,
    }
}

/// A guest's drydock agent: really listening on loopback, standing in for
/// the guest's interface behind E2B's proxy.
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

struct Template {
    id: String,
    name: String,
    cpus: u64,
    memory_mb: u64,
    builds: Vec<Build>,
}
struct Build {
    id: String,
    status: String,
    start: Option<Value>,
    polls_left: u32,
}
struct Sandbox {
    id: String,
    template: String,
    cpus: u64,
    memory_mb: u64,
    metadata: Value,
    network: Value,
    state: String,
    started_at: chrono::DateTime<chrono::Utc>,
    end_at: chrono::DateTime<chrono::Utc>,
    envd_token: String,
    traffic_token: Option<String>,
    /// /run/drydock/tcp.token in the guest.
    token_file: Option<String>,
    /// The `--tcp` address the agent was started with.
    agent_bind: Option<String>,
    guest: Option<Guest>,
}
impl Sandbox {
    fn listed(&self) -> Value {
        json!({"templateID": self.template, "sandboxID": self.id, "clientID": "6532622b", "startedAt": self.started_at.to_rfc3339(),
            "endAt": self.end_at.to_rfc3339(), "cpuCount": self.cpus, "memoryMB": self.memory_mb, "diskSizeMB": 10240,
            "metadata": self.metadata, "state": self.state, "envdVersion": "0.4.2"})
    }
    fn detail(&self) -> Value {
        let mut detail = self.listed();
        detail["envdAccessToken"] = json!(self.envd_token);
        detail["network"] = self.network.clone();
        detail["domain"] = json!(DOMAIN);
        detail["lifecycle"] = json!({"autoResume": false, "onTimeout": "pause"});
        detail
    }
    fn created(&self) -> Value {
        json!({"templateID": self.template, "sandboxID": self.id, "clientID": "6532622b", "envdVersion": "0.4.2",
            "envdAccessToken": self.envd_token, "trafficAccessToken": self.traffic_token, "domain": DOMAIN})
    }
    fn event(&self, kind: &str) -> Value {
        let now = chrono::Utc::now();
        json!({"id": format!("{kind}-{}-{}", self.id, now.timestamp_nanos_opt().unwrap()), "version": "v2", "type": format!("sandbox.lifecycle.{kind}"),
            "timestamp": now.to_rfc3339(), "sandboxId": self.id, "sandboxExecutionId": "exec-1", "sandboxTemplateId": self.template,
            "sandboxBuildId": "build-1", "sandboxTeamId": TEAM,
            "eventData": {"sandbox_metadata": self.metadata, "execution": {"started_at": self.started_at.to_rfc3339(), "vcpu_count": self.cpus, "memory_mb": self.memory_mb, "execution_time": (now - self.started_at).num_milliseconds()}}})
    }
}

#[derive(Default)]
struct State {
    registries: BTreeMap<(String, String), (String, Bytes)>,
    /// The base registry wants this Basic credential.
    base_auth: Option<(String, String)>,
    /// Authorization headers each registry host received.
    registry_auth: Vec<(String, String)>,
    templates: Vec<Template>,
    /// E2B's team-wide build file cache, by hash.
    files: BTreeMap<String, Bytes>,
    uploads: usize,
    sandboxes: BTreeMap<String, Sandbox>,
    events: Vec<Value>,
    metrics: Vec<Value>,
    creates: Vec<Value>,
    connects: usize,
    violations: Vec<String>,
    requests: Vec<String>,
    /// Builds end failed with this message and log line.
    build_failure: Option<(String, String)>,
    /// Polls a build stays building.
    build_polls: u32,
    /// The bootstrap's exec finds no agent in the template.
    agent_missing: bool,
    exec_output: Vec<u8>,
    exec_exit: i64,
    /// Every control-plane request answers this, as an outage would.
    outage: Option<(u16, String, Option<u64>)>,
    /// The list ignores its metadata filter, so only the module's own
    /// check of both tags keeps others' sandboxes out.
    ignore_metadata_filter: bool,
    tunnels: Vec<tokio::task::JoinHandle<()>>,
    next: u64,
}
impl State {
    fn id(&mut self, prefix: &str) -> String {
        self.next += 1;
        format!("{prefix}{:0>8}", self.next)
    }
    fn template(&mut self, key: &str) -> Option<&mut Template> {
        self.templates.iter_mut().find(|t| t.id == key || t.name == key)
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
/// E2B's Error schema: `{code, message}`.
fn error(status: u16, message: &str) -> http::Response<Bytes> {
    json_reply(status, json!({"code": status, "message": message}))
}
fn query(request: &reqwest::Request) -> Vec<(String, String)> {
    request.url().query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect()
}
fn body(request: &reqwest::Request) -> Value {
    request.body().and_then(|b| b.as_bytes()).filter(|b| !b.is_empty()).map(|b| serde_json::from_slice(b).unwrap()).unwrap_or(Value::Null)
}
fn header<'a>(request: &'a reqwest::Request, name: &str) -> Option<&'a str> {
    request.headers().get(name).and_then(|v| v.to_str().ok())
}
/// E2B template names: lowercase letters, digits, hyphens and underscores,
/// starting with a letter or digit, at most 128.
fn template_name_allowed(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        && name.as_bytes()[0].is_ascii_alphanumeric()
}
fn unexpected_keys(body: &Value, allowed: &[&str]) -> Vec<String> {
    body.as_object().map(|o| o.keys().filter(|k| !allowed.contains(&k.as_str())).cloned().collect()).unwrap_or_default()
}
/// A network entry E2B takes: an IPv4 CIDR or address, or a domain name.
fn network_entry_allowed(entry: &str, domains: bool) -> bool {
    let (ip, bits) = entry.split_once('/').unwrap_or((entry, "32"));
    if ip.parse::<std::net::Ipv4Addr>().is_ok() {
        return bits.parse::<u32>().is_ok_and(|b| b <= 32);
    }
    domains && !entry.contains(['/', ':']) && entry.contains('.')
}
/// One Connect envelope.
fn envelope(flags: u8, message: &Value) -> Vec<u8> {
    let bytes = message.to_string().into_bytes();
    let mut framed = vec![flags];
    framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(&bytes);
    framed
}
/// The single message of a unary-shaped Connect request body.
fn start_message(request: &reqwest::Request) -> Option<Value> {
    let body = request.body()?.as_bytes()?;
    let [0, a, b, c, d, rest @ ..] = body else { return None };
    let length = u32::from_be_bytes([*a, *b, *c, *d]) as usize;
    (rest.len() == length).then(|| serde_json::from_slice(rest).ok()).flatten()
}
/// envd's process stream: start, output as base64 data events, an end whose
/// zero exit code protobuf JSON leaves out, and the end-stream envelope.
fn process_stream(output: &[u8], code: i64) -> http::Response<Bytes> {
    let mut body = envelope(0, &json!({"event": {"start": {"pid": 412}}}));
    for chunk in output.chunks(7) {
        body.extend(envelope(0, &json!({"event": {"data": {"stdout": base64::engine::general_purpose::STANDARD.encode(chunk)}}})));
    }
    let mut end = json!({"exited": true, "status": format!("exit status {code}")});
    if code != 0 {
        end["exitCode"] = json!(code);
    }
    body.extend(envelope(0, &json!({"event": {"end": end}})));
    body.extend(envelope(2, &json!({})));
    http::Response::builder().status(200).header("content-type", "application/connect+json").body(Bytes::from(body)).unwrap()
}

impl StandIn {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn with_images() -> (Self, Images) {
        let images = images();
        let stand_in = Self::default();
        stand_in.state().registries = images.blobs.clone();
        stand_in.state().build_polls = 0;
        (stand_in, images)
    }
    fn respond(&self, request: &reqwest::Request) -> http::Response<Bytes> {
        let mut s = self.state();
        let host = request.url().host_str().unwrap_or_default().to_owned();
        let method = request.method().as_str().to_owned();
        let path = request.url().path().to_owned();
        s.requests.push(format!("{method} {host}{path}"));
        if [BASE_REGISTRY, TOOLS_REGISTRY].contains(&host.as_str()) {
            return registry(&mut s, &host, request);
        }
        if host == STORAGE {
            return upload(&mut s, request);
        }
        if let Some(id) = host.strip_prefix(&format!("{ENVD}-")).and_then(|h| h.strip_suffix(&format!(".{DOMAIN}"))) {
            return envd(&mut s, id, request);
        }
        if host != API {
            s.violations.push(format!("request to an unknown host {host}"));
            return reply(400, "unknown host");
        }
        if header(request, "x-api-key") != Some(KEY) {
            return error(401, "Invalid API key, it must start with 'e2b_' prefix");
        }
        if header(request, "authorization").is_some() {
            s.violations.push("an Authorization header on the control plane".into());
        }
        if let Some((status, text, retry_after)) = s.outage.clone() {
            let mut response = error(status, &text);
            if let Some(seconds) = retry_after {
                response.headers_mut().insert("retry-after", seconds.into());
            }
            return response;
        }
        let segments: Vec<String> = path.trim_start_matches('/').split('/').map(str::to_owned).collect();
        let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
        match (method.as_str(), segments.as_slice()) {
            ("POST", ["v3", "templates"]) => create_template(&mut s, body(request)),
            ("GET", ["templates", "aliases", alias]) => match s.template(alias) {
                Some(t) => json_reply(200, json!({"templateID": t.id, "public": false})),
                None => error(404, &format!("template '{alias}' not found")),
            },
            ("GET", ["templates", id, "files", hash]) => {
                if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                    return error(400, "invalid files hash");
                }
                if s.template(id).is_none() {
                    return error(404, "template not found");
                }
                if s.files.contains_key(*hash) {
                    return json_reply(201, json!({"present": true}));
                }
                let url = format!(
                    "https://{STORAGE}/e2b-build-files/{id}/{hash}.tar.gz?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=sig-{hash}"
                );
                json_reply(201, json!({"present": false, "url": url, "headers": {"x-goog-content-sha256": "UNSIGNED-PAYLOAD"}}))
            }
            ("POST", ["v2", "templates", id, "builds", build]) => start_build(&mut s, id, build, body(request)),
            ("GET", ["templates", id, "builds", build, "status"]) => build_status(&mut s, id, build),
            ("GET", ["templates", id]) => match s.template(id) {
                Some(t) => {
                    let builds: Vec<Value> = t.builds.iter().rev().map(|b| json!({"buildID": b.id, "status": b.status, "createdAt": "2026-11-02T00:00:00Z", "updatedAt": "2026-11-02T00:00:00Z", "cpuCount": t.cpus, "memoryMB": t.memory_mb, "diskSizeMB": 10240})).collect();
                    let status = builds.first().map_or(json!("waiting"), |b| b["status"].clone());
                    json_reply(
                        200,
                        json!({"templateID": t.id, "buildID": builds.first().map(|b| b["buildID"].clone()), "cpuCount": t.cpus, "memoryMB": t.memory_mb,
                        "diskSizeMB": 10240, "public": false, "aliases": [t.name], "names": [t.name], "createdAt": "2026-11-02T00:00:00Z", "updatedAt": "2026-11-02T00:00:00Z",
                        "createdBy": null, "lastSpawnedAt": null, "spawnCount": 0, "buildCount": builds.len(), "envdVersion": "0.4.2", "buildStatus": status, "builds": builds}),
                    )
                }
                None => error(404, "template not found"),
            },
            ("POST", ["v2", "sandboxes"]) => create_sandbox(&mut s, body(request)),
            ("GET", ["v2", "sandboxes"]) => list_sandboxes(&mut s, request),
            ("GET", ["sandboxes", id]) => match s.sandboxes.get(*id) {
                Some(sandbox) => json_reply(200, sandbox.detail()),
                None => error(404, &format!("sandbox \"{id}\" doesn't exist or you don't have access to it")),
            },
            ("DELETE", ["sandboxes", id]) => match s.sandboxes.remove(*id) {
                Some(sandbox) => {
                    if sandbox.state == "running" {
                        s.events.push(sandbox.event("killed"));
                    }
                    reply(204, "")
                }
                None => error(404, &format!("sandbox \"{id}\" doesn't exist or you don't have access to it")),
            },
            ("POST", ["sandboxes", id, "pause"]) => {
                let Some(sandbox) = s.sandboxes.get_mut(*id) else { return error(404, "sandbox not found") };
                if sandbox.state == "paused" {
                    return error(409, &format!("sandbox {id} is already paused"));
                }
                sandbox.state = "paused".into();
                let event = sandbox.event("paused");
                s.events.push(event);
                reply(204, "")
            }
            ("POST", ["v2", "sandboxes", id, "connect"]) => {
                let timeout = body(request).get("timeout").and_then(Value::as_u64).unwrap_or(300);
                s.connects += 1;
                let Some(sandbox) = s.sandboxes.get_mut(*id) else { return error(404, "sandbox not found") };
                // Hobby clamps a longer timeout without saying so.
                sandbox.end_at = chrono::Utc::now() + chrono::TimeDelta::seconds(timeout.min(HOBBY_SECONDS) as i64);
                let resumed = sandbox.state == "paused";
                if resumed {
                    sandbox.state = "running".into();
                    sandbox.started_at = chrono::Utc::now();
                }
                json_reply(if resumed { 201 } else { 200 }, sandbox.created())
            }
            ("PUT", ["sandboxes", id, "network"]) => {
                let update = body(request);
                let Some(sandbox) = s.sandboxes.get_mut(*id) else { return error(404, "sandbox not found") };
                // The whole egress configuration is replaced; the proxy's gate stays.
                let public = sandbox.network["allowPublicTraffic"].clone();
                sandbox.network = json!({"allowPublicTraffic": public});
                for key in ["allowOut", "denyOut", "dnsServers"] {
                    if let Some(value) = update.get(key) {
                        sandbox.network[key] = value.clone();
                    }
                }
                reply(204, "")
            }
            ("GET", ["teams", team, "metrics"]) => {
                if *team != TEAM {
                    return error(403, "You are not allowed to access this team");
                }
                json_reply(200, json!(s.metrics))
            }
            ("GET", ["events", "sandboxes"]) => {
                let pairs = query(request);
                let get = |key: &str| pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
                let types: Vec<String> = pairs.iter().filter(|(k, _)| k == "types").map(|(_, v)| v.clone()).collect();
                let limit: usize = get("limit").and_then(|l| l.parse().ok()).unwrap_or(10);
                if limit > 100 {
                    return error(400, "limit must be at most 100");
                }
                let offset: usize = get("offset").and_then(|o| o.parse().ok()).unwrap_or(0);
                let mut events: Vec<Value> =
                    s.events.iter().filter(|e| types.is_empty() || types.iter().any(|t| e["type"] == *t)).cloned().collect();
                events.sort_by_key(|e| e["timestamp"].as_str().unwrap().parse::<chrono::DateTime<chrono::Utc>>().unwrap());
                if get("orderAsc").as_deref() != Some("true") {
                    events.reverse();
                }
                json_reply(200, json!(events.into_iter().skip(offset).take(limit).collect::<Vec<_>>()))
            }
            _ => {
                s.violations.push(format!("unexpected request {method} {path}"));
                error(404, "not found")
            }
        }
    }

    /// The bootstrap script, run as root with the token in its environment:
    /// its shell code runs over a temporary /run/drydock, the agent's argv
    /// goes through the supervisor's own parser, and an agent starts unless
    /// one already runs.
    async fn bootstrap(&self, request: &reqwest::Request) {
        let message = start_message(request).unwrap_or(Value::Null);
        let id =
            request.url().host_str().unwrap().trim_start_matches(&format!("{ENVD}-")).trim_end_matches(&format!(".{DOMAIN}")).to_owned();
        let script = message["process"]["args"][1].as_str().unwrap_or_default().to_owned();
        let start = {
            let mut s = self.state();
            let token = message["process"]["envs"]["DRYDOCK_TCP_TOKEN"].as_str().and_then(|t| Token::parse(t).ok());
            if token.as_ref().is_some_and(|t| script.contains(t.secret())) {
                s.violations.push("the token is on the agent's argv".into());
            }
            if !script.contains("umask 077") {
                s.violations.push(format!("the token file is not written root-only: {script}"));
            }
            let argv = supervised_argv(&script);
            let starts = argv.is_some() && !s.agent_missing;
            let Some(sandbox) = s.sandboxes.get_mut(&id).filter(|sb| sb.state == "running") else { return };
            if header(request, "authorization") != Some("Basic cm9vdDo=") {
                return;
            }
            sandbox.token_file = token_file_after(&script, sandbox.token_file.as_deref(), token.as_ref());
            sandbox.agent_bind = argv.and_then(|argv| argv.windows(2).find(|w| w[0] == "--tcp").map(|w| w[1].clone()));
            match (&sandbox.guest, sandbox.token_file.as_deref().map(Token::parse)) {
                (None, Some(Ok(token))) if starts => Some(token),
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
    /// Replaces a guest's agent and token, as a reboot and another host's
    /// bootstrap would, so a module's cached token goes stale.
    async fn rotate_agent_token(&self, id: &str) {
        let token = Token::generate().unwrap();
        let guest = start_guest(token.clone()).await;
        let mut s = self.state();
        let sandbox = s.sandboxes.get_mut(id).unwrap();
        sandbox.token_file = Some(token.secret().to_owned());
        sandbox.guest = Some(guest);
    }

    /// E2B's port proxy behind Google's front end: a WebSocket upgrade only
    /// (any other upgrade token is a 400), addressed `<port>-<id>.<domain>`,
    /// to a running sandbox, with its traffic token when it refuses public
    /// traffic (403 otherwise), to a port the guest listens on at its
    /// interface (502 otherwise). Then the request goes on to the guest as
    /// it came, `Authorization` included. The guest's answer comes back, but
    /// a 101 whose `Connection` lists `close` is not spliced: live E2B answers
    /// it with the same 502 as a closed port. Otherwise bytes are spliced
    /// both ways.
    async fn serve_proxy(self, mut listener: drydock_transport::MemoryListener) {
        while let Ok(stream) = listener.accept().await {
            let stand_in = self.clone();
            let task = tokio::spawn(async move { stand_in.proxy(stream).await });
            self.state().tunnels.push(task);
        }
    }
    async fn proxy(&self, mut stream: ByteStream) {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                return;
            }
            head.push(byte[0]);
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        let field = |name: &str| {
            text.lines()
                .skip(1)
                .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_owned()))
        };
        let refuse = |status: &str, message: &str| {
            format!(
                "HTTP/1.1 {status}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{message}",
                message.len()
            )
        };
        let host = field("host").unwrap_or_default();
        let target = {
            let mut s = self.state();
            let address = host.strip_suffix(&format!(".{DOMAIN}")).and_then(|h| h.split_once('-'));
            if !field("upgrade").is_some_and(|u| u.eq_ignore_ascii_case("websocket")) {
                if field("upgrade").is_some() {
                    s.violations.push(format!("a non-WebSocket upgrade through the front end: {:?}", field("upgrade")));
                }
                Err(refuse("400 Bad Request", "Your client has issued a malformed or illegal request."))
            } else if field("sec-websocket-key").is_none() || field("sec-websocket-version").as_deref() != Some("13") {
                Err(refuse("400 Bad Request", "Your client has issued a malformed or illegal request."))
            } else {
                match address.and_then(|(port, id)| Some((port.to_owned(), s.sandboxes.get(id)?))) {
                    None => Err(refuse("502 Bad Gateway", "The sandbox was not found")),
                    Some((_, sandbox)) if sandbox.state != "running" => Err(refuse("502 Bad Gateway", "The sandbox is paused")),
                    Some((_, sandbox))
                        if sandbox.network["allowPublicTraffic"] == false && field("e2b-traffic-access-token") != sandbox.traffic_token =>
                    {
                        Err(refuse("403 Forbidden", "missing or invalid traffic access token"))
                    }
                    Some((port, sandbox)) => match (&sandbox.guest, &sandbox.agent_bind) {
                        // The proxy enters through the guest's interface: a loopback listener is out of its reach.
                        (Some(guest), Some(bind)) if *bind == format!("0.0.0.0:{port}") => Ok((guest.address, port)),
                        _ => Err(refuse("502 Bad Gateway", &format!("The sandbox is running but port is not open: {port}"))),
                    },
                }
            }
        };
        let (address, port) = match target {
            Ok(target) => target,
            Err(answer) => {
                let _ = stream.write_all(answer.as_bytes()).await;
                return;
            }
        };
        let Ok(mut guest) = tokio::net::TcpStream::connect(address).await else { return };
        if guest.write_all(&head).await.is_err() {
            return;
        }
        let mut answer = Vec::new();
        while !answer.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            if guest.read(&mut byte).await.unwrap_or(0) == 0 {
                let _ = stream.write_all(&answer).await;
                return;
            }
            answer.push(byte[0]);
        }
        let text = String::from_utf8_lossy(&answer).into_owned();
        let switched = text.split_whitespace().nth(1) == Some("101");
        let closes = text.lines().skip(1).filter_map(|l| l.split_once(':')).any(|(name, value)| {
            name.eq_ignore_ascii_case("connection") && value.split(',').any(|token| token.trim().eq_ignore_ascii_case("close"))
        });
        if switched && closes {
            let _ = stream
                .write_all(refuse("502 Bad Gateway", &format!("The sandbox is running but port is not open: {port}")).as_bytes())
                .await;
            return;
        }
        if stream.write_all(&answer).await.is_err() {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut guest).await;
    }
}

fn registry(s: &mut State, host: &str, request: &reqwest::Request) -> http::Response<Bytes> {
    let authorization = header(request, "authorization").map(str::to_owned);
    if let Some(value) = &authorization {
        s.registry_auth.push((host.to_owned(), value.clone()));
    }
    if host == BASE_REGISTRY
        && let Some((user, secret)) = &s.base_auth
    {
        let expected = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{secret}")));
        if authorization.as_deref() != Some(&expected) {
            return http::Response::builder()
                .status(401)
                .header("www-authenticate", "Basic realm=\"registry\"")
                .body(Bytes::new())
                .unwrap();
        }
    }
    let digest = request.url().path().rsplit('/').next().unwrap_or_default().to_owned();
    match s.registries.get(&(host.to_owned(), digest)) {
        Some((content_type, bytes)) => {
            http::Response::builder().status(200).header("content-type", content_type).body(bytes.clone()).unwrap()
        }
        None => json_reply(404, json!({"errors": [{"code": "MANIFEST_UNKNOWN", "message": "manifest unknown"}]})),
    }
}
/// The signed Google Storage URL: its signature and required header are the
/// authorization, the content must hash to the name, and the key must not
/// travel here.
fn upload(s: &mut State, request: &reqwest::Request) -> http::Response<Bytes> {
    if header(request, "x-api-key").is_some() {
        s.violations.push("the API key was sent to the signed upload URL".into());
    }
    let hash = request.url().path().rsplit('/').next().unwrap_or_default().trim_end_matches(".tar.gz").to_owned();
    let signed = query(request).iter().any(|(k, v)| k == "X-Goog-Signature" && *v == format!("sig-{hash}"));
    if request.method() != "PUT" || !signed || header(request, "x-goog-content-sha256") != Some("UNSIGNED-PAYLOAD") {
        return reply(403, "<Error><Code>SignatureDoesNotMatch</Code></Error>");
    }
    let bytes = Bytes::copy_from_slice(request.body().and_then(|b| b.as_bytes()).unwrap_or_default());
    if format!("{:x}", Sha256::digest(&bytes)) != hash {
        s.violations.push("an uploaded file does not hash to its name".into());
    }
    s.uploads += 1;
    s.files.insert(hash, bytes);
    reply(200, "")
}
fn create_template(s: &mut State, body: Value) -> http::Response<Bytes> {
    let unexpected = unexpected_keys(&body, &["name", "tags", "alias", "teamID", "cpuCount", "memoryMB", "minFreeDiskMb"]);
    if !unexpected.is_empty() {
        s.violations.push(format!("unexpected template fields {unexpected:?}"));
    }
    let Some(name) = body["name"].as_str().filter(|n| template_name_allowed(n)) else {
        return error(400, "Invalid template name: it must be lowercase letters, numbers, dashes and underscores");
    };
    let (Some(cpus), Some(memory)) = (body["cpuCount"].as_u64(), body["memoryMB"].as_u64()) else {
        s.violations.push(format!("a template without a size: {body}"));
        return error(400, "cpuCount and memoryMB are required");
    };
    // Hobby's sandbox limits.
    if !(1..=8).contains(&cpus) || !(512..=8192).contains(&memory) || memory % 2 != 0 {
        return error(400, "CPU count must be 1 to 8 and memory 512 to 8192 MiB, an even number");
    }
    let build = s.id("build-");
    let name = name.to_owned();
    let id = match s.template(&name) {
        Some(t) => {
            // A rebuild of a name; it may also resize the template.
            t.cpus = cpus;
            t.memory_mb = memory;
            t.id.clone()
        }
        None => {
            let id = s.id("tpl");
            s.templates.push(Template { id: id.clone(), name: name.clone(), cpus, memory_mb: memory, builds: vec![] });
            id
        }
    };
    let polls_left = s.build_polls;
    s.template(&id).unwrap().builds.push(Build { id: build.clone(), status: "waiting".into(), start: None, polls_left });
    json_reply(202, json!({"templateID": id, "buildID": build, "public": false, "names": [name], "aliases": [name], "tags": ["default"]}))
}
fn start_build(s: &mut State, template: &str, build: &str, body: Value) -> http::Response<Bytes> {
    let unexpected = unexpected_keys(&body, &["fromImage", "fromTemplate", "fromImageRegistry", "force", "steps", "startCmd", "readyCmd"]);
    if !unexpected.is_empty() {
        s.violations.push(format!("unexpected build fields {unexpected:?}"));
    }
    let image = body["fromImage"].as_str().filter(|i| !i.is_empty());
    if image.is_some() == body["fromTemplate"].as_str().is_some_and(|t| !t.is_empty()) {
        return error(400, "Exactly one of fromImage or fromTemplate must be given and non-empty");
    }
    if let Some(registry) = body.get("fromImageRegistry")
        && (registry["type"] != "registry"
            || registry["username"].as_str().is_none_or(str::is_empty)
            || registry["password"].as_str().is_none_or(str::is_empty))
    {
        return error(400, "fromImageRegistry: type registry requires username and password");
    }
    let mut problem = None;
    for step in body["steps"].as_array().into_iter().flatten() {
        let args = step["args"].as_array().cloned().unwrap_or_default();
        match step["type"].as_str() {
            Some("ENV") if args.len() % 2 == 0 && !args.is_empty() => {}
            Some("COPY") if args.len() == 4 => {
                let hash = step["filesHash"].as_str().unwrap_or_default();
                if hash.len() != 64 {
                    return error(400, "filesHash must be a lowercase hex SHA-256");
                }
                if !s.files.contains_key(hash) {
                    problem = Some(format!("failed to get files for step COPY: object {hash} not found"));
                }
            }
            Some("RUN" | "WORKDIR" | "USER") => {}
            _ => return error(400, &format!("invalid step {step}")),
        }
    }
    let Some(t) = s.template(template) else { return error(404, "template not found") };
    let Some(b) = t.builds.iter_mut().find(|b| b.id == build) else { return error(404, "build not found") };
    if b.status != "waiting" {
        return error(400, "build has already been started");
    }
    b.status = "building".into();
    b.start = Some(body.clone());
    if let Some(problem) = problem {
        s.violations.push(problem);
    }
    reply(202, "")
}
fn build_status(s: &mut State, template: &str, build: &str) -> http::Response<Bytes> {
    let failure = s.build_failure.clone();
    let Some(t) = s.template(template) else { return error(404, "template not found") };
    let tid = t.id.clone();
    let Some(b) = t.builds.iter_mut().find(|b| b.id == build) else { return error(404, "build not found") };
    let mut logs = vec![json!({"timestamp": "2026-11-02T00:00:01Z", "level": "info", "message": "Building template", "step": "base"})];
    let mut reason = Value::Null;
    if b.status == "building" {
        if b.polls_left > 0 {
            b.polls_left -= 1;
        } else if let Some((message, line)) = &failure {
            b.status = "error".into();
            logs.push(json!({"timestamp": "2026-11-02T00:00:02Z", "level": "error", "message": line, "step": "base"}));
            reason = json!({"message": message, "step": "base"});
        } else {
            b.status = "ready".into();
        }
    }
    let mut info = json!({"templateID": tid, "buildID": b.id, "status": b.status, "logs": [], "logEntries": logs});
    if !reason.is_null() {
        info["reason"] = reason;
    }
    json_reply(200, info)
}
fn create_sandbox(s: &mut State, body: Value) -> http::Response<Bytes> {
    s.creates.push(body.clone());
    let allowed = [
        "templateID",
        "timeout",
        "autoPause",
        "autoPauseMemory",
        "autoResume",
        "allow_internet_access",
        "network",
        "metadata",
        "mcp",
        "iam",
        "volumeMounts",
    ];
    let unexpected = unexpected_keys(&body, &allowed);
    if !unexpected.is_empty() {
        // Notably envVars: nothing secret rides the create request.
        s.violations.push(format!("unexpected create fields {unexpected:?}"));
    }
    let Some(template) = body["templateID"].as_str() else { return error(400, "templateID is required") };
    let Some(t) = s.template(template).filter(|t| t.builds.iter().any(|b| b.status == "ready")) else {
        return error(404, &format!("template '{template}' not found"));
    };
    let (template, cpus, memory_mb) = (t.id.clone(), t.cpus, t.memory_mb);
    let timeout = body["timeout"].as_u64().unwrap_or(300);
    if timeout > HOBBY_SECONDS {
        return error(400, "Timeout cannot be greater than 1 hours");
    }
    let mut network = body.get("network").cloned().unwrap_or(json!({}));
    for (key, domains) in [("allowOut", true), ("denyOut", false)] {
        for entry in network[key].as_array().into_iter().flatten() {
            if !entry.as_str().is_some_and(|e| network_entry_allowed(e, domains)) {
                return error(400, &format!("invalid {key} entry {entry}"));
            }
        }
    }
    if !body["metadata"].as_object().is_some_and(|m| m.values().all(Value::is_string)) {
        return error(400, "metadata values must be strings");
    }
    let public = network["allowPublicTraffic"].as_bool().unwrap_or(true);
    network["allowPublicTraffic"] = json!(public);
    let id = format!("{}x2b7k", s.id("i"));
    let sandbox = Sandbox {
        id: id.clone(),
        template,
        cpus,
        memory_mb,
        metadata: body["metadata"].clone(),
        network,
        state: "running".into(),
        started_at: chrono::Utc::now(),
        end_at: chrono::Utc::now() + chrono::TimeDelta::seconds(timeout as i64),
        envd_token: Token::generate().unwrap().secret().to_owned(),
        traffic_token: (!public).then(|| Token::generate().unwrap().secret().to_owned()),
        token_file: None,
        agent_bind: None,
        guest: None,
    };
    let created = sandbox.created();
    s.sandboxes.insert(id, sandbox);
    json_reply(201, created)
}
fn list_sandboxes(s: &mut State, request: &reqwest::Request) -> http::Response<Bytes> {
    let pairs = query(request);
    let get = |key: &str| pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
    // `metadata` is itself a query string, each key and value URL encoded.
    let filter: Vec<(String, String)> =
        get("metadata").map(|m| url::form_urlencoded::parse(m.as_bytes()).into_owned().collect()).unwrap_or_default();
    let states: Vec<String> = get("state").map(|s| s.split(',').map(str::to_owned).collect()).unwrap_or_else(|| vec!["running".into()]);
    if get("limit").and_then(|l| l.parse::<u64>().ok()).is_some_and(|l| l > 100) {
        return error(400, "limit must be at most 100");
    }
    let rows: Vec<Value> = s
        .sandboxes
        .values()
        .filter(|sb| states.contains(&sb.state))
        .filter(|sb| s.ignore_metadata_filter || filter.iter().all(|(k, v)| sb.metadata[k] == *v))
        .map(Sandbox::listed)
        .collect();
    // Two a page, so paging is exercised.
    let start: usize = get("nextToken").map(|t| t.trim_start_matches("page-").parse().unwrap()).unwrap_or(0);
    let end = (start + 2).min(rows.len());
    let mut response = json_reply(200, json!(rows[start..end]));
    if end < rows.len() {
        response.headers_mut().insert("x-next-token", format!("page-{end}").parse().unwrap());
    }
    response
}
/// envd's process service: Start only, as Connect-RPC server streaming with
/// JSON, the sandbox's envd token, and the user chosen by Basic `user:`.
fn envd(s: &mut State, id: &str, request: &reqwest::Request) -> http::Response<Bytes> {
    let Some(sandbox) = s.sandboxes.get(id) else { return reply(502, "The sandbox was not found") };
    if sandbox.state != "running" {
        return reply(502, "The sandbox is paused");
    }
    if request.method() != "POST" || request.url().path() != "/process.Process/Start" {
        s.violations.push(format!("unexpected envd request {} {}", request.method(), request.url().path()));
        return reply(404, "");
    }
    if header(request, "x-access-token") != Some(&sandbox.envd_token) {
        return json_reply(
            401,
            json!({"code": 401, "message": "unauthorized access, please provide a valid access token or method signing if supported"}),
        );
    }
    if header(request, "content-type") != Some("application/connect+json") {
        return reply(415, "");
    }
    if !header(request, "connect-timeout-ms").and_then(|t| t.parse::<u64>().ok()).is_some_and(|t| t <= 30_000) {
        s.violations.push("a guest command without a Connect deadline inside the host's".into());
    }
    let user = header(request, "authorization")
        .and_then(|a| a.strip_prefix("Basic "))
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|u| u.strip_suffix(':').map(str::to_owned))
        .unwrap_or_else(|| "user".into());
    let Some(message) = start_message(request) else {
        return process_error("invalid_argument", "malformed Connect envelope");
    };
    if message["process"]["cmd"] != "/bin/sh" || message["process"]["args"][0] != "-c" {
        s.violations.push(format!("unexpected command {message}"));
    }
    let script = message["process"]["args"][1].as_str().unwrap_or_default().to_owned();
    let root = user == "root";
    let (output, code): (Vec<u8>, i64) = if script.starts_with("echo \"drydock-tcp-token $(cat /run/drydock/tcp.token)\"") {
        match (&sandbox.token_file, root) {
            (Some(token), true) => (format!("drydock-tcp-token {token}\n").into(), 0),
            _ => (b"cat: /run/drydock/tcp.token: Permission denied\n".to_vec(), 1),
        }
    } else if script.starts_with("test \"$(id -u)\" = 0") {
        (json!({"uid": 0, "unlisted_canary": false, "raw_dns": false, "listed_direct": true}).to_string().into(), if root { 0 } else { 1 })
    } else if script.contains("--supervise") {
        // StandIn::bootstrap has run the script's shell code and started the agent.
        let token = format!("drydock-tcp-token {}\n", sandbox.token_file.clone().unwrap_or_default());
        match supervised_argv(&script) {
            _ if !root => (format!("{token}mkdir: cannot create directory '/run/drydock': Permission denied\n").into(), 1),
            _ if s.agent_missing => (format!("{token}env: '/opt/drydock/drydock-agent': No such file or directory\n").into(), 127),
            Some(_) => (token.into(), 0),
            None => (format!("{token}usage: drydock-agent --supervise [...] --socket PATH\n").into(), 1),
        }
    } else {
        (s.exec_output.clone(), s.exec_exit)
    };
    process_stream(&output, code)
}
fn process_error(code: &str, message: &str) -> http::Response<Bytes> {
    let body = envelope(2, &json!({"error": {"code": code, "message": message}}));
    http::Response::builder().status(200).header("content-type", "application/connect+json").body(Bytes::from(body)).unwrap()
}
/// The agent's argv as the guest's `drydock-agent --supervise` parses it,
/// through the supervisor's own parser; None when it would refuse.
fn supervised_argv(script: &str) -> Option<Vec<String>> {
    const EXEC: &str = "exec env -u DRYDOCK_TCP_TOKEN /opt/drydock/drydock-agent --supervise ";
    let (_, argv) = script.split_once(EXEC)?;
    let argv: Vec<String> = argv.split_whitespace().map(str::to_owned).collect();
    let os: Vec<std::ffi::OsString> = argv.iter().map(Into::into).collect();
    drydock_agent::socket::supervised(&os).ok().map(|_| argv)
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
        let bootstrap = request.url().host_str().is_some_and(|h| h.starts_with(&format!("{ENVD}-")))
            && start_message(&request).is_some_and(|m| m["process"]["args"][1].as_str().is_some_and(|s| s.contains("--supervise")));
        if bootstrap {
            self.0.bootstrap(&request).await;
        }
        Ok(self.0.respond(&request))
    }
}
/// Names resolve as the lab's do: its registry host to its private address.
struct Names;
#[async_trait]
impl Resolver for Names {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        match host {
            "forgejo.lab.example" => Ok(vec!["192.168.1.31".parse().unwrap()]),
            "mixed.example" => Ok(vec!["203.0.113.5".parse().unwrap(), "10.0.0.5".parse().unwrap()]),
            "mapped.example" => Ok(vec!["::ffff:10.0.0.5".parse().unwrap()]),
            "registry.example.com" | "ghcr.io" => Ok(vec!["203.0.113.10".parse().unwrap()]),
            _ => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no such host")),
        }
    }
}

struct World {
    stand_in: StandIn,
    images: Images,
    provider: Arc<dyn Provider>,
    credentials: Credentials,
    dialer: drydock_transport::MemoryDialer,
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
            assert!(violations.is_empty(), "E2B contract violations: {violations:?}");
        }
    }
}
async fn configure(name: &str, settings: Value, stand_in: &StandIn, dialer: &drydock_transport::MemoryDialer) -> Result<Arc<dyn Provider>> {
    let config = ProviderConfiguration { module: "e2b".into(), settings: serde_json::from_value(settings).unwrap(), credential: None };
    let module = E2bModule::with_parts(Arc::new(dialer.clone()), Arc::new(Names));
    module.configure(name, &config, Arc::new(Wire(stand_in.clone()))).await
}
async fn world_with(settings: Value) -> World {
    let (stand_in, images) = StandIn::with_images();
    let (dialer, listener) = drydock_transport::memory();
    tokio::spawn(stand_in.clone().serve_proxy(listener));
    let provider = configure("e2b", settings, &stand_in, &dialer).await.unwrap();
    World { stand_in, images, provider, credentials: Credentials::new(Some(Secret::new(KEY))), dialer }
}
async fn world() -> World {
    world_with(json!({"team_id": TEAM})).await
}
fn size(cpus: f64, memory_mib: u64, disk_gib: u64) -> Size {
    Size { cpus, memory_bytes: memory_mib << 20, disk_bytes: disk_gib << 30 }
}
impl World {
    fn prepare_request(&self, size: Size, image_pull: Option<RegistryCredential>) -> PrepareRequest {
        PrepareRequest {
            size,
            platform: Some(Platform::new("linux", "amd64")),
            route: Some(ImageRouteKind::RegistryPull),
            image_pull,
            image_digest: self.images.base.clone(),
            tools_digest: self.images.tools.clone(),
        }
    }
    async fn prepare(&self, size: Size) -> Result<Prepared> {
        self.provider.prepare(self.prepare_request(size, None), &self.credentials).await
    }
    async fn provision_as(&self, provider: &dyn Provider, label: &str, size: Size, egress: EgressRequest) -> Result<Provisioned> {
        let prepared = provider.prepare(self.prepare_request(size.clone(), None), &self.credentials).await?;
        provider.provision(ProvisionRequest { label: label.into(), prepared, size, egress, ssh_public_key: None }, &self.credentials).await
    }
    async fn provision(&self, label: &str, size: Size, egress: EgressRequest) -> Result<Provisioned> {
        self.provision_as(&*self.provider, label, size, egress).await
    }
    async fn launched(&self, label: &str) -> Environment {
        self.provision(label, size(2.0, 2048, 10), EgressRequest::Open).await.unwrap().into_inner()
    }
    /// The agent's hello through the provider's relay.
    async fn agent_through(&self, provider: &dyn Provider, id: &str) -> Client {
        let stream = provider.relay(id, &self.credentials).await.unwrap();
        Client::connect(Box::new(stream), "test-build").await.unwrap()
    }
    async fn agent(&self, id: &str) -> Client {
        self.agent_through(&*self.provider, id).await
    }
    /// This host's provider as after a restart: the same stand-in, no tokens held.
    async fn restarted(&self) -> Arc<dyn Provider> {
        configure("e2b", json!({"team_id": TEAM}), &self.stand_in, &self.dialer).await.unwrap()
    }
}

// Prepare builds the template once: created with its size under a name
// holding the image and size, the tools layer uploaded to the signed URL
// (without the key) as the COPY context, the base image's ENV restored, then
// polled to ready. A second prepare finds it by name and builds nothing; a
// template of another size or tools pin reuses the cached tools file without
// uploading.
#[tokio::test(start_paused = true)]
async fn prepare_builds_once_then_finds_the_template_by_name() {
    let w = world().await;
    w.stand_in.state().build_polls = 2;
    let first = w.prepare(size(2.0, 2048, 10)).await.unwrap();
    assert_eq!((first.provider.as_str(), first.platform.clone()), ("e2b", Platform::new("linux", "amd64")));
    assert!(first.id.starts_with("drydock-"), "{}", first.id);
    {
        let s = w.stand_in.state();
        assert_eq!(s.templates.len(), 1);
        let template = &s.templates[0];
        assert_eq!((template.name.as_str(), template.cpus, template.memory_mb), (first.id.as_str(), 2, 2048));
        assert_eq!(template.builds.len(), 1);
        let start = template.builds[0].start.clone().unwrap();
        assert_eq!(
            start,
            json!({"fromImage": w.images.base, "steps": [
                {"type": "ENV", "args": ["PATH", "/usr/local/cargo/bin:/usr/bin:/bin", "CARGO_HOME", "/usr/local/cargo"]},
                {"type": "COPY", "args": ["opt/drydock", "/opt/drydock", "root", ""], "filesHash": w.images.layer_hash},
            ]})
        );
        assert_eq!(s.uploads, 1);
        assert_eq!(s.files[&w.images.layer_hash], w.images.layer);
    }
    let again = w.prepare(size(2.0, 2048, 10)).await.unwrap();
    assert_eq!(again.id, first.id);
    assert_eq!(w.stand_in.state().templates[0].builds.len(), 1, "found by name, not rebuilt");
    let larger = w.prepare(size(4.0, 4096, 10)).await.unwrap();
    assert_ne!(larger.id, first.id);
    assert_eq!(w.stand_in.state().templates.len(), 2);
    // A new tools pin is a new template, so a new agent is baked in.
    let mut request = w.prepare_request(size(2.0, 2048, 10), None);
    request.tools_digest = request.tools_digest.replace("/drydock-tools@", "/drydock-tools-next@");
    let tools = w.provider.prepare(request, &w.credentials).await.unwrap();
    assert!(tools.id != first.id && tools.id != larger.id, "{}", tools.id);
    let s = w.stand_in.state();
    assert_eq!((s.templates.len(), s.uploads), (3, 1), "the tools file is present at E2B");
}

/// A tools image (an index over one amd64 manifest) whose layers are
/// `layers`, stored at the tools registry; its pinned reference.
fn tools_image(w: &World, layers: Value) -> String {
    let mut s = w.stand_in.state();
    let mut put = |content_type: &str, bytes: Vec<u8>| {
        let (digest, size) = (sha256(&bytes), bytes.len());
        s.registries.insert((TOOLS_REGISTRY.to_owned(), digest.clone()), (content_type.to_owned(), Bytes::from(bytes)));
        (digest, size)
    };
    let (config, config_size) = put("application/octet-stream", br#"{"architecture":"amd64","os":"linux"}"#.to_vec());
    let manifest = json!({"schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config, "size": config_size}, "layers": layers});
    let (manifest, manifest_size) = put(OCI_MANIFEST, serde_json::to_vec(&manifest).unwrap());
    let index = json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": [
        {"mediaType": OCI_MANIFEST, "digest": manifest, "size": manifest_size, "platform": {"os": "linux", "architecture": "amd64"}}]});
    let (index, _) = put(OCI_INDEX, serde_json::to_vec(&index).unwrap());
    format!("{TOOLS_REGISTRY}/flotilla-org/drydock-tools@{index}")
}

// The tools image must be one layer that fits the host's HTTP deadline
// (64 MiB): two layers, or a larger one, are refused before any template
// is created or anything uploaded.
#[tokio::test]
async fn prepare_refuses_tools_it_cannot_copy() {
    let w = world().await;
    let layer = |size: u64| json!({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": format!("sha256:{}", "c".repeat(64)), "size": size});
    for (layers, expected) in [
        (json!([layer(10), layer(10)]), "the tools image has 2 layers"),
        (json!([]), "the tools image has 0 layers"),
        (json!([layer((64 << 20) + 1)]), "the tools layer holds 67108865 bytes"),
    ] {
        let mut request = w.prepare_request(size(1.0, 1024, 10), None);
        request.tools_digest = tools_image(&w, layers);
        match w.provider.prepare(request, &w.credentials).await {
            Err(ProtocolError::Refused { reason }) => assert!(reason.contains(expected), "{reason}"),
            other => panic!("{other:?}"),
        }
    }
    let s = w.stand_in.state();
    assert_eq!((s.templates.len(), s.uploads), (0, 0));
}

// A failed build is a refusal carrying E2B's reason and the log's tail.
#[tokio::test(start_paused = true)]
async fn a_failed_build_is_refused_with_its_reason_and_log() {
    let w = world().await;
    w.stand_in.state().build_failure =
        Some(("unable to retrieve image from registry".into(), "pull registry.example.com/team/rust: 401".into()));
    match w.prepare(size(1.0, 1024, 10)).await {
        Err(ProtocolError::Refused { reason }) => {
            assert!(reason.contains("unable to retrieve image from registry") && reason.contains("401"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
}

// A build still running when prepare gives up is Unavailable, and the
// retried prepare waits for that build rather than starting another.
#[tokio::test(start_paused = true)]
async fn a_build_in_progress_is_rejoined() {
    let w = world().await;
    w.stand_in.state().build_polls = 200;
    assert!(matches!(w.prepare(size(1.0, 1024, 10)).await, Err(ProtocolError::Unavailable { .. })));
    w.prepare(size(1.0, 1024, 10)).await.unwrap();
    let s = w.stand_in.state();
    assert_eq!(s.templates[0].builds.len(), 1);
    assert_eq!(s.templates[0].builds[0].status, "ready");
}

// A base on a private address, literally or by resolution, is refused
// before any request, naming why: E2B pulls over the public internet.
#[tokio::test]
async fn a_private_registry_base_is_refused_up_front() {
    let w = world().await;
    for registry in [
        "192.168.1.31:3000",
        "10.1.2.3:5000",
        "127.0.0.1:5000",
        "100.64.0.9",
        "localhost:5000",
        "registry:5000",
        "forgejo.lab.internal",
        "forgejo.lab.example",
        "mixed.example",
        "mapped.example",
    ] {
        let mut request = w.prepare_request(size(1.0, 1024, 10), None);
        request.image_digest = format!("{registry}/lab/image@sha256:{}", "3".repeat(64));
        match w.provider.prepare(request, &w.credentials).await {
            Err(ProtocolError::Refused { reason }) => assert!(reason.contains("public internet") && reason.contains(registry), "{reason}"),
            other => panic!("{registry}: {other:?}"),
        }
    }
    assert!(w.stand_in.state().requests.is_empty());
}

// The pull credential reaches the base's registry and that build's
// fromImageRegistry, and never the tools image's registry.
#[tokio::test(start_paused = true)]
async fn the_pull_credential_goes_to_the_base_registry_and_its_build_only() {
    let w = world().await;
    w.stand_in.state().base_auth = Some((PULL.0.into(), PULL.1.into()));
    let pull = RegistryCredential { username: PULL.0.into(), secret: Secret::new(PULL.1) };
    w.provider.prepare(w.prepare_request(size(1.0, 1024, 10), Some(pull)), &w.credentials).await.unwrap();
    let s = w.stand_in.state();
    let start = s.templates[0].builds[0].start.clone().unwrap();
    assert_eq!(start["fromImageRegistry"], json!({"type": "registry", "username": PULL.0, "password": PULL.1}));
    assert!(s.registry_auth.iter().any(|(host, _)| host == BASE_REGISTRY));
    assert!(s.registry_auth.iter().all(|(host, _)| host != TOOLS_REGISTRY), "{:?}", s.registry_auth);
}

// Prepare refuses what E2B cannot hold before any request: another route,
// unpinned images, another platform, fractional vCPUs, odd or tiny memory,
// and more disk than the plan's.
#[tokio::test]
async fn prepare_refuses_unpinned_images_platforms_and_sizes() {
    let w = world().await;
    let base = |f: &dyn Fn(&mut PrepareRequest)| {
        let mut request = w.prepare_request(size(1.0, 1024, 10), None);
        f(&mut request);
        request
    };
    let requests = [
        base(&|r| r.route = Some(ImageRouteKind::ProviderPush)),
        base(&|r| r.image_digest = "registry.example.com/team/rust:latest".into()),
        base(&|r| r.tools_digest = "ghcr.io/flotilla-org/drydock-tools:main".into()),
        base(&|r| r.size = size(1.5, 1024, 10)),
        base(&|r| r.size = size(1.0, 1023, 10)),
        base(&|r| r.size = size(1.0, 256, 10)),
        base(&|r| r.size = size(1.0, 1024, 11)),
    ];
    for request in requests {
        assert!(matches!(w.provider.prepare(request.clone(), &w.credentials).await, Err(ProtocolError::Refused { .. })), "{request:?}");
    }
    let arm = base(&|r| r.platform = Some(Platform::new("linux", "arm64")));
    assert!(matches!(w.provider.prepare(arm, &w.credentials).await, Err(ProtocolError::ImageRefused { .. })));
    assert!(w.stand_in.state().requests.is_empty());
}

// Provision creates the sandbox from the template with the configured
// lifetime, autoPause, both ownership tags, the proxy's gate on and no
// envVars; it starts the agent as root with a fresh token in a root-only
// file, never on argv, listening on the guest's interface; the agent answers
// hello through the relay.
#[tokio::test]
async fn provision_creates_bootstraps_and_reaches_the_agent() {
    let w = world().await;
    let provisioned = w.provision("vessel-1", size(2.0, 2048, 10), EgressRequest::Open).await.unwrap();
    let Provisioned::Created(environment) = provisioned else { panic!("{provisioned:?}") };
    assert_eq!(environment.label.as_deref(), Some("vessel-1"));
    assert_eq!(environment.state, Observation::Running);
    assert_eq!(environment.granted_size, Some(size(2.0, 2048, 10)));
    assert_eq!(environment.egress, Enforcement::Enforced);
    {
        let s = w.stand_in.state();
        let create = &s.creates[0];
        let prepared = &s.templates[0].name;
        assert_eq!(
            create,
            &json!({"templateID": prepared, "timeout": 3600, "autoPause": true, "metadata": {"drydock.provider": "e2b", "flotilla.label": "vessel-1"},
                "network": {"allowPublicTraffic": false}})
        );
        let sandbox = &s.sandboxes[&environment.id];
        let guest = sandbox.guest.as_ref().expect("the agent runs");
        assert_eq!(sandbox.token_file.as_deref(), Some(guest.token.secret()));
        assert_eq!(sandbox.agent_bind.as_deref(), Some("0.0.0.0:7811"));
    }
    let client = w.agent(&environment.id).await;
    assert_eq!(client.hello().fingerprint, "test-build");
}

// A bootstrap whose agent doesn't start fails provision with the guest's
// output as its cause, so drydockd's log says why, and never the token.
#[tokio::test]
async fn a_failed_bootstrap_reports_the_guests_output() {
    let w = world().await;
    w.stand_in.state().agent_missing = true;
    let error = w.provision("vessel-1", size(1.0, 1024, 10), EgressRequest::Open).await.unwrap_err();
    let token = w.stand_in.state().sandboxes.values().next().unwrap().token_file.clone().unwrap();
    let ProtocolError::Internal { provider_error, .. } = &error else { panic!("{error:?}") };
    assert!(provider_error.contains("drydock-agent': No such file or directory"), "{provider_error}");
    assert!(!format!("{error:?}").contains(&token), "{error:?}");
}

// Provision finds an existing sandbox by both ownership tags, so it is
// idempotent by label: the running one is bootstrapped again and adopted.
// Another instance's sandbox with the same label is not adopted.
#[tokio::test]
async fn provision_readopts_by_metadata() {
    let w = world().await;
    let first = w.launched("vessel-1").await;
    let again = w.provision("vessel-1", size(2.0, 2048, 10), EgressRequest::Open).await.unwrap();
    let Provisioned::Existing(again) = again else { panic!("{again:?}") };
    assert_eq!(again.id, first.id);
    assert_eq!(w.stand_in.state().creates.len(), 1);
    w.agent(&again.id).await;
    let other = configure("e2b-other", json!({"team_id": TEAM}), &w.stand_in, &w.dialer).await.unwrap();
    let theirs = w.provision_as(&*other, "vessel-1", size(2.0, 2048, 10), EgressRequest::Open).await;
    let Ok(Provisioned::Created(theirs)) = theirs else { panic!("{theirs:?}") };
    assert_ne!(theirs.id, first.id);
    assert_eq!(w.provider.list(&w.credentials).await.unwrap().len(), 1);
}

// Re-adoption refuses a sandbox whose size or egress policy differs from the
// request, rather than handing back something else.
#[tokio::test]
async fn readoption_refuses_another_size_or_policy() {
    let w = world().await;
    w.launched("vessel-1").await;
    let refused = |r: Result<Provisioned>| matches!(r, Err(ProtocolError::Refused { .. }));
    assert!(refused(w.provision("vessel-1", size(4.0, 2048, 10), EgressRequest::Open).await));
    assert!(refused(w.provision("vessel-1", size(2.0, 2048, 10), EgressRequest::DenyAll { direct: vec![] }).await));
    assert_eq!(w.stand_in.state().creates.len(), 1);
}

// Hobby refuses a timeout over an hour at create; the refusal carries E2B's text.
#[tokio::test]
async fn a_lifetime_over_the_plans_cap_is_refused_at_create() {
    let w = world_with(json!({"team_id": TEAM, "lifetime_seconds": 7200})).await;
    match w.provision("vessel-1", size(1.0, 1024, 10), EgressRequest::Open).await {
        Err(ProtocolError::Refused { reason }) => assert!(reason.contains("Timeout cannot be greater than 1 hours"), "{reason}"),
        other => panic!("{other:?}"),
    }
}

// Relay after a host restart holds no tokens: the traffic token comes from
// connect, the agent's from the guest, and hello answers. A traffic token
// the proxy refuses, or an agent token the agent refuses, is fetched again
// once. Without the traffic token the proxy refuses (403), as live.
#[tokio::test]
async fn relay_recovers_its_tokens_and_the_proxy_gates_traffic() {
    let w = world().await;
    let id = w.launched("vessel-1").await.id;
    let restarted = w.restarted().await;
    w.agent_through(&*restarted, &id).await;
    assert_eq!(w.stand_in.state().connects, 1);
    w.stand_in.state().sandboxes.get_mut(&id).unwrap().traffic_token = Some(Token::generate().unwrap().secret().to_owned());
    w.agent_through(&*restarted, &id).await;
    w.stand_in.rotate_agent_token(&id).await;
    w.agent_through(&*restarted, &id).await;
    let token = w.stand_in.state().sandboxes[&id].guest.as_ref().unwrap().token.clone();
    let url = format!("https://7811-{id}.{DOMAIN}/v1/connect");
    let error = drydock_transport::tcp::connect_at(w.dialer.connect().await.unwrap(), &url, &token).await.err().unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("403") && error.to_string().contains("traffic access token"), "{error}");
}

// The proxy will not splice a 101 that says `Connection: close`: an agent
// that answered so is refused with the closed port's 502, as live.
#[tokio::test]
async fn the_proxy_refuses_a_closing_upgrade() {
    let w = world().await;
    let id = w.launched("vessel-1").await.id;
    let closing = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = closing.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = closing.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(stream.read_u8().await.unwrap());
                }
                let answer = "HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade, close\r\nupgrade: websocket\r\n\r\n";
                let _ = stream.write_all(answer.as_bytes()).await;
            });
        }
    });
    let token = {
        let mut s = w.stand_in.state();
        let guest = s.sandboxes.get_mut(&id).unwrap().guest.as_mut().unwrap();
        guest.address = address;
        guest.token.clone()
    };
    let traffic = w.stand_in.state().sandboxes[&id].traffic_token.clone().unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert("e2b-traffic-access-token", traffic.parse().unwrap());
    let url = format!("https://7811-{id}.{DOMAIN}/v1/connect");
    let error = drydock_transport::tcp::connect_at_with(w.dialer.connect().await.unwrap(), &url, &token, headers).await.err().unwrap();
    let refusal = drydock_transport::tcp::Refusal::of(&error).expect("an HTTP refusal");
    assert_eq!(refusal.status, 502, "{error}");
    assert!(refusal.body.contains("port is not open: 7811"), "{error}");
}

// A paused sandbox is refused rather than woken.
#[tokio::test]
async fn relay_refuses_a_paused_sandbox() {
    let w = world().await;
    let id = w.launched("vessel-1").await.id;
    w.provider.operations().suspend_resume.unwrap().suspend(&id, &w.credentials).await.unwrap();
    let connects = w.stand_in.state().connects;
    assert!(matches!(w.provider.relay(&id, &w.credentials).await, Err(ProtocolError::Refused { .. })));
    assert_eq!(w.stand_in.state().connects, connects, "no connect, which would resume it");
    assert_eq!(w.stand_in.state().sandboxes[&id].state, "paused");
}

// Egress requests map to E2B's network: open sends only the proxy's gate;
// deny-all denies 0.0.0.0/0 and allows CIDRs, IPv4 literals as /32 and
// names as domain entries. Ports and IPv6 are refused before any create.
// With a probe configured, inspect measures the claim as root.
#[tokio::test]
async fn egress_requests_map_to_network_configuration() {
    let w = world_with(json!({"team_id": TEAM, "egress_probe": {"command": ["/probe"]}})).await;
    let host = |h: &str| serde_json::from_value::<Destination>(json!({"kind": "host", "host": h})).unwrap();
    let cidr = |c: &str| serde_json::from_value::<Destination>(json!({"kind": "cidr", "cidr": c})).unwrap();
    let deny = w.provision("a", size(1.0, 1024, 10), EgressRequest::DenyAll { direct: vec![] }).await.unwrap().into_inner();
    assert!(deny.egress_measured && deny.egress == Enforcement::Enforced);
    let listed = EgressRequest::DenyAll { direct: vec![cidr("1.1.1.0/24"), host("8.8.8.8"), host("GitHub.com.")] };
    w.provision("b", size(1.0, 1024, 10), listed).await.unwrap();
    {
        let s = w.stand_in.state();
        assert_eq!(s.creates[0]["network"], json!({"allowPublicTraffic": false, "denyOut": ["0.0.0.0/0"]}));
        assert_eq!(
            s.creates[1]["network"],
            json!({"allowPublicTraffic": false, "denyOut": ["0.0.0.0/0"], "allowOut": ["1.1.1.0/24", "8.8.8.8/32", "github.com"]})
        );
    }
    for direct in [
        vec![serde_json::from_value::<Destination>(json!({"kind": "host_port", "host": "github.com", "port": 443})).unwrap()],
        vec![cidr("2001:db8::/32")],
        vec![host("2001:db8::1")],
    ] {
        let refused = w.provision("c", size(1.0, 1024, 10), EgressRequest::DenyAll { direct }).await;
        assert!(matches!(refused, Err(ProtocolError::Refused { .. })), "{refused:?}");
    }
    assert_eq!(w.stand_in.state().creates.len(), 2);
}

// Suspend pauses with memory and reads as suspended by request; resume
// connects (its timeout clamped to the plan's hour without a word),
// bootstraps again into the same agent, and hello answers again. A pause
// at the lifetime cap reads as paused by the provider.
#[tokio::test]
async fn suspend_and_resume_keep_the_agent() {
    let w = world().await;
    let id = w.launched("vessel-1").await.id;
    let ports = w.provider.operations().suspend_resume.unwrap();
    let token = ports.suspend(&id, &w.credentials).await.unwrap();
    assert_eq!(w.provider.inspect(&id, &w.credentials).await.unwrap().state, Observation::Stopped { cause: StopCause::SuspendedByRequest });
    assert_eq!(ports.suspend(&id, &w.credentials).await.unwrap(), token, "suspend is idempotent");
    let bad = ResumeToken { token: Secret::new("e2b-resume-other") };
    assert!(matches!(ports.resume(&id, bad, &w.credentials).await, Err(ProtocolError::Refused { .. })));
    let agent = w.stand_in.state().sandboxes[&id].guest.as_ref().unwrap().address;
    ports.resume(&id, token, &w.credentials).await.unwrap();
    {
        let s = w.stand_in.state();
        let sandbox = &s.sandboxes[&id];
        assert_eq!(sandbox.state, "running");
        assert_eq!(sandbox.guest.as_ref().unwrap().address, agent, "memory kept: the same agent");
        assert!(sandbox.end_at <= chrono::Utc::now() + chrono::TimeDelta::seconds(HOBBY_SECONDS as i64));
        assert_eq!(s.events.iter().filter(|e| e["type"] == "sandbox.lifecycle.paused").count(), 1);
    }
    w.agent(&id).await;
    w.stand_in.state().sandboxes.get_mut(&id).unwrap().state = "paused".into();
    assert_eq!(w.provider.inspect(&id, &w.credentials).await.unwrap().state, Observation::Stopped { cause: StopCause::PausedByProvider });
}

// Destroy kills our sandbox and is idempotent; the id then reads as gone.
// Another's sandbox in the team is refused and left alone.
#[tokio::test]
async fn destroy_is_idempotent_and_checks_ownership() {
    let w = world().await;
    let id = w.launched("vessel-1").await.id;
    w.provider.destroy(&id, &w.credentials).await.unwrap();
    w.provider.destroy(&id, &w.credentials).await.unwrap();
    assert_eq!(w.provider.inspect(&id, &w.credentials).await.unwrap().state, Observation::Gone { cause: GoneCause::DestroyedAtProvider });
    let other = configure("e2b-other", json!({"team_id": TEAM}), &w.stand_in, &w.dialer).await.unwrap();
    let theirs = w.provision_as(&*other, "vessel-2", size(1.0, 1024, 10), EgressRequest::Open).await.unwrap().into_inner();
    assert!(matches!(w.provider.destroy(&theirs.id, &w.credentials).await, Err(ProtocolError::Refused { .. })));
    assert!(w.stand_in.state().sandboxes.contains_key(&theirs.id));
    assert!(matches!(w.provider.destroy("../teams", &w.credentials).await, Ok(())), "a malformed id names no sandbox");
}

// List pages through E2B's metadata filter and keeps this instance's
// sandboxes, paused ones too, each with its policy's fingerprint.
#[tokio::test]
async fn list_pages_and_keeps_this_instances_sandboxes() {
    let w = world().await;
    let mut ids = vec![];
    for label in ["a", "b", "c"] {
        ids.push(w.launched(label).await.id);
    }
    w.provider.operations().suspend_resume.unwrap().suspend(&ids[0], &w.credentials).await.unwrap();
    let other = configure("e2b-other", json!({"team_id": TEAM}), &w.stand_in, &w.dialer).await.unwrap();
    w.provision_as(&*other, "d", size(2.0, 2048, 10), EgressRequest::Open).await.unwrap();
    let mut rows = w.provider.list(&w.credentials).await.unwrap();
    rows.sort_by_key(|r| r.label.clone());
    assert_eq!(rows.iter().map(|r| r.id.clone()).collect::<Vec<_>>(), ids);
    assert_eq!(rows[0].state, Observation::Stopped { cause: StopCause::SuspendedByRequest });
    w.stand_in.state().ignore_metadata_filter = true;
    assert_eq!(w.provider.list(&w.credentials).await.unwrap().len(), 3, "both tags are checked again");
    assert!(
        matches!(w.provision("d", size(2.0, 2048, 10), EgressRequest::Open).await, Ok(Provisioned::Created(_))),
        "never adopts another's"
    );
    w.stand_in.state().ignore_metadata_filter = false;
    let inspected = w.provider.inspect(&ids[1], &w.credentials).await.unwrap();
    assert!(rows[1].egress_policy.is_some() && rows[1].egress_policy == inspected.egress_policy);
}

// Quota is the team's latest concurrency metric, with the configured limit.
#[tokio::test]
async fn quota_reads_the_latest_concurrency() {
    let w = world_with(json!({"team_id": TEAM, "concurrency_limit": 20})).await;
    w.stand_in.state().metrics = vec![
        json!({"timestamp": "2026-11-02T00:00:00Z", "timestampUnix": 1_793_577_600, "concurrentSandboxes": 7, "sandboxStartRate": 0.1}),
        json!({"timestamp": "2026-11-02T00:00:05Z", "timestampUnix": 1_793_577_605, "concurrentSandboxes": 3, "sandboxStartRate": 0.0}),
    ];
    let quota = w.provider.operations().quota.unwrap().quota(&w.credentials).await.unwrap();
    assert_eq!((quota.concurrency_in_use, quota.concurrency_limit), (Some(3), Some(20)));
    let wrong = world_with(json!({"team_id": "team-2"})).await;
    assert!(matches!(wrong.provider.operations().quota.unwrap().quota(&wrong.credentials).await, Err(ProtocolError::Refused { .. })));
}

// Usage sums our executions inside the period from pause and kill events:
// hours by size, vCPU and memory seconds, sandboxes counted once. Others'
// events, and time outside the period, are left out.
#[tokio::test]
async fn usage_sums_our_executions_from_lifecycle_events() {
    let w = world().await;
    let event = |id: &str, kind: &str, provider: &str, started: &str, ended: &str, cpus: u64, memory: u64| {
        json!({"id": format!("{id}-{kind}-{ended}"), "version": "v2", "type": format!("sandbox.lifecycle.{kind}"), "timestamp": ended,
            "sandboxId": id, "sandboxExecutionId": "x", "sandboxTemplateId": "t", "sandboxBuildId": "b", "sandboxTeamId": TEAM,
            "eventData": {"sandbox_metadata": {"drydock.provider": provider, "flotilla.label": "l"}, "execution": {"started_at": started, "vcpu_count": cpus, "memory_mb": memory, "execution_time": 1}}})
    };
    w.stand_in.state().events = vec![
        // One hour inside the period, paused, then half an hour more until killed.
        event("s1", "paused", "e2b", "2026-11-01T01:00:00Z", "2026-11-01T02:00:00Z", 2, 2048),
        event("s1", "killed", "e2b", "2026-11-01T03:00:00Z", "2026-11-01T03:30:00Z", 2, 2048),
        // Straddles the period's start: half an hour counts.
        event("s2", "killed", "e2b", "2026-10-31T23:30:00Z", "2026-11-01T00:30:00Z", 1, 1024),
        // Ended before the period.
        event("s3", "killed", "e2b", "2026-10-31T20:00:00Z", "2026-10-31T21:00:00Z", 1, 1024),
        // Another instance's.
        event("s4", "killed", "elsewhere", "2026-11-01T01:00:00Z", "2026-11-01T02:00:00Z", 8, 8192),
    ];
    let period: Period = serde_json::from_value(json!({"start": "2026-11-01T00:00:00Z", "end": "2026-11-02T00:00:00Z"})).unwrap();
    let usage = w.provider.operations().usage.unwrap().usage(period, &w.credentials).await.unwrap();
    let hours: BTreeMap<u64, f64> = usage.environment_hours.iter().map(|u| (u.size.cpus as u64, u.hours)).collect();
    assert_eq!(hours, BTreeMap::from([(1, 0.5), (2, 1.5)]));
    let measurements = usage.measurements.unwrap();
    assert_eq!(measurements.resources[&ResourceKind::Cpu].amount, 2.0 * 5400.0 + 1800.0);
    assert_eq!(measurements.resources[&ResourceKind::Memory].amount, (2048.0 * 5400.0 + 1024.0 * 1800.0) * (1 << 20) as f64);
    assert_eq!(measurements.resources[&ResourceKind::Environments].amount, 2.0);
    assert!(measurements.cost.is_none());
}

// Exec runs as root through envd: output bytes intact, a non-zero exit as
// CommandFailed with the output. A stale envd token is read again, once.
#[tokio::test]
async fn exec_returns_bytes_and_reports_failure() {
    let w = world().await;
    let id = w.launched("vessel-1").await.id;
    let exec = w.provider.operations().exec.unwrap();
    w.stand_in.state().exec_output = b"ok\xff\n".to_vec();
    let mut output = Vec::new();
    let request = ExecRequest { command: vec!["echo".into(), "it's".into()] };
    exec.exec(&id, request.clone(), &w.credentials).await.unwrap().read_to_end(&mut output).await.unwrap();
    assert_eq!(output, b"ok\xff\n");
    w.stand_in.state().sandboxes.get_mut(&id).unwrap().envd_token = "rotated".into();
    exec.exec(&id, request.clone(), &w.credentials).await.unwrap();
    w.stand_in.state().exec_exit = 2;
    match exec.exec(&id, request, &w.credentials).await {
        Err(ProtocolError::CommandFailed { exit_code, output, .. }) => assert_eq!((exit_code, output.expose()), (2, "ok\u{fffd}\n")),
        Err(other) => panic!("{other:?}"),
        Ok(_) => panic!("a failed command succeeded"),
    }
}

// E2B's statuses map to protocol errors carrying its message: a missing or
// wrong key is CredentialRejected, 403 Refused, 404 NotFound, 429 RateLimited
// with Retry-After (QuotaExhausted when it is the concurrency limit), 5xx
// Unavailable.
#[tokio::test]
async fn vendor_errors_map_to_protocol_errors() {
    let w = world().await;
    let wrong = Credentials::new(Some(Secret::new("e2b_wrong")));
    assert!(matches!(w.provider.list(&wrong).await, Err(ProtocolError::CredentialRejected { .. })));
    assert!(matches!(w.provider.list(&Credentials::default()).await, Err(ProtocolError::CredentialRejected { .. })));
    type Expected = fn(&ProtocolError) -> bool;
    let cases: [(u16, &str, Option<u64>, Expected); 6] = [
        (401, "Invalid API key", None, |e| matches!(e, ProtocolError::CredentialRejected { .. })),
        (403, "Team is blocked", None, |e| matches!(e, ProtocolError::Refused { .. })),
        (404, "not found", None, |e| matches!(e, ProtocolError::NotFound { .. })),
        (429, "Rate limit exceeded", Some(17), |e| matches!(e, ProtocolError::RateLimited { retry_after: Some(17), .. })),
        (429, "You have reached the maximum number of concurrent E2B sandboxes (20)", None, |e| {
            matches!(e, ProtocolError::QuotaExhausted { .. })
        }),
        (503, "Service Unavailable", Some(5), |e| matches!(e, ProtocolError::Unavailable { retry_after: Some(5), .. })),
    ];
    for (status, message, retry_after, expected) in cases {
        w.stand_in.state().outage = Some((status, message.into(), retry_after));
        let error = w.provider.list(&w.credentials).await.unwrap_err();
        assert!(expected(&error), "{status}: {error:?}");
        assert!(format!("{error:?}").contains(message), "{error:?}");
    }
    w.stand_in.state().outage = Some((500, "internal".into(), None));
    assert!(matches!(w.provider.inspect("abc123", &w.credentials).await, Err(ProtocolError::Unavailable { .. })));
}

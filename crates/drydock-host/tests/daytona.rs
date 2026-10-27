//! Stand-in at the vendor HTTP boundary: validates requests and stores real
//! sandbox/snapshot state in memory. No live tokens or token-mint recordings.
use async_trait::async_trait;
use bytes::Bytes;
use drydock_host::{daytona::DaytonaModule, module::*};
use drydock_protocol::*;
use rigging_http_client::ChannelLabel;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::io::AsyncReadExt;

#[derive(Default)]
struct State {
    snapshots: BTreeMap<String, Value>,
    snapshot_requests: Vec<Value>,
    ssh_expiries: Vec<Option<String>>,
    rows: BTreeMap<String, Value>,
    creates: usize,
    bootstraps: usize,
    mints: usize,
    requests: usize,
    failure: Option<u16>,
    failure_message: Option<String>,
    /// A vendor outage applies to every caller until the test clears it.
    outage: Option<(u16, String)>,
    ssh_response: Option<Value>,
    exec_response: Option<Value>,
    probe_failure_message: Option<String>,
    executed: Vec<String>,
    probe: Option<Value>,
    violations: Vec<String>,
    fixture_rows: Vec<Value>,
    usage_periods: Option<Value>,
    accounting_delay_millis: Option<i64>,
    analytics_windows: Vec<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
    hide_label_once: bool,
    activations: usize,
    inactive_reads: usize,
    created_state: Option<String>,
    complete_transition_on_read: bool,
    lifecycle_posts: Vec<String>,
    command_exit: Option<i32>,
    command_output: Option<String>,
    require_bootstrap_budget: bool,
    probe_exit: Option<i32>,
    probe_http_failure: Option<u16>,
    exec_timeouts: Vec<u64>,
    oci: Registries,
}
/// In-memory OCI registries behind the distribution protocol: a private lab
/// registry Daytona cannot reach, a public tools registry, and Daytona's
/// transient push registry (Harbor). (The stand-in's client follows redirects
/// itself, so blob redirects are covered in the oci module's tests.)
#[derive(Default)]
struct Registries {
    /// Blobs by (registry host, digest); repositories share storage.
    blobs: BTreeMap<(String, String), Bytes>,
    /// Manifests by (host, repository, tag or digest): media type and content.
    manifests: BTreeMap<(String, String, String), (String, Bytes)>,
    uploads: BTreeMap<String, (String, Vec<u8>)>,
    /// Harbor serves a pushed manifest only after this many further reads.
    pending_reads: BTreeMap<String, usize>,
    /// Lifetime of minted push access; Daytona documents 3600 s.
    push_lifetime: Option<chrono::TimeDelta>,
    /// Robot accounts and bearer tokens with their expiry.
    robots: BTreeMap<String, (String, chrono::DateTime<chrono::Utc>)>,
    tokens: BTreeMap<String, (String, chrono::DateTime<chrono::Utc>)>,
    mints: usize,
    patch_sizes: Vec<usize>,
    /// Source registries answer ranged reads with the whole blob.
    ignore_range: bool,
}
const LAB: &str = "lab.invalid";
const TOOLS: &str = "registry.invalid";
const HARBOR: &str = "harbor.invalid";
const VISIBILITY_DELAY_READS: usize = 2;
#[derive(Default)]
struct StandIn(Arc<Mutex<State>>, tokio::sync::OnceCell<rigging_replay_testkit::http_contract::StandIn>);
impl StandIn {
    async fn network(&self) -> &rigging_replay_testkit::http_contract::StandIn {
        self.1
            .get_or_init(|| async {
                rigging_tls::install_default_provider();
                let router = |origin: &'static str| {
                    let state = self.0.clone();
                    axum::Router::new().fallback(axum::routing::any(move |r: axum::extract::Request| {
                        let state = state.clone();
                        async move {
                            let (parts, body) = r.into_parts();
                            let bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
                                Ok(bytes) => bytes,
                                Err(_) => return http::Response::builder().status(400).body(axum::body::Body::empty()).unwrap(),
                            };
                            // Adapt the received wire request to the contract validator;
                            // serialization and header/query encoding happened on TCP.
                            let mut request = reqwest::Request::new(parts.method, format!("{origin}{}", parts.uri).parse().unwrap());
                            *request.headers_mut() = parts.headers;
                            *request.body_mut() = Some(bytes.to_vec().into());
                            let response = Self::respond(&state, request);
                            let (parts, body) = response.into_parts();
                            if let Ok(value) = serde_json::from_slice::<Value>(&body) {
                                let rows = value.get("items").and_then(Value::as_array).cloned().unwrap_or_else(|| vec![value]);
                                state
                                    .lock()
                                    .unwrap()
                                    .fixture_rows
                                    .extend(rows.into_iter().filter(|r| r.get("cpu").is_some() && r.get("mem").is_none()));
                            }
                            http::Response::from_parts(parts, axum::body::Body::from(body))
                        }
                    }))
                };
                rigging_replay_testkit::http_contract::StandIn::start_many([
                    ("https://app.daytona.io", router("https://app.daytona.io")),
                    ("https://runner.invalid", router("https://runner.invalid")),
                    ("https://analytics.app.daytona.io", router("https://analytics.app.daytona.io")),
                    ("https://lab.invalid", router("https://lab.invalid")),
                    ("https://registry.invalid", router("https://registry.invalid")),
                    ("https://harbor.invalid", router("https://harbor.invalid")),
                ])
                .await
            })
            .await
    }
    fn respond(state: &Mutex<State>, request: reqwest::Request) -> http::Response<Bytes> {
        let mut s = state.lock().unwrap();
        s.requests += 1;
        if request.url().host_str().is_some_and(|host| [LAB, TOOLS, HARBOR].contains(&host)) {
            return registry_response(&mut s, &request);
        }
        // Daytona requires bearer auth for both API and toolbox requests.
        let authorized = matches!(
            request.headers().get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer key-a" | "Bearer key-b" | "Bearer placeholder")
        );
        let response = |status, mut body: Value| {
            if status == 200 && request.url().host_str() == Some("analytics.app.daytona.io") {
                let schema = if request.url().path().ends_with("/aggregated") {
                    "models.AggregatedUsage"
                } else if request.url().path().ends_with("/usage/sandbox") {
                    "models.SandboxUsage"
                } else {
                    "models.UsagePeriod"
                };
                validate_analytics_fixture(&body, schema);
            }
            // Current snapshot routes all return SnapshotDto on success; list/delete
            // routes must choose their own response schema when added here.
            if (200..300).contains(&status) && request.url().path().starts_with("/api/snapshots") {
                assert!(snapshot_schema_valid(&body, "SnapshotDto", false), "invalid snapshot fixture: {body}");
            }
            // Schema-valid vendor fixtures, independent of the module request.
            if let Some(rows) = body.get_mut("items").and_then(Value::as_array_mut) {
                for row in rows {
                    *row = schema_row(row.clone());
                }
            } else if body.get("cpu").is_some() && body.get("mem").is_none() {
                body = schema_row(body);
            }

            let mut response = http::Response::builder()
                .status(status)
                .header("x-ratelimit-limit-authenticated", "10000")
                .header("x-ratelimit-remaining-authenticated", if status == 429 { "0" } else { "9999" });
            if status == 429 {
                response = response.header("retry-after-sandbox-create", "17");
            }
            response.body(Bytes::from(body.to_string())).unwrap()
        };
        if !authorized {
            return response(401, json!({"statusCode":401,"message":"Unauthorized","error":"Unauthorized"}));
        }
        if let Some((status, message)) = &s.outage {
            return response(*status, json!({"statusCode":status,"message":message,"error":"Bad Request"}));
        }
        if let Some(status) = s.failure.take() {
            let message = s.failure_message.take().unwrap_or_else(|| "key-a must never be echoed".into());
            return response(status, json!({"statusCode":status,"message":message,"error":"Too Many Requests"}));
        }
        let method = request.method().as_str();
        let path = request.url().path();
        macro_rules! reject {
            ($message:expr) => {{
                s.violations.push($message.to_string());
                return response(400, json!({"statusCode":400,"message":$message,"error":"Bad Request"}));
            }};
        }
        let origin = request.url().origin().ascii_serialization();
        let permitted = match origin.as_str() {
            "https://app.daytona.io" => path.starts_with("/api/"),
            "https://runner.invalid" => path.starts_with("/toolbox/"),
            "https://analytics.app.daytona.io" => path.starts_with("/organization/"),
            _ => false,
        };
        if !permitted {
            reject!(format!("wrong origin for {path}: {origin}"));
        }
        if origin == "https://analytics.app.daytona.io" {
            let query: BTreeMap<_, _> = request.url().query_pairs().collect();
            let parse =
                |key| query.get(key).and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok()).map(|v| v.with_timezone(&chrono::Utc));
            let (Some(from), Some(to)) = (parse("from"), parse("to")) else {
                reject!("analytics time range must be RFC3339");
            };
            if from >= to {
                reject!("analytics time range must be ordered");
            }
            s.analytics_windows.push((from, to));
            if s.accounting_delay_millis.is_some_and(|delay| (chrono::Utc::now() - to).num_milliseconds() < delay) {
                return response(503, json!({"message":"usage not settled"}));
            }
        }
        let body = request.body().and_then(|b| b.as_bytes()).filter(|b| !b.is_empty()).map(serde_json::from_slice::<Value>).transpose();
        let body = match body {
            Ok(value) => value.unwrap_or(Value::Null),
            Err(_) => reject!("invalid JSON"),
        };
        if method == "POST" && request.headers().get("content-type").is_some() == body.is_null() {
            reject!("content-type does not match body");
        }
        match (method, path) {
            ("GET", p) if p.starts_with("/api/snapshots/") => {
                let key = p.trim_start_matches("/api/snapshots/");
                if s.activations > 0 {
                    s.inactive_reads += 1;
                    if s.inactive_reads >= 2 {
                        for v in s.snapshots.values_mut() {
                            if v["state"] == "inactive" {
                                v["state"] = json!("active");
                            }
                        }
                    }
                }
                let row = s.snapshots.get(key).or_else(|| s.snapshots.values().find(|v| v["id"].as_str() == Some(key)));
                response(if row.is_some() { 200 } else { 404 }, row.cloned().unwrap_or(Value::Null))
            }
            ("POST", p) if p.ends_with("/activate") => {
                let id = p.strip_prefix("/api/snapshots/").and_then(|p| p.strip_suffix("/activate"));
                let snapshot = id.and_then(|id| s.snapshots.values().find(|v| v["id"].as_str() == Some(id))).cloned();
                let Some(snapshot) = snapshot else {
                    return response(404, json!({"statusCode":404,"message":"Snapshot not found"}));
                };
                s.activations += 1;
                // Activation is asynchronous; a successful POST may still say inactive.
                response(200, snapshot)
            }
            ("GET", "/api/docker-registry/registry-push-access") => {
                if !request.url().query_pairs().any(|(k, v)| k == "regionId" && v == "eu") {
                    reject!("push access must name the region");
                }
                s.oci.mints += 1;
                let username = format!("robot$push-{}", s.oci.mints);
                let secret = format!("push-secret-{}", s.oci.mints);
                let expires = chrono::Utc::now() + s.oci.push_lifetime.unwrap_or(chrono::TimeDelta::seconds(3600));
                s.oci.robots.insert(username.clone(), (secret.clone(), expires));
                response(200, json!({"username":username,"secret":secret,"registryUrl":HARBOR,"registryId":"registry-1","project":"daytona-transient","expiresAt":expires.to_rfc3339()}))
            }
            ("POST", "/api/snapshots") => {
                if !snapshot_schema_valid(&body, "CreateSnapshot", true) {
                    reject!("invalid CreateSnapshot body");
                }
                if let Some(image) = body.get("imageName").and_then(Value::as_str) {
                    if body.get("buildInfo").is_some() {
                        reject!("a snapshot takes an image or a build, not both");
                    }
                    if let Err(problem) = pushed_image_ready(&s.oci, image) {
                        reject!(problem);
                    }
                }
                // CreateSnapshot validation above guarantees a required string name.
                let name = body["name"].as_str().unwrap();
                s.snapshot_requests.push(body.clone());
                if s.snapshots.contains_key(name) {
                    return response(409, json!({"statusCode":409}));
                }
                let snapshot = json!({"id":format!("snap-{}",s.snapshots.len()+1),"name":name,"state":"active","cpu":body.get("cpu").unwrap_or(&json!(1)),"mem":body.get("memory").unwrap_or(&json!(1)),"disk":body.get("disk").unwrap_or(&json!(3)),"gpu":0,"general":false,"size":null,"entrypoint":null,"errorReason":null,"createdAt":"2026-10-21T00:00:00Z","updatedAt":"2026-10-21T00:00:00Z","lastUsedAt":null,"sourceSandboxId":null});
                s.snapshots.insert(name.into(), snapshot.clone());
                response(201, snapshot)
            }
            ("GET", "/api/sandbox") => {
                if s.hide_label_once {
                    s.hide_label_once = false;
                    return response(200, json!({"items":[],"nextCursor":null}));
                }
                let labels =
                    request.url().query_pairs().find(|(k, _)| k == "labels").map(|(_, v)| serde_json::from_str::<Value>(&v)).transpose();
                let labels = match labels { Ok(v) => v, Err(_) => reject!("invalid labels JSON") };
                let mut rows: Vec<_> = s
                    .rows
                    .values()
                    .filter(|v| labels.as_ref().is_none_or(|labels| labels["flotilla.label"] == v["labels"]["flotilla.label"]))
                    .cloned()
                    .collect();
                // Force pagination to prove list never reports a partial inventory.
                let cursor = request.url().query_pairs().find(|(k, _)| k == "cursor").map(|(_, v)| v.into_owned());
                if cursor.is_some() {
                    rows.remove(0);
                }
                let next = if cursor.is_none() && rows.len() > 1 {
                    rows.truncate(1);
                    Some("page-two")
                } else {
                    None
                };
                response(200, json!({"items":rows,"nextCursor":next}))
            }
            ("POST", "/api/sandbox") => {
                let mut body = body;
                if !body["snapshot"].is_null() && ["cpu", "memory", "disk"].iter().any(|k| body.get(*k).is_some()) {
                    return response(400, json!({"statusCode":400,"message":"Cannot specify Sandbox resources when using a snapshot","error":"Bad Request"}));
                }

                // CreateSandbox has no required fields. Validate documented
                // mutual exclusion and IPv4 CIDR syntax, not our caller's choices.
                if ["networkAllowList", "domainAllowList", "networkBlockAll"].iter().filter(|k| !body[**k].is_null()).count() > 1 {
                    return response(400, json!({"statusCode":400,"message":"network rules are mutually exclusive","error":"Bad Request"}));
                }
                if let Some(list) = body["networkAllowList"].as_str() {
                    for cidr in list.split(',') {
                        let valid = cidr.split_once('/').is_some_and(|(ip, bits)| {
                            ip.parse::<std::net::Ipv4Addr>().is_ok() && bits.parse::<u8>().is_ok_and(|n| n <= 32)
                        });
                        if !valid {
                            return response(400, json!({"statusCode":400,"message":"invalid CIDR","error":"Bad Request"}));
                        }
                    }
                }
                if let Some(snapshot) = body["snapshot"].as_str().and_then(|name| s.snapshots.get(name)) {
                    let snapshot = snapshot.clone();
                    for key in ["cpu", "memory", "disk"] {
                        body[key] = snapshot[if key == "memory" { "mem" } else { key }].clone();
                    }
                }
                let defaults = json!({"name":format!("auto-{}",s.creates+1),"labels":{},"cpu":1,"memory":1,"disk":3});
                for (key, value) in defaults.as_object().unwrap() {
                    if body[key].is_null() {
                        body[key] = value.clone();
                    }
                }
                if s.rows.values().any(|v| v["name"] == body["name"]) {
                    return response(409, json!({"statusCode":409,"message":"name already exists"}));
                }
                s.creates += 1;
                let id = format!("sandbox-{}", s.creates);
                let row = json!({"id":id,"name":body["name"],"labels":body["labels"],"state":s.created_state.clone().unwrap_or_else(||"started".into()),"cpu":body["cpu"],"memory":body["memory"],"disk":body["disk"],"networkAllowList":body["networkAllowList"],"networkBlockAll":body["networkBlockAll"].as_bool().unwrap_or(false),"domainAllowList":body["domainAllowList"],"organizationId":"org-1","target":"eu","user":"daytona","public":false,"gpu":0,"env":{},"kvm":false,"toolboxProxyUrl":"https://runner.invalid/toolbox","updatedAt":"2026-10-19T12:00:00Z"});
                s.rows.insert(id, row.clone());
                response(201, row)
            }
            ("GET", p) if p.starts_with("/api/sandbox/") => {
                let id = p.trim_start_matches("/api/sandbox/");
                let row = s.rows.get(id).or_else(|| s.rows.values().find(|v| v["name"].as_str() == Some(id))).cloned();
                if s.complete_transition_on_read
                    && let Some(row) = &row
                {
                    let next = match row["state"].as_str() {
                        Some("starting") => Some("started"),
                        Some("stopping") => Some("stopped"),
                        _ => None,
                    };
                    if let Some(next) = next {
                        let Some(key) = row["id"].as_str() else { reject!("fixture missing id"); };
                        if let Some(row) = s.rows.get_mut(key) { row["state"] = json!(next); }
                        s.complete_transition_on_read = false;
                    }
                }
                response(if row.is_some() { 200 } else { 404 }, row.unwrap_or(Value::Null))
            }
            ("DELETE", p) if p.starts_with("/api/sandbox/") => {
                let row = s.rows.remove(p.trim_start_matches("/api/sandbox/"));
                response(if row.is_some() { 200 } else { 404 }, row.unwrap_or(Value::Null))
            }
            ("POST", p) if p.ends_with("/ssh-access") => {
                s.ssh_expiries.push(request.url().query_pairs().find(|(k,_)|k=="expiresInMinutes").map(|(_,v)|v.into_owned()));
                s.mints += 1;
                response(200, s.ssh_response.clone().unwrap_or_else(|| json!({"token":format!("ephemeral-{}",s.mints),"expiresAt":"2026-10-19T12:05:00Z"})))
            }
            ("POST", p) if p.ends_with("/stop") || p.ends_with("/start") => {
                s.lifecycle_posts.push(p.into());
                let id = p.trim_start_matches("/api/sandbox/").split('/').next().unwrap();
                let Some(row) = s.rows.get_mut(id) else { return response(404,json!({"statusCode":404,"message":"Not Found","error":"Not Found"})); };
                row["state"] = json!(if p.ends_with("/stop") { "stopped" } else { "started" });
                response(200, row.clone())
            }
            ("POST", p) if p.starts_with("/toolbox/") && p.ends_with("/process/execute") => {
                let Some(command) = body["command"].as_str() else { reject!("missing command"); };
                let Some(timeout) = body["timeout"].as_u64() else { reject!("missing timeout"); };
                s.exec_timeouts.push(timeout);
                if command.starts_with("test \"$(id -u)\"") && let Some(status) = s.probe_http_failure {
                    return response(status, json!({"statusCode":status,"message":s.probe_failure_message.as_deref().unwrap_or("Bad Gateway"),"error":"Bad Gateway"}));
                }
                if let Some(value) = &s.exec_response { return response(200, value.clone()); }
                if s.require_bootstrap_budget && command.contains("--supervise") && timeout < 20 {
                    return response(200, json!({"exitCode":124,"result":"bootstrap exceeded vendor deadline"}));
                }
                if command.contains("--supervise") {
                    s.bootstraps += 1;
                    if !command.contains("--socket /run/drydock/agent.sock") { reject!("bootstrap missing socket flag"); }
                }
                s.executed.push(command.into());
                let output = if command.starts_with("test \"$(id -u)\"") {
                    s.probe.clone().unwrap_or(Value::Null).to_string()
                } else {
                    s.command_output.clone().unwrap_or_else(|| "guest output".into())
                };
                let code = if command.starts_with("test \"$(id -u)\"") { s.probe_exit.unwrap_or(0) } else { s.command_exit.unwrap_or(0) };
                response(200, json!({"exitCode":code,"result":output}))
            }
            ("GET", "/api/organizations/org-1/usage") => response(
                200,
                json!({"regionUsage":[{"regionId":"eu","sandboxClass":"container","currentCpuUsage":2,"totalCpuQuota":10,"currentMemoryUsage":4,"totalMemoryQuota":20,"currentDiskUsage":10,"totalDiskQuota":30}],"currentSnapshotUsage":1,"totalSnapshotQuota":100,"currentVolumeUsage":0,"totalVolumeQuota":100}),
            ),
            ("GET", "/organization/org-1/usage/aggregated") => {
                if !request.url().query_pairs().any(|(k, _)| k == "from") || !request.url().query_pairs().any(|(k, _)| k == "to") { reject!("missing analytics time range"); }
                let usage = json!({"totalCPUSeconds":7200,"totalRAMGBSeconds":14400,"totalDiskGBSeconds":36000,"totalGPUSeconds":0,"totalPrice":0.0123,"sandboxCount":1});
                response(200, usage)
            }
            ("GET", "/organization/org-1/usage/sandbox") => response(200,json!([{"sandboxId":"sandbox-1"}])),
            ("GET", "/organization/org-1/sandbox/sandbox-1/usage") => response(200,s.usage_periods.clone().unwrap_or_else(|| if s.accounting_delay_millis.is_some() {
                if let Some(row) = s.rows.values().find(|row| row["state"] == "started") {
                    json!([{"cpu":row["cpu"],"ramGB":row["memory"],"diskGB":row["disk"],"startAt":"2020-01-01T00:00:00Z"}])
                } else { json!([]) }
            } else { json!([
                {"cpu":2,"ramGB":4,"diskGB":10,"gpu":0,"price":0.0123,"startAt":"2026-10-19T00:00:00Z","endAt":"2026-10-19T01:00:00Z"}
            ]) })),
            _ => reject!(format!("unexpected vendor request: {method} {path}")),
        }
    }
}
impl Drop for StandIn {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let state = self.0.lock().unwrap();
            assert!(state.violations.is_empty(), "vendor contract violations: {:?}", state.violations);
            for body in &state.snapshot_requests {
                if let Some(image) = body.get("imageName") {
                    // Daytona accepts digest references; never a tag or untagged name.
                    assert!(image.as_str().unwrap().starts_with("harbor.invalid/daytona-transient/drydock-vessel@sha256:"));
                    assert!(body.get("buildInfo").is_none() && body.get("entrypoint").is_none());
                    assert_eq!(body["regionId"], "eu");
                    continue;
                }
                let dockerfile = body["buildInfo"]["dockerfileContent"].as_str().expect("prepare must build the tools layer");
                let instructions: Vec<_> = dockerfile.lines().collect();
                assert_eq!(instructions.len(), 3, "only FROM and COPY preserve the base entrypoint and command");
                assert!(instructions[0].starts_with("FROM --platform=linux/amd64 registry.invalid/drydock-tools@sha256:"));
                assert!(instructions[1].starts_with("FROM --platform=linux/amd64 ") && instructions[1].contains("@sha256:"));
                assert_eq!(instructions[2], "COPY --from=drydock_tools /opt/drydock/ /opt/drydock/");
                assert!(body.get("entrypoint").is_none());
                assert!(body.get("imageName").is_none());
                assert_eq!(body["sandboxClass"], "container");
                assert_eq!(body["regionId"], "eu");
            }
            assert!(state.ssh_expiries.iter().all(|v| v.as_deref() == Some("5")), "reach must request a short expiry");
            assert!(state.executed.iter().filter(|c| c.contains("--supervise")).all(|c| c.contains("--socket /run/drydock/agent.sock")));
            let spec: Value = serde_json::from_str(include_str!("fixtures/daytona-schemas.json")).unwrap();
            for row in &state.fixture_rows {
                for key in spec["schemas"]["Sandbox"]["required"].as_array().unwrap() {
                    assert!(!row[key.as_str().unwrap()].is_null(), "invalid vendor fixture missing {key}");
                }
            }
        }
    }
}
/// Daytona refuses `:latest` and untagged names, and its builder can pull only
/// what its registry already serves; the image must also be amd64.
fn pushed_image_ready(oci: &Registries, image: &str) -> std::result::Result<(), String> {
    let (name, digest) = image.split_once('@').ok_or("snapshot image must be pinned by digest")?;
    let (host, repository) = name.split_once('/').ok_or("snapshot image has no registry")?;
    if name.rsplit('/').next().is_some_and(|last| last.contains(':')) {
        return Err("snapshot image names a tag beside its digest".into());
    }
    if host != HARBOR || oci.pending_reads.contains_key(digest) {
        return Err(format!("snapshot image {image} is not visible to Daytona's builder"));
    }
    let (_, manifest) =
        oci.manifests.get(&(host.into(), repository.into(), digest.into())).ok_or("snapshot image is not in the registry")?;
    let manifest: Value = serde_json::from_slice(manifest).unwrap();
    let config = &oci.blobs[&(HARBOR.to_owned(), manifest["config"]["digest"].as_str().unwrap().to_owned())];
    let config: Value = serde_json::from_slice(config).unwrap();
    if config["architecture"] != "amd64" {
        return Err("Daytona runs only amd64 images".into());
    }
    Ok(())
}
/// The OCI distribution protocol with bearer-token challenges. Lab pulls need
/// lab credentials; Harbor accepts only unexpired robots; the public registry
/// must never see a credential; Range reads and chunked uploads are honoured.
fn registry_response(s: &mut State, request: &reqwest::Request) -> http::Response<Bytes> {
    let host = request.url().host_str().unwrap().to_owned();
    let now = chrono::Utc::now();
    let reply = |status: u16, headers: &[(&str, String)], body: Bytes| {
        let mut response = http::Response::builder().status(status);
        for (name, value) in headers {
            response = response.header(*name, value);
        }
        response.body(body).unwrap()
    };
    let authorization = request.headers().get("authorization").and_then(|v| v.to_str().ok()).map(str::to_owned);
    let basic = |user: &str, secret: &str| {
        use base64::Engine;
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{secret}")))
    };
    let path = request.url().path().to_owned();
    let ignore_range = s.oci.ignore_range && host != HARBOR;
    let range = |bytes: &Bytes| -> http::Response<Bytes> {
        match request.headers().get("range").and_then(|v| v.to_str().ok()).and_then(|r| r.strip_prefix("bytes=")).filter(|_| !ignore_range)
        {
            None => reply(200, &[], bytes.clone()),
            Some(r) => {
                let (start, end) = r.split_once('-').unwrap();
                let (start, end): (usize, usize) = (start.parse().unwrap(), end.parse().unwrap());
                let end = end.min(bytes.len() - 1);
                reply(206, &[("content-range", format!("bytes {start}-{end}/{}", bytes.len()))], bytes.slice(start..=end))
            }
        }
    };
    if path == "/token" || path == "/service/token" {
        let permitted = match host.as_str() {
            LAB => authorization.as_deref() == Some(&basic("lab-user", "lab-secret")),
            HARBOR => s
                .oci
                .robots
                .iter()
                .any(|(user, (secret, expires))| authorization.as_deref() == Some(&basic(user, secret)) && now < *expires),
            _ => {
                if authorization.is_some() {
                    s.violations.push(format!("credential sent to the public registry {host}"));
                }
                true
            }
        };
        if !permitted {
            return reply(401, &[], Bytes::new());
        }
        let expires = match host.as_str() {
            HARBOR => s.oci.robots.values().map(|(_, e)| *e).max().unwrap(),
            _ => now + chrono::TimeDelta::seconds(300),
        };
        let token = format!("token-{}", s.oci.tokens.len() + 1);
        s.oci.tokens.insert(token.clone(), (host.clone(), expires));
        return reply(200, &[], Bytes::from(json!({"token": token}).to_string()));
    }
    let authorized = authorization
        .as_deref()
        .and_then(|a| a.strip_prefix("Bearer "))
        .and_then(|t| s.oci.tokens.get(t))
        .is_some_and(|(h, expires)| *h == host && now < *expires);
    if !authorized {
        let realm = if host == HARBOR { "service/token" } else { "token" };
        return reply(401, &[("www-authenticate", format!(r#"Bearer realm="https://{host}/{realm}",service="{host}""#))], Bytes::new());
    }
    let rest = path.strip_prefix("/v2/").unwrap_or_default();
    let method = request.method().as_str();
    let body = request.body().and_then(|b| b.as_bytes()).map(Bytes::copy_from_slice).unwrap_or_default();
    if let Some((repository, reference)) = rest.rsplit_once("/manifests/") {
        let key = (host.clone(), repository.to_owned(), reference.to_owned());
        if method == "PUT" {
            let digest = drydock_host::oci::sha256(&body);
            let manifest: Value = serde_json::from_slice(&body).unwrap();
            let referenced = std::iter::once(&manifest["config"]).chain(manifest["layers"].as_array().unwrap());
            if host != HARBOR
                || referenced.into_iter().any(|d| !s.oci.blobs.contains_key(&(host.clone(), d["digest"].as_str().unwrap().into())))
            {
                s.violations.push("manifest pushed before its blobs".into());
                return reply(400, &[], Bytes::new());
            }
            let media_type = request.headers().get("content-type").unwrap().to_str().unwrap().to_owned();
            for reference in [reference.to_owned(), digest.clone()] {
                s.oci.manifests.insert((host.clone(), repository.into(), reference), (media_type.clone(), body.clone()));
            }
            s.oci.pending_reads.insert(digest.clone(), VISIBILITY_DELAY_READS);
            return reply(201, &[("docker-content-digest", digest)], Bytes::new());
        }
        if let Some(pending) = s.oci.pending_reads.get_mut(reference) {
            *pending -= 1;
            if *pending == 0 {
                s.oci.pending_reads.remove(reference);
            }
            return reply(404, &[], Bytes::new());
        }
        return match s.oci.manifests.get(&key) {
            Some((media_type, bytes)) => {
                let digest = drydock_host::oci::sha256(bytes);
                reply(
                    200,
                    &[("content-type", media_type.clone()), ("docker-content-digest", digest)],
                    if method == "HEAD" { Bytes::new() } else { bytes.clone() },
                )
            }
            None => reply(404, &[], Bytes::new()),
        };
    }
    if let Some((_, tail)) = rest.split_once("/blobs/uploads/") {
        if host != HARBOR {
            s.violations.push(format!("upload attempted at {host}"));
            return reply(405, &[], Bytes::new());
        }
        let location = |id: &str| format!("/v2/{}/blobs/uploads/{id}", rest.split_once("/blobs/uploads/").unwrap().0);
        if method == "POST" {
            let id = format!("upload-{}", s.oci.uploads.len() + 1);
            s.oci.uploads.insert(id.clone(), (host.clone(), vec![]));
            return reply(202, &[("location", location(&id))], Bytes::new());
        }
        let Some((_, data)) = s.oci.uploads.get_mut(tail) else { return reply(404, &[], Bytes::new()) };
        if method == "PATCH" {
            let expected = format!("{}-{}", data.len(), data.len() + body.len() - 1);
            if request.headers().get("content-range").and_then(|v| v.to_str().ok()) != Some(&expected) {
                s.violations.push(format!("chunk out of order; expected {expected}"));
                return reply(416, &[], Bytes::new());
            }
            data.extend_from_slice(&body);
            let len = data.len();
            s.oci.patch_sizes.push(body.len());
            return reply(202, &[("location", location(tail)), ("range", format!("0-{}", len - 1))], Bytes::new());
        }
        data.extend_from_slice(&body);
        let data = Bytes::from(data.clone());
        let digest = request.url().query_pairs().find(|(k, _)| k == "digest").map(|(_, v)| v.into_owned()).unwrap_or_default();
        if drydock_host::oci::sha256(&data) != digest {
            s.violations.push("upload committed under the wrong digest".into());
            return reply(400, &[], Bytes::new());
        }
        s.oci.uploads.remove(tail);
        s.oci.blobs.insert((host.clone(), digest.clone()), data);
        return reply(201, &[("docker-content-digest", digest)], Bytes::new());
    }
    if let Some((_, digest)) = rest.rsplit_once("/blobs/") {
        let Some(bytes) = s.oci.blobs.get(&(host.clone(), digest.to_owned())).cloned() else { return reply(404, &[], Bytes::new()) };
        return match (method, host.as_str()) {
            ("HEAD", _) => reply(200, &[("content-length", bytes.len().to_string())], Bytes::new()),
            ("GET", _) => range(&bytes),
            _ => reply(405, &[], Bytes::new()),
        };
    }
    s.violations.push(format!("unexpected registry request {method} {path}"));
    reply(400, &[], Bytes::new())
}
/// Layers of `size` bytes, with distinct content per (image, platform, index).
struct Seed<'a> {
    host: &'a str,
    repository: &'a str,
    manifest_type: &'a str,
    layer_type: &'a str,
    platforms: &'a [&'a str],
    layers: usize,
    /// A descriptor size that overstates the stored layer, to model huge images.
    declared_layer_size: Option<u64>,
}
/// Stores an image index over one image per platform and returns its
/// digest reference, plus each platform's manifest.
fn seed(s: &mut State, seed: Seed) -> (String, BTreeMap<String, Value>) {
    let mut entries = vec![];
    let mut manifests = BTreeMap::new();
    for arch in seed.platforms {
        let layers: Vec<Bytes> =
            (0..seed.layers).map(|i| Bytes::from(format!("{}:{}:{arch}:{i}:layer-bytes", seed.host, seed.repository))).collect();
        let config = json!({"os":"linux","architecture":arch,"config":{"Entrypoint":["/base-entry"]},"rootfs":{"type":"layers","diff_ids":layers.iter().map(|l| drydock_host::oci::sha256(&[l.as_ref(), b"tar"].concat())).collect::<Vec<_>>()}});
        let config = Bytes::from(config.to_string());
        let config_type = if seed.manifest_type.contains("docker") {
            "application/vnd.docker.container.image.v1+json"
        } else {
            "application/vnd.oci.image.config.v1+json"
        };
        let descriptor = |media_type: &str, bytes: &Bytes, size: Option<u64>| json!({"mediaType":media_type,"digest":drydock_host::oci::sha256(bytes),"size":size.unwrap_or(bytes.len() as u64)});
        let manifest = json!({"schemaVersion":2,"mediaType":seed.manifest_type,"config":descriptor(config_type,&config,None),
            "layers":layers.iter().map(|l| descriptor(seed.layer_type, l, seed.declared_layer_size)).collect::<Vec<_>>()});
        for blob in layers.iter().chain([&config]) {
            s.oci.blobs.insert((seed.host.into(), drydock_host::oci::sha256(blob)), blob.clone());
        }
        let bytes = Bytes::from(manifest.to_string());
        let digest = drydock_host::oci::sha256(&bytes);
        s.oci.manifests.insert((seed.host.into(), seed.repository.into(), digest.clone()), (seed.manifest_type.into(), bytes.clone()));
        entries
            .push(json!({"mediaType":seed.manifest_type,"digest":digest,"size":bytes.len(),"platform":{"os":"linux","architecture":arch}}));
        manifests.insert(arch.to_string(), manifest);
    }
    let index_type = if seed.manifest_type.contains("docker") {
        "application/vnd.docker.distribution.manifest.list.v2+json"
    } else {
        "application/vnd.oci.image.index.v1+json"
    };
    let index = Bytes::from(json!({"schemaVersion":2,"mediaType":index_type,"manifests":entries}).to_string());
    let digest = drydock_host::oci::sha256(&index);
    s.oci.manifests.insert((seed.host.into(), seed.repository.into(), digest.clone()), (index_type.into(), index));
    (format!("{}/{}@{digest}", seed.host, seed.repository), manifests)
}
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const DOCKER_LAYER: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_LAYER: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
fn lab_base(platforms: &'static [&'static str]) -> Seed<'static> {
    Seed {
        host: LAB,
        repository: "crew/base",
        manifest_type: DOCKER_MANIFEST,
        layer_type: DOCKER_LAYER,
        platforms,
        layers: 3,
        declared_layer_size: None,
    }
}
fn published_tools() -> Seed<'static> {
    Seed {
        host: TOOLS,
        repository: "drydock-tools",
        manifest_type: OCI_MANIFEST,
        layer_type: OCI_LAYER,
        platforms: &["amd64", "arm64"],
        layers: 1,
        declared_layer_size: None,
    }
}
fn lab_pull() -> Option<RegistryCredential> {
    Some(RegistryCredential { username: "lab-user".into(), secret: Secret::new("lab-secret") })
}
#[async_trait]
impl HttpClient for StandIn {
    async fn execute(&self, request: reqwest::Request, label: &ChannelLabel) -> std::result::Result<http::Response<Bytes>, String> {
        self.network().await.http.execute(request, label).await
    }
}

fn schema_row(mut row: Value) -> Value {
    let defaults = json!({"name":"fixture","labels":{},"cpu":1,"memory":1,"disk":3,"gpu":0,"organizationId":"org-1","target":"eu","user":"daytona","public":false,"env":{},"kvm":false,"networkBlockAll":false,"toolboxProxyUrl":"https://runner.invalid/toolbox"});
    for (key, value) in defaults.as_object().unwrap() {
        if row[key].is_null() {
            row[key] = value.clone();
        }
    }
    row
}

fn credentials(proxied: bool) -> Credentials {
    if proxied {
        Credentials::new(CredentialMode::Proxied { proxy_url: "http://proxy".into(), placeholder_token: Secret::new("placeholder") })
    } else {
        Credentials { mode: CredentialMode::Direct { credential_reference: "test".into() }, value: Some(Secret::new("key-a")) }
    }
}
async fn provider(http: Arc<dyn HttpClient>) -> Arc<dyn Provider> {
    provider_with_probe(http, false).await
}
async fn provider_with_probe(http: Arc<dyn HttpClient>, probe: bool) -> Arc<dyn Provider> {
    let config:ProviderConfiguration = serde_json::from_value(json!({"name":"daytona","module":"daytona","settings":{"organization_id":"org-1","ssh_host_key":"ssh-ed25519 AAAA"},"credential":{"mode":"direct","credential_reference":"test"}})).unwrap();
    let mut config = config;
    if probe {
        config.settings.insert("egress_probe".into(), json!({"command":["/usr/local/bin/check-egress"]}));
    }
    DaytonaModule.configure(&config, http).await.unwrap()
}
fn tools_image(digit: char) -> String {
    format!("registry.invalid/drydock-tools@sha256:{}", digit.to_string().repeat(64))
}
fn daytona_size() -> Size {
    Size { cpus: 2.0, memory_bytes: 4 << 30, disk_bytes: 10 << 30 }
}
async fn prepared(p: &dyn Provider, c: &Credentials) -> Prepared {
    let request = PrepareRequest {
        platform: Some(Platform::new("linux", "amd64")),
        route: Some(ImageRouteKind::RegistryPull),
        image_pull: None,
        size: daytona_size(),
        image_digest: format!("docker.io/test/image@sha256:{}", "a".repeat(64)),
        tools_digest: tools_image('a'),
    };
    let first = p.prepare(request.clone(), c).await.unwrap();
    assert_eq!(p.prepare(request, c).await.unwrap(), first);
    first
}
fn request(prepared: Prepared, label: &str) -> ProvisionRequest {
    ProvisionRequest { label: label.into(), prepared, size: daytona_size(), egress: EgressRequest::default(), ssh_public_key: None }
}
fn row(p: Provisioned) -> Environment {
    match p {
        Provisioned::Created(e) | Provisioned::Existing(e) => e.environment,
    }
}

// A label creates one resource even under concurrent retries. Inventory re-adopts
// it after factory reconstruction, and resume restarts the agent (not memory).
#[tokio::test]
async fn lifecycle_and_credential_modes() {
    for proxied in [false, true] {
        let http = Arc::new(StandIn::default());
        let p = provider(http.clone()).await;
        let mut c = credentials(proxied);
        let prep = prepared(p.as_ref(), &c).await;
        let r = request(prep, "label-a");
        let (a, b) = tokio::join!(p.provision(r.clone(), &c), p.provision(r.clone(), &c));
        let a = a.unwrap();
        let (Provisioned::Created(observation) | Provisioned::Existing(observation)) = &a;
        assert!(!observation.egress_measured, "no probe means no measured evidence");
        let b = b.unwrap();
        assert!(matches!(
            (&a, &b),
            (Provisioned::Created(_), Provisioned::Existing(_)) | (Provisioned::Existing(_), Provisioned::Created(_))
        ));
        let id = row(a).id;
        assert_eq!(id, row(b).id);
        let p = provider(http.clone()).await;
        assert!(matches!(p.provision(r, &c).await.unwrap(), Provisioned::Existing(_)));
        if !proxied {
            c.value = Some(Secret::new("key-b"));
        }
        let rows = p.list(&c).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].environment.label.as_deref(), Some("label-a"));
        assert_eq!(rows[0].environment.granted_size.as_ref().unwrap().memory_bytes, 4 << 30);
        assert_eq!(rows[0].timestamp.unwrap().to_rfc3339(), "2026-10-19T12:00:00+00:00");
        let ops = p.operations();
        let token = ops.suspend_resume.unwrap().suspend(&id, &c).await.unwrap();
        assert!(matches!(p.inspect(&id, &c).await.unwrap().environment.state, Observation::Stopped { .. }));
        let before = http.0.lock().unwrap().bootstraps;
        ops.suspend_resume.unwrap().resume(&id, token, &c).await.unwrap();
        assert_eq!(http.0.lock().unwrap().bootstraps, before + 1);
        assert_eq!(p.capabilities().suspend_preserves_memory, Some(false));
        let mut output = String::new();
        ops.exec
            .unwrap()
            .exec(&id, ExecRequest { command: vec!["echo".into(), "one'; touch /bad".into()] }, &c)
            .await
            .unwrap()
            .read_to_string(&mut output)
            .await
            .unwrap();
        assert_eq!(output, "guest output");
        assert!(http.0.lock().unwrap().executed.last().unwrap().contains("'one'\\''; touch /bad'"));
        for expected in ["ephemeral-1", "ephemeral-2"] {
            let Connection::Ssh { user, endpoint, reverse_forwards, .. } = p.reach(&id, &c).await.unwrap() else {
                panic!("SSH recipe required")
            };
            assert_eq!(user.expose(), expected);
            // Daytona's gateway refuses remote port forwarding.
            assert!(!reverse_forwards);
            assert_eq!(endpoint, "ssh.app.daytona.io:22");
            let recipe = Reach::Ssh { user, endpoint, host_key: "key".into(), reverse_forwards };
            assert!(!format!("{recipe:?}").contains(expected));
        }
        let quota = ops.quota.unwrap().quota(&c).await.unwrap();
        assert_eq!(quota.resources[0].in_use, 2.0);
        assert_eq!(quota.resources[0].limit, Some(10.0));
        let period = Period::new("2026-10-19T00:00:00Z".parse().unwrap(), "2026-10-20T00:00:00Z".parse().unwrap()).unwrap();
        let measurements = ops.usage.unwrap().usage(period.clone(), &c).await.unwrap().measurements.unwrap();
        assert_eq!(measurements.resources[&ResourceKind::Memory].unit, "By.s");
        assert_eq!(measurements.resources[&ResourceKind::Memory].amount, 14400.0 * (1u64 << 30) as f64);
        assert_eq!(measurements.resources[&ResourceKind::Disk].amount, 36000.0 * (1u64 << 30) as f64);
        let cost = measurements.cost.unwrap();
        assert_eq!(cost.amount, "0.0123");
        assert_eq!(cost.currency, "USD");
        let usage = ops.usage.unwrap().usage(period, &c).await.unwrap();
        assert_eq!(usage.environment_hours.len(), 1);
        assert_eq!(usage.environment_hours[0].hours, 1.0);
        assert_eq!(usage.environment_hours[0].size.cpus, 2.0);
        p.destroy(&id, &c).await.unwrap();
        p.destroy(&id, &c).await.unwrap();
        assert!(p.list(&c).await.unwrap().is_empty());
        assert_eq!(http.0.lock().unwrap().creates, 1);
    }
}

// Every request failure is typed, sanitized and returned without retry. The
// standard 429 response carries Retry-After through the module boundary.
#[tokio::test]
async fn vendor_errors() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let c = credentials(false);
    for (status, class) in [
        (400, "internal"),
        (401, "credential_rejected"),
        (402, "quota_exhausted"),
        (403, "refused"),
        (404, "not_found"),
        (409, "internal"),
        (422, "internal"),
        (429, "rate_limited"),
        (500, "unavailable"),
    ] {
        http.0.lock().unwrap().failure = Some(status);
        let before = http.0.lock().unwrap().requests;
        let e = p.list(&c).await.unwrap_err();
        assert_eq!(e.class(), class);
        assert!(e.to_string().contains(&format!("HTTP {status}")));
        assert!(e.to_string().contains("key-a must never be echoed"));
        if status == 429 {
            assert_eq!(e.retry_after(), Some(17));
        }
        assert_eq!(http.0.lock().unwrap().requests, before + 1);
    }
}

// CIDRs/literals are IPv4-only and ports are never silently widened. The
// matrix spans empty/open/duplicate rules, IPv6 and exact port restrictions.
#[tokio::test]
async fn egress_and_sizes() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    for (index, egress) in [
        EgressRequest::default(),
        EgressRequest::Open,
        EgressRequest::DenyAll {
            direct: vec![
                Destination::Cidr { cidr: "192.0.2.0/24".parse().unwrap() },
                Destination::Cidr { cidr: "192.0.2.0/24".parse().unwrap() },
            ],
        },
        EgressRequest::DenyAll { direct: vec![Destination::Host { host: "127.0.0.1".parse().unwrap() }] },
    ]
    .into_iter()
    .enumerate()
    {
        let mut r = request(prep.clone(), &format!("valid-{index}"));
        r.egress = egress;
        assert!(matches!(row(p.provision(r, &c).await.unwrap()).egress, Enforcement::Advisory));
    }
    assert_eq!(p.list(&c).await.unwrap().len(), 4);
    for entry in [
        Destination::Cidr { cidr: "::/0".parse().unwrap() },
        Destination::Host { host: "::1".parse().unwrap() },
        Destination::HostPort { host: "example.com".parse().unwrap(), port: Port::new(443).unwrap() },
    ] {
        let before = http.0.lock().unwrap().requests;
        let mut r = request(prep.clone(), "refused");
        r.egress = EgressRequest::DenyAll { direct: vec![entry] };
        assert!(matches!(p.provision(r, &c).await, Err(ProtocolError::Refused { .. })));
        assert_eq!(http.0.lock().unwrap().requests, before);
    }
    for cpus in [0.0, 0.5, 4.1, 5.0] {
        let mut r = request(prep.clone(), "invalid-size");
        r.size.cpus = cpus;
        assert!(matches!(p.provision(r, &c).await, Err(ProtocolError::Refused { .. })));
    }
}

// Generated lifecycle sequences preserve label identity across repeated create,
// stop/start, deletion and provider reconstruction. Each step checks inventory.
#[hegel::test]
fn generated_lifecycle(tc: hegel::TestCase) {
    use hegel::generators as gs;
    // 1..10 operations, including duplicate creates, destroy and resume.
    let steps = tc.draw(gs::integers::<usize>().min_value(1).max_value(10));
    let operations: Vec<_> = (0..steps).map(|_| tc.draw(gs::integers::<u8>().min_value(0).max_value(3))).collect();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let http = Arc::new(StandIn::default());
        let mut p = provider(http.clone()).await;
        let c = credentials(false);
        let prep = prepared(p.as_ref(), &c).await;
        let mut expected: Option<String> = None;
        for op in operations {
            match op {
                0 => {
                    let e = row(p.provision(request(prep.clone(), "generated"), &c).await.unwrap());
                    if let Some(id) = &expected {
                        assert_eq!(id, &e.id);
                    }
                    expected = Some(e.id);
                }
                1 => {
                    if let Some(id) = expected.take() {
                        p.destroy(&id, &c).await.unwrap();
                    }
                }
                2 => {
                    if let Some(id) = &expected {
                        let ops = p.operations();
                        let t = ops.suspend_resume.unwrap().suspend(id, &c).await.unwrap();
                        ops.suspend_resume.unwrap().resume(id, t, &c).await.unwrap();
                    }
                }
                _ => p = provider(http.clone()).await,
            }
            let rows = p.list(&c).await.unwrap();
            assert_eq!(rows.len(), usize::from(expected.is_some()));
            if let Some(id) = &expected {
                assert_eq!(&rows[0].environment.id, id);
                assert!(matches!(rows[0].environment.state, Observation::Running));
            }
        }
    });
}

// Enforced is a measured root claim. A declaration, a non-root result, an
// allowed canary, or successful raw DNS is never sufficient to assert it.
#[tokio::test]
async fn root_egress_claim_is_measured_each_time() {
    let http = Arc::new(StandIn::default());
    let p = provider_with_probe(http.clone(), true).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    let mut r = request(prep, "probe");
    r.egress = EgressRequest::DenyAll { direct: vec![Destination::Cidr { cidr: "192.0.2.1/32".parse().unwrap() }] };
    let good = json!({"uid":0,"listed_direct":true,"unlisted_canary":false,"raw_dns":false});
    http.0.lock().unwrap().probe = Some(good.clone());
    let env = row(p.provision(r, &c).await.unwrap());
    assert_eq!(env.egress, Enforcement::Enforced);
    let original_policy = p.inspect(&env.id, &c).await.unwrap().egress_policy;
    assert!(original_policy.is_some());
    assert_eq!(p.list(&c).await.unwrap()[0].egress_policy, original_policy);
    http.0.lock().unwrap().rows.get_mut(&env.id).unwrap()["networkAllowList"] = json!("198.51.100.0/24");
    assert_ne!(p.list(&c).await.unwrap()[0].egress_policy, original_policy);
    for (key, bad) in [("uid", json!(1000)), ("listed_direct", json!(false)), ("unlisted_canary", json!(true)), ("raw_dns", json!(true))] {
        let mut result = good.clone();
        result[key] = bad;
        http.0.lock().unwrap().probe = Some(result);
        assert_eq!(p.inspect(&env.id, &c).await.unwrap().environment.egress, Enforcement::Advisory);
        assert_eq!(p.list(&c).await.unwrap()[0].environment.egress, Enforcement::Advisory);
    }
}

// Error reasons map to typed loss/unknown causes and granted sizes come from
// provider observations, including unlabelled sandboxes re-adopted by inventory.
#[tokio::test]
async fn observations_are_typed() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let c = credentials(false);
    // Published vendor wording, not a captured live-account response. Other
    // rows below are synthetic cause/refusal examples, labelled deliberately.
    let schema: Value = serde_json::from_str(include_str!("fixtures/daytona-schemas.json")).unwrap();
    let documented_reason = schema["schemas"]["Sandbox"]["properties"]["errorReason"]["example"].as_str().unwrap();
    for (state, reason, expected) in [
        ("error", documented_reason, Observation::Unknown { reason: UnknownReason::ProviderApiError }),
        ("error", "no room on runner", Observation::Unknown { reason: UnknownReason::ProviderApiError }),
        ("error", "zoom process startup failed", Observation::Unknown { reason: UnknownReason::ProviderApiError }),
        ("error", "out of memory", Observation::Gone { cause: GoneCause::HostOutOfMemory }),
        ("error", "evicted by provider", Observation::Gone { cause: GoneCause::EvictedByProvider }),
        ("error", "runner unreachable", Observation::Unknown { reason: UnknownReason::HostUnreachable }),
        ("build_failed", "unknown vendor error", Observation::Unknown { reason: UnknownReason::ProviderApiError }),
        ("unknown", "", Observation::Unknown { reason: UnknownReason::ProviderStateUnknown }),
        ("paused", "", Observation::Stopped { cause: StopCause::PausedByProvider }),
        ("creating", "", Observation::Transitioning { phase: TransitionPhase::Preparing }),
        ("destroyed", "", Observation::Gone { cause: GoneCause::DestroyedAtProvider }),
    ] {
        http.0
            .lock()
            .unwrap()
            .rows
            .insert("unlabelled".into(), json!({"id":"unlabelled","state":state,"errorReason":reason,"cpu":3,"memory":7,"disk":9}));
        let row = p.inspect("unlabelled", &c).await.unwrap();
        assert_eq!(row.environment.state, expected);
        assert!(row.environment.label.is_none());
        assert_eq!(row.environment.granted_size.unwrap().cpus, 3.0);
        assert!(row.timestamp.is_none());
    }
}

// A missed inventory read (e.g. visibility delay) cannot duplicate a labelled
// sandbox. The deterministic vendor name arbitrates across independent hosts.
#[tokio::test]
async fn name_conflict_readopts_without_retrying_creation() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    let r = request(prep, "same-name");
    let id = row(p.provision(r.clone(), &c).await.unwrap()).id;
    http.0.lock().unwrap().hide_label_once = true;
    let other = provider(http.clone()).await;
    let result = other.provision(r.clone(), &c).await.unwrap();
    assert!(matches!(result, Provisioned::Existing(_)));
    assert_eq!(row(result).id, id);
    assert_eq!(http.0.lock().unwrap().creates, 1);
    http.0.lock().unwrap().rows.get_mut(&id).unwrap()["state"] = json!("stopped");
    http.0.lock().unwrap().hide_label_once = true;
    let stopped = tokio::time::timeout(std::time::Duration::from_secs(2), other.provision(r, &c)).await.unwrap().unwrap();
    assert!(matches!(row(stopped).state, Observation::Stopped { .. }));
}

// Concurrent prepare at independent hosts converges on the digest-pair name;
// changing the tools digest must produce a different snapshot.
#[tokio::test]
async fn preparation_converges_by_digest_pair() {
    let http = Arc::new(StandIn::default());
    let a = provider(http.clone()).await;
    let b = provider(http.clone()).await;
    let c = credentials(false);
    let mut r = PrepareRequest {
        platform: Some(Platform::new("linux", "amd64")),
        route: Some(ImageRouteKind::RegistryPull),
        image_pull: None,
        size: daytona_size(),
        image_digest: format!("image@sha256:{}", "b".repeat(64)),
        tools_digest: tools_image('a'),
    };
    let (x, y) = tokio::join!(a.prepare(r.clone(), &c), b.prepare(r.clone(), &c));
    let x = x.unwrap();
    assert_eq!(x, y.unwrap());
    assert_eq!(http.0.lock().unwrap().snapshots.len(), 1);
    r.tools_digest = tools_image('b');
    let other = a.prepare(r, &c).await.unwrap();
    assert_ne!(x.id, other.id);
    assert_eq!(http.0.lock().unwrap().snapshots.len(), 2);
    assert!(
        a.prepare(
            PrepareRequest {
                platform: Some(Platform::new("linux", "amd64")),
                route: Some(ImageRouteKind::RegistryPull),
                image_pull: None,
                size: daytona_size(),
                image_digest: "image:latest".into(),
                tools_digest: tools_image('a')
            },
            &c
        )
        .await
        .is_err()
    );
}

// Daytona fixes resources at prepare: every size component participates in the
// key, retries converge across provider reconstruction, and provision inherits it.
#[hegel::test]
fn prepared_sizes_route_to_snapshots(tc: hegel::TestCase) {
    use hegel::generators as gs;
    // Span all supported whole-unit sizes, including minima and maxima.
    let size = Size {
        cpus: tc.draw(gs::integers::<u8>().min_value(1).max_value(4)) as f64,
        memory_bytes: u64::from(tc.draw(gs::integers::<u8>().min_value(1).max_value(8))) << 30,
        disk_bytes: u64::from(tc.draw(gs::integers::<u8>().min_value(1).max_value(10))) << 30,
    };
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let http = Arc::new(StandIn::default());
        let p = provider(http.clone()).await;
        let c = credentials(false);
        let base = PrepareRequest {
            platform: Some(Platform::new("linux", "amd64")),
            route: Some(ImageRouteKind::RegistryPull),
            image_pull: None,
            image_digest: format!("image@sha256:{}", "c".repeat(64)),
            tools_digest: tools_image('a'),
            size: size.clone(),
        };
        let prep = p.prepare(base.clone(), &c).await.unwrap();
        let other_host = provider(http.clone()).await;
        assert_eq!(other_host.prepare(base.clone(), &c).await.unwrap(), prep);
        let mut provision = request(prep.clone(), "sized");
        provision.size = size.clone();
        assert_eq!(row(other_host.provision(provision.clone(), &c).await.unwrap()).granted_size, Some(size.clone()));
        assert_eq!(row(other_host.provision(provision.clone(), &c).await.unwrap()).granted_size, Some(size.clone()));
        for component in 0..3 {
            let mut changed = base.clone();
            match component {
                0 => changed.size.cpus = size.cpus % 4.0 + 1.0,
                1 => changed.size.memory_bytes = (size.memory_bytes / (1 << 30) % 8 + 1) << 30,
                _ => changed.size.disk_bytes = (size.disk_bytes / (1 << 30) % 10 + 1) << 30,
            }
            // A changed size is refused before any vendor request, even for an existing label.
            let before = http.0.lock().unwrap().requests;
            provision.size = changed.size.clone();
            assert!(matches!(other_host.provision(provision.clone(), &c).await, Err(ProtocolError::Refused { .. })));
            assert_eq!(http.0.lock().unwrap().requests, before);
            let changed_prep = p.prepare(changed.clone(), &c).await.unwrap();
            assert_ne!(changed_prep.id, prep.id);
            let mut r = request(changed_prep, &format!("changed-{component}"));
            r.size = changed.size.clone();
            assert_eq!(row(p.provision(r, &c).await.unwrap()).granted_size, Some(changed.size));
        }
        assert_eq!(http.0.lock().unwrap().snapshots.len(), 4);
    });
}

// An active snapshot created out of band under our deterministic name must not
// be adopted if any vendor resource differs (SnapshotDto calls RAM `mem`).
#[tokio::test]
async fn preparation_refuses_existing_snapshot_resource_mismatch() {
    for key in ["cpu", "mem", "disk"] {
        let http = Arc::new(StandIn::default());
        let p = provider(http.clone()).await;
        let c = credentials(false);
        let prep = prepared(p.as_ref(), &c).await;
        http.0.lock().unwrap().snapshots.get_mut(&prep.id).unwrap()[key] = json!(1);
        let r = PrepareRequest {
            platform: Some(Platform::new("linux", "amd64")),
            route: Some(ImageRouteKind::RegistryPull),
            image_pull: None,
            image_digest: prep.image_digest,
            tools_digest: prep.tools_digest,
            size: daytona_size(),
        };
        assert!(matches!(p.prepare(r, &c).await, Err(ProtocolError::Refused { .. })));
        assert_eq!(http.0.lock().unwrap().snapshot_requests.len(), 1);
    }
}

// Preparation refuses unsupported resources without creating a snapshot. Both
// operations share whole-unit limits; cover zero, fractional, oversized and NaN.
#[tokio::test]
async fn invalid_preparation_sizes_do_not_call_vendor() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    let valid = request(prep.clone(), "invalid").size;
    let mut sizes = vec![];
    for cpus in [0.0, 0.5, 5.0, f64::NAN, f64::INFINITY] {
        sizes.push(Size { cpus, ..valid.clone() });
    }
    for memory_bytes in [0, 1, 8 * (1 << 30) + 1, 9 * (1 << 30), u64::MAX] {
        sizes.push(Size { memory_bytes, ..valid.clone() });
    }
    for disk_bytes in [0, 1, 10 * (1 << 30) + 1, 11 * (1 << 30), u64::MAX] {
        sizes.push(Size { disk_bytes, ..valid.clone() });
    }
    let before = http.0.lock().unwrap().requests;
    for size in sizes {
        let preparation = PrepareRequest {
            platform: Some(Platform::new("linux", "amd64")),
            route: Some(ImageRouteKind::RegistryPull),
            image_pull: None,
            image_digest: prep.image_digest.clone(),
            tools_digest: prep.tools_digest.clone(),
            size: size.clone(),
        };
        assert!(matches!(p.prepare(preparation, &c).await, Err(ProtocolError::Refused { .. })));
        let mut r = request(prep.clone(), "invalid");
        r.size = size;
        assert!(matches!(p.provision(r, &c).await, Err(ProtocolError::Refused { .. })));
    }
    assert_eq!(http.0.lock().unwrap().requests, before);
}

// The stand-in rejects each resource field with a snapshot, but accepts the
// fields when creating without one.
#[tokio::test]
async fn standin_rejects_snapshot_resources() {
    let http = StandIn::default();
    let client = reqwest::Client::new();
    for key in ["cpu", "memory", "disk"] {
        let mut body = json!({"snapshot":"snapshot"});
        body[key] = json!(1);
        let req = client.post("https://app.daytona.io/api/sandbox").bearer_auth("key-a").json(&body).build().unwrap();
        let response = http.execute(req, &ChannelLabel::Default).await.unwrap();
        assert_eq!(response.status(), 400);
        assert!(String::from_utf8(response.into_body().to_vec()).unwrap().contains("Cannot specify Sandbox resources"));
        let mut body = json!({});
        body[key] = json!(1);
        let req = client.post("https://app.daytona.io/api/sandbox").bearer_auth("key-a").json(&body).build().unwrap();
        assert_eq!(http.execute(req, &ChannelLabel::Default).await.unwrap().status(), 201);
    }
}

// Activation is submitted once, then its lagging state is observed with paced
// reads. Repeated activate POSTs cannot make that transition progress faster.
#[tokio::test]
async fn inactive_snapshot_activates_once_then_polls() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    http.0.lock().unwrap().snapshots.values_mut().next().unwrap()["state"] = json!("inactive");
    let start = tokio::time::Instant::now();
    let result = p
        .prepare(
            PrepareRequest {
                platform: Some(Platform::new("linux", "amd64")),
                route: Some(ImageRouteKind::RegistryPull),
                image_pull: None,
                size: daytona_size(),
                image_digest: prep.image_digest,
                tools_digest: prep.tools_digest,
            },
            &c,
        )
        .await;
    assert!(result.is_ok());
    assert_eq!(http.0.lock().unwrap().activations, 1);
    assert!(start.elapsed() >= std::time::Duration::from_secs(2));
}

// Bootstrap retains a bounded vendor deadline for starting supervision.
// Guest command failure is not a transient provider outage.
#[tokio::test]
async fn bootstrap_budget_and_command_failure() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    http.0.lock().unwrap().require_bootstrap_budget = true;
    let env = row(p.provision(request(prep, "budget"), &c).await.unwrap());
    http.0.lock().unwrap().command_exit = Some(7);
    let err = p.operations().exec.unwrap().exec(&env.id, ExecRequest { command: vec!["false".into()] }, &c).await.err().unwrap();
    assert_eq!(err.class(), "command_failed");
    let value = serde_json::to_value(&err).unwrap();
    assert_eq!(value["exit_code"], 7);
    assert_eq!(value["output"], "guest output");
    assert!(!format!("{err:?}").contains("guest output"));
}

// A terminal start/build failure must return immediately, rather than spending
// the entire successful-operation observation budget polling an impossible start.
#[tokio::test]
async fn terminal_sandbox_and_snapshot_errors_fail_fast() {
    for state in ["error", "build_failed", "destroyed"] {
        let http = Arc::new(StandIn::default());
        let p = provider(http.clone()).await;
        let c = credentials(false);
        let prep = prepared(p.as_ref(), &c).await;
        http.0.lock().unwrap().created_state = Some(state.into());
        let start = tokio::time::Instant::now();
        assert!(p.provision(request(prep, "terminal"), &c).await.is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(2), "terminal state waited out the start budget");
    }
    for state in ["error", "build_failed"] {
        let http = Arc::new(StandIn::default());
        let p = provider(http.clone()).await;
        let c = credentials(false);
        let prep = prepared(p.as_ref(), &c).await;
        http.0.lock().unwrap().snapshots.values_mut().next().unwrap()["state"] = json!(state);
        assert!(matches!(
            p.prepare(
                PrepareRequest {
                    platform: Some(Platform::new("linux", "amd64")),
                    route: Some(ImageRouteKind::RegistryPull),
                    image_pull: None,
                    size: daytona_size(),
                    image_digest: prep.image_digest,
                    tools_digest: prep.tools_digest
                },
                &c
            )
            .await,
            Err(ProtocolError::Refused { .. })
        ));
    }
}

// A failed row-local guest probe cannot erase a healthy authoritative inventory.
#[tokio::test]
async fn probe_failures_surface_without_erasing_inventory() {
    let http = Arc::new(StandIn::default());
    let p = provider_with_probe(http.clone(), true).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    http.0.lock().unwrap().probe = Some(json!({"uid":0,"listed_direct":true,"unlisted_canary":false,"raw_dns":false}));
    let mut r = request(prep, "probe-fails");
    r.egress = EgressRequest::DenyAll { direct: vec![Destination::Cidr { cidr: "192.0.2.1/32".parse().unwrap() }] };
    let env = row(p.provision(r, &c).await.unwrap());
    http.0.lock().unwrap().probe_exit = Some(1);
    assert!(matches!(p.inspect(&env.id, &c).await, Err(ProtocolError::CommandFailed { .. })));
    assert_eq!(p.list(&c).await.unwrap().len(), 1);
}

// Bootstrap delegates to the baked binary and needs no Python, flock, or shell
// fragment setting. Lifecycle readiness belongs to the daemon's agent hello.
#[tokio::test]
async fn bootstrap_uses_only_baked_tools() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    p.provision(request(prep, "tools-only"), &c).await.unwrap();
    let state = http.0.lock().unwrap();
    assert_eq!(state.executed, ["/opt/drydock/drydock-agent --supervise --socket /run/drydock/agent.sock"]);
}

// This network-boundary wrapper controls response latency without sleeping
// while holding the stand-in's state lock.
struct Latency {
    vendor: Arc<StandIn>,
    block_start: bool,
    blocked: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
    delay_probes: bool,
    active: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
}
impl Latency {
    fn new(vendor: Arc<StandIn>, block_start: bool, delay_probes: bool) -> Self {
        Self {
            vendor,
            block_start,
            blocked: false.into(),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
            delay_probes,
            active: 0.into(),
            peak: 0.into(),
        }
    }
}
#[async_trait]
impl HttpClient for Latency {
    async fn execute(&self, request: reqwest::Request, label: &ChannelLabel) -> std::result::Result<http::Response<Bytes>, String> {
        use std::sync::atomic::Ordering::SeqCst;
        if self.block_start
            && request.method() == reqwest::Method::GET
            && request.url().path() == "/api/sandbox/sandbox-1"
            && !self.blocked.swap(true, SeqCst)
        {
            self.entered.notify_one();
            self.release.acquire().await.unwrap().forget();
        }
        let probe = self.delay_probes && request.url().path().starts_with("/toolbox/");
        if probe {
            let active = self.active.fetch_add(1, SeqCst) + 1;
            self.peak.fetch_max(active, SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let result = self.vendor.execute(request, label).await;
        if probe {
            self.active.fetch_sub(1, SeqCst);
        }
        result
    }
}

// Vendor uniqueness protects label idempotence without a provider-wide lock:
// a slow first start must not hold up provisioning an independent label.
#[tokio::test]
async fn slow_start_does_not_queue_other_labels() {
    let vendor = Arc::new(StandIn::default());
    let http = Arc::new(Latency::new(vendor, true, false));
    let p = provider(http.clone()).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    let slow_p = p.clone();
    let slow_c = c.clone();
    let slow_r = request(prep.clone(), "slow");
    let slow = tokio::spawn(async move { slow_p.provision(slow_r, &slow_c).await });
    http.entered.notified().await;
    let fast = tokio::time::timeout(std::time::Duration::from_millis(500), p.provision(request(prep, "fast"), &c)).await;
    http.release.add_permits(1);
    assert!(fast.unwrap().is_ok());
    assert!(slow.await.unwrap().is_ok());
}

// Polling does not execute guest probes, so inventory cost does not grow with
// probe latency or interfere with observation cadence.
#[tokio::test]
async fn list_never_runs_guest_probes() {
    let vendor = Arc::new(StandIn::default());
    let http = Arc::new(Latency::new(vendor.clone(), false, true));
    let p = provider_with_probe(http.clone(), true).await;
    let c = credentials(false);
    for i in 0..7 {
        vendor.0.lock().unwrap().rows.insert(
            format!("s-{i}"),
            json!({"id":format!("s-{i}"),"state":"started","networkAllowList":"192.0.2.1/32","cpu":1,"memory":1,"disk":1}),
        );
    }
    vendor.0.lock().unwrap().probe = Some(json!({"uid":0,"listed_direct":true,"unlisted_canary":false,"raw_dns":false}));
    assert_eq!(p.list(&c).await.unwrap().len(), 7);
    assert_eq!(http.peak.load(std::sync::atomic::Ordering::SeqCst), 0);
}

// Reusing a label cannot silently return a wider network policy or a different
// size than the request. Exact retries still converge on the same sandbox.
#[tokio::test]
async fn existing_labels_surface_size_and_egress_mismatches() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    let r = request(prep, "mismatch");
    p.provision(r.clone(), &c).await.unwrap();
    let mut changed = r.clone();
    changed.size.cpus = 3.0;
    assert!(matches!(p.provision(changed, &c).await, Err(ProtocolError::Refused { .. })));
    let mut changed = r.clone();
    changed.egress = EgressRequest::Open;
    assert!(matches!(p.provision(changed, &c).await, Err(ProtocolError::Refused { .. })));
    assert!(matches!(p.provision(r, &c).await.unwrap(), Provisioned::Existing(_)));
}

// Deny-all has no listed destination: a root proof of blocked canary/DNS is
// enough, but missing facts, non-root execution and probe errors never enforce.
#[tokio::test]
async fn deny_all_proof_and_probe_diagnostics() {
    let http = Arc::new(StandIn::default());
    let p = provider_with_probe(http.clone(), true).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    http.0.lock().unwrap().probe = Some(json!({"uid":0,"unlisted_canary":false,"raw_dns":false}));
    let env = row(p.provision(request(prep, "deny-all"), &c).await.unwrap());
    assert_eq!(env.egress, Enforcement::Enforced);
    assert!(http.0.lock().unwrap().executed.iter().any(|s| s.contains("DRYDOCK_PROBE_DENY_ALL=1")));
    let before = http.0.lock().unwrap().executed.len();
    p.list(&c).await.unwrap();
    assert_eq!(http.0.lock().unwrap().executed.len(), before);
    http.0.lock().unwrap().probe = Some(json!({"uid":1000,"unlisted_canary":false,"raw_dns":false}));
    assert_eq!(p.inspect(&env.id, &c).await.unwrap().environment.egress, Enforcement::Advisory);
    http.0.lock().unwrap().probe = Some(json!({"uid":0,"unlisted_canary":true,"raw_dns":false}));
    assert_eq!(p.inspect(&env.id, &c).await.unwrap().environment.egress, Enforcement::Advisory);
    http.0.lock().unwrap().probe_exit = Some(2);
    assert!(matches!(p.inspect(&env.id, &c).await, Err(ProtocolError::CommandFailed { exit_code: 2, .. })));
}

// Native host rules preserve request identity without consulting current DNS.
// Mixed CIDR/domain requests are refused rather than weakening either policy.
#[tokio::test]
async fn native_domains_are_idempotent_and_mixed_rules_refused() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    let mut r = request(prep, "domains");
    r.egress = EgressRequest::DenyAll { direct: vec![Destination::Host { host: "dual-stack.example".parse().unwrap() }] };
    let env = row(p.provision(r.clone(), &c).await.unwrap());
    assert_eq!(http.0.lock().unwrap().rows[&env.id]["domainAllowList"], "dual-stack.example");
    assert!(matches!(p.provision(r.clone(), &c).await.unwrap(), Provisioned::Existing(_)));
    let EgressRequest::DenyAll { direct } = &mut r.egress else { unreachable!() };
    direct.push(Destination::Cidr { cidr: "192.0.2.0/24".parse().unwrap() });
    assert!(matches!(p.provision(r, &c).await, Err(ProtocolError::Refused { .. })));
}

// The HTTP stand-in validates actual wire auth and networking rules. Empty
// CreateSandbox is schema-valid; conflicting policies and malformed CIDRs aren't.
#[tokio::test]
async fn standin_enforces_vendor_wire_contract() {
    let http = Arc::new(StandIn::default());
    let network = http.network().await;
    let client = rigging_tls::client_builder().build().unwrap();
    for (token, body, expected) in [
        ("wrong", json!({}), 401),
        ("key-a", json!({"networkBlockAll":true,"networkAllowList":"0.0.0.0/0"}), 400),
        ("key-a", json!({"networkAllowList":"not-a-cidr"}), 400),
        ("key-a", json!({}), 201),
    ] {
        let r = client.post("https://app.daytona.io/api/sandbox").bearer_auth(token).json(&body).build().unwrap();
        assert_eq!(network.http.execute(r, &ChannelLabel::Default).await.unwrap().status(), expected);
    }
    let p = provider(http.clone()).await;
    let mut c = credentials(false);
    c.value = Some(Secret::new("wrong"));
    assert!(matches!(p.list(&c).await, Err(ProtocolError::CredentialRejected { .. })));
}

// Unknown HTTP responses retain bounded vendor evidence. The host masks
// configured credentials before displaying or returning these diagnostics.
#[tokio::test]
async fn internal_retains_vendor_body() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    http.0.lock().unwrap().failure = Some(400);
    let error = p.list(&credentials(false)).await.unwrap_err();
    assert!(format!("{error:?}").contains("key-a"));
    let ProtocolError::Internal { provider_error, .. } = error else { panic!("internal error") };
    assert!(provider_error.as_str().contains("key-a must never be echoed"));
}

// Lifecycle state checks must not invoke isolation probes. Even a failing probe
// cannot block stop; resume performs only the agent bootstrap exec, with the
// host responsible for consuming a subsequent explicit measurement.
#[tokio::test]
async fn lifecycle_state_checks_do_not_probe() {
    let http = Arc::new(StandIn::default());
    let p = provider_with_probe(http.clone(), true).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    http.0.lock().unwrap().probe = Some(json!({"uid":0,"unlisted_canary":false,"raw_dns":false}));
    let env = row(p.provision(request(prep, "probe-independent-stop"), &c).await.unwrap());
    http.0.lock().unwrap().probe_exit = Some(1);
    let before = http.0.lock().unwrap().executed.len();
    let sr = p.operations().suspend_resume.unwrap();
    let token = sr.suspend(&env.id, &c).await.unwrap();
    assert_eq!(http.0.lock().unwrap().executed.len(), before);
    sr.resume(&env.id, token, &c).await.unwrap();
    assert_eq!(http.0.lock().unwrap().executed.len(), before + 1);
    assert!(matches!(p.inspect(&env.id, &c).await, Err(ProtocolError::CommandFailed { .. })));
}

// Retried stop/start observes operations already moving in the requested
// direction. It must not submit another lifecycle command during transition.
#[tokio::test]
async fn lifecycle_retries_wait_for_existing_transition() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    let env = row(p.provision(request(prep, "transition-retry"), &c).await.unwrap());
    {
        let mut state = http.0.lock().unwrap();
        state.rows.get_mut(&env.id).unwrap()["state"] = json!("stopping");
        state.complete_transition_on_read = true;
    }
    let sr = p.operations().suspend_resume.unwrap();
    let token = sr.suspend(&env.id, &c).await.unwrap();
    assert!(http.0.lock().unwrap().lifecycle_posts.is_empty());
    {
        let mut state = http.0.lock().unwrap();
        state.rows.get_mut(&env.id).unwrap()["state"] = json!("starting");
        state.complete_transition_on_read = true;
    }
    sr.resume(&env.id, token, &c).await.unwrap();
    assert!(http.0.lock().unwrap().lifecycle_posts.is_empty());
    assert_eq!(p.inspect(&env.id, &c).await.unwrap().environment.state, Observation::Running);
}

// A transport outage is retryable Unavailable, never an adaptor-bug Internal.
#[tokio::test]
async fn transport_outages_are_unavailable() {
    struct Offline;
    #[async_trait]
    impl HttpClient for Offline {
        async fn execute(&self, _: reqwest::Request, _: &ChannelLabel) -> std::result::Result<http::Response<Bytes>, String> {
            Err("connection reset: private transport detail".into())
        }
    }
    let p = provider(Arc::new(Offline)).await;
    let error = p.list(&credentials(false)).await.unwrap_err();
    assert!(matches!(error, ProtocolError::Unavailable { .. }));
    assert!(error.to_string().contains("private transport detail"));
    let ProtocolError::Unavailable { provider_error: Some(detail), .. } = error else { panic!("missing protected transport diagnostic") };
    assert!(detail.as_str().contains("private transport detail"));
}

// Probe command failure and malformed proof leave successful creation/re-adoption
// and resume enrichment Advisory. Explicit inspect still exposes the typed error.
#[tokio::test]
async fn lifecycle_success_is_independent_of_probe_failure() {
    for failure in 0..3 {
        let http = Arc::new(StandIn::default());
        let p = provider_with_probe(http.clone(), true).await;
        let c = credentials(false);
        let prep = prepared(p.as_ref(), &c).await;
        if failure == 1 {
            http.0.lock().unwrap().probe_exit = Some(1);
        }
        if failure == 2 {
            http.0.lock().unwrap().probe_http_failure = Some(502);
        }
        let mut request = request(prep, "broken-probe");
        request.egress = EgressRequest::DenyAll { direct: vec![] };
        for _ in 0..2 {
            let result = p.provision(request.clone(), &c).await.unwrap();
            let (Provisioned::Created(row) | Provisioned::Existing(row)) = result;
            assert_eq!(row.environment.egress, Enforcement::Advisory);
            assert!(!row.egress_measured);
            assert!(p.inspect(&row.environment.id, &c).await.is_err());
            let port = p.operations().suspend_resume.unwrap();
            let token = port.suspend(&row.environment.id, &c).await.unwrap();
            port.resume(&row.environment.id, token, &c).await.unwrap();
            // Failed enrichment reuses the sandbox GET; it must not list the inventory.
            let requests = http.0.lock().unwrap().requests;
            let resumed = p.inspect_after_lifecycle(&row.environment.id, &c).await.unwrap();
            // The probe resolves its toolbox URL with a second GET, then executes.
            assert_eq!(http.0.lock().unwrap().requests - requests, 3);
            assert!(matches!(resumed.environment.state, Observation::Running));
            assert_eq!(resumed.environment.egress, Enforcement::Advisory);
            assert!(!resumed.egress_measured);
        }
    }
}

// Size-hours clip vendor periods to the requested window, ignore boundary-only
// intersections, retain size changes, and reject reversed or malformed periods.
#[tokio::test]
async fn sandbox_usage_periods_are_clipped_and_validated() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let port = p.operations().usage.unwrap();
    let period = Period::new("2026-10-19T00:00:00Z".parse().unwrap(), "2026-10-19T02:00:00Z".parse().unwrap()).unwrap();
    http.0.lock().unwrap().usage_periods = Some(json!([
        {"cpu":1,"ramGB":2,"diskGB":3,"startAt":"2026-10-18T23:00:00Z","endAt":"2026-10-19T01:00:00Z"},
        {"cpu":2,"ramGB":4,"diskGB":5,"startAt":"2026-10-19T01:00:00Z"},
        {"cpu":2,"ramGB":4,"diskGB":5,"startAt":"2026-10-19T02:00:00Z","endAt":"2026-10-19T03:00:00Z"},
        {"cpu":0,"startAt":"2026-10-19T00:00:00Z"},
        {"cpu":1,"ramGB":2,"diskGB":3,"startAt":"2026-10-19T03:00:00Z"}
    ]));
    let usage = port.usage(period.clone(), &credentials(false)).await.unwrap();
    assert_eq!(usage.environment_hours.len(), 2);
    assert_eq!(usage.environment_hours.iter().map(|r| r.hours).sum::<f64>(), 2.0);
    assert_eq!(usage.environment_hours[1].size.memory_bytes, 4 << 30);
    for value in
        [json!([]), json!([{"cpu":1,"startAt":"bad"}]), json!([{"cpu":1,"startAt":"2026-10-19T01:00:00Z","endAt":"2026-10-19T00:00:00Z"}])]
    {
        http.0.lock().unwrap().usage_periods = Some(value.clone());
        let result = port.usage(period.clone(), &credentials(false)).await;
        if value.as_array().unwrap().is_empty() {
            assert!(result.unwrap().environment_hours.is_empty());
        } else {
            assert!(result.is_err());
        }
    }
}

// Each origin rejects another service's routes and malformed required fields
// produce 4xx plus a recorded violation, rather than a dropped connection/panic.
#[tokio::test]
async fn standin_origin_and_contract_errors_are_observable() {
    let http = StandIn::default();
    let network = http.network().await;
    let client = rigging_tls::client_builder().build().unwrap();
    for (url, body) in [
        ("https://app.daytona.io/toolbox/sandbox-1/process/execute", json!({"command":"true","timeout":20})),
        ("https://runner.invalid/api/sandbox", json!({})),
        ("https://analytics.app.daytona.io/api/sandbox", json!({})),
        ("https://app.daytona.io/api/snapshots", json!({"imageName":"unpinned"})),
    ] {
        let request = client.post(url).bearer_auth("key-a").json(&body).build().unwrap();
        let response = network.http.execute(request, &ChannelLabel::Default).await.unwrap();
        assert_eq!(response.status(), 400);
        assert_eq!(http.0.lock().unwrap().violations.len(), 1);
        http.0.lock().unwrap().violations.clear(); // expected negative contract case
    }
    let request = client.get("https://app.daytona.io/api/sandbox").bearer_auth("key-a").build().unwrap();
    assert_eq!(network.http.execute(request, &ChannelLabel::Default).await.unwrap().status(), 200);
}

// Stored state mutations in lifecycle tests model valid vendor states and are
// validated on readback. Unknown-state robustness cases must use a separate raw
// HTTP response double so they deliberately bypass this vendor contract.
// Snapshot wire bodies follow the pinned OpenAPI, including referenced enums,
// required-but-nullable response fields, and integer request resources.
fn snapshot_schema_valid(value: &Value, name: &str, request: bool) -> bool {
    static SPEC: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    let spec = SPEC.get_or_init(|| serde_json::from_str(include_str!("fixtures/daytona-schemas.json")).unwrap());
    // Unknown request members are rejected deliberately: OpenAPI permits them by
    // default, but accepting a renamed resource would hide caller/schema drift.
    snapshot_value_valid(value, spec["schemas"].get(name).expect("pinned snapshot schema"), spec, request)
}

fn snapshot_value_valid(v: &Value, schema: &Value, spec: &Value, strict: bool) -> bool {
    if v.is_null() && schema["nullable"] == true {
        return true;
    }
    if let Some(reference) = schema["$ref"].as_str() {
        // The fixture stores components/schemas under its top-level schemas key.
        let name = reference.strip_prefix("#/components/schemas/").expect("local schema reference");
        return snapshot_value_valid(v, spec["schemas"].get(name).expect("pinned referenced schema"), spec, strict);
    }
    if let Some(parts) = schema["allOf"].as_array()
        && !parts.iter().all(|s| snapshot_value_valid(v, s, spec, strict))
    {
        return false;
    }
    if let Some(parts) = schema["oneOf"].as_array()
        && parts.iter().filter(|s| snapshot_value_valid(v, s, spec, strict)).count() != 1
    {
        return false;
    }
    if let Some(parts) = schema["anyOf"].as_array()
        && !parts.iter().any(|s| snapshot_value_valid(v, s, spec, strict))
    {
        return false;
    }
    if let Some(choices) = schema["enum"].as_array()
        && !choices.contains(v)
    {
        return false;
    }
    match schema["type"].as_str() {
        Some("object") => {
            let Some(object) = v.as_object() else {
                return false;
            };
            if schema["required"].as_array().is_some_and(|keys| keys.iter().any(|k| !object.contains_key(k.as_str().unwrap()))) {
                return false;
            }
            object.iter().all(|(k, v)| match schema["properties"].get(k) {
                Some(s) => snapshot_value_valid(v, s, spec, strict),
                None => !strict,
            })
        }
        Some("array") => v.as_array().is_some_and(|items| items.iter().all(|v| snapshot_value_valid(v, &schema["items"], spec, strict))),
        Some("integer") => v.is_i64() || v.is_u64(),
        Some("number") => v.is_number(),
        Some("boolean") => v.is_boolean(),
        Some("string") => v.as_str().is_some_and(|s| schema["format"] != "date-time" || chrono::DateTime::parse_from_rfc3339(s).is_ok()),
        None => true,
        kind => panic!("unsupported snapshot schema type {kind:?}"),
    }
}
// Composition follows JSON Schema: anyOf accepts a match; oneOf needs exactly
// one. Integer values overlap the integer and number branches; strings match neither.
#[test]
fn snapshot_schema_composition_requires_matching_branches() {
    let spec = json!({});
    for value in [json!(1), json!(1.5), json!("1")] {
        let any = json!({"anyOf":[{"type":"integer"},{"type":"number"}]});
        let one = json!({"oneOf":[{"type":"integer"},{"type":"number"}]});
        assert_eq!(snapshot_value_valid(&value, &any, &spec, false), value.is_number());
        // Integers match both branches, so oneOf must reject them.
        assert_eq!(snapshot_value_valid(&value, &one, &spec, false), value.is_number() && !value.is_i64());
    }
}

// Exercise absent, unknown, and every mistyped resource field at the HTTP boundary.
// Concurrent/duplicate lifecycle behaviour is covered by the prepare properties.
#[tokio::test]
async fn standin_validates_snapshot_create_schema() {
    let http = StandIn::default();
    let client = reqwest::Client::new();
    // Activation requires the addressed snapshot, even when another snapshot exists.
    let req = client.post("https://app.daytona.io/api/snapshots/missing/activate").bearer_auth("key-a").build().unwrap();
    assert_eq!(http.execute(req, &ChannelLabel::Default).await.unwrap().status(), 404);
    assert_eq!(http.0.lock().unwrap().activations, 0);
    let base = json!({"name":"fixture","buildInfo":{"dockerfileContent":format!("FROM --platform=linux/amd64 {} AS drydock_tools\nFROM --platform=linux/amd64 image@sha256:{}\nCOPY --from=drydock_tools /opt/drydock/ /opt/drydock/\n", tools_image('a'), "b".repeat(64))},"regionId":"eu","sandboxClass":"container","cpu":2,"memory":4,"disk":10});
    let mut invalid = vec![json!({}), json!(null)];
    let mut unknown = base.clone();
    unknown["mem"] = json!(4);
    invalid.push(unknown);
    for key in ["cpu", "memory", "disk"] {
        for value in [json!("4"), json!(1.5), json!(null), json!(true)] {
            let mut body = base.clone();
            body[key] = value;
            invalid.push(body);
        }
    }
    for body in invalid {
        let req = client.post("https://app.daytona.io/api/snapshots").bearer_auth("key-a").json(&body).build().unwrap();
        assert_eq!(http.execute(req, &ChannelLabel::Default).await.unwrap().status(), 400, "{body}");
        assert_eq!(http.0.lock().unwrap().violations.len(), 1);
        http.0.lock().unwrap().violations.clear();
    }
    let req = client.post("https://app.daytona.io/api/snapshots").bearer_auth("key-a").json(&base).build().unwrap();
    let response = http.execute(req, &ChannelLabel::Default).await.unwrap();
    assert_eq!(response.status(), 201);
    let row: Value = serde_json::from_slice(response.body()).unwrap();
    let req = client.post("https://app.daytona.io/api/snapshots/missing/activate").bearer_auth("key-a").build().unwrap();
    assert_eq!(http.execute(req, &ChannelLabel::Default).await.unwrap().status(), 404);
    assert_eq!(http.0.lock().unwrap().activations, 0);
    assert!(snapshot_schema_valid(&row, "SnapshotDto", false));
    for key in ["gpu", "general", "size", "entrypoint", "createdAt"] {
        let mut missing = row.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(!snapshot_schema_valid(&missing, "SnapshotDto", false), "missing {key}");
    }
}

// The pinned analytics schemas contain objects with optional primitive fields.
// Check every fixture field and required member without strengthening that contract.
fn validate_analytics_fixture(body: &Value, name: &str) {
    let spec: Value = serde_json::from_str(include_str!("fixtures/daytona-analytics-schemas.json")).unwrap();
    let schema = &spec["schemas"][name];
    let rows = if name == "models.AggregatedUsage" {
        std::slice::from_ref(body)
    } else {
        body.as_array().expect("analytics fixture must be an array").as_slice()
    };
    for row in rows {
        let object = row.as_object().expect("analytics fixture must be an object");
        if let Some(required) = schema["required"].as_array() {
            for key in required {
                assert!(object.contains_key(key.as_str().unwrap()));
            }
        }
        for (key, value) in object {
            let valid = match schema["properties"][key]["type"].as_str().expect("documented fixture field") {
                "integer" => value.is_i64() || value.is_u64(),
                "number" => value.is_number(),
                "string" => value.is_string(),
                kind => panic!("unsupported analytics schema type {kind}"),
            };
            assert!(valid, "{name}.{key} has invalid type: {value}");
        }
    }
}

// Inject only the vendor HTTP boundary; the host and typed client use real sockets.
struct VendorModule(Arc<StandIn>);
#[async_trait]
impl Module for VendorModule {
    fn version(&self) -> &str {
        "test"
    }
    async fn configure(&self, config: &ProviderConfiguration, _: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
        DaytonaModule.configure(config, self.0.clone()).await
    }
}
struct HostHarness {
    client: drydock::client::Client,
    _dir: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}
impl HostHarness {
    async fn start(vendor: Arc<StandIn>) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = dir.path().join("host.sock");
        let client = drydock::client::Client::unix(&socket).unwrap();
        let host = drydock_host::Host::new(BTreeMap::from([("daytona".into(), Arc::new(VendorModule(vendor)) as Arc<dyn Module>)]));
        let (stop, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            host.serve_unix(socket, unsafe { libc::geteuid() }, async {
                let _ = rx.await;
            })
            .await
            .unwrap();
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while client.hello().await.is_err() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        client
            .configure(
                &serde_json::from_value(json!({
                    "modules":[{"name":"daytona","entrypoint":"daytona"}],
                    "providers":[{"name":"daytona","module":"daytona","settings":{
                        "organization_id":"org-1","ssh_host_key":"ssh-ed25519 AAAA",
                        "egress_probe":{"command":["/usr/local/bin/check-egress"]}
                    },"credential":{"mode":"direct","credential_reference":"test"}}]
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        client.credential("daytona", Secret::new("key-a")).await.unwrap();
        Self { client, _dir: dir, task, stop: Some(stop) }
    }
    async fn finish(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.task.await.unwrap();
    }
}

// A stop/start between polls must lose measured enforcement as soon as either
// preparing or starting is observed, even when the effective policy is unchanged.
#[tokio::test]
async fn fast_restart_invalidates_host_egress_evidence() {
    let vendor = Arc::new(StandIn::default());
    vendor.0.lock().unwrap().probe = Some(json!({"uid":0,"listed_direct":true,"unlisted_canary":false,"raw_dns":false}));
    let host = HostHarness::start(vendor.clone()).await;
    let p = provider(vendor.clone()).await;
    let prep = prepared(p.as_ref(), &credentials(false)).await;
    let mut r = request(prep, "fast-restart");
    r.egress = EgressRequest::DenyAll { direct: vec![Destination::Cidr { cidr: "192.0.2.1/32".parse().unwrap() }] };
    let env = host.client.provision("daytona", &r).await.unwrap();
    for phase in ["starting", "creating"] {
        assert_eq!(host.client.inspect("daytona", &env.id).await.unwrap().egress, Enforcement::Enforced);
        assert_eq!(host.client.list("daytona").await.unwrap()[0].egress, Enforcement::Enforced);
        vendor.0.lock().unwrap().rows.get_mut(&env.id).unwrap()["state"] = json!(phase);
        assert!(matches!(host.client.list("daytona").await.unwrap()[0].state, Observation::Transitioning { .. }));
        vendor.0.lock().unwrap().rows.get_mut(&env.id).unwrap()["state"] = json!("started");
        assert_eq!(host.client.list("daytona").await.unwrap()[0].egress, Enforcement::Advisory);
    }
    host.finish().await;
}

// The exact running/stopped sample is queried only after accounting has settled.
// Zero delay deliberately fails against the same lagging vendor, proving the seam.
#[tokio::test]
async fn conformance_waits_for_settled_billing_windows() {
    use drydock::conformance::{self, Options, Scenario};
    for settle in [0, 4000] {
        let vendor = Arc::new(StandIn::default());
        vendor.0.lock().unwrap().accounting_delay_millis = Some(2000);
        let host = HostHarness::start(vendor.clone()).await;
        let p = provider(vendor.clone()).await;
        let prep = prepared(p.as_ref(), &credentials(false)).await;
        let options = Options {
            request: request(prep, "settled-billing"),
            scenarios: vec![Scenario::Observation],
            fixture_configuration: None,
            null_environment_id: None,
            auth_audit: None,
            billing_sample_millis: 25,
            billing_settle_millis: settle,
            timeouts: conformance::Timeouts { record_seconds: 1, transition_seconds: 1, ..Default::default() },
            echo_relay: false,
            reach_probe: None,
            egress_probe: None,
        };
        let report = conformance::run(&host.client, "daytona", &options).await;
        for name in ["billing_running", "billing_suspended"] {
            let check = report.checks.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("{report:?}"));
            assert_eq!(check.passed, settle > 0, "{check:?}");
        }
        let windows = vendor.0.lock().unwrap().analytics_windows.clone();
        assert_eq!(windows.len(), if settle > 0 { 6 } else { 2 });
        for (start, end) in windows {
            assert!((end - start).num_milliseconds() >= 25, "sample must retain its full duration");
        }
        host.finish().await;
    }
}

// Analytics requires ordered RFC3339 endpoints, including explicit offsets;
// mere presence, numeric epochs and local times do not meet the vendor contract.
#[tokio::test]
async fn analytics_query_formats_are_enforced() {
    let http = StandIn::default();
    let network = http.network().await;
    let client = rigging_tls::client_builder().build().unwrap();
    for query in [
        vec![],
        vec![("from", "2026-10-19T00:00:00Z")],
        vec![("from", "1729296000"), ("to", "1729299600")],
        vec![("from", "2026-10-19T00:00:00"), ("to", "2026-10-19T01:00:00")],
        vec![("from", "2026-10-19T01:00:00Z"), ("to", "2026-10-19T00:00:00Z")],
        vec![("from", "2026-10-19T00:00:00Z"), ("to", "2026-10-19T00:00:00Z")],
    ] {
        let request = client
            .get("https://analytics.app.daytona.io/organization/org-1/usage/aggregated")
            .bearer_auth("key-a")
            .query(&query)
            .build()
            .unwrap();
        assert_eq!(network.http.execute(request, &ChannelLabel::Default).await.unwrap().status(), 400);
        assert_eq!(http.0.lock().unwrap().violations.len(), 1);
        http.0.lock().unwrap().violations.clear();
    }
    let request = client
        .get("https://analytics.app.daytona.io/organization/org-1/usage/aggregated")
        .bearer_auth("key-a")
        .query(&[("from", "2026-10-19T00:00:00+02:00"), ("to", "2026-10-19T01:00:00+02:00")])
        .build()
        .unwrap();
    assert_eq!(network.http.execute(request, &ChannelLabel::Default).await.unwrap().status(), 200);
}

// New providers inherit a lifecycle read that never attempts guest enrichment.
struct InventoryLifecycle(Arc<dyn Provider>);
#[async_trait]
impl Provider for InventoryLifecycle {
    fn capabilities(&self) -> Capabilities {
        self.0.capabilities()
    }
    fn observation(&self) -> ObservationMode {
        self.0.observation()
    }
    async fn prepare(&self, r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
        self.0.prepare(r, c).await
    }
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        self.0.provision(r, c).await
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<ObservedEnvironment>> {
        self.0.list(c).await
    }
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<ObservedEnvironment> {
        self.0.inspect(id, c).await
    }
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        self.0.destroy(id, c).await
    }
    async fn reach(&self, id: &str, c: &Credentials) -> Result<Connection> {
        self.0.reach(id, c).await
    }
    async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream> {
        self.0.relay(id, c).await
    }
}
#[tokio::test]
async fn default_lifecycle_inspection_uses_inventory_without_probing() {
    let http = Arc::new(StandIn::default());
    let p = provider_with_probe(http.clone(), true).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    let env = row(p.provision(request(prep, "default-lifecycle"), &c).await.unwrap());
    let provider = InventoryLifecycle(p);
    let probes = http.0.lock().unwrap().executed.len();
    let row = provider.inspect_after_lifecycle(&env.id, &c).await.unwrap();
    assert_eq!(row.environment.egress, Enforcement::Advisory);
    assert_eq!(http.0.lock().unwrap().executed.len(), probes);
    assert!(matches!(provider.inspect_after_lifecycle("absent", &c).await, Err(ProtocolError::NotFound { .. })));
    http.0.lock().unwrap().failure = Some(401);
    assert!(matches!(provider.inspect_after_lifecycle(&env.id, &c).await, Err(ProtocolError::CredentialRejected { .. })));
}

// Ongoing periods cannot bill time that has not elapsed, even in future windows.
#[tokio::test]
async fn ongoing_usage_does_not_bill_the_future() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let now = chrono::Utc::now();
    let start = now - chrono::Duration::hours(1);
    let end = now + chrono::Duration::hours(1);
    http.0.lock().unwrap().usage_periods = Some(json!([
        {"cpu":1,"ramGB":2,"diskGB":3,"startAt": start.to_rfc3339()}
    ]));
    let period = Period::new(start.into(), end.into()).unwrap();
    let usage = p.operations().usage.unwrap().usage(period, &credentials(false)).await.unwrap();
    let elapsed_hours = (chrono::Utc::now() - start).num_milliseconds() as f64 / 3_600_000.0;
    assert!((1.0..=elapsed_hours).contains(&usage.environment_hours[0].hours));
}

// Masking at the host boundary sees the complete vendor body before truncation,
// including a credential that crosses the old 16 KiB byte boundary. The same
// vendor outage must survive another caller (including the host's poller).
#[tokio::test]
async fn vendor_body_masking_precedes_truncation() {
    let vendor = Arc::new(StandIn::default());
    let host = HostHarness::start(vendor.clone()).await;
    drydock::client::Observer::new(host.client.clone(), None).next().await.unwrap();
    // Place the credential across both historical raw truncation and the
    // current bounded-diagnostic payload cut (which reserves a marker).
    let prefix = json!({"statusCode":400,"message":"key-a trailing","error":"Bad Request"}).to_string().find("key-a").unwrap();
    for boundary in [16384, 16384 - "...<truncated>".len()] {
        let message = format!("{}key-a trailing", "x".repeat(boundary - prefix - 2));
        vendor.0.lock().unwrap().outage = Some((400, message));
        // Force a competing vendor call before the foreground host call. This
        // deterministically covers the poller's one-shot-fault consumption race.
        let p = provider(vendor.clone()).await;
        let ProtocolError::Internal { provider_error, .. } = p.list(&credentials(false)).await.unwrap_err() else {
            panic!("expected body")
        };
        assert!(provider_error.len() > 16384);
        assert_eq!(provider_error.find("key-a"), Some(boundary - 2));
        assert!(provider_error.contains("key-a trailing"));
        let error = host.client.list("daytona").await.unwrap_err();
        let drydock::client::Error::Protocol(ProtocolError::Internal { provider_error, .. }) = error else {
            panic!("expected provider body")
        };
        assert!(provider_error.len() <= 16384);
        assert!(!provider_error.contains("ke"), "even a two-byte credential prefix must not escape");
    }
    host.finish().await;
}

// Malformed successful responses must not turn minted SSH recipes or guest
// command/probe output into ordinary diagnostics in any operator-facing view.
#[tokio::test]
async fn malformed_sensitive_responses_do_not_disclose_values() {
    let http = Arc::new(StandIn::default());
    let p = provider_with_probe(http.clone(), true).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    let env = row(p.provision(request(prep, "malformed-sensitive"), &c).await.unwrap());
    http.0.lock().unwrap().ssh_response = Some(json!({"token":null,"sshCommand":"ssh minted-private-token@gateway"}));
    let error = p.reach(&env.id, &c).await.err().unwrap();
    for view in [error.to_string(), format!("{error:?}"), serde_json::to_string(&error).unwrap()] {
        assert!(!view.contains("minted-private-token"), "{view}");
        assert!(!view.contains("sshCommand"), "{view}");
    }
    for response in [json!({"result":"guest-private-output"}), json!({"exitCode":"invalid","result":"guest-private-output"})] {
        http.0.lock().unwrap().exec_response = Some(response);
        let error = p.operations().exec.unwrap().exec(&env.id, ExecRequest { command: vec!["run".into()] }, &c).await.err().unwrap();
        for view in [error.to_string(), format!("{error:?}"), serde_json::to_string(&error).unwrap()] {
            assert!(!view.contains("guest-private-output"), "{view}");
        }
    }
    http.0.lock().unwrap().exec_response = None;
    http.0.lock().unwrap().rows.get_mut(&env.id).unwrap()["networkBlockAll"] = json!(true);
    http.0.lock().unwrap().probe = Some(json!({"private_output":"guest-private-output"}));
    let error = p.inspect(&env.id, &c).await.unwrap_err();
    for view in [error.to_string(), format!("{error:?}"), serde_json::to_string(&error).unwrap()] {
        assert!(!view.contains("guest-private-output"), "{view}");
    }
}

// Lifecycle fallback succeeds, so its module-level log must contain only the
// category: the host never receives this error to apply credential masking.
#[test]
fn lifecycle_fallback_log_does_not_disclose_provider_body() {
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let logs = Arc::new(Mutex::new(Vec::new()));
    let output = logs.clone();
    let subscriber = tracing_subscriber::fmt().without_time().with_ansi(false).with_writer(move || Capture(output.clone())).finish();
    // This must remain the only global-subscriber installer in this integration
    // binary; another installer would fail. Use the process dispatcher
    // so HTTP/provider tasks and parallel callsite registration are captured too.
    tracing::subscriber::set_global_default(subscriber).unwrap();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let http = Arc::new(StandIn::default());
        let p = provider_with_probe(http.clone(), true).await;
        let c = credentials(false);
        let prep = prepared(p.as_ref(), &c).await;
        http.0.lock().unwrap().probe_http_failure = Some(502);
        http.0.lock().unwrap().probe_failure_message = Some("validation fallback-secret-xyz".into());
        let mut r = request(prep, "fallback-log");
        r.egress = EgressRequest::DenyAll { direct: vec![] };
        p.provision(r, &c).await.unwrap();
    });
    let logs = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("lifecycle succeeded; egress measurement failed"), "{logs}");
    assert!(!logs.contains("fallback-secret-xyz"), "{logs}");
}

// Concurrent provision retries both bootstrap the same started sandbox, without
// holding a host-local creation lock. The baked supervisor enforces singleton.
#[tokio::test]
async fn concurrent_bootstraps_after_start_and_resume() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    let request = request(prep, "concurrent-bootstrap");
    let (first, second) = tokio::join!(p.provision(request.clone(), &c), p.provision(request, &c));
    let first = row(first.unwrap());
    assert_eq!(first.id, row(second.unwrap()).id);
    assert_eq!(http.0.lock().unwrap().bootstraps, 2);
    let operations = p.operations();
    let lifecycle = operations.suspend_resume.unwrap();
    let token = lifecycle.suspend(&first.id, &c).await.unwrap();
    let (first_resume, second_resume) =
        tokio::join!(lifecycle.resume(&first.id, token.clone(), &c), lifecycle.resume(&first.id, token, &c));
    first_resume.unwrap();
    second_resume.unwrap();
    assert_eq!(http.0.lock().unwrap().bootstraps, 4);
}

// Unpublished, mutable and instruction-injecting tools references must refuse
// before contacting Daytona, as must instruction-injecting base references.
#[tokio::test]
async fn prepare_refuses_unpublished_or_unsafe_tools() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let c = credentials(false);
    for tools in [
        "unpublished".into(),
        "tools:latest".into(),
        format!("tools\nRUN bad@sha256:{}", "a".repeat(64)),
        format!("tools@sha256:{}", "a".repeat(63)),
    ] {
        assert!(
            p.prepare(
                PrepareRequest {
                    platform: Some(Platform::new("linux", "amd64")),
                    route: Some(ImageRouteKind::RegistryPull),
                    image_pull: None,
                    size: daytona_size(),
                    image_digest: format!("ubuntu@sha256:{}", "a".repeat(64)),
                    tools_digest: tools
                },
                &c
            )
            .await
            .is_err()
        );
    }
    assert!(
        p.prepare(
            PrepareRequest {
                platform: Some(Platform::new("linux", "amd64")),
                route: Some(ImageRouteKind::RegistryPull),
                image_pull: None,
                size: daytona_size(),
                image_digest: format!("ubuntu\nRUN bad@sha256:{}", "a".repeat(64)),
                tools_digest: tools_image('a')
            },
            &c
        )
        .await
        .is_err()
    );
    assert_eq!(http.0.lock().unwrap().requests, 0);
}

async fn provider_with_settings(http: Arc<dyn HttpClient>, settings: Value) -> Arc<dyn Provider> {
    let mut config: ProviderConfiguration = serde_json::from_value(json!({"name":"daytona","module":"daytona","settings":{"organization_id":"org-1","ssh_host_key":"ssh-ed25519 AAAA"},"credential":{"mode":"direct","credential_reference":"test"}})).unwrap();
    config.settings.extend(settings.as_object().unwrap().clone());
    DaytonaModule.configure(&config, http).await.unwrap()
}
fn push_request(image_digest: String, tools_digest: String) -> PrepareRequest {
    PrepareRequest {
        platform: Some(Platform::new("linux", "amd64")),
        route: Some(ImageRouteKind::ProviderPush),
        image_pull: lab_pull(),
        size: daytona_size(),
        image_digest,
        tools_digest,
    }
}

// Push route (#103): the host appends the tools layer to a private base that
// Daytona cannot reach, uploads it in bounded chunks with minted push access,
// waits out the registry's visibility delay, and creates the snapshot by
// digest. The stand-in refuses anything else Daytona would. Another host then
// converges on the same snapshot without pushing again, and it launches.
#[tokio::test]
async fn pushed_image_becomes_snapshot_by_digest() {
    let http = Arc::new(StandIn::default());
    let (base, base_manifests, tools, tools_manifests) = {
        let mut s = http.0.lock().unwrap();
        let (base, base_manifests) = seed(&mut s, lab_base(&["arm64", "amd64"]));
        let (tools, tools_manifests) = seed(&mut s, published_tools());
        (base, base_manifests, tools, tools_manifests)
    };
    let chunk = 7;
    let p = provider_with_settings(http.clone(), json!({"push_chunk_bytes": chunk})).await;
    let c = credentials(false);
    let prep = p.prepare(push_request(base.clone(), tools.clone()), &c).await.unwrap();

    {
        let s = http.0.lock().unwrap();
        let image = s.snapshot_requests[0]["imageName"].as_str().unwrap().to_owned();
        let (name, digest) = image.split_once('@').unwrap();
        let repository = name.strip_prefix("harbor.invalid/").unwrap();
        let (_, pushed) = &s.oci.manifests[&(HARBOR.to_owned(), repository.to_owned(), digest.to_owned())];
        let pushed: Value = serde_json::from_slice(pushed).unwrap();
        // The base's amd64 layers, then the tools layer in the base's (Docker) media type.
        let digests = |m: &Value| m["layers"].as_array().unwrap().iter().map(|l| l["digest"].clone()).collect::<Vec<_>>();
        let mut expected = digests(&base_manifests["amd64"]);
        expected.extend(digests(&tools_manifests["amd64"]));
        assert_eq!(digests(&pushed), expected);
        assert!(pushed["layers"].as_array().unwrap().iter().all(|l| l["mediaType"] == DOCKER_LAYER));
        assert!(s.oci.patch_sizes.len() > s.oci.blobs.len() / 4 && s.oci.patch_sizes.iter().all(|n| *n <= chunk));
        assert_eq!(s.oci.mints, 1);
    }

    let other_host = provider(http.clone()).await;
    assert_eq!(other_host.prepare(push_request(base, tools), &c).await.unwrap(), prep);
    assert_eq!(http.0.lock().unwrap().oci.mints, 1);
    assert!(matches!(other_host.provision(request(prep, "pushed"), &c).await.unwrap(), Provisioned::Created(_)));
}

// Contract item 4: a platform Daytona cannot run, an image over the snapshot
// limit, and push access that expires before the upload completes are each
// the typed image refusal, and none of them creates a snapshot.
#[tokio::test]
async fn push_route_refusals_are_typed() {
    let http = Arc::new(StandIn::default());
    let (arm_only, huge, base, tools) = {
        let mut s = http.0.lock().unwrap();
        let arm_only = seed(&mut s, Seed { repository: "crew/arm", ..lab_base(&["arm64"]) }).0;
        let huge = seed(&mut s, Seed { repository: "crew/huge", declared_layer_size: Some(7 << 30), ..lab_base(&["amd64"]) }).0;
        (arm_only, huge, seed(&mut s, lab_base(&["amd64"])).0, seed(&mut s, published_tools()).0)
    };
    let p = provider(http.clone()).await;
    let c = credentials(false);
    let refusal = |result: Result<Prepared>| match result {
        Err(ProtocolError::ImageRefused { refusal, .. }) => refusal,
        other => panic!("{other:?}"),
    };
    let arm = Platform::new("linux", "arm64");
    assert_eq!(
        refusal(p.prepare(PrepareRequest { platform: Some(arm.clone()), ..push_request(base.clone(), tools.clone()) }, &c).await),
        ImageRefusal::UnsupportedPlatform { platform: arm }
    );
    assert_eq!(
        refusal(p.prepare(push_request(arm_only, tools.clone()), &c).await),
        ImageRefusal::UnsupportedPlatform { platform: Platform::new("linux", "amd64") }
    );
    // Three declared 7 GiB layers exceed Daytona's default 20 GiB snapshot maximum.
    assert!(matches!(
        refusal(p.prepare(push_request(huge, tools.clone()), &c).await),
        ImageRefusal::TooLarge { bytes, limit_bytes } if bytes > 21 << 30 && limit_bytes == 20 << 30
    ));
    assert_eq!(http.0.lock().unwrap().oci.mints, 0, "refused before minting push access");
    http.0.lock().unwrap().oci.push_lifetime = Some(chrono::TimeDelta::seconds(10));
    assert_eq!(refusal(p.prepare(push_request(base, tools), &c).await), ImageRefusal::PushCredentialExpired);
    assert!(http.0.lock().unwrap().snapshot_requests.is_empty());
}

// A source blob is copied only when it can be verified inside bounded
// requests: a registry that ignores Range for a blob larger than one chunk,
// and a blob whose bytes do not match its digest, are each refused before the
// upload commits, so Daytona's registry never holds the layer and no snapshot
// is created.
#[tokio::test]
async fn unverifiable_source_blobs_are_refused() {
    let http = Arc::new(StandIn::default());
    let (base, base_manifests, tools) = {
        let mut s = http.0.lock().unwrap();
        let (base, base_manifests) = seed(&mut s, lab_base(&["amd64"]));
        (base, base_manifests, seed(&mut s, published_tools()).0)
    };
    let layer = base_manifests["amd64"]["layers"][0]["digest"].as_str().unwrap().to_owned();
    let p = provider_with_settings(http.clone(), json!({"push_chunk_bytes": 7})).await;
    let c = credentials(false);
    let refused_unstored = |result: Result<Prepared>| {
        assert!(matches!(result, Err(ProtocolError::Internal { .. })), "{result:?}");
        assert!(!http.0.lock().unwrap().oci.blobs.contains_key(&(HARBOR.to_owned(), layer.clone())));
    };
    http.0.lock().unwrap().oci.ignore_range = true;
    refused_unstored(p.prepare(push_request(base.clone(), tools.clone()), &c).await);
    {
        let mut s = http.0.lock().unwrap();
        s.oci.ignore_range = false;
        let stored = s.oci.blobs.get_mut(&(LAB.to_owned(), layer.clone())).unwrap();
        let mut corrupt = stored.to_vec();
        corrupt[0] ^= 1;
        *stored = Bytes::from(corrupt);
    }
    refused_unstored(p.prepare(push_request(base, tools), &c).await);
    assert!(http.0.lock().unwrap().snapshot_requests.is_empty());
}

// The stand-in itself enforces what Daytona documents for pushed images: a
// snapshot names an image by digest only, and only once the registry serves
// it; push robots stop authenticating when they expire.
#[tokio::test]
async fn standin_enforces_push_contract() {
    let http = StandIn::default();
    let client = reqwest::Client::new();
    let send = |request: reqwest::Request| http.execute(request, &ChannelLabel::Default);
    let access = send(
        client.get("https://app.daytona.io/api/docker-registry/registry-push-access?regionId=eu").bearer_auth("key-a").build().unwrap(),
    )
    .await
    .unwrap();
    let access: Value = serde_json::from_slice(access.body()).unwrap();
    let robot =
        |user: &str, secret: &str| client.get("https://harbor.invalid/service/token").basic_auth(user, Some(secret)).build().unwrap();
    let user = access["username"].as_str().unwrap();
    assert_eq!(send(robot(user, access["secret"].as_str().unwrap())).await.unwrap().status(), 200);
    http.0.lock().unwrap().oci.robots.get_mut(user).unwrap().1 = chrono::Utc::now();
    assert_eq!(send(robot(user, access["secret"].as_str().unwrap())).await.unwrap().status(), 401);

    let (image, _) =
        seed(&mut http.0.lock().unwrap(), Seed { host: HARBOR, repository: "daytona-transient/drydock-vessel", ..lab_base(&["amd64"]) });
    let manifest_digest = {
        let s = http.0.lock().unwrap();
        let (_, index) = &s.oci.manifests
            [&(HARBOR.to_owned(), "daytona-transient/drydock-vessel".to_owned(), image.split_once('@').unwrap().1.to_owned())];
        let index: Value = serde_json::from_slice(index).unwrap();
        index["manifests"][0]["digest"].as_str().unwrap().to_owned()
    };
    let name = "harbor.invalid/daytona-transient/drydock-vessel";
    let snapshot = |image: String| {
        let body = json!({"name":"pushed","imageName":image,"regionId":"eu","sandboxClass":"container","cpu":2,"memory":4,"disk":10});
        client.post("https://app.daytona.io/api/snapshots").bearer_auth("key-a").json(&body).build().unwrap()
    };
    http.0.lock().unwrap().oci.pending_reads.insert(manifest_digest.clone(), 1);
    for refused in [name.to_owned(), format!("{name}:latest"), format!("{name}:v1@{manifest_digest}"), format!("{name}@{manifest_digest}")]
    {
        assert_eq!(send(snapshot(refused.clone())).await.unwrap().status(), 400, "{refused}");
    }
    http.0.lock().unwrap().oci.pending_reads.clear();
    assert_eq!(send(snapshot(format!("{name}@{manifest_digest}"))).await.unwrap().status(), 201);
    http.0.lock().unwrap().violations.clear();
    http.0.lock().unwrap().snapshot_requests.clear();
}

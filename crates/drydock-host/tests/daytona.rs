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
}
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
                ])
                .await
            })
            .await
    }
    fn respond(state: &Mutex<State>, request: reqwest::Request) -> http::Response<Bytes> {
        let mut s = state.lock().unwrap();
        s.requests += 1;
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
        if let Some(status) = s.failure.take() {
            return response(status, json!({"statusCode":status,"message":"key-a must never be echoed","error":"Too Many Requests"}));
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
                s.activations += 1;
                // Activation is asynchronous; a successful POST may still say inactive.
                response(200, s.snapshots.values().next().cloned().unwrap_or(Value::Null))
            }
            ("POST", "/api/snapshots") => {
                let Some(name) = body["name"].as_str() else { reject!("missing snapshot name"); };
                s.snapshot_requests.push(body.clone());
                if s.snapshots.contains_key(name) {
                    return response(409, json!({"statusCode":409}));
                }
                let snapshot = json!({"id":format!("snap-{}",s.snapshots.len()+1),"name":name,"state":"active","cpu":body["cpu"],"mem":body["memory"],"disk":body["disk"]});
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
                response(200, json!({"token":format!("ephemeral-{}",s.mints),"expiresAt":"2026-10-19T12:05:00Z"}))
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
                    return response(status, json!({"statusCode":status,"message":"Bad Gateway","error":"Bad Gateway"}));
                }
                if s.require_bootstrap_budget && command.contains("nohup") && timeout < 20 {
                    return response(200, json!({"exitCode":124,"result":"bootstrap exceeded vendor deadline"}));
                }
                if command.contains("nohup") {
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
                assert!(body["imageName"].as_str().is_some_and(|v| v.contains("@sha256:")), "snapshot must pin the image digest");
                assert_eq!(body["sandboxClass"], "container");
                assert_eq!(body["regionId"], "eu");
            }
            assert!(state.ssh_expiries.iter().all(|v| v.as_deref() == Some("5")), "reach must request a short expiry");
            assert!(state.executed.iter().filter(|c| c.contains("nohup")).all(|c| c.contains("--socket /run/drydock/agent.sock")));
            let spec: Value = serde_json::from_str(include_str!("fixtures/daytona-schemas.json")).unwrap();
            for row in &state.fixture_rows {
                for key in spec["schemas"]["Sandbox"]["required"].as_array().unwrap() {
                    assert!(!row[key.as_str().unwrap()].is_null(), "invalid vendor fixture missing {key}");
                }
            }
        }
    }
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
    let config:ProviderConfiguration = serde_json::from_value(json!({"name":"daytona","module":"daytona","settings":{"organization_id":"org-1","ssh_host_key":"ssh-ed25519 AAAA","agent_command":"agent --socket /run/drydock/agent.sock"},"credential":{"mode":"direct","credential_reference":"test"}})).unwrap();
    let mut config = config;
    if probe {
        config.settings.insert("egress_probe".into(), json!({"command":["/usr/local/bin/check-egress"]}));
    }
    DaytonaModule.configure(&config, http).await.unwrap()
}
fn daytona_size() -> Size {
    Size { cpus: 2.0, memory_bytes: 4 << 30, disk_bytes: 10 << 30 }
}
async fn prepared(p: &dyn Provider, c: &Credentials) -> Prepared {
    let request = PrepareRequest {
        size: daytona_size(),
        image_digest: format!("docker.io/test/image@sha256:{}", "a".repeat(64)),
        tools_digest: "sha256:tools".into(),
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
            let Connection::Ssh { user, endpoint, .. } = p.reach(&id, &c).await.unwrap() else { panic!("SSH recipe required") };
            assert_eq!(user.expose(), expected);
            assert_eq!(endpoint, "ssh.app.daytona.io:22");
            let recipe = Reach::Ssh { user, endpoint, host_key: "key".into() };
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
    let mut r =
        PrepareRequest { size: daytona_size(), image_digest: format!("image@sha256:{}", "b".repeat(64)), tools_digest: "tools-a".into() };
    let (x, y) = tokio::join!(a.prepare(r.clone(), &c), b.prepare(r.clone(), &c));
    let x = x.unwrap();
    assert_eq!(x, y.unwrap());
    assert_eq!(http.0.lock().unwrap().snapshots.len(), 1);
    r.tools_digest = "tools-b".into();
    let other = a.prepare(r, &c).await.unwrap();
    assert_ne!(x.id, other.id);
    assert_eq!(http.0.lock().unwrap().snapshots.len(), 2);
    assert!(
        a.prepare(PrepareRequest { size: daytona_size(), image_digest: "image:latest".into(), tools_digest: "tools".into() }, &c)
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
        let base =
            PrepareRequest { image_digest: format!("image@sha256:{}", "c".repeat(64)), tools_digest: "tools".into(), size: size.clone() };
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
        let r = PrepareRequest { image_digest: prep.image_digest, tools_digest: prep.tools_digest, size: daytona_size() };
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
        let preparation =
            PrepareRequest { image_digest: prep.image_digest.clone(), tools_digest: prep.tools_digest.clone(), size: size.clone() };
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
    let result =
        p.prepare(PrepareRequest { size: daytona_size(), image_digest: prep.image_digest, tools_digest: prep.tools_digest }, &c).await;
    assert!(result.is_ok());
    assert_eq!(http.0.lock().unwrap().activations, 1);
    assert!(start.elapsed() >= std::time::Duration::from_secs(2));
}

// Bootstrap's vendor deadline must contain its flock and readiness budgets.
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
            p.prepare(PrepareRequest { size: daytona_size(), image_digest: prep.image_digest, tools_digest: prep.tools_digest }, &c).await,
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

// A socket inode without a listener must not count as successful bootstrap.
// Execute the actual emitted guest script in a disposable local directory.
#[tokio::test]
async fn stale_socket_fails_bootstrap_liveness() {
    if std::process::Command::new("flock").arg("--version").output().is_err() {
        return;
    }
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    p.provision(request(prep, "stale"), &c).await.unwrap();
    let script = http.0.lock().unwrap().executed.iter().find(|v| v.contains("nohup")).unwrap().clone();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
    assert!(socket.exists());
    let status = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(script.replace("agent --socket /run/drydock/agent.sock", "true").replace("/run/drydock", dir.path().to_str().unwrap()))
        .status()
        .await
        .unwrap();
    assert!(!status.success(), "stale socket was accepted as a live agent");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let status = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(script.replace("agent --socket /run/drydock/agent.sock", "true").replace("/run/drydock", dir.path().to_str().unwrap()))
        .status()
        .await
        .unwrap();
    assert!(status.success(), "an actual listening agent was not accepted");
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

// The trusted bootstrap preflight has a safe public diagnostic while preserving
// its raw merged output inside the redacting field.
#[tokio::test]
async fn missing_python_has_a_public_bootstrap_diagnostic() {
    let http = Arc::new(StandIn::default());
    let p = provider(http.clone()).await;
    let c = credentials(false);
    let prep = prepared(p.as_ref(), &c).await;
    http.0.lock().unwrap().command_exit = Some(2);
    http.0.lock().unwrap().command_output = Some("missing-python3\n".into());
    let Err(ProtocolError::CommandFailed { reason, exit_code: 2, output }) = p.provision(request(prep, "missing-tool"), &c).await else {
        panic!("bootstrap must fail")
    };
    assert!(reason.contains("missing python3"));
    assert_eq!(output.expose(), "missing-python3\n");
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
                        "agent_command":"agent --socket /run/drydock/agent.sock",
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

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
    rows: BTreeMap<String, Value>,
    creates: usize,
    bootstraps: usize,
    mints: usize,
    requests: usize,
    failure: Option<u16>,
    executed: Vec<String>,
    probe: Option<Value>,
    hide_label_once: bool,
}
#[derive(Default)]
struct StandIn(Mutex<State>);
#[async_trait]
impl HttpClient for StandIn {
    async fn execute(&self, request: reqwest::Request, _: &ChannelLabel) -> std::result::Result<http::Response<Bytes>, String> {
        tokio::task::yield_now().await;
        let mut s = self.0.lock().unwrap();
        s.requests += 1;
        // Daytona requires bearer auth for both API and toolbox requests.
        assert!(matches!(
            request.headers().get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer key-a" | "Bearer key-b" | "Bearer placeholder")
        ));
        let response = |status, body: Value| {
            Ok(http::Response::builder()
                .status(status)
                .header("x-ratelimit-limit-authenticated", "10000")
                .header("x-ratelimit-remaining-authenticated", "9999")
                .header("x-ratelimit-reset-authenticated", "60")
                .header("retry-after", "17")
                .body(Bytes::from(body.to_string()))
                .unwrap())
        };
        if let Some(status) = s.failure.take() {
            return response(status, json!({"statusCode":status,"message":"key-a must never be echoed"}));
        }
        let method = request.method().as_str();
        let path = request.url().path();
        let body: Value = request.body().and_then(|b| b.as_bytes()).map(|v| serde_json::from_slice(v).unwrap()).unwrap_or(Value::Null);
        if method == "POST" {
            assert_eq!(request.headers().get("content-type").is_some(), !body.is_null());
        }
        match (method, path) {
            ("GET", p) if p.starts_with("/api/snapshots/") => {
                let key = p.trim_start_matches("/api/snapshots/");
                let row = s.snapshots.get(key).or_else(|| s.snapshots.values().find(|v| v["id"].as_str() == Some(key)));
                response(if row.is_some() { 200 } else { 404 }, row.cloned().unwrap_or(Value::Null))
            }
            ("POST", "/api/snapshots") => {
                assert!(body["imageName"].as_str().unwrap().contains("@sha256:"));
                assert_eq!(body["sandboxClass"], "container");
                assert_eq!(body["regionId"], "eu");
                let name = body["name"].as_str().unwrap();
                if s.snapshots.contains_key(name) {
                    return response(409, json!({"statusCode":409}));
                }
                let snapshot = json!({"id":format!("snap-{}",s.snapshots.len()+1),"name":name,"state":"active"});
                s.snapshots.insert(name.into(), snapshot.clone());
                response(201, snapshot)
            }
            ("GET", "/api/sandbox") => {
                if s.hide_label_once {
                    s.hide_label_once = false;
                    return response(200, json!({"items":[],"nextCursor":null}));
                }
                let labels =
                    request.url().query_pairs().find(|(k, _)| k == "labels").map(|(_, v)| serde_json::from_str::<Value>(&v).unwrap());
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
                for key in [
                    "snapshot",
                    "labels",
                    "target",
                    "cpu",
                    "memory",
                    "disk",
                    "networkAllowList",
                    "networkBlockAll",
                    "autoStopInterval",
                    "autoDeleteInterval",
                ] {
                    assert!(!body[key].is_null(), "missing {key}");
                }
                assert_eq!(body["autoStopInterval"], 0);
                assert_eq!(body["autoDeleteInterval"], -1);
                let list = body["networkAllowList"].as_str().unwrap();
                for cidr in list.split(',').filter(|c| !c.is_empty()) {
                    let (ip, bits) = cidr.split_once('/').unwrap();
                    ip.parse::<std::net::Ipv4Addr>().unwrap();
                    assert!(bits.parse::<u8>().unwrap() <= 32);
                }
                if list.is_empty() {
                    assert_eq!(body["networkBlockAll"], true);
                }
                if s.rows.values().any(|v| v["name"] == body["name"]) {
                    return response(409, json!({"statusCode":409,"message":"name already exists"}));
                }
                s.creates += 1;
                let id = format!("sandbox-{}", s.creates);
                let row = json!({"id":id,"name":body["name"],"labels":body["labels"],"state":"started","cpu":body["cpu"],"memory":body["memory"],"disk":body["disk"],"networkAllowList":body["networkAllowList"],"networkBlockAll":body["networkBlockAll"],"updatedAt":"2026-10-19T12:00:00Z"});
                s.rows.insert(id, row.clone());
                response(201, row)
            }
            ("GET", p) if p.starts_with("/api/sandbox/") => {
                let id = p.trim_start_matches("/api/sandbox/");
                let row = s.rows.get(id).or_else(|| s.rows.values().find(|v| v["name"].as_str() == Some(id)));
                response(if row.is_some() { 200 } else { 404 }, row.cloned().unwrap_or(Value::Null))
            }
            ("DELETE", p) if p.starts_with("/api/sandbox/") => {
                let row = s.rows.remove(p.trim_start_matches("/api/sandbox/"));
                response(if row.is_some() { 200 } else { 404 }, row.unwrap_or(Value::Null))
            }
            ("POST", p) if p.ends_with("/ssh-access") => {
                assert!(request.url().query_pairs().any(|(k, v)| k == "expiresInMinutes" && v == "5"));
                s.mints += 1;
                response(200, json!({"token":format!("ephemeral-{}",s.mints),"expiresAt":"2026-10-19T12:05:00Z"}))
            }
            ("POST", p) if p.ends_with("/stop") || p.ends_with("/start") => {
                let id = p.trim_start_matches("/api/sandbox/").split('/').next().unwrap();
                let row = s.rows.get_mut(id).unwrap();
                row["state"] = json!(if p.ends_with("/stop") { "stopped" } else { "started" });
                response(200, row.clone())
            }
            ("POST", p) if p.starts_with("/toolbox/") && p.ends_with("/process/execute") => {
                let command = body["command"].as_str().unwrap();
                assert_eq!(body["timeout"], 10);
                if command.contains("nohup") {
                    s.bootstraps += 1;
                    assert!(command.contains("--socket /run/drydock/agent.sock"));
                }
                s.executed.push(command.into());
                let output = if command.starts_with("test \"$(id -u)\"") {
                    s.probe.clone().unwrap_or(Value::Null).to_string()
                } else {
                    "guest output".into()
                };
                response(200, json!({"exitCode":0,"result":output}))
            }
            ("GET", "/api/organizations/org-1/usage") => response(
                200,
                json!({"regionUsage":[{"regionId":"eu","sandboxClass":"container","currentCpuUsage":2,"totalCpuQuota":10,"currentMemoryUsage":4,"totalMemoryQuota":20,"currentDiskUsage":10,"totalDiskQuota":30}],"currentSnapshotUsage":1,"totalSnapshotQuota":100,"currentVolumeUsage":0,"totalVolumeQuota":100}),
            ),
            ("GET", "/organization/org-1/usage/aggregated") => {
                assert!(request.url().query_pairs().any(|(k, v)| k == "from" && v == "2026-10-19T00:00:00Z"));
                response(
                    200,
                    json!({"totalCPUSeconds":7200,"totalRAMGBSeconds":14400,"totalDiskGBSeconds":36000,"totalGPUSeconds":0,"totalPrice":0.0123,"sandboxCount":1}),
                )
            }
            _ => panic!("unexpected vendor request: {method} {path}"),
        }
    }
}
fn credentials(proxied: bool) -> Credentials {
    if proxied {
        Credentials::new(CredentialMode::Proxied { proxy_url: "http://proxy".into(), placeholder_token: Secret::new("placeholder") })
    } else {
        Credentials { mode: CredentialMode::Direct { credential_reference: "test".into() }, value: Some(Secret::new("key-a")) }
    }
}
async fn provider(http: Arc<StandIn>) -> Arc<dyn Provider> {
    provider_with_probe(http, false).await
}
async fn provider_with_probe(http: Arc<StandIn>, probe: bool) -> Arc<dyn Provider> {
    let config:ProviderConfiguration = serde_json::from_value(json!({"name":"daytona","module":"daytona","settings":{"organization_id":"org-1","ssh_host_key":"ssh-ed25519 AAAA","agent_command":"agent --socket /run/drydock/agent.sock"},"credential":{"mode":"direct","credential_reference":"test"}})).unwrap();
    let mut config = config;
    if probe {
        config.settings.insert("egress_probe".into(), json!({"command":["/usr/local/bin/check-egress"]}));
    }
    DaytonaModule.configure(&config, http).await.unwrap()
}
async fn prepared(p: &dyn Provider, c: &Credentials) -> Prepared {
    let request =
        PrepareRequest { image_digest: format!("docker.io/test/image@sha256:{}", "a".repeat(64)), tools_digest: "sha256:tools".into() };
    let first = p.prepare(request.clone(), c).await.unwrap();
    assert_eq!(p.prepare(request, c).await.unwrap(), first);
    first
}
fn request(prepared: Prepared, label: &str) -> ProvisionRequest {
    ProvisionRequest {
        label: label.into(),
        prepared,
        size: Size { cpus: 2.0, memory_bytes: 4 << 30, disk_bytes: 10 << 30 },
        egress: EgressRequest::default(),
        ssh_public_key: None,
    }
}
fn row(p: Provisioned) -> Environment {
    match p {
        Provisioned::Created(e) | Provisioned::Existing(e) => e,
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
        assert_eq!(quota.resources[0].limit, 10.0);
        let period = Period::new("2026-10-19T00:00:00Z".parse().unwrap(), "2026-10-20T00:00:00Z".parse().unwrap()).unwrap();
        assert_eq!(ops.usage.unwrap().usage(period, &c).await.unwrap().totals.unwrap().cost_usd, 0.0123);
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
        (400, "refused"),
        (401, "credential_rejected"),
        (402, "quota_exhausted"),
        (403, "credential_rejected"),
        (404, "not_found"),
        (409, "refused"),
        (422, "refused"),
        (429, "rate_limited"),
        (500, "unavailable"),
    ] {
        http.0.lock().unwrap().failure = Some(status);
        let before = http.0.lock().unwrap().requests;
        let e = p.list(&c).await.unwrap_err();
        assert_eq!(e.class(), class);
        assert!(!serde_json::to_string(&e).unwrap().contains("key-a"));
        if status == 429 {
            assert_eq!(e.retry_after(), Some(17));
        }
        assert_eq!(http.0.lock().unwrap().requests, before + 1);
    }
}

// CIDR/host rules are IPv4-only and ports are never silently widened. The
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
    for (state, reason, expected) in [
        ("error", "out of memory", Observation::Gone { cause: GoneCause::HostOutOfMemory }),
        ("error", "evicted by provider", Observation::Gone { cause: GoneCause::EvictedByProvider }),
        ("error", "runner unreachable", Observation::Unknown { reason: UnknownReason::HostUnreachable }),
        ("build_failed", "unknown vendor error", Observation::Unknown { reason: UnknownReason::ProviderApiError }),
        ("paused", "", Observation::Stopped { cause: StopCause::PausedByProvider }),
        ("creating", "", Observation::Unknown { reason: UnknownReason::ProviderApiError }),
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
    let result = other.provision(r, &c).await.unwrap();
    assert!(matches!(result, Provisioned::Existing(_)));
    assert_eq!(row(result).id, id);
    assert_eq!(http.0.lock().unwrap().creates, 1);
}

// Concurrent prepare at independent hosts converges on the digest-pair name;
// changing the tools digest must produce a different snapshot.
#[tokio::test]
async fn preparation_converges_by_digest_pair() {
    let http = Arc::new(StandIn::default());
    let a = provider(http.clone()).await;
    let b = provider(http.clone()).await;
    let c = credentials(false);
    let mut r = PrepareRequest { image_digest: format!("image@sha256:{}", "b".repeat(64)), tools_digest: "tools-a".into() };
    let (x, y) = tokio::join!(a.prepare(r.clone(), &c), b.prepare(r.clone(), &c));
    let x = x.unwrap();
    assert_eq!(x, y.unwrap());
    assert_eq!(http.0.lock().unwrap().snapshots.len(), 1);
    r.tools_digest = "tools-b".into();
    let other = a.prepare(r, &c).await.unwrap();
    assert_ne!(x.id, other.id);
    assert_eq!(http.0.lock().unwrap().snapshots.len(), 2);
    assert!(a.prepare(PrepareRequest { image_digest: "image:latest".into(), tools_digest: "tools".into() }, &c).await.is_err());
}

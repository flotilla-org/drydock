use drydock_host::module::{Connection, HttpClient, ObservationMode, ObservedEnvironment, Provisioned};
use drydock_host::{Host, reference};
use drydock_protocol::*;
use futures::{StreamExt, stream::BoxStream};
use reqwest::{Client, Method, Response};
use serde_json::{Value, json};
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

struct Harness {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    client: Client,
    task: tokio::task::JoinHandle<()>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}
impl Harness {
    async fn start() -> Self {
        Self::with_uid(unsafe { libc::geteuid() }).await
    }
    async fn with_uid(uid: u32) -> Self {
        Self::with_host(Host::new(reference::registry()), uid).await
    }
    async fn with_host(host: Host, uid: u32) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("host.sock");
        let (stop, rx) = tokio::sync::oneshot::channel();
        let socket = path.clone();
        let task = tokio::spawn(async move {
            host.serve_unix(socket, uid, async {
                let _ = rx.await;
            })
            .await
            .unwrap();
        });
        let client = rigging_tls::client_builder().unix_socket(path.clone()).timeout(Duration::from_secs(30)).build().unwrap();
        wait_hello(&client).await;
        Self { _dir: dir, path, client, task, stop: Some(stop) }
    }

    async fn send(&self, method: Method, path: &str, body: Value) -> Response {
        self.client.request(method, format!("http://localhost/v1{path}")).json(&body).send().await.unwrap()
    }
    async fn ok(&self, method: Method, path: &str, body: Value, status: u16) -> Response {
        let r = self.send(method, path, body).await;
        assert_eq!(r.status().as_u16(), status, "{path}");
        r
    }
    async fn configure(&self, providers: Vec<Value>) {
        self.ok(Method::PUT, "/config", json!({"modules":[{"name":"memory","entrypoint":"reference"}],"providers":providers}), 204).await;
    }
    async fn credential(&self, p: &str, value: &str) {
        self.ok(Method::PUT, &format!("/providers/{p}/credential"), json!({"value":value}), 204).await;
    }
    async fn hello(&self) -> Hello {
        self.ok(Method::GET, "/hello", Value::Null, 200).await.json().await.unwrap()
    }
    async fn normal(&self) {
        self.configure(vec![provider("a", json!({})), provider("b", json!({}))]).await;
        self.credential("a", "one").await;
        self.credential("b", "two").await;
    }
    async fn prepared(&self, p: &str) -> Prepared {
        self.ok(Method::POST, &format!("/providers/{p}/prepare"), json!({"image_digest":"sha256:image","tools_digest":"sha256:tools"}), 200)
            .await
            .json()
            .await
            .unwrap()
    }
    async fn provision(&self, p: &str, label: &str, prepared: &Prepared, status: u16) -> Environment {
        self.ok(Method::POST, &format!("/providers/{p}/environments"), request(label, prepared), status).await.json().await.unwrap()
    }
    async fn stream(&self, since: Option<&str>) -> Records {
        let mut req = self.client.get("http://localhost/v1/events");
        if let Some(s) = since {
            req = req.query(&[("since", s)]);
        }
        let r = req.send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["content-type"], "application/x-ndjson");
        Records { stream: r.bytes_stream().boxed(), buffer: vec![] }
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.task.abort();
    }
}
fn provider(name: &str, settings: Value) -> Value {
    json!({"name":name,"module":"memory","settings":settings,"credential":{"mode":"direct","credential_reference":"embedder:test"}})
}
fn request(label: &str, p: &Prepared) -> Value {
    json!({"label":label,"prepared":p,"size":{"cpus":1.0,"memory_bytes":1024,"disk_bytes":0}})
}
struct Records {
    stream: BoxStream<'static, std::result::Result<axum::body::Bytes, reqwest::Error>>,
    buffer: Vec<u8>,
}
impl Records {
    async fn next(&mut self) -> ObserveRecord {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(n) = self.buffer.iter().position(|b| *b == b'\n') {
                    let line: Vec<_> = self.buffer.drain(..=n).collect();
                    return serde_json::from_slice(&line).unwrap();
                }
                self.buffer.extend(self.stream.next().await.unwrap().unwrap());
            }
        })
        .await
        .unwrap()
    }
}
fn cursor(record: &ObserveRecord) -> &str {
    match record {
        ObserveRecord::Event { event } => &event.cursor,
        ObserveRecord::Snapshot { cursor, .. } => cursor,
    }
}

// ADR 0070: hello reports configured module/provider capabilities and readiness;
// Direct credentials arrive separately and refreshing them preserves live resources.
#[tokio::test]
async fn hello_configuration_credentials_and_atomic_rejection() {
    let h = Harness::start().await;
    let empty: Hello = h.hello().await;
    assert!(empty.is_compatible());
    assert!(empty.providers.is_empty());
    h.configure(vec![provider("a", json!({})), provider("b", json!({}))]).await;
    let hello: Hello = h.hello().await;
    assert_eq!(hello.modules[0].name, "memory");
    assert_eq!(hello.providers.len(), 2);
    assert!(hello.providers.iter().all(|p| matches!(p.readiness, Readiness::MissingCredential { .. })));
    h.ok(Method::GET, "/providers/a/environments", Value::Null, 503).await;
    h.ok(Method::PUT, "/providers/a/credential", json!({"value":""}), 422).await;
    let still_missing: Hello = h.hello().await;
    assert!(matches!(still_missing.providers[0].readiness, Readiness::MissingCredential { .. }));
    h.credential("a", "TOP_SECRET").await;
    let prepared = h.prepared("a").await;
    let s = h.provision("a", "label", &prepared, 201).await;
    h.credential("a", "ROTATED").await;
    h.configure(vec![provider("a", json!({})), provider("b", json!({}))]).await;
    let again = h.provision("a", "label", &prepared, 200).await;
    assert_eq!(s, again);
    let bad = json!({"modules":[{"name":"memory","entrypoint":"reference"}],"providers":[provider("c",json!({})),provider("a",json!({"changed":true}))]});
    h.ok(Method::PUT, "/config", bad, 422).await;
    let hello: Hello = h.hello().await;
    assert_eq!(hello.providers.len(), 2);
    assert!(matches!(hello.providers[0].readiness, Readiness::Ready));
    let malformed =
        h.client.put("http://localhost/v1/providers/a/credential").body(r#"{"value":{"TOP_SECRET":123}}"#).send().await.unwrap();
    assert_eq!(malformed.status(), 422);
    assert!(!malformed.text().await.unwrap().contains("TOP_SECRET"));
    h.ok(Method::PUT, "/config", json!({"modules":[{"name":"memory","entrypoint":"unknown"}],"providers":[]}), 422).await;
}

// Label idempotency and provider isolation hold after every generated create/delete step.
// Generator spans empty state, duplicate labels, both providers, deletion of absent IDs,
// and re-creation after deletion. Real sockets and the reference module are collaborators.
#[hegel::test]
fn generated_label_lifecycle(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let count = tc.draw(gs::integers::<usize>().min_value(1).max_value(12));
    let steps: Vec<_> = (0..count)
        .map(|_| (tc.draw(gs::booleans()), tc.draw(gs::integers::<usize>().min_value(0).max_value(2)), tc.draw(gs::booleans())))
        .collect();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let h = Harness::start().await;
        h.normal().await;
        let prepared = [h.prepared("a").await, h.prepared("b").await];
        let mut model: BTreeMap<(usize, usize), Environment> = BTreeMap::new();
        for (provider, label, delete) in steps {
            let p = usize::from(provider);
            let name = ["a", "b"][p];
            let key = (p, label);
            let path = format!("/providers/{name}/environments");
            if delete {
                let id = model.remove(&key).map(|s| s.id).unwrap_or_else(|| "absent".into());
                h.ok(Method::DELETE, &format!("{path}/{id}"), Value::Null, 204).await;
                h.ok(Method::DELETE, &format!("{path}/{id}"), Value::Null, 204).await;
            } else {
                let old = model.get(&key);
                let s = h.provision(name, &format!("label-{label}"), &prepared[p], if old.is_some() { 200 } else { 201 }).await;
                if let Some(old) = old {
                    assert_eq!(&s, old);
                }
                model.insert(key, s);
            }
            for name in ["a", "b"] {
                let actual: Vec<Environment> =
                    h.ok(Method::GET, &format!("/providers/{name}/environments"), Value::Null, 200).await.json().await.unwrap();
                let expected: Vec<_> = model.values().filter(|s| s.provider == name).cloned().collect();
                assert_eq!(actual.len(), expected.len());
                for s in &expected {
                    assert!(actual.contains(s));
                    let inspected: Environment = h
                        .ok(Method::GET, &format!("/providers/{name}/environments/{}", s.id), Value::Null, 200)
                        .await
                        .json()
                        .await
                        .unwrap();
                    assert_eq!(&inspected, s);
                }
            }
        }
    });
}

// Simultaneous retries with one label create one environment and emit only one creation pair.
// since is exclusive; unknown cursors produce a complete gap snapshot across providers.
#[tokio::test]
async fn concurrent_provision_and_event_resume() {
    let h = Harness::start().await;
    h.normal().await;
    let prepared = h.prepared("a").await;
    let mut initial = h.stream(None).await;
    let snapshot = initial.next().await;
    assert!(matches!(&snapshot,ObserveRecord::Snapshot {environments,..} if environments.is_empty()));
    let start = cursor(&snapshot).to_owned();
    let (first, second) = tokio::join!(
        h.send(Method::POST, "/providers/a/environments", request("same", &prepared)),
        h.send(Method::POST, "/providers/a/environments", request("same", &prepared))
    );
    let statuses = [first.status().as_u16(), second.status().as_u16()];
    assert!(statuses.contains(&201) && statuses.contains(&200));
    assert_eq!(first.json::<Environment>().await.unwrap(), second.json::<Environment>().await.unwrap());
    let created = initial.next().await;
    assert!(matches!(&created,ObserveRecord::Event {event} if matches!(event.event,EventKind::Created)));
    let running = initial.next().await;
    assert!(matches!(&running,ObserveRecord::Event {event} if matches!(event.event,EventKind::Running {..})));
    let mut resumed = h.stream(Some(cursor(&created))).await;
    assert_eq!(resumed.next().await, running);
    let mut replay = h.stream(Some(&start)).await;
    assert_eq!(replay.next().await, created);
    assert_eq!(replay.next().await, running);
    let pb = h.prepared("b").await;
    h.provision("b", "second", &pb, 201).await;
    initial.next().await;
    initial.next().await;
    let mut gap = h.stream(Some("expired-cursor")).await;
    assert!(matches!(gap.next().await,ObserveRecord::Snapshot {environments,..} if environments.len()==2));
}

// Every typed module error retains its class and agreed status, retry hints, and
// CredentialRejected changes hello readiness until an explicit credential refresh.
#[tokio::test]
async fn all_typed_error_classes() {
    let (h, _) = controlled().await;
    let errors = [
        (422, json!({"kind":"refused","reason":"no"})),
        (503, json!({"kind":"unavailable","reason":"no","retry_after":3})),
        (429, json!({"kind":"rate_limited","reason":"no","retry_after":7})),
        (402, json!({"kind":"quota_exhausted","reason":"no"})),
        (502, json!({"kind":"credential_rejected","reason":"no"})),
        (500, json!({"kind":"internal","reason":"no","provider_error":"raw vendor error"})),
        (404, json!({"kind":"not_found","reason":"no"})),
        (405, json!({"kind":"method_not_allowed","reason":"no"})),
    ];
    h.configure(
        errors.iter().enumerate().map(|(n, (_, e))| provider(&format!("p{n}"), json!({"fault":e,"poll_interval_ms":100000}))).collect(),
    )
    .await;
    for (n, (status, error)) in errors.iter().enumerate() {
        let p = format!("p{n}");
        h.credential(&p, "secret").await;
        let response = h.ok(Method::GET, &format!("/providers/{p}/environments"), Value::Null, *status).await;
        if let Some(retry) = error.get("retry_after") {
            assert_eq!(response.headers()["retry-after"], retry.to_string());
        }
        assert_eq!(response.json::<Value>().await.unwrap(), *error);
    }
    let hello: Hello = h.hello().await;
    assert!(matches!(hello.providers[4].readiness, Readiness::MissingCredential { .. }));
    h.credential("p4", "refreshed").await;
    let hello: Hello = h.hello().await;
    assert!(matches!(hello.providers[4].readiness, Readiness::Ready));
}

// Optional lifecycle operations use opaque IDs; provider-local resume tokens cannot cross
// providers, repeated suspend/resume is idempotent, and malformed semantic inputs are refused.
#[tokio::test]
async fn optional_operations_and_validation() {
    let h = Harness::start().await;
    h.normal().await;
    let pa = h.prepared("a").await;
    assert_eq!(pa, h.prepared("a").await);
    let pb = h.prepared("b").await;
    h.ok(Method::POST, "/providers/b/environments", request("cross", &pa), 422).await;
    for cpus in [json!(0), json!(-1), json!("NaN")] {
        let mut r = request("bad", &pa);
        r["size"]["cpus"] = cpus;
        h.ok(Method::POST, "/providers/a/environments", r, 422).await;
    }
    for direct in [
        json!({"kind":"cidr","cidr":"1.2.3.4/33"}),
        json!({"kind":"host_port","host":"bad host","port":1}),
        json!({"kind":"host_port","host":"host","port":0}),
    ] {
        let mut r = request("bad", &pa);
        r["egress"] = json!({"mode":"deny_all","direct":[direct]});
        let error: ProtocolError = h.ok(Method::POST, "/providers/a/environments", r, 422).await.json().await.unwrap();
        assert_eq!(error, ProtocolError::Refused { reason: "invalid JSON request".into() });
    }
    let mut valid = request("valid-direct", &pa);
    valid["egress"] = json!({"mode":"deny_all","direct":[{"kind":"host_port","host":"valid.example","port":443}]});
    let error: ProtocolError = h.ok(Method::POST, "/providers/a/environments", valid, 422).await.json().await.unwrap();
    assert_eq!(error, ProtocolError::Refused { reason: "reference cannot implement direct destinations".into() });
    let a = h.provision("a", "a", &pa, 201).await;
    let b = h.provision("b", "b", &pb, 201).await;
    let path = format!("/providers/a/environments/{}", a.id);
    let reach: Reach = h.ok(Method::POST, &format!("{path}/reach"), Value::Null, 200).await.json().await.unwrap();
    assert!(matches!(reach,Reach::Relay {path:p} if p==format!("/v1{path}/relay")));
    let token: ResumeToken = h.ok(Method::POST, &format!("{path}/suspend"), Value::Null, 200).await.json().await.unwrap();
    let repeat: ResumeToken = h.ok(Method::POST, &format!("{path}/suspend"), Value::Null, 200).await.json().await.unwrap();
    assert_eq!(token, repeat);
    let paused: Environment = h.ok(Method::GET, &path, Value::Null, 200).await.json().await.unwrap();
    assert!(matches!(paused.state, Observation::Stopped { .. }));
    h.ok(Method::POST, &format!("/providers/b/environments/{}/resume", b.id), serde_json::to_value(&token).unwrap(), 422).await;
    for _ in 0..2 {
        h.ok(Method::POST, &format!("{path}/resume"), serde_json::to_value(&token).unwrap(), 204).await;
    }
    let running: Environment = h.ok(Method::GET, &path, Value::Null, 200).await.json().await.unwrap();
    assert!(matches!(running.state, Observation::Running));
    let exported: Export = h.ok(Method::POST, &format!("{path}/export"), Value::Null, 200).await.json().await.unwrap();
    assert!(exported.reference.contains(&a.id));
    let quota: Quota = h.ok(Method::GET, "/providers/a/quota", Value::Null, 200).await.json().await.unwrap();
    assert_eq!(quota.concurrency_in_use, Some(1));
    h.ok(Method::GET, "/providers/a/usage?start=2026-01-01T00:00:00Z&end=2026-01-02T00:00:00Z", Value::Null, 200).await;
    for query in ["start=bad&end=bad", "start=2026-01-02T00:00:00Z&end=2026-01-01T00:00:00Z", ""] {
        h.ok(Method::GET, &format!("/providers/a/usage?{query}"), Value::Null, 422).await;
    }
    h.ok(Method::GET, &format!("{path}/relay"), Value::Null, 422).await;
    h.ok(Method::GET, "/providers/a/environments/usage", Value::Null, 404).await;
    h.ok(Method::GET, "/providers/a", Value::Null, 404).await;
}

async fn raw_upgrade(h: &Harness, path: &str, command: Option<Value>) -> BufReader<tokio::net::UnixStream> {
    let socket = tokio::net::UnixStream::connect(&h.path).await.unwrap();
    let mut io = BufReader::new(socket);
    let body = command.as_ref().map(Value::to_string).unwrap_or_default();
    let (method, protocol) = if command.is_some() { ("POST", "drydock-stream") } else { ("GET", "drydock-relay") };
    io.write_all(format!("{method} /v1{path} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: {protocol}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
    let mut line = String::new();
    io.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("HTTP/1.1 101"), "{line}");
    let mut headers = String::new();
    loop {
        line.clear();
        io.read_line(&mut line).await.unwrap();
        if line == "\r\n" {
            break;
        }
        headers.push_str(&line.to_lowercase());
    }
    assert!(headers.contains("connection: upgrade"));
    assert!(headers.contains(&format!("upgrade: {protocol}")));
    io
}
// Relay and POST exec preserve the 101 upgrade and bridge raw bytes, including half close
// and payloads larger than the reference stream buffer. Exec is a fake vendor boundary.
#[tokio::test]
async fn relay_and_exec_round_trip() {
    let h = Harness::start().await;
    h.normal().await;
    let prepared = h.prepared("a").await;
    let s = h.provision("a", "stream", &prepared, 201).await;
    let path = format!("/providers/a/environments/{}", s.id);
    for command in [None, Some(json!({"command":["cat"]}))] {
        let route = if command.is_some() { "exec" } else { "relay" };
        let mut stream = raw_upgrade(&h, &format!("{path}/{route}"), command).await;
        let data: Vec<u8> = (0..200_000).map(|n| (n % 256) as u8).collect();
        let (mut read, mut write) = tokio::io::split(&mut stream);
        let ((), received) = tokio::join!(
            async {
                write.write_all(&data).await.unwrap();
                write.shutdown().await.unwrap();
            },
            async {
                let mut bytes = vec![];
                tokio::time::timeout(Duration::from_secs(5), read.read_to_end(&mut bytes)).await.unwrap().unwrap();
                bytes
            }
        );
        assert_eq!(received, data);
    }
    let mut stream = raw_upgrade(&h, &format!("{path}/exec"), Some(json!({"command":["echo","hello"]}))).await;
    let mut data = vec![];
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut data)).await.unwrap().unwrap();
    assert_eq!(data, b"hello\n");
}

// Kernel peer credentials gate even hello; a caller-supplied HTTP header cannot impersonate UID.
#[tokio::test]
async fn unix_peer_rejected() {
    let h = Harness::with_uid(unsafe { libc::geteuid() } + 1).await;
    let r = h.client.get("http://localhost/v1/hello").header("X-Uid", unsafe { libc::geteuid() }).send().await.unwrap();
    assert_eq!(r.status(), 403);
}

// Loopback hosts create a private token file, require bearer auth, and reject wrong tokens.
#[tokio::test]
async fn tcp_bearer_auth() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let token = dir.path().join("token");
    let server = rigging_http_serve::TcpServer::bind("127.0.0.1:0".parse().unwrap(), &token).await.unwrap();
    let addr = server.local_addr().unwrap();
    let host = Host::new(reference::registry());
    let task = tokio::spawn(async move {
        host.serve_bound_tcp(server, std::future::pending()).await.unwrap();
    });
    let secret = std::fs::read_to_string(&token).unwrap();
    assert_eq!(std::fs::metadata(&token).unwrap().permissions().mode() & 0o777, 0o600);
    let client = rigging_tls::client_builder().no_proxy().build().unwrap();
    let url = format!("http://{addr}/v1/hello");
    assert_eq!(client.get(&url).send().await.unwrap().status(), 401);
    assert_eq!(client.get(&url).bearer_auth("wrong").send().await.unwrap().status(), 401);
    assert_eq!(client.get(&url).header("Cookie", format!("rigging_token={secret}")).send().await.unwrap().status(), 401);
    assert_eq!(
        client.get(&url).bearer_auth("wrong").header("Cookie", format!("rigging_token={secret}")).send().await.unwrap().status(),
        401
    );
    assert_eq!(client.get(&url).bearer_auth(secret).send().await.unwrap().status(), 200);
    task.abort();
}

// After bounded history eviction, readers get a complete snapshot and can resume at
// its new cursor without a missing transition. A failed provider is marked separately.
#[tokio::test]
async fn event_eviction_and_initial_error() {
    let h = Harness::start().await;
    h.normal().await;
    let prepared = h.prepared("a").await;
    let mut initial = h.stream(None).await;
    let start = initial.next().await;
    let count = drydock_host::EVENT_HISTORY_CAPACITY / 2 + 1;
    for n in 0..count {
        h.provision("a", &format!("item-{n}"), &prepared, 201).await;
        for _ in 0..2 {
            initial.next().await;
        }
    }
    drop(initial);
    let mut expired = h.stream(Some(cursor(&start))).await;
    let snapshot = expired.next().await;
    assert!(matches!(&snapshot,ObserveRecord::Snapshot {environments,..} if environments.len()==count));
    let pb = h.prepared("b").await;
    h.provision("b", "after-snapshot", &pb, 201).await;
    let created = expired.next().await;
    assert!(
        matches!(&created,ObserveRecord::Event {event} if event.provider=="b" && matches!(event.event,EventKind::Created) && event.timestamp.instant() <= chrono::Utc::now())
    );
    let mut resumed = h.stream(Some(cursor(&snapshot))).await;
    assert_eq!(resumed.next().await, created);
    let bad = Harness::start().await;
    bad.configure(vec![provider("fault", json!({"fault":{"kind":"unavailable","reason":"offline","retry_after":null}}))]).await;
    bad.credential("fault", "delivered").await;
    let mut records = bad.stream(None).await;
    let record = serde_json::to_value(records.next().await).unwrap();
    assert_eq!(record["unavailable_providers"]["fault"]["kind"], "unavailable");
}

// The supervisor proxy receives absolute vendor requests and the placeholder token.
// This stand-in represents the external proxy network boundary, not a mocked HTTP client.
#[tokio::test]
async fn proxied_credentials_use_supervisor_proxy() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut heads = vec![];
        for status in ["401 Unauthorized", "204 No Content"] {
            let (socket, _) = listener.accept().await.unwrap();
            let mut io = BufReader::new(socket);
            let mut head = String::new();
            loop {
                let mut line = String::new();
                io.read_line(&mut line).await.unwrap();
                if line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            io.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            heads.push(head);
        }
        heads
    });
    let mode = CredentialMode::Proxied { placeholder_token: Secret::new("proxy-placeholder"), proxy_url: format!("http://{address}") };
    let (h, control) = controlled().await;
    control.execute_http.store(true, std::sync::atomic::Ordering::SeqCst);
    *control.http_url.lock().unwrap() = Some("http://vendor.invalid/resource".into());
    let mut config = provider("proxied", json!({}));
    config["credential"] = serde_json::to_value(mode).unwrap();
    h.configure(vec![config]).await;
    let error = h.ok(Method::POST, "/providers/proxied/prepare", json!({"image_digest":"i","tools_digest":"t"}), 502).await;
    assert!(matches!(error.json::<ProtocolError>().await.unwrap(), ProtocolError::CredentialRejected { .. }));
    // Proxy-side repair needs no Direct refresh or host reconfiguration.
    h.prepared("proxied").await;
    for head in task.await.unwrap() {
        assert!(head.starts_with("GET http://vendor.invalid/resource HTTP/1.1\r\n"));
        assert!(head.to_lowercase().contains("authorization: bearer proxy-placeholder"));
    }
    let hello: Hello = h.hello().await;
    assert!(matches!(hello.providers[0].readiness, Readiness::Ready));
    h.ok(Method::PUT, "/providers/proxied/credential", json!({"value":"direct"}), 422).await;
}

// Extractor failures (oversized bodies, invalid methods and path encodings) use the
// same typed refusal body as semantic validation, without returning request values.
#[tokio::test]
async fn transport_rejections_are_typed() {
    let h = Harness::start().await;
    for (method, path, body) in
        [(Method::PUT, "/config", "x".repeat(2 * 1024 * 1024 + 1)), (Method::GET, "/providers/%FF/environments", String::new())]
    {
        let response = h.client.request(method, format!("http://localhost/v1{path}")).body(body).send().await.unwrap();
        assert_eq!(response.status(), 422);
        assert!(matches!(response.json::<ProtocolError>().await.unwrap(), ProtocolError::Refused { .. }));
    }
    let response = h.ok(Method::POST, "/hello", Value::Null, 405).await;
    assert!(matches!(response.json::<ProtocolError>().await.unwrap(), ProtocolError::MethodNotAllowed { .. }));
}

// Shutdown ends long-lived event bodies before draining HTTP, and removes the owned socket.
#[tokio::test]
async fn shutdown_closes_event_stream() {
    let mut h = Harness::start().await;
    h.normal().await;
    let prepared = h.prepared("a").await;
    let environment = h.provision("a", "shutdown", &prepared, 201).await;
    let mut relay = raw_upgrade(&h, &format!("/providers/a/environments/{}/relay", environment.id), None).await;
    let mut records = h.stream(None).await;
    records.next().await;
    h.stop.take().unwrap().send(()).unwrap();
    let mut bytes = vec![];
    tokio::time::timeout(Duration::from_secs(2), relay.read_to_end(&mut bytes)).await.unwrap().unwrap();
    assert!(bytes.is_empty());
    assert!(tokio::time::timeout(Duration::from_secs(2), records.stream.next()).await.unwrap().is_none());
    tokio::time::timeout(Duration::from_secs(2), &mut h.task).await.unwrap().unwrap();
    assert!(!h.path.exists());
}

#[derive(Default)]
struct Control {
    poll: std::sync::atomic::AtomicBool,
    execute_http: std::sync::atomic::AtomicBool,
    disable_exec: std::sync::atomic::AtomicBool,
    skip_list_timestamp: std::sync::atomic::AtomicBool,
    timestamp: std::sync::Mutex<Option<chrono::DateTime<chrono::Utc>>>,
    global_limit: std::sync::atomic::AtomicBool,
    list_limit: std::sync::atomic::AtomicU32,
    list_period: std::sync::atomic::AtomicU64,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,

    hold_list: std::sync::atomic::AtomicBool,
    hold_list_result: std::sync::atomic::AtomicBool,
    list_result_ready: tokio::sync::Notify,
    list_entered: tokio::sync::Notify,
    list_release: tokio::sync::Notify,
    vendor: std::sync::Mutex<VendorState>,
    list_held: tokio::sync::Notify,
    http_url: std::sync::Mutex<Option<String>>,
    reject_list: std::sync::atomic::AtomicBool,
    missing_tool: std::sync::atomic::AtomicBool,
    dropped: tokio::sync::Notify,
    hold_destroy: std::sync::atomic::AtomicBool,
    fail_destroy: std::sync::atomic::AtomicBool,
    destroy_entered: tokio::sync::Notify,
    destroy_release: tokio::sync::Notify,
    hold_success: std::sync::atomic::AtomicBool,
    success_entered: tokio::sync::Notify,
    success_release: tokio::sync::Notify,
    started: tokio::sync::Notify,
    stopped: tokio::sync::Notify,
    list_calls: std::sync::atomic::AtomicUsize,
    sink: std::sync::Mutex<Option<drydock_host::EventSink>>,
}
#[derive(Default)]
struct VendorState {
    row: Option<Environment>,
    error: bool,
}
struct ControlledModule(std::sync::Arc<Control>);
struct ControlledProvider {
    http: std::sync::Arc<dyn HttpClient>,
    inner: std::sync::Arc<dyn drydock_host::module::Provider>,
    control: std::sync::Arc<Control>,
}
impl Drop for ControlledProvider {
    fn drop(&mut self) {
        self.control.dropped.notify_one();
    }
}
// The gate and error flag stand in for the vendor network boundary; all resource
// behavior is delegated to the real reference provider, through real HTTP sockets.
#[async_trait::async_trait]
impl drydock_host::module::Module for ControlledModule {
    fn version(&self) -> &str {
        "test"
    }
    async fn configure(
        &self,
        c: &ProviderConfiguration,
        http: std::sync::Arc<dyn HttpClient>,
    ) -> drydock_host::module::Result<std::sync::Arc<dyn drydock_host::module::Provider>> {
        let inner = drydock_host::module::Module::configure(&reference::ReferenceModule, c, http.clone()).await?;
        Ok(std::sync::Arc::new(ControlledProvider { inner, http, control: self.0.clone() }))
    }
}
#[async_trait::async_trait]
impl drydock_host::module::Provider for ControlledProvider {
    fn readiness(&self, c: &drydock_host::module::Credentials) -> Readiness {
        if self.control.missing_tool.load(std::sync::atomic::Ordering::SeqCst) {
            Readiness::MissingTool { reason: "test tool absent".into() }
        } else {
            self.inner.readiness(c)
        }
    }

    async fn run(&self, mut context: drydock_host::module::PushContext) -> drydock_host::module::Result<()> {
        *self.control.sink.lock().unwrap() = Some(context.events.clone());
        self.control.started.notify_one();
        if !*context.stopping.borrow() {
            let _ = context.stopping.changed().await;
        }
        self.control.stopped.notify_one();
        Ok(())
    }

    fn observation(&self) -> ObservationMode {
        if self.control.poll.load(std::sync::atomic::Ordering::SeqCst) {
            ObservationMode::Poll { interval: Duration::from_millis(10) }
        } else {
            ObservationMode::Push
        }
    }
    fn rate_limits(&self) -> Vec<RateLimit> {
        let requests = self.control.list_limit.load(std::sync::atomic::Ordering::SeqCst);
        if requests == 0 {
            vec![]
        } else {
            vec![RateLimit {
                operation: if self.control.global_limit.load(std::sync::atomic::Ordering::SeqCst) { "*" } else { "list" }.into(),
                requests,
                period_seconds: self.control.list_period.load(std::sync::atomic::Ordering::SeqCst).max(1),
            }]
        }
    }
    fn capabilities(&self) -> Capabilities {
        let mut capabilities = self.inner.capabilities();
        capabilities.fallback_runner = !self.control.disable_exec.load(std::sync::atomic::Ordering::SeqCst);
        capabilities
    }
    async fn prepare(&self, r: PrepareRequest, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<Prepared> {
        if self.control.hold_success.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.control.success_entered.notify_one();
            self.control.success_release.notified().await;
        }
        if c.token().is_some_and(|t| t.expose() == "old") {
            self.control.entered.notify_one();
            self.control.release.notified().await;
            return Err(ProtocolError::CredentialRejected { reason: "old credential rejected".into() });
        }
        if self.control.execute_http.load(std::sync::atomic::Ordering::SeqCst) {
            let url = self.control.http_url.lock().unwrap().clone().unwrap_or_else(|| "https://vendor.example/prepare".into());
            let mut request = reqwest::Request::new(reqwest::Method::GET, url.parse().unwrap());
            request.headers_mut().insert("Authorization", format!("Bearer {}", c.token().unwrap().expose()).parse().unwrap());
            let response = self
                .http
                .execute(request, &rigging_http_client::http_channel_label("GET", &url))
                .await
                .map_err(|_| ProtocolError::Unavailable { reason: "transport failure".into(), retry_after: None })?;
            if response.status() == 401 {
                return Err(ProtocolError::CredentialRejected { reason: "vendor rejected credential".into() });
            }
            assert!(response.status().is_success());
        }
        self.inner.prepare(r, c).await
    }
    async fn provision(&self, r: ProvisionRequest, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<Provisioned> {
        self.inner.provision(r, c).await
    }
    async fn list(&self, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<Vec<ObservedEnvironment>> {
        use std::sync::atomic::Ordering::SeqCst;
        if self.control.hold_list.load(SeqCst) {
            self.control.list_held.notify_one();
            self.control.list_release.notified().await;
        }
        let mut rows = self.inner.list(c).await?;
        // Capture the complete external response atomically: failure and inventory
        // can never come from two different vendor revisions.
        let vendor = {
            let state = self.control.vendor.lock().unwrap();
            (state.error, state.row.clone())
        };
        self.control.list_calls.fetch_add(1, SeqCst);
        self.control.list_entered.notify_waiters();
        if self.control.reject_list.load(SeqCst) {
            return Err(ProtocolError::CredentialRejected { reason: "vendor credential rejected".into() });
        }
        if vendor.0 {
            return Err(ProtocolError::Unavailable { reason: "vendor unavailable".into(), retry_after: None });
        }
        if let Some(row) = vendor.1 {
            rows.push(ObservedEnvironment {
                environment: row,
                timestamp: if self.control.skip_list_timestamp.load(SeqCst) { None } else { *self.control.timestamp.lock().unwrap() },
            });
        }
        if self.control.hold_list_result.swap(false, SeqCst) {
            self.control.list_result_ready.notify_one();
            self.control.list_release.notified().await;
        }
        Ok(rows)
    }
    async fn inspect(&self, id: &str, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<ObservedEnvironment> {
        if let Some(row) = self.control.vendor.lock().unwrap().row.clone().filter(|row| row.id == id) {
            return Ok(ObservedEnvironment { environment: row, timestamp: *self.control.timestamp.lock().unwrap() });
        }
        self.inner.inspect(id, c).await
    }
    async fn destroy(&self, id: &str, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<()> {
        self.inner.destroy(id, c).await?;
        if self.control.hold_destroy.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.control.destroy_entered.notify_one();
            self.control.destroy_release.notified().await;
        }
        if self.control.fail_destroy.load(std::sync::atomic::Ordering::SeqCst) {
            Err(ProtocolError::Unavailable { reason: "ambiguous vendor failure".into(), retry_after: None })
        } else {
            Ok(())
        }
    }
    async fn reach(&self, id: &str, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<Connection> {
        self.inner.reach(id, c).await
    }
    async fn relay(
        &self,
        id: &str,
        c: &drydock_host::module::Credentials,
    ) -> drydock_host::module::Result<drydock_host::module::ByteStream> {
        self.inner.relay(id, c).await
    }
    async fn exec(
        &self,
        id: &str,
        r: ExecRequest,
        c: &drydock_host::module::Credentials,
    ) -> drydock_host::module::Result<drydock_host::module::ByteStream> {
        self.inner.exec(id, r, c).await
    }
    async fn suspend(&self, id: &str, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<ResumeToken> {
        self.inner.suspend(id, c).await
    }
    async fn resume(&self, id: &str, r: ResumeToken, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<()> {
        self.inner.resume(id, r, c).await
    }
    async fn export(&self, id: &str, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<Export> {
        self.inner.export(id, c).await
    }
    async fn usage(&self, r: Period, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<Usage> {
        self.inner.usage(r, c).await
    }
    async fn quota(&self, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<Quota> {
        self.inner.quota(c).await
    }
}
async fn controlled() -> (Harness, std::sync::Arc<Control>) {
    let control = std::sync::Arc::new(Control::default());
    let registry = drydock_host::module::Registry::from([(
        "reference".into(),
        std::sync::Arc::new(ControlledModule(control.clone())) as std::sync::Arc<dyn drydock_host::module::Module>,
    )]);
    (Harness::with_host(Host::new(registry), unsafe { libc::geteuid() }).await, control)
}

// A held vendor request on A must not block B, hello, or credential refresh for A.
// When that old request later rejects its credential, the refresh remains ready.
#[tokio::test]
async fn independent_providers_and_inflight_credential_refresh() {
    let (h, control) = controlled().await;
    h.normal().await;
    h.credential("a", "old").await;
    let client = h.client.clone();
    let pending = tokio::spawn(async move {
        client
            .post("http://localhost/v1/providers/a/prepare")
            .json(&json!({"image_digest":"image","tools_digest":"tools"}))
            .send()
            .await
            .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), control.entered.notified()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        h.ok(Method::GET, "/hello", Value::Null, 200).await;
        h.ok(Method::GET, "/providers/b/environments", Value::Null, 200).await;
        h.ok(Method::GET, "/providers/a/environments", Value::Null, 200).await;
        let mut events = h.stream(None).await;
        assert!(matches!(events.next().await, ObserveRecord::Snapshot { .. }));
        h.credential("a", "new").await;
    })
    .await
    .expect("other providers, hello, and refresh must not wait for vendor A");
    control.release.notify_one();
    assert_eq!(pending.await.unwrap().status(), 502);
    let hello: Hello = h.hello().await;
    assert!(matches!(hello.providers[0].readiness, Readiness::Ready));
    h.prepared("a").await;
}

// An unready provider must not block another provider's snapshot or call the
// vendor without credentials. Snapshot metadata marks its inventory unavailable.
#[tokio::test]
async fn snapshots_isolate_unready_providers() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    h.configure(vec![provider("a", json!({})), provider("b", json!({}))]).await;
    h.credential("b", "ready").await;
    let prepared = h.prepared("b").await;
    let environment = h.provision("b", "healthy", &prepared, 201).await;
    let mut records = h.stream(None).await;
    let record = serde_json::to_value(records.next().await).unwrap();
    assert_eq!(record["environments"][0]["id"], environment.id);
    assert!(record["unavailable_providers"]["a"].is_object());
    assert_eq!(control.list_calls.load(SeqCst), 1);
}

// Before the first successful poll, missing credentials are provider-local;
// refreshing them lets normal polling produce a complete cached snapshot.
#[tokio::test]
async fn unready_polled_provider_has_snapshot_marker() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    control.poll.store(true, SeqCst);
    h.configure(vec![provider("a", json!({}))]).await;
    let mut records = h.stream(None).await;
    let record = serde_json::to_value(records.next().await).unwrap();
    assert_eq!(record["environments"], json!([]));
    assert!(record["unavailable_providers"]["a"].is_object());
    assert_eq!(control.list_calls.load(SeqCst), 0);
    h.credential("a", "ready").await;
    let mut repaired = h.stream(None).await;
    let record = serde_json::to_value(repaired.next().await).unwrap();
    assert!(record.get("unavailable_providers").is_none());
    assert!(control.list_calls.load(SeqCst) >= 1);
}

// Cached polling rows are withheld, with a marker, after the provider becomes
// unready. Recovery restores the inventory without inferring a deletion.
#[tokio::test]
async fn unready_polled_provider_withholds_cached_inventory() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    control.poll.store(true, SeqCst);
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    let prepared = h.prepared("a").await;
    let mut events = h.stream(None).await;
    events.next().await;
    let environment = h.provision("a", "cached", &prepared, 201).await;
    for _ in 0..2 {
        events.next().await;
    }
    let mut cached = h.stream(None).await;
    assert!(matches!(cached.next().await, ObserveRecord::Snapshot { environments, .. } if environments == vec![environment.clone()]));
    control.missing_tool.store(true, SeqCst);
    let mut unavailable = h.stream(None).await;
    let record = serde_json::to_value(unavailable.next().await).unwrap();
    assert_eq!(record["environments"], json!([]));
    assert_eq!(record["unavailable_providers"]["a"]["kind"], "unavailable");
    control.missing_tool.store(false, SeqCst);
    let mut repaired = h.stream(None).await;
    assert!(matches!(repaired.next().await, ObserveRecord::Snapshot { environments, unavailable_providers, .. }
        if environments == vec![environment] && unavailable_providers.is_empty()));
}

// A rejected proxy remains callable for repair. Events must both isolate a
// persistent rejection and repair a push provider once its list probe succeeds.
#[tokio::test]
async fn events_after_proxied_rejection_probe_and_repair() {
    use std::sync::atomic::Ordering::SeqCst;
    let control = std::sync::Arc::new(Control::default());
    let healthy_control = std::sync::Arc::new(Control::default());
    let registry = drydock_host::module::Registry::from([
        ("reference".into(), std::sync::Arc::new(ControlledModule(control.clone())) as std::sync::Arc<dyn drydock_host::module::Module>),
        (
            "healthy".into(),
            std::sync::Arc::new(ControlledModule(healthy_control.clone())) as std::sync::Arc<dyn drydock_host::module::Module>,
        ),
    ]);
    let h = Harness::with_host(Host::new(registry), unsafe { libc::geteuid() }).await;
    let mut proxied = provider("a", json!({}));
    proxied["credential"] = json!({"mode":"proxied", "proxy_url":"http://127.0.0.1:1", "placeholder_token":"placeholder"});
    let mut healthy = provider("b", json!({}));
    healthy["module"] = json!("healthy");
    h.ok(
        Method::PUT,
        "/config",
        json!({
            "modules":[{"name":"memory","entrypoint":"reference"},{"name":"healthy","entrypoint":"healthy"}],
            "providers":[proxied, healthy]
        }),
        204,
    )
    .await;
    h.credential("b", "ready").await;
    let prepared = h.prepared("b").await;
    let environment = h.provision("b", "healthy", &prepared, 201).await;
    control.reject_list.store(true, SeqCst);
    h.ok(Method::GET, "/providers/a/environments", Value::Null, 502).await;
    assert!(matches!(h.hello().await.providers[0].readiness, Readiness::Unknown { .. }));
    let mut records = h.stream(None).await;
    let record = serde_json::to_value(records.next().await).unwrap();
    assert!(record["unavailable_providers"]["a"].is_object());
    assert_eq!(record["environments"][0]["id"], environment.id);
    healthy_control.started.notified().await;
    healthy_control.sink.lock().unwrap().as_ref().unwrap().publish("healthy-event".into(), None, None, EventKind::Created);
    assert!(matches!(records.next().await, ObserveRecord::Event { event } if event.provider == "b" && event.id == "healthy-event"));
    control.reject_list.store(false, SeqCst);
    let mut repaired = h.stream(None).await;
    let record = serde_json::to_value(repaired.next().await).unwrap();
    assert!(record.get("unavailable_providers").is_none());
    assert!(matches!(h.hello().await.providers[0].readiness, Readiness::Ready));
}

// After history eviction, a failed provider is marked in the recovery snapshot;
// the stream remains open and continues delivering healthy provider events.
#[tokio::test]
async fn recovery_snapshot_error_is_provider_local() {
    let (h, control) = controlled().await;
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    let mut records = h.stream(None).await;
    records.next().await;
    // A synchronous burst evicts cursor zero before the server can poll its log.
    control.vendor.lock().unwrap().error = true;
    control.started.notified().await;
    let sink = control.sink.lock().unwrap().clone().unwrap();
    for n in 0..drydock_host::EVENT_HISTORY_CAPACITY + 1 {
        sink.publish(format!("id-{n}"), None, None, EventKind::Created);
    }
    let record = serde_json::to_value(records.next().await).unwrap();
    assert_eq!(record["type"], "snapshot");
    assert_eq!(record["unavailable_providers"]["a"]["kind"], "unavailable");
    sink.publish("after-gap".into(), None, None, EventKind::Created);
    assert!(matches!(records.next().await, ObserveRecord::Event { event } if event.id == "after-gap"));
}

// A later factory failure leaves both existing providers and credentials intact,
// and none of the earlier successful additions in that document become visible.
#[tokio::test]
async fn partial_factory_failure_preserves_configuration() {
    let h = Harness::start().await;
    h.normal().await;
    let prepared = h.prepared("a").await;
    let s = h.provision("a", "retained", &prepared, 201).await;
    h.ok(Method::PUT,"/config",json!({"modules":[{"name":"memory","entrypoint":"reference"}],"providers":[provider("a",json!({})),provider("b",json!({})),provider("temporary",json!({})),provider("fails",json!({"fault":"invalid error"}))]}),422).await;
    let hello: Hello = h.hello().await;
    assert_eq!(hello.providers.len(), 2);
    assert_eq!(s, h.provision("a", "retained", &prepared, 200).await);
    h.ok(Method::GET, "/providers/temporary/environments", Value::Null, 404).await;
}

// Loopback enforcement belongs to Rigging, so the host must propagate its refusal
// without creating a token file or introducing its own parallel bind/auth policy.
#[tokio::test]
async fn tcp_refuses_nonloopback_bind() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    let error = Host::new(reference::registry()).serve_tcp("0.0.0.0:0".parse().unwrap(), &token, std::future::pending()).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(!token.exists());
}

// SIGTERM follows the same graceful path as Ctrl-C, ending an open event body and
// unlinking the managed socket before the binary exits successfully.
#[tokio::test]
async fn binary_sigterm_drains_and_removes_socket() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("host.sock");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_drydock-host"))
        .arg("--unix")
        .arg(&path)
        .kill_on_drop(true)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let client = rigging_tls::client_builder().unix_socket(path.clone()).build().unwrap();
    wait_hello(&client).await;
    let mut records = client.get("http://localhost/v1/events").send().await.unwrap().bytes_stream();
    assert!(records.next().await.unwrap().is_ok());
    let config = json!({"modules":[{"name":"memory","entrypoint":"reference"}],"providers":[provider("fault",json!({"fault":{"kind":"unavailable","reason":"sensitive-vendor-reason","retry_after":null}}))]});
    assert_eq!(client.put("http://localhost/v1/config").json(&config).send().await.unwrap().status(), 204);
    assert_eq!(
        client
            .put("http://localhost/v1/providers/fault/credential")
            .json(&json!({"value":"sensitive-credential-value"}))
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(client.get("http://localhost/v1/events?since=expired").send().await.unwrap().status(), 200);
    let malformed = client
        .put("http://localhost/v1/config")
        .header("content-type", "application/json")
        .body("sensitive-value-never-log")
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), 422);
    // SAFETY: the child PID is live and owned by this test; SIGTERM is its shutdown signal.
    assert_eq!(unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGTERM) }, 0);
    assert!(tokio::time::timeout(Duration::from_secs(2), records.next()).await.unwrap().is_none());
    assert!(tokio::time::timeout(Duration::from_secs(2), child.wait()).await.unwrap().unwrap().success());
    assert!(!path.exists());
    let mut logs = String::new();
    child.stderr.take().unwrap().read_to_string(&mut logs).await.unwrap();
    assert!(logs.contains("route=\"/v1/config\""));
    assert!(logs.contains("error_class=\"refused\""));
    assert!(!logs.contains("sensitive-value-never-log"));
    assert!(!logs.contains("sensitive-vendor-reason"));
    assert!(!logs.contains("sensitive-credential-value"));
    assert!(logs.contains("route=\"poll\""));
    assert!(logs.contains("error_class=\"unavailable\""));
    assert!(logs.contains("readiness=\"ready\""));
}

// Wire sizes use unsigned integers: zero and u64::MAX are valid; negative sizes
// cannot deserialize. Equal period endpoints represent a valid empty interval.
#[tokio::test]
async fn size_boundaries_zero_period_and_empty_credentials() {
    let h = Harness::start().await;
    h.normal().await;
    let prepared = h.prepared("a").await;
    for n in [0, u64::MAX] {
        let mut r = request(&format!("size-{n}"), &prepared);
        r["size"]["memory_bytes"] = json!(n);
        r["size"]["disk_bytes"] = json!(n);
        h.ok(Method::POST, "/providers/a/environments", r, 201).await;
    }
    for field in ["memory_bytes", "disk_bytes"] {
        let mut r = request("negative", &prepared);
        r["size"][field] = json!(-1);
        h.ok(Method::POST, "/providers/a/environments", r, 422).await;
    }
    h.ok(Method::GET, "/providers/a/usage?start=2026-01-01T00:00:00Z&end=2026-01-01T00:00:00Z", Value::Null, 200).await;
    h.ok(Method::PUT, "/providers/a/credential", json!({"value":""}), 422).await;
    // A syntactically valid but changed repeat still denotes the existing label.
    let original = h.provision("a", "repeat", &prepared, 201).await;
    let mut changed = request("repeat", &prepared);
    changed["size"]["cpus"] = json!(2);
    changed["egress"] = json!({"mode":"open"});
    let repeat: Environment = h.ok(Method::POST, "/providers/a/environments", changed, 200).await.json().await.unwrap();
    assert_eq!(repeat, original);
}

// A poll snapshot reads the last committed host inventory without a vendor call,
// even while the next vendor poll is held. Its cursor includes the cached events.
#[tokio::test]
async fn snapshot_uses_polled_inventory_while_vendor_is_held() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    control.poll.store(true, SeqCst);
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    let mut events = h.stream(None).await;
    events.next().await;
    let prepared = h.prepared("a").await;
    let environment = h.provision("a", "observed", &prepared, 201).await;
    events.next().await;
    let running = events.next().await;
    control.hold_list.store(true, SeqCst);
    tokio::time::timeout(Duration::from_secs(2), control.list_held.notified()).await.unwrap();
    let calls = control.list_calls.load(SeqCst);
    let mut snapshot =
        tokio::time::timeout(Duration::from_secs(1), h.stream(Some("expired"))).await.expect("cached snapshot must not wait for vendor");
    assert!(matches!(snapshot.next().await, ObserveRecord::Snapshot { cursor: c, environments, .. }
        if c == cursor(&running) && environments == vec![environment]));
    assert_eq!(control.list_calls.load(SeqCst), calls);
    control.hold_list.store(false, SeqCst);
    control.list_release.notify_one();
}

// The reference module declares polling and emits no events itself. Host list diffs
// produce creation/running, stopped, resumed/running, and confirmed deletion events.
#[tokio::test]
async fn reference_polling_billing_transitions() {
    let h = Harness::start().await;
    h.normal().await;
    let prepared = h.prepared("a").await;
    let mut events = h.stream(None).await;
    events.next().await;
    let s = h.provision("a", "polled", &prepared, 201).await;
    for expected in ["created", "running"] {
        let ObserveRecord::Event { event } = events.next().await else { panic!("expected event") };
        assert_eq!(event.id, s.id);
        assert_eq!(event.timestamp_source, TimestampSource::Adaptor);
        assert_eq!(serde_json::to_value(event.event).unwrap()["kind"], expected);
    }
    let path = format!("/providers/a/environments/{}", s.id);
    let token: ResumeToken = h.ok(Method::POST, &format!("{path}/suspend"), Value::Null, 200).await.json().await.unwrap();
    assert!(matches!(events.next().await,ObserveRecord::Event {event} if matches!(event.event,EventKind::Stopped {..})));
    h.ok(Method::POST, &format!("{path}/resume"), serde_json::to_value(token).unwrap(), 204).await;
    assert!(matches!(events.next().await,ObserveRecord::Event {event} if matches!(event.event,EventKind::Resumed)));
    assert!(matches!(events.next().await,ObserveRecord::Event {event} if matches!(event.event,EventKind::Running {..})));
    h.ok(Method::DELETE, &path, Value::Null, 204).await;
    assert!(
        matches!(events.next().await,ObserveRecord::Event {event} if matches!(event.event,EventKind::Gone {cause:GoneCause::DestroyedByRequest}))
    );
}

// External changes observed through polling retain typed provider timestamps.
// Failed lists keep prior state; only a successful complete list can report loss.
#[tokio::test]
async fn polled_provider_time_pause_and_authoritative_loss() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    control.poll.store(true, SeqCst);
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    let mut events = h.stream(None).await;
    events.next().await;
    let time = "2026-10-19T00:00:00Z".parse::<chrono::DateTime<chrono::Utc>>().unwrap();
    *control.timestamp.lock().unwrap() = Some(time);
    let row = Environment {
        id: "vendor".into(),
        label: None,
        provider: "a".into(),
        state: Observation::Running,
        granted_size: Some(Size { cpus: 2.0, memory_bytes: 0, disk_bytes: 0 }),
        egress: Enforcement::Advisory,
    };
    control.vendor.lock().unwrap().row = Some(row.clone());
    for _ in 0..2 {
        let ObserveRecord::Event { event } = events.next().await else { panic!("expected event") };
        assert_eq!(event.timestamp_source, TimestampSource::Provider);
        assert_eq!(event.timestamp.instant(), time);
    }
    control.vendor.lock().unwrap().row.as_mut().unwrap().state = Observation::Stopped { cause: StopCause::PausedByProvider };
    assert!(
        matches!(events.next().await,ObserveRecord::Event {event} if matches!(event.event,EventKind::Paused {cause:StopCause::PausedByProvider}))
    );
    {
        let mut vendor = control.vendor.lock().unwrap();
        vendor.error = true;
        vendor.row = None;
    }
    assert!(tokio::time::timeout(Duration::from_millis(40), events.stream.next()).await.is_err());
    control.vendor.lock().unwrap().error = false;
    assert!(
        matches!(events.next().await,ObserveRecord::Event {event} if event.timestamp_source==TimestampSource::Adaptor && matches!(event.event,EventKind::Gone {cause:GoneCause::MissingOnList}))
    );
}

// Polling has at most half the declared list allowance; a route can use the
// remaining slot. A subsequent route gets the host's typed 429 and Retry-After.
#[tokio::test]
async fn polling_respects_declared_list_budget() {
    use std::sync::atomic::Ordering::SeqCst;
    for global in [false, true] {
        let (h, control) = controlled().await;
        control.poll.store(true, SeqCst);
        control.global_limit.store(global, SeqCst);
        control.list_limit.store(2, SeqCst);
        h.configure(vec![provider("a", json!({}))]).await;
        h.credential("a", "ready").await;
        control.wait_lists(0).await;
        h.ok(Method::GET, "/providers/a/environments", Value::Null, 200).await;
        let response = h.ok(Method::GET, "/providers/a/environments", Value::Null, 429).await;
        assert!(response.headers()["retry-after"].to_str().unwrap().parse::<u64>().unwrap() > 0);
        assert!(matches!(response.json::<ProtocolError>().await.unwrap(), ProtocolError::RateLimited { .. }));
        assert_eq!(control.list_calls.load(SeqCst), 2);
    }
}

// Modules receive the shared HttpClient port independently of credentials. A
// Rigging replay client can replace production transport without changing a module.
#[tokio::test]
async fn module_uses_rigging_replay_http_port() {
    use drydock_host::module::{Credentials, Module};
    use rigging_replay_testkit::{Masks, NoExtra, ReplayHttpClient, Session};
    let (h, control) = controlled().await;
    h.configure(vec![provider("a", json!({}))]).await;
    control.execute_http.store(true, std::sync::atomic::Ordering::SeqCst);
    let session = Session::<NoExtra>::replaying_from_str(
        r#"
interactions:
  - channel: http
    method: GET
    url: https://vendor.example/prepare
    request_headers:
      authorization: Bearer placeholder
    status: 200
    response_body: '{}'
"#,
        Masks::new(),
    );
    let http = std::sync::Arc::new(ReplayHttpClient::new(session.clone()));
    let config: ProviderConfiguration = serde_json::from_value(provider("a", json!({}))).unwrap();
    control.started.notified().await;
    let module = ControlledModule(control);
    let provider = module.configure(&config, http).await.unwrap();
    let mut credentials = Credentials::new(config.credential);
    credentials.value = Some(Secret::new("placeholder"));
    let prepared =
        provider.prepare(PrepareRequest { image_digest: "image".into(), tools_digest: "tools".into() }, &credentials).await.unwrap();
    assert_eq!(prepared.provider, "a");
    session.assert_complete();
}

// Optional operation gates use the declaration cached at configure, rather than
// re-reading dynamic module capabilities or depending on unsupported method defaults.
#[tokio::test]
async fn cached_capability_gate_refuses_exec() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    control.disable_exec.store(true, SeqCst);
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    let prepared = h.prepared("a").await;
    let environment = h.provision("a", "exec", &prepared, 201).await;
    control.disable_exec.store(false, SeqCst);
    let response = h
        .client
        .post(format!("http://localhost/v1/providers/a/environments/{}/exec", environment.id))
        .header("Connection", "Upgrade")
        .header("Upgrade", "drydock-stream")
        .json(&json!({"command":["cat"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 422);
}

// If list has no timestamp, matching inspect metadata supplies the provider's
// timestamp. A held poll list does not prevent the same provider's inspect call.
#[tokio::test]
async fn poll_uses_matching_inspect_timestamp() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    control.poll.store(true, SeqCst);
    control.skip_list_timestamp.store(true, SeqCst);
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    let mut events = h.stream(None).await;
    events.next().await;
    control.hold_list.store(true, SeqCst);
    let time = "2026-01-01T00:00:00Z".parse::<chrono::DateTime<chrono::Utc>>().unwrap();
    *control.timestamp.lock().unwrap() = Some(time);
    control.vendor.lock().unwrap().row = Some(Environment {
        id: "external".into(),
        label: None,
        provider: "a".into(),
        state: Observation::Running,
        granted_size: Some(Size { cpus: 1.0, memory_bytes: 0, disk_bytes: 0 }),
        egress: Enforcement::Advisory,
    });
    tokio::time::timeout(Duration::from_secs(2), control.list_held.notified()).await.unwrap();
    h.ok(Method::GET, "/providers/a/environments/external", Value::Null, 200).await;
    control.hold_list.store(false, SeqCst);
    control.list_release.notify_one();
    let ObserveRecord::Event { event } = events.next().await else { panic!("expected event") };
    assert_eq!(event.timestamp_source, TimestampSource::Provider);
    assert_eq!(event.timestamp.instant(), time);
}

// Invalid poll policies cannot panic a background observer or partly commit a
// provider document: zero intervals and overflowing declared periods are refused.
#[tokio::test]
async fn invalid_poll_intervals_leave_configuration_empty() {
    let h = Harness::start().await;
    h.ok(
        Method::PUT,
        "/config",
        json!({"modules":[{"name":"memory","entrypoint":"reference"}],"providers":[provider("a",json!({"poll_interval_ms":0}))]}),
        422,
    )
    .await;
    let hello: Hello = h.hello().await;
    assert!(hello.providers.is_empty());
    let (h, control) = controlled().await;
    control.poll.store(true, std::sync::atomic::Ordering::SeqCst);
    control.list_limit.store(1, std::sync::atomic::Ordering::SeqCst);
    control.list_period.store(u64::MAX, std::sync::atomic::Ordering::SeqCst);
    h.ok(
        Method::PUT,
        "/config",
        json!({"modules":[{"name":"memory","entrypoint":"reference"}],"providers":[provider("a",json!({}))]}),
        422,
    )
    .await;
    let hello: Hello = h.hello().await;
    assert!(hello.providers.is_empty());
}

// A successful deletion can race a list response containing the pre-delete row.
// That stale poll must not discard attribution before the next list sees absence.
#[tokio::test]
async fn destroy_attribution_survives_stale_poll() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    control.poll.store(true, SeqCst);
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    let prepared = h.prepared("a").await;
    let mut events = h.stream(None).await;
    events.next().await;
    let environment = h.provision("a", "delete-race", &prepared, 201).await;
    for _ in 0..2 {
        events.next().await;
    }
    control.hold_list_result.store(true, SeqCst);
    tokio::time::timeout(Duration::from_secs(2), control.list_result_ready.notified()).await.unwrap();
    h.ok(Method::DELETE, &format!("/providers/a/environments/{}", environment.id), Value::Null, 204).await;
    control.list_release.notify_one();
    assert!(matches!(events.next().await, ObserveRecord::Event { event }
        if event.id == environment.id && matches!(event.event,
            EventKind::Gone { cause: GoneCause::DestroyedByRequest })));
}

// Startup is complete only after HTTP responds; a socket pathname alone is insufficient.
async fn wait_hello(client: &Client) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if client.get("http://localhost/v1/hello").send().await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("host did not serve hello before startup deadline");
}
impl Control {
    async fn wait_lists(&self, after: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let notified = self.list_entered.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.list_calls.load(std::sync::atomic::Ordering::SeqCst) > after {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("vendor list did not complete");
    }
}

// A poll-path rejection is sticky within a Direct generation, even if a call
// started earlier succeeds later. Only a delivered refresh repairs that rejection.
#[tokio::test]
async fn poll_rejection_survives_stale_success_until_refresh() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    control.poll.store(true, SeqCst);
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "same-generation").await;
    control.hold_success.store(true, SeqCst);
    let client = h.client.clone();
    let pending = tokio::spawn(async move {
        client.post("http://localhost/v1/providers/a/prepare").json(&json!({"image_digest":"i","tools_digest":"t"})).send().await.unwrap()
    });
    control.success_entered.notified().await;
    control.reject_list.store(true, SeqCst);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let hello: Hello = h.hello().await;
            if matches!(hello.providers[0].readiness, Readiness::MissingCredential { .. }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    control.success_release.notify_one();
    assert_eq!(pending.await.unwrap().status(), 200);
    let hello: Hello = h.hello().await;
    assert!(matches!(hello.providers[0].readiness, Readiness::MissingCredential { .. }));
    h.ok(Method::GET, "/providers/a/environments", Value::Null, 503).await;
    control.reject_list.store(false, SeqCst);
    h.credential("a", "refreshed").await;
    h.ok(Method::GET, "/providers/a/environments", Value::Null, 200).await;
}

// Push lifecycle starts after commit and receives an explicit shutdown signal.
// Serving waits for cleanup before returning instead of relying on instance drop.
#[tokio::test]
async fn push_observer_starts_after_commit_and_stops_with_host() {
    let (mut h, control) = controlled().await;
    h.configure(vec![provider("a", json!({}))]).await;
    tokio::time::timeout(Duration::from_secs(2), control.started.notified()).await.unwrap();
    let hello: Hello = h.hello().await;
    assert_eq!(hello.providers[0].provider, "a");
    h.stop.take().unwrap().send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), control.stopped.notified()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), &mut h.task).await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(2), control.dropped.notified()).await.unwrap();
}

// Route, provider and environment misses share NotFound, while a wrong method
// has its own 405 class. A vendor-facing module can return the same typed 404.
#[tokio::test]
async fn not_found_and_method_statuses() {
    let h = Harness::start().await;
    h.normal().await;
    for path in ["/missing", "/providers/unknown/environments", "/providers/a/environments/unknown"] {
        let error = h.ok(Method::GET, path, Value::Null, 404).await.json::<ProtocolError>().await.unwrap();
        assert!(matches!(error, ProtocolError::NotFound { .. }));
    }
    assert!(matches!(
        h.ok(Method::POST, "/hello", Value::Null, 405).await.json::<ProtocolError>().await.unwrap(),
        ProtocolError::MethodNotAllowed { .. }
    ));
}

// Supervisor CA material must flow through the host's transport construction;
// rejecting an invalid bundle proves host configuration does not discard it.
#[tokio::test]
async fn host_validates_supervisor_proxy_ca() {
    let h = Harness::with_host(Host::new(reference::registry()).with_proxy_ca(b"not a CA".to_vec()), unsafe { libc::geteuid() }).await;
    let mut config = provider("proxy", json!({}));
    config["credential"] = json!({"mode":"proxied","placeholder_token":"placeholder","proxy_url":"http://127.0.0.1:1234"});
    let response =
        h.ok(Method::PUT, "/config", json!({"modules":[{"name":"memory","entrypoint":"reference"}],"providers":[config]}), 422).await;
    assert_eq!(
        response.json::<ProtocolError>().await.unwrap(),
        ProtocolError::Refused { reason: "invalid HTTP transport configuration".into() }
    );
}

// A refresh derives module readiness instead of forcing Ready. The same source
// is used by hello and route admission as external prerequisites change.
#[tokio::test]
async fn credential_refresh_respects_module_readiness() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    control.missing_tool.store(true, SeqCst);
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "valid").await;
    let hello: Hello = h.hello().await;
    assert!(matches!(hello.providers[0].readiness, Readiness::MissingTool { .. }));
    h.ok(Method::GET, "/providers/a/environments", Value::Null, 503).await;
    control.missing_tool.store(false, SeqCst);
    h.ok(Method::GET, "/providers/a/environments", Value::Null, 200).await;
    let hello: Hello = h.hello().await;
    assert!(matches!(hello.providers[0].readiness, Readiness::Ready));
}

// The first poll is eligible immediately, even when subsequent polling is hours
// apart. Refresh wakes the initial observer rather than waiting for the next tick.
#[tokio::test]
async fn first_snapshot_does_not_wait_for_large_poll_interval() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    control.poll.store(true, SeqCst);
    control.list_limit.store(1, SeqCst);
    control.list_period.store(3600, SeqCst);
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    let mut stream = tokio::time::timeout(Duration::from_secs(1), h.stream(None)).await.expect("first snapshot must not wait two hours");
    assert!(matches!(stream.next().await, ObserveRecord::Snapshot {environments,..} if environments.is_empty()));
    // A single slot is indivisible: the immediate poll consumes this shared
    // window, so a subsequent route is rate-limited with a retry hint.
    let response = h.ok(Method::GET, "/providers/a/environments", Value::Null, 429).await;
    assert!(response.headers()["retry-after"].to_str().unwrap().parse::<u64>().unwrap() > 0);
    assert!(matches!(response.json::<ProtocolError>().await.unwrap(), ProtocolError::RateLimited { .. }));
    assert_eq!(control.list_calls.load(SeqCst), 1);
}

// A poll can see absence before the deleting call returns. Only a confirmed
// deletion gets DestroyedByRequest; an ambiguous failed call gets MissingOnList.
#[tokio::test]
async fn poll_during_delete_waits_for_confirmed_cause() {
    use std::sync::atomic::Ordering::SeqCst;
    for failed in [false, true] {
        let (h, control) = controlled().await;
        control.poll.store(true, SeqCst);
        h.configure(vec![provider("a", json!({}))]).await;
        h.credential("a", "ready").await;
        let mut stream = h.stream(None).await;
        stream.next().await;
        let prepared = h.prepared("a").await;
        let environment = h.provision("a", "delete-window", &prepared, 201).await;
        stream.next().await;
        stream.next().await;
        control.hold_destroy.store(true, SeqCst);
        control.fail_destroy.store(failed, SeqCst);
        let client = h.client.clone();
        let deletion = tokio::spawn(async move {
            client.delete(format!("http://localhost/v1/providers/a/environments/{}", environment.id)).send().await.unwrap()
        });
        control.destroy_entered.notified().await;
        let calls = control.list_calls.load(SeqCst);
        control.wait_lists(calls + 1).await; // two completed lists with deletion still pending
        control.destroy_release.notify_one();
        assert_eq!(deletion.await.unwrap().status().as_u16(), if failed { 503 } else { 204 });
        let expected = if failed { GoneCause::MissingOnList } else { GoneCause::DestroyedByRequest };
        assert!(matches!(stream.next().await, ObserveRecord::Event { event } if event.event == EventKind::Gone {cause: expected}));
    }
}

// Shutdown interrupts a held recovery list. A stream already serving HTTP ends
// with normal EOF rather than converting the shutdown signal into a body error.
#[tokio::test]
async fn shutdown_during_recovery_ends_with_clean_eof() {
    use std::sync::atomic::Ordering::SeqCst;
    let (mut h, control) = controlled().await;
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    let mut records = h.stream(None).await;
    records.next().await;
    control.started.notified().await;
    control.hold_list.store(true, SeqCst);
    let sink = control.sink.lock().unwrap().clone().unwrap();
    for n in 0..drydock_host::EVENT_HISTORY_CAPACITY + 1 {
        sink.publish(format!("evict-{n}"), None, None, EventKind::Created);
    }
    tokio::time::timeout(Duration::from_secs(2), control.list_held.notified()).await.unwrap();
    h.stop.take().unwrap().send(()).unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(2), records.stream.next()).await.unwrap().is_none());
    tokio::time::timeout(Duration::from_secs(2), &mut h.task).await.unwrap().unwrap();
}

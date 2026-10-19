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
        let client = rigging_tls::client_builder()
            .unix_socket(path.clone())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        for _ in 0..200 {
            if client.get("http://localhost/v1/hello").send().await.is_ok() {
                return Self {
                    _dir: dir,
                    path,
                    client,
                    task,
                    stop: Some(stop),
                };
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("host did not bind");
    }
    async fn send(&self, method: Method, path: &str, body: Value) -> Response {
        self.client
            .request(method, format!("http://localhost/v1{path}"))
            .json(&body)
            .send()
            .await
            .unwrap()
    }
    async fn ok(&self, method: Method, path: &str, body: Value, status: u16) -> Response {
        let r = self.send(method, path, body).await;
        assert_eq!(r.status().as_u16(), status, "{path}");
        r
    }
    async fn configure(&self, providers: Vec<Value>) {
        self.ok(
            Method::PUT,
            "/config",
            json!({"modules":[{"name":"memory","entrypoint":"reference"}],"providers":providers}),
            204,
        )
        .await;
    }
    async fn credential(&self, p: &str, value: &str) {
        self.ok(
            Method::PUT,
            &format!("/providers/{p}/credential"),
            json!({"value":value}),
            204,
        )
        .await;
    }
    async fn normal(&self) {
        self.configure(vec![provider("a", json!({})), provider("b", json!({}))])
            .await;
        self.credential("a", "one").await;
        self.credential("b", "two").await;
    }
    async fn prepared(&self, p: &str) -> Prepared {
        self.ok(
            Method::POST,
            &format!("/providers/{p}/prepare"),
            json!({"image_digest":"sha256:image","tools_digest":"sha256:tools"}),
            200,
        )
        .await
        .json()
        .await
        .unwrap()
    }
    async fn provision(&self, p: &str, label: &str, prepared: &Prepared, status: u16) -> Sandbox {
        self.ok(
            Method::POST,
            &format!("/providers/{p}/environments"),
            request(label, prepared),
            status,
        )
        .await
        .json()
        .await
        .unwrap()
    }
    async fn stream(&self, since: Option<&str>) -> Records {
        let mut req = self.client.get("http://localhost/v1/events");
        if let Some(s) = since {
            req = req.query(&[("since", s)]);
        }
        let r = req.send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["content-type"], "application/x-ndjson");
        Records {
            stream: r.bytes_stream().boxed(),
            buffer: vec![],
        }
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
                self.buffer
                    .extend(self.stream.next().await.unwrap().unwrap());
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
    let empty: Hello = h
        .ok(Method::GET, "/hello", Value::Null, 200)
        .await
        .json()
        .await
        .unwrap();
    assert!(empty.is_compatible());
    assert!(empty.providers.is_empty());
    h.configure(vec![provider("a", json!({})), provider("b", json!({}))])
        .await;
    let hello: Hello = h
        .ok(Method::GET, "/hello", Value::Null, 200)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(hello.modules[0].name, "memory");
    assert_eq!(hello.providers.len(), 2);
    assert!(
        hello
            .providers
            .iter()
            .all(|p| matches!(p.readiness, Readiness::MissingCredential { .. }))
    );
    h.ok(Method::GET, "/providers/a/environments", Value::Null, 502)
        .await;
    h.ok(
        Method::PUT,
        "/providers/a/credential",
        json!({"value":""}),
        422,
    )
    .await;
    let still_missing: Hello = h
        .ok(Method::GET, "/hello", Value::Null, 200)
        .await
        .json()
        .await
        .unwrap();
    assert!(matches!(
        still_missing.providers[0].readiness,
        Readiness::MissingCredential { .. }
    ));
    h.credential("a", "TOP_SECRET").await;
    let prepared = h.prepared("a").await;
    let s = h.provision("a", "label", &prepared, 201).await;
    h.credential("a", "ROTATED").await;
    h.configure(vec![provider("a", json!({})), provider("b", json!({}))])
        .await;
    let again = h.provision("a", "label", &prepared, 200).await;
    assert_eq!(s, again);
    let bad = json!({"modules":[{"name":"memory","entrypoint":"reference"}],"providers":[provider("c",json!({})),provider("a",json!({"changed":true}))]});
    h.ok(Method::PUT, "/config", bad, 422).await;
    let hello: Hello = h
        .ok(Method::GET, "/hello", Value::Null, 200)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(hello.providers.len(), 2);
    assert!(matches!(hello.providers[0].readiness, Readiness::Ready));
    let malformed = h
        .client
        .put("http://localhost/v1/providers/a/credential")
        .body(r#"{"value":{"TOP_SECRET":123}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), 422);
    assert!(!malformed.text().await.unwrap().contains("TOP_SECRET"));
    h.ok(
        Method::PUT,
        "/config",
        json!({"modules":[{"name":"memory","entrypoint":"unknown"}],"providers":[]}),
        422,
    )
    .await;
}

// Label idempotency and provider isolation hold after every generated create/delete step.
// Generator spans empty state, duplicate labels, both providers, deletion of absent IDs,
// and re-creation after deletion. Real sockets and the reference module are collaborators.
#[hegel::test]
fn generated_label_lifecycle(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let count = tc.draw(gs::integers::<usize>().min_value(1).max_value(12));
    let steps: Vec<_> = (0..count)
        .map(|_| {
            (
                tc.draw(gs::booleans()),
                tc.draw(gs::integers::<usize>().min_value(0).max_value(2)),
                tc.draw(gs::booleans()),
            )
        })
        .collect();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let h = Harness::start().await;
        h.normal().await;
        let prepared = [h.prepared("a").await, h.prepared("b").await];
        let mut model: BTreeMap<(usize, usize), Sandbox> = BTreeMap::new();
        for (provider, label, delete) in steps {
            let p = usize::from(provider);
            let name = ["a", "b"][p];
            let key = (p, label);
            let path = format!("/providers/{name}/environments");
            if delete {
                let id = model
                    .remove(&key)
                    .map(|s| s.id)
                    .unwrap_or_else(|| "absent".into());
                h.ok(Method::DELETE, &format!("{path}/{id}"), Value::Null, 204)
                    .await;
                h.ok(Method::DELETE, &format!("{path}/{id}"), Value::Null, 204)
                    .await;
            } else {
                let old = model.get(&key);
                let s = h
                    .provision(
                        name,
                        &format!("label-{label}"),
                        &prepared[p],
                        if old.is_some() { 200 } else { 201 },
                    )
                    .await;
                if let Some(old) = old {
                    assert_eq!(&s, old);
                }
                model.insert(key, s);
            }
            for name in ["a", "b"] {
                let actual: Vec<Sandbox> = h
                    .ok(
                        Method::GET,
                        &format!("/providers/{name}/environments"),
                        Value::Null,
                        200,
                    )
                    .await
                    .json()
                    .await
                    .unwrap();
                let expected: Vec<_> = model
                    .values()
                    .filter(|s| s.provider == name)
                    .cloned()
                    .collect();
                assert_eq!(actual.len(), expected.len());
                for s in &expected {
                    assert!(actual.contains(s));
                    let inspected: Sandbox = h
                        .ok(
                            Method::GET,
                            &format!("/providers/{name}/environments/{}", s.id),
                            Value::Null,
                            200,
                        )
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

// Simultaneous retries with one label create one sandbox and emit only one creation pair.
// since is exclusive; unknown cursors produce a complete gap snapshot across providers.
#[tokio::test]
async fn concurrent_provision_and_event_resume() {
    let h = Harness::start().await;
    h.normal().await;
    let prepared = h.prepared("a").await;
    let mut initial = h.stream(None).await;
    let snapshot = initial.next().await;
    assert!(matches!(&snapshot,ObserveRecord::Snapshot {sandboxes,..} if sandboxes.is_empty()));
    let start = cursor(&snapshot).to_owned();
    let (first, second) = tokio::join!(
        h.send(
            Method::POST,
            "/providers/a/environments",
            request("same", &prepared)
        ),
        h.send(
            Method::POST,
            "/providers/a/environments",
            request("same", &prepared)
        )
    );
    let statuses = [first.status().as_u16(), second.status().as_u16()];
    assert!(statuses.contains(&201) && statuses.contains(&200));
    assert_eq!(
        first.json::<Sandbox>().await.unwrap(),
        second.json::<Sandbox>().await.unwrap()
    );
    let created = initial.next().await;
    assert!(
        matches!(&created,ObserveRecord::Event {event} if matches!(event.event,EventKind::Created))
    );
    let running = initial.next().await;
    assert!(
        matches!(&running,ObserveRecord::Event {event} if matches!(event.event,EventKind::Running {..}))
    );
    let mut resumed = h.stream(Some(cursor(&created))).await;
    assert_eq!(resumed.next().await, running);
    let mut replay = h.stream(Some(&start)).await;
    assert_eq!(replay.next().await, created);
    assert_eq!(replay.next().await, running);
    let pb = h.prepared("b").await;
    h.provision("b", "second", &pb, 201).await;
    let mut gap = h.stream(Some("expired-cursor")).await;
    assert!(
        matches!(gap.next().await,ObserveRecord::Snapshot {sandboxes,..} if sandboxes.len()==2)
    );
}

// Every typed module error retains its class and agreed status, retry hints, and
// CredentialRejected changes hello readiness until an explicit credential refresh.
#[tokio::test]
async fn all_typed_error_classes() {
    let h = Harness::start().await;
    let errors = [
        (422, json!({"kind":"refused","reason":"no"})),
        (
            503,
            json!({"kind":"unavailable","reason":"no","retry_after":3}),
        ),
        (
            429,
            json!({"kind":"rate_limited","reason":"no","retry_after":7}),
        ),
        (402, json!({"kind":"quota_exhausted","reason":"no"})),
        (502, json!({"kind":"credential_rejected","reason":"no"})),
        (
            500,
            json!({"kind":"internal","reason":"no","provider_error":"raw vendor error"}),
        ),
    ];
    h.configure(
        errors
            .iter()
            .enumerate()
            .map(|(n, (_, e))| provider(&format!("p{n}"), json!({"fault":e})))
            .collect(),
    )
    .await;
    for (n, (status, error)) in errors.iter().enumerate() {
        let p = format!("p{n}");
        h.credential(&p, "secret").await;
        let response = h
            .ok(
                Method::GET,
                &format!("/providers/{p}/environments"),
                Value::Null,
                *status,
            )
            .await;
        if let Some(retry) = error.get("retry_after") {
            assert_eq!(response.headers()["retry-after"], retry.to_string());
        }
        assert_eq!(response.json::<Value>().await.unwrap(), *error);
    }
    let hello: Hello = h
        .ok(Method::GET, "/hello", Value::Null, 200)
        .await
        .json()
        .await
        .unwrap();
    assert!(matches!(
        hello.providers[4].readiness,
        Readiness::MissingCredential { .. }
    ));
    h.credential("p4", "refreshed").await;
    let hello: Hello = h
        .ok(Method::GET, "/hello", Value::Null, 200)
        .await
        .json()
        .await
        .unwrap();
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
    h.ok(
        Method::POST,
        "/providers/b/environments",
        request("cross", &pa),
        422,
    )
    .await;
    for cpus in [json!(0), json!(-1), json!("NaN")] {
        let mut r = request("bad", &pa);
        r["size"]["cpus"] = cpus;
        h.ok(Method::POST, "/providers/a/environments", r, 422)
            .await;
    }
    for direct in [
        json!({"kind":"cidr","cidr":"1.2.3.4/33"}),
        json!({"kind":"host_port","host":"bad host","port":1}),
        json!({"kind":"host_port","host":"host","port":0}),
        json!({"kind":"host_port","host":"valid.example","port":443}),
    ] {
        let mut r = request("bad", &pa);
        r["egress"] = json!({"mode":"deny_all","direct":[direct]});
        h.ok(Method::POST, "/providers/a/environments", r, 422)
            .await;
    }
    let a = h.provision("a", "a", &pa, 201).await;
    let b = h.provision("b", "b", &pb, 201).await;
    let path = format!("/providers/a/environments/{}", a.id);
    let reach: Reach = h
        .ok(Method::POST, &format!("{path}/reach"), Value::Null, 200)
        .await
        .json()
        .await
        .unwrap();
    assert!(matches!(reach,Reach::Relay {path:p} if p==format!("/v1{path}/relay")));
    let token: ResumeToken = h
        .ok(Method::POST, &format!("{path}/suspend"), Value::Null, 200)
        .await
        .json()
        .await
        .unwrap();
    let repeat: ResumeToken = h
        .ok(Method::POST, &format!("{path}/suspend"), Value::Null, 200)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(token, repeat);
    let paused: Sandbox = h
        .ok(Method::GET, &path, Value::Null, 200)
        .await
        .json()
        .await
        .unwrap();
    assert!(matches!(paused.state, Observation::Stopped { .. }));
    h.ok(
        Method::POST,
        &format!("/providers/b/environments/{}/resume", b.id),
        serde_json::to_value(&token).unwrap(),
        422,
    )
    .await;
    for _ in 0..2 {
        h.ok(
            Method::POST,
            &format!("{path}/resume"),
            serde_json::to_value(&token).unwrap(),
            204,
        )
        .await;
    }
    let running: Sandbox = h
        .ok(Method::GET, &path, Value::Null, 200)
        .await
        .json()
        .await
        .unwrap();
    assert!(matches!(running.state, Observation::Running));
    let exported: Export = h
        .ok(Method::POST, &format!("{path}/export"), Value::Null, 200)
        .await
        .json()
        .await
        .unwrap();
    assert!(exported.reference.contains(&a.id));
    let quota: Quota = h
        .ok(Method::GET, "/providers/a/quota", Value::Null, 200)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(quota.concurrency_in_use, Some(1));
    h.ok(
        Method::GET,
        "/providers/a/usage?start=2026-01-01T00:00:00Z&end=2026-01-02T00:00:00Z",
        Value::Null,
        200,
    )
    .await;
    for query in [
        "start=bad&end=bad",
        "start=2026-01-02T00:00:00Z&end=2026-01-01T00:00:00Z",
        "",
    ] {
        h.ok(
            Method::GET,
            &format!("/providers/a/usage?{query}"),
            Value::Null,
            422,
        )
        .await;
    }
    h.ok(Method::GET, &format!("{path}/relay"), Value::Null, 422)
        .await;
    h.ok(
        Method::GET,
        "/providers/a/environments/usage",
        Value::Null,
        422,
    )
    .await;
    h.ok(Method::GET, "/providers/a", Value::Null, 422).await;
}

async fn raw_upgrade(
    h: &Harness,
    path: &str,
    command: Option<Value>,
) -> BufReader<tokio::net::UnixStream> {
    let socket = tokio::net::UnixStream::connect(&h.path).await.unwrap();
    let mut io = BufReader::new(socket);
    let body = command.as_ref().map(Value::to_string).unwrap_or_default();
    let (method, protocol) = if command.is_some() {
        ("POST", "drydock-stream")
    } else {
        ("GET", "drydock-relay")
    };
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
                tokio::time::timeout(Duration::from_secs(5), read.read_to_end(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
                bytes
            }
        );
        assert_eq!(received, data);
    }
    let mut stream = raw_upgrade(
        &h,
        &format!("{path}/exec"),
        Some(json!({"command":["echo","hello"]})),
    )
    .await;
    let mut data = vec![];
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data, b"hello\n");
}

// Kernel peer credentials gate even hello; a caller-supplied HTTP header cannot impersonate UID.
#[tokio::test]
async fn unix_peer_rejected() {
    let h = Harness::with_uid(unsafe { libc::geteuid() } + 1).await;
    let r = h
        .client
        .get("http://localhost/v1/hello")
        .header("X-Uid", unsafe { libc::geteuid() })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}

// Loopback hosts create a private token file, require bearer auth, and reject wrong tokens.
#[tokio::test]
async fn tcp_bearer_auth() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let token = dir.path().join("token");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let host = Host::new(reference::registry());
    let path = token.clone();
    let task = tokio::spawn(async move {
        host.serve_tcp(addr, path, std::future::pending())
            .await
            .unwrap();
    });
    for _ in 0..200 {
        if token.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let secret = std::fs::read_to_string(&token).unwrap();
    assert_eq!(
        std::fs::metadata(&token).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let client = rigging_tls::client_builder().no_proxy().build().unwrap();
    let url = format!("http://{addr}/v1/hello");
    assert_eq!(client.get(&url).send().await.unwrap().status(), 401);
    assert_eq!(
        client
            .get(&url)
            .bearer_auth("wrong")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .get(&url)
            .header("Cookie", format!("rigging_token={secret}"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .get(&url)
            .bearer_auth("wrong")
            .header("Cookie", format!("rigging_token={secret}"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .get(&url)
            .bearer_auth(secret)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    task.abort();
}

// After bounded history eviction, readers get a complete snapshot and can resume at
// its new cursor without a missing transition. An initial snapshot failure is typed.
#[tokio::test]
async fn event_eviction_and_initial_error() {
    let h = Harness::start().await;
    h.normal().await;
    let prepared = h.prepared("a").await;
    let mut initial = h.stream(None).await;
    let start = initial.next().await;
    drop(initial);
    for n in 0..513 {
        h.provision("a", &format!("item-{n}"), &prepared, 201).await;
    }
    let mut expired = h.stream(Some(cursor(&start))).await;
    let snapshot = expired.next().await;
    assert!(matches!(&snapshot,ObserveRecord::Snapshot {sandboxes,..} if sandboxes.len()==513));
    let pb = h.prepared("b").await;
    h.provision("b", "after-snapshot", &pb, 201).await;
    let created = expired.next().await;
    assert!(
        matches!(&created,ObserveRecord::Event {event} if event.provider=="b" && matches!(event.event,EventKind::Created) && chrono::DateTime::parse_from_rfc3339(&event.timestamp).is_ok())
    );
    let mut resumed = h.stream(Some(cursor(&snapshot))).await;
    assert_eq!(resumed.next().await, created);
    let bad = Harness::start().await;
    bad.configure(vec![provider(
        "fault",
        json!({"fault":{"kind":"unavailable","reason":"offline","retry_after":null}}),
    )])
    .await;
    bad.credential("fault", "delivered").await;
    let response = bad.ok(Method::GET, "/events", Value::Null, 503).await;
    assert!(matches!(
        response.json::<ProtocolError>().await.unwrap(),
        ProtocolError::Unavailable { .. }
    ));
}

// The supervisor proxy receives absolute vendor requests and the placeholder token.
// This stand-in represents the external proxy network boundary, not a mocked HTTP client.
#[tokio::test]
async fn proxied_credentials_use_supervisor_proxy() {
    use drydock_host::module::Credentials;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
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
        io.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        head
    });
    let mode = CredentialMode::Proxied {
        placeholder_token: Secret::new("proxy-placeholder"),
        proxy_url: format!("http://{address}"),
    };
    let credentials = Credentials::new(mode.clone(), None).unwrap();
    let response = credentials
        .http
        .get("http://vendor.invalid/resource")
        .bearer_auth(credentials.token().unwrap().expose())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
    let head = task.await.unwrap();
    assert!(head.starts_with("GET http://vendor.invalid/resource HTTP/1.1\r\n"));
    assert!(
        head.to_lowercase()
            .contains("authorization: bearer proxy-placeholder")
    );
    assert!(Credentials::new(mode.clone(), Some(b"invalid PEM")).is_err());
    let h = Harness::start().await;
    let mut config = provider("proxied", json!({}));
    config["credential"] = serde_json::to_value(mode).unwrap();
    h.configure(vec![config]).await;
    let hello: Hello = h
        .ok(Method::GET, "/hello", Value::Null, 200)
        .await
        .json()
        .await
        .unwrap();
    assert!(matches!(hello.providers[0].readiness, Readiness::Ready));
    h.ok(
        Method::PUT,
        "/providers/proxied/credential",
        json!({"value":"direct"}),
        422,
    )
    .await;
}

// Extractor failures (oversized bodies, invalid methods and path encodings) use the
// same typed refusal body as semantic validation, without returning request values.
#[tokio::test]
async fn transport_rejections_are_typed() {
    let h = Harness::start().await;
    for (method, path, body) in [
        (Method::POST, "/hello", String::new()),
        (Method::PUT, "/config", "x".repeat(2 * 1024 * 1024 + 1)),
        (Method::GET, "/providers/%FF/environments", String::new()),
    ] {
        let response = h
            .client
            .request(method, format!("http://localhost/v1{path}"))
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 422);
        assert!(matches!(
            response.json::<ProtocolError>().await.unwrap(),
            ProtocolError::Refused { .. }
        ));
    }
}

// Shutdown ends long-lived event bodies before draining HTTP, and removes the owned socket.
#[tokio::test]
async fn shutdown_closes_event_stream() {
    let mut h = Harness::start().await;
    h.normal().await;
    let prepared = h.prepared("a").await;
    let sandbox = h.provision("a", "shutdown", &prepared, 201).await;
    let mut relay = raw_upgrade(
        &h,
        &format!("/providers/a/environments/{}/relay", sandbox.id),
        None,
    )
    .await;
    let mut records = h.stream(None).await;
    records.next().await;
    h.stop.take().unwrap().send(()).unwrap();
    let mut bytes = vec![];
    tokio::time::timeout(Duration::from_secs(2), relay.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert!(bytes.is_empty());
    assert!(
        tokio::time::timeout(Duration::from_secs(2), records.stream.next())
            .await
            .unwrap()
            .is_none()
    );
    tokio::time::timeout(Duration::from_secs(2), &mut h.task)
        .await
        .unwrap()
        .unwrap();
    assert!(!h.path.exists());
}

#[derive(Default)]
struct Control {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    list_error: std::sync::atomic::AtomicBool,
    hold_list: std::sync::atomic::AtomicBool,
    list_entered: tokio::sync::Notify,
    list_release: tokio::sync::Notify,
    snapshot_row: std::sync::Mutex<Option<Sandbox>>,
    list_calls: std::sync::atomic::AtomicUsize,
    sink: std::sync::Mutex<Option<drydock_host::EventSink>>,
}
struct ControlledModule(std::sync::Arc<Control>);
struct ControlledProvider {
    inner: Box<dyn drydock_host::module::Provider>,
    control: std::sync::Arc<Control>,
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
        sink: drydock_host::EventSink,
    ) -> drydock_host::module::Result<Box<dyn drydock_host::module::Provider>> {
        *self.0.sink.lock().unwrap() = Some(sink.clone());
        let inner =
            drydock_host::module::Module::configure(&reference::ReferenceModule, c, sink).await?;
        Ok(Box::new(ControlledProvider {
            inner,
            control: self.0.clone(),
        }))
    }
}
#[async_trait::async_trait]
impl drydock_host::module::Provider for ControlledProvider {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }
    async fn prepare(
        &mut self,
        r: PrepareRequest,
        c: &drydock_host::module::Credentials,
    ) -> drydock_host::module::Result<Prepared> {
        if c.token().is_some_and(|t| t.expose() == "old") {
            self.control.entered.notify_one();
            self.control.release.notified().await;
            return Err(ProtocolError::CredentialRejected {
                reason: "old credential rejected".into(),
            });
        }
        self.inner.prepare(r, c).await
    }
    async fn provision(
        &mut self,
        r: ProvisionRequest,
        c: &drydock_host::module::Credentials,
    ) -> drydock_host::module::Result<(Sandbox, bool)> {
        self.inner.provision(r, c).await
    }
    async fn list(
        &mut self,
        c: &drydock_host::module::Credentials,
    ) -> drydock_host::module::Result<Vec<Sandbox>> {
        use std::sync::atomic::Ordering::SeqCst;
        self.control.list_calls.fetch_add(1, SeqCst);
        if self.control.list_error.load(SeqCst) {
            return Err(ProtocolError::Unavailable {
                reason: "vendor unavailable".into(),
                retry_after: None,
            });
        }
        if self.control.hold_list.load(SeqCst) {
            self.control.list_entered.notify_one();
            self.control.list_release.notified().await;
        }
        let mut rows = self.inner.list(c).await?;
        if let Some(row) = self.control.snapshot_row.lock().unwrap().clone() {
            rows.push(row);
        }
        Ok(rows)
    }
    async fn inspect(
        &mut self,
        id: &str,
        c: &drydock_host::module::Credentials,
    ) -> drydock_host::module::Result<Sandbox> {
        self.inner.inspect(id, c).await
    }
    async fn destroy(
        &mut self,
        id: &str,
        c: &drydock_host::module::Credentials,
    ) -> drydock_host::module::Result<()> {
        self.inner.destroy(id, c).await
    }
    async fn reach(
        &mut self,
        id: &str,
        c: &drydock_host::module::Credentials,
    ) -> drydock_host::module::Result<Reach> {
        self.inner.reach(id, c).await
    }
}
async fn controlled() -> (Harness, std::sync::Arc<Control>) {
    let control = std::sync::Arc::new(Control::default());
    let registry = drydock_host::module::Registry::from([(
        "reference".into(),
        std::sync::Arc::new(ControlledModule(control.clone()))
            as std::sync::Arc<dyn drydock_host::module::Module>,
    )]);
    (
        Harness::with_host(Host::new(registry), unsafe { libc::geteuid() }).await,
        control,
    )
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
    tokio::time::timeout(Duration::from_secs(2), control.entered.notified())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        h.ok(Method::GET, "/hello", Value::Null, 200).await;
        h.ok(Method::GET, "/providers/b/environments", Value::Null, 200)
            .await;
        h.credential("a", "new").await;
    })
    .await
    .expect("other providers, hello, and refresh must not wait for vendor A");
    control.release.notify_one();
    assert_eq!(pending.await.unwrap().status(), 502);
    let hello: Hello = h
        .ok(Method::GET, "/hello", Value::Null, 200)
        .await
        .json()
        .await
        .unwrap();
    assert!(matches!(hello.providers[0].readiness, Readiness::Ready));
    h.prepared("a").await;
}

// A complete snapshot cannot omit unready providers: refuse before invoking their
// vendor API, rather than reporting their existing sandboxes as missing.
#[tokio::test]
async fn snapshots_never_call_unready_providers() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    h.configure(vec![provider("a", json!({}))]).await;
    h.ok(Method::GET, "/events", Value::Null, 502).await;
    assert_eq!(control.list_calls.load(SeqCst), 0);
    h.credential("a", "ready").await;
    let mut records = h.stream(None).await;
    assert!(matches!(
        records.next().await,
        ObserveRecord::Snapshot { .. }
    ));
    assert_eq!(control.list_calls.load(SeqCst), 1);
}

// After headers are sent, a failed recovery snapshot fails the body, rather than
// reporting normal EOF or introducing an undocumented NDJSON terminal-error shape.
#[tokio::test]
async fn recovery_snapshot_error_fails_stream() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    let mut records = h.stream(None).await;
    records.next().await;
    // A synchronous burst evicts cursor zero before the server can poll its log.
    control.list_error.store(true, SeqCst);
    let sink = control.sink.lock().unwrap().clone().unwrap();
    for n in 0..1030 {
        sink.publish(
            format!("id-{n}"),
            None,
            "2026-10-19T00:00:00Z".into(),
            TimestampSource::Adaptor,
            EventKind::Created,
        );
    }
    let failed = tokio::time::timeout(Duration::from_secs(2), records.stream.next())
        .await
        .unwrap();
    assert!(
        matches!(failed, Some(Err(_))),
        "failed snapshot must not look like normal EOF"
    );
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
    let hello: Hello = h
        .ok(Method::GET, "/hello", Value::Null, 200)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(hello.providers.len(), 2);
    assert_eq!(s, h.provision("a", "retained", &prepared, 200).await);
    h.ok(
        Method::GET,
        "/providers/temporary/environments",
        Value::Null,
        422,
    )
    .await;
}

// Loopback enforcement belongs to Rigging, so the host must propagate its refusal
// without creating a token file or introducing its own parallel bind/auth policy.
#[tokio::test]
async fn tcp_refuses_nonloopback_bind() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    let error = Host::new(reference::registry())
        .serve_tcp("0.0.0.0:0".parse().unwrap(), &token, std::future::pending())
        .await
        .unwrap_err();
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
        .spawn()
        .unwrap();
    let client = rigging_tls::client_builder()
        .unix_socket(path.clone())
        .build()
        .unwrap();
    for _ in 0..200 {
        if path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let mut records = client
        .get("http://localhost/v1/events")
        .send()
        .await
        .unwrap()
        .bytes_stream();
    assert!(records.next().await.unwrap().is_ok());
    // SAFETY: the child PID is live and owned by this test; SIGTERM is its shutdown signal.
    assert_eq!(
        unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGTERM) },
        0
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), records.next())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    assert!(!path.exists());
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
        h.ok(Method::POST, "/providers/a/environments", r, 201)
            .await;
    }
    for field in ["memory_bytes", "disk_bytes"] {
        let mut r = request("negative", &prepared);
        r["size"][field] = json!(-1);
        h.ok(Method::POST, "/providers/a/environments", r, 422)
            .await;
    }
    h.ok(
        Method::GET,
        "/providers/a/usage?start=2026-01-01T00:00:00Z&end=2026-01-01T00:00:00Z",
        Value::Null,
        200,
    )
    .await;
    h.ok(
        Method::PUT,
        "/providers/a/credential",
        json!({"value":""}),
        422,
    )
    .await;
    // A syntactically valid but changed repeat still denotes the existing label.
    let original = h.provision("a", "repeat", &prepared, 201).await;
    let mut changed = request("repeat", &prepared);
    changed["size"]["cpus"] = json!(2);
    changed["egress"] = json!({"mode":"open"});
    let repeat: Sandbox = h
        .ok(Method::POST, "/providers/a/environments", changed, 200)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(repeat, original);
}

// Snapshot cursors precede listing. A concurrent background observation can appear
// in both the snapshot rows and subsequent events, but its event is never skipped.
#[tokio::test]
async fn snapshot_overlap_replays_background_observation() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    control.hold_list.store(true, SeqCst);
    let client = h.client.clone();
    let response = tokio::spawn(async move {
        client
            .get("http://localhost/v1/events?since=expired-cursor")
            .send()
            .await
            .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), control.list_entered.notified())
        .await
        .unwrap();
    let sandbox = Sandbox {
        id: "background".into(),
        label: Some("new".into()),
        provider: "a".into(),
        state: Observation::Running,
        granted_size: None,
        egress: Enforcement::Advisory,
    };
    *control.snapshot_row.lock().unwrap() = Some(sandbox.clone());
    control.sink.lock().unwrap().as_ref().unwrap().publish(
        sandbox.id.clone(),
        sandbox.label.clone(),
        "2026-10-19T00:00:00Z".into(),
        TimestampSource::Adaptor,
        EventKind::Created,
    );
    control.list_release.notify_one();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut records = Records {
        stream: response.bytes_stream().boxed(),
        buffer: vec![],
    };
    let snapshot = records.next().await;
    assert!(
        matches!(&snapshot,ObserveRecord::Snapshot {sandboxes,..} if sandboxes==std::slice::from_ref(&sandbox))
    );
    let event = records.next().await;
    assert!(
        matches!(&event,ObserveRecord::Event {event} if event.id==sandbox.id && matches!(event.event,EventKind::Created))
    );
    assert_ne!(cursor(&snapshot), cursor(&event));
    let mut replay = h.stream(Some(cursor(&snapshot))).await;
    assert_eq!(replay.next().await, event);
}

// An authenticated client that never completes its exec JSON cannot retain a task
// indefinitely: the bounded body-read deadline returns a typed refusal before exec.
#[tokio::test]
async fn incomplete_exec_body_has_deadline() {
    let h = Harness::start().await;
    h.normal().await;
    let prepared = h.prepared("a").await;
    let sandbox = h.provision("a", "slow-body", &prepared, 201).await;
    let mut socket = tokio::net::UnixStream::connect(&h.path).await.unwrap();
    socket.write_all(format!("POST /v1/providers/a/environments/{}/exec HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: drydock-stream\r\nContent-Length: 100\r\n\r\n{{",sandbox.id).as_bytes()).await.unwrap();
    let mut reader = BufReader::new(socket);
    let mut status = String::new();
    tokio::time::timeout(Duration::from_secs(8), reader.read_line(&mut status))
        .await
        .unwrap()
        .unwrap();
    assert!(status.starts_with("HTTP/1.1 422"), "{status}");
    let mut length = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        if line == "\r\n" {
            break;
        }
        if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
            length = Some(value.trim().parse::<usize>().unwrap());
        }
    }
    let mut body = vec![0; length.unwrap()];
    reader.read_exact(&mut body).await.unwrap();
    assert!(
        matches!(serde_json::from_slice::<ProtocolError>(&body).unwrap(),ProtocolError::Refused {reason} if reason=="exec body deadline exceeded")
    );
}

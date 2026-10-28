#[path = "../../drydock-host/tests/support/provider.rs"]
mod provider;
#[path = "../../drydock-host/tests/support/public_server.rs"]
mod public_server;
use drydock::{api::ProviderApi, runtime::Runtime as Host};
use drydock_host::reference;
use drydock_protocol::*;
use futures::{StreamExt, stream::BoxStream};
use provider::{Control, ControlledModule};
use reqwest::{Client, Method, Response};
use serde_json::{Value, json};
use std::{os::unix::fs::PermissionsExt, time::Duration};
use tokio::io::AsyncReadExt;

struct Harness {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    client: Client,
    task: tokio::task::JoinHandle<()>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}
impl Harness {
    async fn start() -> Self {
        Self::with_host(Host::new(reference::registry())).await
    }
    async fn with_host(host: Host) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("host.sock");
        let (stop, rx) = tokio::sync::oneshot::channel();
        let socket = path.clone();
        let task = tokio::spawn(async move {
            public_server::serve_unix(host, socket, async {
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
        self.ok(Method::PUT, "/config", document(providers), 204).await;
    }
    async fn credential(&self, p: &str, value: &str) {
        self.ok(Method::PUT, &format!("/providers/{p}/credential"), json!({"value":value}), 204).await;
    }
    async fn hello(&self) -> Hello {
        self.ok(Method::GET, "/hello", Value::Null, 200).await.json().await.unwrap()
    }
    async fn providers(&self) -> Vec<ProviderDeclaration> {
        self.ok(Method::GET, "/providers", Value::Null, 200).await.json().await.unwrap()
    }
    async fn normal(&self) {
        self.configure(vec![provider("a", json!({})), provider("b", json!({}))]).await;
        self.credential("a", "one").await;
        self.credential("b", "two").await;
    }
    async fn prepared(&self, p: &str) -> Prepared {
        self.ok(
            Method::POST,
            &format!("/providers/{p}/prepare"),
            json!({"image_digest":"sha256:image","tools_digest":"sha256:tools","size":{"cpus":1.0,"memory_bytes":1024,"disk_bytes":0}}),
            200,
        )
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
    json!({"name":name,"module":"reference","settings":settings})
}
/// The configuration document for these providers, each named by its "name".
fn document(providers: Vec<Value>) -> Value {
    let providers: serde_json::Map<_, _> = providers
        .into_iter()
        .map(|mut p| {
            let name = p.as_object_mut().unwrap().remove("name").unwrap();
            (name.as_str().unwrap().to_owned(), p)
        })
        .collect();
    json!({ "providers": providers })
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
    assert!(h.providers().await.is_empty());
    h.configure(vec![provider("a", json!({})), provider("b", json!({}))]).await;
    let providers = h.providers().await;
    assert_eq!(providers[0].module, "reference");
    assert_eq!(providers.len(), 2);
    assert!(providers.iter().all(|p| matches!(p.readiness, Readiness::MissingCredential { .. })));
    h.ok(Method::GET, "/providers/a/environments", Value::Null, 503).await;
    h.ok(Method::PUT, "/providers/a/credential", json!({"value":""}), 422).await;
    assert!(matches!(h.providers().await[0].readiness, Readiness::MissingCredential { .. }));
    h.credential("a", "TOP_SECRET").await;
    let prepared = h.prepared("a").await;
    let s = h.provision("a", "label", &prepared, 201).await;
    let client = drydock::client::Client::unix(&h.path).unwrap();
    let configuration: Configuration = serde_json::from_value(document(vec![provider("a", json!({})), provider("b", json!({}))])).unwrap();
    drydock::conformance::configuration_contract(&client, &configuration, "a", &s).await.unwrap();
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
        let client = drydock::client::Client::unix(&h.path).unwrap();
        drydock::conformance::lifecycle_sequence(&client, ["a", "b"], "generated", &steps).await.unwrap();
    });
}

// Simultaneous retries with one label create one environment and emit only one creation pair.
// since is exclusive; unknown cursors produce a complete gap snapshot across providers.
#[tokio::test]
async fn concurrent_provision_and_event_resume() {
    let h = Harness::start().await;
    h.normal().await;
    let prepared = h.prepared("a").await;
    let client = drydock::client::Client::unix(&h.path).unwrap();
    let options: drydock::conformance::Options = serde_json::from_value(
        json!({"request":request("concurrent", &prepared),"scenarios":["prepare","lifecycle","observation","destroy"]}),
    )
    .unwrap();
    let report = drydock::conformance::run(&client, "a", &options).await;
    assert!(report.passed(), "{report:?}");
}

// Every typed module error retains its class and agreed status, retry hints, and
// CredentialRejected changes hello readiness until an explicit credential refresh.
#[tokio::test]
async fn all_typed_error_classes() {
    let h = Harness::start().await;
    let client = drydock::client::Client::unix(&h.path).unwrap();
    let configuration: Configuration = serde_json::from_value(document(vec![provider("a", json!({}))])).unwrap();
    let mut report = drydock::conformance::Report::default();
    drydock::conformance::error_contract(&client, &configuration, &mut report).await;
    assert!(report.passed(), "{report:?}");
}

// Optional lifecycle operations use opaque IDs; provider-local resume tokens cannot cross
// providers, repeated suspend/resume is idempotent, and malformed semantic inputs are refused.
#[tokio::test]
async fn optional_operations_and_validation() {
    let h = Harness::start().await;
    h.normal().await;
    let client = drydock::client::Client::unix(&h.path).unwrap();
    let prepared = h.prepared("a").await;
    let request: ProvisionRequest = serde_json::from_value(request("optional", &prepared)).unwrap();
    drydock::conformance::optional_contract(&client, "a", "b", &request, &Default::default()).await.unwrap();
    let options: drydock::conformance::Options =
        serde_json::from_value(json!({"request":request,"scenarios":["prepare","semantics"]})).unwrap();
    let report = drydock::conformance::run(&client, "a", &options).await;
    assert!(report.passed(), "{report:?}");
}

// Relay and POST exec preserve the 101 upgrade and bridge raw bytes, including half close
// and payloads larger than the reference stream buffer. Exec is a fake vendor boundary.
#[tokio::test]
async fn relay_and_exec_round_trip() {
    let h = Harness::start().await;
    h.normal().await;
    let prepared = h.prepared("a").await;
    let environment = h.provision("a", "streams", &prepared, 201).await;
    let client = drydock::client::Client::unix(&h.path).unwrap();
    drydock::conformance::stream_contract(&client, "a", &environment.id, &Default::default()).await.unwrap();
}

// Loopback hosts create a private token file, require bearer auth, and reject wrong tokens.
#[tokio::test]
async fn tcp_bearer_auth() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let token = dir.path().join("token");
    let server = rigging_http_serve::TcpServer::bind("127.0.0.1:0".parse().unwrap(), &token).await.unwrap();
    let addr = server.local_addr().unwrap();
    // The thin Rust host owns the loopback listener; the server is not served over TCP.
    let host = drydock_host::Host::new(reference::registry());
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
    drydock::conformance::authentication(
        &drydock::client::Client::external(&format!("http://{addr}"), Secret::new(secret.clone())).unwrap(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
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
    let count = drydock::runtime::EVENT_HISTORY_CAPACITY / 2 + 1;
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

// Extractor failures (oversized bodies, invalid methods and path encodings) use the
// same typed refusal body as semantic validation, without returning request values.
#[tokio::test]
async fn transport_rejections_are_typed() {
    let h = Harness::start().await;
    for (method, path, body) in [
        (Method::POST, "/providers/a/prepare", "x".repeat(2 * 1024 * 1024 + 1)),
        (Method::GET, "/providers/%FF/environments", String::new()),
    ] {
        let response = h.client.request(method, format!("http://localhost/v1{path}")).body(body).send().await.unwrap();
        assert_eq!(response.status(), 422);
        assert!(matches!(response.json::<ProtocolError>().await.unwrap(), ProtocolError::Refused { .. }));
    }
    // A malformed field is named with the decoder's reason, never its value.
    let body = json!({"image_digest":"i","tools_digest":"t","size":{"cpus":"secret-value","memory_bytes":1,"disk_bytes":0}});
    let error: ProtocolError = h.ok(Method::POST, "/providers/a/prepare", body, 422).await.json().await.unwrap();
    assert!(matches!(&error, ProtocolError::Refused { reason } if reason.contains("size.cpus") && !reason.contains("secret")), "{error}");
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
    let mut relay = drydock::client::Client::unix(&h.path).unwrap().relay("a", &environment.id).await.unwrap();
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

async fn controlled() -> (Harness, std::sync::Arc<Control>) {
    let control = std::sync::Arc::new(Control::default());
    let registry = drydock_host::module::Registry::from([(
        "reference".into(),
        std::sync::Arc::new(ControlledModule(control.clone())) as std::sync::Arc<dyn drydock_host::module::Module>,
    )]);
    (Harness::with_host(Host::new(registry)).await, control)
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
            .json(&json!({"image_digest":"image","tools_digest":"tools","size":{"cpus":1.0,"memory_bytes":1024,"disk_bytes":0}}))
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
    assert!(matches!(h.providers().await[0].readiness, Readiness::Ready));
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
    let mut events = h.stream(None).await;
    events.next().await;
    let environment = h.provision("b", "healthy", &prepared, 201).await;
    // Wait for polling to see the new environment before taking a fresh snapshot.
    assert!(matches!(events.next().await, ObserveRecord::Event { event } if event.id == environment.id));
    let mut records = h.stream(None).await;
    let record = serde_json::to_value(records.next().await).unwrap();
    assert_eq!(record["environments"][0]["id"], environment.id);
    assert!(record["unavailable_providers"]["a"].is_object());
    assert!(control.list_calls.load(SeqCst) > 0);
    assert!(control.list_credentials.lock().unwrap().iter().all(|token| token.as_deref() == Some("ready")));
}

// Before the first successful poll, missing credentials are provider-local;
// refreshing them lets normal polling produce a complete cached snapshot.
#[tokio::test]
async fn unready_polled_provider_has_snapshot_marker() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
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
    assert!(matches!(cached.next().await, ObserveRecord::Snapshot { environments, .. } if *environments == vec![environment.clone()]));
    control.missing_tool.store(true, SeqCst);
    let mut unavailable = h.stream(None).await;
    let record = serde_json::to_value(unavailable.next().await).unwrap();
    assert_eq!(record["environments"], json!([]));
    assert_eq!(record["unavailable_providers"]["a"]["kind"], "unavailable");
    control.missing_tool.store(false, SeqCst);
    let mut repaired = h.stream(None).await;
    assert!(matches!(repaired.next().await, ObserveRecord::Snapshot { environments, unavailable_providers, .. }
        if *environments == vec![environment.clone()] && unavailable_providers.is_empty()));
}

// A later factory failure leaves both existing providers and credentials intact,
// and none of the earlier successful additions in that document become visible.
#[tokio::test]
async fn partial_factory_failure_preserves_configuration() {
    let h = Harness::start().await;
    h.normal().await;
    let prepared = h.prepared("a").await;
    let s = h.provision("a", "retained", &prepared, 201).await;
    let providers = vec![
        provider("a", json!({})),
        provider("b", json!({})),
        provider("temporary", json!({})),
        provider("fails", json!({"fault":"invalid error"})),
    ];
    h.ok(Method::PUT, "/config", document(providers), 422).await;
    assert_eq!(h.providers().await.len(), 2);
    assert_eq!(s, h.provision("a", "retained", &prepared, 200).await);
    h.ok(Method::GET, "/providers/temporary/environments", Value::Null, 404).await;
}

// Loopback enforcement belongs to Rigging, so the host must propagate its refusal
// without creating a token file or introducing its own parallel bind/auth policy.
#[tokio::test]
async fn tcp_refuses_nonloopback_bind() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    let error = drydock_host::Host::new(reference::registry())
        .serve_tcp("0.0.0.0:0".parse().unwrap(), &token, std::future::pending())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(!token.exists());
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
        if c == cursor(&running) && *environments == vec![environment.clone()]));
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
    let client = drydock::client::Client::unix(&h.path).unwrap();
    let options: drydock::conformance::Options = serde_json::from_value(
        json!({"request":request("polled", &prepared),"scenarios":["prepare","lifecycle","observation","destroy","metering"]}),
    )
    .unwrap();
    let report = drydock::conformance::run(&client, "a", &options).await;
    assert!(report.passed(), "{report:?}");
}

// External changes observed through polling retain typed provider timestamps.
// Failed lists keep prior state; only a successful complete list can report loss.
#[tokio::test]
async fn polled_provider_time_pause_and_authoritative_loss() {
    let h = Harness::start().await;
    h.configure(vec![provider("a", json!({"fixture":true}))]).await;
    h.credential("a", "ready").await;
    let prepared = h.prepared("a").await;
    let environment = h.provision("a", "poll-contract", &prepared, 201).await;
    let client = drydock::client::Client::unix(&h.path).unwrap();
    let options: drydock::conformance::Options = serde_json::from_value(json!({"request":request("poll-probes", &prepared)})).unwrap();
    let mut report = drydock::conformance::Report::default();
    drydock::conformance::poll_contract(&client, "a", &options, &environment, &mut report).await;
    assert!(report.passed(), "{report:?}");
}

// Polling has at most half the declared list allowance; a route can use the
// remaining slot. A subsequent route gets the host's typed 429 and Retry-After.
#[tokio::test]
async fn polling_respects_declared_list_budget() {
    use std::sync::atomic::Ordering::SeqCst;
    for global in [false, true] {
        let (h, control) = controlled().await;
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
    let config: ProviderConfiguration = serde_json::from_value(json!({"module":"reference","settings":{}})).unwrap();
    let module = ControlledModule(control);
    let provider = module.configure("a", &config, http).await.unwrap();
    let credentials = Credentials::new(Some(Secret::new("placeholder")));
    let prepared = provider
        .prepare(
            PrepareRequest {
                platform: Some(drydock_protocol::Platform::new("linux", "amd64")),
                route: None,
                image_pull: None,
                size: drydock_protocol::Size { cpus: 2.0, memory_bytes: 4 << 30, disk_bytes: 10 << 30 },
                image_digest: "image".into(),
                tools_digest: "tools".into(),
            },
            &credentials,
        )
        .await
        .unwrap();
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
    control.skip_list_timestamp.store(true, SeqCst);
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    let mut events = h.stream(None).await;
    events.next().await;
    control.hold_list.store(true, SeqCst);
    let time = "2026-01-01T00:00:00Z".parse::<chrono::DateTime<chrono::Utc>>().unwrap();
    *control.timestamp.lock().unwrap() = Some(time);
    control.vendor.lock().unwrap().row = Some(Environment {
        platform: None,
        id: "external".into(),
        label: None,
        provider: "a".into(),
        state: Observation::Running,
        granted_size: Some(Size { cpus: 1.0, memory_bytes: 0, disk_bytes: 0 }),
        egress: Enforcement::Advisory,
        egress_measured: false,
        egress_policy: None,
        timestamp: None,
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
    h.ok(Method::PUT, "/config", document(vec![provider("a", json!({"poll_interval_ms":0}))]), 422).await;
    assert!(h.providers().await.is_empty());
    let (h, control) = controlled().await;
    control.list_limit.store(1, std::sync::atomic::Ordering::SeqCst);
    control.list_period.store(u64::MAX, std::sync::atomic::Ordering::SeqCst);
    h.ok(Method::PUT, "/config", document(vec![provider("a", json!({}))]), 422).await;
    assert!(h.providers().await.is_empty());
}

// A successful deletion can race a list response containing the pre-delete row.
// That stale poll must not discard attribution before the next list sees absence.
#[tokio::test]
async fn destroy_attribution_survives_stale_poll() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
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
    control.list_result_release.notify_one();
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
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "same-generation").await;
    control.hold_success.store(true, SeqCst);
    let client = h.client.clone();
    let pending = tokio::spawn(async move {
        client
            .post("http://localhost/v1/providers/a/prepare")
            .json(&json!({"image_digest":"i","tools_digest":"t","size":{"cpus":1.0,"memory_bytes":1024,"disk_bytes":0}}))
            .send()
            .await
            .unwrap()
    });
    control.success_entered.notified().await;
    control.reject_list.store(true, SeqCst);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if matches!(h.providers().await[0].readiness, Readiness::MissingCredential { .. }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut records = h.stream(None).await;
    let ObserveRecord::Snapshot { unavailable_providers, .. } = records.next().await else { panic!("expected snapshot") };
    assert!(matches!(unavailable_providers.get("a"), Some(ProtocolError::CredentialRejected { .. })));
    control.success_release.notify_one();
    assert_eq!(pending.await.unwrap().status(), 200);
    assert!(matches!(h.providers().await[0].readiness, Readiness::MissingCredential { .. }));
    h.ok(Method::GET, "/providers/a/environments", Value::Null, 502).await;
    control.reject_list.store(false, SeqCst);
    h.credential("a", "refreshed").await;
    h.ok(Method::GET, "/providers/a/environments", Value::Null, 200).await;
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

// A refresh derives module readiness instead of forcing Ready. The same source
// is used by hello and route admission as external prerequisites change.
#[tokio::test]
async fn credential_refresh_respects_module_readiness() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    control.missing_tool.store(true, SeqCst);
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "valid").await;
    assert!(matches!(h.providers().await[0].readiness, Readiness::MissingTool { .. }));
    h.ok(Method::GET, "/providers/a/environments", Value::Null, 503).await;
    control.missing_tool.store(false, SeqCst);
    h.ok(Method::GET, "/providers/a/environments", Value::Null, 200).await;
    assert!(matches!(h.providers().await[0].readiness, Readiness::Ready));
}

// The first poll is eligible immediately, even when subsequent polling is hours
// apart. Refresh wakes the initial observer rather than waiting for the next tick.
#[tokio::test]
async fn first_snapshot_does_not_wait_for_large_poll_interval() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
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

// A module that violates its stable declaration after configuration must return a
// typed refusal rather than panic an HTTP task after the cached gate admits it.
#[tokio::test]
async fn disappearing_operation_port_is_a_typed_refusal() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "token").await;
    let prepared = h.prepared("a").await;
    let row = h.provision("a", "port-change", &prepared, 201).await;
    control.disable_exec.store(true, SeqCst);
    let response = h
        .client
        .post(format!("http://localhost/v1/providers/a/environments/{}/exec", row.id))
        .header("connection", "Upgrade")
        .header("upgrade", "drydock-stream")
        .json(&json!({"command":["cat"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 422);
    assert!(
        matches!(response.json::<ProtocolError>().await.unwrap(), ProtocolError::Refused { reason } if reason.ends_with("operation port unavailable"))
    );
    assert!(h.providers().await[0].capabilities.fallback_runner);
}

// Known progress samples preserve the last stable billing baseline, while
// authoritative inventory still exposes progress. Unknown breaks that baseline.
#[tokio::test]
async fn progress_retains_billing_baseline_and_inventory() {
    let (h, control) = controlled().await;
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    let mut events = h.stream(None).await;
    events.next().await;
    let environment = Environment {
        platform: None,
        id: "progress".into(),
        provider: "a".into(),
        label: None,
        state: Observation::Stopped { cause: StopCause::SuspendedByRequest },
        granted_size: Some(Size { cpus: 1., memory_bytes: 0, disk_bytes: 0 }),
        egress: Enforcement::Advisory,
        egress_measured: false,
        egress_policy: None,
        timestamp: None,
    };
    control.vendor.lock().unwrap().row = Some(environment.clone());
    // Wait for the initial stable state, then progress must appear in snapshots
    // without inserting an Unknown state or emitting an extra billing event.
    loop {
        if let ObserveRecord::Event { event } = events.next().await
            && matches!(event.event, EventKind::Stopped { .. })
        {
            break;
        }
    }
    control.vendor.lock().unwrap().row.as_mut().unwrap().state = Observation::Transitioning { phase: TransitionPhase::Starting };
    tokio::time::sleep(Duration::from_millis(40)).await;
    let ObserveRecord::Snapshot { environments, .. } = h.stream(None).await.next().await else { panic!("snapshot") };
    assert!(matches!(environments[0].state, Observation::Transitioning { phase: TransitionPhase::Starting }));
    control.vendor.lock().unwrap().row.as_mut().unwrap().state = Observation::Running;
    let mut kinds = vec![];
    while kinds.len() < 2 {
        if let ObserveRecord::Event { event } = events.next().await {
            kinds.push(event.event);
        }
    }
    assert!(matches!(kinds[0], EventKind::Resumed));
    assert!(matches!(kinds[1], EventKind::Running { .. }));
}

// Cheap polling retains explicit inspect's measured claim while running, and
// clears it when stopped. No network probe is needed for each inventory sample.
#[tokio::test]
async fn cheap_inventory_carries_measured_egress() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    control.skip_egress_measurement.store(true, SeqCst);
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    let env = Environment {
        platform: None,
        id: "measured".into(),
        provider: "a".into(),
        label: None,
        state: Observation::Running,
        granted_size: Some(Size { cpus: 1., memory_bytes: 0, disk_bytes: 0 }),
        egress: Enforcement::Enforced,
        egress_measured: false,
        egress_policy: None,
        timestamp: None,
    };
    control.vendor.lock().unwrap().row = Some(env);
    h.ok(Method::GET, "/providers/a/environments/measured", Value::Null, 200).await;
    control.vendor.lock().unwrap().row.as_mut().unwrap().egress = Enforcement::Advisory;
    let rows: Vec<Environment> = h.ok(Method::GET, "/providers/a/environments", Value::Null, 200).await.json().await.unwrap();
    assert_eq!(rows[0].egress, Enforcement::Enforced);
    // Cheap inventory cannot extend evidence indefinitely after an unmeasured
    // policy change. Expiry is inclusive at exactly sixty seconds.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(60)).await;
    tokio::time::resume();
    let rows: Vec<Environment> = h.ok(Method::GET, "/providers/a/environments", Value::Null, 200).await.json().await.unwrap();
    assert_eq!(rows[0].egress, Enforcement::Advisory);
    // A fresh measurement repairs expiry; an observed stop invalidates that
    // fresh claim immediately rather than waiting for the next deadline.
    control.vendor.lock().unwrap().row.as_mut().unwrap().egress = Enforcement::Enforced;
    h.ok(Method::GET, "/providers/a/environments/measured", Value::Null, 200).await;
    control.vendor.lock().unwrap().row.as_mut().unwrap().egress = Enforcement::Advisory;
    control.vendor.lock().unwrap().row.as_mut().unwrap().state = Observation::Stopped { cause: StopCause::SuspendedByRequest };
    let rows: Vec<Environment> = h.ok(Method::GET, "/providers/a/environments", Value::Null, 200).await.json().await.unwrap();
    assert_eq!(rows[0].egress, Enforcement::Advisory);
}

// Diagnostics are masked against every configured credential, including another
// provider's old generation, before wire/Debug/Display.
#[tokio::test]
async fn diagnostics_mask_all_configured_credentials() {
    let h = Harness::start().await;
    let fault = json!({"fault":{"kind":"internal","reason":"vendor direct-token old-token",
        "provider_error":"validation direct-token old-token"}});
    h.configure(vec![provider("a", fault), provider("b", json!({}))]).await;
    h.credential("a", "direct-token").await;
    h.credential("b", "old-token").await;
    h.credential("b", "new-token").await;
    let response = h.ok(Method::GET, "/providers/a/environments", Value::Null, 500).await;
    let body = response.text().await.unwrap();
    let error: ProtocolError = serde_json::from_str(&body).unwrap();
    for view in [body, error.to_string(), format!("{error:?}")] {
        for secret in ["direct-token", "old-token"] {
            assert!(!view.contains(secret), "{view}");
        }
        assert!(view.contains("validation <REDACTED> <REDACTED>"), "{view}");
    }
}

// An admission error after rejection retains the original context exactly once.
#[tokio::test]
async fn rejected_credential_context_is_not_nested() {
    let h = Harness::start().await;
    h.configure(vec![provider("a", json!({"fixture":true,"fault":{"kind":"credential_rejected","reason":"vendor rejected"}}))]).await;
    h.credential("a", "fixture-token").await;
    h.ok(Method::GET, "/providers/a/environments", Value::Null, 502).await;
    // A stored rejection stays CredentialRejected; it is never a retryable 503.
    let error: ProtocolError = h.ok(Method::GET, "/providers/a/environments", Value::Null, 502).await.json().await.unwrap();
    assert_eq!(error.to_string().matches("provider a operation list").count(), 1);
}

// A request's Drydock-Credential reaches the provider for that call only: it is
// never stored, and its rejection leaves the held credential's readiness alone.
#[tokio::test]
async fn request_credential_overrides_held_credential_for_one_call() {
    let (h, control) = controlled().await;
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "held").await;
    let list = |credential: Option<&'static str>| {
        let mut request = h.client.get("http://localhost/v1/providers/a/environments");
        if let Some(credential) = credential {
            request = request.header("drydock-credential", credential);
        }
        request.send()
    };
    assert_eq!(list(Some("override")).await.unwrap().status(), 200);
    assert_eq!(list(None).await.unwrap().status(), 200);
    let seen = control.list_credentials.lock().unwrap().clone();
    assert_eq!(seen.iter().filter(|token| token.as_deref() == Some("override")).count(), 1);
    assert!(seen.iter().all(|token| matches!(token.as_deref(), Some("override" | "held"))));
    assert_eq!(seen.last().unwrap().as_deref(), Some("held"));
    // The fake vendor rejects "old" once released.
    let client = h.client.clone();
    let rejected = tokio::spawn(async move {
        client
            .post("http://localhost/v1/providers/a/prepare")
            .header("drydock-credential", "old")
            .json(&json!({"image_digest":"i","tools_digest":"t","size":{"cpus":1.0,"memory_bytes":1024,"disk_bytes":0}}))
            .send()
            .await
            .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), control.entered.notified()).await.unwrap();
    control.release.notify_one();
    assert_eq!(rejected.await.unwrap().status(), 502);
    assert!(matches!(h.providers().await[0].readiness, Readiness::Ready));
    h.prepared("a").await;
}

// A vendor resume that succeeded is reported as success even when the cache
// refresh after it fails; the observer reconciles the cache later.
#[tokio::test]
async fn resume_succeeds_when_the_refresh_after_it_fails() {
    let (h, control) = controlled().await;
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    let prepared = h.prepared("a").await;
    let environment = h.provision("a", "resume", &prepared, 201).await;
    let client = drydock::client::Client::unix(&h.path).unwrap();
    let token = client.suspend("a", &environment.id).await.unwrap();
    control.fail_inspect.store(true, std::sync::atomic::Ordering::SeqCst);
    client.resume("a", &environment.id, &token).await.unwrap();
}

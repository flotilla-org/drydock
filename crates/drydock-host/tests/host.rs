use drydock_host::module::{Connection, HttpClient, ObservationMode, ObservedEnvironment, Provisioned};
use drydock_host::{Host, reference};
use drydock_protocol::*;
use futures::{StreamExt, stream::BoxStream};
use reqwest::{Client, Method, Response};
use serde_json::{Value, json};
use std::{os::unix::fs::PermissionsExt, time::Duration};
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
    let client = drydock::client::Client::unix(&h.path).unwrap();
    let configuration: HostConfiguration = serde_json::from_value(
        json!({"modules":[{"name":"memory","entrypoint":"reference"}],"providers":[provider("a",json!({})),provider("b",json!({}))]}),
    )
    .unwrap();
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
    let configuration: HostConfiguration =
        serde_json::from_value(json!({"modules":[{"name":"memory","entrypoint":"reference"}],"providers":[]})).unwrap();
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

// Kernel peer credentials gate even hello; a caller-supplied HTTP header cannot impersonate UID.
#[tokio::test]
async fn unix_peer_rejected() {
    let h = Harness::with_uid(unsafe { libc::geteuid() } + 1).await;
    drydock::conformance::unix_peer_admission(&drydock::client::Client::unix(&h.path).unwrap()).await.unwrap();
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
    let error = h
        .ok(
            Method::POST,
            "/providers/proxied/prepare",
            json!({"image_digest":"i","tools_digest":"t","size":{"cpus":1.0,"memory_bytes":1024,"disk_bytes":0}}),
            502,
        )
        .await;
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

#[derive(Default)]
struct Control {
    poll: std::sync::atomic::AtomicBool,
    execute_http: std::sync::atomic::AtomicBool,
    disable_exec: std::sync::atomic::AtomicBool,
    skip_list_timestamp: std::sync::atomic::AtomicBool,
    skip_egress_measurement: std::sync::atomic::AtomicBool,
    timestamp: std::sync::Mutex<Option<chrono::DateTime<chrono::Utc>>>,
    global_limit: std::sync::atomic::AtomicBool,
    list_limit: std::sync::atomic::AtomicU32,
    list_period: std::sync::atomic::AtomicU64,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,

    hold_list: std::sync::atomic::AtomicBool,
    hold_list_result: std::sync::atomic::AtomicBool,
    list_result_ready: tokio::sync::Notify,
    list_result_release: tokio::sync::Notify,
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
    fn operations(&self) -> drydock_host::module::Operations<'_> {
        drydock_host::module::Operations {
            exec: if self.control.disable_exec.load(std::sync::atomic::Ordering::SeqCst) { None } else { self.inner.operations().exec },
            ..self.inner.operations()
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
                .map_err(|_| ProtocolError::unavailable("transport failure", None))?;
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
            return Err(ProtocolError::unavailable("vendor unavailable", None));
        }
        if let Some(row) = vendor.1 {
            rows.push(ObservedEnvironment {
                egress_policy: None,
                egress_measured: !self.control.skip_egress_measurement.load(SeqCst),
                environment: row,
                timestamp: if self.control.skip_list_timestamp.load(SeqCst) { None } else { *self.control.timestamp.lock().unwrap() },
            });
        }
        if self.control.hold_list_result.swap(false, SeqCst) {
            self.control.list_result_ready.notify_one();
            self.control.list_result_release.notified().await;
        }
        Ok(rows)
    }
    async fn inspect(&self, id: &str, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<ObservedEnvironment> {
        if let Some(row) = self.control.vendor.lock().unwrap().row.clone().filter(|row| row.id == id) {
            return Ok(ObservedEnvironment {
                egress_policy: None,
                egress_measured: true,
                environment: row,
                timestamp: *self.control.timestamp.lock().unwrap(),
            });
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
            Err(ProtocolError::unavailable("ambiguous vendor failure", None))
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
    let config = json!({"modules":[{"name":"memory","entrypoint":"reference"}],"providers":[provider("fault",json!({"fault":{"kind":"unavailable","reason":"sensitive-vendor-reason","provider_error":"provider explanation sensitive-credential-value","retry_after":null}}))]});
    assert_eq!(client.put("http://localhost/v1/config").json(&config).send().await.unwrap().status(), 204);
    let before: Hello = client.get("http://localhost/v1/hello").send().await.unwrap().json().await.unwrap();
    assert!(matches!(before.providers[0].readiness, Readiness::MissingCredential { .. }));
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
    assert!(logs.contains("sensitive-vendor-reason"));
    assert!(logs.contains("provider explanation <REDACTED>"));
    assert!(!logs.contains("provider is not ready"));
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
    let prepared = provider
        .prepare(
            PrepareRequest {
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
    control.poll.store(true, SeqCst);
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
            let hello: Hello = h.hello().await;
            if matches!(hello.providers[0].readiness, Readiness::MissingCredential { .. }) {
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

// Independent push lists start together. Hung calls share one deadline, omit
// even a captured-but-unfinished response, and preserve healthy inventory/replay.
#[tokio::test]
async fn push_snapshot_lists_share_deadline_and_isolate_partial_results() {
    use std::sync::{Arc, atomic::Ordering::SeqCst};
    for count in [1, 3] {
        let controls: Vec<_> = (0..count).map(|_| Arc::new(Control::default())).collect();
        let healthy_control = Arc::new(Control::default());
        let mut registry = drydock_host::module::Registry::from([(
            "reference".into(),
            Arc::new(ControlledModule(healthy_control.clone())) as Arc<dyn drydock_host::module::Module>,
        )]);
        let mut modules = vec![json!({"name":"memory", "entrypoint":"reference"})];
        let mut providers = vec![provider("healthy", json!({}))];
        for (n, control) in controls.iter().enumerate() {
            let name = format!("held-{n}");
            // Alternate a request held before listing and a complete response
            // held before return: neither is an authoritative list at timeout.
            control.hold_list.store(n % 2 == 0, SeqCst);
            control.hold_list_result.store(n % 2 != 0, SeqCst);
            control.vendor.lock().unwrap().row = Some(Environment {
                id: "unfinished".into(),
                provider: name.clone(),
                label: None,
                state: Observation::Running,
                granted_size: None,
                egress: Enforcement::Advisory,
            });
            registry.insert(name.clone(), Arc::new(ControlledModule(control.clone())));
            modules.push(json!({"name":name,"entrypoint":name}));
            let mut p = provider(&name, json!({}));
            p["module"] = json!(name);
            providers.push(p);
        }
        let host = Host::new(registry);
        let h = Harness::with_host(host, unsafe { libc::geteuid() }).await;
        h.ok(Method::PUT, "/config", json!({"modules":modules,"providers":providers}), 204).await;
        h.credential("healthy", "token").await;
        let prepared = h.prepared("healthy").await;
        let row = h.provision("healthy", "visible", &prepared, 201).await;
        for n in 0..count {
            h.credential(&format!("held-{n}"), "token").await;
        }
        let client = h.client.clone();
        let start = tokio::time::Instant::now();
        let pending = tokio::spawn(async move { client.get("http://localhost/v1/events").send().await.unwrap() });
        for (n, control) in controls.iter().enumerate() {
            let entered = if n % 2 == 0 { &control.list_held } else { &control.list_result_ready };
            tokio::time::timeout(Duration::from_secs(1), entered.notified()).await.expect("all lists must start concurrently");
        }
        healthy_control.sink.lock().unwrap().as_ref().unwrap().publish("overlap".into(), None, None, EventKind::Created);
        healthy_control.wait_lists(0).await;
        // Keep socket setup on real time; advance only once all vendor gates
        // have entered, then resume before waiting for the real HTTP response.
        tokio::time::pause();
        tokio::time::advance(drydock_host::PUSH_SNAPSHOT_TIMEOUT).await;
        tokio::time::resume();
        let response = tokio::time::timeout(Duration::from_secs(1), pending).await.unwrap().unwrap();
        assert!(start.elapsed() < Duration::from_secs(6), "deadline must be shared, not per provider");
        let mut records = Records { stream: response.bytes_stream().boxed(), buffer: vec![] };
        let ObserveRecord::Snapshot { environments, unavailable_providers, .. } = records.next().await else { panic!("expected snapshot") };
        assert_eq!(environments, vec![row]);
        assert_eq!(unavailable_providers.len(), count);
        assert!(matches!(records.next().await, ObserveRecord::Event { event } if event.id == "overlap"));
        for error in unavailable_providers.values() {
            assert!(matches!(error, ProtocolError::Unavailable { reason, .. } if reason == "snapshot list timed out"));
        }
    }
}

// Shutdown cancels outstanding push snapshot lists immediately, rather than
// waiting for the vendor deadline or publishing a partial successful snapshot.
#[tokio::test]
async fn shutdown_cancels_held_push_snapshot() {
    use std::sync::atomic::Ordering::SeqCst;
    let control = std::sync::Arc::new(Control::default());
    control.hold_list.store(true, SeqCst);
    let host = Host::new(drydock_host::module::Registry::from([(
        "reference".into(),
        std::sync::Arc::new(ControlledModule(control.clone())) as std::sync::Arc<dyn drydock_host::module::Module>,
    )]));
    let mut h = Harness::with_host(host.clone(), unsafe { libc::geteuid() }).await;
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "token").await;
    let client = h.client.clone();
    let request = tokio::spawn(async move { client.get("http://localhost/v1/events").send().await.unwrap() });
    control.list_held.notified().await;
    h.stop.take().unwrap().send(()).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(1), request).await.expect("shutdown cancels snapshot").unwrap();
    assert_eq!(response.status(), 503);
    assert!(matches!(response.json::<ProtocolError>().await.unwrap(), ProtocolError::Unavailable { .. }));
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
    assert!(h.hello().await.providers[0].capabilities.fallback_runner);
}

// Admission fault: a server allowing this UID must fail a scenario that requires
// rejection of an unauthorized peer. The healthy counterpart uses another UID.
#[tokio::test]
async fn unix_peer_admission_fault_matrix() {
    for admits_this_uid in [false, true] {
        let uid = unsafe { libc::geteuid() } + u32::from(!admits_this_uid);
        let h = Harness::with_uid(uid).await;
        let result = drydock::conformance::unix_peer_admission(&drydock::client::Client::unix(&h.path).unwrap()).await;
        assert_eq!(result.is_ok(), !admits_this_uid);
    }
}

// Known progress samples preserve the last stable billing baseline, while
// authoritative inventory still exposes progress. Unknown breaks that baseline.
#[tokio::test]
async fn progress_retains_billing_baseline_and_inventory() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    control.poll.store(true, SeqCst);
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    let mut events = h.stream(None).await;
    events.next().await;
    let environment = Environment {
        id: "progress".into(),
        provider: "a".into(),
        label: None,
        state: Observation::Stopped { cause: StopCause::SuspendedByRequest },
        granted_size: Some(Size { cpus: 1., memory_bytes: 0, disk_bytes: 0 }),
        egress: Enforcement::Advisory,
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
    control.poll.store(true, SeqCst);
    control.skip_egress_measurement.store(true, SeqCst);
    h.configure(vec![provider("a", json!({}))]).await;
    h.credential("a", "ready").await;
    let env = Environment {
        id: "measured".into(),
        provider: "a".into(),
        label: None,
        state: Observation::Running,
        granted_size: Some(Size { cpus: 1., memory_bytes: 0, disk_bytes: 0 }),
        egress: Enforcement::Enforced,
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
// provider's old generation and proxied placeholder, before wire/Debug/Display.
#[tokio::test]
async fn diagnostics_mask_all_configured_credentials() {
    let h = Harness::start().await;
    let fault = json!({"fault":{"kind":"internal","reason":"vendor direct-token old-token placeholder-token",
        "provider_error":"validation direct-token old-token placeholder-token"}});
    let mut proxy = provider("proxy", json!({}));
    proxy["credential"] = json!({"mode":"proxied","placeholder_token":"placeholder-token","proxy_url":"http://127.0.0.1:12345"});
    h.configure(vec![provider("a", fault), provider("b", json!({})), proxy]).await;
    h.credential("a", "direct-token").await;
    h.credential("b", "old-token").await;
    h.credential("b", "new-token").await;
    let response = h.ok(Method::GET, "/providers/a/environments", Value::Null, 500).await;
    let body = response.text().await.unwrap();
    let error: ProtocolError = serde_json::from_str(&body).unwrap();
    for view in [body, error.to_string(), format!("{error:?}")] {
        for secret in ["direct-token", "old-token", "placeholder-token"] {
            assert!(!view.contains(secret), "{view}");
        }
        assert!(view.contains("validation <REDACTED> <REDACTED> <REDACTED>"), "{view}");
    }
}

// An unrelated module prerequisite must take precedence over a stale proxied
// rejection when the proxy remains eligible for credential repair probes.
#[tokio::test]
async fn proxied_missing_tool_does_not_report_stale_rejection() {
    use std::sync::atomic::Ordering::SeqCst;
    let (h, control) = controlled().await;
    let mut proxy = provider("a", json!({}));
    proxy["credential"] = json!({"mode":"proxied", "placeholder_token":"placeholder", "proxy_url":"http://127.0.0.1:1"});
    h.configure(vec![proxy]).await;
    control.reject_list.store(true, SeqCst);
    h.ok(Method::GET, "/providers/a/environments", Value::Null, 502).await;
    control.missing_tool.store(true, SeqCst);
    let error: ProtocolError = h.ok(Method::GET, "/providers/a/environments", Value::Null, 503).await.json().await.unwrap();
    assert!(error.to_string().contains("test tool absent"));
    assert!(!error.to_string().contains("credential_rejected"));
}

// An admission error after rejection retains the original context exactly once.
#[tokio::test]
async fn rejected_credential_context_is_not_nested() {
    let h = Harness::start().await;
    h.configure(vec![provider(
        "a",
        json!({"fixture":true,"fixture_push":true,"fault":{"kind":"credential_rejected","reason":"vendor rejected"}}),
    )])
    .await;
    h.credential("a", "fixture-token").await;
    h.ok(Method::GET, "/providers/a/environments", Value::Null, 502).await;
    let error: ProtocolError = h.ok(Method::GET, "/providers/a/environments", Value::Null, 503).await.json().await.unwrap();
    assert_eq!(error.to_string().matches("provider a operation list").count(), 1);
}

// Provider-only TOML must reach readiness using the bundled managed binary's
// loadable-module handshake, without declaring a host/module registry in config.
#[tokio::test]
async fn managed_daemon_discovers_reference_module() {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path().join("run");
    let config = drydock::config::Config::parse(
        r#"
[provider.demo]
module = "reference"
credential = {env="PATH"}
image = "image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
settings = {
    poll_interval_ms = 10,
}
"#,
    )
    .unwrap();
    let daemon = drydock::daemon::Daemon::start(
        config,
        &run,
        run.join("keys"),
        vec![drydock::daemon::HostOption {
            optional: false,
            name: "rust".into(),
            connection: drydock::HostConnection::Managed {
                command: vec![env!("CARGO_BIN_EXE_drydock-host").into()],
                runtime: None,
                proxy_environment: Default::default(),
            },
        }],
    )
    .await
    .unwrap();
    assert_eq!(daemon.providers()[0]["readiness"]["status"], "ready");
    // Discovery works before the first pin is published; only prepare/launch need the
    // build's image pin. Stamped builds retain the complete launch assertion.
    let launch = daemon.launch("demo", &drydock::launch::LaunchOptions::default()).await;
    if drydock::launch::build_tools_digest().is_ok() {
        let environment = launch.unwrap();
        assert_eq!(environment.provider, "demo");
        assert_eq!(drydock::daemon::ProviderApi::list(daemon.as_ref(), "demo").await.unwrap(), vec![environment]);
    } else {
        assert!(launch.unwrap_err().to_string().contains("the tools image has not been published yet"));
        assert!(drydock::daemon::ProviderApi::list(daemon.as_ref(), "demo").await.unwrap().is_empty());
    }
    drop(daemon);
    // Supervisor cancellation releases the managed child and its socket lease.
    let lock = drydock::local::lock(&run.join("hosts/rust.lock")).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if lock.try_lock().is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

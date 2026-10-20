use drydock::{
    HostConnection, HostSpec, Supervisor, ToolDetector,
    client::{Client, Error, Observer, StatusCache},
    credentials::*,
};
use drydock_protocol::*;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
};

fn spec() -> HostSpec {
    HostSpec {
        name: "rust".into(),
        connection: HostConnection::Managed { command: vec![env!("CARGO_BIN_EXE_drydock-host").into()], runtime: None, proxy_environment: BTreeMap::new() },
        configuration: serde_json::from_value(serde_json::json!({"modules":[{"name":"memory","entrypoint":"reference"}],"providers":[{"name":"a","module":"memory","settings":{},"credential":{"mode":"direct","credential_reference":"test"}}]})).unwrap(),
        credentials: BTreeMap::from([("test".into(), CredentialReference::Env { name: "PATH".into() })]),
    }
}
async fn prepare(client: &Client) -> Prepared {
    client.prepare("a", &PrepareRequest { image_digest: "sha256:image".into(), tools_digest: "sha256:tools".into() }).await.unwrap()
}
fn request(prepared: Prepared) -> ProvisionRequest {
    ProvisionRequest {
        label: "label".into(),
        prepared,
        size: Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
        egress: EgressRequest::default(),
        ssh_public_key: None,
    }
}
fn supervisor(path: &std::path::Path) -> Supervisor {
    let mut s = Supervisor::new(path.join("run"), Arc::new(BuiltinCredentials::default()));
    s.refresh_interval = Duration::from_millis(20);
    s
}

// ADR 0070: managed hosts spawn, accept idempotent provision, and expose every
// lifecycle/stream route with typed values. Real reference host, real Unix socket.
#[tokio::test]
async fn typed_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let mut host = supervisor(dir.path()).start(spec()).await.unwrap();
    host.ready(Duration::from_secs(5)).await.unwrap();
    let c = &host.client;
    let prepared = prepare(c).await;
    let environment = c.provision("a", &request(prepared.clone())).await.unwrap();
    assert_eq!(c.provision("a", &request(prepared)).await.unwrap(), environment);
    assert_eq!(c.list("a").await.unwrap(), vec![environment.clone()]);
    assert_eq!(c.inspect("a", &environment.id).await.unwrap(), environment);
    assert!(matches!(c.reach("a", &environment.id).await.unwrap(), Reach::Relay { .. }));
    let mut stream = c.relay("a", &environment.id).await.unwrap();
    stream.write_all(b"hello").await.unwrap();
    let mut bytes = [0; 5];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"hello");
    let mut exec = c.exec("a", &environment.id, &ExecRequest { command: vec!["echo".into(), "hello".into()] }).await.unwrap();
    let mut output = String::new();
    exec.read_to_string(&mut output).await.unwrap();
    assert_eq!(output, "hello\n");
    let token = c.suspend("a", &environment.id).await.unwrap();
    c.resume("a", &environment.id, &token).await.unwrap();
    c.export("a", &environment.id).await.unwrap();
    c.quota("a").await.unwrap();
    let period: Period = serde_json::from_value(serde_json::json!({"start":"2026-01-01T00:00:00Z","end":"2026-01-02T00:00:00Z"})).unwrap();
    c.usage("a", &period).await.unwrap();
    c.destroy("a", &environment.id).await.unwrap();
    c.destroy("a", &environment.id).await.unwrap();
    assert!(matches!(c.inspect("a", "missing").await, Err(Error::Protocol(ProtocolError::NotFound { .. }))));
}

// The injected detector reports absent node/uv without ever trying to spawn.
struct Missing;
#[async_trait::async_trait]
impl ToolDetector for Missing {
    async fn available(&self, _: &str) -> bool {
        false
    }
}
#[tokio::test]
async fn missing_runtime_is_not_ready() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = supervisor(dir.path());
    s.detector = Arc::new(Missing);
    for runtime in ["node", "uv"] {
        let mut spec = spec();
        spec.name = runtime.into();
        if let HostConnection::Managed { runtime: tool, .. } = &mut spec.connection {
            *tool = Some(runtime.into());
        }
        let mut host = s.start(spec).await.unwrap();
        assert!(host.ready(Duration::from_secs(2)).await.is_err());
        assert!(matches!(host.status.borrow().readiness, Readiness::MissingTool { .. }));
    }
}

// Killing the real Rust host forces the supervisor to restart it. Observation
// retains its old cursor and receives the marked gap snapshot after restart.
#[tokio::test]
async fn restart_resumes_observe_as_gap() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("pid");
    let mut spec = spec();
    // Process boundary wrapper records the child PID, then execs the reference host.
    if let HostConnection::Managed { command, .. } = &mut spec.connection {
        *command = vec![
            "sh".into(),
            "-c".into(),
            "echo $$ > \"$1\"; shift; exec \"$@\"".into(),
            "host-wrapper".into(),
            pid_file.to_string_lossy().into_owned(),
            env!("CARGO_BIN_EXE_drydock-host").into(),
        ];
    }
    let mut host = supervisor(dir.path()).start(spec).await.unwrap();
    let initial = host.ready(Duration::from_secs(5)).await.unwrap();
    let mut observer = Observer::new(host.client.clone(), None);
    let record = tokio::time::timeout(Duration::from_secs(3), observer.next()).await.unwrap().unwrap();
    assert!(matches!(record, ObserveRecord::Snapshot { .. }));
    let cursor = observer.cursor().unwrap().to_owned();
    let pid: i32 = tokio::fs::read_to_string(&pid_file).await.unwrap().trim().parse().unwrap();
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            host.status.changed().await.unwrap();
            let status = host.status.borrow().clone();
            if status.generation > initial.generation && matches!(status.readiness, Readiness::Ready) {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(observer.cursor(), Some(cursor.as_str()));
    let record = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(record) = observer.next().await {
                break record;
            }
        }
    })
    .await
    .unwrap();
    assert!(matches!(record, ObserveRecord::Snapshot { .. }));
    let new_pid: i32 = tokio::fs::read_to_string(&pid_file).await.unwrap().trim().parse().unwrap();
    assert_ne!(pid, new_pid);
    drop(host);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if unsafe { libc::kill(new_pid, 0) } != 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

// HTTP boundary stand-in: capture call count and return chosen protocol responses.
struct Http {
    calls: Mutex<Vec<String>>,
    version: &'static str,
}
#[async_trait::async_trait]
impl rigging_http_client::HttpClient for Http {
    async fn execute(
        &self,
        request: reqwest::Request,
        _: &rigging_http_client::ChannelLabel,
    ) -> Result<http::Response<bytes::Bytes>, String> {
        self.calls.lock().unwrap().push(request.url().path().to_owned());
        let body = if request.url().path().ends_with("hello") {
            serde_json::json!({"protocol_version":self.version,"host_version":"test","modules":[],"providers":[]}).to_string()
        } else {
            "[]".into()
        };
        Ok(http::Response::new(bytes::Bytes::from(body)))
    }
}
// Version refusal is a client error, so configuration cannot silently proceed.
#[tokio::test]
async fn version_mismatch_refused() {
    let http = Arc::new(Http { calls: Mutex::new(vec![]), version: "future" });
    let client = Client::unix("/unused").unwrap().with_http(http.clone());
    assert!(matches!(client.hello().await, Err(Error::VersionMismatch)));
    assert_eq!(http.calls.lock().unwrap().len(), 1);
}

// The rate-limit cache must coalesce concurrent reads and allow another call
// exactly at the declared boundary. This uses the real host over a Unix socket.
#[tokio::test]
async fn cache_honours_declared_limit() {
    let dir = tempfile::tempdir().unwrap();
    let mut spec = spec();
    spec.configuration.providers[0]
        .settings
        .insert("rate_limits".into(), serde_json::json!([{"operation":"inspect","requests":1,"period_seconds":1}]));
    let mut host = supervisor(dir.path()).start(spec).await.unwrap();
    let status = host.ready(Duration::from_secs(5)).await.unwrap();
    assert_eq!(status.providers[0].rate_limits[0].requests, 1);
    let environment = host.client.provision("a", &request(prepare(&host.client).await)).await.unwrap();
    let cache = Arc::new(StatusCache::new(host.client.clone(), &status.providers));
    assert!(matches!(cache.inspect("a", &environment.id).await.unwrap().state, Observation::Running));
    host.client.suspend("a", &environment.id).await.unwrap();
    let (a, b) = tokio::join!(cache.inspect("a", &environment.id), cache.inspect("a", &environment.id));
    assert!(matches!(a.unwrap().state, Observation::Running));
    assert!(matches!(b.unwrap().state, Observation::Running));
    // Distinct IDs share the provider's inspect budget, so a cache miss cannot
    // bypass the declared limit. The client returns its typed local refusal.
    assert!(matches!(cache.inspect("a", "another-id").await, Err(Error::RateLimited)));
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(matches!(cache.inspect("a", &environment.id).await.unwrap().state, Observation::Stopped { .. }));
}

// Explicit generated space: zero through three calls/window, one through four
// seconds, and operation sequences across expiration, cached reads, and misses.
// After each step the shared provider budget must hold, including zero limits.
#[hegel::test]
fn cache_budget_sequences(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let requests = tc.draw(gs::integers::<u32>().min_value(0).max_value(3));
    let seconds = tc.draw(gs::integers::<u64>().min_value(1).max_value(4));
    let count = tc.draw(gs::integers::<usize>().min_value(1).max_value(8));
    let advances: Vec<_> = (0..count).map(|_| tc.draw(gs::integers::<u64>().min_value(0).max_value(4))).collect();
    tokio::runtime::Builder::new_current_thread().enable_all().start_paused(true).build().unwrap().block_on(async {
        let http = Arc::new(Http { calls: Mutex::new(vec![]), version: "1" });
        let client = Client::unix("/unused").unwrap().with_http(http.clone());
        let mut declaration: ProviderDeclaration = serde_json::from_value(serde_json::json!({"provider":"a","module":"memory","capabilities":{"material_modes":[],"checkout_strategies":[],"workspace_root":"/","suspend_resume":false,"export":false,"egress":{"routes":[],"enforcement":"advisory"},"fallback_runner":false,"bootstrap":"bake","usage":false,"quota":false},"readiness":{"status":"ready"},"rate_limits":[]})).unwrap();
        declaration.rate_limits = vec![RateLimit { operation:"list".into(), requests, period_seconds:seconds }];
        let cache = StatusCache::new(client, &[declaration]);
        let mut calls = Vec::new(); let mut now = 0;
        for advance in advances {
            tokio::time::advance(Duration::from_secs(advance)).await; now += advance;
            let before = http.calls.lock().unwrap().len();
            let result = cache.list("a").await;
            if requests == 0 { assert!(matches!(result, Err(Error::RateLimited))); } else { assert!(result.is_ok()); }
            if http.calls.lock().unwrap().len() != before { calls.push(now); }
            // A duplicate read at the same instant must consume no new attempt.
            let after_first = http.calls.lock().unwrap().len();
            let duplicate = cache.list("a").await;
            if requests == 0 { assert!(matches!(duplicate, Err(Error::RateLimited))); } else { assert!(duplicate.is_ok()); }
            assert_eq!(http.calls.lock().unwrap().len(), after_first);
            assert!(calls.iter().filter(|at| now - **at < seconds).count() <= requests as usize);
        }
    });
}

struct Rotating {
    value: Mutex<Option<Credential>>,
    changes: watch::Sender<u64>,
}
#[async_trait::async_trait]
impl CredentialSource for Rotating {
    async fn resolve(&self, _: &CredentialReference) -> Result<Credential, CredentialError> {
        self.value.lock().unwrap().clone().ok_or(CredentialError)
    }
    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}
// A temporarily unavailable or expired credential makes the host not ready;
// rotation refreshes it without reconfiguring and losing the reference's state.
#[tokio::test]
async fn credential_rotation_preserves_live_state() {
    let dir = tempfile::tempdir().unwrap();
    let (changes, _) = watch::channel(0);
    let source = Arc::new(Rotating { value: Mutex::new(Some(Credential { value: Secret::new("first"), expires_at: None })), changes });
    let mut s = supervisor(dir.path());
    s.credentials = source.clone();
    let mut host = s.start(spec()).await.unwrap();
    host.ready(Duration::from_secs(5)).await.unwrap();
    let environment = host.client.provision("a", &request(prepare(&host.client).await)).await.unwrap();
    *source.value.lock().unwrap() = Some(Credential { value: Secret::new("expired"), expires_at: Some(std::time::SystemTime::UNIX_EPOCH) });
    source.changes.send_replace(1);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            host.status.changed().await.unwrap();
            if matches!(host.instances().get("a"), Some(Readiness::MissingCredential { .. })) {
                break;
            }
        }
    })
    .await
    .unwrap();
    *source.value.lock().unwrap() = Some(Credential { value: Secret::new("second"), expires_at: None });
    source.changes.send_replace(2);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            host.status.changed().await.unwrap();
            if matches!(host.instances().get("a"), Some(Readiness::Ready)) {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(host.client.inspect("a", &environment.id).await.unwrap(), environment);
}

// An external reference host has independent lifetime: dropping the client-side
// handle must not terminate or replace its server, and reconnect can configure it.
#[tokio::test]
async fn external_host_is_not_supervised() {
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("external.sock");
    let server_socket = socket.clone();
    let server = tokio::spawn(async move {
        drydock_host::Host::new(drydock_host::reference::registry())
            .serve_unix(server_socket, unsafe { libc::geteuid() }, std::future::pending())
            .await
            .unwrap()
    });
    let mut spec = spec();
    spec.connection = HostConnection::ExternalUnix { path: socket.clone() };
    let mut host = supervisor(dir.path()).start(spec).await.unwrap();
    host.ready(Duration::from_secs(5)).await.unwrap();
    let environment = host.client.provision("a", &request(prepare(&host.client).await)).await.unwrap();
    drop(host);
    assert_eq!(Client::unix(socket).unwrap().inspect("a", &environment.id).await.unwrap(), environment);
    assert!(!server.is_finished());
    server.abort();
}

// HTTP host boundary stand-in changes only the protocol version. The supervisor
// must report each configured instance's mismatch without configuring the server.
#[tokio::test]
async fn supervisor_version_mismatch_does_not_send_configuration() {
    use axum::{
        Json, Router,
        routing::{get, put},
    };
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let called = calls.clone();
    let router = Router::new()
        .route(
            "/v1/hello",
            get(|| async { Json(serde_json::json!({"protocol_version":"future","host_version":"test","providers":[],"modules":[]})) }),
        )
        .route(
            "/v1/config",
            put(move || {
                let calls = called.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    axum::http::StatusCode::NO_CONTENT
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, "bearer").unwrap();
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut spec = spec();
    spec.connection = HostConnection::External { url: format!("http://{address}"), token_file };
    let mut host = supervisor(dir.path()).start(spec).await.unwrap();
    assert!(matches!(host.ready(Duration::from_secs(3)).await, Err(Error::VersionMismatch)));
    assert!(matches!(host.instances().get("a"), Some(Readiness::VersionMismatch { .. })));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    server.abort();
}

// Duplicate ownership and unsafe names fail before any socket is stolen.
#[tokio::test]
async fn managed_socket_has_one_owner() {
    let dir = tempfile::tempdir().unwrap();
    let s = supervisor(dir.path());
    let mut host = s.start(spec()).await.unwrap();
    host.ready(Duration::from_secs(5)).await.unwrap();
    assert!(matches!(s.start(spec()).await, Err(Error::InvalidRequest)));
    for name in ["", "../elsewhere", "a/b"] {
        let mut spec = spec();
        spec.name = name.into();
        assert!(matches!(s.start(spec).await, Err(Error::InvalidRequest)));
    }
    assert!(host.client.hello().await.is_ok());
}

// Built-ins cover raw and JSON file values, missing/invalid fields and files,
// environment reads, and the unsupported embedder port, without exposing values.
#[tokio::test]
async fn builtin_credential_resolution_and_redaction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret");
    let source = BuiltinCredentials::default();
    std::fs::write(&path, "secret-value\n").unwrap();
    let raw = CredentialReference::File { path: path.clone(), json_field: None };
    let resolved = source.resolve(&raw).await.unwrap();
    assert_eq!(resolved.value.expose(), "secret-value");
    assert!(!format!("{resolved:?}").contains("secret-value"));
    std::fs::write(&path, r#"{"token":"second-value"}"#).unwrap();
    let json = CredentialReference::File { path: path.clone(), json_field: Some("token".into()) };
    assert_eq!(source.resolve(&json).await.unwrap().value.expose(), "second-value");
    for content in ["{bad-json-secret", "{}", r#"{"token":123}"#, r#"{"token":""}"#] {
        std::fs::write(&path, content).unwrap();
        let error = source.resolve(&json).await.unwrap_err();
        assert_eq!(error.to_string(), "credential unavailable");
    }
    std::fs::remove_file(&path).unwrap();
    assert!(source.resolve(&raw).await.is_err());
    assert!(source.resolve(&CredentialReference::Env { name: "PATH".into() }).await.is_ok());
    assert!(source.resolve(&CredentialReference::Env { name: "DRYDOCK_MISSING_CREDENTIAL_TEST".into() }).await.is_err());
    assert!(source.resolve(&CredentialReference::Embedder { reference: "owned-by-embedder".into() }).await.is_err());
}

// Proxied instances never invoke Direct resolution, and the managed command
// receives the embedder's proxy environment. The reference makes no vendor calls.
#[tokio::test]
async fn proxied_host_receives_environment_without_resolving_secrets() {
    struct NoDirect(watch::Sender<u64>);
    #[async_trait::async_trait]
    impl CredentialSource for NoDirect {
        async fn resolve(&self, _: &CredentialReference) -> Result<Credential, CredentialError> {
            panic!("proxied mode must not resolve direct secrets")
        }
        fn changes(&self) -> watch::Receiver<u64> {
            self.0.subscribe()
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let mut s = supervisor(dir.path());
    s.credentials = Arc::new(NoDirect(watch::channel(0).0));
    let mut spec = spec();
    spec.credentials.clear();
    spec.configuration.providers[0].credential =
        CredentialMode::Proxied { placeholder_token: Secret::new("placeholder"), proxy_url: "http://127.0.0.1:9".into() };
    if let HostConnection::Managed { command, proxy_environment, .. } = &mut spec.connection {
        *command = vec![
            "sh".into(),
            "-c".into(),
            "test \"$HTTP_PROXY\" = http://127.0.0.1:9 || exit 2; exec \"$@\"".into(),
            "proxy-wrapper".into(),
            env!("CARGO_BIN_EXE_drydock-host").into(),
        ];
        proxy_environment.insert("HTTP_PROXY".into(), "http://127.0.0.1:9".into());
    }
    let mut host = s.start(spec).await.unwrap();
    host.ready(Duration::from_secs(3)).await.unwrap();
    assert!(matches!(host.instances().get("a"), Some(Readiness::Ready)));
    assert!(host.client.list("a").await.unwrap().is_empty());
}

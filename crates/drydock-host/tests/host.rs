#[path = "support/provider.rs"]
mod provider;
use drydock::{
    api::{ConfigUpdate, ProviderApi},
    client::Client,
};
use drydock_host::module::*;
use drydock_protocol::*;
use provider::{Control, ControlledModule};
use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};

async fn serve(host: drydock_host::Host) -> (tempfile::TempDir, Client) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("host.sock");
    let client = Client::unix(&socket).unwrap();
    tokio::spawn(async move { host.serve_unix(socket, std::future::pending()).await.unwrap() });
    wait_for_host(&client).await;
    (dir, client)
}
async fn wait_for_host(client: &Client) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while client.hello().await.is_err() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
fn configuration(value: serde_json::Value) -> Configuration {
    serde_json::from_value(value).unwrap()
}
fn preparation() -> PrepareRequest {
    PrepareRequest {
        size: Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
        platform: None,
        route: None,
        image_pull: None,
        image_digest: "image".into(),
        tools_digest: "tools".into(),
    }
}

// Provider-only TOML must reach readiness using the bundled managed binary's
// loadable-module handshake, without declaring a host/module registry in config.
#[tokio::test]
async fn managed_daemon_discovers_reference_module() {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path().join("run");
    let config = drydock::config::Config::parse(
        r#"
[providers.demo]
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
            connection: drydock::HostConnection::Managed { command: vec![env!("CARGO_BIN_EXE_drydock-host").into()], runtime: None },
        }],
    )
    .await
    .unwrap();
    assert_eq!(daemon.providers()[0].readiness, Readiness::Ready);
    // Discovery works before the first pin is published; only prepare/launch need the
    // build's image pin. Stamped builds retain the complete launch assertion.
    let launch = daemon.launch("demo", &drydock::launch::LaunchOptions::default()).await;
    if drydock::launch::build_tools_digest().is_ok() {
        let environment = launch.unwrap();
        assert_eq!(environment.provider, "demo");
        let listed = drydock::daemon::ProviderApi::list(daemon.as_ref(), "demo").await.unwrap();
        assert_eq!(listed, vec![environment.clone()]);
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

// The thin binary closes open streams and unlinks its owned socket on SIGTERM.
#[tokio::test]
async fn binary_sigterm_drains_and_removes_socket() {
    use tokio::io::AsyncReadExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("host.sock");
    let mut child =
        tokio::process::Command::new(env!("CARGO_BIN_EXE_drydock-host")).arg("--unix").arg(&socket).kill_on_drop(true).spawn().unwrap();
    let client = Client::unix(&socket).unwrap();
    wait_for_host(&client).await;
    client.configure(ConfigUpdate::Replace(configuration(serde_json::json!({"providers":{"a":{"module":"reference"}}})))).await.unwrap();
    let prepared = client.prepare("a", &preparation()).await.unwrap();
    let request = ProvisionRequest {
        label: "stream".into(),
        prepared,
        size: Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
        egress: EgressRequest::Open,
        ssh_public_key: None,
    };
    let environment = client.provision("a", &request).await.unwrap().into_inner();
    let mut stream = client.relay("a", &environment.id).await.unwrap();
    // SAFETY: the test owns this live child process.
    assert_eq!(unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGTERM) }, 0);
    let mut rest = vec![];
    assert_eq!(tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await.unwrap().unwrap(), 0);
    assert!(tokio::time::timeout(Duration::from_secs(5), child.wait()).await.unwrap().unwrap().success());
    assert!(!socket.exists());
}

// The reference module declares the host's own filesystem only when a test's
// stand-in vessel is the test host, and the host serves the declaration.
#[tokio::test]
async fn reference_declares_the_host_filesystem_when_told() {
    let (_dir, client) = serve(drydock_host::Host::new(drydock_host::reference::registry())).await;
    let document =
        serde_json::json!({"providers":{"guest":{"module":"reference"},"host":{"module":"reference","settings":{"host_filesystem":true}}}});
    client.configure(ConfigUpdate::Replace(configuration(document))).await.unwrap();
    let declared: Vec<_> = client.providers().await.unwrap().into_iter().map(|d| (d.provider, d.capabilities.host_filesystem)).collect();
    assert_eq!(declared, [("guest".into(), false), ("host".into(), true)]);
}

// The host takes the configuration document by PUT and merge-patch PATCH. An
// unchanged entry keeps its provider, and with it its in-memory resources; a
// document naming a server-only credential is refused without applying any of it.
#[tokio::test]
async fn host_configuration_document() {
    let (_dir, client) = serve(drydock_host::Host::new(drydock_host::reference::registry())).await;
    client.configure(ConfigUpdate::Replace(configuration(serde_json::json!({"providers":{"a":{"module":"reference"}}})))).await.unwrap();
    let prepared = client.prepare("a", &preparation()).await.unwrap();
    client
        .configure(ConfigUpdate::MergePatch(serde_json::json!({"providers":{"b":{"module":"reference","settings":{"agent":true}}}})))
        .await
        .unwrap();
    let names: Vec<_> = client.providers().await.unwrap().into_iter().map(|d| (d.provider, d.capabilities.agent)).collect();
    assert_eq!(names, [("a".into(), false), ("b".into(), true)]);
    // The reference keeps prepared forms in memory: the same form proves the same provider.
    assert_eq!(client.prepare("a", &preparation()).await.unwrap(), prepared);
    // Refused documents apply nothing: a server-only key, or a provider that
    // fails to build after an earlier new one was built.
    for patch in [
        serde_json::json!({"providers":{"a":null,"c":{"module":"reference","credential":{"env":"PATH"}}}}),
        serde_json::json!({"providers":{"a":null,"c":{"module":"reference"},"d":{"module":"reference","settings":{"bogus":1}}}}),
    ] {
        let refused = client.configure(ConfigUpdate::MergePatch(patch)).await;
        assert!(matches!(refused, Err(drydock::client::Error::Protocol(ProtocolError::Refused { .. }))), "{refused:?}");
        assert_eq!(client.providers().await.unwrap().len(), 2);
        assert_eq!(client.prepare("a", &preparation()).await.unwrap(), prepared);
    }
}

// The host holds no credential: each call reaches the module with exactly the
// Drydock-Credential its request carried, and a call without one carries none.
#[tokio::test]
async fn request_credential_reaches_the_module_for_that_call() {
    let control = Arc::new(Control::default());
    let module = Arc::new(ControlledModule(control.clone())) as Arc<dyn Module>;
    let (_dir, client) = serve(drydock_host::Host::new(Registry::from([("cloud".into(), module)]))).await;
    client.configure(ConfigUpdate::Replace(configuration(serde_json::json!({"providers":{"a":{"module":"cloud"}}})))).await.unwrap();
    for credential in [Some("first"), None, Some("second")] {
        client.clone().credentialed(credential.map(Secret::new)).list("a").await.unwrap();
    }
    assert_eq!(*control.list_credentials.lock().unwrap(), [Some("first".into()), None, Some("second".into())]);
    let declaration = client.provider("a").await.unwrap();
    assert!(matches!(declaration.readiness, Readiness::MissingCredential { .. }));
    let declaration = client.clone().credentialed(Some(Secret::new("first"))).provider("a").await.unwrap();
    assert_eq!(declaration.readiness, Readiness::Ready);
}

// A host connection that drops mid-provision leaves the outcome unknown. The
// server reports that once and never replays the mutation on its own.
#[tokio::test]
async fn transport_drop_mid_provision_is_unknown_and_not_retried() {
    use axum::{
        Json,
        routing::{get, put},
    };
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    let reference = drydock_host::reference::ReferenceModule
        .configure(
            "p",
            &ProviderConfiguration { module: "fake".into(), settings: Default::default(), credential: None },
            Arc::new(rigging_http_client::ReqwestHttpClient::restricted(None, None).unwrap()),
        )
        .await
        .unwrap();
    let declaration = ProviderDeclaration {
        provider: "p".into(),
        module: "fake".into(),
        capabilities: reference.capabilities(),
        readiness: Readiness::Ready,
        rate_limits: vec![],
        ports: reference.operations().into(),
        observation: ObservationMode::Poll { interval_ms: 3_600_000 },
    };
    let provisions = Arc::new(AtomicUsize::new(0));
    let hello = serde_json::json!({
        "protocol_version": PROTOCOL_VERSION, "host_version": "fake",
        "loadable_modules": [{"name": "fake", "version": "1", "smallest_size": {"cpus": 1.0, "memory_bytes": 1024, "disk_bytes": 0}}],
    });
    let (listed, counter) = (declaration.clone(), provisions.clone());
    let router = axum::Router::new()
        .route("/v1/hello", get(move || async move { Json(hello) }))
        .route("/v1/config", put(|| async { axum::http::StatusCode::NO_CONTENT }).patch(|| async { axum::http::StatusCode::NO_CONTENT }))
        .route("/v1/providers", get(move || async move { Json(vec![listed]) }))
        .route("/v1/providers/p", get(move || async move { Json(declaration) }))
        .route(
            "/v1/providers/p/environments",
            get(|| async { Json(serde_json::json!([])) }).post(move || async move {
                counter.fetch_add(1, SeqCst);
                // Headers arrive, then the connection fails inside the body.
                axum::body::Body::from_stream(futures::stream::iter([Err::<bytes::Bytes, _>(std::io::Error::other("host died"))]))
            }),
        );
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("fake.sock");
    let listener = rigging_http_serve::UnixServer::bind(&socket, 0o600).await.unwrap();
    tokio::spawn(listener.serve(router, rigging_http_serve::Caller::<()>::Unix, std::future::pending()));
    let mut host = drydock::Supervisor::new(dir.path().join("hosts"), Arc::new(drydock::credentials::BuiltinCredentials::default()))
        .start(drydock::HostSpec {
            name: "fake".into(),
            connection: drydock::HostConnection::ExternalUnix { path: socket },
            configuration: configuration(serde_json::json!({"providers":{"p":{"module":"fake"}}})),
            credentials: [("p".into(), drydock::credentials::CredentialReference::Env { name: "PATH".into() })].into(),
        })
        .await
        .unwrap();
    host.ready(Duration::from_secs(5)).await.unwrap();
    let request = ProvisionRequest {
        label: "dropped".into(),
        prepared: Prepared {
            provider: "p".into(),
            id: "prepared".into(),
            platform: Platform::new("linux", "amd64"),
            image_digest: "image".into(),
            tools_digest: "tools".into(),
        },
        size: Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
        egress: EgressRequest::Open,
        ssh_public_key: None,
    };
    let error = host.client.provision("p", &request).await.unwrap_err();
    assert!(matches!(&error, drydock::client::Error::Protocol(ProtocolError::Unavailable { provider_error: Some(_), .. })), "{error}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(provisions.load(SeqCst), 1);
}

struct NotifiedCredentials(tokio::sync::watch::Sender<u64>);
#[async_trait::async_trait]
impl drydock::credentials::CredentialSource for NotifiedCredentials {
    async fn resolve(
        &self,
        _: &drydock::credentials::CredentialReference,
    ) -> std::result::Result<drydock::credentials::Credential, drydock::credentials::CredentialError> {
        Ok(drydock::credentials::Credential { value: Secret::new("snapshot"), expires_at: None })
    }
    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.0.subscribe()
    }
}

// An external host that restarts without its providers is configured again,
// and supervision recovers admission without replaying a mutation.
#[tokio::test]
async fn external_host_restart_reconfigures_it() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("external.sock");
    let host = drydock_host::Host::new(drydock_host::reference::registry());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let path = socket.clone();
    let server = tokio::spawn(async move {
        host.serve_unix(path, async {
            let _ = stopped.await;
        })
        .await
        .unwrap();
    });
    let changes = tokio::sync::watch::channel(0).0;
    let mut supervisor = drydock::Supervisor::new(dir.path().join("run"), Arc::new(NotifiedCredentials(changes.clone())));
    supervisor.refresh_interval = Duration::from_secs(60);
    let mut managed = supervisor
        .start(drydock::HostSpec {
            name: "external".into(),
            connection: drydock::HostConnection::ExternalUnix { path: socket.clone() },
            configuration: configuration(serde_json::json!({"providers":{"a":{"module":"reference"}}})),
            credentials: [("a".into(), drydock::credentials::CredentialReference::Env { name: "PATH".into() })].into(),
        })
        .await
        .unwrap();
    let initial = managed.ready(Duration::from_secs(5)).await.unwrap();
    assert_eq!(managed.client.prepare("a", &preparation()).await.unwrap().provider, "a");
    stop.send(()).unwrap();
    server.await.unwrap();
    let raw = Client::unix(&socket).unwrap();
    let host = drydock_host::Host::new(drydock_host::reference::registry());
    let server = tokio::spawn(async move {
        host.serve_unix(socket, std::future::pending()).await.unwrap();
    });
    wait_for_host(&raw).await;
    changes.send_replace(1);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = managed.status.borrow().clone();
            if status.generation > initial.generation && matches!(status.readiness, Readiness::Ready) {
                assert_eq!(managed.client.prepare("a", &preparation()).await.unwrap().provider, "a");
                break;
            }
            managed.status.changed().await.unwrap();
        }
    })
    .await
    .expect("external host restart must reconfigure the host");
    assert_eq!(raw.providers().await.unwrap().len(), 1);
    server.abort();
}

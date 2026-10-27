#[path = "support/provider.rs"]
mod provider;
use drydock::api::ProviderApi;
use drydock_host::module::*;
use drydock_protocol::*;
use provider::{Control, ControlledModule};
use std::{sync::Arc, time::Duration};
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

// The thin binary cancels raw subscriptions and unlinks its owned socket on SIGTERM.
#[tokio::test]
async fn binary_sigterm_drains_and_removes_socket() {
    use futures::StreamExt;
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("host.sock");
    let mut child =
        tokio::process::Command::new(env!("CARGO_BIN_EXE_drydock-host")).arg("--unix").arg(&socket).kill_on_drop(true).spawn().unwrap();
    let client = drydock::client::Client::unix(&socket).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while client.hello().await.is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let configuration: HostConfiguration=serde_json::from_value(serde_json::json!({"modules":[{"name":"reference","entrypoint":"reference"}],"providers":[{"name":"a","module":"reference","settings":{"fixture":true,"fixture_push":true},"credential":{"mode":"direct","credential_reference":"test"}}]})).unwrap();
    let handle = client.configure_provider("reference", &configuration.providers[0]).await.unwrap().instance;
    let http = rigging_tls::client_builder().unix_socket(socket.clone()).build().unwrap();
    let response = http
        .post(format!("http://localhost/private/providers/{handle}/subscribe"))
        .json(&drydock_host::module::Call {
            credentials: drydock_host::module::Credentials::new(CredentialMode::Direct { credential_reference: "test".into() }),
            argument: (),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let mut records = response.bytes_stream();
    // SAFETY: the test owns this live child process.
    assert_eq!(unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGTERM) }, 0);
    assert!(tokio::time::timeout(Duration::from_secs(5), records.next()).await.unwrap().is_none());
    assert!(tokio::time::timeout(Duration::from_secs(5), child.wait()).await.unwrap().unwrap().success());
    assert!(!socket.exists());
}

// The thin host carries each call's own credentials and the raw push stream:
// updates keep their provider time, a provider error keeps its class, a lost
// update ends the stream, and a client disconnect cancels the subscription.
#[tokio::test]
async fn raw_subscription_over_the_bridge() {
    use std::{os::unix::fs::PermissionsExt, sync::atomic::Ordering::SeqCst};
    let control = Arc::new(Control::default());
    let host =
        drydock_host::Host::new(Registry::from([("reference".into(), Arc::new(ControlledModule(control.clone())) as Arc<dyn Module>)]));
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("raw.sock");
    let client = drydock::client::Client::unix(&socket).unwrap();
    tokio::spawn(async move { host.serve_unix(socket, std::future::pending()).await.unwrap() });
    tokio::time::timeout(Duration::from_secs(5), async {
        while client.hello().await.is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mode = CredentialMode::Direct { credential_reference: "opaque".into() };
    let configuration =
        ProviderConfiguration { name: "a".into(), module: "reference".into(), settings: Default::default(), credential: mode.clone() };
    let handle = client.configure_provider("reference", &configuration).await.unwrap().instance;
    let credentials = |value: &str| Credentials { mode: mode.clone(), value: Some(Secret::new(value)) };
    let subscribe = |value: &str, sink: EventSink| {
        let (client, handle, credentials) = (client.clone(), handle.clone(), credentials(value));
        tokio::spawn(async move { client.provider_updates(&handle, &credentials, sink).await })
    };

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let stream = subscribe("first", EventSink::new(move |update| tx.send(update).map_err(|_| refused("closed"))));
    tokio::time::timeout(Duration::from_secs(5), control.started.notified()).await.unwrap();
    let timestamp = chrono::DateTime::from_timestamp(123456, 0);
    control.sink.lock().unwrap().clone().unwrap().publish(Update::Removed { id: "gone".into(), timestamp }).unwrap();
    assert!(matches!(rx.recv().await.unwrap(), Update::Removed { id, timestamp: t } if id == "gone" && t == timestamp));
    stream.abort();
    let _ = stream.await;
    tokio::time::timeout(Duration::from_secs(5), control.cancelled.notified())
        .await
        .expect("disconnect must drop the provider subscription");

    control.reject_subscription.store(true, SeqCst);
    let rejected = subscribe("second", EventSink::new(|_| Ok(()))).await.unwrap();
    assert!(matches!(rejected, Err(drydock::client::Error::Protocol(ProtocolError::CredentialRejected { .. }))), "{rejected:?}");
    control.reject_subscription.store(false, SeqCst);
    control.started.notified().await; // the rejected run started too

    let overflowing = subscribe("third", EventSink::new(|_| Ok(())));
    tokio::time::timeout(Duration::from_secs(5), control.started.notified()).await.unwrap();
    let sink = control.sink.lock().unwrap().clone().unwrap();
    for _ in 0..64 {
        let _ = sink.publish(Update::Removed { id: "overflow".into(), timestamp: None });
    }
    let overflowed = tokio::time::timeout(Duration::from_secs(5), overflowing).await.unwrap().unwrap();
    assert!(matches!(overflowed, Err(drydock::client::Error::Protocol(ProtocolError::Unavailable { .. }))), "{overflowed:?}");
    assert_eq!(*control.subscriptions.lock().unwrap(), [Some("first".into()), Some("second".into()), Some("third".into())]);
}

// A host connection that drops mid-provision leaves the outcome unknown. The
// server reports that once and never replays the mutation on its own.
#[tokio::test]
async fn transport_drop_mid_provision_is_unknown_and_not_retried() {
    use axum::{Json, routing::post};
    use std::{
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicUsize, Ordering::SeqCst},
    };
    let reference = drydock_host::reference::ReferenceModule
        .configure(
            &ProviderConfiguration {
                name: "fake".into(),
                module: "fake".into(),
                settings: Default::default(),
                credential: CredentialMode::Direct { credential_reference: "unused".into() },
            },
            Arc::new(rigging_http_client::ReqwestHttpClient::restricted(None, None).unwrap()),
        )
        .await
        .unwrap();
    let facts = serde_json::json!({
        "ports": Ports::from(reference.operations()),
        "capabilities": reference.capabilities(),
        "observation": {"Poll": {"interval": {"secs": 3600, "nanos": 0}}},
        "rate_limits": [],
        "readiness": {"status": "ready"},
    });
    let provisions = Arc::new(AtomicUsize::new(0));
    let hello = serde_json::json!({
        "protocol_version": PROTOCOL_VERSION, "host_version": "fake", "modules": [], "providers": [], "incarnation": "one",
        "loadable_modules": [{"name": "fake", "version": "1", "smallest_size": {"cpus": 1.0, "memory_bytes": 1024, "disk_bytes": 0}}],
    });
    let (configured, counter) = (serde_json::json!({"instance": "handle", "facts": facts}), provisions.clone());
    let router = axum::Router::new()
        .route("/v1/hello", axum::routing::get(move || async move { Json(hello) }))
        .route("/private/modules/fake/configure", post(move || async move { Json(configured) }))
        .route("/private/providers/handle/facts", post(move || async move { Json(facts) }))
        .route("/private/providers/handle/list", post(|| async { Json(serde_json::json!([])) }))
        .route(
            "/private/providers/handle/provision",
            post(move || async move {
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
            configuration: HostConfiguration {
                modules: vec![ModuleConfiguration { name: "fake".into(), entrypoint: "fake".into() }],
                providers: vec![ProviderConfiguration {
                    name: "p".into(),
                    module: "fake".into(),
                    settings: Default::default(),
                    credential: CredentialMode::Proxied {
                        placeholder_token: Secret::new("placeholder"),
                        proxy_url: "http://127.0.0.1:1".into(),
                    },
                }],
            },
            credentials: Default::default(),
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

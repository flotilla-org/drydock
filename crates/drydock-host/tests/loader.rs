#[path = "support/provider.rs"]
mod provider;
use drydock::api::ProviderApi;
use drydock_host::module::*;
use drydock_protocol::*;
use provider::{Control, ControlledModule};
use std::{sync::Arc, time::Duration};

fn raw_configuration(name: &str) -> ProviderConfiguration {
    ProviderConfiguration {
        name: name.into(),
        module: "cloud".into(),
        settings: Default::default(),
        credential: CredentialMode::Direct { credential_reference: "test".into() },
    }
}
fn preparation() -> PrepareRequest {
    PrepareRequest {
        size: Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
        platform: Some(Platform::new("linux", "amd64")),
        route: None,
        image_pull: None,
        image_digest: "image".into(),
        tools_digest: "tools".into(),
    }
}
async fn wait_for_bridge(client: &drydock::client::Client) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while client.hello().await.is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

// Identical configurations reuse one module binding, even when configured
// concurrently; the reuse key includes the selected entrypoint. Each configure
// still returns its own handle, and release drops only that handle.
#[tokio::test]
async fn loader_reuses_bindings_and_releases_handles() {
    use std::{os::unix::fs::PermissionsExt, sync::atomic::Ordering::SeqCst};
    let (first, second) = (Arc::new(Control::default()), Arc::new(Control::default()));
    first.slow_configure.store(true, SeqCst);
    let host = drydock_host::Host::new(Registry::from([
        ("first".into(), Arc::new(ControlledModule(first.clone())) as Arc<dyn Module>),
        ("second".into(), Arc::new(ControlledModule(second.clone())) as Arc<dyn Module>),
    ]));
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("loader.sock");
    let client = drydock::client::Client::unix(&socket).unwrap();
    tokio::spawn(async move { host.serve_unix(socket, std::future::pending()).await.unwrap() });
    wait_for_bridge(&client).await;
    let config = raw_configuration("a");
    let (a, b) = tokio::join!(client.configure_provider("first", &config), client.configure_provider("first", &config));
    let (a, b) = (a.unwrap().instance, b.unwrap().instance);
    assert_ne!(a, b);
    assert_eq!(first.configured.load(SeqCst), 1);
    client.configure_provider("second", &config).await.unwrap();
    assert_eq!(second.configured.load(SeqCst), 1);
    client.release_provider(&a).await.unwrap();
    let credentials = Credentials { mode: config.credential, value: Some(Secret::new("snapshot")) };
    assert!(client.provider_call::<Prepared, _>(&a, "prepare", preparation(), &credentials).await.is_err());
    assert_eq!(client.provider_call::<Prepared, _>(&b, "prepare", preparation(), &credentials).await.unwrap().provider, "a");
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

// External-host restart invalidates old remote handles and reconfigures through
// the same loader. Supervision recovers admission without replaying a mutation.
#[tokio::test]
async fn external_host_restart_recovers_remote_handles() {
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
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
            configuration: HostConfiguration {
                modules: vec![ModuleConfiguration { name: "cloud".into(), entrypoint: "reference".into() }],
                providers: vec![raw_configuration("a")],
            },
            credentials: std::collections::BTreeMap::from([(
                "test".into(),
                drydock::credentials::CredentialReference::Env { name: "PATH".into() },
            )]),
        })
        .await
        .unwrap();
    let initial = managed.ready(Duration::from_secs(5)).await.unwrap();
    assert_eq!(managed.client.prepare("a", &preparation()).await.unwrap().provider, "a");
    stop.send(()).unwrap();
    server.await.unwrap();
    let raw = drydock::client::Client::unix(&socket).unwrap();
    let host = drydock_host::Host::new(drydock_host::reference::registry());
    let server = tokio::spawn(async move {
        host.serve_unix(socket, std::future::pending()).await.unwrap();
    });
    wait_for_bridge(&raw).await;
    // Another server may configure the same logical name before we reconnect.
    // Presence of names alone therefore cannot establish handle validity.
    raw.configure_provider("reference", &raw_configuration("a")).await.unwrap();
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
    .expect("external host restart must recover configured remote handles");
    server.abort();
}

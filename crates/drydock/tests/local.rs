//! A daemon configured with the `local` provider takes a launch through to an
//! agent it has connected to, the whole path a convoy's crew uses, with no
//! credential configured and no cloud or container runtime involved.
#[path = "../../drydock-host/tests/support/agent.rs"]
mod agent;
use drydock::{
    HostConnection,
    config::Config,
    daemon::{Daemon, HostOption, ProviderApi, Seams},
    launch::LaunchOptions,
};
use drydock_protocol::*;
use std::{os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Digests;
#[async_trait::async_trait]
impl drydock::launch::ImageResolver for Digests {
    async fn resolve(&self, image: &str) -> Result<String, drydock::client::Error> {
        Ok(image.into())
    }
}

/// The agent build drydock pushes to a vessel: the very binary the vessel runs.
struct Build;
#[async_trait::async_trait]
impl drydock::daemon::AgentBuilds for Build {
    async fn build(&self, _: &Platform) -> Result<Vec<u8>, String> {
        std::fs::read(agent::agent_binary()).map_err(|e| e.to_string())
    }
}

async fn start(dir: &Path) -> Arc<Daemon> {
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.join("host.sock");
    if !socket.exists() {
        let mut registry = drydock_host::reference::registry();
        registry.extend(drydock_host::local::registry());
        let host = drydock_host::Host::new(registry);
        let served = socket.clone();
        tokio::spawn(async move { host.serve_unix(served, std::future::pending()).await.unwrap() });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !socket.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    // The provider has no `credential`: a local vessel needs none.
    let text = format!(
        "[providers.local]\nmodule='local'\nimage='image@sha256:{digest}'\nsettings={{root='{}', agent='{}'}}\n\
         [providers.guarded]\nmodule='reference'\nimage='image@sha256:{digest}'\n",
        dir.join("vessels").display(),
        agent::agent_binary().display(),
        digest = "a".repeat(64)
    );
    let run = dir.join("run");
    let option = HostOption { optional: false, name: "rust".into(), connection: HostConnection::ExternalUnix { path: socket } };
    let seams = Seams { builds: Arc::new(Build), ..Seams::new(Arc::new(Digests)) };
    Daemon::start_with_seams(Config::parse(&text).unwrap(), &run, run.join("keys"), vec![option], seams).await.unwrap()
}

#[tokio::test]
async fn launch_reaches_an_agent_and_the_vessel_lives_through_its_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = start(dir.path()).await;
    let providers = daemon.providers();
    let local = providers.iter().find(|p| p.provider == "local").unwrap();
    assert_eq!(local.readiness, Readiness::Ready);
    assert!(local.capabilities.agent);
    // Leaving out a credential is no way round one a module needs.
    let guarded = providers.iter().find(|p| p.provider == "guarded").unwrap();
    assert!(matches!(guarded.readiness, Readiness::MissingCredential { .. }), "{:?}", guarded.readiness);

    // Launch returns only once drydock has connected to the vessel's current agent.
    let vessel = daemon.launch("local", &LaunchOptions::default()).await.unwrap();
    assert_eq!(vessel.state, Observation::Running);
    assert_eq!(vessel.platform, Some(Platform::current()));
    assert!(dir.path().join("vessels").join(&vessel.id).join("run/drydock/agent.sock").exists());

    let token = daemon.suspend("local", &vessel.id).await.unwrap();
    assert!(matches!(daemon.inspect("local", &vessel.id).await.unwrap().state, Observation::Stopped { .. }));
    daemon.resume("local", &vessel.id, &token).await.unwrap();
    assert_eq!(daemon.inspect("local", &vessel.id).await.unwrap().state, Observation::Running);
    let mut stream = daemon.relay("local", &vessel.id).await.unwrap();
    stream.write_all(b"GET /hello HTTP/1.1\r\nhost: agent\r\nconnection: close\r\n\r\n").await.unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await.unwrap();
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");

    daemon.destroy("local", &vessel.id).await.unwrap();
    assert!(daemon.list("local").await.unwrap().is_empty());
    assert!(!dir.path().join("vessels").join(&vessel.id).exists());
}

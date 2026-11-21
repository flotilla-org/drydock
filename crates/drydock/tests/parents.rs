//! An instance whose endpoint is on its parent's machine: drydockd hands the
//! child a socket of its own, and the parent opens each connection made there.
//! The parent here is a `local` instance, so its machine is this one and the
//! endpoint a Unix socket in a temporary directory.
#![cfg(target_os = "linux")]
#[path = "../../drydock-host/tests/support/agent.rs"]
mod agent;
use drydock::{
    HostConnection,
    config::Config,
    daemon::{Daemon, HostOption, ProviderApi, Seams},
};
use drydock_protocol::*;
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Digests;
#[async_trait::async_trait]
impl drydock::launch::ImageResolver for Digests {
    async fn resolve(&self, image: &str) -> Result<String, drydock::client::Error> {
        Ok(image.into())
    }
}

async fn host(dir: &Path) -> PathBuf {
    let socket = dir.join("host.sock");
    let mut registry = drydock_host::reference::registry();
    registry.extend(drydock_host::local::registry());
    registry.insert("docker_engine".into(), Arc::new(drydock_host::docker_engine::DockerEngineModule));
    let host = drydock_host::Host::new(registry);
    let served = socket.clone();
    tokio::spawn(async move { host.serve_unix(served, std::future::pending()).await.unwrap() });
    while !socket.exists() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    socket
}

/// drydockd started with `providers`, after a `local` instance named `box`
/// whose agent is `agent`.
async fn start(dir: &Path, agent: &Path, providers: &str) -> Result<Arc<Daemon>, String> {
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let text = format!(
        "[providers.box]\nmodule='local'\nsettings={{root='{}', agent='{}'}}\n{providers}",
        dir.join("vessels").display(),
        agent.display()
    );
    let config = Config::parse(&text)?;
    let option = HostOption { optional: false, name: "rust".into(), connection: HostConnection::ExternalUnix { path: host(dir).await } };
    let run = dir.join("run");
    Daemon::start_with_seams(config, &run, run.join("keys"), vec![option], Seams::new(Arc::new(Digests))).await
}
fn engine(endpoint: &Path) -> String {
    format!("[providers.engine]\nmodule='docker_engine'\nparent={{instance='box', endpoint={{unix='{}'}}}}\n", endpoint.display())
}
/// Echoes each connection back to itself.
fn echo(path: &Path) {
    let listener = tokio::net::UnixListener::bind(path).unwrap();
    tokio::spawn(async move {
        while let Ok((mut connection, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reading, mut writing) = connection.split();
                let _ = tokio::io::copy(&mut reading, &mut writing).await;
            });
        }
    });
}
/// Answers each request with a Docker Engine's version, one per connection.
fn docker(path: &Path) {
    let listener = tokio::net::UnixListener::bind(path).unwrap();
    tokio::spawn(async move {
        while let Ok((mut connection, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0; 1];
                    if connection.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    request.push(byte[0]);
                }
                let body = r#"{"Os":"linux","Arch":"amd64"}"#;
                let answer = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = connection.write_all(answer.as_bytes()).await;
            });
        }
    });
}
fn endpoint(daemon: &Daemon, name: &str) -> PathBuf {
    let declaration = daemon.providers().into_iter().find(|p| p.provider == name).unwrap();
    let Some(Local::Unix(path)) = declaration.endpoint else { panic!("{name} has no endpoint") };
    PathBuf::from(path)
}

// Each connection to the child's socket is its own stream to the endpoint on
// the parent's machine, and only drydockd's user can open that socket.
#[tokio::test]
async fn a_childs_connections_reach_its_endpoint_through_the_parent() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("engine.sock");
    echo(&target);
    let daemon = start(dir.path(), &agent::agent_binary(), &engine(&target)).await.unwrap();
    let socket = endpoint(&daemon, "engine");
    assert_eq!(std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(socket.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);

    let mut first = tokio::net::UnixStream::connect(&socket).await.unwrap();
    let mut second = tokio::net::UnixStream::connect(&socket).await.unwrap();
    first.write_all(b"one").await.unwrap();
    second.write_all(b"two").await.unwrap();
    let mut answer = [0; 3];
    second.read_exact(&mut answer).await.unwrap();
    assert_eq!(&answer, b"two");
    first.read_exact(&mut answer).await.unwrap();
    assert_eq!(&answer, b"one");
}

// The child is configured while drydockd starts, and what its endpoint says
// on that first connection is what the child declares.
#[tokio::test]
async fn a_child_configured_at_start_reaches_its_endpoint_on_its_first_connection() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("engine.sock");
    docker(&target);
    let daemon = start(dir.path(), &agent::agent_binary(), &engine(&target)).await.unwrap();
    let engine = daemon.providers().into_iter().find(|p| p.provider == "engine").unwrap();
    assert_eq!(engine.capabilities.platforms, vec![Platform::new("linux", "amd64")]);
}

// A stream the parent cannot open ends the child's connection; the child's
// readiness stays its own.
#[tokio::test]
async fn a_stream_the_parent_cannot_open_ends_the_connection() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = start(dir.path(), &agent::agent_binary(), &engine(&dir.path().join("absent.sock"))).await.unwrap();
    let mut connection = tokio::net::UnixStream::connect(endpoint(&daemon, "engine")).await.unwrap();
    let mut buffer = [0; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), connection.read(&mut buffer)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    let engine = daemon.providers().into_iter().find(|p| p.provider == "engine").unwrap();
    assert!(!matches!(engine.readiness, Readiness::ParentNotReady { .. }), "{:?}", engine.readiness);
}

// While the parent is not ready the child says so, naming the parent and
// giving its reason, and its calls are refused with that readiness.
#[tokio::test]
async fn a_child_whose_parent_is_not_ready_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = start(dir.path(), &dir.path().join("no-agent"), &engine(&dir.path().join("engine.sock"))).await.unwrap();
    let engine = daemon.providers().into_iter().find(|p| p.provider == "engine").unwrap();
    let Readiness::ParentNotReady { parent, reason } = &engine.readiness else { panic!("{:?}", engine.readiness) };
    assert_eq!(parent, "box");
    assert!(reason.starts_with("missing tool:"), "{reason}");
    match daemon.list("engine").await {
        Err(drydock::client::Error::NotReady(readiness)) => assert_eq!(readiness, engine.readiness),
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_unknown_parent_is_refused_when_the_configuration_is_read() {
    let error = Config::parse(&engine(Path::new("/run/engine.sock"))).err().unwrap();
    assert_eq!(error, "provider engine: parent \"box\" is not configured");
}

#[test]
fn parents_forming_a_cycle_are_refused_when_the_configuration_is_read() {
    let child = |name: &str, parent: &str| {
        format!("[providers.{name}]\nmodule='docker_engine'\nparent={{instance='{parent}', endpoint={{unix='/run/engine.sock'}}}}\n")
    };
    let error = Config::parse(&(child("a", "b") + &child("b", "a"))).err().unwrap();
    assert_eq!(error, "provider a: its parents form a cycle (a → b → a)");
}

#[test]
fn a_configured_parent_naming_an_environment_is_refused_when_the_configuration_is_read() {
    let providers = "[providers.box]\nmodule='local'\n\
        [providers.engine]\nmodule='docker_engine'\nparent={instance='box', environment='v1', endpoint={unix='/run/engine.sock'}}\n";
    let error = Config::parse(providers).err().unwrap();
    assert_eq!(error, "provider engine: parent names an environment, which only a carried instance's parent can");
}

#[test]
fn a_relative_endpoint_or_an_operators_endpoint_is_refused_when_the_configuration_is_read() {
    let parent = "[providers.box]\nmodule='local'\n";
    assert!(Config::parse(&format!("{parent}{}", engine(Path::new("engine.sock")))).is_err());
    assert!(Config::parse(&format!("{parent}[providers.engine]\nmodule='docker_engine'\nendpoint={{unix='/run/engine.sock'}}\n")).is_err());
}

#[tokio::test]
async fn a_parent_that_carries_no_streams_is_refused_at_start() {
    let dir = tempfile::tempdir().unwrap();
    let providers = "[providers.memory]\nmodule='reference'\n\
        [providers.engine]\nmodule='docker_engine'\nparent={instance='memory', endpoint={unix='/run/engine.sock'}}\n";
    let error = start(dir.path(), &agent::agent_binary(), providers).await.err().unwrap();
    assert_eq!(error, "provider engine: parent memory (module reference) carries no unix endpoints");
}

#[tokio::test]
async fn a_module_that_takes_no_endpoint_has_no_parent() {
    let dir = tempfile::tempdir().unwrap();
    let providers = "[providers.memory]\nmodule='reference'\nparent={instance='box', endpoint={unix='/run/engine.sock'}}\n";
    let error = start(dir.path(), &agent::agent_binary(), providers).await.err().unwrap();
    assert_eq!(error, "provider memory: module reference cannot be given its endpoint, so it has no parent");
}

//! Instances carried into an environment while drydockd runs, through its
//! HTTP API. The parent is a reference vessel whose agent the stand-in
//! gateway serves on this host, so paths in the vessel are this host's. The
//! carried module is the reference module with a recipe whose engine is a
//! second `drydock-agent`, answering on a socket in the vessel.
#![cfg(target_os = "linux")]
#[path = "../../drydock-host/tests/support/agent.rs"]
mod agent;
use drydock::{
    HostConnection,
    agent::stand_in::Gateway,
    api::Provisioned,
    client::{Client, Error},
    config::Config,
    daemon::{Daemon, HostOption, ProviderApi, Seams},
};
use drydock_protocol::{service::*, *};
use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};

const BUILD: &[u8] = b"carried test agent";
const PARENT: &str = "vessels";
const ENGINE: &str = "engine";

struct Digests;
#[async_trait::async_trait]
impl drydock::launch::ImageResolver for Digests {
    async fn resolve(&self, image: &str) -> Result<String, Error> {
        Ok(image.into())
    }
}
struct Build;
#[async_trait::async_trait]
impl drydock::daemon::AgentBuilds for Build {
    async fn build(&self, _: &Platform) -> Result<Vec<u8>, String> {
        Ok(BUILD.to_vec())
    }
}

struct Harness {
    // Under /tmp, so socket paths stay within SUN_LEN.
    _dir: tempfile::TempDir,
    _gateway: Arc<Gateway>,
    host: tokio::task::JoinHandle<()>,
    server: tokio::task::JoinHandle<()>,
    _daemon: Arc<Daemon>,
    api: Client,
    /// The parent environment.
    id: String,
    /// The recipe's service.
    engine: Service,
}
impl Drop for Harness {
    /// Services outlive the agent that started them, so the recipe's engine
    /// is stopped here, by the process group each service record names.
    fn drop(&mut self) {
        self.host.abort();
        self.server.abort();
        let records = std::fs::read_dir(self._dir.path().join("vessel/drydock-agent.services")).into_iter().flatten().flatten();
        for record in records.filter(|r| r.path().extension().is_some_and(|e| e == "json")) {
            let record: serde_json::Value = serde_json::from_slice(&std::fs::read(record.path()).unwrap_or_default()).unwrap_or_default();
            if let Some(pid) = record["pid"].as_i64().and_then(|pid| i32::try_from(pid).ok()) {
                // SAFETY: a signal to a process group this test's agent started.
                unsafe { libc::kill(-pid, libc::SIGKILL) };
            }
        }
    }
}
impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let vessel = dir.path().join("vessel");
        std::fs::create_dir(&vessel).unwrap();
        let gateway = Gateway::start_as(&vessel, BUILD, Platform::new("linux", "amd64")).unwrap();
        let engine = dir.path().join("engine").join("agent.sock");
        let service = Service {
            program: agent::agent_binary().to_string_lossy().into_owned(),
            args: vec!["--socket".into(), engine.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let recipe = Recipe {
            service: service.clone(),
            endpoint: Carried::Unix(engine.to_string_lossy().into_owned()),
            requires: vec!["sh".into()],
        };
        let mut registry = drydock_host::reference::registry();
        registry.insert(ENGINE.into(), Arc::new(drydock_host::reference::CarriedReference(recipe)));
        let reference = dir.path().join("reference.sock");
        let socket = reference.clone();
        let host = tokio::spawn(async move { drydock_host::Host::new(registry).serve_unix(socket, std::future::pending()).await.unwrap() });
        for _ in 0..200 {
            if Client::unix(&reference).unwrap().hello().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let text = format!(
            "[providers.{PARENT}]\nmodule='reference'\ncredential={{env='PATH'}}\nimage='image@sha256:{}'\n\
             settings={{agent=true, poll_interval_ms=10, reach={{kind='ssh', endpoint='gateway.test:22', user='minted', host_key='ssh-ed25519 AAAA'}}}}\n",
            "a".repeat(64)
        );
        let run = dir.path().join("run");
        let seams = Seams { dialer: gateway.clone(), builds: Arc::new(Build), ..Seams::new(Arc::new(Digests)) };
        let option = HostOption { optional: false, name: "rust".into(), connection: HostConnection::ExternalUnix { path: reference } };
        let daemon = Daemon::start_with_seams(Config::parse(&text).unwrap(), &run, run.join("keys"), vec![option], seams).await.unwrap();
        let socket = run.join("api.sock");
        let (serving, path) = (daemon.clone(), socket.clone());
        let server = tokio::spawn(async move { serving.serve(&path, std::future::pending()).await.unwrap() });
        let api = Client::unix(&socket).unwrap();
        for _ in 0..200 {
            if api.hello().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let id = daemon.launch(PARENT, &Default::default()).await.unwrap().id;
        Self { _dir: dir, _gateway: gateway, host, server, _daemon: daemon, api, id, engine: service }
    }
    fn carry(&self) -> Carry {
        Carry {
            module: ENGINE.into(),
            settings: [("poll_interval_ms".into(), 10.into()), ("owned".into(), true.into())].into(),
            parent: Parent { instance: PARENT.into(), environment: Some(self.id.clone()), endpoint: None },
        }
    }
    /// An environment provisioned through the carried instance `name`.
    async fn provision(&self, name: &str, label: &str) -> Environment {
        let size = Size { cpus: 1.0, memory_bytes: 1024, disk_bytes: 1024 };
        let request = PrepareRequest {
            platform: None,
            route: None,
            image_pull: None,
            image_digest: format!("image@sha256:{}", "a".repeat(64)),
            tools_digest: "tools".into(),
            size: size.clone(),
        };
        let prepared = self.api.prepare(name, &request).await.unwrap();
        let request = ProvisionRequest { label: label.into(), prepared, size, egress: EgressRequest::Open, ssh_public_key: None };
        self.api.provision(name, &request).await.unwrap().into_inner()
    }
}
fn refused(result: Result<impl std::fmt::Debug, Error>) -> String {
    match result {
        Err(Error::Protocol(ProtocolError::Refused { reason })) => reason,
        other => panic!("not refused: {other:?}"),
    }
}

// A carry names only the module and the parent environment: drydockd runs the
// module's recipe there through the vessel's agent, and once the engine
// answers, the instance is ready. Its socket reaches the engine in the
// vessel, and a provision goes through it.
#[tokio::test]
async fn a_carry_by_recipe_starts_the_engine_and_provisions_through_it() {
    let h = Harness::start().await;
    let Provisioned::Created(carried) = h.api.put_provider("inner", &h.carry()).await.unwrap() else { panic!("a first carry creates") };
    assert_eq!(carried.parent, Some(h.carry().parent));
    assert_eq!(carried.readiness, Readiness::Ready);
    let services = h.api.services(PARENT, &h.id).await.unwrap();
    assert!(matches!(&services[..], [ServiceInfo { state: ServiceState::Running, .. }]), "{services:?}");
    assert!(h.api.providers().await.unwrap().iter().any(|p| p.provider == "inner"));

    let Some(Local::Unix(socket)) = carried.endpoint else { panic!("a carried instance has an endpoint") };
    let stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
    let engine = drydock_agent::Client::connect(Box::new(stream), String::new()).await.unwrap();
    assert!(!engine.hello().boot_id.is_empty());

    let environment = h.provision("inner", "inner/one").await;
    assert_eq!(h.api.inspect("inner", &environment.id).await.unwrap().id, environment.id);
}

// A carry is an ensure: an engine already answering at the recipe's endpoint,
// as when the image's entrypoint started one, is carried onto as it is.
#[tokio::test]
async fn a_carry_onto_an_engine_already_answering_starts_no_service() {
    let h = Harness::start().await;
    h.api.put_service(PARENT, &h.id, "entrypoint", &h.engine).await.unwrap();
    while tokio::net::UnixStream::connect(&h.engine.args[1]).await.is_err() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(matches!(h.api.put_provider("inner", &h.carry()).await.unwrap(), Provisioned::Created(_)));
    let services = h.api.services(PARENT, &h.id).await.unwrap();
    assert_eq!(services.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["entrypoint"]);
    h.provision("inner", "inner/one").await;
}

// The same body again is the same instance; a different body under the name
// is refused, and so is a name the configuration declares.
#[tokio::test]
async fn a_repeat_carry_is_the_same_instance_and_a_different_body_is_refused() {
    let h = Harness::start().await;
    let first = h.api.put_provider("inner", &h.carry()).await.unwrap();
    let Provisioned::Existing(again) = h.api.put_provider("inner", &h.carry()).await.unwrap() else { panic!("a repeat finds it") };
    assert_eq!(again, first.into_inner());
    let other = Carry { settings: Default::default(), ..h.carry() };
    let reason = refused(h.api.put_provider("inner", &other).await.map_err(|e| e.error));
    assert_eq!(reason, "provider inner is carried from a different body; remove it first");
    let reason = refused(h.api.put_provider(PARENT, &h.carry()).await.map_err(|e| e.error));
    assert!(reason.starts_with(&format!("provider {PARENT} is configured")), "{reason}");
}

// An instance holding environments is not removed, and the refusal names
// them. Without them, DELETE stops the recipe's service and forgets it.
#[tokio::test]
async fn a_carried_instance_holding_environments_is_not_removed() {
    let h = Harness::start().await;
    h.api.put_provider("inner", &h.carry()).await.unwrap();
    let held = h.provision("inner", "inner/one").await;
    let reason = refused(h.api.remove_provider("inner").await);
    assert_eq!(reason, format!("inner holds environments {}; destroy them first", held.id));

    h.api.destroy("inner", &held.id).await.unwrap();
    h.api.remove_provider("inner").await.unwrap();
    match h.api.provider("inner").await {
        Err(Error::Protocol(ProtocolError::NotFound { missing: Some(Missing::Provider), .. })) => {}
        other => panic!("{other:?}"),
    }
    assert!(h.api.services(PARENT, &h.id).await.unwrap().is_empty());
    h.api.remove_provider("inner").await.unwrap();
}

// Destroying the parent environment takes the carried instance with it, and
// each of its environments is gone, naming the parent that went.
#[tokio::test]
async fn destroying_the_parent_environment_takes_the_carried_instance() {
    use futures::StreamExt;
    let h = Harness::start().await;
    h.api.put_provider("inner", &h.carry()).await.unwrap();
    let inner = h.provision("inner", "inner/one").await;
    let mut events = ProviderApi::observe(&h.api, None).await.unwrap();
    h.api.destroy(PARENT, &h.id).await.unwrap();
    let gone = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let ObserveRecord::Event { event } = events.next().await.unwrap().unwrap()
                && event.provider == "inner"
                && let EventKind::Gone { cause } = event.event
            {
                return (event.id, cause);
            }
        }
    })
    .await
    .expect("a gone event");
    assert_eq!(gone, (inner.id, Some(GoneCause::ParentGone { provider: PARENT.into(), environment: h.id.clone() })));
    assert!(matches!(h.api.provider("inner").await, Err(Error::Protocol(ProtocolError::NotFound { .. }))));
}

// A vessel's services pass through drydockd to its agent: started once,
// found running from the same body, read, listed and stopped.
#[tokio::test]
async fn a_vessels_services_pass_through_to_its_agent() {
    let h = Harness::start().await;
    let service = Service { program: "sleep".into(), args: vec!["600".into()], output: ServiceOutput::Discard, ..Default::default() };
    let Provisioned::Created(started) = h.api.put_service(PARENT, &h.id, "sleeper", &service).await.unwrap() else { panic!("started") };
    assert_eq!(started.state, ServiceState::Running);
    assert!(matches!(h.api.put_service(PARENT, &h.id, "sleeper", &service).await.unwrap(), Provisioned::Existing(_)));
    assert_eq!(h.api.service(PARENT, &h.id, "sleeper").await.unwrap().pid, started.pid);
    assert_eq!(h.api.services(PARENT, &h.id).await.unwrap().len(), 1);
    let stopped = h.api.remove_service(PARENT, &h.id, "sleeper", Some(1000)).await.unwrap();
    assert!(matches!(stopped.state, ServiceState::Exited { .. }), "{stopped:?}");
    assert!(matches!(h.api.service(PARENT, &h.id, "sleeper").await, Err(Error::Protocol(ProtocolError::NotFound { .. }))));
}

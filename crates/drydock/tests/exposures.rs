//! Exposures through the HTTP API, against the reference module. The vessel
//! is the test host: the stand-in gateway serves a real agent here and stands
//! in only for the SSH process boundary, so guest paths are this host's paths.
use drydock::{
    HostConnection,
    agent::stand_in::Gateway,
    api::Exposed,
    client::Client,
    config::Config,
    daemon::{Daemon, HostOption, ProviderApi, Seams},
    exposures::{GuestLayout, Timing},
};
use drydock_protocol::*;
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

const BUILD: &[u8] = b"exposures test agent";
const PROVIDER: &str = "vessels";
/// A provider whose vessels run no agent.
const PLAIN: &str = "plain";

/// The registry boundary: tags are already digests here.
struct Digests;
#[async_trait::async_trait]
impl drydock::launch::ImageResolver for Digests {
    async fn resolve(&self, image: &str) -> Result<String, drydock::client::Error> {
        Ok(image.into())
    }
}

/// The agent build every daemon here pushes, given through its seam.
struct Build;
#[async_trait::async_trait]
impl drydock::daemon::AgentBuilds for Build {
    async fn build(&self, _: &Platform) -> Result<Vec<u8>, String> {
        Ok(BUILD.to_vec())
    }
}

struct Harness {
    // Under /tmp, so socket paths stay within SUN_LEN.
    dir: tempfile::TempDir,
    gateway: Arc<Gateway>,
    host: tokio::task::JoinHandle<()>,
    reference: PathBuf,
    daemon: Option<(Arc<Daemon>, tokio::task::JoinHandle<()>)>,
    api: Client,
    id: String,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.host.abort();
        if let Some((_, server)) = self.daemon.take() {
            server.abort();
        }
    }
}
impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(dir.path().join("hosts"), "127.0.0.1 localhost\n").unwrap();
        let vessel = dir.path().join("vessel");
        std::fs::create_dir(&vessel).unwrap();
        let gateway = Gateway::start_as(&vessel, BUILD, Platform::new("linux", "amd64")).unwrap();
        let reference = dir.path().join("reference.sock");
        let socket = reference.clone();
        let host = tokio::spawn(async move {
            drydock_host::Host::new(drydock_host::reference::registry()).serve_unix(socket, std::future::pending()).await.unwrap();
        });
        let mut harness =
            Self { dir, gateway, host, reference, daemon: None, api: Client::unix("/nonexistent").unwrap(), id: String::new() };
        harness.start_daemon().await;
        let daemon = harness.daemon.as_ref().unwrap().0.clone();
        harness.id = daemon.launch(PROVIDER, &Default::default()).await.unwrap().id;
        harness
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    async fn start_daemon(&mut self) {
        for _ in 0..200 {
            if Client::unix(&self.reference).unwrap().hello().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let text = format!(
            "[providers.{PROVIDER}]\nmodule='reference'\ncredential={{env='PATH'}}\nimage='image@sha256:{}'\n\
             settings={{agent=true, poll_interval_ms=10, reach={{kind='ssh', endpoint='gateway.test:22', user='minted', host_key='ssh-ed25519 AAAA'}}}}\n\
             [providers.{PLAIN}]\nmodule='reference'\ncredential={{env='PATH'}}\nimage='image@sha256:{}'\nsettings={{poll_interval_ms=10}}\n",
            "a".repeat(64),
            "a".repeat(64)
        );
        let run = self.path("run");
        let seams = Seams {
            dialer: self.gateway.clone(),
            builds: Arc::new(Build),
            guest: GuestLayout { hosts: self.path("hosts"), sockets: self.path("guest") },
            timing: Timing { connect: Duration::from_secs(3), retry: Duration::from_millis(100), heartbeat: Duration::from_millis(200) },
            ..Seams::new(Arc::new(Digests))
        };
        let option =
            HostOption { optional: false, name: "rust".into(), connection: HostConnection::ExternalUnix { path: self.reference.clone() } };
        let daemon = Daemon::start_with_seams(Config::parse(&text).unwrap(), &run, run.join("keys"), vec![option], seams).await.unwrap();
        let socket = run.join("api.sock");
        let (serving, path) = (daemon.clone(), socket.clone());
        let server = tokio::spawn(async move { serving.serve(&path, std::future::pending()).await.unwrap() });
        self.api = Client::unix(&socket).unwrap();
        for _ in 0..200 {
            if self.api.hello().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.daemon = Some((daemon, server));
    }

    /// Drydock stops, closing what it held, and starts again from its files.
    async fn restart_daemon(&mut self) {
        let (daemon, server) = self.daemon.take().unwrap();
        server.abort();
        let _ = server.await;
        drop(daemon);
        self.start_daemon().await;
    }

    async fn events(&self) -> drydock::api::ObservationStream {
        ProviderApi::observe(&self.api, None).await.unwrap()
    }
}

/// The next exposure event on the stream.
async fn next_exposure(events: &mut drydock::api::ObservationStream) -> (Direction, String, bool, Option<ExposureError>, bool) {
    use futures::StreamExt;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let ObserveRecord::Event { event } = events.next().await.unwrap().unwrap()
                && let EventKind::Exposure { direction, name, ready, error, removed } = event.event
            {
                return (direction, name, ready, error, removed);
            }
        }
    })
    .await
    .expect("an exposure event")
}

/// Poll until `check` holds, for things the supervisor does in its own time.
async fn eventually<F: std::future::Future<Output = bool>>(mut check: impl FnMut() -> F) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("condition within 10s");
}

/// Bytes written on `from` arrive at whatever `listener` accepts, and its reply comes back.
async fn round_trip<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut from: S,
    accept: impl std::future::Future<Output = UnixStream>,
) {
    from.write_all(b"ping").await.unwrap();
    let mut far = tokio::time::timeout(Duration::from_secs(5), accept).await.expect("the far end is reached");
    let mut ping = [0; 4];
    far.read_exact(&mut ping).await.unwrap();
    assert_eq!(&ping, b"ping");
    far.write_all(b"pong").await.unwrap();
    let mut pong = [0; 4];
    from.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"pong");
}

fn unix(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn local(inward: &Inward) -> PathBuf {
    let Local::Unix(path) = &inward.local;
    path.into()
}

// Flotilla case 1, attach to cleat: an inward exposure gives a Unix socket on
// drydock's machine that reaches a socket in the vessel. A first PUT creates
// it (201) and announces it; a second replaces it (200). It reads back alone
// and in the list, and DELETE removes it, its socket and announces that;
// deleting it again succeeds.
#[tokio::test]
async fn an_inward_exposure_reaches_a_socket_in_the_vessel() {
    let h = Harness::start().await;
    let mut events = h.events().await;
    let cleat = h.path("cleat.sock");
    let target = UnixListener::bind(&cleat).unwrap();
    let request = InwardRequest { target: InwardTarget::Unix(unix(&cleat)) };
    let Exposed::Created(set) = h.api.put_inward(PROVIDER, &h.id, "cleat", &request).await.unwrap() else { panic!("a first PUT creates") };
    assert!(set.ready, "{set:?}");
    assert_eq!(next_exposure(&mut events).await, (Direction::Inward, "cleat".into(), true, None, false));
    round_trip(UnixStream::connect(local(&set)).await.unwrap(), async { target.accept().await.unwrap().0 }).await;

    let Exposed::Replaced(again) = h.api.put_inward(PROVIDER, &h.id, "cleat", &request).await.unwrap() else {
        panic!("a second PUT replaces")
    };
    assert_eq!(again, set);
    assert_eq!(next_exposure(&mut events).await, (Direction::Inward, "cleat".into(), true, None, false), "a replacing set fires too");
    assert_eq!(h.api.inward(PROVIDER, &h.id, "cleat").await.unwrap(), set);
    assert_eq!(h.api.inwards(PROVIDER, &h.id).await.unwrap(), vec![set.clone()]);

    h.api.remove_inward(PROVIDER, &h.id, "cleat").await.unwrap();
    assert!(matches!(next_exposure(&mut events).await, (Direction::Inward, name, false, None, true) if name == "cleat"));
    assert!(!local(&set).exists());
    assert!(matches!(h.api.inward(PROVIDER, &h.id, "cleat").await, Err(drydock::client::Error::Protocol(ProtocolError::NotFound { .. }))));
    assert!(h.api.inwards(PROVIDER, &h.id).await.unwrap().is_empty());
    h.api.remove_inward(PROVIDER, &h.id, "cleat").await.unwrap();
}

// Flotilla case 4, drive the agent: case 1 aimed at the agent's own socket
// gives a client a working agent connection without SSH or keys, and the
// agent speaks plain HTTP there, so curl reads its hello.
#[tokio::test]
async fn an_inward_exposure_of_the_agent_socket_drives_the_agent() {
    let h = Harness::start().await;
    let request = InwardRequest { target: InwardTarget::Unix(unix(&h.path("vessel/agent.sock"))) };
    let set = h.api.put_inward(PROVIDER, &h.id, "agent", &request).await.unwrap().into_inner();
    assert!(set.ready, "{set:?}");
    let stream = UnixStream::connect(local(&set)).await.unwrap();
    let agent = drydock_agent::Client::connect(Box::new(stream), String::new()).await.unwrap();
    assert!(!agent.hello().boot_id.is_empty());
    let hello = tokio::process::Command::new("curl")
        .arg("--unix-socket")
        .arg(local(&set))
        .args(["-sS", "http://agent/hello"])
        .output()
        .await
        .expect("curl is required by this test");
    assert!(hello.status.success(), "{}", String::from_utf8_lossy(&hello.stderr));
    let hello: drydock_agent::Hello = serde_json::from_slice(&hello.stdout).unwrap();
    assert_eq!(hello.boot_id, agent.hello().boot_id);
}

/// A provision request under `label`, prepared on the reference module.
async fn labelled(h: &Harness, label: &str, ssh_public_key: Option<String>) -> ProvisionRequest {
    labelled_on(h, PROVIDER, label, ssh_public_key).await
}
async fn labelled_on(h: &Harness, provider: &str, label: &str, ssh_public_key: Option<String>) -> ProvisionRequest {
    let size = Size { cpus: 1.0, memory_bytes: 1024, disk_bytes: 1024 };
    let request = PrepareRequest {
        platform: None,
        route: None,
        image_pull: None,
        image_digest: format!("image@sha256:{}", "a".repeat(64)),
        tools_digest: "tools".into(),
        size: size.clone(),
    };
    let prepared = h.api.prepare(provider, &request).await.unwrap();
    ProvisionRequest { label: label.into(), prepared, size, egress: EgressRequest::Open, ssh_public_key }
}

// A client that provisions under its own label and names no key gets one drydock
// holds, as a launch does: its vessel takes exposures, a repeated provision
// adopts it with the same key, and its exposures come back after a restart.
#[tokio::test]
async fn a_labelled_provision_without_a_key_takes_exposures() {
    let mut h = Harness::start().await;
    let request = labelled(&h, "client/vessel", None).await;
    let drydock::api::Provisioned::Created(created) = h.api.provision(PROVIDER, &request).await.unwrap() else {
        panic!("a first provision creates")
    };
    let cleat = h.path("labelled-cleat.sock");
    let target = UnixListener::bind(&cleat).unwrap();
    let set = h.api.put_inward(PROVIDER, &created.id, "cleat", &InwardRequest { target: InwardTarget::Unix(unix(&cleat)) }).await.unwrap();
    assert!(set.into_inner().ready);
    let drydock::api::Provisioned::Existing(adopted) = h.api.provision(PROVIDER, &request).await.unwrap() else {
        panic!("the label adopts")
    };
    assert_eq!(adopted.id, created.id);
    // The label names no path: its key directory is its digest.
    let keys: Vec<_> = std::fs::read_dir(h.path("run/keys")).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    assert!(keys.iter().all(|name| !name.contains("client")), "{keys:?}");
    h.restart_daemon().await;
    let api = h.api.clone();
    let id = created.id.clone();
    eventually(|| {
        let (api, id) = (api.clone(), id.clone());
        async move { api.inward(PROVIDER, &id, "cleat").await.is_ok_and(|inward| inward.ready) }
    })
    .await;
    let inward = h.api.inward(PROVIDER, &created.id, "cleat").await.unwrap();
    round_trip(UnixStream::connect(local(&inward)).await.unwrap(), async { target.accept().await.unwrap().0 }).await;
}

// Two first provisions of one label at once share the one key drydock makes,
// and adopt one environment.
#[tokio::test]
async fn concurrent_first_provisions_of_a_label_share_one_key() {
    let h = Harness::start().await;
    let request = labelled(&h, "raced", None).await;
    let (a, b) = tokio::join!(h.api.provision(PROVIDER, &request), h.api.provision(PROVIDER, &request));
    assert_eq!(a.unwrap().into_inner().id, b.unwrap().into_inner().id);
    let held = std::fs::read_dir(h.path("run/keys")).unwrap().filter(|e| e.as_ref().unwrap().path().join("id_ed25519").is_file()).count();
    assert_eq!(held, 2, "the harness's launch and this label");
}

// A client label equal to a launch's UUID gets no share of that launch's key:
// it names an environment drydock holds no client key for, so it is refused.
#[tokio::test]
async fn a_client_label_never_takes_a_launchs_key() {
    let h = Harness::start().await;
    let launched = h.api.inspect(PROVIDER, &h.id).await.unwrap().label.unwrap();
    let request = labelled(&h, &launched, None).await;
    let refused = h.api.provision(PROVIDER, &request).await.map(drop);
    assert!(matches!(refused, Err(drydock::client::Error::Protocol(ProtocolError::Refused { .. }))), "{refused:?}");
    let launch = std::fs::read(h.path("run/keys").join(&launched).join("request.json")).unwrap();
    assert!(!String::from_utf8_lossy(&launch).contains("\"tools\""), "the launch's record is its own");
}

// A keyless provision for a provider whose vessels run no agent is passed
// through untouched: drydock makes no key for it.
#[tokio::test]
async fn a_keyless_provision_without_an_agent_gets_no_key() {
    let h = Harness::start().await;
    let before = std::fs::read_dir(h.path("run/keys")).unwrap().count();
    let request = labelled_on(&h, PLAIN, "plain-vessel", None).await;
    h.api.provision(PLAIN, &request).await.unwrap();
    assert_eq!(std::fs::read_dir(h.path("run/keys")).unwrap().count(), before);
}

// A label already naming an environment drydock holds no key for (one
// provisioned with the client's own key) is refused: its key cannot be rotated.
#[tokio::test]
async fn a_label_drydock_holds_no_key_for_is_refused() {
    let h = Harness::start().await;
    let own = labelled(&h, "own-key", Some("ssh-ed25519 AAAA client".into())).await;
    h.api.provision(PROVIDER, &own).await.unwrap();
    let keyless = ProvisionRequest { ssh_public_key: None, ..own };
    let refused = h.api.provision(PROVIDER, &keyless).await.map(drop);
    assert!(matches!(refused, Err(drydock::client::Error::Protocol(ProtocolError::Refused { .. }))), "{refused:?}");
}

// Flotilla case 2, crew talks back: an outward exposure gives a Unix socket in
// the vessel that reaches a socket on drydock's machine.
#[tokio::test]
async fn an_outward_exposure_reaches_a_socket_on_drydocks_machine() {
    let h = Harness::start().await;
    let crew = h.path("crew.sock");
    let destination = UnixListener::bind(&crew).unwrap();
    let guest = h.path("guest-crew.sock");
    let request = OutwardRequest { guest: Guest::Unix { unix: unix(&guest) }, destination: OutwardDestination::Unix(unix(&crew)) };
    let set = h.api.put_outward(PROVIDER, &h.id, "crew", &request).await.unwrap().into_inner();
    assert!(set.ready && set.address.is_none() && set.resolved.is_none(), "{set:?}");
    round_trip(UnixStream::connect(&guest).await.unwrap(), async { destination.accept().await.unwrap().0 }).await;
}

// Flotilla case 3, private services: each guest name gets its own loopback
// address in the vessel and a hosts-file line, and reaches its destination,
// whose name was resolved when set. Removing one removes its line only;
// lines drydock did not write are kept.
#[tokio::test]
async fn named_outward_exposures_get_loopback_addresses_and_hosts_lines() {
    let h = Harness::start().await;
    let resolved = tokio::net::lookup_host("localhost:0").await.unwrap().next().unwrap().ip();
    let service = tokio::net::TcpListener::bind((resolved, 0)).await.unwrap();
    let port = service.local_addr().unwrap().port();
    let request = |name: &str| OutwardRequest {
        guest: Guest::Name { name: HostAddress::try_from(name.to_owned()).unwrap(), port: Port::new(8443).unwrap() },
        destination: OutwardDestination::Tcp(format!("localhost:{port}")),
    };
    let forge = h.api.put_outward(PROVIDER, &h.id, "forge", &request("forge.test")).await.unwrap().into_inner();
    let cache = h.api.put_outward(PROVIDER, &h.id, "cache", &request("cache.test")).await.unwrap().into_inner();
    assert!(forge.ready && cache.ready, "{forge:?} {cache:?}");
    assert_eq!(forge.resolved, Some(std::net::SocketAddr::new(resolved, port)));
    let (forge_at, cache_at) = (forge.address.unwrap(), cache.address.unwrap());
    assert!(forge_at.ip().is_loopback() && cache_at.ip().is_loopback() && forge_at.ip() != cache_at.ip());
    assert_eq!(forge_at.port(), 8443);
    let hosts = std::fs::read_to_string(h.path("hosts")).unwrap();
    let names: Vec<(&str, &str)> = hosts
        .lines()
        .filter_map(|line| line.split_whitespace().take(2).collect::<Vec<_>>().try_into().ok().map(|[a, n]: [&str; 2]| (a, n)))
        .collect();
    let (forge_ip, cache_ip) = (forge_at.ip().to_string(), cache_at.ip().to_string());
    assert!(names.contains(&(forge_ip.as_str(), "forge.test")) && names.contains(&(cache_ip.as_str(), "cache.test")), "{hosts}");
    assert!(hosts.starts_with("127.0.0.1 localhost\n"), "{hosts}");

    let mut guest = tokio::net::TcpStream::connect(forge_at).await.unwrap();
    guest.write_all(b"ping").await.unwrap();
    let (mut far, _) = tokio::time::timeout(Duration::from_secs(5), service.accept()).await.unwrap().unwrap();
    let mut ping = [0; 4];
    far.read_exact(&mut ping).await.unwrap();
    assert_eq!(&ping, b"ping");

    // One guest name on a second port shares its address and its one line.
    let mut second = request("forge.test");
    second.guest = Guest::Name { name: HostAddress::try_from("forge.test".to_owned()).unwrap(), port: Port::new(8444).unwrap() };
    let forge_ssh = h.api.put_outward(PROVIDER, &h.id, "forge-ssh", &second).await.unwrap().into_inner();
    assert!(forge_ssh.ready, "{forge_ssh:?}");
    assert_eq!(forge_ssh.address.unwrap().ip(), forge_at.ip());
    assert_eq!(std::fs::read_to_string(h.path("hosts")).unwrap().matches("forge.test").count(), 1);
    // A name another line already gives would be shadowed, so it is refused.
    let shadowed = h.api.put_outward(PROVIDER, &h.id, "local", &request("localhost")).await.unwrap().into_inner();
    assert_eq!(shadowed.error.map(|e| e.code), Some(ExposureErrorCode::Refused));

    h.api.remove_outward(PROVIDER, &h.id, "cache").await.unwrap();
    let hosts = std::fs::read_to_string(h.path("hosts")).unwrap();
    assert!(hosts.contains("forge.test") && !hosts.contains("cache.test") && hosts.starts_with("127.0.0.1 localhost\n"), "{hosts}");
}

// A guest name removed while the vessel is stopped loses its hosts line
// when the vessel runs again, even when no exposure is left.
// Stand-in vessels share this host's loopback, so this test's guest port is its own.
#[tokio::test]
async fn a_guest_name_removed_while_stopped_loses_its_hosts_line_on_resume() {
    let h = Harness::start().await;
    let service = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let request = OutwardRequest {
        guest: Guest::Name { name: HostAddress::try_from("forge.test".to_owned()).unwrap(), port: Port::new(8453).unwrap() },
        destination: OutwardDestination::Tcp(service.local_addr().unwrap().to_string()),
    };
    assert!(h.api.put_outward(PROVIDER, &h.id, "forge", &request).await.unwrap().into_inner().ready);
    let token = h.api.suspend(PROVIDER, &h.id).await.unwrap();
    h.api.remove_outward(PROVIDER, &h.id, "forge").await.unwrap();
    assert!(std::fs::read_to_string(h.path("hosts")).unwrap().contains("forge.test"), "unreachable while stopped");
    h.api.resume(PROVIDER, &h.id, &token).await.unwrap();
    let hosts = h.path("hosts");
    // The file is rewritten in place (a bind-mounted hosts file keeps its
    // inode), so wait for its final content rather than any without the line.
    eventually(|| {
        let hosts = hosts.clone();
        async move { std::fs::read_to_string(&hosts).unwrap() == "127.0.0.1 localhost\n" }
    })
    .await;
}

// What a PUT reports is what drydock stored: when the record cannot be
// saved, the request fails and nothing is set.
#[tokio::test]
async fn an_exposure_that_cannot_be_recorded_is_not_set() {
    let h = Harness::start().await;
    let keys = std::fs::read_dir(h.path("run/keys")).unwrap().flatten().map(|e| e.path()).next().unwrap();
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o500)).unwrap();
    let request = InwardRequest { target: InwardTarget::Unix(unix(&h.path("cleat.sock"))) };
    let result = h.api.put_inward(PROVIDER, &h.id, "cleat", &request).await;
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err(), "{result:?}");
    assert!(h.api.inwards(PROVIDER, &h.id).await.unwrap().is_empty());
    assert!(
        std::fs::read_dir(h.path("run/exposures")).unwrap().flatten().all(|dir| std::fs::read_dir(dir.path()).unwrap().next().is_none())
    );
}

// An environment destroyed while drydock was down is forgotten when drydock
// starts again and finds it gone: its record and local sockets go.
#[tokio::test]
async fn an_environment_destroyed_while_drydock_was_down_is_forgotten() {
    let mut h = Harness::start().await;
    let set = h
        .api
        .put_inward(PROVIDER, &h.id, "cleat", &InwardRequest { target: InwardTarget::Unix(unix(&h.path("cleat.sock"))) })
        .await
        .unwrap()
        .into_inner();
    let (daemon, server) = h.daemon.take().unwrap();
    server.abort();
    let _ = server.await;
    drop(daemon);
    let host = Client::unix(&h.reference).unwrap().credentialed(Some(Secret::new(std::env::var("PATH").unwrap())));
    host.destroy(PROVIDER, &h.id).await.unwrap();
    h.start_daemon().await;
    let keys = h.path("run/keys");
    eventually(|| {
        let keys = keys.clone();
        async move { std::fs::read_dir(&keys).unwrap().flatten().all(|e| !e.path().join("exposures.json").exists()) }
    })
    .await;
    assert!(!local(&set).exists());
}

// A PUT on a vessel that is not running records the exposure and returns
// ready false with not_running; resuming the vessel sets it up, announced by
// an event as ready changes.
#[tokio::test]
async fn an_exposure_set_while_suspended_is_set_up_on_resume() {
    let h = Harness::start().await;
    let token = h.api.suspend(PROVIDER, &h.id).await.unwrap();
    let mut events = h.events().await;
    let cleat = h.path("cleat.sock");
    let target = UnixListener::bind(&cleat).unwrap();
    let request = InwardRequest { target: InwardTarget::Unix(unix(&cleat)) };
    let Exposed::Created(set) = h.api.put_inward(PROVIDER, &h.id, "cleat", &request).await.unwrap() else { panic!("created") };
    assert!(!set.ready);
    assert_eq!(set.error.as_ref().map(|e| e.code), Some(ExposureErrorCode::NotRunning));
    assert!(matches!(
        next_exposure(&mut events).await,
        (_, _, false, Some(ExposureError { code: ExposureErrorCode::NotRunning, .. }), false)
    ));
    h.api.resume(PROVIDER, &h.id, &token).await.unwrap();
    assert_eq!(next_exposure(&mut events).await, (Direction::Inward, "cleat".into(), true, None, false));
    assert!(h.api.inward(PROVIDER, &h.id, "cleat").await.unwrap().ready);
    round_trip(UnixStream::connect(local(&set)).await.unwrap(), async { target.accept().await.unwrap().0 }).await;
}

// A vessel that cannot be reached reports vessel_unreachable, as an event
// when ready changes; when its agent comes back (with none of its earlier
// forwards) drydock sets every exposure up again.
#[tokio::test]
async fn a_lost_vessel_is_reported_and_its_exposures_come_back() {
    let h = Harness::start().await;
    let cleat = h.path("cleat.sock");
    let target = UnixListener::bind(&cleat).unwrap();
    let set =
        h.api.put_inward(PROVIDER, &h.id, "cleat", &InwardRequest { target: InwardTarget::Unix(unix(&cleat)) }).await.unwrap().into_inner();
    assert!(set.ready);
    let mut events = h.events().await;
    h.gateway.stop();
    let (_, _, ready, error, _) = next_exposure(&mut events).await;
    assert!(!ready);
    assert_eq!(error.map(|e| e.code), Some(ExposureErrorCode::VesselUnreachable));
    assert!(!h.api.inward(PROVIDER, &h.id, "cleat").await.unwrap().ready);
    h.gateway.restart().unwrap();
    assert_eq!(next_exposure(&mut events).await, (Direction::Inward, "cleat".into(), true, None, false));
    round_trip(UnixStream::connect(local(&set)).await.unwrap(), async { target.accept().await.unwrap().0 }).await;
}

// Drydock keeps exposures in its files: after drydock restarts, it sets them
// up again at the same local path, without being asked.
#[tokio::test]
async fn exposures_come_back_after_drydock_restarts() {
    let mut h = Harness::start().await;
    let cleat = h.path("cleat.sock");
    let target = UnixListener::bind(&cleat).unwrap();
    let crew = h.path("crew.sock");
    let destination = UnixListener::bind(&crew).unwrap();
    let guest = h.path("guest-crew.sock");
    let inward =
        h.api.put_inward(PROVIDER, &h.id, "cleat", &InwardRequest { target: InwardTarget::Unix(unix(&cleat)) }).await.unwrap().into_inner();
    let outward = OutwardRequest { guest: Guest::Unix { unix: unix(&guest) }, destination: OutwardDestination::Unix(unix(&crew)) };
    h.api.put_outward(PROVIDER, &h.id, "crew", &outward).await.unwrap();
    h.restart_daemon().await;
    let (api, id) = (h.api.clone(), h.id.clone());
    eventually(|| {
        let (api, id) = (api.clone(), id.clone());
        async move {
            let inward = api.inwards(PROVIDER, &id).await.unwrap();
            let outward = api.outwards(PROVIDER, &id).await.unwrap();
            inward.len() == 1 && inward[0].ready && outward.len() == 1 && outward[0].ready
        }
    })
    .await;
    assert_eq!(h.api.inward(PROVIDER, &h.id, "cleat").await.unwrap(), inward);
    round_trip(UnixStream::connect(local(&inward)).await.unwrap(), async { target.accept().await.unwrap().0 }).await;
    round_trip(UnixStream::connect(&guest).await.unwrap(), async { destination.accept().await.unwrap().0 }).await;
}

// Deleting the environment removes its exposures: their local sockets, their
// record, and an event for each saying so.
#[tokio::test]
async fn destroying_the_environment_removes_its_exposures() {
    let h = Harness::start().await;
    let cleat = h.path("cleat.sock");
    let _target = UnixListener::bind(&cleat).unwrap();
    let set =
        h.api.put_inward(PROVIDER, &h.id, "cleat", &InwardRequest { target: InwardTarget::Unix(unix(&cleat)) }).await.unwrap().into_inner();
    let record = std::fs::read_dir(h.path("run/keys")).unwrap().flatten().map(|e| e.path().join("exposures.json")).find(|p| p.exists());
    let record = record.expect("a record beside the key");
    let mut events = h.events().await;
    h.api.destroy(PROVIDER, &h.id).await.unwrap();
    assert!(matches!(next_exposure(&mut events).await, (Direction::Inward, name, false, None, true) if name == "cleat"));
    assert!(!record.exists() && !local(&set).exists());
    assert!(h.api.inwards(PROVIDER, &h.id).await.is_err(), "the environment is gone");
}

// Exposures are refused up front when they could never work: a name that is
// not a safe file name, a relative path, a TCP destination that is not
// host:port, a guest name that is an address, and an environment unknown to
// the provider.
#[tokio::test]
async fn invalid_exposures_are_refused() {
    let h = Harness::start().await;
    let inward = |target: &str| InwardRequest { target: InwardTarget::Unix(target.into()) };
    let refused =
        |result: Result<_, drydock::client::Error>| matches!(result, Err(drydock::client::Error::Protocol(ProtocolError::Refused { .. })));
    assert!(refused(h.api.put_inward(PROVIDER, &h.id, ".hidden", &inward("/run/cleat.sock")).await.map(drop)));
    assert!(refused(h.api.put_inward(PROVIDER, &h.id, "cleat", &inward("run/cleat.sock")).await.map(drop)));
    let outward = |guest: Guest, destination: &str| OutwardRequest { guest, destination: OutwardDestination::Tcp(destination.into()) };
    let crew = Guest::Unix { unix: "/run/crew.sock".into() };
    assert!(refused(h.api.put_outward(PROVIDER, &h.id, "lab", &outward(crew.clone(), "no-port")).await.map(drop)));
    let address = Guest::Name { name: HostAddress::try_from("10.0.0.5".to_owned()).unwrap(), port: Port::new(443).unwrap() };
    assert!(refused(h.api.put_outward(PROVIDER, &h.id, "lab", &outward(address, "lab.test:443")).await.map(drop)));
    assert!(matches!(
        h.api.put_inward(PROVIDER, "unknown", "cleat", &inward("/run/cleat.sock")).await,
        Err(drydock::client::Error::Protocol(ProtocolError::NotFound { .. }))
    ));
    assert!(h.api.inwards(PROVIDER, &h.id).await.unwrap().is_empty() && h.api.outwards(PROVIDER, &h.id).await.unwrap().is_empty());
}

// A PUT that finds its environment destroyed behind drydock's back answers
// NotFound, and drydock forgets the environment's exposures at once.
#[tokio::test]
async fn a_put_on_an_environment_destroyed_behind_drydock_is_not_found() {
    let h = Harness::start().await;
    let request = InwardRequest { target: InwardTarget::Unix(unix(&h.path("cleat.sock"))) };
    let set = h.api.put_inward(PROVIDER, &h.id, "cleat", &request).await.unwrap().into_inner();
    let host = Client::unix(&h.reference).unwrap().credentialed(Some(Secret::new(std::env::var("PATH").unwrap())));
    host.destroy(PROVIDER, &h.id).await.unwrap();
    let (api, id) = (h.api.clone(), h.id.clone());
    eventually(|| {
        let (api, id) = (api.clone(), id.clone());
        async move { api.inspect(PROVIDER, &id).await.is_err() }
    })
    .await;
    let again = h.api.put_inward(PROVIDER, &h.id, "agent", &request).await;
    assert!(matches!(again, Err(drydock::client::Error::Protocol(ProtocolError::NotFound { .. }))), "{again:?}");
    assert!(!local(&set).exists());
}

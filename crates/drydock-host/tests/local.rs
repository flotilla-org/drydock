//! The `local` module against the real `drydock-agent`: each test starts agents
//! as child processes under a temporary root.
#![cfg(target_os = "linux")]
#[path = "support/agent.rs"]
mod agent;
#[path = "support/public_server.rs"]
mod public_server;
use drydock::{
    api::ProviderApi as _,
    conformance::{self, Options},
};
use drydock_host::{
    local::LocalModule,
    module::{Credentials, HttpClient, Module, Provider, Provisioned},
};
use drydock_protocol::*;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A temporary root whose agents are killed when the test ends, passing or not.
struct Root(tempfile::TempDir);
impl Root {
    fn new() -> Self {
        Self(tempfile::tempdir().unwrap())
    }
    fn path(&self) -> PathBuf {
        self.0.path().join("vessels")
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        for pid in std::fs::read_dir(self.path()).into_iter().flatten().flatten() {
            if let Some(pid) = std::fs::read_to_string(pid.path().join("agent.pid")).ok().and_then(|pid| pid.trim().parse::<i32>().ok()) {
                unsafe { libc::kill(-pid, libc::SIGKILL) };
            }
        }
    }
}

struct NoHttp;
#[async_trait::async_trait]
impl HttpClient for NoHttp {
    async fn execute(&self, _: reqwest::Request, _: &rigging_http_client::ChannelLabel) -> Result<http::Response<bytes::Bytes>, String> {
        Err("local makes no HTTP calls".into())
    }
}

/// A provider as a freshly started host configures it. Calling again with the
/// same root is a host restart.
async fn provider(root: &Root) -> Arc<dyn Provider> {
    configured(serde_json::json!({"root": root.path(), "agent": agent::agent_binary()})).await.unwrap()
}
async fn configured(settings: serde_json::Value) -> Result<Arc<dyn Provider>, ProtocolError> {
    let configuration =
        ProviderConfiguration { module: "local".into(), settings: serde_json::from_value(settings).unwrap(), credential: None };
    LocalModule.configure("local", &configuration, Arc::new(NoHttp)).await
}
fn credentials() -> Credentials {
    Credentials::default()
}
async fn prepared(p: &dyn Provider) -> Prepared {
    p.prepare(
        PrepareRequest {
            size: Size { cpus: 1., memory_bytes: 1 << 30, disk_bytes: 1 << 30 },
            platform: Some(Platform::current()),
            route: Some(ImageRouteKind::RegistryPull),
            image_pull: None,
            image_digest: format!("ubuntu@sha256:{}", "a".repeat(64)),
            tools_digest: "tools".into(),
        },
        &credentials(),
    )
    .await
    .unwrap()
}
async fn request(p: &dyn Provider, label: &str) -> ProvisionRequest {
    ProvisionRequest {
        label: label.into(),
        prepared: prepared(p).await,
        size: Size { cpus: 1., memory_bytes: 1 << 30, disk_bytes: 1 << 30 },
        egress: EgressRequest::Open,
        ssh_public_key: None,
    }
}
async fn provision(p: &dyn Provider, label: &str) -> Environment {
    p.provision(request(p, label).await, &credentials()).await.unwrap().into_inner()
}
/// `GET /hello` over a relayed connection: what drydock sends to wait for an agent.
async fn hello(p: &dyn Provider, id: &str) -> Result<String, ProtocolError> {
    let mut stream = p.relay(id, &credentials()).await?;
    stream.write_all(b"GET /hello HTTP/1.1\r\nhost: agent\r\nconnection: close\r\n\r\n").await.unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await.unwrap();
    Ok(reply)
}
fn pid(root: &Root, id: &str) -> i32 {
    std::fs::read_to_string(root.path().join(id).join("agent.pid")).unwrap().trim().parse().unwrap()
}
fn alive(pid: i32) -> bool {
    // A zombie still answers signal 0; its cmdline is empty.
    (unsafe { libc::kill(pid, 0) } == 0) && std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| !c.is_empty())
}
async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

// Prepare records the image and tools digests and the host's platform without
// pulling anything, and repeating it changes nothing.
#[tokio::test]
async fn prepare_records_the_request_without_pulling() {
    let root = Root::new();
    let p = provider(&root).await;
    let first = prepared(&*p).await;
    assert_eq!(first, prepared(&*p).await);
    assert_eq!(first.platform, Platform::current());
    assert_eq!(first.image_digest, format!("ubuntu@sha256:{}", "a".repeat(64)));
    assert_eq!(first.tools_digest, "tools");
    assert!(!root.path().exists(), "prepare creates nothing on disk");
}

// The declaration says what a local vessel is: no isolation, the host's platform,
// open egress that is only advisory, no usage or quota to report, and the
// host's own filesystem.
#[tokio::test]
async fn capabilities_are_honest_about_having_no_isolation() {
    let root = Root::new();
    let p = provider(&root).await;
    let c = p.capabilities();
    assert!(c.agent);
    assert_eq!(c.platforms, [Platform::current()]);
    assert_eq!(c.egress, EgressCapability { routes: vec![EgressRoute::Open], model: EgressModel::unfiltered() });
    assert!(c.suspend_resume && c.suspend_preserves_memory == Some(false));
    assert!(!c.usage && !c.quota && !c.export && !c.fallback_runner);
    assert_eq!(c.workspace_root, root.path().to_str().unwrap());
    assert!(c.host_filesystem, "vessels share this machine's filesystem");
    assert!(c.host_processes, "vessels are processes of this machine: no isolation");
    // The network is the host's, and the agent carries exposures all the same.
    assert_eq!(c.reach_ways, [ReachWay::HostNetwork, ReachWay::OutwardExposure]);
    let ports = Ports::from(p.operations());
    assert_eq!(ports, Ports { suspend_resume: true, ..Ports::default() });
    assert_eq!(p.readiness(&credentials()), Readiness::Ready);
}

// A provider that cannot find an agent build says so, instead of failing every launch.
#[tokio::test]
async fn readiness_reports_a_missing_agent_build() {
    let root = Root::new();
    let p = configured(serde_json::json!({"root": root.path(), "agent": root.path().join("absent")})).await.unwrap();
    assert!(matches!(p.readiness(&credentials()), Readiness::MissingTool { .. }));
}

#[tokio::test]
async fn settings_are_validated() {
    assert!(configured(serde_json::json!({"root": "relative/path"})).await.is_err());
    assert!(configured(serde_json::json!({"unknown": 1})).await.is_err());
}

// Provision creates the vessel's directory, starts the agent on the socket
// inside it, and returns only once the agent answers hello through the relay.
#[tokio::test]
async fn provision_starts_an_agent_that_answers_hello() {
    let root = Root::new();
    let p = provider(&root).await;
    let environment = provision(&*p, "first").await;
    assert_eq!(environment.label.as_deref(), Some("first"));
    assert_eq!(environment.state, Observation::Running);
    assert_eq!(environment.platform, Some(Platform::current()));
    assert_eq!(environment.egress, Enforcement::Advisory);
    let socket = root.path().join(&environment.id).join("run/drydock/agent.sock");
    assert!(socket.exists(), "the agent listens inside the environment's directory");
    assert!(hello(&*p, &environment.id).await.unwrap().starts_with("HTTP/1.1 200"));
    assert_eq!(p.reach(&environment.id, &credentials()).await.unwrap(), Reach::relay("local", &environment.id));
}

// The same label is the same environment, even when asked at the same moment.
#[tokio::test]
async fn provision_is_idempotent_by_label() {
    let root = Root::new();
    let p = provider(&root).await;
    let (a, b) = tokio::join!(async { p.provision(request(&*p, "same").await, &credentials()).await.unwrap() }, async {
        p.provision(request(&*p, "same").await, &credentials()).await.unwrap()
    },);
    assert_ne!(matches!(a, Provisioned::Created(_)), matches!(b, Provisioned::Created(_)));
    assert_eq!(a.into_inner().id, b.into_inner().id);
    let again = p.provision(request(&*p, "same").await, &credentials()).await.unwrap();
    assert!(matches!(again, Provisioned::Existing(_)));
    assert_eq!(p.list(&credentials()).await.unwrap().len(), 1);
}

// Deny-all cannot be enforced on the host's own network, so it is refused with
// the reason; open egress is accepted.
#[tokio::test]
async fn deny_all_egress_is_refused_with_a_reason() {
    let root = Root::new();
    let p = provider(&root).await;
    for egress in [EgressRequest::DenyAll { direct: vec![] }, EgressRequest::default()] {
        let error = p.provision(ProvisionRequest { egress, ..request(&*p, "denied").await }, &credentials()).await.unwrap_err();
        let ProtocolError::Refused { reason } = error else { panic!("{error:?}") };
        assert!(reason.contains("deny-all"), "{reason}");
    }
    assert!(p.list(&credentials()).await.unwrap().is_empty());
}

// A prepared form from another provider is refused before anything is created.
#[tokio::test]
async fn a_foreign_prepared_form_is_refused() {
    let root = Root::new();
    let p = provider(&root).await;
    let mut foreign = request(&*p, "foreign").await;
    foreign.prepared.provider = "elsewhere".into();
    assert!(matches!(p.provision(foreign, &credentials()).await, Err(ProtocolError::Refused { .. })));
    assert!(!root.path().exists());
}

// A missing agent build fails the provision and leaves no environment behind.
#[tokio::test]
async fn provision_without_an_agent_build_leaves_nothing() {
    let root = Root::new();
    let p = configured(serde_json::json!({"root": root.path(), "agent": root.path().join("absent")})).await.unwrap();
    let error = p.provision(request(&*p, "nothing").await, &credentials()).await.unwrap_err();
    assert!(matches!(error, ProtocolError::Unavailable { .. }), "{error:?}");
    assert!(p.list(&credentials()).await.unwrap().is_empty());
}

// An agent that dies while starting fails the provision and cleans up.
#[tokio::test]
async fn provision_cleans_up_when_the_agent_cannot_start() {
    let root = Root::new();
    let broken = root.0.path().join("broken-agent");
    std::fs::write(&broken, "#!/bin/sh\nexit 1\n").unwrap();
    let p = configured(serde_json::json!({"root": root.path(), "agent": broken})).await.unwrap();
    let error = p.provision(request(&*p, "broken").await, &credentials()).await.unwrap_err();
    assert!(matches!(error, ProtocolError::Unavailable { .. }), "{error:?}");
    assert!(p.list(&credentials()).await.unwrap().is_empty());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

// Suspend stops the agent and keeps the files; resume starts it again. The
// token is stable, and only this environment's token resumes it.
#[tokio::test]
async fn suspend_stops_the_agent_and_resume_restarts_it() {
    let root = Root::new();
    let p = provider(&root).await;
    let suspend = p.operations().suspend_resume.unwrap();
    let environment = provision(&*p, "sleeper").await;
    let kept = root.path().join(&environment.id).join("kept.txt");
    std::fs::write(&kept, "still here").unwrap();
    let before = pid(&root, &environment.id);

    let token = suspend.suspend(&environment.id, &credentials()).await.unwrap();
    assert_eq!(suspend.suspend(&environment.id, &credentials()).await.unwrap(), token);
    assert_eq!(
        p.inspect(&environment.id, &credentials()).await.unwrap().state,
        Observation::Stopped { cause: StopCause::SuspendedByRequest }
    );
    assert!(!alive(before));
    assert!(matches!(hello(&*p, &environment.id).await, Err(ProtocolError::Unavailable { .. })));
    assert_eq!(std::fs::read_to_string(&kept).unwrap(), "still here");

    let wrong = ResumeToken { token: Secret::new("local:local-000000000000") };
    assert!(matches!(suspend.resume(&environment.id, wrong, &credentials()).await, Err(ProtocolError::Refused { .. })));
    suspend.resume(&environment.id, token, &credentials()).await.unwrap();
    assert_eq!(p.inspect(&environment.id, &credentials()).await.unwrap().state, Observation::Running);
    assert!(hello(&*p, &environment.id).await.unwrap().starts_with("HTTP/1.1 200"));
    assert_eq!(std::fs::read_to_string(&kept).unwrap(), "still here");
}

// Destroy kills the agent and everything it started, removes the directory,
// and is safe to repeat.
#[tokio::test]
async fn destroy_kills_the_agent_and_its_process_group() {
    let root = Root::new();
    let p = provider(&root).await;
    let environment = provision(&*p, "doomed").await;
    let agent_pid = pid(&root, &environment.id);

    // A command the agent starts shares the agent's process group.
    let build = std::fs::read(agent::agent_binary()).unwrap();
    let open = || async {
        let stream = p.relay(&environment.id, &credentials()).await.map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        Ok(Box::new(stream) as _)
    };
    let client = drydock_agent::Client::connect_current(open, &Platform::current(), &build, Duration::from_secs(10)).await.unwrap();
    let marker = root.path().join(&environment.id).join("child.pid");
    let script = format!("sleep 300 & echo $! > {}; wait", marker.display());
    let _child = client.spawn(drydock_agent::Exec::new("sh", ["-c", &script])).await.unwrap();
    eventually("the command started", || marker.exists() && !std::fs::read_to_string(&marker).unwrap().trim().is_empty()).await;
    let child_pid: i32 = std::fs::read_to_string(&marker).unwrap().trim().parse().unwrap();
    eventually("the command is running", || alive(child_pid)).await;

    p.destroy(&environment.id, &credentials()).await.unwrap();
    p.destroy(&environment.id, &credentials()).await.unwrap();
    eventually("the agent and its child stopped", || !alive(agent_pid) && !alive(child_pid)).await;
    assert!(!root.path().join(&environment.id).exists());
    assert!(p.list(&credentials()).await.unwrap().is_empty());
    assert!(matches!(p.inspect(&environment.id, &credentials()).await, Err(ProtocolError::NotFound { .. })));
}

/// A session of someone else's, with a member besides its leader: what a wrong kill would reach.
struct Bystander {
    leader: std::process::Child,
    member: i32,
}
impl Bystander {
    fn new(dir: &std::path::Path) -> Self {
        use std::os::unix::process::CommandExt;
        let marker = dir.join("bystander.pid");
        let mut command = std::process::Command::new("sh");
        command.args(["-c", &format!("sleep 300 & echo $! > {}; wait", marker.display())]);
        // SAFETY: setsid is async-signal-safe.
        unsafe { command.pre_exec(|| if libc::setsid() < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }) };
        let leader = command.spawn().unwrap();
        let member = loop {
            if let Some(pid) = std::fs::read_to_string(&marker).ok().and_then(|pid| pid.trim().parse().ok()) {
                break pid;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        Self { leader, member }
    }
    fn pid(&self) -> i32 {
        self.leader.id() as i32
    }
    fn untouched(&self) -> bool {
        alive(self.pid()) && alive(self.member)
    }
}
impl Drop for Bystander {
    fn drop(&mut self) {
        unsafe { libc::kill(-self.pid(), libc::SIGKILL) };
        let _ = self.leader.wait();
    }
}

// Destroy ends the vessel's processes and nobody else's, whatever its files say. A
// vessel directory outlives the machine's processes (a restart of the host, of its
// container, of the machine), so the PID it names can belong to another process by
// now, or lead a session that is not the agent's. Signalling that session's members
// is how destroy reached drydock-host itself (flotilla-org/drydock#269).
#[tokio::test]
async fn destroy_never_signals_a_process_outside_the_vessel() {
    let root = Root::new();
    let p = provider(&root).await;
    let bystander = Bystander::new(root.0.path());
    let namespace = std::fs::read_link("/proc/self/ns/pid").unwrap();
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", bystander.pid())).unwrap();
    let start = stat.rsplit_once(')').unwrap().1.split_whitespace().nth(19).unwrap().to_owned();
    let stale = [
        // Written before scopes were recorded: a PID that is not an agent for this vessel.
        None,
        // The PID was recycled: the process under it started at another time.
        Some(format!("session {} {} {}", bystander.pid(), namespace.display(), start.parse::<u64>().unwrap() + 1)),
        // The directory is from another PID namespace, where the PID meant another process.
        Some(format!("session {} pid:[1] {start}", bystander.pid())),
    ];
    for (n, scope) in stale.into_iter().enumerate() {
        let environment = provision(&*p, &format!("stale-{n}")).await;
        let dir = root.path().join(&environment.id);
        let agent = pid(&root, &environment.id);
        // The agent is gone but for its record, which now names the bystander.
        unsafe { libc::kill(-agent, libc::SIGKILL) };
        eventually("the agent stopped", || !alive(agent)).await;
        std::fs::write(dir.join("agent.pid"), bystander.pid().to_string()).unwrap();
        match scope {
            Some(scope) => std::fs::write(dir.join("agent.scope"), scope).unwrap(),
            None => std::fs::remove_file(dir.join("agent.scope")).unwrap(),
        }
        p.destroy(&environment.id, &credentials()).await.unwrap();
        assert!(!dir.exists());
        assert!(bystander.untouched(), "case {n}: destroy signalled a process outside the vessel");
    }
}

// A vessel's own processes are found by the identity of its agent, so destroy
// ends them even once the agent is gone, and still leaves a neighbour alone.
#[tokio::test]
async fn destroy_ends_what_a_dead_agent_left_and_only_that() {
    let root = Root::new();
    let p = provider(&root).await;
    let bystander = Bystander::new(root.0.path());
    let environment = provision(&*p, "orphaned").await;
    let agent = pid(&root, &environment.id);
    let marker = root.path().join(&environment.id).join("orphan.pid");
    // A grandchild in the agent's session that outlives the agent.
    let script = format!("sleep 300 & echo $! > {}", marker.display());
    let build = std::fs::read(agent::agent_binary()).unwrap();
    let open = || async {
        let stream = p.relay(&environment.id, &credentials()).await.map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        Ok(Box::new(stream) as _)
    };
    let client = drydock_agent::Client::connect_current(open, &Platform::current(), &build, Duration::from_secs(10)).await.unwrap();
    let _command = client.spawn(drydock_agent::Exec::new("sh", ["-c", &script])).await.unwrap();
    eventually("the command started", || std::fs::read_to_string(&marker).is_ok_and(|pid| !pid.trim().is_empty())).await;
    let orphan: i32 = std::fs::read_to_string(&marker).unwrap().trim().parse().unwrap();
    unsafe { libc::kill(agent, libc::SIGKILL) };
    eventually("the agent died", || !alive(agent)).await;
    assert!(alive(orphan));
    p.destroy(&environment.id, &credentials()).await.unwrap();
    eventually("the orphan ended", || !alive(orphan)).await;
    assert!(bystander.untouched());
}

// Where the host may make cgroups, a process that leaves the agent's session and
// process group is still in the vessel, and destroy ends it.
#[tokio::test]
async fn destroy_ends_a_process_that_escaped_the_session_when_cgroups_are_available() {
    let probe = std::fs::read_to_string("/proc/self/cgroup").unwrap();
    let own =
        std::path::Path::new("/sys/fs/cgroup").join(probe.lines().find_map(|l| l.strip_prefix("0::")).unwrap().trim_start_matches('/'));
    let trial = own.join("drydock-trial");
    if std::fs::create_dir(&trial).is_err() {
        eprintln!("skipped: no writable cgroup v2 tree here");
        return;
    }
    let usable = trial.join("cgroup.kill").exists();
    let _ = std::fs::remove_dir(&trial);
    if !usable {
        eprintln!("skipped: no cgroup.kill here");
        return;
    }
    let root = Root::new();
    let p = provider(&root).await;
    let environment = provision(&*p, "escapee").await;
    let marker = root.path().join(&environment.id).join("escapee.pid");
    let build = std::fs::read(agent::agent_binary()).unwrap();
    let open = || async {
        let stream = p.relay(&environment.id, &credentials()).await.map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        Ok(Box::new(stream) as _)
    };
    let client = drydock_agent::Client::connect_current(open, &Platform::current(), &build, Duration::from_secs(10)).await.unwrap();
    let script = format!("setsid sh -c 'echo $$ > {}; exec sleep 300' </dev/null >/dev/null 2>&1 &", marker.display());
    let _command = client.spawn(drydock_agent::Exec::new("sh", ["-c", &script])).await.unwrap();
    eventually("the command started", || std::fs::read_to_string(&marker).is_ok_and(|pid| !pid.trim().is_empty())).await;
    let escapee: i32 = std::fs::read_to_string(&marker).unwrap().trim().parse().unwrap();
    p.destroy(&environment.id, &credentials()).await.unwrap();
    eventually("the escapee ended", || !alive(escapee)).await;
}

// Destroy removes what the vessel left read-only, as the agent's artifact
// store leaves its unpacked trees.
#[tokio::test]
async fn destroy_removes_read_only_contents() {
    use std::os::unix::fs::PermissionsExt;
    let root = Root::new();
    let p = provider(&root).await;
    let environment = provision(&*p, "frozen").await;
    let tree = root.path().join(&environment.id).join("store/tree");
    std::fs::create_dir_all(tree.join("nested")).unwrap();
    std::fs::write(tree.join("nested/file"), "frozen").unwrap();
    for dir in [tree.join("nested"), tree.clone()] {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    }

    p.destroy(&environment.id, &credentials()).await.unwrap();
    assert!(!root.path().join(&environment.id).exists());
}

// Destroy follows no link out of the environment: a read-only directory a link
// names keeps its permissions and contents.
#[tokio::test]
async fn destroy_leaves_what_a_link_names_alone() {
    use std::os::unix::fs::PermissionsExt;
    let root = Root::new();
    let outside = tempfile::tempdir().unwrap();
    let kept = outside.path().join("kept");
    std::fs::create_dir(&kept).unwrap();
    std::fs::write(kept.join("file"), "kept").unwrap();
    std::fs::set_permissions(&kept, std::fs::Permissions::from_mode(0o555)).unwrap();
    let p = provider(&root).await;
    let environment = provision(&*p, "linked").await;
    std::os::unix::fs::symlink(&kept, root.path().join(&environment.id).join("link")).unwrap();

    p.destroy(&environment.id, &credentials()).await.unwrap();
    assert!(!root.path().join(&environment.id).exists());
    assert_eq!(std::fs::metadata(&kept).unwrap().permissions().mode() & 0o777, 0o555);
    assert_eq!(std::fs::read_to_string(kept.join("file")).unwrap(), "kept");
    std::fs::set_permissions(&kept, std::fs::Permissions::from_mode(0o755)).unwrap();
}

// Environments are their directories: a host that starts over finds them,
// agents still running, and can destroy them.
#[tokio::test]
async fn environments_survive_a_host_restart() {
    let root = Root::new();
    let first = provider(&root).await;
    let environment = provision(&*first, "durable").await;
    let agent_pid = pid(&root, &environment.id);
    drop(first);

    let second = provider(&root).await;
    let found = second.list(&credentials()).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(
        (found[0].id.as_str(), found[0].label.as_deref(), &found[0].state),
        (environment.id.as_str(), Some("durable"), &Observation::Running)
    );
    assert!(hello(&*second, &environment.id).await.unwrap().starts_with("HTTP/1.1 200"));
    let again = second.provision(request(&*second, "durable").await, &credentials()).await.unwrap();
    assert!(matches!(again, Provisioned::Existing(_)));
    second.destroy(&environment.id, &credentials()).await.unwrap();
    eventually("the agent stopped", || !alive(agent_pid)).await;
}

// An agent that died is reported stopped, not running; resume starts it again.
#[tokio::test]
async fn a_dead_agent_is_reported_stopped_and_restarted_on_resume() {
    let root = Root::new();
    let p = provider(&root).await;
    let suspend = p.operations().suspend_resume.unwrap();
    let environment = provision(&*p, "crashed").await;
    unsafe { libc::kill(-pid(&root, &environment.id), libc::SIGKILL) };
    eventually("the agent died", || !alive(pid(&root, &environment.id))).await;

    assert_eq!(p.inspect(&environment.id, &credentials()).await.unwrap().state, Observation::Stopped { cause: StopCause::GuestHalted });
    assert_eq!(p.list(&credentials()).await.unwrap()[0].state, Observation::Stopped { cause: StopCause::GuestHalted });
    let token = ResumeToken { token: Secret::new(format!("local:{}", environment.id)) };
    suspend.resume(&environment.id, token, &credentials()).await.unwrap();
    assert_eq!(p.inspect(&environment.id, &credentials()).await.unwrap().state, Observation::Running);
    assert!(hello(&*p, &environment.id).await.unwrap().starts_with("HTTP/1.1 200"));
}

// An id names a directory under the root and nothing else.
#[tokio::test]
async fn ids_cannot_leave_the_root() {
    let root = Root::new();
    let p = provider(&root).await;
    provision(&*p, "bystander").await;
    let outside = root.0.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    for id in ["../outside", "..", "local-../../x", "/tmp", ""] {
        assert!(matches!(p.inspect(id, &credentials()).await, Err(ProtocolError::NotFound { .. })), "{id}");
        assert!(matches!(p.reach(id, &credentials()).await, Err(ProtocolError::NotFound { .. })), "{id}");
        p.destroy(id, &credentials()).await.unwrap();
    }
    assert!(outside.exists());
    assert_eq!(p.list(&credentials()).await.unwrap().len(), 1);
}

// The local module runs the endpoint scenarios any provider does, with real
// agents as its vessels, through the server's own runtime and policy. Checks
// its declaration rules out are reported as not applicable instead of failing.
#[tokio::test]
async fn local_passes_conformance() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let vessels = dir.path().join("vessels");
    // An environment made by hand has no label and no recorded size: the nulls check reads it.
    let unlabelled = vessels.join("local-aaaaaaaaaaaa");
    std::fs::create_dir_all(&unlabelled).unwrap();
    std::fs::write(unlabelled.join("environment.json"), "{}").unwrap();

    let socket = dir.path().join("host.sock");
    let host = drydock_host::Host::new(drydock_host::local::registry());
    tokio::spawn({
        let socket = socket.clone();
        async move { host.serve_unix(socket, std::future::pending()).await.unwrap() }
    });
    let configuration: Configuration = serde_json::from_value(serde_json::json!({
        "providers": {"a": {"module": "local", "settings": {"root": vessels, "agent": agent::agent_binary()}}}
    }))
    .unwrap();
    // No credential is configured: a local provider has none to hold.
    let supervisor = drydock::Supervisor::new(dir.path().join("run"), Arc::new(drydock::credentials::BuiltinCredentials::default()));
    let mut managed = supervisor
        .start(drydock::HostSpec {
            name: "local".into(),
            connection: drydock::HostConnection::ExternalUnix { path: socket },
            configuration,
            credentials: Default::default(),
        })
        .await
        .unwrap();
    managed.ready(Duration::from_secs(10)).await.unwrap();
    let client = public_server::client(managed.client.clone(), dir.path().join("public.sock")).await;

    let size = Size { cpus: 1., memory_bytes: 1 << 30, disk_bytes: 1 << 30 };
    let prepared = managed
        .client
        .prepare(
            "a",
            &PrepareRequest {
                size: size.clone(),
                platform: None,
                route: None,
                image_pull: None,
                image_digest: format!("image@sha256:{}", "a".repeat(64)),
                tools_digest: "tools".into(),
            },
        )
        .await
        .unwrap();
    let options = Options {
        request: ProvisionRequest { label: "conformance".into(), prepared, size, egress: EgressRequest::Open, ssh_public_key: None },
        scenarios: conformance::Scenario::ALL
            .iter()
            .copied()
            .filter(|s| !matches!(s, conformance::Scenario::Authentication | conformance::Scenario::HostFixtures))
            .collect(),
        fixture_configuration: None,
        billing_sample_millis: 25,
        billing_settle_millis: 0,
        auth_audit: None,
        timeouts: Default::default(),
        echo_relay: false,
        reach_probe: None,
        egress_probe: None,
    };
    let report = conformance::run(&client, "a", &options).await;
    assert!(report.passed(), "{}", serde_json::to_string_pretty(&report).unwrap());
    let skipped: Vec<_> = report.not_applicable.iter().map(|check| check.name.as_str()).collect();
    for name in ["quota", "billing", "usage", "enforced_egress"] {
        assert!(skipped.contains(&name), "{name} is not applicable to local: {skipped:?}");
    }
    for name in ["reach_byte_stream", "suspend", "resume", "destroy_absent"] {
        assert!(report.checks.iter().any(|check| check.name == name && check.passed), "{name} ran: {report:?}");
    }
    // Only the hand-made environment remains, and no agent is left running.
    let remaining = managed.client.list("a").await.unwrap();
    assert_eq!(remaining.len(), 1, "{remaining:?}");
}

// A record that cannot be read is an error, not an absent environment: the
// directory beside it is never written over.
#[tokio::test]
async fn a_corrupt_record_is_not_overwritten_by_provision() {
    let root = Root::new();
    let p = provider(&root).await;
    let environment = provision(&*p, "precious").await;
    let record = root.path().join(&environment.id).join("environment.json");
    std::fs::write(&record, "not json").unwrap();
    let error = p.provision(request(&*p, "precious").await, &credentials()).await.unwrap_err();
    assert!(matches!(error, ProtocolError::Internal { .. }), "{error:?}");
    assert_eq!(std::fs::read_to_string(&record).unwrap(), "not json");
    assert!(alive(pid(&root, &environment.id)), "the running agent was left alone");
}

// A label whose id belongs to another label is refused, not given that environment.
#[tokio::test]
async fn a_colliding_label_is_refused() {
    let root = Root::new();
    let p = provider(&root).await;
    let environment = provision(&*p, "owner").await;
    let record = root.path().join(&environment.id).join("environment.json");
    // Another label's environment sits where "owner" hashes to.
    std::fs::write(&record, r#"{"label":"someone-else"}"#).unwrap();
    let error = p.provision(request(&*p, "owner").await, &credentials()).await.unwrap_err();
    assert!(matches!(error, ProtocolError::Refused { .. }), "{error:?}");
    assert_eq!(std::fs::read_to_string(&record).unwrap(), r#"{"label":"someone-else"}"#);
}

// If the recorded PID now belongs to another process, destroy leaves that process alone.
#[tokio::test]
async fn destroy_spares_a_process_that_recycled_the_agents_pid() {
    let root = Root::new();
    let p = provider(&root).await;
    let environment = provision(&*p, "recycled").await;
    let real = pid(&root, &environment.id);
    unsafe { libc::kill(-real, libc::SIGKILL) };
    eventually("the agent died", || !alive(real)).await;
    let mut bystander = std::process::Command::new("sleep").arg("300").spawn().unwrap();
    std::fs::write(root.path().join(&environment.id).join("agent.pid"), bystander.id().to_string()).unwrap();
    p.destroy(&environment.id, &credentials()).await.unwrap();
    assert!(alive(bystander.id() as i32), "an unrelated process was killed");
    bystander.kill().unwrap();
    bystander.wait().unwrap();
}

// While suspend stops the agent, the environment never reads as a crash.
#[tokio::test]
async fn suspending_never_looks_like_a_crash() {
    let root = Root::new();
    let p = provider(&root).await;
    let environment = provision(&*p, "quiet").await;
    let suspend = p.operations().suspend_resume.unwrap();
    let credentials = credentials();
    let (token, seen) = tokio::join!(suspend.suspend(&environment.id, &credentials), async {
        let mut seen = vec![];
        loop {
            let state = p.inspect(&environment.id, &credentials).await.unwrap().state;
            let stopped = matches!(state, Observation::Stopped { .. });
            seen.push(state);
            if stopped {
                return seen;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });
    token.unwrap();
    assert!(
        seen.iter().all(|state| matches!(state, Observation::Running | Observation::Stopped { cause: StopCause::SuspendedByRequest })),
        "{seen:?}"
    );
}

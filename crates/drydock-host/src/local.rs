//! Vessels as child processes on the host's own machine, for end-to-end trials
//! without a cloud provider or a container runtime. A test fixture, not a
//! sandbox: every vessel shares the host's filesystem, network and users.
//!
//! An environment is a directory `<root>/<id>/` holding a record of what was
//! asked for, its own copy of `drydock-agent` and the agent's socket at
//! `run/drydock/agent.sock`. The agent runs as a child in its own process
//! group, so destroying or suspending kills the agent and anything it started.
//! Nothing else is remembered in memory: environments are found by their
//! directories, so they survive a restart of the host.
use crate::module::*;
use async_trait::async_trait;
use drydock_protocol::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The longest Unix socket path every supported system accepts, with a margin.
const SOCKET_PATH_LIMIT: usize = 100;
const STARTUP: Duration = Duration::from_secs(30);
const TERMINATION_GRACE: Duration = Duration::from_secs(2);
const SOCKET: &str = "run/drydock/agent.sock";
const AGENT: &str = "opt/drydock/drydock-agent";
const RECORD: &str = "environment.json";
const PID: &str = "agent.pid";
const SUSPENDED: &str = "suspended";

pub fn registry() -> Registry {
    BTreeMap::from([("local".into(), Arc::new(LocalModule) as Arc<dyn Module>)])
}

pub struct LocalModule;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// Where environment directories live. Defaults to `local` under drydock's state directory.
    root: Option<PathBuf>,
    /// The `drydock-agent` to run, instead of the installed build.
    agent: Option<PathBuf>,
}

#[async_trait]
impl Module for LocalModule {
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    async fn configure(&self, name: &str, c: &ProviderConfiguration, _http: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
        let settings: Settings = serde_json::from_value(serde_json::to_value(&c.settings).expect("settings map"))
            .map_err(|_| refused("invalid local settings: expected optional string `root` and `agent` paths"))?;
        let root = match settings.root {
            Some(root) => root,
            None => default_root()?,
        };
        if !root.is_absolute() {
            return Err(refused("local root must be an absolute path"));
        }
        Ok(Arc::new(Local { name: name.to_owned(), root, agent: settings.agent, lifecycle: tokio::sync::Mutex::new(()) }))
    }
}

fn default_root() -> Result<PathBuf> {
    let paths = rigging_paths::PathPolicy::from_env("drydock", &rigging_process::ProcessEnvVars)
        .map_err(|e| refused(format!("no default local root ({e}); set `root`")))?;
    Ok(paths.state_dir.join("local"))
}

/// The agent build a local vessel runs: the host's own platform, found the way
/// drydock finds the build it pushes.
fn agent_build(configured: Option<&Path>) -> std::result::Result<PathBuf, String> {
    let platform = Platform::current();
    let variable = format!("DRYDOCK_AGENT_BIN_{}_{}", platform.os.to_ascii_uppercase(), platform.architecture.to_ascii_uppercase());
    let named = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    let path = configured.map(Path::to_path_buf).or_else(|| named(&variable)).or_else(|| named("DRYDOCK_AGENT_BIN")).or_else(|| {
        let sibling = std::env::current_exe().ok()?.with_file_name("drydock-agent");
        sibling.is_file().then_some(sibling)
    });
    match path {
        Some(path) if path.is_file() => Ok(path),
        Some(path) => Err(format!("agent build {} is not a file", path.display())),
        None => Err(format!("install drydock-agent beside drydock-host, or set {variable} or the `agent` setting")),
    }
}

/// What provisioning was asked for, kept beside the environment.
#[derive(Serialize, Deserialize)]
struct Record {
    /// Absent for an environment made by hand, which is listed unlabelled.
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    size: Option<Size>,
    #[serde(default)]
    platform: Option<Platform>,
}

struct Local {
    name: String,
    root: PathBuf,
    agent: Option<PathBuf>,
    /// Serializes changes, so a label is created once and suspend, resume and
    /// destroy never interleave. Reads do not take it.
    lifecycle: tokio::sync::Mutex<()>,
}

fn not_found() -> ProtocolError {
    ProtocolError::NotFound { reason: "unknown environment".into() }
}
fn unavailable(reason: impl Into<String>) -> ProtocolError {
    ProtocolError::Unavailable { reason: reason.into(), retry_after: None, provider_error: None }
}
fn internal(reason: impl Into<String>) -> ProtocolError {
    ProtocolError::Internal { reason: reason.into(), provider_error: String::new() }
}
/// An id is `local-` and 12 lowercase hex digits, never a path.
fn valid_id(id: &str) -> bool {
    id.strip_prefix("local-").is_some_and(|hex| hex.len() == 12 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}
fn environment_id(label: &str) -> String {
    format!("local-{}", &format!("{:x}", Sha256::digest(label.as_bytes()))[..12])
}
fn prepared_id(image_digest: &str, platform: &Platform) -> String {
    format!("prepared-{}", &format!("{:x}", Sha256::digest(format!("{image_digest}\n{platform}").as_bytes()))[..12])
}
fn resume_token(provider: &str, id: &str) -> ResumeToken {
    ResumeToken { token: Secret::new(format!("{provider}:{id}")) }
}

impl Local {
    fn dir(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }
    fn socket(&self, id: &str) -> PathBuf {
        self.dir(id).join(SOCKET)
    }
    async fn record(&self, id: &str) -> Result<Record> {
        if !valid_id(id) {
            return Err(not_found());
        }
        match tokio::fs::read(self.dir(id).join(RECORD)).await {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| internal(format!("environment record: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(not_found()),
            Err(e) => Err(unavailable(format!("environment record: {e}"))),
        }
    }
    async fn environment(&self, id: &str, record: Record) -> Environment {
        let dir = self.dir(id);
        let state = if running(&dir, &self.socket(id)).await {
            Observation::Running
        } else if dir.join(SUSPENDED).exists() {
            Observation::Stopped { cause: StopCause::SuspendedByRequest }
        } else {
            // The agent is gone and nobody asked: reported, not restarted.
            Observation::Stopped { cause: StopCause::GuestHalted }
        };
        Environment {
            id: id.to_owned(),
            label: record.label.clone(),
            provider: self.name.clone(),
            state,
            granted_size: record.size,
            egress: Enforcement::Advisory,
            platform: record.platform,
            egress_measured: false,
            egress_policy: None,
            timestamp: None,
        }
    }
    /// Environments found on disk, with the label each was created for.
    async fn found(&self) -> Result<Vec<(String, Record)>> {
        let mut entries = match tokio::fs::read_dir(&self.root).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(unavailable(format!("read local root: {e}"))),
        };
        let mut found = vec![];
        while let Some(entry) = entries.next_entry().await.map_err(|e| unavailable(format!("read local root: {e}")))? {
            let Some(id) = entry.file_name().to_str().filter(|id| valid_id(id)).map(str::to_owned) else { continue };
            if let Ok(record) = self.record(&id).await {
                found.push((id, record));
            }
        }
        found.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(found)
    }
    /// Start the environment's agent as a child in its own process group, and
    /// return once the agent answers hello.
    async fn start(&self, id: &str) -> Result<()> {
        let dir = self.dir(id);
        let socket = self.socket(id);
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(dir.join("agent.log"))
            .map_err(|e| unavailable(format!("open agent log: {e}")))?;
        let mut command = tokio::process::Command::new(dir.join(AGENT));
        command
            .arg("--socket")
            .arg(&socket)
            .current_dir(&dir)
            .stdin(Stdio::null())
            .stdout(log.try_clone().map_err(|e| unavailable(format!("open agent log: {e}")))?)
            .stderr(log)
            .kill_on_drop(false);
        // A session of its own: the agent starts commands in process groups of their own,
        // so only the session finds everything it started.
        // SAFETY: setsid is async-signal-safe and touches no shared state.
        unsafe {
            command.pre_exec(|| if libc::setsid() < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) });
        }
        let mut child = command.spawn().map_err(|e| unavailable(format!("start agent: {e}")))?;
        let pid = child.id().ok_or_else(|| unavailable("agent exited at once"))?;
        if let Err(e) = tokio::fs::write(dir.join(PID), pid.to_string()).await {
            // Unrecorded, the agent could never be stopped later.
            let _ = child.start_kill();
            return Err(unavailable(format!("record agent pid: {e}")));
        }
        // Reaps the agent when it exits, however that happens.
        let exit = tokio::spawn(async move { child.wait().await });
        let ready = tokio::time::timeout(STARTUP, async {
            loop {
                if hello(&socket).await {
                    return Ok(());
                }
                if exit.is_finished() {
                    return Err(unavailable(format!("agent exited during startup; see {}", dir.join("agent.log").display())));
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        let result = ready.unwrap_or_else(|_| Err(unavailable(format!("agent did not answer hello within {STARTUP:?}"))));
        if result.is_err() {
            let _ = stop(&dir, &socket).await;
        }
        result
    }
    async fn create(&self, request: ProvisionRequest) -> Result<Environment> {
        let id = environment_id(&request.label);
        let dir = self.dir(&id);
        if self.socket(&id).as_os_str().len() >= SOCKET_PATH_LIMIT {
            return Err(refused(format!(
                "the agent socket path {} is too long for a Unix socket; set a shorter local `root`",
                self.socket(&id).display()
            )));
        }
        let build = agent_build(self.agent.as_deref()).map_err(|reason| ProtocolError::Unavailable {
            reason: format!("no agent build: {reason}"),
            retry_after: None,
            provider_error: None,
        })?;
        let record = Record { label: Some(request.label), size: Some(request.size), platform: Some(request.prepared.platform) };
        let setup = || -> std::io::Result<()> {
            for path in [self.root.clone(), dir.clone(), dir.join("opt/drydock"), dir.join("run/drydock")] {
                std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path)?;
            }
            // The vessel's own copy: an agent upgrade replaces this file, never the installed build.
            std::fs::copy(&build, dir.join(AGENT))?;
            std::fs::set_permissions(dir.join(AGENT), std::fs::Permissions::from_mode(0o700))?;
            std::fs::write(dir.join(RECORD), serde_json::to_vec(&record).expect("record serializes"))
        };
        if let Err(e) = setup() {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(unavailable(format!("create environment directory: {e}")));
        }
        if let Err(error) = self.start(&id).await {
            let _ = tokio::fs::remove_dir_all(&dir).await;
            return Err(error);
        }
        Ok(self.environment(&id, record).await)
    }
}

/// Whether the environment's agent process is alive. An agent mid-upgrade has
/// no socket for a moment, so the process decides, not the socket.
async fn running(dir: &Path, socket: &Path) -> bool {
    match agent_pid(dir).await {
        Some(pid) => process(pid, socket) == Process::Agent,
        None => false,
    }
}
async fn agent_pid(dir: &Path) -> Option<i32> {
    tokio::fs::read_to_string(dir.join(PID)).await.ok()?.trim().parse().ok().filter(|pid| *pid > 1)
}
#[derive(PartialEq)]
enum Process {
    /// Not running; a zombie awaiting its parent counts as gone.
    Gone,
    /// Started for this socket.
    Agent,
    /// Another process that has taken over the PID.
    Other,
}
fn process(pid: i32, socket: &Path) -> Process {
    // SAFETY: signal 0 only checks that the process exists. EPERM (another user's
    // process has taken the PID) also reads as gone: it is not ours to signal.
    if unsafe { libc::kill(pid, 0) } != 0 {
        return Process::Gone;
    }
    match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(cmdline) if cmdline.is_empty() => Process::Gone,
        Ok(cmdline) if cmdline.split(|b| *b == 0).any(|arg| arg == socket.as_os_str().as_bytes()) => Process::Agent,
        Ok(_) => Process::Other,
        // Procfs is how the process is recognised; the module is ready only where it exists.
        Err(_) => Process::Gone,
    }
}
/// The processes still in the session the agent leads: the agent, the commands
/// it started and what those started, unless one made a session of its own.
fn session(leader: i32) -> Vec<i32> {
    let Ok(entries) = std::fs::read_dir("/proc") else { return vec![] };
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| {
            // The fields after the parenthesised name: state, parent, group, session.
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { return false };
            let fields: Vec<_> = stat.rsplit_once(')').map(|(_, rest)| rest.split_whitespace().collect()).unwrap_or_default();
            fields.get(3).and_then(|sid| sid.parse::<i32>().ok()) == Some(leader) && fields.first() != Some(&"Z")
        })
        .collect()
}
/// Kill the agent and everything in its session, and wait until they are gone.
async fn stop(dir: &Path, socket: &Path) -> Result<()> {
    let Some(pid) = agent_pid(dir).await else { return Ok(()) };
    if process(pid, socket) != Process::Other {
        let signal_all = |signal: i32| {
            // The group is the agent's only while the agent is: its PID may have been recycled
            // since. Session members are matched by session id, so they are always ours.
            if process(pid, socket) == Process::Agent {
                // SAFETY: signals the process group the agent leads.
                unsafe { libc::kill(-pid, signal) };
            }
            for member in session(pid) {
                // SAFETY: signals a process found in the agent's session; ESRCH when it has gone.
                unsafe { libc::kill(member, signal) };
            }
        };
        let gone = |limit: Duration| async move {
            let deadline = tokio::time::Instant::now() + limit;
            while (process(pid, socket) == Process::Agent || !session(pid).is_empty()) && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        signal_all(libc::SIGTERM);
        gone(TERMINATION_GRACE).await;
        signal_all(libc::SIGKILL);
        gone(Duration::from_secs(5)).await;
        if process(pid, socket) == Process::Agent || !session(pid).is_empty() {
            return Err(unavailable("the agent or its processes survived SIGKILL"));
        }
    }
    let _ = tokio::fs::remove_file(dir.join(PID)).await;
    let _ = tokio::fs::remove_file(socket).await;
    Ok(())
}
/// Whether the agent at `socket` answers `GET /hello`, which it serves over plain HTTP/1.1.
async fn hello(socket: &Path) -> bool {
    let attempt = async {
        let mut stream = tokio::net::UnixStream::connect(socket).await?;
        stream.write_all(b"GET /hello HTTP/1.1\r\nhost: agent\r\nconnection: close\r\n\r\n").await?;
        let mut reply = Vec::new();
        (&mut stream).take(65536).read_to_end(&mut reply).await?;
        Ok::<_, std::io::Error>(reply.starts_with(b"HTTP/1.1 200"))
    };
    matches!(tokio::time::timeout(Duration::from_secs(2), attempt).await, Ok(Ok(true)))
}

#[async_trait]
impl Provider for Local {
    fn operations(&self) -> Operations<'_> {
        Operations { suspend_resume: Some(self), ..Default::default() }
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            material_modes: vec![MaterialMode::Frozen, MaterialMode::Pushed, MaterialMode::Shared],
            checkout_strategies: vec![CheckoutStrategy::HostWorktree, CheckoutStrategy::HostClone, CheckoutStrategy::CloneInVessel],
            // Vessels share the host's filesystem; a client picks a directory per vessel below this one.
            workspace_root: self.root.to_string_lossy().into_owned(),
            suspend_resume: true,
            suspend_preserves_memory: Some(false),
            export: false,
            // No isolation: nothing is enforced, and deny-all cannot be represented.
            egress: EgressCapability { routes: vec![EgressRoute::Open], enforcement: Enforcement::Advisory },
            fallback_runner: false,
            bootstrap: BootstrapRoute::Upload,
            agent: true,
            platforms: vec![Platform::current()],
            // Nothing is pulled: the route only records which image was asked for.
            image_routes: vec![ImageRoute::RegistryPull {
                auth: RegistryAuthKind::Anonymous,
                registration: CredentialRegistration::NotRequired,
                digest_references: true,
                tools_layer: ToolsLayer::Provider,
            }],
            usage: false,
            quota: false,
        }
    }
    fn observation(&self) -> ObservationMode {
        ObservationMode::Poll { interval_ms: 1000 }
    }
    fn readiness(&self, _: &Credentials) -> Readiness {
        if !cfg!(target_os = "linux") {
            return Readiness::MissingTool { reason: "local vessels track their processes through procfs and need Linux".into() };
        }
        match agent_build(self.agent.as_deref()) {
            Ok(_) => Readiness::Ready,
            Err(reason) => Readiness::MissingTool { reason },
        }
    }
    async fn prepare(&self, r: PrepareRequest, _: &Credentials) -> Result<Prepared> {
        let platform = prepare_platform(&r)?;
        Ok(Prepared {
            provider: self.name.clone(),
            id: prepared_id(&r.image_digest, &platform),
            platform,
            image_digest: r.image_digest,
            tools_digest: r.tools_digest,
        })
    }
    async fn provision(&self, r: ProvisionRequest, _: &Credentials) -> Result<Provisioned> {
        let _changing = self.lifecycle.lock().await;
        let id = environment_id(&r.label);
        // Only an absent environment is created. An unreadable or corrupt record is an
        // error, and a directory another label hashed to is never written over.
        match self.record(&id).await {
            Ok(record) if record.label.as_deref() == Some(r.label.as_str()) => {
                return Ok(Provisioned::Existing(self.environment(&id, record).await));
            }
            Ok(_) => {
                return Err(refused(format!("label {:?} collides with the id of another environment; use a different label", r.label)));
            }
            Err(ProtocolError::NotFound { .. }) => {}
            Err(error) => return Err(error),
        }
        if r.prepared.provider != self.name
            || r.prepared.platform != Platform::current()
            || r.prepared.id != prepared_id(&r.prepared.image_digest, &r.prepared.platform)
        {
            return Err(refused("unknown prepared form"));
        }
        if let EgressRequest::DenyAll { .. } = r.egress {
            return Err(refused("local vessels share the host's network, so deny-all egress cannot be enforced; request open egress"));
        }
        self.create(r).await.map(Provisioned::Created)
    }
    async fn list(&self, _: &Credentials) -> Result<Vec<Environment>> {
        let mut environments = vec![];
        for (id, record) in self.found().await? {
            environments.push(self.environment(&id, record).await);
        }
        Ok(environments)
    }
    async fn inspect(&self, id: &str, _: &Credentials) -> Result<Environment> {
        let record = self.record(id).await?;
        Ok(self.environment(id, record).await)
    }
    async fn destroy(&self, id: &str, _: &Credentials) -> Result<()> {
        if !valid_id(id) {
            return Ok(());
        }
        let _changing = self.lifecycle.lock().await;
        let dir = self.dir(id);
        stop(&dir, &self.socket(id)).await?;
        match tokio::fs::remove_dir_all(&dir).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(unavailable(format!("remove environment directory: {e}"))),
        }
    }
    /// The agent's socket is on this machine: the host carries the connection.
    async fn reach(&self, id: &str, _: &Credentials) -> Result<Reach> {
        self.record(id).await?;
        Ok(Reach::relay(&self.name, id))
    }
    async fn relay(&self, id: &str, _: &Credentials) -> Result<ByteStream> {
        self.record(id).await?;
        let stream = tokio::net::UnixStream::connect(self.socket(id)).await.map_err(|e| unavailable(format!("agent socket: {e}")))?;
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl SuspendResume for Local {
    /// Stops the agent and its process group; the directory and its files stay.
    async fn suspend(&self, id: &str, _: &Credentials) -> Result<ResumeToken> {
        let _changing = self.lifecycle.lock().await;
        self.record(id).await?;
        let dir = self.dir(id);
        stop(&dir, &self.socket(id)).await?;
        tokio::fs::write(dir.join(SUSPENDED), b"").await.map_err(|e| unavailable(format!("record suspension: {e}")))?;
        Ok(resume_token(&self.name, id))
    }
    /// Starts the agent again, whether it was suspended or died.
    async fn resume(&self, id: &str, token: ResumeToken, _: &Credentials) -> Result<()> {
        let _changing = self.lifecycle.lock().await;
        self.record(id).await?;
        if token != resume_token(&self.name, id) {
            return Err(refused("invalid resume token for this provider/environment"));
        }
        let dir = self.dir(id);
        if !running(&dir, &self.socket(id)).await {
            self.start(id).await?;
        }
        match tokio::fs::remove_file(dir.join(SUSPENDED)).await {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(unavailable(format!("clear suspension: {e}"))),
            _ => Ok(()),
        }
    }
}

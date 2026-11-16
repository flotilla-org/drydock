//! Vessels as child processes on the host's own machine, for end-to-end trials
//! without a cloud provider or a container runtime. A test fixture, not a
//! sandbox: every vessel shares the host's filesystem, network and users.
//!
//! The vessels are host-direct (see [`kit::vessels`]). The agent runs as a child
//! in a cgroup of its own where the kernel allows one, else in a session of its
//! own (see `scope`). Sizes are recorded as asked for, and nothing holds a
//! vessel to them.
mod scope;
use crate::{
    kit::vessels::{self, AGENT, Found, Grant, LOG, Machine, RECORD, Record, SOCKET, SUSPENDED, Vessels, internal, unavailable},
    module::*,
};
use async_trait::async_trait;
use drydock_protocol::*;
use scope::Scope;
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

const TERMINATION_GRACE: Duration = Duration::from_secs(2);
const PID: &str = "agent.pid";
const SCOPE: &str = "agent.scope";

pub fn registry() -> Registry {
    BTreeMap::from([("local".into(), Arc::new(LocalModule) as Arc<dyn Module>)])
}

pub struct LocalModule;

#[derive(serde::Deserialize)]
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
            .map_err(|e| refused(format!("invalid local settings (optional `root` and `agent` paths): {e}")))?;
        let root = match settings.root {
            Some(root) => root,
            None => default_root()?,
        };
        if !root.is_absolute() {
            return Err(refused("local root must be an absolute path"));
        }
        Ok(Arc::new(Vessels::new(name, Local { root, agent: settings.agent })))
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
    match configured {
        Some(path) if path.is_file() => Ok(path.to_path_buf()),
        Some(path) => Err(format!("agent build {} is not a file", path.display())),
        None => drydock_provider::agent_build::agent_build(&Platform::current()).map_err(|e| format!("{e}, or the `agent` setting")),
    }
}

struct Local {
    root: PathBuf,
    agent: Option<PathBuf>,
}

impl Local {
    fn dir(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }
    fn socket(&self, id: &str) -> PathBuf {
        self.dir(id).join(SOCKET)
    }
    async fn record(&self, id: &str) -> Result<Record> {
        match tokio::fs::read(self.dir(id).join(RECORD)).await {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| internal(format!("environment record: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(vessels::not_found()),
            Err(e) => Err(unavailable(format!("environment record: {e}"))),
        }
    }
    async fn found(&self, id: String, record: Record) -> Found {
        let dir = self.dir(&id);
        let running = running(&dir, &self.socket(&id)).await;
        Found { suspended: dir.join(SUSPENDED).exists(), id, record, running, vendor: None }
    }
}

#[async_trait]
impl Machine for Local {
    fn prefix(&self) -> &'static str {
        "local"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            material_modes: vec![MaterialMode::Frozen, MaterialMode::Pushed, MaterialMode::Shared],
            checkout_strategies: vec![CheckoutStrategy::HostWorktree, CheckoutStrategy::HostClone, CheckoutStrategy::CloneInVessel],
            // Vessels are processes on this machine: its network is theirs.
            reach_ways: vec![ReachWay::HostNetwork, ReachWay::OutwardExposure],
            // Vessels share the host's filesystem; a client picks a directory per vessel below this one.
            ..vessels::capabilities(vec![Platform::current()], self.root.to_string_lossy().into_owned())
        }
    }
    fn ways_in(&self) -> Vec<WayIn> {
        vec![WayIn::Poll { interval_ms: 1000 }]
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
    fn platform(&self) -> Option<Platform> {
        Some(Platform::current())
    }
    async fn grant(&self, size: &Size, _: &Credentials) -> Result<(Size, Option<Grant>)> {
        Ok((size.clone(), None))
    }
    async fn vessels(&self, only: Option<&str>, _: &Credentials) -> Result<Vec<Found>> {
        if let Some(id) = only {
            let record = self.record(id).await?;
            return Ok(vec![self.found(id.to_owned(), record).await]);
        }
        let mut entries = match tokio::fs::read_dir(&self.root).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(unavailable(format!("read local root: {e}"))),
        };
        let mut found = vec![];
        while let Some(entry) = entries.next_entry().await.map_err(|e| unavailable(format!("read local root: {e}")))? {
            let Some(id) = entry.file_name().to_str().filter(|id| vessels::valid_id("local", id)).map(str::to_owned) else { continue };
            match self.record(&id).await {
                Ok(record) => found.push(self.found(id, record).await),
                Err(error) => tracing::warn!(%id, ?error, "skipping a local environment whose record cannot be read"),
            }
        }
        Ok(found)
    }
    async fn create(&self, id: &str, record: &Record, _: &Credentials) -> Result<()> {
        let dir = self.dir(id);
        vessels::check_socket(&dir, "root")?;
        let build = agent_build(self.agent.as_deref()).map_err(|reason| unavailable(format!("no agent build: {reason}")))?;
        let setup = || -> std::io::Result<()> {
            for path in [self.root.clone(), dir.clone(), dir.join("opt/drydock"), dir.join("run/drydock")] {
                std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path)?;
            }
            // The vessel's own copy: an agent upgrade replaces this file, never the installed build.
            // Written here while other threads may fork: `launch` execs it with
            // spawn_retrying_busy, which waits out the ETXTBSY that can cause.
            std::fs::copy(&build, dir.join(AGENT))?;
            std::fs::set_permissions(dir.join(AGENT), std::fs::Permissions::from_mode(0o700))?;
            // Whole or absent: a crash mid-write must not leave a record that never parses.
            let staged = dir.join("environment.json.new");
            std::fs::write(&staged, serde_json::to_vec(record).expect("record serializes"))?;
            std::fs::rename(staged, dir.join(RECORD))
        };
        if let Err(e) = setup() {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(unavailable(format!("create environment directory: {e}")));
        }
        Ok(())
    }
    /// The agent starts as a child, in a session of its own and, where the kernel
    /// gives one, a cgroup of its own.
    async fn launch(&self, id: &str, _: &Record, _: &Credentials) -> Result<()> {
        let dir = self.dir(id);
        let socket = self.socket(id);
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(dir.join(LOG))
            .map_err(|e| unavailable(format!("open agent log: {e}")))?;
        // A socket left by a dead agent would only be unlinked by the new one after a probe.
        let _ = tokio::fs::remove_file(&socket).await;
        let mut command = tokio::process::Command::new(dir.join(AGENT));
        command
            .arg("--socket")
            .arg(&socket)
            .current_dir(&dir)
            .stdin(Stdio::null())
            .stdout(log.try_clone().map_err(|e| unavailable(format!("open agent log: {e}")))?)
            .stderr(log)
            .kill_on_drop(false);
        // A session of its own, so that a signal for the agent's group never reaches the host's.
        // SAFETY: setsid is async-signal-safe and touches no shared state.
        unsafe {
            command.pre_exec(|| if libc::setsid() < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) });
        }
        // A cgroup of its own where the kernel gives one: the agent joins it before it runs
        // anything, so what it starts cannot be outside. The scope is recorded first, so that
        // a vessel whose start fails half way can still be ended.
        let cgroup = Scope::new_cgroup(id).map(Scope::Cgroup);
        if let Some(scope) = &cgroup {
            scope.record(&dir).map_err(|e| unavailable(format!("record agent scope: {e}")))?;
            if let Some(join) = scope.joiner() {
                // SAFETY: `joiner` makes only async-signal-safe calls.
                unsafe { command.pre_exec(join) };
            }
        }
        let mut child = match spawn_retrying_busy(&mut command).await {
            Ok(child) => child,
            Err(e) => {
                if cgroup.as_ref().is_some_and(Scope::release) {
                    let _ = std::fs::remove_file(dir.join(SCOPE));
                }
                return Err(unavailable(format!("start agent: {e}")));
            }
        };
        let pid = child.id().ok_or_else(|| unavailable("agent exited at once"))?;
        let recorded = match cgroup.or_else(|| Scope::session(pid as i32)) {
            Some(scope) => scope.record(&dir),
            None => Err(std::io::Error::other("cannot identify the agent process")),
        };
        if let Err(e) = recorded.and(std::fs::write(dir.join(PID), pid.to_string())) {
            // Unrecorded, the agent could never be stopped later.
            let _ = child.start_kill();
            return Err(unavailable(format!("record agent: {e}")));
        }
        // Reaps the agent when it exits, however that happens.
        tokio::spawn(async move { child.wait().await });
        Ok(())
    }
    async fn running(&self, id: &str, _: &Credentials) -> Result<bool> {
        Ok(running(&self.dir(id), &self.socket(id)).await)
    }
    async fn stop(&self, id: &str, _: &Credentials) -> Result<()> {
        stop(&self.dir(id), &self.socket(id)).await
    }
    async fn remove(&self, id: &str, _: &Credentials) -> Result<()> {
        let dir = self.dir(id);
        // The agent's artifact store keeps its unpacked trees read-only.
        let writable = dir.clone();
        tokio::task::spawn_blocking(move || owner_writable(&writable))
            .await
            .map_err(|e| internal(format!("make environment directory writable: {e}")))?;
        match tokio::fs::remove_dir_all(&dir).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(unavailable(format!("remove environment directory: {e}"))),
        }
    }
    async fn mark_suspended(&self, id: &str, suspended: bool, _: &Credentials) -> Result<()> {
        let marker = self.dir(id).join(SUSPENDED);
        if suspended {
            return tokio::fs::write(marker, b"").await.map_err(|e| unavailable(format!("record suspension: {e}")));
        }
        match tokio::fs::remove_file(marker).await {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(unavailable(format!("clear suspension: {e}"))),
            _ => Ok(()),
        }
    }
    async fn connect(&self, id: &str, _: &Credentials) -> Result<ByteStream> {
        let stream = tokio::net::UnixStream::connect(self.socket(id)).await.map_err(|e| unavailable(format!("agent socket: {e}")))?;
        Ok(Box::new(stream))
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
/// Kill the agent and everything in its scope, and wait until they are gone.
async fn stop(dir: &Path, socket: &Path) -> Result<()> {
    let Some(scope) = Scope::load(dir, socket) else {
        // Nothing the vessel can be told from other processes by: leave every process alone.
        if dir.join(PID).exists() || dir.join(SCOPE).exists() {
            tracing::warn!(dir = %dir.display(), "no usable record of the agent's scope: signalling nothing; its processes, if any, are left running");
        }
        for file in [PID, SCOPE] {
            let _ = tokio::fs::remove_file(dir.join(file)).await;
        }
        return Ok(());
    };
    let gone = |limit: Duration| {
        let scope = &scope;
        async move {
            let deadline = tokio::time::Instant::now() + limit;
            while !scope.gone() && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(scope::POLL).await;
            }
        }
    };
    scope.terminate();
    gone(TERMINATION_GRACE).await;
    scope.kill();
    gone(Duration::from_secs(5)).await;
    if !scope.gone() {
        return Err(unavailable("the agent or its processes survived SIGKILL"));
    }
    // The record stays until the cgroup is removed, so that a later stop finds it.
    let mut released = scope.release();
    for _ in 0..50 {
        if released {
            break;
        }
        tokio::time::sleep(scope::POLL).await;
        released = scope.release();
    }
    for file in [PID].into_iter().chain(released.then_some(SCOPE)) {
        let _ = tokio::fs::remove_file(dir.join(file)).await;
    }
    let _ = tokio::fs::remove_file(socket).await;
    Ok(())
}

/// Give the owner write access to every directory below `dir`, so that its
/// entries can be removed. Symbolic links are not followed. Best effort: a
/// directory it cannot change or read is logged and skipped, and removing the
/// tree reports what is in the way.
fn owner_writable(dir: &Path) {
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let metadata = match std::fs::symlink_metadata(&dir) {
            Ok(metadata) if metadata.is_dir() => metadata,
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                tracing::warn!(dir = %dir.display(), error = %e, "cannot read a local environment directory before removing it");
                continue;
            }
        };
        let mode = metadata.permissions().mode();
        if mode & 0o700 != 0o700
            && let Err(e) = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode | 0o700))
        {
            tracing::warn!(dir = %dir.display(), error = %e, "cannot make a local environment directory writable");
        }
        match std::fs::read_dir(&dir) {
            Ok(entries) => pending.extend(entries.flatten().map(|entry| entry.path())),
            Err(e) => tracing::warn!(dir = %dir.display(), error = %e, "cannot list a local environment directory before removing it"),
        }
    }
}

/// Spawns `command`, retrying while its executable is busy. A thread of this
/// process that forks while another holds a just-copied executable open for
/// writing passes the descriptor to its child until that child execs, and
/// exec then fails with ETXTBSY. That lasts milliseconds, so up to eight
/// retries of doubling delay (about 2.5 s in all) see it through.
async fn spawn_retrying_busy(command: &mut tokio::process::Command) -> std::io::Result<tokio::process::Child> {
    let mut delay = Duration::from_millis(10);
    for _ in 0..8 {
        match command.spawn() {
            Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) => {
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
            result => return result,
        }
    }
    command.spawn()
}

#[cfg(test)]
mod tests {
    use super::*;
    // An executable held open for writing cannot be spawned (ETXTBSY);
    // spawn_retrying_busy retries until the writer closes it, then starts it.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn spawn_waits_out_a_busy_executable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("busy");
        let mut writer = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o755).open(&path).unwrap();
        std::io::Write::write_all(&mut writer, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut command = tokio::process::Command::new(&path);
        let busy = command.spawn().map(drop).unwrap_err();
        assert_eq!(busy.raw_os_error(), Some(libc::ETXTBSY));
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(writer);
        });
        let status = spawn_retrying_busy(&mut command).await.unwrap().wait().await.unwrap();
        assert!(status.success());
        release.await.unwrap();
    }
}

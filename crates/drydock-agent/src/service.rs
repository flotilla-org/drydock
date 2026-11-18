//! Long-lived services, kept under names the client chooses. A service writes
//! its output straight to a file and is found again through a record on
//! disk, so it never depends on the agent process that started it.
use crate::{AgentError, ErrorKind, ExitStatus, Service, ServiceInfo, ServiceOutput, ServiceState, events::Event};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    io,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

/// A log is rotated once it passes this size, keeping one previous file.
pub(crate) const LOG_LIMIT: u64 = 64 * 1024 * 1024;
const ROTATE_EVERY: Duration = Duration::from_secs(1);
pub(crate) const DEFAULT_GRACE: Duration = Duration::from_secs(10);
pub(crate) const MAX_GRACE: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(20);

#[derive(Serialize, Deserialize)]
struct Record {
    service: Service,
    pid: u32,
    /// The process's start time, which a reused PID does not share.
    started: u64,
}
/// The PID that exited, and its status when known.
type Exit = (u32, Option<ExitStatus>);
/// A running process as the kernel reports it.
struct Live {
    started: u64,
    group: i32,
}

pub(crate) struct Services {
    dir: PathBuf,
    events: Arc<crate::events::Events>,
    /// Starts, stops and rotations of one name never interleave.
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Exits this agent process saw, by name, with the PID that exited. The
    /// status is known only for services this process started.
    exits: Arc<Mutex<HashMap<String, Exit>>>,
}
impl Services {
    pub(crate) fn new(dir: PathBuf, events: Arc<crate::events::Events>) -> Self {
        Self { dir, events, locks: Mutex::default(), exits: Arc::default() }
    }
    fn lock(&self, name: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.locks.lock().unwrap().entry(name.to_owned()).or_default().clone()
    }
    fn record_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.json"))
    }
    fn log_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.log"))
    }
    fn record(&self, name: &str) -> Result<Option<Record>, AgentError> {
        match std::fs::read(self.record_path(name)) {
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| AgentError::io("service.record", name, crate::invalid(e))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(AgentError::io("service.record", name, error)),
        }
    }
    fn running(record: &Record) -> bool {
        live(record.pid).is_some_and(|live| live.started == record.started)
    }
    fn info(&self, name: &str, record: &Record) -> ServiceInfo {
        let state = match self.exits.lock().unwrap().get(name) {
            Some((pid, status)) if *pid == record.pid => ServiceState::Exited { status: *status },
            _ if Self::running(record) => ServiceState::Running,
            _ => ServiceState::Exited { status: None },
        };
        let log = (record.service.output == ServiceOutput::File).then(|| self.log_path(name));
        ServiceInfo { name: name.to_owned(), pid: record.pid, service: record.service.clone(), state, log }
    }
    pub(crate) fn get(&self, name: &str) -> Result<ServiceInfo, AgentError> {
        check_name(name)?;
        let record =
            self.record(name)?.ok_or_else(|| AgentError::new("service.find", name, ErrorKind::NotFound, "no service with this name"))?;
        Ok(self.info(name, &record))
    }
    pub(crate) fn list(&self) -> Result<Vec<ServiceInfo>, AgentError> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(AgentError::io("service.list", self.dir.display(), error)),
        };
        let mut names: Vec<String> = entries
            .filter_map(|entry| entry.ok()?.file_name().to_str()?.strip_suffix(".json").map(str::to_owned))
            .filter(|name| check_name(name).is_ok())
            .collect();
        names.sort();
        Ok(names.iter().filter_map(|name| Some(self.info(name, &self.record(name).ok()??))).collect())
    }
    /// Start the service unless it already runs from the same request.
    /// Returns its status and whether it was started.
    pub(crate) async fn put(
        &self,
        name: &str,
        service: Service,
        environment: BTreeMap<String, String>,
    ) -> Result<(ServiceInfo, bool), AgentError> {
        const OP: &str = "service.start";
        check_name(name)?;
        let lock = self.lock(name);
        let _held = lock.lock().await;
        if let Some(record) = self.record(name)?
            && self.info(name, &record).state == ServiceState::Running
        {
            if record.service != service {
                return Err(AgentError::new(OP, name, ErrorKind::Conflict, "a service with this name runs from a different request"));
            }
            return Ok((self.info(name, &record), false));
        }
        if service.environment.iter().any(|(k, v)| k.is_empty() || k.contains(['=', '\0']) || v.contains('\0')) {
            return Err(AgentError::new("service.environment", name, ErrorKind::InvalidInput, "invalid service environment"));
        }
        if let Some(cwd) = &service.cwd
            && !std::fs::metadata(cwd).map_err(|e| AgentError::io("service.cwd", cwd.display(), e))?.is_dir()
        {
            return Err(AgentError::new("service.cwd", cwd.display(), ErrorKind::NotADirectory, "working directory is not a directory"));
        }
        crate::socket::private_directory(&self.dir).map_err(|e| AgentError::io(OP, name, e))?;
        let (stdout, stderr) = match service.output {
            ServiceOutput::File => {
                let log = self.log_path(name);
                match std::fs::rename(&log, rotated(&log)) {
                    Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(AgentError::io(OP, log.display(), error)),
                    _ => {}
                }
                let file = std::fs::OpenOptions::new()
                    .append(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&log)
                    .map_err(|e| AgentError::io(OP, log.display(), e))?;
                let copy = file.try_clone().map_err(|e| AgentError::io(OP, log.display(), e))?;
                (Stdio::from(file), Stdio::from(copy))
            }
            ServiceOutput::Discard => (Stdio::null(), Stdio::null()),
        };
        let mut command = tokio::process::Command::new(&service.program);
        command.args(&service.args).envs(environment).envs(&service.environment).stdin(Stdio::null()).stdout(stdout).stderr(stderr);
        if let Some(cwd) = &service.cwd {
            command.current_dir(cwd);
        }
        command.process_group(0).kill_on_drop(false);
        let mut child = command.spawn().map_err(|e| AgentError::io(OP, &service.program, e))?;
        let pid = child.id().unwrap_or_default();
        let record = Record { service, pid, started: live(pid).map_or(0, |live| live.started) };
        let written = serde_json::to_vec(&record)
            .map_err(io::Error::other)
            .and_then(|bytes| crate::durable::replace(&self.record_path(name), &bytes, 0o600));
        if let Err(error) = written {
            // Unrecorded, it could never be found or stopped again.
            let _ = rustix::process::Pid::from_raw(pid as i32)
                .map(|group| rustix::process::kill_process_group(group, rustix::process::Signal::KILL));
            return Err(AgentError::io(OP, name, error));
        }
        self.exits.lock().unwrap().remove(name);
        let (exits, events, name_owned) = (self.exits.clone(), self.events.clone(), name.to_owned());
        tokio::spawn(async move {
            let status = match child.wait().await {
                Ok(status) => {
                    use std::os::unix::process::ExitStatusExt;
                    Some(ExitStatus { code: status.code(), signal: status.signal(), timed_out: false })
                }
                Err(error) => {
                    tracing::warn!(%error, service = %name_owned, "service wait failed");
                    None
                }
            };
            exits.lock().unwrap().insert(name_owned.clone(), (pid, status));
            events.push(Event::ServiceExited { name: name_owned, pid, status });
        });
        Ok((self.info(name, &record), true))
    }
    /// Stop the service's process group, SIGTERM then SIGKILL after `grace`,
    /// and forget its record. The log stays.
    pub(crate) async fn remove(&self, name: &str, grace: Duration) -> Result<ServiceInfo, AgentError> {
        check_name(name)?;
        let lock = self.lock(name);
        let _held = lock.lock().await;
        let record =
            self.record(name)?.ok_or_else(|| AgentError::new("service.find", name, ErrorKind::NotFound, "no service with this name"))?;
        for (signal, wait) in [(rustix::process::Signal::TERM, grace), (rustix::process::Signal::KILL, MAX_GRACE)] {
            let deadline = tokio::time::Instant::now() + wait;
            if !self.signal(&record, signal) {
                break;
            }
            while self.info(name, &record).state == ServiceState::Running {
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(POLL).await;
            }
        }
        let info = self.info(name, &record);
        if info.state == ServiceState::Running {
            return Err(AgentError::new("service.stop", name, ErrorKind::TimedOut, "the service outlived SIGKILL"));
        }
        std::fs::remove_file(self.record_path(name)).map_err(|e| AgentError::io("service.stop", name, e))?;
        Ok(info)
    }
    /// Signal the group the service leads, checked just before, so a reused
    /// PID is never signalled. False when it no longer runs.
    fn signal(&self, record: &Record, signal: rustix::process::Signal) -> bool {
        let Some(live) = live(record.pid).filter(|live| live.started == record.started && live.group == record.pid as i32) else {
            return false;
        };
        let Some(group) = rustix::process::Pid::from_raw(live.group) else { return false };
        rustix::process::kill_process_group(group, signal).is_ok()
    }
    /// Watch the services an earlier agent process started, so their exits
    /// are still announced, without a status.
    pub(crate) fn adopt(&self) {
        let Ok(services) = self.list() else { return };
        for info in services.into_iter().filter(|info| info.state == ServiceState::Running) {
            #[cfg(target_os = "linux")]
            {
                let Some(pid) = rustix::process::Pid::from_raw(info.pid as i32) else { continue };
                let Ok(pidfd) = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) else { continue };
                // The PID might have been reused between the check and the open.
                if !self.record(&info.name).ok().flatten().is_some_and(|record| Self::running(&record)) {
                    continue;
                }
                #[allow(deprecated)]
                let Ok(pidfd) = tokio::io::unix::AsyncFd::with_interest(pidfd, tokio::io::Interest::READABLE) else { continue };
                let (exits, events) = (self.exits.clone(), self.events.clone());
                tokio::spawn(async move {
                    let _ = pidfd.readable().await;
                    exits.lock().unwrap().insert(info.name.clone(), (info.pid, None));
                    events.push(Event::ServiceExited { name: info.name, pid: info.pid, status: None });
                });
            }
            #[cfg(not(target_os = "linux"))]
            let _ = info;
        }
    }
    /// Rotate every log past [`LOG_LIMIT`], for as long as the agent runs.
    pub(crate) async fn rotate_logs(self: Arc<Self>) {
        loop {
            tokio::time::sleep(ROTATE_EVERY).await;
            for info in self.list().unwrap_or_default() {
                let Some(log) = info.log else { continue };
                if std::fs::metadata(&log).is_ok_and(|m| m.len() > LOG_LIMIT) {
                    let lock = self.lock(&info.name);
                    let _held = lock.lock().await;
                    if let Err(error) = rotate(&log) {
                        tracing::warn!(%error, service = %info.name, "service log rotation failed");
                    }
                }
            }
        }
    }
}
fn rotated(log: &Path) -> PathBuf {
    let mut name = log.as_os_str().to_owned();
    name.push(".1");
    name.into()
}
/// The service holds the log open for appending, so it is copied aside and
/// emptied in place; bytes written between the two are lost.
fn rotate(log: &Path) -> io::Result<()> {
    let previous = rotated(log);
    let parent = log.parent().unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    let mut source = std::fs::OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW).open(log)?;
    io::copy(&mut source, temporary.as_file_mut())?;
    temporary.persist(&previous).map_err(|e| e.error)?;
    source.set_len(0)
}
fn check_name(name: &str) -> Result<(), AgentError> {
    let valid = (1..=64).contains(&name.len())
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    if !valid {
        return Err(AgentError::new(
            "service.name",
            name,
            ErrorKind::InvalidInput,
            "a service name is 1 to 64 letters, digits, '_', '.' or '-', starting with a letter or digit",
        ));
    }
    Ok(())
}
/// A process that has not exited, with its start time and process group.
#[cfg(target_os = "linux")]
fn live(pid: u32) -> Option<Live> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name may hold spaces and parentheses; it ends at the last ')'.
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    if matches!(fields.first(), Some(&"Z" | &"X" | &"x")) {
        return None;
    }
    Some(Live { group: fields.get(2)?.parse().ok()?, started: fields.get(19)?.parse().ok()? })
}
#[cfg(target_os = "macos")]
fn live(pid: u32) -> Option<Live> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: the buffer is one proc_bsdinfo of `size` bytes.
    let read = unsafe { libc::proc_pidinfo(pid as libc::c_int, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
    if read != size || info.pbi_status == libc::SZOMB {
        return None;
    }
    Some(Live { group: info.pbi_pgid as i32, started: info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec })
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn live(_: u32) -> Option<Live> {
    None
}

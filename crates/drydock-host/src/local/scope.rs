//! Which processes belong to a vessel, and how to end them.
//!
//! A vessel is the agent and everything it started. Where the kernel can say
//! so, it does: the agent is born into a cgroup v2 cgroup of its own, every
//! process it starts stays in it, and `cgroup.kill` ends them all at once,
//! touching nothing outside. Otherwise (no writable cgroup tree, as in most
//! containers) the vessel is the session the agent leads, and a process is
//! only signalled once it is known to belong to that session of that agent:
//! a PID read from a file is not evidence, since PIDs are recycled, and a
//! file left by an earlier life of the machine names someone else's processes.
//! Even so, a session's members are listed and then signalled, and a listed
//! process can exit and its PID be reused in between; the cgroup's kill has no
//! such window, which is why it is preferred.
use super::{PID, SCOPE};
use std::{
    ffi::CString,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::Duration,
};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The processes of one vessel.
#[derive(Debug, PartialEq)]
pub(super) enum Scope {
    /// A cgroup of the vessel's own.
    Cgroup(PathBuf),
    /// The session led by the agent with this PID, in this PID namespace,
    /// which started at this tick: the agent's identity, since a PID alone is not.
    Session { pid: i32, namespace: String, start: u64 },
}

impl Scope {
    /// A cgroup for the vessel `id`, made beside the host's own, when this
    /// process may create one and the kernel can kill it whole.
    pub(super) fn new_cgroup(id: &str) -> Option<PathBuf> {
        let own = std::fs::read_to_string("/proc/self/cgroup").ok()?;
        let relative = own.lines().find_map(|line| line.strip_prefix("0::"))?;
        let path = Path::new(CGROUP_ROOT).join(relative.trim_start_matches('/')).join(format!("drydock-{id}"));
        match std::fs::create_dir(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return None,
        }
        if path.join("cgroup.kill").exists() {
            Some(path)
        } else {
            let _ = std::fs::remove_dir(&path);
            None
        }
    }
    /// The session `pid` leads, as `pid` is now. Call right after starting it.
    pub(super) fn session(pid: i32) -> Option<Scope> {
        Some(Scope::Session { pid, namespace: namespace()?, start: start_time(pid)? })
    }
    /// What the vessel's directory records. A directory written before scopes
    /// were recorded has only the agent's PID: that counts when the process
    /// is the agent started for `socket`, and names nothing otherwise.
    pub(super) fn load(dir: &Path, socket: &Path) -> Option<Scope> {
        if let Ok(text) = std::fs::read_to_string(dir.join(SCOPE)) {
            if let Some(path) = text.strip_prefix("cgroup ") {
                // A file is not evidence: only the cgroup this module makes for this vessel is
                // ever written to or removed.
                let path = PathBuf::from(path.trim_end());
                let ours = path.starts_with(CGROUP_ROOT)
                    && path.components().all(|part| !matches!(part, std::path::Component::ParentDir))
                    && path.file_name().and_then(|name| name.to_str()) == Some(&format!("drydock-{}", dir.file_name()?.to_str()?));
                return ours.then_some(Scope::Cgroup(path));
            }
            let fields: Vec<_> = text.split_whitespace().collect();
            return match fields[..] {
                ["session", pid, namespace, start] => Some(Scope::Session {
                    pid: pid.parse().ok().filter(|pid| *pid > 1)?,
                    namespace: namespace.into(),
                    start: start.parse().ok()?,
                }),
                _ => None,
            };
        }
        let pid: i32 = std::fs::read_to_string(dir.join(PID)).ok()?.trim().parse().ok().filter(|pid| *pid > 1)?;
        if super::process(pid, socket) == super::Process::Agent { Scope::session(pid) } else { None }
    }
    pub(super) fn record(&self, dir: &Path) -> std::io::Result<()> {
        let text = match self {
            Scope::Cgroup(path) => format!("cgroup {}", path.display()),
            Scope::Session { pid, namespace, start } => format!("session {pid} {namespace} {start}"),
        };
        std::fs::write(dir.join(SCOPE), text)
    }
    /// The processes in the vessel now.
    pub(super) fn members(&self) -> Vec<i32> {
        match self {
            Scope::Cgroup(path) => std::fs::read_to_string(path.join("cgroup.procs"))
                .map(|procs| procs.lines().filter_map(|pid| pid.trim().parse().ok()).collect())
                .unwrap_or_default(),
            Scope::Session { pid, namespace, start } => {
                // Another machine life, or another process under the PID: the session is not
                // the agent's and nothing in it is ours.
                if Some(namespace.as_str()) != self::namespace().as_deref() {
                    return vec![];
                }
                if start_time(*pid).is_some_and(|now| now != *start) {
                    return vec![];
                }
                // The session id stays taken while any member lives, so with the agent gone
                // the session's remaining members are still the agent's. If its PID is already
                // taken by another process the session is empty; nothing survives to be found.
                session_members(*pid)
            }
        }
    }
    /// Ask the vessel's processes to exit. A cgroup's own processes only: those moved into a
    /// child cgroup get no graceful stop, only the kill.
    pub(super) fn terminate(&self) {
        for member in self.members() {
            // SAFETY: signals a process found in the vessel; ESRCH when it has gone.
            unsafe { libc::kill(member, libc::SIGTERM) };
        }
    }
    /// End the vessel's processes, those started meanwhile included.
    pub(super) fn kill(&self) {
        match self {
            Scope::Cgroup(path) => {
                let _ = std::fs::write(path.join("cgroup.kill"), "1");
            }
            Scope::Session { .. } => {
                for member in self.members() {
                    // SAFETY: as in `terminate`.
                    unsafe { libc::kill(member, libc::SIGKILL) };
                }
            }
        }
    }
    /// Whether no live process is left. A zombie awaiting a parent that never reaps it is not live.
    pub(super) fn gone(&self) -> bool {
        match self {
            Scope::Cgroup(path) => match std::fs::read_to_string(path.join("cgroup.events")) {
                Ok(events) => events.lines().any(|line| line == "populated 0"),
                Err(_) => !path.exists(),
            },
            Scope::Session { .. } => self.members().is_empty(),
        }
    }
    /// Remove what held the vessel together, once it is gone. Whether it is removed: a cgroup
    /// can refuse for a moment after its last process exits, until the zombie is reaped.
    pub(super) fn release(&self) -> bool {
        match self {
            Scope::Cgroup(path) => std::fs::remove_dir(path).is_ok() || !path.exists(),
            Scope::Session { .. } => true,
        }
    }
    /// A cgroup for the agent to join before it executes anything, so that nothing it
    /// starts can be outside. Called between fork and exec: only async-signal-safe calls.
    pub(super) fn joiner(&self) -> Option<impl Fn() -> std::io::Result<()> + Send + Sync + 'static> {
        let Scope::Cgroup(path) = self else { return None };
        let procs = CString::new(path.join("cgroup.procs").as_os_str().as_bytes()).ok()?;
        Some(move || {
            // SAFETY: open, write and close take no locks and allocate nothing; "0" names the caller.
            unsafe {
                let fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let written = libc::write(fd, b"0".as_ptr().cast(), 1);
                let error = std::io::Error::last_os_error();
                libc::close(fd);
                if written == 1 { Ok(()) } else { Err(error) }
            }
        })
    }
}

/// How long to wait between looks at a vessel that is ending.
pub(super) const POLL: Duration = Duration::from_millis(20);

/// The PID namespace of this process, which says whether PIDs mean the same as when they were recorded.
fn namespace() -> Option<String> {
    Some(std::fs::read_link("/proc/self/ns/pid").ok()?.to_string_lossy().into_owned())
}
/// The fields of `/proc/<pid>/stat` after the parenthesised name: state, parent, group, session, ...
fn stat(pid: i32) -> Option<Vec<String>> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    Some(stat.rsplit_once(')')?.1.split_whitespace().map(str::to_owned).collect())
}
/// When the process started, in clock ticks since boot: fixed for a process's life and
/// different for a process that takes over its PID.
fn start_time(pid: i32) -> Option<u64> {
    stat(pid)?.get(19)?.parse().ok()
}
/// The live processes whose session is `leader`'s.
fn session_members(leader: i32) -> Vec<i32> {
    let Ok(entries) = std::fs::read_dir("/proc") else { return vec![] };
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| {
            stat(*pid).is_some_and(|fields| {
                fields.get(3).and_then(|sid| sid.parse::<i32>().ok()) == Some(leader) && fields.first().map(String::as_str) != Some("Z")
            })
        })
        .collect()
}

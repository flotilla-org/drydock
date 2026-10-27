use drydock_agent::Agent;
use drydock_transport::{Limits, Transport, native::UnixConnections};
use std::{io, path::PathBuf, sync::Arc};
use tokio::net::UnixListener;
mod supervisor;
const HOST_SOCKET: &str = "/run/drydock/host.sock";
#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();
    if std::process::id() == 1 {
        return Err(io::Error::other("drydock-agent must not be PID 1"));
    }
    reap_inherited_children();
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|a| a == "--supervise") {
        return supervisor::start(&args[1..]);
    }
    if args.first().is_some_and(|a| a == "--supervisor") {
        return supervisor::run(&args[1..]).await;
    }
    let mut socket = PathBuf::from("/run/drydock/agent.sock");
    let mut vsock = None;
    let mut store = None;
    let mut options = args.iter();
    while let Some(flag) = options.next() {
        match flag.to_str() {
            Some("--socket") => socket = options.next().ok_or_else(|| io::Error::other("--socket requires a path"))?.into(),
            Some("--store") => store = Some(PathBuf::from(options.next().ok_or_else(|| io::Error::other("--store requires a path"))?)),
            Some("--vsock-port") => {
                vsock = Some(
                    options
                        .next()
                        .and_then(|s| s.to_str())
                        .and_then(|s| s.parse::<u32>().ok())
                        .ok_or_else(|| io::Error::other("--vsock-port requires a port"))?,
                )
            }
            _ => return Err(io::Error::other("usage: drydock-agent [--socket PATH] [--vsock-port PORT] [--store DIR]")),
        }
    }
    drydock_agent::socket::private_directory(
        socket
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("socket {} requires a run directory", socket.display())))?,
    )?;
    if let Ok(metadata) = std::fs::symlink_metadata(&socket) {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, format!("agent socket {} is occupied", socket.display())));
        }
        match tokio::time::timeout(std::time::Duration::from_millis(100), tokio::net::UnixStream::connect(&socket)).await {
            Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionRefused => std::fs::remove_file(&socket)
                .map_err(|e| io::Error::new(e.kind(), format!("remove stale socket {}: {e}", socket.display())))?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("agent socket {} already in use or inaccessible", socket.display()),
                ));
            }
        }
    }
    let listener =
        UnixListener::bind(&socket).map_err(|e| io::Error::new(e.kind(), format!("bind agent socket {}: {e}", socket.display())))?;
    drydock_agent::socket::protect(&socket)?;
    let transport = Transport::native(Arc::new(UnixConnections::new(listener, HOST_SOCKET)), Limits::default())?;
    let current = std::env::current_exe()?;
    let fingerprint = drydock_agent::fingerprint()?;
    let executable = drydock_agent::upgrade::startup(&current)
        .map_err(|e| io::Error::new(e.kind(), format!("recover agent {}: {e}", current.display())))?;
    let mut agent = Agent::new(transport, fingerprint, executable.clone());
    if let Some(store) = store {
        agent = agent.with_store(store);
    }
    #[cfg(target_os = "linux")]
    if let Some(port) = vsock {
        let listener = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, port))?;
        let peer = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_HOST, port);
        let transport = Transport::native(Arc::new(drydock_transport::native::VsockConnections::new(listener, peer)), Limits::default())?;
        agent.add_transport(transport);
    }
    #[cfg(not(target_os = "linux"))]
    if vsock.is_some() {
        return Err(io::Error::other("vsock requires Linux"));
    }
    let path = agent.run().await?;
    let _ = std::fs::remove_file(socket);
    let error = replace_image(&path, &args);
    if drydock_agent::upgrade::rollback(&executable)? {
        return Err(replace_image(&executable, &args));
    }
    Err(error)
}

// Re-exec keeps the PID and its children, but loses Tokio's old Child handles.
// Reap only the children inherited at startup, so this cannot steal statuses
// from commands launched by the new runtime. Provider init owns crash orphans.
#[cfg(target_os = "linux")]
fn reap_inherited_children() {
    let mut children = inherited_children(std::path::Path::new("/proc/self/task"));
    if !children.is_empty() {
        tokio::spawn(async move {
            while !children.is_empty() {
                children.retain(|pid| {
                    rustix::process::Pid::from_raw(*pid)
                        .is_some_and(|pid| matches!(rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG), Ok(None)))
                });
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        });
    }
}
#[cfg(not(target_os = "linux"))]
fn reap_inherited_children() {}

// execv deliberately does not apply execvp's ENOEXEC shell-script fallback.
// A rejected agent image must return here so the previous binary can recover.
fn replace_image(path: &std::path::Path, args: &[std::ffi::OsString]) -> io::Error {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let strings: Result<Vec<_>, _> =
        std::iter::once(path.as_os_str()).chain(args.iter().map(|arg| arg.as_os_str())).map(|arg| CString::new(arg.as_bytes())).collect();
    let strings = match strings {
        Ok(strings) => strings,
        Err(error) => return io::Error::new(io::ErrorKind::InvalidInput, error),
    };
    let mut pointers: Vec<_> = strings.iter().map(|arg| arg.as_ptr()).collect();
    pointers.push(std::ptr::null());
    // SAFETY: all C strings and the null-terminated argv remain live for execv.
    unsafe {
        libc::execv(strings[0].as_ptr(), pointers.as_ptr());
    }
    io::Error::last_os_error()
}

#[cfg(target_os = "linux")]
fn inherited_children(root: &std::path::Path) -> Vec<libc::pid_t> {
    let mut children = std::collections::HashSet::new();
    if let Ok(tasks) = std::fs::read_dir(root) {
        for task in tasks.flatten() {
            if let Ok(pids) = std::fs::read_to_string(task.path().join("children")) {
                children.extend(pids.split_whitespace().filter_map(|pid| pid.parse::<libc::pid_t>().ok()));
            }
        }
    }
    children.into_iter().collect()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    // Fake procfs boundary: child lists can belong to any thread, overlap, or
    // disappear while scanning. Missing CONFIG_PROC_CHILDREN must not bar startup.
    #[test]
    fn proc_children_scan_all_threads_and_tolerate_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        for (thread, pids) in [("main", "11 22"), ("worker", "22 33"), ("vanished", "")] {
            std::fs::create_dir(dir.path().join(thread)).unwrap();
            if !pids.is_empty() {
                std::fs::write(dir.path().join(thread).join("children"), pids).unwrap();
            }
        }
        let mut pids = inherited_children(dir.path());
        pids.sort();
        assert_eq!(pids, vec![11, 22, 33]);
        assert!(inherited_children(&dir.path().join("missing")).is_empty());
    }
    // Linux keeps an exited, unreaped child in procfs. Exiting before the startup
    // scan does not hide it; waitpid can still reap the recorded PID afterwards.
    #[test]
    fn proc_scan_includes_already_exited_children() {
        let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
        let pid = child.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
            if stat.rsplit_once(')').unwrap().1.trim_start().starts_with('Z') {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(inherited_children(std::path::Path::new("/proc/self/task")).contains(&(pid as i32)));
        child.wait().unwrap();
        assert!(!inherited_children(std::path::Path::new("/proc/self/task")).contains(&(pid as i32)));
    }
}

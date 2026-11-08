use drydock_agent::Agent;
use std::{io, path::PathBuf};
use tokio::net::UnixListener;
mod supervisor;
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
    if args.first().is_some_and(|a| a == "--bridge") {
        let socket = match args.get(1..) {
            Some([]) => PathBuf::from("/run/drydock/agent.sock"),
            Some([flag, path]) if flag == "--socket" => path.into(),
            _ => return Err(io::Error::other("usage: drydock-agent --bridge [--socket PATH]")),
        };
        return drydock_agent::socket::bridge(&socket, tokio::io::stdin(), tokio::io::stdout()).await;
    }
    if args.first().is_some_and(|a| a == "--supervise") {
        return supervisor::start(&args[1..]);
    }
    if args.first().is_some_and(|a| a == "--print-token") {
        return print_token(&args[1..]);
    }
    if args.first().is_some_and(|a| a == "--supervisor") {
        return supervisor::run(&args[1..]).await;
    }
    if args.first().is_some_and(|a| a == "--collect") {
        return collect(&args[1..]).await;
    }
    let mut socket = PathBuf::from("/run/drydock/agent.sock");
    let mut vsock = None;
    let mut store = None;
    let (mut tcp, mut token_file) = (None, None);
    let mut options = args.iter();
    while let Some(flag) = options.next() {
        match flag.to_str() {
            Some("--socket") => socket = options.next().ok_or_else(|| io::Error::other("--socket requires a path"))?.into(),
            Some("--store") => store = Some(PathBuf::from(options.next().ok_or_else(|| io::Error::other("--store requires a path"))?)),
            Some("--tcp") => {
                tcp = Some(
                    options
                        .next()
                        .and_then(|s| s.to_str())
                        .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
                        .ok_or_else(|| io::Error::other("--tcp requires ADDR:PORT"))?,
                )
            }
            Some("--tcp-token-file") => {
                token_file = Some(PathBuf::from(options.next().ok_or_else(|| io::Error::other("--tcp-token-file requires a path"))?))
            }
            Some("--vsock-port") => {
                vsock = Some(
                    options
                        .next()
                        .and_then(|s| s.to_str())
                        .and_then(|s| s.parse::<u32>().ok())
                        .ok_or_else(|| io::Error::other("--vsock-port requires a port"))?,
                )
            }
            _ => {
                return Err(io::Error::other(
                    "usage: drydock-agent [--socket PATH] [--vsock-port PORT] [--store DIR] [--tcp ADDR:PORT --tcp-token-file PATH]",
                ));
            }
        }
    }
    // Read before anything is bound, so a bad token file refuses startup.
    let tcp = match (tcp, token_file) {
        (Some(address), Some(path)) => Some((address, drydock_agent::tcp::read_token(&path)?)),
        (None, None) => None,
        (Some(_), None) => return Err(io::Error::other("--tcp requires --tcp-token-file")),
        (None, Some(_)) => return Err(io::Error::other("--tcp-token-file requires --tcp")),
    };
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
    let current = std::env::current_exe()?;
    let fingerprint = drydock_agent::fingerprint()?;
    let executable = drydock_agent::upgrade::startup(&current)
        .map_err(|e| io::Error::new(e.kind(), format!("recover agent {}: {e}", current.display())))?;
    let mut agent = Agent::new(listener, fingerprint, executable.clone()).with_holder(socket.to_string_lossy().into_owned());
    if let Some(store) = store {
        agent = agent.with_store(store);
    }
    if let Some((address, token)) = tcp {
        agent.add_listener(drydock_agent::tcp::TokenListener::bind(address, token).await?);
    }
    #[cfg(target_os = "linux")]
    if let Some(port) = vsock {
        agent.add_listener(tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, port))?);
    }
    #[cfg(not(target_os = "linux"))]
    if vsock.is_some() {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "the vsock listener is not built for this platform yet"));
    }
    let path = agent.run().await?;
    let _ = std::fs::remove_file(socket);
    let error = replace_image(&path, &args);
    if drydock_agent::upgrade::rollback(&executable)? {
        return Err(replace_image(&executable, &args));
    }
    Err(error)
}

/// `--print-token --tcp-token-file PATH`: the token a supervised agent was
/// started with, read back from its file under the same checks the agent makes.
fn print_token(args: &[std::ffi::OsString]) -> io::Result<()> {
    let [flag, path] = args else { return Err(io::Error::other("usage: drydock-agent --print-token --tcp-token-file PATH")) };
    if flag != "--tcp-token-file" {
        return Err(io::Error::other("usage: drydock-agent --print-token --tcp-token-file PATH"));
    }
    println!("{}", drydock_agent::tcp::token_line(&drydock_agent::tcp::read_token(std::path::Path::new(path))?));
    Ok(())
}

/// `--collect --store DIR [--release SOCKET]... [--idle SECONDS]`: one
/// collection over a store other agents may share, run while they serve.
/// Each `--release` names the socket of an agent retired for good, whose
/// links no longer keep entries. Prints what it removed as JSON.
async fn collect(args: &[std::ffi::OsString]) -> io::Result<()> {
    const USAGE: &str = "usage: drydock-agent --collect --store DIR [--release SOCKET]... [--idle SECONDS]";
    let (mut store, mut released, mut idle) = (None, Vec::new(), std::time::Duration::from_secs(600));
    let mut options = args.iter();
    while let Some(flag) = options.next() {
        let mut value = || options.next().ok_or_else(|| io::Error::other(USAGE));
        match flag.to_str() {
            Some("--store") => store = Some(PathBuf::from(value()?)),
            Some("--release") => released.push(value()?.to_string_lossy().into_owned()),
            Some("--idle") => {
                idle =
                    std::time::Duration::from_secs(value()?.to_str().and_then(|s| s.parse().ok()).ok_or_else(|| io::Error::other(USAGE))?)
            }
            _ => return Err(io::Error::other(USAGE)),
        }
    }
    let store = store.ok_or_else(|| io::Error::other(USAGE))?;
    if !store.exists() {
        eprintln!("drydock-agent --collect: no store at {}; nothing to collect", store.display());
        println!("{}", serde_json::to_string(&drydock_agent::Collected::default()).map_err(io::Error::other)?);
        return Ok(());
    }
    let collected = drydock_agent::collect(store, &released, idle).await?;
    println!("{}", serde_json::to_string(&collected).map_err(io::Error::other)?);
    Ok(())
}

// Re-exec keeps the PID and its children, but loses Tokio's old Child handles.
// Reap only the children inherited at startup, so this cannot steal statuses
// from commands launched by the new runtime. Provider init owns crash orphans.
fn reap_inherited_children() {
    let mut children = match inherited_children() {
        Ok(children) => children,
        Err(error) => {
            tracing::warn!(%error, "children inherited from before an upgrade are not reaped");
            return;
        }
    };
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
fn inherited_children() -> io::Result<Vec<libc::pid_t>> {
    Ok(children_of_tasks(std::path::Path::new("/proc/self/task")))
}
#[cfg(target_os = "linux")]
fn children_of_tasks(root: &std::path::Path) -> Vec<libc::pid_t> {
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
#[cfg(target_os = "macos")]
fn inherited_children() -> io::Result<Vec<libc::pid_t>> {
    let parent = std::process::id() as libc::pid_t;
    loop {
        // SAFETY: a null buffer asks only for an upper bound.
        let bound = unsafe { libc::proc_listchildpids(parent, std::ptr::null_mut(), 0) };
        if bound < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut pids = vec![0; bound as usize + 1];
        let size = std::mem::size_of_val(pids.as_slice()) as libc::c_int;
        // SAFETY: the buffer is `size` bytes of pid_t.
        let found = unsafe { libc::proc_listchildpids(parent, pids.as_mut_ptr().cast(), size) };
        if found < 0 {
            return Err(io::Error::last_os_error());
        }
        // A full buffer may have left children out.
        if (found as usize) < pids.len() {
            pids.truncate(found as usize);
            return Ok(pids);
        }
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn inherited_children() -> io::Result<Vec<libc::pid_t>> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "listing a process's children is not built for this platform yet"))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Fake procfs boundary: child lists can belong to any thread, overlap, or
    // disappear while scanning. Missing CONFIG_PROC_CHILDREN must not bar startup.
    #[cfg(target_os = "linux")]
    #[test]
    fn proc_children_scan_all_threads_and_tolerate_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        for (thread, pids) in [("main", "11 22"), ("worker", "22 33"), ("vanished", "")] {
            std::fs::create_dir(dir.path().join(thread)).unwrap();
            if !pids.is_empty() {
                std::fs::write(dir.path().join(thread).join("children"), pids).unwrap();
            }
        }
        let mut pids = children_of_tasks(dir.path());
        pids.sort();
        assert_eq!(pids, vec![11, 22, 33]);
        assert!(children_of_tasks(&dir.path().join("missing")).is_empty());
    }
    // A child that exited before the startup scan is still listed while
    // unreaped, so it is reaped afterwards; once reaped it is not listed.
    #[test]
    fn inherited_children_include_exited_unreaped_ones() {
        use rustix::process::{WaitId, WaitIdOptions, waitid};
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id() as libc::pid_t;
        waitid(WaitId::Pid(rustix::process::Pid::from_raw(pid).unwrap()), WaitIdOptions::EXITED | WaitIdOptions::NOWAIT).unwrap();
        assert!(inherited_children().unwrap().contains(&pid));
        child.wait().unwrap();
        assert!(!inherited_children().unwrap().contains(&pid));
    }
}

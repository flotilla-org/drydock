use drydock_agent::Agent;
use drydock_transport::{Limits, Transport, native::UnixConnections};
use std::{io, os::unix::process::CommandExt, path::PathBuf, sync::Arc};
use tokio::net::UnixListener;
#[tokio::main]
async fn main() -> io::Result<()> {
    if std::process::id() == 1 {
        return Err(io::Error::other("drydock-agent must not be PID 1"));
    }
    reap_inherited_children()?;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mut socket = PathBuf::from("/run/drydock/agent.sock");
    let mut vsock = None;
    let mut options = args.iter();
    while let Some(flag) = options.next() {
        match flag.to_str() {
            Some("--socket") => socket = options.next().ok_or_else(|| io::Error::other("--socket requires a path"))?.into(),
            Some("--vsock-port") => {
                vsock = Some(
                    options
                        .next()
                        .and_then(|s| s.to_str())
                        .and_then(|s| s.parse::<u32>().ok())
                        .ok_or_else(|| io::Error::other("--vsock-port requires a port"))?,
                )
            }
            _ => return Err(io::Error::other("usage: drydock-agent [--socket PATH] [--vsock-port PORT]")),
        }
    }
    if let Ok(metadata) = std::fs::symlink_metadata(&socket) {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, "agent socket path is occupied"));
        }
        match tokio::time::timeout(std::time::Duration::from_millis(100), tokio::net::UnixStream::connect(&socket)).await {
            Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionRefused => std::fs::remove_file(&socket)?,
            _ => return Err(io::Error::new(io::ErrorKind::AddrInUse, "agent socket already in use or inaccessible")),
        }
    }
    let listener = UnixListener::bind(&socket)?;
    let transport = Transport::native(Arc::new(UnixConnections::new(listener, "/run/drydock/host.sock")), Limits::default())?;
    let executable = std::env::current_exe()?;
    let fingerprint = drydock_agent::fingerprint()?;
    let mut agent = Agent::new(transport, fingerprint, executable);
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
    Err(std::process::Command::new(path).args(args).exec())
}

// Re-exec keeps the PID and its children, but loses Tokio's old Child handles.
// Reap only the children inherited at startup, so this cannot steal statuses
// from commands launched by the new runtime. Provider init owns crash orphans.
#[cfg(target_os = "linux")]
fn reap_inherited_children() -> io::Result<()> {
    let children = std::fs::read_to_string(format!("/proc/self/task/{}/children", std::process::id()))?;
    let mut children: Vec<libc::pid_t> = children.split_whitespace().filter_map(|pid| pid.parse().ok()).collect();
    if !children.is_empty() {
        tokio::spawn(async move {
            while !children.is_empty() {
                children.retain(|pid| {
                    // SAFETY: waitpid writes only to the supplied local status;
                    // the PID came from this process's own inherited children.
                    let mut status = 0;
                    unsafe { libc::waitpid(*pid, &mut status, libc::WNOHANG) == 0 }
                });
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        });
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn reap_inherited_children() -> io::Result<()> {
    Ok(())
}

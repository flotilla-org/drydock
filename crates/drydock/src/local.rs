//! Local daemon startup and private directories shared by CLI and daemon.
use crate::client::Client;
use std::{
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

pub fn companion(name: &str, override_var: &str) -> Result<PathBuf, String> {
    rigging_process::resolve_sibling_binary(name, override_var, &rigging_process::ProcessEnvVars, std::env::current_exe, |p| p.is_file())
}
pub fn private_dir(path: &Path) -> Result<(), String> {
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path).map_err(|e| e.to_string())?;
    let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    // SAFETY: geteuid has no preconditions.
    if !meta.is_dir() || meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
        return Err("directory must be private and owned by this user".into());
    }
    Ok(())
}
/// Append lock suffixes: replacing an extension aliases distinct socket overrides.
pub fn socket_lock_path(socket: &Path, suffix: &str) -> PathBuf {
    let mut path = socket.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}
pub fn lock(path: &Path) -> Result<std::fs::File, String> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| e.to_string())?;
    let meta = f.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err("unsafe lock file".into());
    }
    Ok(f)
}
/// Serialize startup, recheck under the lock, and detach only a ready daemon.
/// Reusing an existing daemon never reads the client-side config file.
pub async fn connect(config: &Path, socket: &Path) -> Result<Client, String> {
    let client = Client::unix(socket).map_err(|e| e.to_string())?;
    if client.hello().await.is_ok() {
        return Ok(client);
    }
    let parent = socket.parent().ok_or("socket needs a parent")?;
    private_dir(parent)?;
    let startup = lock(&socket_lock_path(socket, ".startup.lock"))?;
    // Nonblocking lock attempts keep other Tokio tasks and concurrent clients live.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match startup.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err("daemon startup lock timed out".into());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    if client.hello().await.is_ok() {
        return Ok(client);
    }
    // Never replace a live but incompatible/unhealthy endpoint.
    if tokio::net::UnixStream::connect(socket).await.is_ok() {
        return Err("daemon socket is live but does not serve a compatible API".into());
    }
    let log = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(parent.join("drydock.log"))
        .map_err(|e| e.to_string())?;
    let daemon = companion("drydockd", "DRYDOCK_DAEMON_BIN")?;
    let mut child = tokio::process::Command::new(daemon)
        .arg("--config")
        .arg(config)
        .arg("--socket")
        .arg(socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .process_group(0)
        .spawn()
        .map_err(|e| e.to_string())?;
    loop {
        if client.hello().await.is_ok() {
            // Child drop must leave the daemon alive after the client exits.
            return Ok(client);
        }
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("daemon exited ({status}); see {}", parent.join("drydock.log").display()));
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = child.kill().await;
            return Err("daemon startup timed out; see drydock.log".into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Distinct socket overrides must be independently ownable, even when only
    // their extensions differ. Check real OS lock admission, not a path string.
    #[test]
    fn socket_overrides_do_not_alias_lifecycle_locks() {
        let dir = tempfile::tempdir().unwrap();
        let first = lock(&socket_lock_path(&dir.path().join("daemon.sock"), ".lock")).unwrap();
        first.try_lock().unwrap();
        for name in ["daemon.other", "daemon.lock"] {
            let other = lock(&socket_lock_path(&dir.path().join(name), ".lock")).unwrap();
            assert!(other.try_lock().is_ok(), "socket {name} aliases another daemon's lock");
        }
    }
}

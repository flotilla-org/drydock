//! OpenSSH local/remote Unix-socket forwards. Each stream gets an independent
//! SSH channel. OpenSSH must be on PATH; the caller supplies an explicit key file
//! and the reach recipe's host public key. No ambient SSH configuration is read.
use crate::{ByteStream, Connections, Limits, Transport, native::UnixConnections};
use async_trait::async_trait;
use std::{io, path::PathBuf, process::Stdio, sync::Arc};
use tokio::{
    net::UnixListener,
    process::Command,
    sync::{oneshot, watch},
};

#[derive(Clone)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// OpenSSH public key, e.g. `ssh-ed25519 AAAA...` (not a fingerprint).
    pub host_key: String,
    pub identity_file: PathBuf,
    pub agent_socket: PathBuf,
    /// A unique per-vessel path created on the guest by the remote forward.
    pub reverse_socket: PathBuf,
}

/// Starts and owns one SSH session. Local temporary files and the process are
/// removed asynchronously after drop: the monitor kills and reaps the process
/// before removing the directory. Keep the runtime running during teardown.
/// Agent socket permissions and the remote path are the provider's responsibility.
pub async fn connect(config: SshConfig, limits: Limits) -> io::Result<Transport> {
    limits.validate()?;
    if config.host.is_empty()
        || config.host.starts_with('-')
        || config.host.contains(['\n', '\r', ' ', '\t', '@'])
        || config.user.is_empty()
        || config.user.starts_with('-')
        || config.port == 0
        || config.host_key.contains(['\n', '\r'])
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid SSH reach recipe",
        ));
    }
    // Keep Unix socket paths below sun_path limits even with a long TMPDIR.
    let dir = tokio::task::spawn_blocking(|| {
        tempfile::Builder::new()
            .prefix("dd-ssh-")
            .tempdir_in("/tmp")
    })
    .await
    .map_err(io::Error::other)??;
    let incoming_path = dir.path().join("in");
    let outgoing_path = dir.path().join("out");
    let listener = UnixListener::bind(&incoming_path)?;
    let known_hosts = dir.path().join("known_hosts");
    tokio::fs::write(
        &known_hosts,
        format!("drydock-vessel {}\n", config.host_key),
    )
    .await?;
    let stderr_path = dir.path().join("stderr");
    let stderr = tokio::fs::File::create(&stderr_path)
        .await?
        .into_std()
        .await;
    let control = dir.path().join("master");
    let local = forward(&outgoing_path, &config.agent_socket)?;
    let remote = forward(&config.reverse_socket, &incoming_path)?;
    let mut child = Command::new("ssh")
        .args([
            "-F",
            "/dev/null",
            "-T",
            "-n",
            "-N",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "HostKeyAlias=drydock-vessel",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
        ])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
        .arg("-i")
        .arg(&config.identity_file)
        .arg("-p")
        .arg(config.port.to_string())
        .arg("-l")
        .arg(&config.user)
        .arg("-M")
        .arg("-S")
        .arg(&control)
        .arg(&config.host)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .kill_on_drop(true)
        .spawn()?;
    tokio::time::timeout(limits.header_timeout, async {
        loop {
            if let Some(status) = child.try_wait()? {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!(
                        "SSH exited ({status}): {}",
                        tokio::fs::read_to_string(&stderr_path)
                            .await
                            .unwrap_or_default()
                    ),
                ));
            }
            if tokio::fs::try_exists(&control).await? {
                // The multiplexing control command waits for the remote forward
                // acknowledgement. Local socket existence alone is not readiness.
                let output = Command::new("ssh")
                    .args(["-F", "/dev/null", "-S"])
                    .arg(&control)
                    .args(["-O", "forward", "-L"])
                    .arg(&local)
                    .arg("-R")
                    .arg(&remote)
                    .arg(&config.host)
                    .stdin(Stdio::null())
                    .kill_on_drop(true)
                    .output()
                    .await?;
                if !output.status.success() {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!(
                            "SSH forwarding rejected: {}",
                            String::from_utf8_lossy(&output.stderr)
                        ),
                    ));
                }
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SSH forwarding setup"))??;
    let (ended, status) = watch::channel(false);
    let (stop, shutdown) = oneshot::channel();
    tokio::spawn(async move {
        tokio::select! {
            _ = child.wait() => {},
            _ = shutdown => { let _ = child.kill().await; }
        }
        let _ = child.wait().await;
        let _ = ended.send(true);
        // Reap the owned child before removing its private socket directory.
        let _ = tokio::task::spawn_blocking(move || drop(dir)).await;
    });
    let connections = SshConnections {
        native: UnixConnections::new(listener, outgoing_path),
        status,
        stop: Some(stop),
    };
    Transport::native(Arc::new(connections), limits)
}
fn forward(local: &std::path::Path, remote: &std::path::Path) -> io::Result<String> {
    // OpenSSH parses ':' separators itself; reject ambiguous relative paths and
    // metacharacters rather than allowing the recipe to change forwarding kind.
    let path = |p: &std::path::Path| -> io::Result<String> {
        let p = p
            .to_str()
            .filter(|p| p.starts_with('/') && !p.contains([':', '\n', '\r', ' ', '\t']))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SSH socket paths must be absolute without separators or whitespace",
                )
            })?;
        Ok(p.to_owned())
    };
    Ok(format!("{}:{}", path(local)?, path(remote)?))
}
struct SshConnections {
    native: UnixConnections,
    status: watch::Receiver<bool>,
    stop: Option<oneshot::Sender<()>>,
}
impl Drop for SshConnections {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
#[async_trait]
impl Connections for SshConnections {
    async fn connect(&self) -> io::Result<ByteStream> {
        if *self.status.borrow() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "SSH disconnected",
            ));
        }
        self.native.connect().await
    }
    async fn accept(&self) -> io::Result<ByteStream> {
        let mut status = self.status.clone();
        tokio::select! {
            result = self.native.accept() => result,
            _ = status.wait_for(|ended| *ended) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "SSH disconnected")),
        }
    }
}

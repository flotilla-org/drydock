//! OpenSSH local/remote Unix-socket forwards. Each stream gets an independent
//! SSH channel. OpenSSH must be on PATH; the caller supplies an explicit key file
//! and the reach recipe's host public key. No ambient SSH configuration is read.
use crate::{ByteStream, Connections, Limits, Transport, native::UnixConnections};
use async_trait::async_trait;
use std::{
    collections::VecDeque,
    io,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::UnixListener,
    process::Command,
    sync::{oneshot, watch},
};

#[derive(Clone)]
pub struct SshConfig {
    /// Budget for TCP connection, authentication, and forwarding setup.
    pub connect_timeout: Duration,
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
    validate_host_key(&config.host_key)?;
    if config.connect_timeout.is_zero()
        || config.host.is_empty()
        || config.host.starts_with('-')
        || config.host.contains(['\n', '\r', ' ', '\t', '@'])
        || config.user.is_empty()
        || config.user.starts_with('-')
        || config.port == 0
        || config.host_key.contains(['\n', '\r'])
    {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid SSH reach recipe"));
    }
    // Unix-only adapter, validated on Linux. Keep socket paths below sun_path
    // limits even with a long TMPDIR; Windows hosts are not supported.
    let dir =
        tokio::task::spawn_blocking(|| tempfile::Builder::new().prefix("dd-ssh-").tempdir_in("/tmp")).await.map_err(io::Error::other)??;
    let incoming_path = dir.path().join("in");
    let outgoing_path = dir.path().join("out");
    let listener = UnixListener::bind(&incoming_path)?;
    let known_hosts = dir.path().join("known_hosts");
    tokio::fs::write(&known_hosts, format!("drydock-vessel {}\n", config.host_key)).await?;
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
            "LogLevel=ERROR",
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
        .arg("-o")
        .arg(format!(
            "ConnectTimeout={}",
            config.connect_timeout.as_secs().saturating_add(u64::from(config.connect_timeout.subsec_nanos() != 0))
        ))
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
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let stderr = StderrTail::drain(child.stderr.take().unwrap());
    let mut setup = SetupGuard { child: Some(child), dir: Some(dir), stderr: Some(stderr) };
    let child = setup.child.as_mut().unwrap();
    let stderr = setup.stderr.as_ref().unwrap();
    tokio::time::timeout(config.connect_timeout, async {
        loop {
            if let Some(status) = child.try_wait()? {
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, format!("SSH exited ({status}): {}", stderr.text())));
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
                        format!("SSH forwarding rejected: {}", String::from_utf8_lossy(&output.stderr)),
                    ));
                }
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SSH forwarding setup"))??;
    let mut child = setup.child.take().unwrap();
    let dir = setup.dir.take().unwrap();
    let stderr = setup.stderr.take().unwrap();
    let (ended, status) = watch::channel(false);
    let (stop, shutdown) = oneshot::channel();
    tokio::spawn(async move {
        tokio::select! {
            _ = child.wait() => {},
            _ = shutdown => { let _ = child.kill().await; }
        }
        let _ = child.wait().await;
        let _ = ended.send(true);
        drop(stderr);
        // Reap the owned child before removing its private socket directory.
        let _ = tokio::task::spawn_blocking(move || drop(dir)).await;
    });
    let connections = SshConnections { native: UnixConnections::new(listener, outgoing_path), status, stop: Some(stop) };
    Transport::native(Arc::new(connections), limits)
}
fn forward(local: &std::path::Path, remote: &std::path::Path) -> io::Result<String> {
    // OpenSSH parses ':' separators itself; reject ambiguous relative paths and
    // metacharacters rather than allowing the recipe to change forwarding kind.
    let path = |p: &std::path::Path| -> io::Result<String> {
        let p = p.to_str().filter(|p| p.starts_with('/') && !p.contains([':', '\n', '\r', ' ', '\t'])).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "SSH socket paths must be absolute without separators or whitespace")
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
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "SSH disconnected"));
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

// Setup cancellation and failure use the same reap-before-remove order as a
// successful transport. Ownership transfers to the live monitor only on success.
struct SetupGuard {
    child: Option<tokio::process::Child>,
    dir: Option<tempfile::TempDir>,
    stderr: Option<StderrTail>,
}
impl Drop for SetupGuard {
    fn drop(&mut self) {
        let stderr = self.stderr.take();
        if let (Some(mut child), Some(dir)) = (self.child.take(), self.dir.take()) {
            tokio::spawn(async move {
                let _ = child.kill().await;
                let _ = child.wait().await;
                drop(stderr);
                let _ = tokio::task::spawn_blocking(move || drop(dir)).await;
            });
        }
    }
}

const STDERR_TAIL_BYTES: usize = 8192;
struct StderrTail {
    bytes: Arc<Mutex<VecDeque<u8>>>,
    task: tokio::task::AbortHandle,
}
impl StderrTail {
    fn drain<R: tokio::io::AsyncRead + Unpin + Send + 'static>(mut reader: R) -> Self {
        let bytes = Arc::new(Mutex::new(VecDeque::with_capacity(STDERR_TAIL_BYTES)));
        let buffer = bytes.clone();
        let task = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut chunk = [0; 1024];
            while let Ok(n) = reader.read(&mut chunk).await {
                if n == 0 {
                    break;
                }
                let mut tail = buffer.lock().unwrap();
                let excess = (tail.len() + n).saturating_sub(STDERR_TAIL_BYTES);
                tail.drain(..excess);
                tail.extend(&chunk[..n]);
            }
        });
        Self { bytes, task: task.abort_handle() }
    }
    fn text(&self) -> String {
        let bytes: Vec<_> = self.bytes.lock().unwrap().iter().copied().collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}
impl Drop for StderrTail {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn validate_host_key(key: &str) -> io::Result<()> {
    let mut fields = key.split_whitespace();
    let kind = fields.next().unwrap_or_default();
    let supported = matches!(kind, "ssh-ed25519" | "ssh-rsa" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521");
    let blob = fields.next().unwrap_or_default();
    if !supported
        || blob.is_empty()
        || !blob.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
        || key.contains(['\n', '\r'])
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SSH reach requires a raw OpenSSH host public key, not known-hosts options or markers",
        ));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    // Real process boundary: cancelling a partially initialized setup must reap
    // its child before deleting the socket directory, not leave an orphan behind.
    #[tokio::test]
    async fn cancelled_setup_reaps_before_removing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_owned();
        let child = Command::new("sleep").arg("60").kill_on_drop(true).spawn().unwrap();
        let pid = child.id().unwrap();
        drop(SetupGuard { child: Some(child), dir: Some(dir), stderr: None });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while tokio::fs::try_exists(&path).await.unwrap() {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists(), "child must be reaped before its directory disappears");
    }
    // Long-lived SSH diagnostics must drain without pipe backpressure or disk
    // growth, retaining only the documented 8 KiB suffix for error reporting.
    #[tokio::test]
    async fn stderr_drain_retains_only_bounded_tail() {
        use tokio::io::AsyncWriteExt;
        let (mut writer, reader) = tokio::io::duplex(1024);
        let tail = StderrTail::drain(reader);
        let mut data = vec![b'x'; 1024 * 1024];
        data.extend_from_slice(b"last diagnostic");
        tokio::time::timeout(Duration::from_secs(2), async {
            writer.write_all(&data).await.unwrap();
            writer.shutdown().await.unwrap();
            while !tail.text().ends_with("last diagnostic") {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(tail.text().as_bytes(), &data[data.len() - 8192..]);
    }
}

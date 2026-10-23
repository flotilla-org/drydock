//! Drydock's vessel control API and host client. The transport is the trust boundary:
//! only its host-facing side may serve control; guest forwards carry opaque IDs.
mod client;
mod egress;
mod error;
pub use egress::{CA_PATH, Egress, PROXY_PORT};
mod exec;
mod forward;
pub use error::{AgentError, ErrorKind};
mod server;
pub mod socket;
pub mod upgrade;
pub use client::{Client, ExecOutput};
use drydock_transport::ByteStream;
use serde::{Deserialize, Serialize};
pub use server::Agent;
use std::{collections::BTreeMap, io, net::SocketAddr, path::PathBuf};

pub const FEATURES: &[&str] = &["configure", "exec", "files", "forwards", "egress", "upgrade"];
/// Fingerprint of the actual executable, including its linked implementation.
pub fn fingerprint() -> io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut executable = std::fs::File::open(std::env::current_exe()?)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let n = executable.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hello {
    pub fingerprint: String,
    pub features: Vec<String>,
    /// Absent from agents that predate platform reporting. The host cannot
    /// choose an upgrade build for such an agent and refuses to push one.
    #[serde(default)]
    pub platform: Option<Platform>,
}
/// An OCI platform (`linux`, `amd64`/`arm64`). An agent reports the platform
/// its own running executable was built for, not the kernel's `uname`: the
/// guest is already running that build, so a replacement for the same
/// platform runs the same way, natively or under emulation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
}
impl Platform {
    pub fn new(os: impl Into<String>, architecture: impl Into<String>) -> Self {
        Self { os: os.into(), architecture: architecture.into() }
    }
    /// The platform of this executable. Rust target names the tools image
    /// does not build for pass through unchanged.
    pub fn current() -> Self {
        let os = match std::env::consts::OS {
            "macos" => "darwin",
            os => os,
        };
        let architecture = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            architecture => architecture,
        };
        Self::new(os, architecture)
    }
}
impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.os, self.architecture)
    }
}
/// Desired state replaces the previous configuration. Capture forwards traffic;
/// the kind and the upstream own enforcement.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Configuration {
    pub egress: Option<Egress>,
    pub ca: String,
    pub features: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub forwards: Vec<GuestForward>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestForward {
    pub id: String,
    pub unix: PathBuf,
    /// Concrete loopback bind address; wildcard and non-loopback binds are refused.
    pub tcp: Option<SocketAddr>,
}
/// TCP addresses are numeric, so host ownership cannot change through DNS.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Unix(PathBuf),
    Tcp(SocketAddr),
}
impl Endpoint {
    pub(crate) async fn connect_marked(&self, marked: bool) -> io::Result<ByteStream> {
        match self {
            Self::Unix(path) => Ok(Box::new(tokio::net::UnixStream::connect(path).await?)),
            Self::Tcp(addr) => {
                if marked {
                    let socket = if addr.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
                    #[cfg(target_os = "linux")]
                    egress::set_option(&socket, libc::SOL_SOCKET, libc::SO_MARK, egress::SOCKET_MARK)?;
                    Ok(Box::new(socket.connect(*addr).await?))
                } else {
                    Ok(Box::new(tokio::net::TcpStream::connect(addr).await?))
                }
            }
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Exec {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExecEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit { code: Option<i32> },
}
#[derive(Serialize, Deserialize)]
pub(crate) struct FilePath {
    pub path: PathBuf,
}
#[derive(Serialize, Deserialize)]
pub(crate) struct FileWrite {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub executable: bool,
}
#[derive(Serialize, Deserialize)]
pub(crate) struct GuestTarget {
    pub id: String,
    pub endpoint: Endpoint,
}
pub(crate) fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
pub(crate) fn check_id(id: &str) -> io::Result<()> {
    if id.is_empty() || id.len() > 1024 || id.chars().any(char::is_control) {
        return Err(invalid("forward ID must be 1..=1024 bytes without controls"));
    }
    Ok(())
}

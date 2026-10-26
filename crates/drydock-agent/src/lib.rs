//! Drydock's vessel control API and host client. The transport is the trust boundary:
//! only its host-facing side may serve control; guest forwards carry opaque IDs.
mod client;
mod durable;
mod egress;
mod error;
pub use egress::{CA_PATH, Egress, PROXY_PORT};
mod exec;
mod forward;
mod rest;
pub use error::{AgentError, ErrorKind};
mod server;
pub mod socket;
pub mod upgrade;
pub use client::{Client, ExecOutput};
use drydock_transport::ByteStream;
use serde::{Deserialize, Serialize};
pub use server::Agent;
use std::{collections::BTreeMap, io, net::SocketAddr, path::PathBuf};

pub const FEATURES: &[&str] = &["configuration", "exec", "files", "forwards", "egress", "upgrade"];
/// Fingerprint of the actual executable, including its linked implementation.
pub fn fingerprint() -> io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    std::io::copy(&mut std::fs::File::open(std::env::current_exe()?)?, &mut digest)?;
    Ok(format!("{:x}", digest.finalize()))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hello {
    pub fingerprint: String,
    pub features: Vec<String>,
    /// The platform this agent's executable was built for. Absent from agents
    /// that predate platform reporting; hosts then rely on the prepared form.
    #[serde(default)]
    pub platform: Option<Platform>,
    /// A fresh random ID for each agent process. A different boot ID means the
    /// agent restarted and lost its configuration, forwards and processes.
    /// Empty from agents that predate boot IDs.
    #[serde(default)]
    pub boot_id: String,
}
/// The OCI platform type shared with the provider API; an agent reports the
/// platform its own executable was built for.
pub use drydock_protocol::Platform;
/// Desired state replaces the previous configuration. Capture forwards traffic;
/// the kind and the upstream own enforcement. Forwards are separate resources.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub egress: Option<Egress>,
    pub ca: String,
    pub features: Vec<String>,
    pub environment: BTreeMap<String, String>,
}
/// A configuration together with the entity tag the agent gave it. The tag
/// changes whenever the configuration does and whenever the agent restarts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tagged<T> {
    pub value: T,
    pub etag: String,
}
/// A guest listener whose connections reach the host endpoint registered
/// under the same ID.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuestForward {
    pub id: String,
    pub unix: PathBuf,
    /// Concrete loopback bind address; wildcard and non-loopback binds are refused.
    pub tcp: Option<SocketAddr>,
}
/// A guest endpoint the host may open streams to under this ID.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostForward {
    pub id: String,
    pub endpoint: Endpoint,
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
pub(crate) fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
pub(crate) fn check_id(id: &str) -> io::Result<()> {
    if id.is_empty() || id.len() > 1024 || id.chars().any(char::is_control) {
        return Err(invalid("forward ID must be 1..=1024 bytes without controls"));
    }
    Ok(())
}

//! Drydock's vessel control API and host client. The transport is the trust boundary:
//! only its host-facing side may serve control; guest forwards carry opaque IDs.
mod client;
mod exec;
mod server;
pub use client::{Client, ExecOutput};
use drydock_transport::ByteStream;
use serde::{Deserialize, Serialize};
pub use server::Agent;
use std::{collections::BTreeMap, io, net::SocketAddr, path::PathBuf};

pub const FEATURES: &[&str] = &["configure", "exec", "files", "forwards", "upgrade"];
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
}
/// Desired state replaces the previous configuration. Egress is stored for the
/// capture component (#52); this crate does not install redirects or enforce it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Configuration {
    pub egress: serde_json::Value,
    pub ca: String,
    pub features: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub forwards: Vec<GuestForward>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestForward {
    pub id: String,
    pub unix: PathBuf,
    pub tcp: Option<SocketAddr>,
}
/// TCP addresses are numeric, so host ownership cannot change through DNS.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Unix(PathBuf),
    Tcp(SocketAddr),
}
impl Endpoint {
    pub(crate) async fn connect(&self) -> io::Result<ByteStream> {
        match self {
            Self::Unix(path) => Ok(Box::new(tokio::net::UnixStream::connect(path).await?)),
            Self::Tcp(addr) => Ok(Box::new(tokio::net::TcpStream::connect(addr).await?)),
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

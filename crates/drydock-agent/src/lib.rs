//! Drydock's vessel control API and host client. The transport is the trust boundary:
//! only its host-facing side may serve control; guest forwards carry opaque IDs.
mod artifacts;
mod client;
mod durable;
mod egress;
mod error;
pub use egress::{CA_PATH, Egress, PROXY_PORT};
mod fetch;
mod files;
mod forward;
mod frames;
mod process;
mod query;
mod rest;
pub use error::{AgentError, ErrorKind};
mod server;
pub mod socket;
mod store;
pub mod upgrade;
pub use client::{Client, Download, ExecOutput, Process};
use drydock_transport::ByteStream;
use serde::{Deserialize, Serialize};
pub use server::Agent;
use std::{collections::BTreeMap, io, net::SocketAddr, path::PathBuf};

pub const FEATURES: &[&str] = &["configuration", "processes", "files", "uploads", "trees", "forwards", "egress", "upgrade", "artifacts"];
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
    /// This process is an upgrade candidate that nobody has confirmed yet.
    /// Confirm it with [`Client::confirm_upgrade`]; until then the next
    /// ordinary start rolls back to the previous executable.
    #[serde(default)]
    pub probation: bool,
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
/// A process to start. It leads its own process group, with no terminal.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exec {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    /// Added to the configured environment, overriding it per variable.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// Give the process a stdin pipe, written through [`Process::write_stdin`].
    /// Without it, stdin is `/dev/null`.
    #[serde(default)]
    pub stdin: bool,
    /// Kill the process group this many milliseconds after start.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}
impl Exec {
    pub fn new(program: impl Into<String>, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self { program: program.into(), args: args.into_iter().map(Into::into).collect(), ..Self::default() }
    }
}
/// How a process ended. A process killed by a signal has no code; one killed
/// for exceeding its timeout also reports `timed_out`.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitStatus {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    #[serde(default)]
    pub timed_out: bool,
}
impl ExitStatus {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ProcessState {
    Running,
    Exited(ExitStatus),
}
/// A process handle's status.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessInfo {
    pub id: String,
    pub pid: u32,
    pub program: String,
    #[serde(flatten)]
    pub state: ProcessState,
    /// Output bytes held by the agent and not yet sent to a reader. The agent
    /// holds at most a fixed amount, sent bytes kept for a reattach included;
    /// beyond it the process blocks on its pipe.
    pub buffered: u64,
    /// The offsets on stdout and stderr the current reader has reached. A
    /// reattach at lower offsets moves them back.
    pub stdout: u64,
    pub stderr: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecEvent {
    Stdout(bytes::Bytes),
    Stderr(bytes::Bytes),
    Exit(ExitStatus),
}
/// Options for creating a file, directory, link or unpacked tree.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileOptions {
    /// Permission bits. A new file defaults to 0600 and a new directory to
    /// 0700; a replaced file keeps its existing mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// Owner for the new entry and any parents it creates. A replaced file
    /// keeps its existing owner when permitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    /// Create missing parent directories (mode 0755, the given owner).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub parents: bool,
    /// Refuse with 409 when the destination already exists.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exclusive: bool,
    /// Lowercase hex sha256 the content must have. The agent hashes while
    /// writing and refuses, leaving nothing behind, on a mismatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}
/// The digest and size of what the agent wrote.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Written {
    pub sha256: String,
    pub size: u64,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    Other,
}
/// One directory entry or stat result. Symlinks are not followed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Modification time in nanoseconds since the Unix epoch.
    pub modified_ns: i128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<PathBuf>,
}
/// Changes to an existing entry's mode and owner.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Attributes {
    #[serde(default)]
    pub mode: Option<u32>,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u32>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rename {
    pub from: PathBuf,
    pub to: PathBuf,
    /// Refuse with 409 when `to` exists, instead of replacing it.
    #[serde(default)]
    pub exclusive: bool,
    #[serde(default)]
    pub parents: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub target: PathBuf,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    #[default]
    None,
    Gzip,
}
/// Unpack a tar archive into a new directory. The archive's digest is
/// checked before the directory appears; a refusal leaves the target as it was.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TreeOptions {
    /// Lowercase hex sha256 of the archive bytes as sent.
    pub sha256: String,
    #[serde(default)]
    pub compression: Compression,
    /// Owner of every unpacked entry. Without one, entries belong to the agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    /// Mode of the target directory itself; default 0755.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub parents: bool,
    /// Replace an existing target directory atomically. Without it, an
    /// existing target is a 409.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub replace: bool,
}
/// Fetch an artifact by digest into the agent's store, from the first of
/// `sources` that yields bytes with that digest, and unpack it there.
/// Without sources it is only a lookup of the index and of completed uploads.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Fetch {
    /// Tried in order; the order is the caller's policy.
    #[serde(default)]
    pub sources: Vec<ArtifactSource>,
    pub unpack: Unpack,
}
/// One place an artifact's bytes may come from. Every source meets the same
/// final check: the bytes hash to the expected digest, or nothing is stored.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactSource {
    /// An `http` or `https` URL, such as a release download.
    Upstream { url: String },
    /// A blob in an OCI registry, fetched through the distribution API by
    /// the artifact's digest. `registry` is a host (HTTPS) or a base URL.
    Oci {
        registry: String,
        repository: String,
        /// Used for this call only; the agent never stores it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credential: Option<RegistryCredential>,
    },
    /// The caller pushes the bytes with the resumable upload protocol
    /// (`/blobs/{sha256}`), then asks again. Reaching this source without a
    /// completed upload is refused as `artifact.push`, naming the offset.
    Push,
}
/// Registry authentication for one fetch.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RegistryCredential {
    /// Answers a Basic challenge, or authenticates a Bearer token request.
    Basic { username: String, password: String },
    /// Sent as `Authorization: Bearer`.
    Bearer { token: String },
}
impl std::fmt::Debug for RegistryCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Basic { username, .. } => write!(f, "Basic({username}, <redacted>)"),
            Self::Bearer { .. } => f.write_str("Bearer(<redacted>)"),
        }
    }
}
/// How fetched bytes become a store entry.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Unpack {
    /// The bytes are one file with these permission bits; write bits and
    /// setuid/setgid are always cleared.
    #[serde(rename = "file")]
    File {
        #[serde(default = "Unpack::default_mode")]
        mode: u32,
    },
    /// A tar archive unpacked into a directory.
    #[serde(rename = "tar")]
    Tar,
    /// A gzip-compressed tar archive, such as a release `.tar.gz` or an OCI
    /// `tar+gzip` layer.
    #[serde(rename = "tar.gz")]
    TarGz,
}
impl Unpack {
    fn default_mode() -> u32 {
        0o555
    }
}
/// A complete, verified store entry. It is read-only.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Artifact {
    pub sha256: String,
    /// Bytes fetched, before any unpacking.
    pub size: u64,
    pub unpack: Unpack,
    /// The entry: the file itself, or the unpacked directory.
    pub path: PathBuf,
    /// Links placed through the agent that still point into the entry.
    #[serde(default)]
    pub links: Vec<PathBuf>,
}
/// Where a fetch found an artifact's bytes.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// The index already held the entry: nothing was read or hashed.
    Index,
    /// A completed upload of the digest, such as a push.
    Blob,
    /// The source at this position in the request.
    Source(usize),
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Fetched {
    pub artifact: Artifact,
    pub origin: Origin,
}
/// A link to a store entry, or to `member` inside an unpacked one.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactLink {
    #[serde(default)]
    pub member: PathBuf,
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
pub(crate) fn check_sha256(digest: &str) -> io::Result<()> {
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(invalid(format!("sha256 must be 64 lowercase hex digits, not {digest:?}")));
    }
    Ok(())
}

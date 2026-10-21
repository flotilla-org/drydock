use crate::*;
use bytes::{Bytes, BytesMut};
use drydock_transport::{Opener, Purpose, Transport, http2};
use http_body_util::{BodyExt, Full};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, OnceLock},
};
use tokio::task::JoinSet;
#[derive(Clone, PartialEq, Eq, Hash)]
enum EndpointKey {
    Unix(u64, u64),
    UnixPath(PathBuf),
    Tcp(u16),
}
fn claims() -> &'static Mutex<HashSet<EndpointKey>> {
    static CLAIMS: OnceLock<Mutex<HashSet<EndpointKey>>> = OnceLock::new();
    CLAIMS.get_or_init(Mutex::default)
}
struct Claim(Endpoint, Vec<EndpointKey>);
impl Drop for Claim {
    fn drop(&mut self) {
        let mut claims = claims().lock().unwrap();
        for key in &self.1 {
            claims.remove(key);
        }
    }
}
fn claim(endpoint: Endpoint) -> io::Result<Claim> {
    let endpoint = match endpoint {
        Endpoint::Unix(path) => Endpoint::Unix(std::fs::canonicalize(path)?),
        other => other,
    };
    let keys = match &endpoint {
        Endpoint::Unix(path) => {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            let metadata = std::fs::metadata(path)?;
            if !metadata.file_type().is_socket() {
                return Err(invalid("host endpoint must be a Unix socket"));
            }
            vec![EndpointKey::Unix(metadata.dev(), metadata.ino()), EndpointKey::UnixPath(path.clone())]
        }
        Endpoint::Tcp(address) => {
            if !address.ip().is_loopback() || address.port() == 0 {
                return Err(invalid("host TCP endpoint must be a dedicated loopback port"));
            }
            // Conservatively reserve the port across all loopback aliases, so
            // wildcard listeners cannot be shared through different addresses.
            vec![EndpointKey::Tcp(address.port())]
        }
    };
    let mut claims = claims().lock().unwrap();
    if keys.iter().any(|key| claims.contains(key)) {
        return Err(io::Error::new(io::ErrorKind::AddrInUse, "host endpoint already serves a vessel"));
    }
    claims.extend(keys.iter().cloned());
    Ok(Claim(endpoint, keys))
}
type Targets = Arc<Mutex<HashMap<String, Arc<Claim>>>>;
/// One vessel per client. A host endpoint stays exclusively claimed until all
/// streams using it close. Controllers in separate processes must allocate
/// separate endpoints; direct multi-controller connections are out of scope.
pub struct Client {
    sender: http2::Client,
    opener: Opener,
    hello: Hello,
    expected: String,
    targets: Targets,
    tasks: Vec<tokio::task::AbortHandle>,
}
impl Drop for Client {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl Client {
    pub async fn connect(mut transport: Transport, expected: impl Into<String>) -> io::Result<Self> {
        let (sender, driver) = http2::connect(&transport.opener, Purpose::Control).await?;
        let targets: Targets = Arc::default();
        let map = targets.clone();
        let opener = transport.opener.clone();
        let task = tokio::spawn(async move {
            let mut streams = JoinSet::new();
            loop {
                tokio::select! {
                    Some(_) = streams.join_next(), if !streams.is_empty() => {},
                    incoming = transport.accept() => {
                        let Ok(Some(incoming)) = incoming else { break; };
                        // Guest-supplied IDs resolve only in THIS vessel's registry.
                        // No path, host, or port supplied by the guest is dialed.
                        if let Purpose::Forward { id } = incoming.purpose {
                            let target = map.lock().unwrap().get(&id).cloned();
                            if let Some(target) = target { streams.spawn(async move {
                                if let Ok(mut endpoint) = target.0.connect().await {
                                    let mut stream = incoming.stream;
                                    if let Err(error) = tokio::io::copy_bidirectional(&mut stream, &mut endpoint).await { tracing::warn!(%error, forward = %id, "host endpoint stream failed"); }
                                } else { tracing::warn!(forward = %id, "host endpoint connection failed"); }
                            }); }
                        }
                    }
                }
            }
        });
        let mut client = Self {
            sender,
            opener,
            hello: Hello { fingerprint: String::new(), features: vec![] },
            expected: expected.into(),
            targets,
            tasks: vec![driver.abort_handle(), task.abort_handle()],
        };
        client.hello = client.json("GET", "/hello", &()).await?;
        Ok(client)
    }
    pub fn hello(&self) -> &Hello {
        &self.hello
    }
    pub fn is_compatible(&self) -> bool {
        self.hello.fingerprint == self.expected
    }
    fn require_compatible(&self) -> io::Result<()> {
        if !self.is_compatible() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "agent fingerprint mismatch: only hello and upgrade are permitted"));
        }
        Ok(())
    }
    async fn request(&self, method: &str, route: &str, bytes: Vec<u8>) -> io::Result<axum::body::Body> {
        if !matches!(route, "/hello" | "/upgrade") {
            self.require_compatible()?;
        }
        let request = http::Request::builder()
            .method(method)
            .uri(route)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(bytes)))
            .map_err(invalid)?;
        let response = self.sender.clone().send_request(request).await.map_err(io::Error::other)?;
        let status = response.status();
        let body = axum::body::Body::new(response.into_body());
        if !status.is_success() {
            let bytes = axum::body::to_bytes(body, 1024 * 1024).await.map_err(io::Error::other)?;
            return Err(io::Error::other(format!("{status}: {}", String::from_utf8_lossy(&bytes))));
        }
        Ok(body)
    }
    async fn json<T: serde::de::DeserializeOwned>(&self, method: &str, route: &str, value: &impl Serialize) -> io::Result<T> {
        let body = self.request(method, route, serde_json::to_vec(value).map_err(invalid)?).await?;
        let bytes = axum::body::to_bytes(body, 128 * 1024 * 1024).await.map_err(io::Error::other)?;
        serde_json::from_slice(&bytes).map_err(invalid)
    }
    async fn empty(&self, method: &str, route: &str, value: &impl Serialize) -> io::Result<()> {
        self.request(method, route, serde_json::to_vec(value).map_err(invalid)?).await?.collect().await.map_err(io::Error::other)?;
        Ok(())
    }
    pub async fn configure(&self, config: Configuration) -> io::Result<()> {
        self.empty("PUT", "/configure", &config).await
    }
    pub async fn configuration(&self) -> io::Result<Configuration> {
        self.json("GET", "/configure", &()).await
    }
    pub async fn exec(&self, request: Exec) -> io::Result<ExecOutput> {
        Ok(ExecOutput {
            body: self.request("POST", "/exec", serde_json::to_vec(&request).map_err(invalid)?).await?,
            pending: BytesMut::new(),
        })
    }
    pub async fn write(&self, path: PathBuf, bytes: Vec<u8>, executable: bool) -> io::Result<()> {
        self.empty("POST", "/files/write", &FileWrite { path, bytes, executable }).await
    }
    pub async fn read(&self, path: PathBuf) -> io::Result<Vec<u8>> {
        let body = self.request("POST", "/files/read", serde_json::to_vec(&FilePath { path }).map_err(invalid)?).await?;
        Ok(axum::body::to_bytes(body, 128 * 1024 * 1024).await.map_err(io::Error::other)?.to_vec())
    }
    pub async fn flush(&self, path: PathBuf) -> io::Result<()> {
        self.empty("POST", "/files/flush", &FilePath { path }).await
    }
    /// Stage then activate via the stable route. Reconnect afterwards and verify
    /// the new hello fingerprint before using any generation-specific routes.
    pub async fn upgrade(&self, executable: Vec<u8>) -> io::Result<()> {
        self.stage_upgrade(executable).await?;
        self.activate_upgrade().await
    }
    /// Retain a staged image across activation failures without retransmission.
    pub async fn stage_upgrade(&self, executable: Vec<u8>) -> io::Result<()> {
        self.request("PUT", "/upgrade", executable).await?.collect().await.map_err(io::Error::other)?;
        Ok(())
    }
    /// Retry activation of an already staged image after a filesystem failure.
    pub async fn activate_upgrade(&self) -> io::Result<()> {
        self.empty("POST", "/upgrade", &()).await
    }
    pub fn register_host_endpoint(&self, id: String, endpoint: Endpoint) -> io::Result<()> {
        self.require_compatible()?;
        check_id(&id)?;
        let claim = Arc::new(claim(endpoint)?);
        let mut targets = self.targets.lock().unwrap();
        if targets.contains_key(&id) {
            return Err(invalid("forward ID already exists"));
        }
        targets.insert(id, claim);
        Ok(())
    }
    pub async fn add_guest_forward(&self, forward: GuestForward, endpoint: Endpoint) -> io::Result<()> {
        self.register_host_endpoint(forward.id.clone(), endpoint)?;
        if let Err(error) = self.empty("PUT", "/forwards/guest", &forward).await {
            self.targets.lock().unwrap().remove(&forward.id);
            return Err(error);
        }
        Ok(())
    }
    pub async fn remove_guest_forward(&self, id: &str) -> io::Result<()> {
        let original = self.targets.lock().unwrap().get(id).cloned();
        self.empty("DELETE", "/forwards/guest", &id).await?;
        let mut targets = self.targets.lock().unwrap();
        if let Some(original) = original
            && targets.get(id).is_some_and(|current| Arc::ptr_eq(current, &original))
        {
            targets.remove(id);
        }
        Ok(())
    }
    pub async fn add_host_forward(&self, id: String, endpoint: Endpoint) -> io::Result<()> {
        self.empty("PUT", "/forwards/host", &GuestTarget { id, endpoint }).await
    }
    pub async fn remove_host_forward(&self, id: &str) -> io::Result<()> {
        self.empty("DELETE", "/forwards/host", &id).await
    }
    pub async fn forward(&self, id: &str) -> io::Result<ByteStream> {
        self.require_compatible()?;
        self.opener.open(Purpose::Forward { id: id.into() }).await
    }
}
/// Incremental NDJSON. Each output channel preserves its own byte order.
pub struct ExecOutput {
    body: axum::body::Body,
    pending: BytesMut,
}
impl ExecOutput {
    pub async fn next(&mut self) -> io::Result<Option<ExecEvent>> {
        loop {
            if let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
                let line = self.pending.split_to(end + 1);
                return serde_json::from_slice(&line).map(Some).map_err(invalid);
            }
            match self.body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(bytes) = frame.into_data() {
                        self.pending.extend_from_slice(&bytes);
                    }
                }
                Some(Err(error)) => return Err(io::Error::other(error)),
                None if self.pending.is_empty() => return Ok(None),
                None => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated exec event")),
            }
            if self.pending.len() > 1024 * 1024 {
                return Err(invalid("oversized exec event"));
            }
        }
    }
}

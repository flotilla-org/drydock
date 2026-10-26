use crate::{rest::encode_segment, *};
use bytes::{Bytes, BytesMut};
use drydock_transport::{Opener, Purpose, Transport, http2};
use http_body_util::{BodyExt, Empty, Full, combinators::UnsyncBoxBody};
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
struct Claim {
    endpoint: Endpoint,
    keys: Vec<EndpointKey>,
    // Keep an unlinked socket inode alive until the last stream claim closes.
    #[cfg(target_os = "linux")]
    _inode: Option<std::fs::File>,
}
impl Drop for Claim {
    fn drop(&mut self) {
        let mut claims = claims().lock().unwrap();
        for key in &self.keys {
            claims.remove(key);
        }
    }
}
fn canonical(endpoint: Endpoint) -> io::Result<Endpoint> {
    Ok(match endpoint {
        Endpoint::Unix(path) => Endpoint::Unix(std::fs::canonicalize(path)?),
        other => other,
    })
}
fn claim(endpoint: Endpoint) -> io::Result<Claim> {
    let endpoint = canonical(endpoint)?;
    #[cfg(target_os = "linux")]
    let inode = if let Endpoint::Unix(path) = &endpoint {
        use std::os::unix::fs::OpenOptionsExt;
        Some(std::fs::OpenOptions::new().read(true).custom_flags(libc::O_PATH | libc::O_NOFOLLOW).open(path)?)
    } else {
        None
    };
    let keys = match &endpoint {
        Endpoint::Unix(path) => {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            #[cfg(target_os = "linux")]
            let metadata = inode.as_ref().unwrap().metadata()?;
            #[cfg(not(target_os = "linux"))]
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
    Ok(Claim {
        endpoint,
        keys,
        #[cfg(target_os = "linux")]
        _inode: inode,
    })
}
type Targets = Arc<Mutex<HashMap<String, Arc<Claim>>>>;
type RequestBody = UnsyncBoxBody<Bytes, io::Error>;

/// A transport failure on the control link, keeping the underlying error.
#[derive(Debug, thiserror::Error)]
#[error("{context}: {source}")]
struct LinkError {
    context: String,
    source: Box<dyn std::error::Error + Send + Sync>,
}
fn link_error(context: impl Into<String>, source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, LinkError { context: context.into(), source: source.into() })
}
fn empty() -> RequestBody {
    Empty::new().map_err(|never| match never {}).boxed_unsync()
}
fn full(bytes: impl Into<Bytes>) -> RequestBody {
    Full::new(bytes.into()).map_err(|never| match never {}).boxed_unsync()
}
fn json_body(value: &impl Serialize) -> io::Result<RequestBody> {
    Ok(full(serde_json::to_vec(value).map_err(invalid)?))
}
/// The HTTP/2 control link, shared by a client and its process handles.
#[derive(Clone)]
struct Control {
    sender: http2::Client<RequestBody>,
    compatible: bool,
}
impl Control {
    async fn send(
        &self,
        method: &str,
        uri: &str,
        headers: &[(&str, String)],
        body: RequestBody,
    ) -> io::Result<http::Response<axum::body::Body>> {
        if !self.compatible && !(uri == "/hello" || uri.starts_with("/upgrade")) {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "agent fingerprint mismatch: only hello and upgrade are permitted"));
        }
        let mut request = http::Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let request = request.body(body).map_err(invalid)?;
        let response = self.sender.clone().send_request(request).await.map_err(|e| link_error(format!("{method} {uri}"), e))?;
        let status = response.status();
        let (parts, body) = response.into_parts();
        let body = axum::body::Body::new(body);
        if !status.is_success() {
            let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap_or_default();
            return Err(match serde_json::from_slice::<AgentError>(&bytes) {
                Ok(error) => error.into_io(),
                Err(_) => {
                    let text = String::from_utf8_lossy(&bytes);
                    let message =
                        if text.is_empty() { status.canonical_reason().unwrap_or("refused").to_owned() } else { text.into_owned() };
                    AgentError::new("request", format!("{method} {uri}"), ErrorKind::from_status(status.as_u16()), message)
                        .with_status(status.as_u16())
                        .into_io()
                }
            });
        }
        Ok(http::Response::from_parts(parts, body))
    }
    async fn json<T: serde::de::DeserializeOwned>(&self, method: &str, uri: &str, body: RequestBody) -> io::Result<T> {
        decode(self.send(method, uri, &[("content-type", "application/json".into())], body).await?, method, uri).await
    }
    async fn empty(&self, method: &str, uri: &str, body: RequestBody) -> io::Result<http::Response<axum::body::Body>> {
        let response = self.send(method, uri, &[("content-type", "application/json".into())], body).await?;
        let (parts, body) = response.into_parts();
        body.collect().await.map_err(|e| link_error(format!("{method} {uri}"), e))?;
        Ok(http::Response::from_parts(parts, axum::body::Body::empty()))
    }
}
/// A reply's JSON body.
async fn decode<T: serde::de::DeserializeOwned>(response: http::Response<axum::body::Body>, method: &str, uri: &str) -> io::Result<T> {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024 * 1024).await.map_err(|e| link_error(format!("{method} {uri}"), e))?;
    serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{method} {uri}: malformed reply: {e}")))
}
fn header(response: &http::Response<axum::body::Body>, name: &str) -> Option<String> {
    response.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
}

/// One vessel per client. A host endpoint stays exclusively claimed until all
/// streams using it close. Controllers in separate processes must allocate
/// separate endpoints; direct multi-controller connections are out of scope.
pub struct Client {
    link: Control,
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
    /// Connect to a vessel started from any published tools pin. A mismatched
    /// hello triggers push + re-exec, then a fresh transport and verified hello.
    /// The factory must open a new provider transport on every invocation.
    /// `platform` is the platform the vessel was prepared for and `executable`
    /// the current agent build for it; the caller chose both from the prepared
    /// form, never from the guest. Returns only a compatible client; callers
    /// push configuration afterwards. Initial transport/hello errors
    /// return immediately; only post-upgrade reconnects retry. The caller must
    /// arrange initial provider readiness.
    ///
    /// A hello that reports a platform is checked against `platform`. A
    /// different one fails with [`io::ErrorKind::Unsupported`], pushing
    /// nothing. Agents older than platform reporting send none, so the check
    /// is skipped and the build is pushed.
    pub async fn connect_current<F, Fut>(
        mut open: F,
        platform: &Platform,
        executable: &[u8],
        timeout: std::time::Duration,
    ) -> io::Result<Self>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = io::Result<Transport>>,
    {
        if executable.is_empty() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, format!("agent build for platform {platform} is empty")));
        }
        let mut observation = "no hello received".to_owned();
        let result = tokio::time::timeout(timeout, async {
            let mut client = Self::connect(open().await?, String::new()).await?;
            observation = format!("last hello fingerprint {}", client.hello.fingerprint);
            if let Some(reported) = &client.hello.platform
                && reported != platform
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("vessel was prepared for {platform} but its agent reports {reported}"),
                ));
            }
            use sha2::{Digest, Sha256};
            let expected = format!("{:x}", Sha256::digest(executable));
            client.set_expected(expected.clone());
            if client.is_compatible() {
                return Ok(client);
            }
            client.stage_upgrade(executable.to_vec()).await?;
            // Activation acknowledgement is advisory: re-exec can close the
            // stream before the response arrives. Only the next hello decides.
            let _ = client.activate_upgrade().await;
            drop(client);
            loop {
                match open().await {
                    Ok(transport) => match Self::connect(transport, &expected).await {
                        Ok(client) if client.is_compatible() => return Ok(client),
                        Ok(client) => observation = format!("last hello fingerprint {}", client.hello.fingerprint),
                        Err(error) => observation = format!("last hello error: {error}"),
                    },
                    Err(error) => observation = format!("last transport error: {error}"),
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await;
        result.map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("agent did not report the current fingerprint after hello/upgrade; {observation}"),
            )
        })?
    }

    /// Low-level connection for explicit hello/upgrade tooling. Normal hosts
    /// should use connect_current so an older tools pin upgrades automatically.
    pub async fn connect(mut transport: Transport, expected: impl Into<String>) -> io::Result<Self> {
        let (sender, driver) = http2::connect_with_body::<RequestBody>(&transport.opener, Purpose::Control).await?;
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
                            streams.spawn(async move {
                                let endpoint = target.as_ref().map(|claim| &claim.endpoint);
                                if let Err(error) = crate::forward::serve(incoming.stream, &id, endpoint).await {
                                    tracing::warn!(%error, forward = %id, "guest-to-host forward failed");
                                }
                            });
                        }
                    }
                }
            }
        });
        let mut client = Self {
            link: Control { sender, compatible: false },
            opener,
            hello: Hello { fingerprint: String::new(), features: vec![], platform: None, boot_id: String::new() },
            expected: String::new(),
            targets,
            tasks: vec![driver.abort_handle(), task.abort_handle()],
        };
        client.hello = client.link.json("GET", "/hello", empty()).await?;
        client.set_expected(expected.into());
        Ok(client)
    }
    fn set_expected(&mut self, expected: String) {
        self.link.compatible = self.hello.fingerprint == expected;
        self.expected = expected;
    }
    pub fn hello(&self) -> &Hello {
        &self.hello
    }
    pub fn is_compatible(&self) -> bool {
        self.link.compatible
    }
    /// Read hello again; a changed boot ID means the agent restarted.
    pub async fn refresh_hello(&mut self) -> io::Result<&Hello> {
        self.hello = self.link.json("GET", "/hello", empty()).await?;
        self.link.compatible = self.hello.fingerprint == self.expected;
        Ok(&self.hello)
    }

    /// Replace the configuration; returns its new entity tag.
    pub async fn configure(&self, config: Configuration) -> io::Result<String> {
        self.put_configuration(config, None).await
    }
    /// Replace the configuration only if it still has `etag`; a different
    /// tag is refused with 412 (the agent restarted or another host changed it).
    pub async fn configure_if(&self, config: Configuration, etag: &str) -> io::Result<String> {
        self.put_configuration(config, Some(etag)).await
    }
    async fn put_configuration(&self, config: Configuration, etag: Option<&str>) -> io::Result<String> {
        if let Some(egress) = &config.egress {
            check_id(&egress.upstream)?;
            if !self.targets.lock().unwrap().contains_key(&egress.upstream) {
                return Err(crate::error::context(
                    "configuration",
                    &egress.upstream,
                    invalid("egress upstream host endpoint was never registered"),
                ));
            }
        }
        let mut headers = vec![("content-type", "application/json".to_owned())];
        if let Some(etag) = etag {
            headers.push(("if-match", etag.to_owned()));
        }
        let response = self.link.send("PUT", "/configuration", &headers, json_body(&config)?).await?;
        header(&response, "etag").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "configuration reply lacks an ETag"))
    }
    pub async fn configuration(&self) -> io::Result<Tagged<Configuration>> {
        let response = self.link.send("GET", "/configuration", &[], empty()).await?;
        let etag = header(&response, "etag").unwrap_or_default();
        Ok(Tagged { value: decode(response, "GET", "/configuration").await?, etag })
    }

    pub async fn exec(&self, request: Exec) -> io::Result<ExecOutput> {
        let response = self.link.send("POST", "/exec", &[("content-type", "application/json".into())], json_body(&request)?).await?;
        Ok(ExecOutput { body: response.into_body(), pending: BytesMut::new(), seen_exit: false })
    }
    pub async fn write(&self, path: PathBuf, bytes: Vec<u8>, executable: bool) -> io::Result<()> {
        self.link.empty("POST", "/files/write", json_body(&FileWrite { path, bytes, executable })?).await.map(drop)
    }
    pub async fn read(&self, path: PathBuf) -> io::Result<Vec<u8>> {
        let response =
            self.link.send("POST", "/files/read", &[("content-type", "application/json".into())], json_body(&FilePath { path })?).await?;
        Ok(axum::body::to_bytes(response.into_body(), 128 * 1024 * 1024).await.map_err(|e| link_error("POST /files/read", e))?.to_vec())
    }
    pub async fn flush(&self, path: PathBuf) -> io::Result<()> {
        self.link.empty("POST", "/files/flush", json_body(&FilePath { path })?).await.map(drop)
    }

    /// Stage then activate via the stable route. Reconnect afterwards and verify
    /// the new hello fingerprint before using any generation-specific routes.
    pub async fn upgrade(&self, executable: Vec<u8>) -> io::Result<()> {
        self.stage_upgrade(executable).await?;
        self.activate_upgrade().await
    }
    /// Retain a staged image across activation failures without retransmission.
    pub async fn stage_upgrade(&self, executable: Vec<u8>) -> io::Result<()> {
        let response = self.link.send("PUT", "/upgrade", &[("content-type", "application/octet-stream".into())], full(executable)).await?;
        response.into_body().collect().await.map_err(|e| link_error("PUT /upgrade", e))?;
        Ok(())
    }
    /// Retry activation of an already staged image after a filesystem failure.
    pub async fn activate_upgrade(&self) -> io::Result<()> {
        self.link.empty("POST", "/upgrade", empty()).await.map(drop)
    }

    /// Reserve a host endpoint for guest connections arriving under `id`.
    /// Registering the same endpoint again is accepted.
    pub fn register_host_endpoint(&self, id: String, endpoint: Endpoint) -> io::Result<()> {
        self.require_compatible()?;
        check_id(&id)?;
        let mut targets = self.targets.lock().unwrap();
        if let Some(existing) = targets.get(&id) {
            if canonical(endpoint)? == existing.endpoint {
                return Ok(());
            }
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("forward ID {id} already names another host endpoint")));
        }
        targets.insert(id, Arc::new(claim(endpoint)?));
        Ok(())
    }
    /// Release a host endpoint; live streams keep their claim until they close.
    pub fn release_host_endpoint(&self, id: &str) {
        self.targets.lock().unwrap().remove(id);
    }
    fn require_compatible(&self) -> io::Result<()> {
        if !self.is_compatible() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "agent fingerprint mismatch: only hello and upgrade are permitted"));
        }
        Ok(())
    }
    /// Create or update a guest listener whose connections reach `endpoint`.
    /// An identical forward is left as it is, live streams included.
    pub async fn put_guest_forward(&self, forward: GuestForward, endpoint: Endpoint) -> io::Result<()> {
        self.require_compatible()?;
        check_id(&forward.id)?;
        let registered = self.targets.lock().unwrap().get(&forward.id).cloned();
        // The same endpoint, already registered under this ID, is kept.
        let fresh = match registered {
            Some(existing) if canonical(endpoint.clone())? == existing.endpoint => None,
            _ => Some(Arc::new(claim(endpoint)?)),
        };
        let uri = format!("/forwards/guest/{}", encode_segment(&forward.id));
        self.link.empty("PUT", &uri, json_body(&forward)?).await?;
        if let Some(fresh) = fresh {
            self.targets.lock().unwrap().insert(forward.id, fresh);
        }
        Ok(())
    }
    pub async fn guest_forward(&self, id: &str) -> io::Result<GuestForward> {
        self.link.json("GET", &format!("/forwards/guest/{}", encode_segment(id)), empty()).await
    }
    pub async fn guest_forwards(&self) -> io::Result<Vec<GuestForward>> {
        self.link.json("GET", "/forwards/guest", empty()).await
    }
    pub async fn remove_guest_forward(&self, id: &str) -> io::Result<()> {
        let original = self.targets.lock().unwrap().get(id).cloned();
        self.link.empty("DELETE", &format!("/forwards/guest/{}", encode_segment(id)), empty()).await?;
        let mut targets = self.targets.lock().unwrap();
        if let Some(original) = original
            && targets.get(id).is_some_and(|current| Arc::ptr_eq(current, &original))
        {
            targets.remove(id);
        }
        Ok(())
    }
    /// Create or update a guest endpoint the host can open streams to. An
    /// unchanged endpoint keeps its live streams.
    pub async fn put_host_forward(&self, forward: HostForward) -> io::Result<()> {
        let uri = format!("/forwards/host/{}", encode_segment(&forward.id));
        self.link.empty("PUT", &uri, json_body(&forward)?).await.map(drop)
    }
    pub async fn host_forward(&self, id: &str) -> io::Result<HostForward> {
        self.link.json("GET", &format!("/forwards/host/{}", encode_segment(id)), empty()).await
    }
    pub async fn host_forwards(&self) -> io::Result<Vec<HostForward>> {
        self.link.json("GET", "/forwards/host", empty()).await
    }
    pub async fn remove_host_forward(&self, id: &str) -> io::Result<()> {
        self.link.empty("DELETE", &format!("/forwards/host/{}", encode_segment(id)), empty()).await.map(drop)
    }
    pub async fn forward(&self, id: &str) -> io::Result<ByteStream> {
        self.require_compatible()?;
        let mut stream = self.opener.open(Purpose::Forward { id: id.into() }).await?;
        crate::forward::opened(&mut stream).await?;
        Ok(stream)
    }
}
/// Incremental NDJSON. Each output channel preserves its own byte order.
pub struct ExecOutput {
    body: axum::body::Body,
    pending: BytesMut,
    seen_exit: bool,
}
impl ExecOutput {
    pub async fn next(&mut self) -> io::Result<Option<ExecEvent>> {
        if self.seen_exit {
            return Ok(None);
        }
        loop {
            if let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
                let line = self.pending.split_to(end + 1);
                let event = serde_json::from_slice(&line).map_err(invalid)?;
                self.seen_exit = matches!(event, ExecEvent::Exit { .. });
                return Ok(Some(event));
            }
            match self.body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(bytes) = frame.into_data() {
                        self.pending.extend_from_slice(&bytes);
                    }
                }
                Some(Err(error)) => return Err(link_error("exec output", error)),
                None if self.pending.is_empty() => {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "exec stream ended without Exit"));
                }
                None => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated exec event")),
            }
            if self.pending.len() > 1024 * 1024 {
                return Err(invalid("oversized exec event"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // HTTP-body boundary fake: truncate a valid stream at every drawn byte.
    // Only a stream containing a complete Exit event may end successfully.
    #[hegel::test]
    fn exec_requires_exit_at_truncation_boundaries(tc: hegel::TestCase) {
        use hegel::generators as gs;
        let events = [ExecEvent::Stdout(vec![0, 128, 255]), ExecEvent::Stderr(b"err".to_vec()), ExecEvent::Exit { code: Some(0) }];
        let bytes: Vec<u8> = events
            .iter()
            .flat_map(|event| {
                let mut bytes = serde_json::to_vec(event).unwrap();
                bytes.push(b'\n');
                bytes
            })
            .collect();
        let cut = tc.draw(gs::integers::<usize>().min_value(0).max_value(bytes.len()));
        let expected_events = bytes[..cut].iter().filter(|byte| **byte == b'\n').count();
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let mut output = ExecOutput { body: axum::body::Body::from(bytes[..cut].to_vec()), pending: BytesMut::new(), seen_exit: false };
            let mut received = Vec::new();
            let failed = loop {
                match output.next().await {
                    Ok(Some(event)) => received.push(event),
                    Ok(None) => break false,
                    Err(error) => {
                        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
                        break true;
                    }
                }
            };
            assert_eq!(received, events[..expected_events]);
            assert_eq!(failed, cut < bytes.len(), "EOF before Exit must be an error");
        });
    }
}

#[cfg(all(test, target_os = "linux"))]
mod claim_tests {
    use super::*;
    // A removed Unix pathname no longer names a listening endpoint. Retaining
    // its claim must not make a different, newly created socket look shared
    // when the filesystem recycles an inode while old stream claims still live.
    #[test]
    fn removed_unix_sockets_do_not_claim_recycled_inodes() {
        let dir = tempfile::tempdir().unwrap();
        let mut retained = Vec::new();
        for index in 0..256 {
            let path = dir.path().join(format!("endpoint-{index}"));
            let socket = std::os::unix::net::UnixListener::bind(&path).unwrap();
            retained.push(claim(Endpoint::Unix(path.clone())).unwrap());
            drop(socket);
            std::fs::remove_file(path).unwrap();
        }
    }
}

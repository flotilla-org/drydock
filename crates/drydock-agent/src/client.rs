use crate::{
    frames::Frame,
    query::{AttachQuery, DigestQuery, DirQuery, LinkQuery, RemoveQuery, WithBlob, encode as query},
    rest::{encode_path, encode_segment},
    *,
};
use bytes::Bytes;
use drydock_transport::{Opener, Purpose, Transport, http2};
use http_body_util::{BodyExt, Empty, Full, StreamBody, combinators::UnsyncBoxBody};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{Arc, Mutex, OnceLock},
};
use tokio::{io::AsyncRead, task::JoinSet};

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
/// Stream a reader as a request body, 256 KiB at a time.
fn streamed(reader: impl AsyncRead + Send + 'static) -> RequestBody {
    use futures_util::TryStreamExt;
    let stream = tokio_util::io::ReaderStream::with_capacity(reader, 256 * 1024).map_ok(http_body::Frame::data);
    BodyExt::boxed_unsync(StreamBody::new(stream))
}
fn route(prefix: &str, path: &Path) -> io::Result<String> {
    if !path.is_absolute() {
        return Err(crate::error::context("request", path.display(), invalid("path must be absolute")));
    }
    Ok(format!("{prefix}{}", encode_path(path)))
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
        // Hello, upgrade and the upload protocol that carries an upgrade image
        // are the routes every generation keeps.
        let path = uri.split('?').next().unwrap_or(uri);
        let stable =
            matches!(path, "/hello" | "/upgrade" | "/upgrade/confirm") || path.starts_with("/blobs/") || path.starts_with("/uploads/");
        if !self.compatible && !stable {
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
/// A sha256 checked before it goes into a URL.
fn digest(sha256: &str) -> io::Result<&str> {
    check_sha256(sha256).map_err(|e| crate::error::context("request", sha256, e))?;
    Ok(sha256)
}
/// The draft version this client implements, and the upload request headers.
const INTEROP_VERSION: &str = "9";
fn upload_headers(complete: bool, content_type: &str) -> Vec<(&'static str, String)> {
    vec![
        ("upload-draft-interop-version", INTEROP_VERSION.to_owned()),
        ("upload-complete", if complete { "?1" } else { "?0" }.to_owned()),
        ("content-type", content_type.to_owned()),
    ]
}
/// An upload's offset and completeness from its headers.
fn progress(response: &http::Response<axum::body::Body>) -> (u64, bool) {
    let offset = header(response, "upload-offset").and_then(|v| v.parse().ok()).unwrap_or_default();
    (offset, header(response, "upload-complete").as_deref() == Some("?1"))
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
    /// form, never from the guest. Returns only a compatible, confirmed client;
    /// callers push configuration afterwards. Initial transport/hello errors
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
            let expected = format!("{:x}", Sha256::digest(executable));
            client.set_expected(expected.clone());
            // Only the build this host wants is confirmed. Another candidate
            // on probation is replaced below by activating the wanted one,
            // and was never installed.
            if client.is_compatible() {
                if client.hello.probation {
                    client.confirm_upgrade().await?;
                }
                return Ok(client);
            }
            let digest = client.put_upgrade(Bytes::copy_from_slice(executable)).await?;
            // Activation acknowledgement is advisory: re-exec can close the
            // stream before the response arrives. Only the next hello decides.
            let _ = client.activate_upgrade(&digest).await;
            drop(client);
            loop {
                match open().await {
                    Ok(transport) => match Self::connect(transport, &expected).await {
                        Ok(client) if client.is_compatible() => {
                            if client.hello.probation {
                                client.confirm_upgrade().await?;
                            }
                            return Ok(client);
                        }
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
            hello: Hello { fingerprint: String::new(), features: vec![], platform: None, boot_id: String::new(), probation: false },
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

    /// Start a process and return its handle. Attach to read its output.
    pub async fn spawn(&self, request: Exec) -> io::Result<Process> {
        let info: ProcessInfo = self.link.json("POST", "/processes", json_body(&request)?).await?;
        Ok(Process { link: self.link.clone(), info })
    }
    /// Start a process and read its output from the beginning.
    pub async fn exec(&self, request: Exec) -> io::Result<ExecOutput> {
        self.spawn(request).await?.output().await
    }
    /// Run a process to completion, collecting at most `limit` bytes of each
    /// stream, then forget its handle so the agent holds nothing for it.
    pub async fn run(&self, request: Exec, limit: usize) -> io::Result<(Vec<u8>, Vec<u8>, ExitStatus)> {
        let process = self.spawn(request).await?;
        let collected = process.output().await?.collect(limit).await;
        // Removing kills it when collection stopped early; an exited
        // handle is only forgotten.
        let removed = process.remove().await;
        let collected = collected?;
        removed?;
        Ok(collected)
    }
    /// A process started earlier on this agent, by ID.
    pub async fn process(&self, id: &str) -> io::Result<Process> {
        let info = self.link.json("GET", &format!("/processes/{}", encode_segment(id)), empty()).await?;
        Ok(Process { link: self.link.clone(), info })
    }
    pub async fn processes(&self) -> io::Result<Vec<ProcessInfo>> {
        self.link.json("GET", "/processes", empty()).await
    }

    /// Stream `content` to `path`, replacing it atomically.
    pub async fn write(&self, path: &Path, content: impl AsyncRead + Send + 'static, options: &FileOptions) -> io::Result<Written> {
        self.write_body(path, streamed(content), options, None).await
    }
    pub async fn write_bytes(&self, path: &Path, content: impl Into<Bytes>, options: &FileOptions) -> io::Result<Written> {
        self.write_body(path, full(content), options, None).await
    }
    /// Stream `content` to `path` only if the file still has `etag` (412
    /// otherwise, also when it is absent); `*` requires only that it exists.
    pub async fn write_if(
        &self,
        path: &Path,
        content: impl AsyncRead + Send + 'static,
        options: &FileOptions,
        etag: &str,
    ) -> io::Result<Written> {
        self.write_body(path, streamed(content), options, Some(etag)).await
    }
    async fn write_body(&self, path: &Path, body: RequestBody, options: &FileOptions, etag: Option<&str>) -> io::Result<Written> {
        let uri = format!("{}{}", route("/files", path)?, WithBlob { options, blob: None }.encode()?);
        let mut headers = vec![("content-type", "application/octet-stream".to_owned())];
        headers.extend(etag.map(|etag| ("if-match", etag.to_owned())));
        decode(self.link.send("PUT", &uri, &headers, body).await?, "PUT", &uri).await
    }
    /// Stream a whole file.
    pub async fn read(&self, path: &Path) -> io::Result<Download> {
        self.download(path, None, None).await
    }
    /// Stream `length` bytes from `start`, or to the end without a length.
    /// With `etag`, the read is refused (412) if the file has changed since.
    pub async fn read_range(&self, path: &Path, start: u64, length: Option<u64>, etag: Option<&str>) -> io::Result<Download> {
        let range = match length {
            Some(0) => return Err(invalid("a range must select at least one byte")),
            Some(length) => headers::Range::bytes(start..start + length),
            None => headers::Range::bytes(start..),
        };
        self.download(path, Some(range.map_err(invalid)?), etag).await
    }
    async fn download(&self, path: &Path, range: Option<headers::Range>, etag: Option<&str>) -> io::Result<Download> {
        use headers::HeaderMapExt;
        let uri = route("/files", path)?;
        let mut headers = Vec::new();
        if let Some(range) = range {
            let mut map = http::HeaderMap::new();
            map.typed_insert(range);
            headers.extend(map.get(http::header::RANGE).and_then(|v| v.to_str().ok()).map(|v| ("range", v.to_owned())));
        }
        if let Some(etag) = etag {
            headers.push(("if-match", etag.to_owned()));
        }
        let response = self.link.send("GET", &uri, &headers, empty()).await?;
        let length = header(&response, "content-length").and_then(|v| v.parse().ok()).unwrap_or_default();
        let etag = header(&response, "etag").unwrap_or_default();
        let range = response.headers().typed_get::<headers::ContentRange>().and_then(|r| Some((r.bytes_range()?, r.bytes_len()?)));
        let range = range.map(|((start, end), size)| (start, end, size));
        Ok(Download { length, etag, range, body: response.into_body(), received: 0 })
    }
    /// A whole file in memory, refused if it is longer than `limit`.
    pub async fn read_bytes(&self, path: &Path, limit: u64) -> io::Result<Vec<u8>> {
        let download = self.read(path).await?;
        if download.length > limit {
            return Err(crate::error::context(
                "file.read",
                path.display(),
                io::Error::new(io::ErrorKind::FileTooLarge, format!("file has {} bytes, more than {limit}", download.length)),
            ));
        }
        download.bytes().await
    }
    /// A file's size and entity tag, without its bytes.
    pub async fn head(&self, path: &Path) -> io::Result<(u64, String)> {
        let uri = route("/files", path)?;
        let response = self.link.send("HEAD", &uri, &[], empty()).await.map_err(|e| head_error(e, "file.read", path))?;
        let length = header(&response, "content-length").and_then(|v| v.parse().ok()).unwrap_or_default();
        Ok((length, header(&response, "etag").unwrap_or_default()))
    }
    pub async fn stat(&self, path: &Path) -> io::Result<Entry> {
        self.link.json("GET", &route("/entries", path)?, empty()).await
    }
    pub async fn list(&self, path: &Path) -> io::Result<Vec<Entry>> {
        self.link.json("GET", &route("/dirs", path)?, empty()).await
    }
    /// Remove a file, link or empty directory; `recursive` removes a tree.
    pub async fn remove(&self, path: &Path, recursive: bool) -> io::Result<()> {
        let uri = format!("{}{}", route("/entries", path)?, query(&RemoveQuery { recursive })?);
        self.link.empty("DELETE", &uri, empty()).await.map(drop)
    }
    pub async fn set_attributes(&self, path: &Path, attributes: &Attributes) -> io::Result<Entry> {
        self.link.json("PATCH", &route("/entries", path)?, json_body(attributes)?).await
    }
    /// Create a directory. An existing one is accepted unless `exclusive`.
    pub async fn create_dir(&self, path: &Path, options: &FileOptions) -> io::Result<Entry> {
        self.link.json("PUT", &format!("{}{}", route("/dirs", path)?, query(&DirQuery::from(options))?), empty()).await
    }
    /// Create a symlink at `path` pointing at `target`, atomically replacing
    /// any non-directory there unless `exclusive`.
    pub async fn symlink(&self, path: &Path, target: &Path, options: &FileOptions) -> io::Result<()> {
        let uri = format!("{}{}", route("/links", path)?, query(&LinkQuery::from(options))?);
        self.link.empty("PUT", &uri, json_body(&Link { target: target.into() })?).await.map(drop)
    }
    pub async fn rename(&self, rename: &Rename) -> io::Result<()> {
        self.link.empty("POST", "/renames", json_body(rename)?).await.map(drop)
    }
    /// Stream a tar archive into a new directory at `path`.
    pub async fn unpack(&self, path: &Path, archive: impl AsyncRead + Send + 'static, options: &TreeOptions) -> io::Result<Written> {
        digest(&options.sha256)?;
        let uri = format!("{}{}", route("/trees", path)?, WithBlob { options, blob: None }.encode()?);
        let response = self.link.send("PUT", &uri, &[("content-type", "application/x-tar".into())], streamed(archive)).await?;
        decode(response, "PUT", &uri).await
    }
    /// Unpack a completed upload, named by `options.sha256`, into `path`.
    pub async fn unpack_blob(&self, path: &Path, options: &TreeOptions) -> io::Result<Written> {
        digest(&options.sha256)?;
        let uri = format!("{}{}", route("/trees", path)?, WithBlob { options, blob: Some(options.sha256.clone()) }.encode()?);
        self.link.json("PUT", &uri, empty()).await
    }

    /// Upload `content`, all `length` bytes of the blob named by `sha256`, in
    /// one request. If it is interrupted, [`Client::resume_upload`] continues
    /// from what the agent kept.
    pub async fn upload(&self, sha256: &str, length: u64, content: impl AsyncRead + Send + 'static) -> io::Result<Written> {
        let (size, _) = self.create_upload(sha256, Some(length), content, true).await?;
        Ok(Written { sha256: sha256.into(), size })
    }
    /// Upload creation: start the upload of the blob named by `sha256` with
    /// `content`, declaring its `length` if known. With `complete`, `content`
    /// is the whole blob. Returns the offset reached and whether the upload
    /// is complete (its digest then checked).
    pub async fn create_upload(
        &self,
        sha256: &str,
        length: Option<u64>,
        content: impl AsyncRead + Send + 'static,
        complete: bool,
    ) -> io::Result<(u64, bool)> {
        let uri = format!("/blobs/{}", digest(sha256)?);
        let mut headers = upload_headers(complete, "application/octet-stream");
        headers.extend(length.map(|length| ("upload-length", length.to_string())));
        Ok(progress(&self.link.send("PUT", &uri, &headers, streamed(content)).await?))
    }
    /// Upload append: continue the upload at exactly `offset` with `content`,
    /// which with `complete` is the rest of the blob.
    pub async fn append_upload(
        &self,
        sha256: &str,
        offset: u64,
        content: impl AsyncRead + Send + 'static,
        complete: bool,
    ) -> io::Result<(u64, bool)> {
        let uri = format!("/uploads/{}", digest(sha256)?);
        let mut headers = upload_headers(complete, "application/partial-upload");
        headers.push(("upload-offset", offset.to_string()));
        Ok(progress(&self.link.send("PATCH", &uri, &headers, streamed(content)).await?))
    }
    /// How many bytes of the upload named by `sha256` the agent holds, and
    /// whether it is complete; (0, false) when there is no such upload.
    /// Asking ends any request still appending to it.
    pub async fn upload_offset(&self, sha256: &str) -> io::Result<(u64, bool)> {
        Ok(self.upload_state(sha256).await?.unwrap_or_default())
    }
    async fn upload_state(&self, sha256: &str) -> io::Result<Option<(u64, bool)>> {
        let uri = format!("/uploads/{}", digest(sha256)?);
        match self.link.send("HEAD", &uri, &upload_headers(false, "")[..1], empty()).await {
            Ok(response) => Ok(Some(progress(&response))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(head_error(error, "upload.stat", Path::new(sha256))),
        }
    }
    /// Upload or resume the blob named by `sha256` from a seekable source of
    /// `length` bytes: ask how far the agent got, then send the rest.
    pub async fn resume_upload<R>(&self, sha256: &str, length: u64, mut source: R) -> io::Result<(u64, bool)>
    where
        R: AsyncRead + tokio::io::AsyncSeek + Send + Unpin + 'static,
    {
        use tokio::io::AsyncSeekExt;
        match self.upload_state(sha256).await? {
            Some((offset, true)) => Ok((offset, true)),
            None => self.create_upload(sha256, Some(length), source, true).await,
            Some((offset, false)) => {
                source.seek(io::SeekFrom::Start(offset)).await?;
                self.append_upload(sha256, offset, source, true).await
            }
        }
    }
    /// Upload cancellation: discard an incomplete upload.
    pub async fn remove_upload(&self, sha256: &str) -> io::Result<()> {
        self.link.empty("DELETE", &format!("/uploads/{}", digest(sha256)?), empty()).await.map(drop)
    }
    /// Install a completed upload at `path`, as a write of its bytes would.
    pub async fn install_blob(&self, path: &Path, sha256: &str, options: &FileOptions) -> io::Result<Written> {
        let uri = format!("{}{}", route("/files", path)?, WithBlob { options, blob: Some(digest(sha256)?.to_owned()) }.encode()?);
        self.link.json("PUT", &uri, empty()).await
    }
    pub async fn blob_size(&self, sha256: &str) -> io::Result<Option<u64>> {
        match self.link.send("HEAD", &format!("/blobs/{}", digest(sha256)?), &[], empty()).await {
            Ok(response) => Ok(header(&response, "content-length").and_then(|v| v.parse().ok())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(head_error(error, "blob.stat", Path::new(sha256))),
        }
    }
    pub async fn remove_blob(&self, sha256: &str) -> io::Result<()> {
        self.link.empty("DELETE", &format!("/blobs/{}", digest(sha256)?), empty()).await.map(drop)
    }

    /// Upload then activate. Reconnect afterwards and verify the new hello
    /// fingerprint, then confirm, before using any generation-specific routes.
    pub async fn upgrade(&self, executable: impl Into<Bytes>) -> io::Result<()> {
        let digest = self.put_upgrade(executable.into()).await?;
        self.activate_upgrade(&digest).await
    }
    /// Put the image where activation finds it: a blob, uploaded resumably
    /// and digest-checked, unless the agent already holds it. Agents from
    /// before the blob store (hello without `uploads`, such as those baked
    /// into published tools images) take it whole through `PUT /upgrade`.
    /// That legacy path can go once no published tools image bakes such an
    /// agent.
    async fn put_upgrade(&self, executable: Bytes) -> io::Result<String> {
        let digest = format!("{:x}", Sha256::digest(&executable));
        if !self.hello.features.iter().any(|feature| feature == "uploads") {
            let response =
                self.link.send("PUT", "/upgrade", &[("content-type", "application/octet-stream".into())], full(executable)).await?;
            response.into_body().collect().await.map_err(|e| link_error("PUT /upgrade", e))?;
        } else if self.blob_size(&digest).await?.is_none() {
            self.upload(&digest, executable.len() as u64, std::io::Cursor::new(executable)).await?;
        }
        Ok(digest)
    }
    /// Activate the completed upload named by `sha256` as the next agent.
    pub async fn activate_upgrade(&self, sha256: &str) -> io::Result<()> {
        let uri = format!("/upgrade{}", query(&DigestQuery { sha256: digest(sha256)?.to_owned() })?);
        self.link.empty("POST", &uri, empty()).await.map(drop)
    }
    /// Make the running candidate the installed agent. Until then, the next
    /// ordinary start rolls back to the previous executable.
    pub async fn confirm_upgrade(&self) -> io::Result<()> {
        self.link.empty("POST", "/upgrade/confirm", empty()).await.map(drop)
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
/// HEAD replies carry no body, so a refusal has only its status.
fn head_error(error: io::Error, operation: &str, subject: &Path) -> io::Error {
    match AgentError::of(&error) {
        Some(agent) if agent.operation == "request" => {
            let mut agent = agent.clone();
            agent.operation = operation.into();
            agent.subject = subject.display().to_string();
            agent.into_io()
        }
        _ => error,
    }
}

/// A streamed file read.
pub struct Download {
    /// Bytes in this reply: the whole file, or the requested range.
    pub length: u64,
    pub etag: String,
    /// For a ranged read: first and last byte, and the file's size.
    pub range: Option<(u64, u64, u64)>,
    body: axum::body::Body,
    received: u64,
}
impl Download {
    /// The next chunk, or None at the end. A reply shorter than its length is
    /// an UnexpectedEof error.
    pub async fn chunk(&mut self) -> io::Result<Option<Bytes>> {
        loop {
            match self.body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.received += data.len() as u64;
                        return Ok(Some(data));
                    }
                }
                Some(Err(error)) => return Err(link_error("file download", error)),
                None if self.received < self.length => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("download ended after {} of {} bytes", self.received, self.length),
                    ));
                }
                None => return Ok(None),
            }
        }
    }
    pub async fn bytes(mut self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.length.min(64 * 1024 * 1024) as usize);
        while let Some(chunk) = self.chunk().await? {
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
    /// Copy the download to a writer, holding one chunk at a time.
    pub async fn copy_to(mut self, writer: &mut (impl tokio::io::AsyncWrite + Unpin)) -> io::Result<u64> {
        use tokio::io::AsyncWriteExt;
        let mut total = 0;
        while let Some(chunk) = self.chunk().await? {
            writer.write_all(&chunk).await?;
            total += chunk.len() as u64;
        }
        writer.flush().await?;
        Ok(total)
    }
}

/// A process on the agent. Dropping the handle leaves the process running.
pub struct Process {
    link: Control,
    info: ProcessInfo,
}
impl Process {
    pub fn id(&self) -> &str {
        &self.info.id
    }
    pub fn pid(&self) -> u32 {
        self.info.pid
    }
    fn uri(&self, tail: &str) -> String {
        format!("/processes/{}{tail}", encode_segment(&self.info.id))
    }
    pub async fn info(&self) -> io::Result<ProcessInfo> {
        self.link.json("GET", &self.uri(""), empty()).await
    }
    /// Read output from the beginning of what the agent still holds.
    pub async fn output(&self) -> io::Result<ExecOutput> {
        self.attach(0, 0).await
    }
    /// Become the process's reader, skipping bytes already received. A later
    /// attach takes over; this reader then ends with UnexpectedEof.
    pub async fn attach(&self, stdout: u64, stderr: u64) -> io::Result<ExecOutput> {
        let response =
            self.link.send("GET", &self.uri(&format!("/output{}", query(&AttachQuery { stdout, stderr })?)), &[], empty()).await?;
        Ok(ExecOutput::new(self.info.id.clone(), response.into_body(), [stdout, stderr]))
    }
    /// Stream `input` to stdin and close it. The process must have been
    /// started with `stdin: true`.
    pub async fn write_stdin(&self, input: impl AsyncRead + Send + 'static) -> io::Result<()> {
        self.link.send("PUT", &self.uri("/stdin"), &[("content-type", "application/octet-stream".into())], streamed(input)).await.map(drop)
    }
    pub async fn write_stdin_bytes(&self, input: impl Into<Bytes>) -> io::Result<()> {
        self.link.send("PUT", &self.uri("/stdin"), &[("content-type", "application/octet-stream".into())], full(input)).await.map(drop)
    }
    /// Send a signal to the process group.
    pub async fn signal(&self, signal: i32) -> io::Result<()> {
        self.link.empty("POST", &self.uri("/signals"), json_body(&crate::server::Signal { signal })?).await.map(drop)
    }
    pub async fn kill(&self) -> io::Result<()> {
        self.signal(libc::SIGKILL).await
    }
    /// Kill the process group if it is running and forget the handle.
    pub async fn remove(self) -> io::Result<()> {
        self.link.empty("DELETE", &self.uri(""), empty()).await.map(drop)
    }
}

/// A process's framed output: stdout and stderr chunks in the order the agent
/// read them, then the exit status.
pub struct ExecOutput {
    id: String,
    frames: tokio_util::codec::FramedRead<
        tokio_util::io::StreamReader<futures_util::stream::BoxStream<'static, io::Result<Bytes>>, Bytes>,
        tokio_util::codec::LengthDelimitedCodec,
    >,
    offsets: [u64; 2],
    seen_exit: bool,
}
impl ExecOutput {
    fn new(id: String, body: axum::body::Body, offsets: [u64; 2]) -> Self {
        use futures_util::{StreamExt, TryStreamExt};
        let context = format!("process {id} output");
        let bytes = TryStreamExt::map_err(body.into_data_stream(), move |e| link_error(context.clone(), e)).boxed();
        let frames = tokio_util::codec::FramedRead::new(tokio_util::io::StreamReader::new(bytes), crate::frames::codec());
        Self { id, frames, offsets, seen_exit: false }
    }
    pub fn process_id(&self) -> &str {
        &self.id
    }
    /// Bytes received so far on stdout and stderr, including any the agent
    /// reported skipping; pass them to [`Process::attach`] to resume.
    pub fn offsets(&self) -> (u64, u64) {
        (self.offsets[0], self.offsets[1])
    }
    pub async fn next(&mut self) -> io::Result<Option<ExecEvent>> {
        if self.seen_exit {
            return Ok(None);
        }
        use futures_util::StreamExt;
        let frame = match self.frames.next().await {
            Some(Ok(frame)) => Frame::decode(frame.freeze())?,
            // The codec's report of a stream that ended inside a frame; the
            // truncation test (`exec_requires_exit_at_truncation_boundaries`)
            // fails if tokio-util ever words it differently.
            Some(Err(error)) if error.kind() == io::ErrorKind::Other && error.to_string() == "bytes remaining on stream" => {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("process {} output ended mid-frame", self.id)));
            }
            Some(Err(error)) => return Err(error),
            None => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("process {} output ended without an exit", self.id))),
        };
        Ok(Some(match frame {
            Frame::Output { stderr, offset, bytes } => {
                self.offsets[stderr as usize] = offset + bytes.len() as u64;
                if stderr { ExecEvent::Stderr(bytes) } else { ExecEvent::Stdout(bytes) }
            }
            Frame::Exit(status) => {
                self.seen_exit = true;
                ExecEvent::Exit(status)
            }
        }))
    }
    /// Collect everything to the exit status, refusing more than `limit`
    /// bytes on either stream.
    pub async fn collect(mut self, limit: usize) -> io::Result<(Vec<u8>, Vec<u8>, ExitStatus)> {
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        while let Some(event) = self.next().await? {
            let (buffer, bytes) = match event {
                ExecEvent::Stdout(bytes) => (&mut stdout, bytes),
                ExecEvent::Stderr(bytes) => (&mut stderr, bytes),
                ExecEvent::Exit(status) => return Ok((stdout, stderr, status)),
            };
            if buffer.len() + bytes.len() > limit {
                return Err(io::Error::new(io::ErrorKind::FileTooLarge, format!("process {} output exceeds {limit} bytes", self.id)));
            }
            buffer.extend_from_slice(&bytes);
        }
        unreachable!("next returns the exit before None")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // HTTP-body boundary fake: truncate a valid stream at every drawn byte.
    // Only a stream containing a complete exit frame may end successfully.
    #[hegel::test]
    fn exec_requires_exit_at_truncation_boundaries(tc: hegel::TestCase) {
        use hegel::generators as gs;
        let frames = [
            Frame::Output { stderr: false, offset: 0, bytes: Bytes::from_static(&[0, 128, 255]) },
            Frame::Output { stderr: true, offset: 0, bytes: Bytes::from_static(b"err") },
            Frame::Exit(ExitStatus { code: Some(0), signal: None, timed_out: false }),
        ];
        let events = [
            ExecEvent::Stdout(Bytes::from_static(&[0, 128, 255])),
            ExecEvent::Stderr(Bytes::from_static(b"err")),
            ExecEvent::Exit(ExitStatus { code: Some(0), signal: None, timed_out: false }),
        ];
        let encoded: Vec<Vec<u8>> = frames.iter().map(|f| f.encode().to_vec()).collect();
        let bytes: Vec<u8> = encoded.concat();
        let cut = tc.draw(gs::integers::<usize>().min_value(0).max_value(bytes.len()));
        let mut ends = 0;
        let expected_events = encoded
            .iter()
            .take_while(|frame| {
                ends += frame.len();
                ends <= cut
            })
            .count();
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let mut output = ExecOutput::new("1".into(), axum::body::Body::from(bytes[..cut].to_vec()), [0, 0]);
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

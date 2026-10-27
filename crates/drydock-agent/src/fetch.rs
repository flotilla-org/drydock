//! Downloads by digest into the digest-named staging: an upstream URL or an
//! OCI registry blob. Requests leave through the agent's configured egress
//! like any other guest traffic: with egress, each connection is a CONNECT on
//! a fresh stream of the egress upstream forward, trusting the configured CA
//! bundle; without it, the agent connects directly and trusts the system's
//! roots. Bytes stream to disk as they arrive and are hashed on the way; an
//! interrupted body resumes from the staged length with `Range` when the
//! source honours it, and restarts otherwise.
use crate::{ErrorKind, RegistryCredential, egress, store::free_space};
use bytes::Bytes;
use drydock_transport::{ByteStream, Opener};
use http::{StatusCode, header};
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use sha2::{Digest, Sha256};
use std::{io, path::Path, sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, sync::Mutex as AsyncMutex};
use url::Url;

/// Connecting, including any CONNECT and TLS handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Waiting for a response head, or for the next bytes of a body.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Requests for one source's bytes, resumes and restarts included.
const ATTEMPTS: u32 = 5;
const REDIRECTS: usize = 10;

/// How the agent reaches the network for a fetch.
#[derive(Clone)]
pub(crate) enum Network {
    Direct,
    /// Through the configured egress upstream forward, as captured guest
    /// traffic goes; `ca` is the configured trust bundle.
    Upstream {
        opener: Arc<AsyncMutex<Opener>>,
        id: String,
        ca: String,
    },
}

/// Why one source gave no bytes: the step that failed and how.
#[derive(Debug)]
pub(crate) struct Failure {
    pub step: &'static str,
    pub kind: ErrorKind,
    pub message: String,
    /// Another source cannot help, as when the disk is full.
    pub fatal: bool,
}
impl Failure {
    pub(crate) fn new(step: &'static str, kind: ErrorKind, message: impl Into<String>) -> Self {
        Self { step, kind, message: message.into(), fatal: false }
    }
    fn io(step: &'static str, error: io::Error) -> Self {
        let mut message = error.to_string();
        let mut source = std::error::Error::source(&error);
        while let Some(cause) = source {
            message = format!("{message}: {cause}");
            source = cause.source();
        }
        Self::new(step, error.kind().into(), message)
    }
    fn disk(error: io::Error) -> Self {
        Self { fatal: true, ..Self::io("disk", error) }
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.step, self.message)
    }
}

/// A source's URL as it may appear in an error: no user information, and no
/// query, which can carry a signature.
pub(crate) fn redact(url: &Url) -> String {
    let mut shown = url.clone();
    let _ = shown.set_username("");
    let _ = shown.set_password(None);
    shown.set_query(None);
    shown.set_fragment(None);
    shown.to_string()
}

/// Where a source's bytes are, and how to authenticate for them.
pub(crate) struct Remote {
    pub url: Url,
    pub auth: Auth,
}
pub(crate) enum Auth {
    None,
    /// The distribution API's token flow: a 401 challenge is answered once,
    /// anonymously or with the caller's credential.
    Oci {
        repository: String,
        credential: Option<RegistryCredential>,
        header: Option<String>,
        answered: bool,
    },
}
impl Remote {
    pub(crate) fn upstream(url: &str) -> Result<Self, Failure> {
        let url = Url::parse(url).map_err(|e| Failure::new("request", ErrorKind::InvalidInput, format!("not a URL: {e}")))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(Failure::new("request", ErrorKind::InvalidInput, "only http and https URLs with a host can be fetched"));
        }
        Ok(Self { url, auth: Auth::None })
    }
    /// The blob `sha256:<digest>` of `repository` on `registry`, a host
    /// (reached over HTTPS) or a base URL.
    pub(crate) fn oci(registry: &str, repository: &str, credential: Option<RegistryCredential>, digest: &str) -> Result<Self, Failure> {
        let refuse = |message: &str| Failure::new("request", ErrorKind::InvalidInput, message);
        let valid =
            |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
        if !repository.split('/').all(|part| valid(part) && part != "." && part != "..") {
            return Err(refuse("repository must be lowercase path components of [a-z0-9._-]"));
        }
        let base = if registry.contains("://") { registry.to_owned() } else { format!("https://{registry}") };
        let mut remote = Self::upstream(&base).map_err(|_| refuse("registry must be a host or an http(s) base URL"))?;
        if remote.url.path() != "/" || remote.url.query().is_some() {
            return Err(refuse("registry must be a host or an http(s) base URL"));
        }
        if credential.is_some() && remote.url.scheme() != "https" {
            return Err(refuse("credentials are only sent to an https registry"));
        }
        remote.url = remote.url.join(&format!("/v2/{repository}/blobs/sha256:{digest}")).map_err(|_| refuse("unusable registry URL"))?;
        let header = match &credential {
            Some(RegistryCredential::Bearer { token }) => Some(format!("Bearer {token}")),
            _ => None,
        };
        remote.auth = Auth::Oci { repository: repository.to_owned(), credential, header, answered: false };
        Ok(remote)
    }
    fn authorization(&self) -> Option<String> {
        match &self.auth {
            Auth::Oci { header, .. } => header.clone(),
            Auth::None => None,
        }
    }
}

pub(crate) struct Fetcher {
    network: Network,
    tls: Option<Arc<rustls::ClientConfig>>,
}
impl Fetcher {
    pub(crate) fn new(network: Network) -> Self {
        Self { network, tls: None }
    }
    fn tls(&mut self) -> Result<Arc<rustls::ClientConfig>, Failure> {
        if let Some(config) = &self.tls {
            return Ok(config.clone());
        }
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let mut roots = rustls::RootCertStore::empty();
        match &self.network {
            Network::Upstream { ca, .. } => {
                for certificate in CertificateDer::pem_slice_iter(ca.as_bytes()) {
                    let certificate = certificate
                        .map_err(|e| Failure::new("tls", ErrorKind::InvalidData, format!("unreadable egress CA bundle: {e}")))?;
                    let _ = roots.add(certificate);
                }
                if roots.is_empty() {
                    return Err(Failure::new("tls", ErrorKind::InvalidData, "the egress configuration carries no CA certificate"));
                }
            }
            Network::Direct => {
                roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
                // A guest without a system trust store still verifies.
                if roots.is_empty() {
                    roots.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
                }
            }
        }
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| Failure::new("tls", ErrorKind::Other, e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        self.tls = Some(config.clone());
        Ok(config)
    }
    async fn open(&mut self, url: &Url) -> Result<ByteStream, Failure> {
        let host = url.host_str().unwrap_or_default();
        let port = url.port_or_known_default().unwrap_or(443);
        let authority = format!("{host}:{port}");
        let stream: ByteStream = match &self.network {
            Network::Direct => {
                let connected = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(&authority)).await;
                let stream = connected
                    .map_err(|_| Failure::new("connect", ErrorKind::TimedOut, format!("{authority}: timed out")))?
                    .map_err(|e| Failure::new("connect", e.kind().into(), format!("{authority}: {e}")))?;
                Box::new(stream)
            }
            Network::Upstream { opener, id, .. } => {
                let mut remote = egress::upstream(opener, id.clone())
                    .await
                    .map_err(|e| Failure { message: format!("egress upstream {id} unavailable: {e}"), ..Failure::io("egress", e) })?;
                match egress::connect(&mut remote, &authority).await {
                    Ok(()) => remote,
                    Err(error) if error.get_ref().is_some_and(|inner| inner.is::<egress::Refused>()) => {
                        let refused = error.get_ref().map(ToString::to_string).unwrap_or_default();
                        return Err(Failure::new("egress", ErrorKind::PermissionDenied, format!("{authority}: {refused}")));
                    }
                    Err(error) => return Err(Failure { message: format!("{authority}: {error}"), ..Failure::io("egress", error) }),
                }
            }
        };
        if url.scheme() != "https" {
            return Ok(stream);
        }
        let name = match url.host() {
            Some(url::Host::Domain(domain)) => rustls::pki_types::ServerName::try_from(domain.to_owned())
                .map_err(|e| Failure::new("tls", ErrorKind::InvalidInput, format!("{host}: {e}")))?,
            Some(url::Host::Ipv4(ip)) => rustls::pki_types::ServerName::IpAddress(std::net::IpAddr::V4(ip).into()),
            Some(url::Host::Ipv6(ip)) => rustls::pki_types::ServerName::IpAddress(std::net::IpAddr::V6(ip).into()),
            None => return Err(Failure::new("tls", ErrorKind::InvalidInput, "no host")),
        };
        let connector = tokio_rustls::TlsConnector::from(self.tls()?);
        let tls = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, stream))
            .await
            .map_err(|_| Failure::new("tls", ErrorKind::TimedOut, format!("{authority}: handshake timed out")))?
            .map_err(|e| Failure::new("tls", ErrorKind::InvalidData, format!("{authority}: {e}")))?;
        Ok(Box::new(tls))
    }
    /// One GET on its own connection.
    async fn get(&mut self, url: &Url, headers: &[(&'static str, String)]) -> Result<http::Response<Incoming>, Failure> {
        let stream = self.open(url).await?;
        let shown = redact(url);
        let (mut sender, connection) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|e| Failure::new("connect", ErrorKind::ConnectionAborted, format!("{shown}: {e}")))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut target = url.path().to_owned();
        if let Some(query) = url.query() {
            target = format!("{target}?{query}");
        }
        let host = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_owned(),
        };
        let mut request = http::Request::get(target)
            .header(header::HOST, host)
            .header(header::USER_AGENT, concat!("drydock-agent/", env!("CARGO_PKG_VERSION")))
            .header(header::ACCEPT_ENCODING, "identity");
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let request =
            request.body(Empty::<Bytes>::new()).map_err(|e| Failure::new("request", ErrorKind::InvalidInput, format!("{shown}: {e}")))?;
        tokio::time::timeout(IDLE_TIMEOUT, sender.send_request(request))
            .await
            .map_err(|_| Failure::new("http", ErrorKind::TimedOut, format!("{shown}: no response")))?
            .map_err(|e| Failure::new("http", ErrorKind::ConnectionAborted, format!("{shown}: {e}")))
    }
    /// A GET following redirects. `authorization` goes only to the origin it
    /// was meant for, never to a host a redirect names.
    async fn follow(
        &mut self,
        url: &Url,
        headers: &[(&'static str, String)],
        authorization: Option<String>,
    ) -> Result<http::Response<Incoming>, Failure> {
        let mut current = url.clone();
        for _ in 0..=REDIRECTS {
            let mut sent = headers.to_vec();
            if let Some(authorization) = &authorization
                && current.origin() == url.origin()
            {
                sent.push(("authorization", authorization.clone()));
            }
            let response = self.get(&current, &sent).await?;
            if !response.status().is_redirection() || response.status() == StatusCode::NOT_MODIFIED {
                return Ok(response);
            }
            let location = response.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()).ok_or_else(|| {
                Failure::new(
                    "http",
                    ErrorKind::InvalidData,
                    format!("{} from {}: a redirect without Location", response.status(), redact(&current)),
                )
            })?;
            let next = current.join(location).map_err(|e| Failure::new("http", ErrorKind::InvalidData, format!("bad redirect: {e}")))?;
            if !matches!(next.scheme(), "http" | "https") {
                return Err(Failure::new("http", ErrorKind::InvalidData, format!("redirect to an unsupported scheme {}", next.scheme())));
            }
            current = next;
        }
        Err(Failure::new("http", ErrorKind::InvalidData, format!("more than {REDIRECTS} redirects from {}", redact(url))))
    }
    /// A GET of the source, answering one registry challenge.
    async fn authorized(&mut self, remote: &mut Remote, headers: &[(&'static str, String)]) -> Result<http::Response<Incoming>, Failure> {
        loop {
            let response = self.follow(&remote.url, headers, remote.authorization()).await?;
            let challenge = response.headers().get(header::WWW_AUTHENTICATE).and_then(|v| v.to_str().ok()).map(str::to_owned);
            let answerable = matches!(&remote.auth, Auth::Oci { answered: false, credential, .. } if !matches!(credential, Some(RegistryCredential::Bearer { .. })));
            if response.status() != StatusCode::UNAUTHORIZED || !answerable {
                return Ok(response);
            }
            let challenge = challenge.ok_or_else(|| Failure::new("auth", ErrorKind::PermissionDenied, "401 without a challenge"))?;
            let answer = self.answer(remote, &challenge).await?;
            if let Auth::Oci { header, answered, .. } = &mut remote.auth {
                *header = Some(answer);
                *answered = true;
            }
        }
    }
    /// The Authorization a registry's challenge asks for: a token from its
    /// realm (Bearer), or the caller's own Basic credential.
    async fn answer(&mut self, remote: &Remote, challenge: &str) -> Result<String, Failure> {
        let Auth::Oci { repository, credential, .. } = &remote.auth else { unreachable!("only registries are answered") };
        let basic = match credential {
            Some(RegistryCredential::Basic { username, password }) => {
                Some(format!("Basic {}", base64(format!("{username}:{password}").as_bytes())))
            }
            _ => None,
        };
        let (scheme, parameters) = parse_challenge(challenge);
        let refuse = |message: String| Failure::new("auth", ErrorKind::PermissionDenied, message);
        if scheme.eq_ignore_ascii_case("basic") {
            return basic.ok_or_else(|| refuse("the registry asks for Basic credentials and none were given".into()));
        }
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(refuse(format!("unsupported challenge scheme {scheme:?}")));
        }
        let parameter = |name: &str| parameters.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.clone());
        let realm = parameter("realm").ok_or_else(|| refuse("Bearer challenge without a realm".into()))?;
        let mut token = remote.url.join(&realm).map_err(|e| refuse(format!("bad token realm: {e}")))?;
        if !matches!(token.scheme(), "http" | "https") || (basic.is_some() && token.scheme() != "https") {
            return Err(refuse(format!("token realm {} is not usable", redact(&token))));
        }
        {
            let mut query = token.query_pairs_mut();
            if let Some(service) = parameter("service") {
                query.append_pair("service", &service);
            }
            query.append_pair("scope", &parameter("scope").unwrap_or_else(|| format!("repository:{repository}:pull")));
        }
        let response = self.follow(&token, &[], basic).await?;
        let status = response.status();
        if !status.is_success() {
            return Err(refuse(format!("token request to {} answered {status}", redact(&token))));
        }
        let body = tokio::time::timeout(IDLE_TIMEOUT, http_body_util::Limited::new(response.into_body(), 1 << 20).collect())
            .await
            .map_err(|_| refuse("token response timed out".into()))?
            .map_err(|e| refuse(format!("token response: {e}")))?
            .to_bytes();
        #[derive(serde::Deserialize)]
        struct Token {
            token: Option<String>,
            access_token: Option<String>,
        }
        let parsed: Token = serde_json::from_slice(&body).map_err(|e| refuse(format!("token response is not JSON: {e}")))?;
        let token =
            parsed.token.or(parsed.access_token).filter(|t| !t.is_empty()).ok_or_else(|| refuse("token response has no token".into()))?;
        Ok(format!("Bearer {token}"))
    }

    /// Stage the source's bytes at `staging` until they hash to `digest`,
    /// continuing from what is already staged. Returns their length. A
    /// mismatch discards the staged bytes; when the download had resumed
    /// from earlier bytes it is first tried once more from nothing, since
    /// those may have been the wrong ones.
    pub(crate) async fn download(&mut self, remote: &mut Remote, staging: &Path, digest: &str) -> Result<u64, Failure> {
        let mut fresh = false;
        loop {
            let (mut hasher, mut offset) = staged(staging).await.map_err(Failure::disk)?;
            let resumed = offset > 0;
            self.transfer(remote, staging, &mut hasher, &mut offset).await?;
            let actual = format!("{:x}", hasher.finalize());
            if actual == digest {
                return Ok(offset);
            }
            tokio::fs::remove_file(staging).await.map_err(Failure::disk)?;
            if resumed && !fresh {
                fresh = true;
                continue;
            }
            return Err(Failure::new(
                "verify",
                ErrorKind::DigestMismatch,
                format!("expected sha256 {digest}, received {offset} bytes with sha256 {actual}; nothing was stored"),
            ));
        }
    }
    /// Request and receive the rest of the bytes, resuming or restarting
    /// after an interruption, until the body ends complete.
    async fn transfer(&mut self, remote: &mut Remote, staging: &Path, hasher: &mut Sha256, offset: &mut u64) -> Result<(), Failure> {
        let shown = redact(&remote.url);
        let mut last = None;
        for _ in 0..ATTEMPTS {
            let range = (*offset > 0).then(|| ("range", format!("bytes={offset}-")));
            let response = self.authorized(remote, range.as_slice()).await?;
            let status = response.status();
            let total = match status {
                StatusCode::PARTIAL_CONTENT => match content_range(response.headers()) {
                    Some((start, total)) if start == *offset => total,
                    // A range other than the one asked for: start again.
                    _ => {
                        restart(staging, hasher, offset).await?;
                        continue;
                    }
                },
                StatusCode::OK => {
                    // The source ignored the range: its body is the whole
                    // artifact, so the staged bytes go.
                    if *offset > 0 {
                        restart(staging, hasher, offset).await?;
                    }
                    response.headers().get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok())
                }
                StatusCode::RANGE_NOT_SATISFIABLE if *offset > 0 => {
                    restart(staging, hasher, offset).await?;
                    continue;
                }
                status => return Err(Failure::new("http", status_kind(status), format!("{shown} answered {status}"))),
            };
            if let Some(total) = total {
                if total < *offset {
                    restart(staging, hasher, offset).await?;
                    continue;
                }
                if let Some(free) = free_space(staging.parent().unwrap())
                    && total - *offset > free
                {
                    let message = format!("{} more bytes do not fit in the {free} free on the store's filesystem", total - *offset);
                    return Err(Failure { fatal: true, ..Failure::new("disk", ErrorKind::StorageFull, message) });
                }
            }
            let mut file =
                tokio::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(staging).await.map_err(Failure::disk)?;
            match receive(response.into_body(), &mut file, hasher, offset, total).await {
                Ok(()) => {
                    file.sync_all().await.map_err(Failure::disk)?;
                    match total {
                        Some(total) if *offset < total => last = Some(format!("the body ended at {offset} of {total} bytes")),
                        _ => return Ok(()),
                    }
                }
                Err(Stop::Disk(error)) => return Err(Failure::disk(error)),
                Err(Stop::Interrupted(message)) => {
                    let _ = file.sync_all().await;
                    last = Some(message);
                }
            }
        }
        Err(Failure::new(
            "download",
            ErrorKind::ConnectionAborted,
            format!("{shown}: interrupted {ATTEMPTS} times; {offset} bytes are staged for a later fetch: {}", last.unwrap_or_default()),
        ))
    }
}
fn status_kind(status: StatusCode) -> ErrorKind {
    match status.as_u16() {
        401 | 403 => ErrorKind::PermissionDenied,
        404 | 410 => ErrorKind::NotFound,
        _ => ErrorKind::Other,
    }
}
/// The hash and length of what is already staged.
async fn staged(staging: &Path) -> io::Result<(Sha256, u64)> {
    let staging = staging.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut hasher = Sha256::new();
        let length = match std::fs::File::open(&staging) {
            Ok(mut file) => io::copy(&mut file, &mut hasher)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error),
        };
        Ok((hasher, length))
    })
    .await?
}
/// Drop the staged bytes: the source is sending the artifact from its start.
async fn restart(staging: &Path, hasher: &mut Sha256, offset: &mut u64) -> Result<(), Failure> {
    match tokio::fs::remove_file(staging).await {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(Failure::disk(error)),
        _ => {}
    }
    *hasher = Sha256::new();
    *offset = 0;
    Ok(())
}
/// The first byte and complete length of a `Content-Range: bytes a-b/n`.
fn content_range(headers: &http::HeaderMap) -> Option<(u64, Option<u64>)> {
    let value = headers.get(header::CONTENT_RANGE)?.to_str().ok()?.trim().strip_prefix("bytes ")?;
    let (span, total) = value.split_once('/')?;
    let start = span.split_once('-')?.0.trim().parse().ok()?;
    Some((start, total.trim().parse().ok()))
}
enum Stop {
    Interrupted(String),
    Disk(io::Error),
}
/// Stream a body to the staged file, hashing it, holding at most one frame
/// and the write buffer. Stops at a stalled or broken body with what
/// arrived written, and refuses bytes past the expected `total`.
async fn receive(
    mut body: Incoming,
    file: &mut tokio::fs::File,
    hasher: &mut Sha256,
    offset: &mut u64,
    total: Option<u64>,
) -> Result<(), Stop> {
    let mut writer = tokio::io::BufWriter::with_capacity(256 * 1024, file);
    let ended = loop {
        let frame = match tokio::time::timeout(IDLE_TIMEOUT, body.frame()).await {
            Err(_) => break Some(format!("no bytes for {} s", IDLE_TIMEOUT.as_secs())),
            Ok(None) => break None,
            Ok(Some(Err(error))) => break Some(format!("the body broke off: {error}")),
            Ok(Some(Ok(frame))) => frame,
        };
        let Ok(data) = frame.into_data() else { continue };
        if total.is_some_and(|total| *offset + data.len() as u64 > total) {
            break Some(format!("the body runs past its {} bytes", total.unwrap_or_default()));
        }
        writer.write_all(&data).await.map_err(Stop::Disk)?;
        hasher.update(&data);
        *offset += data.len() as u64;
    };
    writer.flush().await.map_err(Stop::Disk)?;
    match ended {
        None => Ok(()),
        Some(message) => Err(Stop::Interrupted(message)),
    }
}
/// `scheme param="value", param=token` as (scheme, parameters).
fn parse_challenge(challenge: &str) -> (String, Vec<(String, String)>) {
    let challenge = challenge.trim();
    let (scheme, mut rest) = challenge.split_once(' ').unwrap_or((challenge, ""));
    let mut parameters = Vec::new();
    loop {
        rest = rest.trim_start_matches([' ', ',']);
        let Some((name, after)) = rest.split_once('=') else { break };
        let after = after.trim_start();
        let (value, remainder) = if let Some(quoted) = after.strip_prefix('"') {
            let mut value = String::new();
            let mut chars = quoted.char_indices();
            let mut end = quoted.len();
            while let Some((index, c)) = chars.next() {
                match c {
                    '\\' => value.extend(chars.next().map(|(_, c)| c)),
                    '"' => {
                        end = index + 1;
                        break;
                    }
                    c => value.push(c),
                }
            }
            (value, &quoted[end..])
        } else {
            let end = after.find(',').unwrap_or(after.len());
            (after[..end].trim().to_owned(), &after[end..])
        };
        parameters.push((name.trim().to_owned(), value));
        rest = remainder;
    }
    (scheme.to_owned(), parameters)
}
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8) | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Endpoint;
    use drydock_transport::{Limits, Purpose, Transport};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The egress upstream's policy: a CONNECT proxy (the host side of the
    /// vessel's egress forward) that refuses `blocked.test` with an RFC 9209
    /// Proxy-Status naming the policy, and tunnels `origin.test:443` to a TLS
    /// origin whose certificate only the test CA vouches for.
    async fn egress(dir: &Path) -> (Transport, Network) {
        let proxy = dir.join("proxy");
        let listener = tokio::net::UnixListener::bind(&proxy).unwrap();
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        tokio::spawn(async move {
            use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
            let chain = vec![CertificateDer::from_pem_slice(include_bytes!("../tests/fixtures/origin.pem")).unwrap()];
            let key = PrivateKeyDer::from_pem_slice(include_bytes!("../tests/fixtures/origin-key.pem")).unwrap();
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            loop {
                let (stream, _) = origin.accept().await.unwrap();
                let mut tls = acceptor.accept(stream).await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(tls.read_u8().await.unwrap());
                }
                assert!(head.starts_with(b"GET /harness HTTP/1.1\r\n"), "{}", String::from_utf8_lossy(&head));
                tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nharness").await.unwrap();
                tls.shutdown().await.unwrap();
            }
        });
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        head.push(stream.read_u8().await.unwrap());
                    }
                    let head = String::from_utf8(head).unwrap();
                    if head.starts_with("CONNECT origin.test:443 ") {
                        stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
                        let mut upstream = tokio::net::TcpStream::connect(origin_address).await.unwrap();
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                    } else {
                        let refusal = "HTTP/1.1 403 Forbidden\r\nProxy-Status: flotilla; error=destination_ip_prohibited; \
                                       details=\"not in the vessel's egress policy\"\r\n\r\n";
                        stream.write_all(refusal.as_bytes()).await.unwrap();
                    }
                });
            }
        });
        // The vessel's transport: the agent opens the egress forward by ID,
        // and the host serves it to the proxy, as `Client` does.
        let (a, b) = tokio::io::duplex(1 << 16);
        let (host, guest) =
            tokio::join!(Transport::yamux(Box::new(a), true, Limits::default()), Transport::yamux(Box::new(b), false, Limits::default()));
        let mut host = host.unwrap();
        let guest = guest.unwrap();
        let endpoint = Endpoint::Unix(proxy);
        tokio::spawn(async move {
            while let Ok(Some(incoming)) = host.accept().await {
                if let Purpose::Forward { id } = incoming.purpose {
                    let endpoint = endpoint.clone();
                    tokio::spawn(async move { crate::forward::serve(incoming.stream, &id, Some(&endpoint)).await });
                }
            }
        });
        let ca = String::from_utf8(include_bytes!("../tests/fixtures/egress-ca.pem").to_vec()).unwrap();
        let opener = Arc::new(AsyncMutex::new(guest.opener.clone()));
        (guest, Network::Upstream { opener, id: "egress".into(), ca })
    }

    // With egress configured, a fetch goes out through the egress upstream
    // like any other guest traffic, by name: a destination the policy blocks
    // is refused at the egress step with the policy's own reason, and an
    // allowed HTTPS source is verified against the configured CA bundle.
    #[tokio::test]
    async fn fetches_leave_through_egress_and_a_blocked_source_names_the_policy() {
        let dir = tempfile::tempdir().unwrap();
        let (_guest, network) = egress(dir.path()).await;
        let mut fetcher = Fetcher::new(network);
        let staging = dir.path().join("staging");
        let digest = format!("{:x}", Sha256::digest(b"harness"));

        let mut blocked = Remote::upstream("https://blocked.test/harness").unwrap();
        let failure = fetcher.download(&mut blocked, &staging, &digest).await.unwrap_err();
        assert_eq!((failure.step, failure.kind), ("egress", ErrorKind::PermissionDenied), "{failure}");
        assert!(failure.message.contains("blocked.test:443") && failure.message.contains("not in the vessel's egress policy"), "{failure}");
        assert!(!staging.exists());

        let mut allowed = Remote::upstream("https://origin.test/harness").unwrap();
        assert_eq!(fetcher.download(&mut allowed, &staging, &digest).await.unwrap(), 7);
        assert_eq!(std::fs::read(&staging).unwrap(), b"harness");
    }
}

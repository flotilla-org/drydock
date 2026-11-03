//! The agent's TCP listener, for providers that reach only a guest TCP port
//! (a port proxy or a tunnel). The handshake each connection must pass, and
//! the client's side of it, are [`drydock_transport::tcp`]'s: a wrong or
//! missing token is answered 401, any other request 404. Either way the
//! connection closes without reaching the agent's API.
use crate::error::context;
use bytes::Bytes;
pub use drydock_transport::tcp::{CONNECT_PATH, PROTOCOL, Token, connect};
use drydock_transport::{ByteStream, Listener};
use http_body_util::Full;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, header};
use hyper_util::rt::TokioIo;
use std::{io, net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::mpsc, task::JoinSet};

/// Also accepted, for proxies that pass only a WebSocket upgrade. The bytes
/// after the 101 are still raw.
const WEBSOCKET: &str = "websocket";
/// A connection that has not completed its handshake by then is closed.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
/// Handshakes in progress at once; further connections wait in the backlog.
const HANDSHAKES: usize = 64;
/// Longer token files are refused rather than read whole.
const TOKEN_FILE_LIMIT: u64 = 1024;

/// Reads the token file at `path`, which must be a regular file owned by
/// the agent's effective user with mode 0600. Anything else is refused,
/// so a token other guest users could read or replace is never trusted.
pub fn read_token(path: &Path) -> io::Result<Token> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    let result = (|| {
        // O_NONBLOCK: opening a FIFO must not wait for a writer.
        let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
        let metadata = file.metadata()?;
        admissible(
            metadata.is_file(),
            std::os::unix::fs::MetadataExt::uid(&metadata),
            std::os::unix::fs::MetadataExt::mode(&metadata),
            rustix::process::geteuid().as_raw(),
        )
        .map_err(|reason| io::Error::new(io::ErrorKind::PermissionDenied, reason))?;
        let mut text = String::new();
        file.take(TOKEN_FILE_LIMIT + 1).read_to_string(&mut text)?;
        if text.len() as u64 > TOKEN_FILE_LIMIT {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "tcp token file is too long"));
        }
        Token::parse(&text)
    })();
    result.map_err(|e| context("tcp.token", path.display(), e))
}

/// The token the file at `path` holds, written first if it holds none. A
/// valid token in an acceptable file (see [`read_token`]) is kept; a missing
/// file is created with `supplied`, or a fresh token, at mode 0600; anything
/// else (garbage, a wrong mode or owner, a symlink or FIFO) is replaced. The
/// file is complete on appearance, and concurrent callers serialize on a lock
/// file beside it, so all of them return the one token the file ends up with.
pub fn provision_token(path: &Path, supplied: Option<Token>) -> io::Result<Token> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let result = (|| {
        let name = path.file_name().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tcp token file needs a file name"))?;
        let directory = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let beside = |suffix: &str| {
            let mut name = name.to_owned();
            name.push(suffix);
            directory.join(name)
        };
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(beside(".lock"))?;
        // A FIFO planted here must fail fast, not block the open or the lock.
        if !lock.metadata()?.is_file() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "tcp token lock must be a regular file"));
        }
        lock.lock()?;
        if let Ok(token) = read_token(path) {
            return Ok(token);
        }
        let token = match supplied {
            Some(token) => token,
            None => Token::generate()?,
        };
        // A pid can repeat across container restarts; under the lock, a leftover
        // of that name is stale, so it is removed rather than trusted.
        let staging = beside(&format!(".{}", std::process::id()));
        let _ = std::fs::remove_file(&staging);
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&staging)?;
        let written = file.write_all(format!("{}\n", token.secret()).as_bytes()).and_then(|()| file.sync_all());
        // rename replaces a symlink or special file itself, never what it names.
        let placed = written.and_then(|()| std::fs::rename(&staging, path));
        if placed.is_err() {
            let _ = std::fs::remove_file(&staging);
        }
        placed?;
        // Make the rename durable where the directory is on persistent storage.
        std::fs::File::open(directory).and_then(|d| d.sync_all())?;
        read_token(path)
    })();
    result.map_err(|e| context("tcp.token", path.display(), e))
}

/// The line `--print-token` writes, for the host that reads the token back.
pub fn token_line(token: &Token) -> String {
    format!("drydock-tcp-token {}", token.secret())
}

fn admissible(regular: bool, owner: u32, mode: u32, euid: u32) -> Result<(), &'static str> {
    if !regular {
        Err("tcp token file must be a regular file")
    } else if owner != euid {
        Err("tcp token file must be owned by the agent's user")
    } else if mode & 0o7777 != 0o600 {
        Err("tcp token file must have mode 0600")
    } else {
        Ok(())
    }
}

/// Refusals are logged at most once a second, with how many went unlogged
/// since, so a guest user hammering the port cannot flood the agent's log.
#[derive(Default)]
struct Refusals(std::sync::Mutex<(Option<std::time::Instant>, u64)>);
impl Refusals {
    fn record(&self, peer: SocketAddr) {
        let mut state = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = std::time::Instant::now();
        if state.0.is_none_or(|last| now.duration_since(last) >= Duration::from_secs(1)) {
            let suppressed = std::mem::take(&mut state.1);
            state.0 = Some(now);
            tracing::warn!(%peer, suppressed, "tcp connection refused: missing or wrong token");
        } else {
            state.1 += 1;
            tracing::debug!(%peer, "tcp connection refused: missing or wrong token");
        }
    }
}

/// What the agent answers a handshake request.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Switch protocols, answering with this `Upgrade` token.
    Connect(&'static str),
    Unauthorized,
    NotFound,
}

fn verdict(method: &Method, path: &str, headers: &HeaderMap, token: &Token) -> Verdict {
    if method != Method::GET || path != CONNECT_PATH {
        return Verdict::NotFound;
    }
    let mut authorizations = headers.get_all(header::AUTHORIZATION).iter();
    let presented = match (authorizations.next(), authorizations.next()) {
        (Some(value), None) => value.as_bytes(),
        _ => b"",
    };
    let credential = match presented.split_at_checked(7) {
        Some((scheme, credential)) if scheme.eq_ignore_ascii_case(b"bearer ") => credential,
        _ => b"",
    };
    // Digest even an absent credential, so its absence takes as long.
    if !token.admits(credential) {
        return Verdict::Unauthorized;
    }
    let lists = |name: header::HeaderName, item: &str| {
        headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| value.split(',').any(|listed| listed.trim().eq_ignore_ascii_case(item)))
    };
    if !lists(header::CONNECTION, "upgrade") {
        return Verdict::NotFound;
    }
    if lists(header::UPGRADE, PROTOCOL) {
        Verdict::Connect(PROTOCOL)
    } else if lists(header::UPGRADE, WEBSOCKET) {
        Verdict::Connect(WEBSOCKET)
    } else {
        Verdict::NotFound
    }
}

fn refusal(status: StatusCode, error: &str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(serde_json::json!({ "error": error }).to_string())));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
    response.headers_mut().insert(header::CONNECTION, header::HeaderValue::from_static("close"));
    response
}

/// Serves one connection's handshake. `Some` is the connection, switched to
/// raw bytes; `None` is a connection refused or closed before it asked.
async fn handshake(stream: tokio::net::TcpStream, peer: SocketAddr, token: &Token, refusals: &Refusals) -> io::Result<Option<ByteStream>> {
    let (admitted, upgrade) = tokio::sync::oneshot::channel();
    let admitted = std::sync::Mutex::new(Some(admitted));
    let service = hyper::service::service_fn(|mut request: Request<hyper::body::Incoming>| {
        let response = match verdict(request.method(), request.uri().path(), request.headers(), token) {
            Verdict::Connect(protocol) => {
                if let Some(admitted) = admitted.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take() {
                    let _ = admitted.send(hyper::upgrade::on(&mut request));
                }
                let mut response = Response::new(Full::default());
                *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                response.headers_mut().insert(header::CONNECTION, header::HeaderValue::from_static("upgrade"));
                response.headers_mut().insert(header::UPGRADE, header::HeaderValue::from_static(protocol));
                response
            }
            Verdict::Unauthorized => {
                refusals.record(peer);
                refusal(StatusCode::UNAUTHORIZED, "unauthorized")
            }
            Verdict::NotFound => {
                tracing::debug!(%peer, method = %request.method(), path = request.uri().path(), "tcp connection refused: not a handshake");
                refusal(StatusCode::NOT_FOUND, "not found")
            }
        };
        std::future::ready(Ok::<_, std::convert::Infallible>(response))
    });
    hyper::server::conn::http1::Builder::new()
        .keep_alive(false)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
        .map_err(io::Error::other)?;
    match upgrade.await {
        Ok(upgrade) => Ok(Some(drydock_transport::http::upgraded(upgrade).await?)),
        Err(_) => Ok(None),
    }
}

/// The agent's TCP listener. Connections it yields have passed the handshake;
/// it handshakes several at once, so a slow client delays no other.
pub struct TokenListener {
    admitted: mpsc::Receiver<io::Result<ByteStream>>,
    local: SocketAddr,
    acceptor: tokio::task::JoinHandle<()>,
}
impl Drop for TokenListener {
    fn drop(&mut self) {
        self.acceptor.abort();
    }
}
impl TokenListener {
    pub async fn bind(address: SocketAddr, token: Token) -> io::Result<Self> {
        let listener = TcpListener::bind(address).await.map_err(|e| context("tcp.bind", address, e))?;
        if !address.ip().is_loopback() {
            tracing::warn!(
                %address,
                "tcp listener beyond loopback: the token and the agent's traffic cross the guest network unencrypted, so the provider's proxy must carry them"
            );
        }
        let local = listener.local_addr()?;
        let (sender, admitted) = mpsc::channel(16);
        Ok(Self { admitted, local, acceptor: tokio::spawn(accept(listener, token, sender, Limits::default())) })
    }
    /// The bound address, with the port chosen when bound to port 0.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
}
#[async_trait::async_trait]
impl Listener for TokenListener {
    async fn accept(&mut self) -> io::Result<ByteStream> {
        self.admitted.recv().await.unwrap_or_else(|| Err(io::Error::new(io::ErrorKind::NotConnected, "tcp listener stopped")))
    }
}

/// How long a handshake may take, and how many run at once.
#[derive(Clone, Copy)]
struct Limits {
    deadline: Duration,
    handshakes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self { deadline: HANDSHAKE_DEADLINE, handshakes: HANDSHAKES }
    }
}

async fn accept(listener: TcpListener, token: Token, admitted: mpsc::Sender<io::Result<ByteStream>>, limits: Limits) {
    let mut handshakes = JoinSet::new();
    let refusals = Arc::new(Refusals::default());
    let mut backoff = Duration::from_millis(100);
    loop {
        tokio::select! {
            Some(_) = handshakes.join_next(), if !handshakes.is_empty() => {}
            _ = admitted.closed() => return,
            accepted = listener.accept(), if handshakes.len() < limits.handshakes => match accepted {
                Ok((stream, peer)) => {
                    backoff = Duration::from_millis(100);
                    let (token, admitted, refusals) = (token.clone(), admitted.clone(), refusals.clone());
                    handshakes.spawn(async move {
                        match tokio::time::timeout(limits.deadline, handshake(stream, peer, &token, &refusals)).await {
                            Ok(Ok(Some(stream))) => {
                                // Holds its handshake slot until the agent takes
                                // the connection: when the agent is slow to accept,
                                // new connections wait in the kernel's backlog
                                // rather than piling up here.
                                let _ = admitted.send(Ok(stream)).await;
                            }
                            Ok(Ok(None)) => {}
                            Ok(Err(error)) => tracing::debug!(%peer, %error, "tcp handshake failed"),
                            Err(_) => tracing::debug!(%peer, "tcp handshake timed out"),
                        }
                    });
                }
                Err(error) if crate::server::retryable(&error) => {
                    tracing::warn!(%error, "tcp listener accept failed");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(1));
                }
                Err(error) => {
                    let _ = admitted.send(Err(error)).await;
                    return;
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::generators as gs;

    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    // No file: one is created at mode 0600 with the supplied token, or a fresh
    // one, and read_token accepts it. A valid file is kept whatever is supplied.
    #[test]
    fn provisioning_creates_and_keeps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tcp.token");
        let supplied = Token::generate().unwrap();
        assert_eq!(provision_token(&path, Some(supplied.clone())).unwrap(), supplied);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(read_token(&path).unwrap(), supplied);
        assert_eq!(provision_token(&path, Some(Token::generate().unwrap())).unwrap(), supplied);
        assert_eq!(provision_token(&path, None).unwrap(), supplied);
        let fresh = dir.path().join("fresh.token");
        let generated = provision_token(&fresh, None).unwrap();
        assert_eq!(read_token(&fresh).unwrap(), generated);
        assert_ne!(generated, supplied);
    }

    // Garbage, a short token, a valid token in a file others could read, a
    // symlink, and a FIFO are each replaced, never trusted or followed.
    #[test]
    fn provisioning_replaces_what_read_token_refuses() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tcp.token");
        let old = Token::generate().unwrap();
        let broken: [&dyn Fn(); 5] = [
            &|| std::fs::write(&path, "not a token!\n").unwrap(),
            &|| std::fs::write(&path, "").unwrap(),
            &|| {
                std::fs::write(&path, format!("{}\n", old.secret())).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            },
            &|| {
                let target = dir.path().join("target");
                std::fs::write(&target, format!("{}\n", old.secret())).unwrap();
                std::os::unix::fs::symlink(&target, &path).unwrap();
            },
            &|| rustix::fs::mknodat(rustix::fs::CWD, &path, rustix::fs::FileType::Fifo, rustix::fs::Mode::from_raw_mode(0o600), 0).unwrap(),
        ];
        for (index, break_it) in broken.iter().enumerate() {
            let _ = std::fs::remove_file(&path);
            break_it();
            let token = provision_token(&path, None).unwrap();
            assert_ne!(token, old, "case {index}");
            assert_eq!(read_token(&path).unwrap(), token, "case {index}");
            assert_eq!(mode(&path), 0o600, "case {index}");
        }
        // The symlink's target was left alone.
        assert_eq!(read_token(&dir.path().join("target")).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read_to_string(dir.path().join("target")).unwrap().trim(), old.secret());
    }

    // Starts racing over a missing or garbage file all end with the one token
    // the file holds, and leave only the token file and its lock.
    #[test]
    fn concurrent_provisioning_agrees_on_one_token() {
        for garbage in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("tcp.token");
            if garbage {
                std::fs::write(&path, "garbage").unwrap();
            }
            let tokens: Vec<_> = (0..16)
                .map(|_| {
                    let path = path.clone();
                    std::thread::spawn(move || provision_token(&path, None).unwrap())
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|t| t.join().unwrap())
                .collect();
            assert!(tokens.iter().all(|t| *t == read_token(&path).unwrap()), "garbage: {garbage}");
            let mut left: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
            left.sort();
            assert_eq!(left, ["tcp.token", "tcp.token.lock"]);
        }
    }

    // A FIFO planted as the lock fails at once instead of blocking the start.
    #[test]
    fn a_fifo_lock_is_refused_not_waited_on() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("tcp.token.lock");
        rustix::fs::mknodat(rustix::fs::CWD, &lock, rustix::fs::FileType::Fifo, rustix::fs::Mode::from_raw_mode(0o600), 0).unwrap();
        assert!(provision_token(&dir.path().join("tcp.token"), None).is_err());
    }

    #[test]
    fn the_printed_line_names_the_token() {
        let token = Token::generate().unwrap();
        assert_eq!(token_line(&token), format!("drydock-tcp-token {}", token.secret()));
    }

    // A token file is trusted only as a regular file of the agent's user with
    // mode 0600 exactly: every other mode is refused on a real file, a
    // directory or FIFO is refused, and so is a file of another owner.
    #[hegel::test]
    fn token_files_must_be_private_regular_files(tc: hegel::TestCase) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tcp.token");
        std::fs::write(&path, format!("{}\n", Token::generate().unwrap().secret())).unwrap();
        let mode = tc.draw(gs::sampled_from(vec![0o600, 0o400, 0o640, 0o644, 0o700, 0o606, 0o4600, 0o660]));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let actual = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        let read = read_token(&path);
        assert_eq!(read.is_ok(), actual == 0o600, "mode {actual:o}: {read:?}");
        if actual != 0o600 {
            assert!(read.unwrap_err().to_string().contains("tcp.token"));
        }
        let euid = rustix::process::geteuid().as_raw();
        assert!(admissible(true, euid, 0o100600, euid).is_ok());
        assert!(admissible(true, euid.wrapping_add(1), 0o100600, euid).is_err());
        assert!(admissible(false, euid, 0o600, euid).is_err());
        assert!(read_token(dir.path()).is_err());
        let fifo = dir.path().join("fifo");
        rustix::fs::mknodat(rustix::fs::CWD, &fifo, rustix::fs::FileType::Fifo, rustix::fs::Mode::from_raw_mode(0o600), 0).unwrap();
        assert!(read_token(&fifo).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_token(&link).is_err());
    }

    // A connection that sends no handshake is closed at the deadline, and
    // only so many handshakes run at once: one more connection gets no answer
    // until a slot frees, then switches as usual. Real time, small limits.
    #[tokio::test]
    async fn idle_handshakes_are_bounded_in_time_and_number() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let limits = Limits { deadline: Duration::from_millis(300), handshakes: 4 };
        let token = Token::generate().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, mut admitted) = mpsc::channel(16);
        tokio::spawn(accept(listener, token.clone(), sender, limits));
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(stream) = admitted.recv().await {
                held.push(stream);
            }
        });
        let mut idle = Vec::new();
        for _ in 0..limits.handshakes {
            idle.push(tokio::net::TcpStream::connect(address).await.unwrap());
        }
        let mut waiting = tokio::net::TcpStream::connect(address).await.unwrap();
        let request = format!(
            "GET /v1/connect HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: drydock-agent\r\nAuthorization: Bearer {}\r\n\r\n",
            token.secret()
        );
        waiting.write_all(request.as_bytes()).await.unwrap();
        let started = std::time::Instant::now();
        // The idle handshakes started before this one connected, so none has
        // freed its slot before the deadline has passed since then.
        let mut byte = [0u8; 1];
        assert!(tokio::time::timeout(limits.deadline / 2, waiting.read(&mut byte)).await.is_err(), "one more waits for a slot");
        for stream in &mut idle {
            let mut rest = Vec::new();
            let read = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut rest)).await;
            assert!(matches!(read, Ok(Ok(0))), "an idle handshake is closed at its deadline: {read:?}");
        }
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(tokio::time::timeout(Duration::from_secs(10), waiting.read_u8()).await.unwrap().unwrap());
        }
        assert!(head.starts_with(b"HTTP/1.1 101 "), "{}", String::from_utf8_lossy(&head));
        assert!(started.elapsed() >= limits.deadline / 2);
    }

    // Refusals within a second of a logged one only count, and the next one
    // logged after it reports that count.
    #[test]
    fn refusals_are_logged_at_most_once_a_second() {
        let refusals = Refusals::default();
        let peer = "127.0.0.1:1".parse().unwrap();
        for _ in 0..5 {
            refusals.record(peer);
        }
        assert_eq!(refusals.0.lock().unwrap().1, 4);
        refusals.0.lock().unwrap().0 = Some(std::time::Instant::now() - Duration::from_secs(1));
        refusals.record(peer);
        assert_eq!(refusals.0.lock().unwrap().1, 0);
    }

    // Only `GET /v1/connect` with Connection: upgrade, an accepted Upgrade
    // token and the right bearer token connects. The credential is checked
    // before anything else about a handshake request, so probing without it
    // learns nothing but 401.
    #[hegel::test]
    fn handshake_requests_connect_only_with_the_token(tc: hegel::TestCase) {
        let token = Token::generate().unwrap();
        let method = [Method::GET, Method::POST, Method::CONNECT][tc.draw(gs::integers::<usize>().max_value(2))].clone();
        let path = tc.draw(gs::sampled_from(vec![CONNECT_PATH, "/hello", "/v1/connect/", "/"]));
        let credential = tc.draw(gs::sampled_from(vec![
            Some(format!("Bearer {}", token.secret())),
            Some(format!("bearer {}", token.secret())),
            Some(format!("Bearer {}x", token.secret())),
            Some(format!("Basic {}", token.secret())),
            Some("Bearer ".to_owned()),
            None,
        ]));
        let duplicated = tc.draw(gs::booleans());
        let connection = tc.draw(gs::sampled_from(vec![Some("Upgrade"), Some("keep-alive, upgrade"), Some("close"), None]));
        let upgrade =
            tc.draw(gs::sampled_from(vec![Some("drydock-agent"), Some("WebSocket"), Some("h2c, drydock-agent"), Some("h2c"), None]));
        let mut headers = HeaderMap::new();
        for (name, value) in [(header::AUTHORIZATION, credential.as_deref()), (header::CONNECTION, connection), (header::UPGRADE, upgrade)]
        {
            if let Some(value) = value {
                headers.append(name.clone(), value.parse().unwrap());
                if name == header::AUTHORIZATION && duplicated {
                    headers.append(name, value.parse().unwrap());
                }
            }
        }
        let authorized =
            credential.as_deref().is_some_and(|c| c[..7].eq_ignore_ascii_case("bearer ") && &c[7..] == token.secret()) && !duplicated;
        let expected = if method != Method::GET || path != CONNECT_PATH {
            Verdict::NotFound
        } else if !authorized {
            Verdict::Unauthorized
        } else if connection.is_none_or(|c| !c.to_lowercase().contains("upgrade")) {
            Verdict::NotFound
        } else {
            match upgrade {
                Some(u) if u.contains("drydock-agent") => Verdict::Connect(PROTOCOL),
                Some("WebSocket") => Verdict::Connect(WEBSOCKET),
                _ => Verdict::NotFound,
            }
        };
        assert_eq!(verdict(&method, path, &headers, &token), expected);
    }
}

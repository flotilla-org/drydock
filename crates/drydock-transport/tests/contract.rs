use axum::{Router, routing::get};
use bytes::Bytes;
use drydock_transport::{Limits, Purpose, Transport, http2, native::UnixConnections, ssh};
use http_body_util::{BodyExt, Full};
use std::{io, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    task::{JoinHandle, JoinSet},
};

#[derive(Clone, Copy, Debug)]
enum Kind {
    Unix,
    Ssh,
    Yamux,
}
struct Pair {
    host: Transport,
    guest: Transport,
    _dir: tempfile::TempDir,
    tasks: Vec<JoinHandle<()>>,
}
impl Drop for Pair {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
async fn pair(kind: Kind) -> Pair {
    let dir = tempfile::tempdir().unwrap();
    let mut tasks = Vec::new();
    let (host, guest) = match kind {
        Kind::Yamux => {
            let (a, b) = tokio::io::duplex(4096);
            let (a, b) = tokio::join!(
                Transport::yamux(Box::new(a), true, Limits::default()),
                Transport::yamux(Box::new(b), false, Limits::default())
            );
            (a.unwrap(), b.unwrap())
        }
        Kind::Unix => {
            let hp = dir.path().join("host");
            let gp = dir.path().join("guest");
            let hl = UnixListener::bind(&hp).unwrap();
            let gl = UnixListener::bind(&gp).unwrap();
            (
                Transport::native(Arc::new(UnixConnections::new(hl, &gp)), Limits::default()).unwrap(),
                Transport::native(Arc::new(UnixConnections::new(gl, &hp)), Limits::default()).unwrap(),
            )
        }
        Kind::Ssh => {
            let gp = dir.path().join("guest").to_str().unwrap().to_owned();
            let rp = dir.path().join("reverse").to_str().unwrap().to_owned();
            let listener = UnixListener::bind(&gp).unwrap();
            let (config, child) = ssh_server(dir.path(), &gp, &rp).await;
            tasks.push(tokio::spawn(async move {
                let mut child = child;
                let _ = child.wait().await;
            }));
            let host = ssh::connect(config, Limits::default()).await.unwrap();
            assert!(std::path::Path::new(&rp).exists(), "connect must confirm the remote forward before returning");
            let guest = Transport::native(Arc::new(UnixConnections::new(listener, rp)), Limits::default()).unwrap();
            (host, guest)
        }
    };
    Pair { host, guest, _dir: dir, tasks }
}
// Real OpenSSH test server at the provider boundary, with disposable host and
// user keys. It runs as the current user and never reads ambient SSH config.
async fn ssh_server(dir: &std::path::Path, guest: &str, reverse: &str) -> (ssh::SshConfig, tokio::process::Child) {
    use std::process::Stdio;
    use tokio::process::Command;
    for name in ["host_key", "user_key"] {
        let result = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(dir.join(name))
            .status()
            .await
            .expect("install openssh-client: ssh-keygen is required by the SSH contract tests");
        assert!(result.success());
    }
    let user = Command::new("id").arg("-un").output().await.unwrap();
    let user = String::from_utf8(user.stdout).unwrap().trim().to_owned();
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let config_path = dir.join("sshd_config");
    std::fs::write(&config_path, format!("Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\nPidFile {}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin yes\nAllowUsers {user}\nAllowStreamLocalForwarding yes\nStreamLocalBindUnlink yes\n", dir.join("host_key").display(), dir.join("user_key.pub").display(), dir.join("sshd.pid").display())).unwrap();
    let sshd = std::env::var("DRYDOCK_TEST_SSHD").unwrap_or_else(|_| "/usr/sbin/sshd".into());
    let log = std::fs::File::create(dir.join("sshd.log")).unwrap();
    let mut child = Command::new(sshd)
        .args(["-D", "-e", "-f"])
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .kill_on_drop(true)
        .spawn()
        .expect("install openssh-server or set DRYDOCK_TEST_SSHD");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(child.try_wait().unwrap().is_none(), "sshd exited: {}", std::fs::read_to_string(dir.join("sshd.log")).unwrap());
            if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (
        ssh::SshConfig {
            connect_timeout: Duration::from_secs(5),
            host: "127.0.0.1".into(),
            port,
            user,
            host_key: std::fs::read_to_string(dir.join("host_key.pub")).unwrap().trim().into(),
            identity_file: dir.join("user_key"),
            agent_socket: guest.into(),
            reverse_socket: reverse.into(),
        },
        child,
    )
}
fn purposes() -> Vec<Purpose> {
    vec![Purpose::Control, Purpose::Forward { id: "crew/α".into() }, Purpose::Forward { id: "service".into() }]
}
async fn transfer(from: &Transport, to: &mut Transport, purpose: Purpose, payload: &[u8]) {
    let mut outgoing = from.open(purpose.clone()).await.unwrap();
    let mut incoming = to.accept().await.unwrap().unwrap();
    assert_eq!(incoming.purpose, purpose);
    outgoing.write_all(payload).await.unwrap();
    outgoing.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    incoming.stream.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, payload);
    // Half-close preserves traffic in the reverse direction.
    incoming.stream.write_all(b"reply").await.unwrap();
    incoming.stream.shutdown().await.unwrap();
    bytes.clear();
    outgoing.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"reply");
}

// ADR 0070: every purpose routes in both directions, preserving arbitrary raw
// bytes and half-close. Duplicate purposes are separate streams.
async fn routing_contract(kind: Kind) {
    let mut p = pair(kind).await;
    for purpose in purposes().into_iter().chain(purposes()) {
        transfer(&p.host, &mut p.guest, purpose.clone(), b"\0arbitrary\xffpayload").await;
        transfer(&p.guest, &mut p.host, purpose, b"").await;
    }
}

// ADR 0070: a slow raw stream must not hold up either long-lived link. This
// contract also checks yamux's per-stream flow control and concurrent HTTP/2 calls.
async fn isolation_contract(kind: Kind) {
    for reverse in [false, true] {
        let mut p = pair(kind).await;
        let purpose = Purpose::Forward { id: "slow".into() };
        let mut raw = if reverse { p.guest.open(purpose).await.unwrap() } else { p.host.open(purpose).await.unwrap() };
        let _unread = if reverse { p.host.accept().await.unwrap().unwrap() } else { p.guest.accept().await.unwrap().unwrap() };
        let writer = tokio::spawn(async move { raw.write_all(&vec![7; 16 * 1024 * 1024]).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!writer.is_finished(), "fixture must actually backpressure the raw stream");
        let host_opener = p.host.opener.clone();
        let guest_opener = p.guest.opener.clone();
        for (from, to, purpose) in [(host_opener, &mut p.guest, Purpose::Control), (guest_opener, &mut p.host, Purpose::Control)] {
            let (client, driver) = http2::connect(&from, purpose).await.unwrap();
            let incoming = to.accept().await.unwrap().unwrap();
            let server = tokio::spawn(http2::serve(incoming, Router::new().route("/hello", get(|| async { "hello" }))));
            let mut calls = JoinSet::new();
            for _ in 0..12 {
                let mut client = client.clone();
                calls.spawn(async move {
                    let response = client
                        .send_request(hyper::Request::builder().uri("http://agent/hello").body(Full::new(Bytes::new())).unwrap())
                        .await
                        .unwrap();
                    assert_eq!(response.version(), hyper::Version::HTTP_2);
                    assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), "hello");
                });
            }
            while let Some(call) = calls.join_next().await {
                call.unwrap();
            }
            driver.abort();
            server.abort();
        }
        assert!(!writer.is_finished());
        writer.abort();
    }
}
macro_rules! contract {
    ($name:ident, $kind:expr, $contract:ident) => {
        #[tokio::test]
        async fn $name() {
            tokio::time::timeout(Duration::from_secs(20), $contract($kind)).await.expect("contract timed out");
        }
    };
}
contract!(unix_routes, Kind::Unix, routing_contract);
contract!(ssh_routes, Kind::Ssh, routing_contract);
contract!(yamux_routes, Kind::Yamux, routing_contract);
contract!(unix_isolation, Kind::Unix, isolation_contract);
contract!(ssh_isolation, Kind::Ssh, isolation_contract);
contract!(yamux_isolation, Kind::Yamux, isolation_contract);

// Generated operation sequences exercise both opening directions and every
// purpose; the routing and byte conservation invariants hold after every step.
#[hegel::test]
fn generated_bidirectional_routes(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let count = tc.draw(gs::integers::<usize>().min_value(1).max_value(10));
    let operations: Vec<_> = (0..count)
        .map(|_| {
            (
                tc.draw(gs::booleans()),
                tc.draw(gs::integers::<usize>().min_value(0).max_value(purposes().len() - 1)),
                tc.draw(gs::integers::<usize>().min_value(0).max_value(4096)),
            )
        })
        .collect();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            for kind in [Kind::Unix, Kind::Ssh, Kind::Yamux] {
                let mut p = pair(kind).await;
                for &(reverse, tag, length) in &operations {
                    let purpose = purposes()[tag].clone();
                    let data: Vec<_> = (0..length).map(|i| i as u8).collect();
                    if reverse {
                        transfer(&p.guest, &mut p.host, purpose, &data).await;
                    } else {
                        transfer(&p.host, &mut p.guest, purpose, &data).await;
                    }
                }
            }
        })
        .await
        .unwrap();
    });
}

// Native negotiation is per connection: an unfinished or malformed preface
// cannot block a valid subsequent stream. A cancelled accept loses no stream.
#[tokio::test]
async fn native_partial_header_and_cancelled_accept() {
    let mut p = pair(Kind::Unix).await;
    let _partial = UnixStream::connect(p._dir.path().join("guest")).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(10), p.guest.accept()).await.is_err());
    tokio::time::timeout(Duration::from_secs(2), transfer(&p.host, &mut p.guest, Purpose::Control, b"ok")).await.unwrap();
    let mut invalid = UnixStream::connect(p._dir.path().join("guest")).await.unwrap();
    invalid.write_all(b"wrong").await.unwrap();
    let error = p.guest.accept().await.err().unwrap();
    assert_eq!(error.scope, drydock_transport::ErrorScope::Connection);
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    transfer(&p.host, &mut p.guest, Purpose::Control, b"still healthy").await;
}

// Every native kind can carry the yamux fallback, using the same connection
// preface detection and purpose routing as direct single-stream connections.
async fn fallback_contract() {
    let mut p = pair(Kind::Unix).await;
    let stream = UnixStream::connect(p._dir.path().join("guest")).await.unwrap();
    let mut mux = Transport::yamux(Box::new(stream), true, Limits::default()).await.unwrap();
    for purpose in purposes() {
        transfer(&mux, &mut p.guest, purpose.clone(), b"fallback").await;
        transfer(&p.guest, &mut mux, purpose, b"reverse fallback").await;
    }
}

// Both sides may open many streams at once; each target and payload remains
// attached to its own stream, including duplicate purpose headers.
async fn concurrent_contract(kind: Kind) {
    let mut p = pair(kind).await;
    let mut tasks = JoinSet::new();
    for opener in [p.host.opener.clone(), p.guest.opener.clone()] {
        tasks.spawn(async move {
            let mut writers = JoinSet::new();
            for i in 0..16u8 {
                let opener = opener.clone();
                writers.spawn(async move {
                    let mut stream = opener.open(Purpose::Forward { id: format!("service-{i}") }).await.unwrap();
                    stream.write_all(&[i]).await.unwrap();
                    stream.shutdown().await.unwrap();
                });
            }
            while let Some(result) = writers.join_next().await {
                result.unwrap();
            }
        });
    }
    for peer in [&mut p.host, &mut p.guest] {
        let mut seen = Vec::new();
        for _ in 0..16 {
            let mut incoming = peer.accept().await.unwrap().unwrap();
            let mut bytes = Vec::new();
            incoming.stream.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes.len(), 1);
            assert_eq!(incoming.purpose, Purpose::Forward { id: format!("service-{}", bytes[0]) });
            seen.push(bytes[0]);
        }
        seen.sort();
        assert_eq!(seen, (0..16).collect::<Vec<_>>());
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
}
contract!(unix_concurrent, Kind::Unix, concurrent_contract);
contract!(ssh_concurrent, Kind::Ssh, concurrent_contract);
contract!(yamux_concurrent, Kind::Yamux, concurrent_contract);

// The reach recipe pins the host key and the vessel identity key. An unknown
// host or a rejected identity never yields a usable transport.
#[tokio::test]
async fn ssh_rejects_wrong_host_and_identity_keys() {
    for wrong_host in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let guest = dir.path().join("guest");
        let reverse = dir.path().join("reverse");
        let (mut config, mut child) = ssh_server(dir.path(), guest.to_str().unwrap(), reverse.to_str().unwrap()).await;
        if wrong_host {
            config.host_key = std::fs::read_to_string(dir.path().join("user_key.pub")).unwrap().trim().into();
        } else {
            config.identity_file = dir.path().join("host_key");
        }
        let result = ssh::connect(config, Limits::default()).await;
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::ConnectionAborted);
        child.kill().await.unwrap();
    }
}

// Dropping the transport terminates its owned SSH session, closing the remote
// listener. No forwarding process survives its vessel transport.
#[tokio::test]
async fn ssh_transport_drop_closes_session() {
    let dir = tempfile::tempdir().unwrap();
    let guest = dir.path().join("guest");
    let reverse = dir.path().join("reverse");
    let (config, mut child) = ssh_server(dir.path(), guest.to_str().unwrap(), reverse.to_str().unwrap()).await;
    let transport = ssh::connect(config, Limits::default()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !reverse.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(UnixStream::connect(&reverse).await.is_ok());
    drop(transport);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if UnixStream::connect(&reverse).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("SSH remote listener must close after transport drop");
    child.kill().await.unwrap();
}

// Invalid limits are refused before any driver/socket task can start.
#[tokio::test]
async fn refuses_zero_limits() {
    for limits in [
        Limits { queue: 0, ..Limits::default() },
        Limits { pending_headers: 0, ..Limits::default() },
        Limits { max_sessions: 0, ..Limits::default() },
        Limits { header_timeout: Duration::ZERO, ..Limits::default() },
    ] {
        let (a, _b) = tokio::io::duplex(8);
        let result = Transport::yamux(Box::new(a), true, limits).await;
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::InvalidInput);
    }
}

#[tokio::test]
async fn yamux_fallback_on_native_listener() {
    tokio::time::timeout(Duration::from_secs(2), fallback_contract()).await.expect("native listener must use yamux for reverse opens");
}

// Socket-boundary fault injection: all successful accepts still use the real
// Unix listener. Transient accept failures must be reported as retrying and
// must not prevent a later connection from reaching the public accept API.
struct FaultyAccept {
    native: UnixConnections,
    failures: tokio::sync::Mutex<std::collections::VecDeque<io::Error>>,
}
#[async_trait::async_trait]
impl drydock_transport::Connections for FaultyAccept {
    async fn connect(&self) -> io::Result<drydock_transport::ByteStream> {
        self.native.connect().await
    }
    async fn accept(&self) -> io::Result<drydock_transport::ByteStream> {
        if let Some(error) = self.failures.lock().await.pop_front() {
            return Err(error);
        }
        self.native.accept().await
    }
}
#[tokio::test]
async fn transient_accept_errors_recover_and_terminal_errors_end() {
    use drydock_transport::ErrorScope;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("listen");
    let errors = vec![
        io::Error::from(io::ErrorKind::ConnectionAborted),
        io::Error::from_raw_os_error(libc::EMFILE),
        io::Error::from_raw_os_error(libc::ENFILE),
    ];
    let source = FaultyAccept {
        native: UnixConnections::new(UnixListener::bind(&path).unwrap(), dir.path().join("peer")),
        failures: tokio::sync::Mutex::new(errors.into()),
    };
    let mut transport = Transport::native(Arc::new(source), Limits::default()).unwrap();
    for _ in 0..3 {
        let error = transport.accept().await.err().unwrap();
        assert_eq!(error.scope, ErrorScope::Retrying);
    }
    let mut stream = UnixStream::connect(&path).await.unwrap();
    stream.write_all(b"DDT\x01\x00\x00").await.unwrap();
    let incoming = tokio::time::timeout(Duration::from_secs(2), transport.accept()).await.unwrap().unwrap().unwrap();
    assert_eq!(incoming.purpose, Purpose::Control);
    let fatal_path = dir.path().join("fatal");
    let fatal = FaultyAccept {
        native: UnixConnections::new(UnixListener::bind(fatal_path).unwrap(), path),
        failures: tokio::sync::Mutex::new(vec![io::Error::from(io::ErrorKind::BrokenPipe)].into()),
    };
    let mut transport = Transport::native(Arc::new(fatal), Limits::default()).unwrap();
    assert_eq!(transport.accept().await.err().unwrap().scope, ErrorScope::Terminal);
    assert!(transport.accept().await.unwrap().is_none());
}

// Established yamux sessions have a separate bound. Even with one pending
// header slot, multiple established sessions must not block new native streams.
#[tokio::test]
async fn established_yamux_sessions_release_header_slots() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("listen");
        let mut transport = Transport::native(
            Arc::new(UnixConnections::new(UnixListener::bind(&path).unwrap(), dir.path().join("unreachable"))),
            Limits { pending_headers: 1, ..Limits::default() },
        )
        .unwrap();
        let mut sessions = Vec::new();
        for _ in 0..3 {
            let stream = UnixStream::connect(&path).await.unwrap();
            let mux = Transport::yamux(Box::new(stream), true, Limits::default()).await.unwrap();
            let _stream = mux.open(Purpose::Control).await.unwrap();
            assert_eq!(transport.accept().await.unwrap().unwrap().purpose, Purpose::Control);
            sessions.push(mux);
        }
        let mut raw = UnixStream::connect(&path).await.unwrap();
        raw.write_all(b"DDT\x01\x00\x00").await.unwrap();
        assert_eq!(transport.accept().await.unwrap().unwrap().purpose, Purpose::Control);
    })
    .await
    .expect("live mux sessions must not consume unfinished-header slots");
}

// With sshd's documented StreamLocalBindUnlink setting, a stale reverse path
// from an earlier session can be reused. The forward is ready immediately.
#[tokio::test]
async fn ssh_reconnect_replaces_stale_remote_socket() {
    let dir = tempfile::tempdir().unwrap();
    let guest = dir.path().join("guest");
    let reverse = dir.path().join("reverse");
    let (config, mut server) = ssh_server(dir.path(), guest.to_str().unwrap(), reverse.to_str().unwrap()).await;
    for _ in 0..2 {
        if reverse.exists() {
            std::fs::remove_file(&reverse).unwrap();
        }
        drop(UnixListener::bind(&reverse).unwrap());
        let transport = ssh::connect(config.clone(), Limits::default()).await.unwrap();
        assert!(UnixStream::connect(&reverse).await.is_ok());
        drop(transport);
        tokio::time::timeout(Duration::from_secs(2), async {
            while UnixStream::connect(&reverse).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
    server.kill().await.unwrap();
}

// Link clients accept streaming request bodies; both chunks must arrive intact
// through the same HTTP/2 connection rather than requiring a fully buffered body.
#[tokio::test]
async fn http2_streaming_request_body() {
    let mut p = pair(Kind::Yamux).await;
    let (mut client, driver) = http2::connect_with_body(&p.host.opener, Purpose::Control).await.unwrap();
    let incoming = p.guest.accept().await.unwrap().unwrap();
    let server =
        tokio::spawn(http2::serve(incoming, Router::new().route("/upload", axum::routing::post(|body: Bytes| async move { body }))));
    let frames = ["first", "second"].map(|s| Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(Bytes::from_static(s.as_bytes()))));
    let body = http_body_util::StreamBody::new(futures::stream::iter(frames));
    let response =
        client.send_request(hyper::Request::builder().method("POST").uri("http://agent/upload").body(body).unwrap()).await.unwrap();
    assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), "firstsecond");
    driver.abort();
    server.abort();
}

// A link whose peer stops polling must fail via HTTP/2 keepalive, even when the
// underlying yamux and byte stream remain open. Paused time avoids wall-clock waits.
#[tokio::test(start_paused = true)]
async fn http2_keepalive_detects_silent_peer() {
    let mut p = pair(Kind::Yamux).await;
    let (mut client, driver) = http2::connect(&p.host.opener, Purpose::Control).await.unwrap();
    let incoming = p.guest.accept().await.unwrap().unwrap();
    let (pause, paused) = tokio::sync::oneshot::channel();
    let (ack, received) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let serve = http2::serve(incoming, Router::new().route("/hello", get(|| async { "hello" })));
        tokio::pin!(serve);
        tokio::select! {
            result = &mut serve => { result.unwrap(); }
            _ = paused => {
                let _ = ack.send(());
                // Retain the peer connection without polling it or replying to pings.
                std::future::pending::<()>().await;
            }
        }
    });
    let response =
        client.send_request(hyper::Request::builder().uri("http://agent/hello").body(Full::new(Bytes::new())).unwrap()).await.unwrap();
    assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), "hello");
    pause.send(()).unwrap();
    received.await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(60), driver).await.expect("silent link must not hang indefinitely").unwrap();
    assert!(result.is_err(), "missing ping acknowledgement must fail the link");
    server.abort();
}

// Bounding fallback session count must refuse only the excess session while
// keeping the native listener and the earlier session usable.
#[tokio::test]
async fn fallback_session_limit_preserves_native_accepts() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("listen");
        let mut transport = Transport::native(
            Arc::new(UnixConnections::new(UnixListener::bind(&path).unwrap(), dir.path().join("peer"))),
            Limits { max_sessions: 1, ..Limits::default() },
        )
        .unwrap();
        let first = Transport::yamux(Box::new(UnixStream::connect(&path).await.unwrap()), true, Limits::default()).await.unwrap();
        let _stream = first.open(Purpose::Control).await.unwrap();
        assert_eq!(transport.accept().await.unwrap().unwrap().purpose, Purpose::Control);
        let _excess = Transport::yamux(Box::new(UnixStream::connect(&path).await.unwrap()), true, Limits::default()).await.unwrap();
        assert_eq!(transport.accept().await.err().unwrap().scope, drydock_transport::ErrorScope::Connection);
        let mut raw = UnixStream::connect(&path).await.unwrap();
        raw.write_all(b"DDT\x01\x00\x00").await.unwrap();
        assert_eq!(transport.accept().await.unwrap().unwrap().purpose, Purpose::Control);
        let _stream = first.open(Purpose::Control).await.unwrap();
        assert_eq!(transport.accept().await.unwrap().unwrap().purpose, Purpose::Control);
    })
    .await
    .unwrap();
}

// Scripted socket boundary: queue one valid stream, then a transient failure.
// A full application queue must not prevent the listener from requesting the
// next connection; dropping a transient diagnostic is safe under overload.
struct ScriptedAccept {
    incoming: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<io::Result<drydock_transport::ByteStream>>>,
    attempts: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl drydock_transport::Connections for ScriptedAccept {
    async fn connect(&self) -> io::Result<drydock_transport::ByteStream> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    async fn accept(&self) -> io::Result<drydock_transport::ByteStream> {
        self.attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.incoming.lock().await.recv().await.unwrap_or_else(|| Err(io::Error::from(io::ErrorKind::BrokenPipe)))
    }
}
#[tokio::test]
async fn full_queue_does_not_block_transient_accept_recovery() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let (send, incoming) = tokio::sync::mpsc::channel(4);
        let source =
            Arc::new(ScriptedAccept { incoming: tokio::sync::Mutex::new(incoming), attempts: std::sync::atomic::AtomicUsize::new(0) });
        let mut transport = Transport::native(source.clone(), Limits { queue: 1, pending_headers: 1, ..Limits::default() }).unwrap();
        let (mut client, accepted) = tokio::io::duplex(32);
        send.send(Ok(Box::new(accepted) as drydock_transport::ByteStream)).await.ok().unwrap();
        client.write_all(b"DDT\x01\x00\x00").await.unwrap();
        while source.attempts.load(std::sync::atomic::Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        // pending_headers=1 means the first stream is already queued here.
        send.send(Err(io::Error::from_raw_os_error(libc::EMFILE))).await.ok().unwrap();
        while source.attempts.load(std::sync::atomic::Ordering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(transport.accept().await.unwrap().unwrap().purpose, Purpose::Control);
        let (mut next, accepted) = tokio::io::duplex(32);
        send.send(Ok(Box::new(accepted) as drydock_transport::ByteStream)).await.ok().unwrap();
        next.write_all(b"DDT\x01\x00\x00").await.unwrap();
        assert_eq!(transport.accept().await.unwrap().unwrap().purpose, Purpose::Control);
    })
    .await
    .expect("a dropped transient notice must not stall a full incoming queue");
}

// Resource exhaustion backs off exponentially up to one second. Aborted/reset
// peer connections yield cooperatively without sleeping or throttling admission.
#[tokio::test(start_paused = true)]
async fn accept_backoff_distinguishes_resource_exhaustion_and_churn() {
    let dir = tempfile::tempdir().unwrap();
    let mut errors: Vec<_> = (0..6).map(|_| io::Error::from_raw_os_error(libc::EMFILE)).collect();
    errors.extend([
        io::Error::from(io::ErrorKind::ConnectionAborted),
        io::Error::from(io::ErrorKind::ConnectionReset),
        io::Error::from_raw_os_error(libc::ENFILE),
    ]);
    let source = FaultyAccept {
        native: UnixConnections::new(UnixListener::bind(dir.path().join("listen")).unwrap(), dir.path().join("peer")),
        failures: tokio::sync::Mutex::new(errors.into()),
    };
    let mut transport = Transport::native(Arc::new(source), Limits::default()).unwrap();
    let mut previous = tokio::time::Instant::now();
    for delay in [0, 100, 200, 400, 800, 1000, 1000, 0, 0] {
        assert_eq!(transport.accept().await.err().unwrap().scope, drydock_transport::ErrorScope::Retrying);
        assert_eq!(previous.elapsed(), Duration::from_millis(delay));
        previous = tokio::time::Instant::now();
    }
}

// Raw host-key validation refuses known-hosts directives, certificates and bad
// key blobs before starting an SSH process, even with no usable identity file.
#[tokio::test]
async fn ssh_rejects_host_key_options_and_markers() {
    for key in [
        "@cert-authority ssh-ed25519 AAAA",
        "@revoked ssh-ed25519 AAAA",
        "ssh-ed25519-cert-v01@openssh.com AAAA",
        "ssh-ed25519",
        "ssh-ed25519 bad!",
        "ssh-ed25519 AAAA\n",
    ] {
        let config = ssh::SshConfig {
            connect_timeout: Duration::from_secs(5),
            host: "127.0.0.1".into(),
            port: 22,
            user: "vessel".into(),
            host_key: key.into(),
            identity_file: "/nonexistent-drydock-identity".into(),
            agent_socket: "/tmp/unused-agent".into(),
            reverse_socket: "/tmp/unused-reverse".into(),
        };
        let error = ssh::connect(config, Limits { header_timeout: Duration::from_millis(20), ..Limits::default() }).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}

// A rejected remote forward must fail setup, and the same server remains usable
// for a subsequent valid setup without changing its configuration or credentials.
#[tokio::test]
async fn ssh_rejected_forward_fails_setup_and_allows_retry() {
    let dir = tempfile::tempdir().unwrap();
    let guest = dir.path().join("guest");
    let reverse = dir.path().join("reverse");
    let (mut config, mut server) = ssh_server(dir.path(), guest.to_str().unwrap(), reverse.to_str().unwrap()).await;
    config.reverse_socket = dir.path().join("missing-directory/reverse");
    assert_eq!(ssh::connect(config.clone(), Limits::default()).await.err().unwrap().kind(), io::ErrorKind::ConnectionAborted);
    config.reverse_socket = reverse.clone();
    let transport = ssh::connect(config, Limits::default()).await.unwrap();
    assert!(UnixStream::connect(reverse).await.is_ok());
    drop(transport);
    server.kill().await.unwrap();
}

// A persistently failing listener must eventually sleep rather than burning a
// worker core. Short bursts retain the zero-delay connection-churn path.
#[tokio::test(start_paused = true)]
async fn persistent_connection_churn_has_a_floor_delay() {
    let dir = tempfile::tempdir().unwrap();
    let source = FaultyAccept {
        native: UnixConnections::new(UnixListener::bind(dir.path().join("listen")).unwrap(), dir.path().join("peer")),
        failures: tokio::sync::Mutex::new((0..10).map(|_| io::Error::from(io::ErrorKind::ConnectionReset)).collect()),
    };
    let mut transport = Transport::native(Arc::new(source), Limits::default()).unwrap();
    let start = tokio::time::Instant::now();
    for _ in 0..10 {
        assert_eq!(transport.accept().await.err().unwrap().scope, drydock_transport::ErrorScope::Retrying);
    }
    assert_eq!(start.elapsed(), Duration::from_millis(2));
}

// SSH bootstrap has its own budget. A tiny raw-header deadline must not abort
// authentication; a silent TCP endpoint must obey the explicit connect budget.
#[tokio::test]
async fn ssh_setup_timeout_is_independent_of_raw_headers() {
    let dir = tempfile::tempdir().unwrap();
    let guest = dir.path().join("guest");
    let reverse = dir.path().join("reverse");
    let (mut config, mut server) = ssh_server(dir.path(), guest.to_str().unwrap(), reverse.to_str().unwrap()).await;
    let mut invalid = config.clone();
    invalid.connect_timeout = Duration::ZERO;
    assert_eq!(ssh::connect(invalid, Limits::default()).await.err().unwrap().kind(), io::ErrorKind::InvalidInput);
    let transport = ssh::connect(config.clone(), Limits { header_timeout: Duration::from_nanos(1), ..Limits::default() }).await.unwrap();
    assert!(reverse.exists());
    drop(transport);
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.port = silent.local_addr().unwrap().port();
    config.connect_timeout = Duration::from_millis(50);
    let error = tokio::time::timeout(Duration::from_secs(2), ssh::connect(config, Limits::default())).await.unwrap().err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    server.kill().await.unwrap();
}

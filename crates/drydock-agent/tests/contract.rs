use drydock_agent::{Agent, Client, Configuration, Endpoint, Exec, ExecEvent, GuestForward};
use drydock_transport::{ByteStream, Limits, Purpose, Transport, native::UnixConnections};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    task::JoinHandle,
};
struct Harness {
    client: Client,
    guest_opener: drydock_transport::Opener,
    agent: JoinHandle<std::io::Result<PathBuf>>,
    dir: tempfile::TempDir,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.agent.abort();
    }
}
async fn harness(unix: bool, expected: &str) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let (host, guest) = if unix {
        let hp = dir.path().join("host");
        let gp = dir.path().join("guest");
        let hl = UnixListener::bind(&hp).unwrap();
        let gl = UnixListener::bind(&gp).unwrap();
        (
            Transport::native(Arc::new(UnixConnections::new(hl, gp)), Limits::default()).unwrap(),
            Transport::native(Arc::new(UnixConnections::new(gl, hp)), Limits::default()).unwrap(),
        )
    } else {
        let (a, b) = tokio::io::duplex(4096);
        let (a, b) =
            tokio::join!(Transport::yamux(Box::new(a), true, Limits::default()), Transport::yamux(Box::new(b), false, Limits::default()));
        (a.unwrap(), b.unwrap())
    };
    let guest_opener = guest.opener.clone();
    let agent = tokio::spawn(Agent::new(guest, "test-build".into(), dir.path().join("agent")).run());
    let client = Client::connect(host, expected).await.unwrap();
    Harness { client, guest_opener, agent, dir }
}
fn shell(script: &str) -> Exec {
    Exec { program: "/bin/sh".into(), args: vec!["-c".into(), script.into()], cwd: None }
}
async fn output(mut output: drydock_agent::ExecOutput) -> (Vec<u8>, Vec<u8>, Option<i32>) {
    let (mut stdout, mut stderr, mut status) = (vec![], vec![], None);
    while let Some(event) = output.next().await.unwrap() {
        match event {
            ExecEvent::Stdout(bytes) => stdout.extend(bytes),
            ExecEvent::Stderr(bytes) => stderr.extend(bytes),
            ExecEvent::Exit { code } => status = code,
        }
    }
    (stdout, stderr, status)
}
// ADR 0070: hello is readiness; each pushed configuration replaces all fields.
// Exec is a pipeline with null stdin and no tty, with independently streamed
// stdout/stderr. Atomic writes, read-back, and explicit flush use the same API
// on both in-memory and Unix-socket transports.
#[tokio::test]
async fn control_contract_on_both_transports() {
    for unix in [false, true] {
        let h = harness(unix, "test-build").await;
        assert_eq!(h.client.hello().fingerprint, "test-build");
        assert!(h.client.hello().features.contains(&"forwards".into()));
        for value in ["one", "two", ""] {
            let config = Configuration {
                egress: serde_json::json!({"upstream": value}),
                ca: format!("CA:{value}"),
                features: vec![value.into()],
                environment: [
                    ("HTTPS_PROXY".into(), value.into()),
                    ("SSL_CERT_FILE".into(), "/tmp/ca".into()),
                    ("TOKEN".into(), "placeholder".into()),
                ]
                .into(),
                forwards: vec![],
            };
            h.client.configure(config.clone()).await.unwrap();
            assert_eq!(h.client.configuration().await.unwrap(), config);
            let (out,err,status) = output(h.client.exec(shell("test ! -t 0 && test ! -t 1; read line && exit 9; printf '%s|%s|%s|%s|%s' \"$HTTPS_PROXY\" \"$SSL_CERT_FILE\" \"$TOKEN\" \"$PAGER\" \"$CI\"; printf err >&2")).await.unwrap()).await;
            assert_eq!(out, format!("{value}|/tmp/ca|placeholder|cat|1").as_bytes());
            assert_eq!(err, b"err");
            assert_eq!(status, Some(0));
        }
        let gate = h.dir.path().join("gate");
        let mut stream = h
            .client
            .exec(shell(&format!("printf first; while test ! -f '{}'; do sleep 0.01; done; printf second", gate.display())))
            .await
            .unwrap();
        let first = tokio::time::timeout(Duration::from_secs(2), stream.next()).await.unwrap().unwrap().unwrap();
        assert_eq!(first, ExecEvent::Stdout(b"first".to_vec()));
        std::fs::write(gate, []).unwrap();
        assert_eq!(output(stream).await.0, b"second");
        let path = h.dir.path().join("push");
        h.client.write(path.clone(), vec![], false).await.unwrap();
        assert_eq!(h.client.read(path.clone()).await.unwrap(), Vec::<u8>::new());
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let flag = running.clone();
        let observed = path.clone();
        let reader = tokio::spawn(async move {
            while flag.load(std::sync::atomic::Ordering::Relaxed) {
                let bytes = tokio::fs::read(&observed).await.unwrap();
                assert!(bytes.is_empty() || bytes == vec![7; 65536] || bytes == vec![9; 32768]);
                tokio::task::yield_now().await;
            }
        });
        for bytes in [vec![7; 65536], vec![9; 32768], vec![]] {
            h.client.write(path.clone(), bytes.clone(), false).await.unwrap();
            h.client.flush(path.clone()).await.unwrap();
            assert_eq!(h.client.read(path.clone()).await.unwrap(), bytes);
        }
        running.store(false, std::sync::atomic::Ordering::Relaxed);
        reader.await.unwrap();
        assert!(h.client.read(h.dir.path().join("absent")).await.is_err());
        assert!(h.client.exec(Exec { program: "/no/such/program".into(), args: vec![], cwd: None }).await.is_err());
    }
}
async fn echo(listener: UnixListener) {
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let (mut r, mut w) = stream.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
    }
}
async fn exchange(stream: &mut ByteStream, bytes: &[u8]) {
    stream.write_all(bytes).await.unwrap();
    stream.flush().await.unwrap();
    let mut read = vec![0; bytes.len()];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut read)).await.unwrap().unwrap();
    assert_eq!(read, bytes);
}
fn forward(h: &Harness, id: &str) -> GuestForward {
    GuestForward { id: id.into(), unix: h.dir.path().join(id), tcp: None }
}
// Forwards carry bytes without parsing HTTP. Exercise HTTP/1.1 headers, an
// upgrade handshake plus masked WebSocket frame, and chunked streaming bodies
// in BOTH directions. Adding/removing another forward cannot interrupt a third.
#[tokio::test]
async fn forwards_are_transparent_and_dynamic() {
    for unix in [false, true] {
        let h = harness(unix, "test-build").await;
        let path = h.dir.path().join("endpoint");
        let task = tokio::spawn(echo(UnixListener::bind(&path).unwrap()));
        h.client.add_host_forward("active".into(), Endpoint::Unix(path.clone())).await.unwrap();
        let mut active = h.client.forward("active").await.unwrap();
        let messages: &[&[u8]] = &[
            b"GET /x HTTP/1.1\r\nHost: a\r\nX-Token: keep-this\r\n\r\n",
            b"GET /socket HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n\x81\x82\x01\x02\x03\x04ik",
            b"POST /upload HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nX-Keep: all\r\n\r\n",
            b"3\r\nabc\r\n", b"4\r\ndefg\r\n", b"0\r\nX-Trailer: kept\r\n\r\n",
        ];
        let endpoint2 = h.dir.path().join("endpoint2");
        let task2 = tokio::spawn(echo(UnixListener::bind(&endpoint2).unwrap()));
        let guest = forward(&h, "reverse");
        h.client.add_guest_forward(guest.clone(), Endpoint::Unix(endpoint2)).await.unwrap();
        let mut reverse: ByteStream = Box::new(UnixStream::connect(&guest.unix).await.unwrap());
        for (index, bytes) in messages.iter().enumerate() {
            exchange(&mut active, bytes).await;
            exchange(&mut reverse, bytes).await;
            if index == 1 {
                h.client.add_host_forward("transient".into(), Endpoint::Unix(path.clone())).await.unwrap();
            }
            if index == 2 {
                h.client.remove_host_forward("transient").await.unwrap();
            }
        }
        h.client.remove_guest_forward("reverse").await.unwrap();
        assert!(!guest.unix.exists());
        h.client.remove_host_forward("active").await.unwrap();
        let mut removed = h.client.forward("active").await.unwrap();
        let mut byte = [0];
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), removed.read(&mut byte)).await.unwrap().unwrap(), 0);
        task.abort();
        task2.abort();
    }
}
// The host resolves only IDs configured in the arriving vessel's client. A
// guessed ID/path from another vessel is closed, and a host endpoint cannot be
// shared between clients (including a symlink alias).
#[tokio::test]
async fn isolation_and_endpoint_ownership() {
    let a = harness(false, "test-build").await;
    let b = harness(false, "test-build").await;
    let endpoint = a.dir.path().join("endpoint");
    let listener = UnixListener::bind(&endpoint).unwrap();
    a.client.add_guest_forward(forward(&a, "private"), Endpoint::Unix(endpoint.clone())).await.unwrap();
    assert!(b.client.add_guest_forward(forward(&b, "private"), Endpoint::Unix(endpoint.clone())).await.is_err());
    let alias = b.dir.path().join("alias");
    std::os::unix::fs::symlink(&endpoint, &alias).unwrap();
    assert!(b.client.register_host_endpoint("alias".into(), Endpoint::Unix(alias)).is_err());
    let hardlink = b.dir.path().join("hardlink");
    std::fs::hard_link(&endpoint, &hardlink).unwrap();
    assert!(b.client.register_host_endpoint("hardlink".into(), Endpoint::Unix(hardlink)).is_err());
    for id in ["private".to_owned(), endpoint.display().to_string()] {
        let mut attack = b.guest_opener.open(Purpose::Forward { id }).await.unwrap();
        let mut byte = [0];
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), attack.read(&mut byte)).await.unwrap().unwrap(), 0);
    }
    assert!(tokio::time::timeout(Duration::from_millis(50), listener.accept()).await.is_err());
    let mut legitimate = UnixStream::connect(a.dir.path().join("private")).await.unwrap();
    legitimate.write_all(b"one vessel").await.unwrap();
    let (mut received, _) = listener.accept().await.unwrap();
    let mut bytes = [0; 10];
    received.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"one vessel");
    // Rebinding a host service at its stable path must not let another client
    // claim it under the new socket inode while the first route still exists.
    std::fs::remove_file(&endpoint).unwrap();
    let _replacement = UnixListener::bind(&endpoint).unwrap();
    assert!(b.client.register_host_endpoint("rebound".into(), Endpoint::Unix(endpoint.clone())).is_err());
}
// Generated configuration sequences cover empty/duplicate/invalid and boundary
// IDs. Each accepted state replaces the old one; refusals preserve it atomically.
#[hegel::test]
fn configuration_sequences(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let steps = tc.draw(gs::integers::<usize>().min_value(1).max_value(8));
    let ops: Vec<u8> = (0..steps).map(|_| tc.draw(gs::integers::<u8>().min_value(0).max_value(7))).collect();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let h = harness(false, "test-build").await;
        let mut previous = Configuration::default();
        for op in ops {
            let mut config = Configuration { ca: op.to_string(), ..Configuration::default() };
            match op {
                1 => {
                    config.environment.insert("".into(), "invalid".into());
                }
                2 => {
                    config.forwards = vec![forward(&h, "")];
                }
                3 => {
                    let f = forward(&h, "duplicate");
                    config.forwards = vec![f.clone(), f];
                }
                4 => {
                    config.forwards = vec![GuestForward { id: "x".repeat(1025), unix: h.dir.path().join("too-long"), tcp: None }];
                }
                5 => {
                    config.forwards = vec![GuestForward { id: "x".into(), unix: h.dir.path().join("minimum-id"), tcp: None }];
                }
                6 => {
                    config.forwards = vec![GuestForward { id: "x".repeat(1024), unix: h.dir.path().join("maximum-id"), tcp: None }];
                }
                7 => {
                    let mut f = forward(&h, "invalid-tcp");
                    f.tcp = Some("0.0.0.0:0".parse().unwrap());
                    config.forwards = vec![f];
                }
                _ => {}
            }
            let result = h.client.configure(config.clone()).await;
            assert_eq!(result.is_ok(), matches!(op, 0 | 5 | 6));
            if result.is_ok() {
                previous = config;
            }
            assert_eq!(h.client.configuration().await.unwrap(), previous);
        }
    });
}

// Configuration-installed forwards accept Unix and optional loopback TCP. Host
// endpoints reserve loopback ports across aliases; guest TCP targets remain raw.
// Failed listener preparation preserves the working configuration and listener.
#[tokio::test]
async fn configured_forwards_and_tcp_endpoints() {
    for unix in [false, true] {
        let h = harness(unix, "test-build").await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        h.client.register_host_endpoint("configured".into(), Endpoint::Tcp(endpoint)).unwrap();
        let other = harness(unix, "test-build").await;
        let alias = std::net::SocketAddr::from(([127, 0, 0, 2], endpoint.port()));
        assert!(other.client.register_host_endpoint("alias".into(), Endpoint::Tcp(alias)).is_err());
        let port_reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = port_reservation.local_addr().unwrap();
        drop(port_reservation);
        let mut f = forward(&h, "configured");
        f.tcp = Some(tcp);
        let config = Configuration { forwards: vec![f.clone()], ..Configuration::default() };
        h.client.configure(config.clone()).await.unwrap();
        assert_eq!(h.client.configuration().await.unwrap(), config);
        let mut socket: ByteStream = Box::new(UnixStream::connect(&f.unix).await.unwrap());
        let mut loopback: ByteStream = Box::new(tokio::net::TcpStream::connect(tcp).await.unwrap());
        exchange(&mut socket, b"Unix in configured forward").await;
        exchange(&mut loopback, b"TCP in configured forward").await;
        // Re-pushing the same forward preserves its streams.
        h.client.configure(config.clone()).await.unwrap();
        exchange(&mut socket, b"still alive").await;
        let occupied = h.dir.path().join("occupied");
        std::fs::write(&occupied, b"do not replace").unwrap();
        let bad = Configuration {
            forwards: vec![f.clone(), GuestForward { id: "bad".into(), unix: occupied.clone(), tcp: None }],
            ..Configuration::default()
        };
        assert!(h.client.configure(bad).await.is_err());
        assert_eq!(h.client.configuration().await.unwrap(), config);
        assert_eq!(std::fs::read(occupied).unwrap(), b"do not replace");
        exchange(&mut socket, b"survived failed config").await;
        h.client.add_host_forward("tcp-target".into(), Endpoint::Tcp(endpoint)).await.unwrap();
        let mut host = h.client.forward("tcp-target").await.unwrap();
        exchange(&mut host, b"host to guest TCP").await;
        h.client.configure(Configuration::default()).await.unwrap();
        assert!(!f.unix.exists());
        assert!(tokio::net::TcpStream::connect(tcp).await.is_err());
        // A crash leaves a Unix socket inode behind without a listener.
        drop(UnixListener::bind(&f.unix).unwrap());
        h.client.configure(config).await.unwrap();
        let mut recovered: ByteStream = Box::new(UnixStream::connect(&f.unix).await.unwrap());
        exchange(&mut recovered, b"after crash").await;
        task.abort();
    }
}

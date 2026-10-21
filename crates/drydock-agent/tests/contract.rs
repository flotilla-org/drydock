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
        assert_error(h.client.read(h.dir.path().join("absent")).await.unwrap_err(), std::io::ErrorKind::NotFound, "file.read", "absent");
        assert_error(
            h.client.exec(Exec { program: "/no/such/program".into(), args: vec![], cwd: None }).await.err().unwrap(),
            std::io::ErrorKind::NotFound,
            "exec.spawn",
            "/no/such/program",
        );
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
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&guest.unix).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(h.dir.path()).unwrap().permissions().mode() & 0o777, 0o700);
        let mut reverse: ByteStream = Box::new(UnixStream::connect(&guest.unix).await.unwrap());
        for (index, bytes) in messages.iter().enumerate() {
            exchange(&mut active, bytes).await;
            exchange(&mut reverse, bytes).await;
            if index == 1 {
                h.client.add_host_forward("transient".into(), Endpoint::Unix(path.clone())).await.unwrap();
                let mut added = h.client.forward("transient").await.unwrap();
                exchange(&mut added, b"added during live traffic").await;
            }
            if index == 2 {
                h.client.remove_host_forward("transient").await.unwrap();
            }
        }
        h.client.remove_guest_forward("reverse").await.unwrap();
        assert!(!guest.unix.exists());
        h.client.remove_host_forward("active").await.unwrap();
        let error = h.client.forward("active").await.err().unwrap();
        assert_error(error, std::io::ErrorKind::NotFound, "forward.open", "active");
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
    assert_refused(b.client.add_guest_forward(forward(&b, "private"), Endpoint::Unix(endpoint.clone())).await);
    let alias = b.dir.path().join("alias");
    std::os::unix::fs::symlink(&endpoint, &alias).unwrap();
    assert_refused(b.client.register_host_endpoint("alias".into(), Endpoint::Unix(alias)));
    let hardlink = b.dir.path().join("hardlink");
    std::fs::hard_link(&endpoint, &hardlink).unwrap();
    assert_refused(b.client.register_host_endpoint("hardlink".into(), Endpoint::Unix(hardlink)));
    for id in ["private".to_owned(), endpoint.display().to_string()] {
        let mut attack = b.guest_opener.open(Purpose::Forward { id }).await.unwrap();
        let length = attack.read_u32().await.unwrap();
        let mut bytes = vec![0; length as usize];
        attack.read_exact(&mut bytes).await.unwrap();
        let result: Result<(), drydock_agent::AgentError> = serde_json::from_slice(&bytes).unwrap();
        let error = result.unwrap_err();
        assert_eq!(error.kind, drydock_agent::ErrorKind::NotFound);
        assert_eq!(error.operation, "forward.open");
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
    assert_refused(b.client.register_host_endpoint("rebound".into(), Endpoint::Unix(endpoint.clone())));
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
        let mut endpoints = vec![];
        for (index, id) in ["x".into(), "x".repeat(1024), "duplicate".into(), "invalid-tcp".into()].into_iter().enumerate() {
            let path = h.dir.path().join(format!("registered-{index}"));
            endpoints.push(UnixListener::bind(&path).unwrap());
            h.client.register_host_endpoint(id, Endpoint::Unix(path)).unwrap();
        }
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
        assert_refused(other.client.register_host_endpoint("alias".into(), Endpoint::Tcp(alias)));
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
        let bad_endpoint = h.dir.path().join("bad-endpoint");
        let _bad_listener = UnixListener::bind(&bad_endpoint).unwrap();
        h.client.register_host_endpoint("bad".into(), Endpoint::Unix(bad_endpoint)).unwrap();
        assert_error(h.client.configure(bad).await.unwrap_err(), std::io::ErrorKind::AddrInUse, "forward.listen", "occupied");
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

// A later control connection cannot take over the first controller's reverse
// opener, even when it registers the same ID and repeats the configuration.
#[tokio::test]
async fn later_control_cannot_replace_reverse_opener() {
    async fn pair() -> (Transport, Transport) {
        let (a, b) = tokio::io::duplex(4096);
        let (a, b) =
            tokio::join!(Transport::yamux(Box::new(a), true, Limits::default()), Transport::yamux(Box::new(b), false, Limits::default()));
        (a.unwrap(), b.unwrap())
    }
    let dir = tempfile::tempdir().unwrap();
    let (host1, guest1) = pair().await;
    let (host2, guest2) = pair().await;
    let mut agent = Agent::new(guest1, "test-build".into(), dir.path().join("agent"));
    agent.add_transport(guest2);
    let task = tokio::spawn(agent.run());
    let first = Client::connect(host1, "test-build").await.unwrap();
    let target1 = dir.path().join("target1");
    let listener1 = UnixListener::bind(&target1).unwrap();
    let f = GuestForward { id: "same".into(), unix: dir.path().join("forward"), tcp: None };
    first.add_guest_forward(f.clone(), Endpoint::Unix(target1)).await.unwrap();
    let config = first.configuration().await.unwrap();
    let second = Client::connect(host2, "test-build").await.unwrap();
    let target2 = dir.path().join("target2");
    let listener2 = UnixListener::bind(&target2).unwrap();
    second.register_host_endpoint("same".into(), Endpoint::Unix(target2)).unwrap();
    second.configure(config).await.unwrap();
    let echo_task = tokio::spawn(echo(listener1));
    let mut guest: ByteStream = Box::new(UnixStream::connect(&f.unix).await.unwrap());
    exchange(&mut guest, b"original host session").await;
    assert!(tokio::time::timeout(Duration::from_millis(50), listener2.accept()).await.is_err());
    task.abort();
    echo_task.abort();
}

// Non-executable pushes default to a CA-readable 0644; replacement preserves
// existing mode/owner, while an explicit executable push uses 0755. Oversized
// reads fail up front, and absent paths have a distinct HTTP error.
#[tokio::test]
async fn file_modes_and_bounded_read_errors() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let h = harness(false, "test-build").await;
    let path = h.dir.path().join("ca");
    h.client.write(path.clone(), b"CA".to_vec(), false).await.unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let before = std::fs::metadata(&path).unwrap();
    h.client.write(path.clone(), b"replacement".to_vec(), false).await.unwrap();
    let after = std::fs::metadata(&path).unwrap();
    assert_eq!((after.mode() & 0o777, after.uid(), after.gid()), (0o640, before.uid(), before.gid()));
    h.client.write(path.clone(), vec![], true).await.unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o755);
    assert!(h.client.read(h.dir.path().join("absent")).await.unwrap_err().to_string().contains("NotFound"));
    let large = h.dir.path().join("large");
    std::fs::File::create(&large).unwrap().set_len(128 * 1024 * 1024 + 1).unwrap();
    assert!(h.client.read(large).await.unwrap_err().to_string().contains("read exceeds 128 MiB"));
}

// Changing only TCP preserves the Unix socket binding. Removing and adding the
// optional TCP listener cannot fail because the Unix path is already bound.
#[tokio::test]
async fn tcp_only_configuration_changes_reuse_unix_listener() {
    let h = harness(false, "test-build").await;
    let target = h.dir.path().join("target");
    let echo_task = tokio::spawn(echo(UnixListener::bind(&target).unwrap()));
    let f = forward(&h, "changing");
    h.client.add_guest_forward(f.clone(), Endpoint::Unix(target)).await.unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let mut changed = f.clone();
    changed.tcp = Some(port);
    h.client.configure(Configuration { forwards: vec![changed], ..Configuration::default() }).await.unwrap();
    let mut tcp: ByteStream = Box::new(tokio::net::TcpStream::connect(port).await.unwrap());
    exchange(&mut tcp, b"added TCP").await;
    h.client.configure(Configuration { forwards: vec![f.clone()], ..Configuration::default() }).await.unwrap();
    assert!(tokio::net::TcpStream::connect(port).await.is_err());
    let mut unix: ByteStream = Box::new(UnixStream::connect(&f.unix).await.unwrap());
    exchange(&mut unix, b"retained Unix").await;
    echo_task.abort();
}

// JSON writes are bounded by encoded body size. Three-digit binary data near
// that limit is accepted at 31 MiB and rejected at 32 MiB; rejection is atomic.
#[tokio::test]
async fn large_binary_write_obeys_encoded_body_limit() {
    let h = harness(false, "test-build").await;
    let path = h.dir.path().join("large-push");
    h.client.write(path.clone(), vec![255; 31 * 1024 * 1024], false).await.unwrap();
    let bytes = h.client.read(path.clone()).await.unwrap();
    assert_eq!(bytes.len(), 31 * 1024 * 1024);
    assert!(bytes.iter().all(|byte| *byte == 255));
    drop(bytes);
    assert!(h.client.write(path.clone(), vec![255; 32 * 1024 * 1024], false).await.unwrap_err().to_string().contains("413"));
    assert_eq!(std::fs::metadata(path).unwrap().len(), 31 * 1024 * 1024);
}

// Detached exec output remains writable after its consumer disconnects. The
// agent still waits for the child, so a completed command cannot leave a zombie.
#[tokio::test]
async fn disconnected_exec_drains_to_spool_and_is_reaped() {
    let h = harness(false, "test-build").await;
    let gate = h.dir.path().join("release");
    let done = h.dir.path().join("done");
    let pidfile = h.dir.path().join("pid");
    let mut stream = h
        .client
        .exec(shell(&format!(
            "echo $$ > '{}'; printf ready; while test ! -f '{}'; do sleep 0.01; done; head -c 131072 /dev/zero; printf complete > '{}'",
            pidfile.display(),
            gate.display(),
            done.display()
        )))
        .await
        .unwrap();
    assert_eq!(stream.next().await.unwrap(), Some(ExecEvent::Stdout(b"ready".to_vec())));
    let pid = std::fs::read_to_string(pidfile).unwrap();
    drop(stream);
    std::fs::write(gate, []).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let completed = std::fs::read(&done).ok().as_deref() == Some(b"complete");
            #[cfg(target_os = "linux")]
            let reaped = !std::path::Path::new(&format!("/proc/{}", pid.trim())).exists();
            #[cfg(not(target_os = "linux"))]
            let reaped = true;
            if completed && reaped {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

// A port owned by another forward is deliberately not stolen during atomic
// configuration. A rejected port swap leaves both existing routes usable.
#[tokio::test]
async fn occupied_port_swap_refuses_without_changing_configuration() {
    let h = harness(false, "test-build").await;
    let mut forwards = Vec::new();
    let mut echo_tasks = Vec::new();
    for id in ["port-a", "port-b"] {
        let target = h.dir.path().join(format!("target-{id}"));
        echo_tasks.push(tokio::spawn(echo(UnixListener::bind(&target).unwrap())));
        let mut f = forward(&h, id);
        f.tcp = Some(std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap());
        h.client.add_guest_forward(f.clone(), Endpoint::Unix(target)).await.unwrap();
        forwards.push(f);
    }
    let before = h.client.configuration().await.unwrap();
    let mut changed = before.clone();
    changed.forwards[0].tcp = forwards[1].tcp;
    changed.forwards[1].tcp = forwards[0].tcp;
    assert_error(h.client.configure(changed).await.unwrap_err(), std::io::ErrorKind::AddrInUse, "forward.listen", "port-a");
    assert_eq!(h.client.configuration().await.unwrap(), before);
    for f in forwards {
        let mut stream: ByteStream = Box::new(tokio::net::TcpStream::connect(f.tcp.unwrap()).await.unwrap());
        exchange(&mut stream, f.id.as_bytes()).await;
    }
    for task in echo_tasks {
        task.abort();
    }
}

// Port zero is malformed input. Unix targets are deliberately resolved lazily
// so a host can register a service before it has created its guest socket.
#[tokio::test]
async fn forward_targets_reject_zero_ports_and_allow_late_socket_creation() {
    let h = harness(false, "test-build").await;
    assert!(
        h.client
            .add_host_forward("zero".into(), Endpoint::Tcp("127.0.0.1:0".parse().unwrap()))
            .await
            .unwrap_err()
            .to_string()
            .contains("InvalidInput")
    );
    let target = h.dir.path().join("later");
    h.client.add_host_forward("later".into(), Endpoint::Unix(target.clone())).await.unwrap();
    let task = tokio::spawn(echo(UnixListener::bind(target).unwrap()));
    let mut stream = h.client.forward("later").await.unwrap();
    exchange(&mut stream, b"late service").await;
    task.abort();
}

fn assert_error(error: std::io::Error, kind: std::io::ErrorKind, operation: &str, subject: &str) {
    assert_eq!(error.kind(), kind, "{error}");
    let detail = error.get_ref().unwrap().downcast_ref::<drydock_agent::AgentError>().expect("structured agent error");
    assert_eq!(detail.operation, operation);
    assert!(detail.subject.contains(subject), "{detail:?}");
    assert!(!detail.message.is_empty());
}
// Errors cross both real control transports with the original kind and enough
// context to distinguish missing programs, cwd, file operations and forwards.
#[tokio::test]
async fn errors_name_the_failed_operation_and_subject() {
    use std::io::ErrorKind;
    for unix in [false, true] {
        let h = harness(unix, "test-build").await;
        let path = h.dir.path().join("absent");
        assert_error(h.client.read(path.clone()).await.unwrap_err(), ErrorKind::NotFound, "file.read", "absent");
        assert_error(h.client.flush(path.clone()).await.unwrap_err(), ErrorKind::NotFound, "file.flush", "absent");
        assert_error(
            h.client.exec(Exec { program: "/missing-program".into(), args: vec![], cwd: None }).await.err().unwrap(),
            ErrorKind::NotFound,
            "exec.spawn",
            "/missing-program",
        );
        assert_error(
            h.client.exec(Exec { program: "/bin/true".into(), args: vec![], cwd: Some(path.clone()) }).await.err().unwrap(),
            ErrorKind::NotFound,
            "exec.cwd",
            "absent",
        );
        let relative = PathBuf::from("relative");
        assert_error(
            h.client.write(relative.clone(), vec![1], false).await.unwrap_err(),
            ErrorKind::InvalidInput,
            "file.write",
            "relative",
        );
        assert_error(h.client.read(relative.clone()).await.unwrap_err(), ErrorKind::InvalidInput, "file.read", "relative");
        assert_error(h.client.flush(relative).await.unwrap_err(), ErrorKind::InvalidInput, "file.flush", "relative");
        h.client.add_host_forward("dead".into(), Endpoint::Unix(path)).await.unwrap();
        assert_error(h.client.forward("dead").await.err().unwrap(), ErrorKind::NotFound, "forward.open", "absent");
        let refused = h.dir.path().join("refused");
        drop(UnixListener::bind(&refused).unwrap());
        h.client.add_host_forward("refused".into(), Endpoint::Unix(refused)).await.unwrap();
        assert_error(h.client.forward("refused").await.err().unwrap(), ErrorKind::ConnectionRefused, "forward.open", "refused");
        assert_error(h.client.forward("unknown").await.err().unwrap(), ErrorKind::NotFound, "forward.open", "unknown");
        assert_error(h.client.remove_host_forward("unknown").await.unwrap_err(), ErrorKind::NotFound, "forward.remove", "unknown");
        assert_error(h.client.remove_guest_forward("unknown").await.unwrap_err(), ErrorKind::NotFound, "forward.remove", "unknown");
        let config = Configuration { forwards: vec![forward(&h, "unregistered")], ..Configuration::default() };
        assert_error(h.client.configure(config).await.unwrap_err(), ErrorKind::NotFound, "configure", "unregistered");
        assert_eq!(h.client.configuration().await.unwrap(), Configuration::default());
        assert!(!h.dir.path().join("unregistered").exists());
    }
}
// Removal closes a live host-to-guest bridge before returning, while another
// route remains usable. Guest listener removal already has the same contract.
#[tokio::test]
async fn removing_host_forward_closes_its_live_streams() {
    for unix in [false, true] {
        let h = harness(unix, "test-build").await;
        let path = h.dir.path().join("target");
        let task = tokio::spawn(echo(UnixListener::bind(&path).unwrap()));
        for id in ["remove", "keep"] {
            h.client.add_host_forward(id.into(), Endpoint::Unix(path.clone())).await.unwrap();
        }
        let mut removed = h.client.forward("remove").await.unwrap();
        let mut kept = h.client.forward("keep").await.unwrap();
        exchange(&mut removed, b"live").await;
        h.client.remove_host_forward("remove").await.unwrap();
        let mut byte = [0];
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), removed.read(&mut byte)).await.unwrap().unwrap(), 0);
        exchange(&mut kept, b"still live").await;
        task.abort();
    }
}
// For each forward direction, each endpoint can half-close independently:
// request EOF leaves replies writable, and reply EOF leaves requests writable.
#[tokio::test]
async fn forward_eof_propagates_in_each_direction() {
    for unix in [false, true] {
        for reverse in [false, true] {
            for server_first in [false, true] {
                let h = harness(unix, "test-build").await;
                let path = h.dir.path().join("endpoint");
                let listener = UnixListener::bind(&path).unwrap();
                if reverse {
                    h.client.add_guest_forward(forward(&h, "eof"), Endpoint::Unix(path)).await.unwrap();
                } else {
                    h.client.add_host_forward("eof".into(), Endpoint::Unix(path)).await.unwrap();
                }
                let endpoint = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    if server_first {
                        stream.write_all(b"reply").await.unwrap();
                        stream.shutdown().await.unwrap();
                    }
                    let mut bytes = vec![];
                    stream.read_to_end(&mut bytes).await.unwrap();
                    assert_eq!(bytes, b"request");
                    if !server_first {
                        stream.write_all(b"reply").await.unwrap();
                        stream.shutdown().await.unwrap();
                    }
                });
                let mut stream: ByteStream = if reverse {
                    Box::new(UnixStream::connect(h.dir.path().join("eof")).await.unwrap())
                } else {
                    h.client.forward("eof").await.unwrap()
                };
                let mut bytes = vec![];
                if server_first {
                    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes)).await.unwrap().unwrap();
                }
                stream.write_all(b"request").await.unwrap();
                stream.shutdown().await.unwrap();
                if !server_first {
                    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes)).await.unwrap().unwrap();
                }
                assert_eq!(bytes, b"reply");
                tokio::time::timeout(Duration::from_secs(2), endpoint).await.unwrap().unwrap();
            }
        }
    }
}

fn assert_refused(result: std::io::Result<()>) {
    let error = result.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    assert!(error.to_string().contains("host endpoint already serves a vessel"), "{error}");
}

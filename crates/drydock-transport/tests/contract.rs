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
                Transport::native(Arc::new(UnixConnections::new(hl, &gp)), Limits::default())
                    .unwrap(),
                Transport::native(Arc::new(UnixConnections::new(gl, &hp)), Limits::default())
                    .unwrap(),
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
            // The remote-forward acknowledgement can arrive after the local
            // listener is bound; wait for the server-side socket before dialing.
            tokio::time::timeout(Duration::from_secs(5), async {
                while !std::path::Path::new(&rp).exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            let guest = Transport::native(
                Arc::new(UnixConnections::new(listener, rp)),
                Limits::default(),
            )
            .unwrap();
            (host, guest)
        }
    };
    Pair {
        host,
        guest,
        _dir: dir,
        tasks,
    }
}
// Real OpenSSH test server at the provider boundary, with disposable host and
// user keys. It runs as the current user and never reads ambient SSH config.
async fn ssh_server(
    dir: &std::path::Path,
    guest: &str,
    reverse: &str,
) -> (ssh::SshConfig, tokio::process::Child) {
    use std::process::Stdio;
    use tokio::process::Command;
    for name in ["host_key", "user_key"] {
        let result = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(dir.join(name))
            .status()
            .await
            .unwrap();
        assert!(result.success());
    }
    let user = Command::new("id").arg("-un").output().await.unwrap();
    let user = String::from_utf8(user.stdout).unwrap().trim().to_owned();
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let config_path = dir.join("sshd_config");
    std::fs::write(&config_path, format!("Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\nPidFile {}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin yes\nAllowUsers {user}\nAllowStreamLocalForwarding yes\n", dir.join("host_key").display(), dir.join("user_key.pub").display(), dir.join("sshd.pid").display())).unwrap();
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
            assert!(
                child.try_wait().unwrap().is_none(),
                "sshd exited: {}",
                std::fs::read_to_string(dir.join("sshd.log")).unwrap()
            );
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (
        ssh::SshConfig {
            host: "127.0.0.1".into(),
            port,
            user,
            host_key: std::fs::read_to_string(dir.join("host_key.pub"))
                .unwrap()
                .trim()
                .into(),
            identity_file: dir.join("user_key"),
            agent_socket: guest.into(),
            reverse_socket: reverse.into(),
        },
        child,
    )
}
fn purposes() -> Vec<Purpose> {
    vec![
        Purpose::Control,
        Purpose::Router,
        Purpose::CleatAttach {
            session: "crew/α".into(),
        },
        Purpose::PortForward {
            host: "::1".into(),
            port: 65535,
        },
    ]
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
        transfer(
            &p.host,
            &mut p.guest,
            purpose.clone(),
            b"\0arbitrary\xffpayload",
        )
        .await;
        transfer(&p.guest, &mut p.host, purpose, b"").await;
    }
}

// ADR 0070: a slow raw stream must not hold up either long-lived link. This
// contract also checks yamux's per-stream flow control and concurrent HTTP/2 calls.
async fn isolation_contract(kind: Kind) {
    for reverse in [false, true] {
        let mut p = pair(kind).await;
        let purpose = Purpose::CleatAttach {
            session: "slow".into(),
        };
        let mut raw = if reverse {
            p.guest.open(purpose).await.unwrap()
        } else {
            p.host.open(purpose).await.unwrap()
        };
        let _unread = if reverse {
            p.host.accept().await.unwrap().unwrap()
        } else {
            p.guest.accept().await.unwrap().unwrap()
        };
        let writer = tokio::spawn(async move { raw.write_all(&vec![7; 16 * 1024 * 1024]).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !writer.is_finished(),
            "fixture must actually backpressure the raw stream"
        );
        let host_opener = p.host.opener.clone();
        let guest_opener = p.guest.opener.clone();
        for (from, to, purpose) in [
            (host_opener, &mut p.guest, Purpose::Control),
            (guest_opener, &mut p.host, Purpose::Router),
        ] {
            let (client, driver) = http2::connect(&from, purpose).await.unwrap();
            let incoming = to.accept().await.unwrap().unwrap();
            let server = tokio::spawn(http2::serve(
                incoming,
                Router::new().route("/hello", get(|| async { "hello" })),
            ));
            let mut calls = JoinSet::new();
            for _ in 0..12 {
                let mut client = client.clone();
                calls.spawn(async move {
                    let response = client
                        .send_request(
                            hyper::Request::builder()
                                .uri("http://agent/hello")
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.version(), hyper::Version::HTTP_2);
                    assert_eq!(
                        response.into_body().collect().await.unwrap().to_bytes(),
                        "hello"
                    );
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
            tokio::time::timeout(Duration::from_secs(20), $contract($kind))
                .await
                .expect("contract timed out");
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
                tc.draw(gs::integers::<usize>().min_value(0).max_value(3)),
                tc.draw(gs::integers::<usize>().min_value(0).max_value(4096)),
            )
        })
        .collect();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
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
    let _partial = UnixStream::connect(p._dir.path().join("guest"))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), p.guest.accept())
            .await
            .is_err()
    );
    tokio::time::timeout(
        Duration::from_secs(2),
        transfer(&p.host, &mut p.guest, Purpose::Control, b"ok"),
    )
    .await
    .unwrap();
    let mut invalid = UnixStream::connect(p._dir.path().join("guest"))
        .await
        .unwrap();
    invalid.write_all(b"wrong").await.unwrap();
    assert_eq!(
        p.guest.accept().await.err().unwrap().kind(),
        io::ErrorKind::InvalidData
    );
    transfer(&p.host, &mut p.guest, Purpose::Router, b"still healthy").await;
}

// Every native kind can carry the yamux fallback, using the same connection
// preface detection and purpose routing as direct single-stream connections.
async fn fallback_contract() {
    let mut p = pair(Kind::Unix).await;
    let stream = UnixStream::connect(p._dir.path().join("guest"))
        .await
        .unwrap();
    let mut mux = Transport::yamux(Box::new(stream), true, Limits::default())
        .await
        .unwrap();
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
                    let mut stream = opener
                        .open(Purpose::PortForward {
                            host: "localhost".into(),
                            port: 1000 + i as u16,
                        })
                        .await
                        .unwrap();
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
            assert_eq!(
                incoming.purpose,
                Purpose::PortForward {
                    host: "localhost".into(),
                    port: 1000 + bytes[0] as u16
                }
            );
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
        let (mut config, mut child) = ssh_server(
            dir.path(),
            guest.to_str().unwrap(),
            reverse.to_str().unwrap(),
        )
        .await;
        if wrong_host {
            config.host_key = std::fs::read_to_string(dir.path().join("user_key.pub"))
                .unwrap()
                .trim()
                .into();
        } else {
            config.identity_file = dir.path().join("host_key");
        }
        let result = ssh::connect(config, Limits::default()).await;
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().kind(),
            io::ErrorKind::ConnectionAborted
        );
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
    let (config, mut child) = ssh_server(
        dir.path(),
        guest.to_str().unwrap(),
        reverse.to_str().unwrap(),
    )
    .await;
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
        Limits {
            queue: 0,
            ..Limits::default()
        },
        Limits {
            pending_headers: 0,
            ..Limits::default()
        },
        Limits {
            header_timeout: Duration::ZERO,
            ..Limits::default()
        },
    ] {
        let (a, _b) = tokio::io::duplex(8);
        let result = Transport::yamux(Box::new(a), true, limits).await;
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::InvalidInput);
    }
}

#[tokio::test]
async fn yamux_fallback_on_native_listener() {
    tokio::time::timeout(Duration::from_secs(2), fallback_contract())
        .await
        .expect("native listener must use yamux for reverse opens");
}

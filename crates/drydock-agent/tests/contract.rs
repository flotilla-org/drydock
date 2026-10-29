mod support;
use drydock_agent::{Agent, Client, Configuration, Endpoint, ErrorKind, InwardForward, OutwardForward, Platform};
use drydock_transport::{ByteStream, Listener};
use std::{sync::Arc, time::Duration};
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

fn forward(h: &Harness, id: &str) -> OutwardForward {
    OutwardForward { id: id.into(), unix: h.dir.path().join(id), tcp: None }
}
fn segment(id: &str) -> String {
    percent_encoding::utf8_percent_encode(id, percent_encoding::NON_ALPHANUMERIC).to_string()
}
fn free_port() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

// ADR 0070: hello is readiness and reports a fresh boot ID; each pushed
// configuration replaces all fields. The configuration's entity tag follows its
// content and the agent's boot, so a host can tell an agent that restarted with
// empty configuration from one that kept what it pushed. A conditional push
// against a stale tag is refused with 412 and changes nothing.
#[tokio::test]
async fn hello_and_tagged_configuration_on_both_transports() {
    for unix in [false, true] {
        let h = harness(unix, "test-build").await;
        let hello = h.client.hello().clone();
        assert_eq!(hello.fingerprint, "test-build");
        assert_eq!(hello.platform, Some(Platform::current()));
        assert!(hello.features.contains(&"forwards".into()) && hello.features.contains(&"processes".into()));
        assert!(hello.boot_id.len() == 32 && hello.boot_id.bytes().all(|b| b.is_ascii_hexdigit()), "{}", hello.boot_id);
        assert!(!hello.probation);
        let initial = h.client.configuration().await.unwrap();
        assert_eq!(initial.value, Configuration::default());
        assert!(initial.etag.starts_with(&format!("\"{}-", hello.boot_id)), "{}", initial.etag);
        let restarted = harness(unix, "test-build").await;
        let error = restarted.client.configure_if(Configuration::default(), &initial.etag).await.unwrap_err();
        assert_eq!(agent_error(&error).status, 412, "a tag from another boot never matches, even for the same content");
        let mut tags = vec![initial.etag.clone()];
        for value in ["one", "two", ""] {
            let config = Configuration {
                egress: None,
                ca: format!("CA:{value}"),
                features: vec![value.into()],
                environment: [("HTTPS_PROXY".into(), value.into()), ("TOKEN".into(), "placeholder".into())].into(),
            };
            let etag = h.client.configure(config.clone()).await.unwrap();
            let read = h.client.configuration().await.unwrap();
            assert_eq!((read.value, &read.etag), (config.clone(), &etag));
            assert_eq!(h.client.configure(config).await.unwrap(), etag, "the same content keeps its tag");
            assert!(!tags.contains(&etag));
            tags.push(etag);
        }
        let current = tags.last().unwrap().clone();
        let stale = &tags[0];
        let error = h.client.configure_if(Configuration::default(), stale).await.unwrap_err();
        let detail = assert_error(error, std::io::ErrorKind::Other, "configuration.replace", "configuration");
        assert_eq!((detail.kind, detail.status), (ErrorKind::PreconditionFailed, 412));
        assert!(detail.message.contains(&current) && detail.message.contains(stale), "{detail}");
        assert_eq!(h.client.configuration().await.unwrap().etag, current);
        // A list matches when any of its tags does; a header that is not a
        // list of tags is refused, not ignored.
        let unparsable = h.client.configure_if(Configuration::default(), "not a tag").await.unwrap_err();
        assert_eq!(agent_error(&unparsable).kind, ErrorKind::InvalidInput, "{unparsable}");
        let replaced = h.client.configure_if(Configuration::default(), &format!("{stale}, {current}")).await.unwrap();
        assert_eq!(replaced, initial.etag, "the tag names content and boot, not history");
        // Another agent process, same content: a different boot, so a different tag.
        let other = harness(unix, "test-build").await;
        assert_ne!(other.client.configuration().await.unwrap().etag, initial.etag);
    }
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
        h.client.put_inward_forward(InwardForward { id: "active".into(), endpoint: Endpoint::Unix(path.clone()) }).await.unwrap();
        let mut active = h.client.open_inward("active").await.unwrap();
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
        h.client.put_outward_forward(guest.clone(), Endpoint::Unix(endpoint2)).await.unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&guest.unix).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(h.dir.path()).unwrap().permissions().mode() & 0o777, 0o700);
        let mut reverse: ByteStream = Box::new(UnixStream::connect(&guest.unix).await.unwrap());
        for (index, bytes) in messages.iter().enumerate() {
            exchange(&mut active, bytes).await;
            exchange(&mut reverse, bytes).await;
            if index == 1 {
                h.client
                    .put_inward_forward(InwardForward { id: "transient".into(), endpoint: Endpoint::Unix(path.clone()) })
                    .await
                    .unwrap();
                let mut added = h.client.open_inward("transient").await.unwrap();
                exchange(&mut added, b"added during live traffic").await;
            }
            if index == 2 {
                h.client.remove_inward_forward("transient").await.unwrap();
            }
        }
        h.client.remove_outward_forward("reverse").await.unwrap();
        assert!(!guest.unix.exists());
        h.client.remove_inward_forward("active").await.unwrap();
        let error = h.client.open_inward("active").await.err().unwrap();
        assert_error(error, std::io::ErrorKind::NotFound, "forward.inward.open", "active");
        task.abort();
        task2.abort();
    }
}

// One state model: each forward, outward or inward, is its own resource that can
// be read back and listed. PUT is an idempotent upsert: repeating it changes
// nothing and keeps live streams; changing only TCP keeps the Unix binding and
// its streams; changing a host endpoint ends the old endpoint's streams.
#[tokio::test]
async fn forwards_are_resources_with_idempotent_upserts() {
    for unix in [false, true] {
        let h = harness(unix, "test-build").await;
        let target = h.dir.path().join("target");
        let echo_task = tokio::spawn(echo(UnixListener::bind(&target).unwrap()));
        let f = forward(&h, "changing");
        h.client.put_outward_forward(f.clone(), Endpoint::Unix(target.clone())).await.unwrap();
        assert_eq!(h.client.outward_forward("changing").await.unwrap(), f);
        let mut unix: ByteStream = Box::new(UnixStream::connect(&f.unix).await.unwrap());
        exchange(&mut unix, b"before").await;
        h.client.put_outward_forward(f.clone(), Endpoint::Unix(target.clone())).await.unwrap();
        exchange(&mut unix, b"identical upsert keeps the stream").await;
        let mut changed = f.clone();
        changed.tcp = Some(free_port());
        h.client.put_outward_forward(changed.clone(), Endpoint::Unix(target.clone())).await.unwrap();
        assert_eq!(h.client.outward_forwards().await.unwrap(), vec![changed.clone()]);
        let mut tcp: ByteStream = Box::new(tokio::net::TcpStream::connect(changed.tcp.unwrap()).await.unwrap());
        exchange(&mut tcp, b"added TCP").await;
        exchange(&mut unix, b"Unix survives a TCP change").await;
        h.client.put_outward_forward(f.clone(), Endpoint::Unix(target.clone())).await.unwrap();
        assert!(tokio::net::TcpStream::connect(changed.tcp.unwrap()).await.is_err());
        let mut retained: ByteStream = Box::new(UnixStream::connect(&f.unix).await.unwrap());
        exchange(&mut retained, b"retained Unix").await;
        h.client.remove_outward_forward("changing").await.unwrap();
        let error = h.client.outward_forward("changing").await.unwrap_err();
        assert_error(error, std::io::ErrorKind::NotFound, "forward.outward.read", "changing");
        assert!(h.client.outward_forwards().await.unwrap().is_empty());

        let other = h.dir.path().join("other-target");
        let other_task = tokio::spawn(echo(UnixListener::bind(&other).unwrap()));
        let first = InwardForward { id: "service".into(), endpoint: Endpoint::Unix(target.clone()) };
        h.client.put_inward_forward(first.clone()).await.unwrap();
        assert_eq!(h.client.inward_forward("service").await.unwrap(), first);
        let mut live = h.client.open_inward("service").await.unwrap();
        exchange(&mut live, b"host to guest").await;
        h.client.put_inward_forward(first.clone()).await.unwrap();
        exchange(&mut live, b"identical upsert keeps the stream").await;
        // An ID may contain `/`; it still names one forward.
        let slashed = InwardForward { id: "a/b".into(), endpoint: Endpoint::Unix(target.clone()) };
        h.client.put_inward_forward(slashed.clone()).await.unwrap();
        assert_eq!(h.client.inward_forward("a/b").await.unwrap(), slashed);
        h.client.remove_inward_forward("a/b").await.unwrap();
        let moved = InwardForward { id: "service".into(), endpoint: Endpoint::Unix(other) };
        h.client.put_inward_forward(moved.clone()).await.unwrap();
        assert_eq!(h.client.inward_forwards().await.unwrap(), vec![moved]);
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), live.read(&mut byte)).await.unwrap().unwrap(),
            0,
            "moved endpoint ends old streams"
        );
        let mut fresh = h.client.open_inward("service").await.unwrap();
        exchange(&mut fresh, b"new endpoint").await;
        echo_task.abort();
        other_task.abort();
    }
}

// The host resolves only IDs registered in the announcing vessel's client. A
// guessed ID/path from another vessel is never claimed, and a host endpoint cannot be
// shared between clients (including a symlink alias).
#[tokio::test]
async fn isolation_and_endpoint_ownership() {
    let a = harness(false, "test-build").await;
    let b = harness(false, "test-build").await;
    let endpoint = a.dir.path().join("endpoint");
    let listener = UnixListener::bind(&endpoint).unwrap();
    a.client.put_outward_forward(forward(&a, "private"), Endpoint::Unix(endpoint.clone())).await.unwrap();
    assert_refused(b.client.put_outward_forward(forward(&b, "private"), Endpoint::Unix(endpoint.clone())).await);
    let alias = b.dir.path().join("alias");
    std::os::unix::fs::symlink(&endpoint, &alias).unwrap();
    assert_refused(b.client.register_host_endpoint("alias".into(), Endpoint::Unix(alias)));
    let hardlink = b.dir.path().join("hardlink");
    std::fs::hard_link(&endpoint, &hardlink).unwrap();
    assert_refused(b.client.register_host_endpoint("hardlink".into(), Endpoint::Unix(hardlink)));
    // Vessel b names a's forward, and a's endpoint path, for its own
    // listeners, bypassing its client. Its connections are announced to b's
    // client, which claims none of them: those IDs are not in its registry.
    for (index, id) in ["private".to_owned(), endpoint.display().to_string()].into_iter().enumerate() {
        let unix = b.dir.path().join(format!("attack-{index}"));
        let body = serde_json::to_vec(&OutwardForward { id: id.clone(), unix: unix.clone(), tcp: None }).unwrap();
        let uri = format!("/forwards/outward/{}", segment(&id));
        assert_eq!(raw(&b, "PUT", &uri, &[("content-type", "application/json")], body).await.0, 201);
        let _attack = UnixStream::connect(&unix).await.unwrap();
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
    // The owning client may register the same endpoint again under its ID,
    // but not move that ID to a different endpoint.
    let other = a.dir.path().join("other");
    let _other_listener = UnixListener::bind(&other).unwrap();
    let error = a.client.register_host_endpoint("private".into(), Endpoint::Unix(other)).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists, "{error}");
}

// Generated operation sequences over two forward IDs: valid upserts, removals,
// and refused upserts (empty, oversized and control-character IDs, a body ID
// that differs from the route, wildcard TCP). After every step the agent's
// listing equals a model of the accepted operations, refusals change nothing,
// and every listed forward has a live socket.
#[hegel::test]
fn forward_operation_sequences(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let steps = tc.draw(gs::integers::<usize>().min_value(1).max_value(10));
    let ops: Vec<(u8, bool)> =
        (0..steps).map(|_| (tc.draw(gs::integers::<u8>().min_value(0).max_value(7)), tc.draw(gs::booleans()))).collect();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let h = harness(false, "test-build").await;
        let ids = ["x".to_owned(), "x".repeat(1024)];
        let mut listeners = vec![];
        for (index, id) in ids.iter().enumerate() {
            let path = h.dir.path().join(format!("registered-{index}"));
            listeners.push(UnixListener::bind(&path).unwrap());
            h.client.register_host_endpoint(id.clone(), Endpoint::Unix(path)).unwrap();
        }
        let endpoint = |index: usize| Endpoint::Unix(h.dir.path().join(format!("registered-{index}")));
        let mut model = std::collections::BTreeMap::new();
        for (op, second) in ops {
            let index = second as usize;
            let id = ids[index].clone();
            let unix = h.dir.path().join(format!("guest-{index}-{op}"));
            let result = match op {
                0 | 1 => {
                    let f = OutwardForward { id: id.clone(), unix, tcp: None };
                    let result = h.client.put_outward_forward(f.clone(), endpoint(index)).await;
                    if result.is_ok() {
                        model.insert(id, f);
                    }
                    result
                }
                2 => {
                    let result = h.client.remove_outward_forward(&id).await;
                    assert_eq!(result.is_ok(), model.remove(&id).is_some());
                    if let Err(error) = &result {
                        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
                    }
                    continue;
                }
                3 => h.client.put_outward_forward(OutwardForward { id: String::new(), unix, tcp: None }, endpoint(index)).await,
                4 => h.client.put_outward_forward(OutwardForward { id: "x".repeat(1025), unix, tcp: None }, endpoint(index)).await,
                5 => h.client.put_outward_forward(OutwardForward { id: "a\nb".into(), unix, tcp: None }, endpoint(index)).await,
                6 => {
                    let f = OutwardForward { id: id.clone(), unix, tcp: Some("0.0.0.0:0".parse().unwrap()) };
                    h.client.put_outward_forward(f, endpoint(index)).await
                }
                _ => {
                    let body = serde_json::json!({"id": "elsewhere", "unix": unix, "tcp": null}).to_string();
                    let error = refused(&h, "PUT", "/forwards/outward/x", &[("content-type", "application/json")], body, 400).await;
                    assert!(error.message.contains("elsewhere"), "{error}");
                    continue;
                }
            };
            assert_eq!(result.is_ok(), matches!(op, 0 | 1), "op {op}: {result:?}");
            let listed = h.client.outward_forwards().await.unwrap();
            assert_eq!(listed, model.values().cloned().collect::<Vec<_>>());
            for forward in listed {
                UnixStream::connect(&forward.unix).await.unwrap();
            }
        }
    });
}

// Host endpoints reserve loopback ports across aliases; guest TCP targets
// remain raw. A refused upsert preserves the working forward and its streams,
// and a crash-stale socket inode is reclaimed by the next upsert.
#[tokio::test]
async fn tcp_endpoints_and_refused_upserts() {
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
        let other = harness(unix, "test-build").await;
        let alias = std::net::SocketAddr::from(([127, 0, 0, 2], endpoint.port()));
        let mut f = forward(&h, "configured");
        f.tcp = Some(free_port());
        h.client.put_outward_forward(f.clone(), Endpoint::Tcp(endpoint)).await.unwrap();
        assert_refused(other.client.register_host_endpoint("alias".into(), Endpoint::Tcp(alias)));
        let mut socket: ByteStream = Box::new(UnixStream::connect(&f.unix).await.unwrap());
        let mut loopback: ByteStream = Box::new(tokio::net::TcpStream::connect(f.tcp.unwrap()).await.unwrap());
        exchange(&mut socket, b"Unix in forward").await;
        exchange(&mut loopback, b"TCP in forward").await;
        let occupied = h.dir.path().join("occupied");
        std::fs::write(&occupied, b"do not replace").unwrap();
        let bad = OutwardForward { id: "configured".into(), unix: occupied.clone(), tcp: f.tcp };
        let error = h.client.put_outward_forward(bad, Endpoint::Tcp(endpoint)).await.unwrap_err();
        assert_error(error, std::io::ErrorKind::AddrInUse, "forward.listen", "occupied");
        assert_eq!(h.client.outward_forward("configured").await.unwrap(), f);
        assert_eq!(std::fs::read(occupied).unwrap(), b"do not replace");
        exchange(&mut socket, b"survived refused upsert").await;
        exchange(&mut loopback, b"TCP survived too").await;
        h.client.put_inward_forward(InwardForward { id: "tcp-target".into(), endpoint: Endpoint::Tcp(endpoint) }).await.unwrap();
        let mut host = h.client.open_inward("tcp-target").await.unwrap();
        exchange(&mut host, b"host to guest TCP").await;
        h.client.remove_outward_forward("configured").await.unwrap();
        assert!(!f.unix.exists());
        // The freed port is ephemeral, so connect may pick it as its own source
        // and reach itself (TCP simultaneous open); only a listener is a failure.
        if let Ok(stream) = tokio::net::TcpStream::connect(f.tcp.unwrap()).await {
            assert_eq!(stream.local_addr().unwrap(), stream.peer_addr().unwrap(), "removed forward still listens");
        }
        // Removal ends the forward's streams, and with them their claim on the
        // host endpoint; until they have closed, nobody can claim it again.
        drop((socket, loopback));
        // A crash leaves a Unix socket inode behind without a listener.
        drop(UnixListener::bind(&f.unix).unwrap());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while let Err(error) = h.client.put_outward_forward(f.clone(), Endpoint::Tcp(endpoint)).await {
            assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse, "{error}");
            assert!(std::time::Instant::now() < deadline, "closed streams must release their claim");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut recovered: ByteStream = Box::new(UnixStream::connect(&f.unix).await.unwrap());
        exchange(&mut recovered, b"after crash").await;
        task.abort();
    }
}

// A port owned by another forward is deliberately not stolen. A refused port
// swap leaves both existing routes usable.
#[tokio::test]
async fn occupied_port_swap_refuses_without_changing_forwards() {
    let h = harness(false, "test-build").await;
    let mut forwards = Vec::new();
    let mut echo_tasks = Vec::new();
    for id in ["port-a", "port-b"] {
        let target = h.dir.path().join(format!("target-{id}"));
        echo_tasks.push(tokio::spawn(echo(UnixListener::bind(&target).unwrap())));
        let mut f = forward(&h, id);
        f.tcp = Some(free_port());
        h.client.put_outward_forward(f.clone(), Endpoint::Unix(target)).await.unwrap();
        forwards.push(f);
    }
    let before = h.client.outward_forwards().await.unwrap();
    let mut swapped = forwards[0].clone();
    swapped.tcp = forwards[1].tcp;
    let endpoint = Endpoint::Unix(h.dir.path().join("target-port-a"));
    let error = h.client.put_outward_forward(swapped, endpoint).await.unwrap_err();
    assert_error(error, std::io::ErrorKind::AddrInUse, "forward.listen", "port-a");
    assert_eq!(h.client.outward_forwards().await.unwrap(), before);
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
    let error =
        h.client.put_inward_forward(InwardForward { id: "zero".into(), endpoint: Endpoint::Tcp("127.0.0.1:0".parse().unwrap()) }).await;
    assert_error(error.unwrap_err(), std::io::ErrorKind::InvalidInput, "forward.inward.put", "zero");
    let target = h.dir.path().join("later");
    h.client.put_inward_forward(InwardForward { id: "later".into(), endpoint: Endpoint::Unix(target.clone()) }).await.unwrap();
    let task = tokio::spawn(echo(UnixListener::bind(target).unwrap()));
    let mut stream = h.client.open_inward("later").await.unwrap();
    exchange(&mut stream, b"late service").await;
    task.abort();
}

// Forward errors cross both real connections with the original kind
// and enough context to tell unknown IDs, dead targets and refusals apart.
#[tokio::test]
async fn forward_errors_name_the_failed_operation_and_subject() {
    use std::io::ErrorKind;
    for unix in [false, true] {
        let h = harness(unix, "test-build").await;
        let path = h.dir.path().join("absent");
        h.client.put_inward_forward(InwardForward { id: "dead".into(), endpoint: Endpoint::Unix(path.clone()) }).await.unwrap();
        let detail = assert_error(h.client.open_inward("dead").await.err().unwrap(), ErrorKind::NotFound, "forward.inward.open", "absent");
        assert!(detail.causes.iter().any(|c| c.contains("os error")), "{detail}");
        let refused_path = h.dir.path().join("refused");
        drop(UnixListener::bind(&refused_path).unwrap());
        h.client.put_inward_forward(InwardForward { id: "refused".into(), endpoint: Endpoint::Unix(refused_path) }).await.unwrap();
        assert_error(h.client.open_inward("refused").await.err().unwrap(), ErrorKind::ConnectionRefused, "forward.inward.open", "refused");
        assert_error(h.client.open_inward("unknown").await.err().unwrap(), ErrorKind::NotFound, "forward.inward.open", "unknown");
        assert_error(h.client.remove_inward_forward("unknown").await.unwrap_err(), ErrorKind::NotFound, "forward.inward.remove", "unknown");
        assert_error(
            h.client.remove_outward_forward("unknown").await.unwrap_err(),
            ErrorKind::NotFound,
            "forward.outward.remove",
            "unknown",
        );
    }
}

// Removal closes a live inward stream before returning, while another route
// remains usable. Outward listener removal already has the same contract.
#[tokio::test]
async fn removing_an_inward_forward_closes_its_live_streams() {
    for unix in [false, true] {
        let h = harness(unix, "test-build").await;
        let path = h.dir.path().join("target");
        let task = tokio::spawn(echo(UnixListener::bind(&path).unwrap()));
        for id in ["remove", "keep"] {
            h.client.put_inward_forward(InwardForward { id: id.into(), endpoint: Endpoint::Unix(path.clone()) }).await.unwrap();
        }
        let mut removed = h.client.open_inward("remove").await.unwrap();
        let mut kept = h.client.open_inward("keep").await.unwrap();
        exchange(&mut removed, b"live").await;
        h.client.remove_inward_forward("remove").await.unwrap();
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
                    h.client.put_outward_forward(forward(&h, "eof"), Endpoint::Unix(path)).await.unwrap();
                } else {
                    h.client.put_inward_forward(InwardForward { id: "eof".into(), endpoint: Endpoint::Unix(path) }).await.unwrap();
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
                    h.client.open_inward("eof").await.unwrap()
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

// The egress forward belongs to this vessel's client registry, just like other
// outward forwards. Unknown IDs must be rejected before any guest changes.
#[tokio::test]
async fn egress_requires_registered_vessel_upstream() {
    let h = harness(false, "test-build").await;
    for id in ["", "unregistered-proxy"] {
        let config = Configuration { egress: Some(drydock_agent::Egress { upstream: id.into() }), ..Configuration::default() };
        assert_eq!(h.client.configure(config).await.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(h.client.configuration().await.unwrap().value, Configuration::default());
    }
}

// Outward TCP listeners require a concrete loopback address. Wildcard and public
// binds must fail before publishing any listener or exemption.
#[tokio::test]
async fn outward_forwards_reject_unspecified_and_nonloopback_addresses() {
    let h = harness(false, "test-build").await;
    let endpoint = h.dir.path().join("host-endpoint");
    let _listener = UnixListener::bind(&endpoint).unwrap();
    for address in ["0.0.0.0:9000", "[::]:9000", "192.0.2.1:9000", "[2001:db8::1]:9000"] {
        let unix = h.dir.path().join("guest-listener");
        let f = OutwardForward { id: "concrete".into(), unix: unix.clone(), tcp: Some(address.parse().unwrap()) };
        let error = h.client.put_outward_forward(f, Endpoint::Unix(endpoint.clone())).await.unwrap_err();
        let detail = assert_error(error, std::io::ErrorKind::InvalidInput, "forward.listen", "guest-listener");
        assert!(detail.message.contains("loopback"), "{detail}");
        assert!(h.client.outward_forwards().await.unwrap().is_empty());
        assert!(!unix.exists());
    }
}

// The one error layer: a refusal from a handler and every refusal the
// framework makes before any handler runs (unknown route, wrong method, wrong
// content type, malformed JSON, JSON of the wrong shape, an oversized body, a
// misspelt query parameter, an undecodable path) is the same structured JSON
// error, with the status its kind maps to, a message that says what was wrong,
// and the framework's other headers. Nothing comes back as text, and nothing
// refused changes state. Other tests check only which kind an operation
// chooses; how a kind is encoded is proven here, and the kind to status table
// in `error::tests`.
#[tokio::test]
async fn refusals_are_structured() {
    let h = harness(false, "test-build").await;
    let json = [("content-type", "application/json")];
    let error = refused(&h, "GET", "/no/such/route", &[], "", 404).await;
    assert_eq!((error.operation.as_str(), error.kind), ("request.route", ErrorKind::NotFound));
    assert!(error.message.contains("/no/such/route"), "{error}");
    let error = refused(&h, "DELETE", "/hello", &[], "", 405).await;
    assert_eq!((error.operation.as_str(), error.kind), ("request.route", ErrorKind::MethodNotAllowed));
    assert!(error.message.contains("DELETE"), "{error}");
    assert!(raw(&h, "DELETE", "/hello", &[], vec![]).await.1.contains_key("allow"), "a 405 keeps its Allow header");
    let error = refused(&h, "PUT", "/configuration", &[("content-type", "text/plain")], "{}", 415).await;
    assert_eq!((error.operation.as_str(), error.kind), ("request", ErrorKind::UnsupportedMediaType));
    assert!(error.message.to_lowercase().contains("content-type"), "{error}");
    let error = refused(&h, "PUT", "/configuration", &json, "{not json", 400).await;
    assert_eq!(error.kind, ErrorKind::InvalidInput);
    assert!(error.message.contains("line 1"), "{error}");
    let error =
        refused(&h, "PUT", "/configuration", &json, r#"{"egress":null,"ca":"","features":[],"environment":{},"forwards":[]}"#, 422).await;
    assert_eq!((error.operation.as_str(), error.kind), ("request", ErrorKind::InvalidData));
    assert!(error.message.contains("unknown field `forwards`"), "{error}");
    let oversized = format!(r#"{{"ca":"{}"}}"#, "x".repeat(17 * 1024 * 1024));
    let error = refused(&h, "PUT", "/configuration", &json, oversized, 413).await;
    assert_eq!((error.operation.as_str(), error.kind), ("request", ErrorKind::PayloadTooLarge));
    let error = refused(&h, "PUT", "/configuration", &json, r#"{"egress":null,"ca":"","features":[],"environment":{"A=B":""}}"#, 400).await;
    assert_eq!(error.operation, "configuration.replace");
    let error = refused(&h, "DELETE", "/entries/tmp/absent?colour=blue", &[], "", 400).await;
    assert_eq!(error.operation, "request");
    assert!(error.message.contains("unknown field `colour`"), "{error}");
    let error = refused(&h, "GET", "/forwards/outward/%FF", &[], "", 400).await;
    assert_eq!(error.operation, "request");
    assert!(error.message.to_lowercase().contains("utf-8") || error.message.contains("decode"), "{error}");
    // Nothing above changed the configuration.
    assert_eq!(h.client.configuration().await.unwrap().value, Configuration::default());
}

// Guest stand-in at the HTTP boundary: serves a fixed hello body and records
// upgrade bodies and confirmations, so a test observes exactly what the host
// sent.
async fn hello_only_guest(hello: serde_json::Value) -> (ByteStream, Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
    use axum::routing::{get, post, put};
    let (dialer, mut guest) = drydock_transport::memory();
    let pushes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (recorded, confirmed) = (pushes.clone(), pushes.clone());
    let router = axum::Router::new()
        .route("/hello", get(move || std::future::ready(axum::Json(hello.clone()))))
        .route(
            "/upgrade",
            put(move |body: bytes::Bytes| {
                recorded.lock().unwrap().push(body.to_vec());
                std::future::ready(())
            }),
        )
        .route(
            "/upgrade/confirm",
            post(move || {
                confirmed.lock().unwrap().push(b"confirm".to_vec());
                std::future::ready(())
            }),
        );
    tokio::spawn(async move {
        while let Ok(stream) = guest.accept().await {
            tokio::spawn(drydock_transport::http::serve(stream, router.clone()));
        }
    });
    (dialer.connect().await.unwrap(), pushes)
}

// An agent that predates platform reporting sends no platform. The host
// already knows the vessel's platform from its prepared form, so it pushes
// that platform's build; it never needs to ask the guest. The push uses the
// same stable upgrade route older agents serve. A candidate on probation that
// is not the wanted build is replaced, never confirmed.
#[tokio::test]
async fn hello_without_platform_gets_the_prepared_platforms_build() {
    let (host, pushes) = hello_only_guest(serde_json::json!({"fingerprint": "older", "features": ["upgrade"], "probation": true})).await;
    let mut host = Some(host);
    // The fake guest never re-executes, so the reconnect after the push times out.
    let error = Client::connect_current(
        || std::future::ready(host.take().ok_or_else(|| std::io::Error::from(std::io::ErrorKind::ConnectionRefused))),
        &Platform::new("linux", "amd64"),
        b"linux amd64 build",
        Duration::from_millis(500),
    )
    .await
    .err()
    .expect("the fake guest never reports the pushed build");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(*pushes.lock().unwrap(), [b"linux amd64 build".to_vec()]);
}

type EventLines =
    tokio::io::Lines<tokio_util::io::StreamReader<futures_util::stream::BoxStream<'static, std::io::Result<bytes::Bytes>>, bytes::Bytes>>;
/// `/events` from the start, as lines, on the harness's raw connection.
async fn events(h: &Harness) -> EventLines {
    events_from(h, "/events").await
}
async fn events_from(h: &Harness, uri: &str) -> EventLines {
    use futures_util::{StreamExt, TryStreamExt};
    use http_body_util::BodyExt;
    use tokio::io::AsyncBufReadExt;
    let request = http::Request::get(uri).body(http_body_util::Full::new(bytes::Bytes::new())).unwrap();
    let response = h.raw.clone().send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/x-ndjson");
    let body = response.into_body().into_data_stream().map_err(std::io::Error::other).boxed();
    tokio_util::io::StreamReader::new(body).lines()
}
async fn next_event(lines: &mut EventLines) -> drydock_agent::events::Event {
    next_record(lines).await.event
}
async fn next_record(lines: &mut EventLines) -> drydock_agent::events::Record {
    let line = tokio::time::timeout(Duration::from_secs(5), lines.next_line()).await.expect("no event arrived").unwrap().unwrap();
    serde_json::from_str(&line).unwrap()
}

// A reader whose /events connection drops resumes from its cursor: an
// announcement made while it was away is the next line it reads, and
// nothing it already read comes again.
#[tokio::test]
async fn a_reader_resumes_from_its_cursor_after_a_dropped_stream() {
    use drydock_agent::events::Event;
    let h = harness(false, "test-build").await;
    let mut lines = events(&h).await;
    let unix = unclaimed_forward(&h, "gap").await;
    let _first = UnixStream::connect(&unix).await.unwrap();
    let seen = next_record(&mut lines).await;
    drop(lines);
    let _second = UnixStream::connect(&unix).await.unwrap();
    let mut resumed = events_from(&h, &format!("/events?since={}", segment(&seen.cursor))).await;
    let Event::OutwardConnection { connection, .. } = next_event(&mut resumed).await else { panic!("the announcement in the gap") };
    let Event::OutwardConnection { connection: first, .. } = seen.event else { panic!("an announcement first") };
    assert_eq!(connection, first + 1);
}
/// An outward forward set straight on the agent, so no client claims its
/// connections.
async fn unclaimed_forward(h: &Harness, id: &str) -> std::path::PathBuf {
    let unix = h.dir.path().join(id);
    let body = serde_json::to_vec(&OutwardForward { id: id.into(), unix: unix.clone(), tcp: None }).unwrap();
    let (status, _, _) = raw(h, "PUT", &format!("/forwards/outward/{}", segment(id)), &[("content-type", "application/json")], body).await;
    assert_eq!(status, 201);
    unix
}
/// A claim of an outward connection as an HTTP/1.1 client makes it: GET with
/// `Upgrade: drydock-forward` on a connection of its own.
async fn claim_over_http1(h: &Harness, id: &str, connection: u64) -> http::Response<hyper::body::Incoming> {
    let stream = h.dial.connect().await.unwrap();
    let (mut sender, link) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await.unwrap();
    tokio::spawn(link.with_upgrades());
    let request = http::Request::get(format!("/forwards/outward/{}/connections/{connection}", segment(id)))
        .header("host", "agent")
        .header("connection", "upgrade")
        .header("upgrade", drydock_transport::http::BYTE_STREAM)
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    sender.send_request(request).await.unwrap()
}

// Outward: the agent accepts a vessel connection, announces it on /events and
// holds it, bytes the guest already sent included, until drydockd claims it;
// the claim's stream is then that connection. A connection is claimed once.
// The claim here is HTTP/1.1's GET with Upgrade; the client uses CONNECT.
#[tokio::test]
async fn an_outward_connection_waits_on_events_for_its_claim() {
    use drydock_agent::events::Event;
    let h = harness(true, "test-build").await;
    let mut lines = events(&h).await;
    let unix = unclaimed_forward(&h, "held").await;
    let mut guest = UnixStream::connect(&unix).await.unwrap();
    guest.write_all(b"sent before the claim").await.unwrap();
    let Event::OutwardConnection { forward, connection } = next_event(&mut lines).await else { panic!("an announcement first") };
    assert_eq!(forward, "held");
    assert_eq!(claim_over_http1(&h, "other", connection).await.status(), 404, "a connection is claimed under its own forward");
    let response = claim_over_http1(&h, "held", connection).await;
    assert_eq!(response.status(), 101);
    let mut claimed = drydock_transport::http::upgraded(hyper::upgrade::on(response)).await.unwrap();
    let mut early = [0; 21];
    claimed.read_exact(&mut early).await.unwrap();
    assert_eq!(&early, b"sent before the claim");
    claimed.write_all(b"reply").await.unwrap();
    let mut reply = [0; 5];
    guest.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"reply");

    let again = claim_over_http1(&h, "held", connection).await;
    assert_eq!(again.status(), 404);
    let body = http_body_util::BodyExt::collect(again.into_body()).await.unwrap().to_bytes();
    let error: drydock_agent::AgentError = serde_json::from_slice(&body).unwrap();
    assert_eq!((error.operation.as_str(), error.kind), ("forward.outward.claim", ErrorKind::NotFound));
}

// A connection nobody claims within the deadline is closed, and the forward's
// failure is reported on /events. A claim after that finds nothing.
#[tokio::test]
async fn an_unclaimed_outward_connection_is_closed_at_its_deadline() {
    use drydock_agent::events::Event;
    let deadline = Duration::from_millis(200);
    let h = harness_with(false, "test-build", |listener, dir| {
        Agent::new(listener, "test-build".into(), dir.join("agent")).with_claim_deadline(deadline)
    })
    .await;
    let mut lines = events(&h).await;
    let unix = unclaimed_forward(&h, "ignored").await;
    let started = std::time::Instant::now();
    let mut guest = UnixStream::connect(&unix).await.unwrap();
    let Event::OutwardConnection { connection, .. } = next_event(&mut lines).await else { panic!("an announcement first") };
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), guest.read_to_end(&mut rest)).await.expect("closed at the deadline").unwrap();
    assert!(rest.is_empty());
    assert!(started.elapsed() >= deadline, "closed after {:?}", started.elapsed());
    let Event::ForwardFailed { forward, reason } = next_event(&mut lines).await else { panic!("a failure next") };
    assert_eq!(forward, "ignored");
    assert!(reason.contains(&format!("connection {connection} was not claimed")), "{reason}");
    assert_eq!(claim_over_http1(&h, "ignored", connection).await.status(), 404);
}

// Plain HTTP on the agent's socket: curl, with no drydock code, reaches
// /hello over HTTP/1.1 and follows /events over HTTP/2 by prior knowledge,
// where a process the agent ran has reported its exit.
#[tokio::test]
async fn curl_reaches_hello_and_events_on_the_socket() {
    use drydock_agent::events::{Event, Record};
    let h = harness(true, "test-build").await;
    let process = h.client.spawn(shell("exit 3")).await.unwrap();
    let id = process.id().to_owned();
    assert_eq!(output(process.output().await.unwrap()).await.2.code, Some(3));
    let curl =
        |args: &[&str]| tokio::process::Command::new("curl").arg("--unix-socket").arg(h.dial.socket()).arg("-sS").args(args).output();
    let hello = curl(&["--http1.1", "http://agent/hello"]).await.expect("curl is required by this test");
    assert!(hello.status.success(), "{}", String::from_utf8_lossy(&hello.stderr));
    let hello: drydock_agent::Hello = serde_json::from_slice(&hello.stdout).unwrap();
    assert_eq!(hello.fingerprint, "test-build");
    // /events stays open; curl gives up after a second with what arrived.
    let events = curl(&["--http2-prior-knowledge", "--max-time", "1", "http://agent/events"]).await.unwrap();
    assert_eq!(events.status.code(), Some(28), "held open until curl's deadline: {}", String::from_utf8_lossy(&events.stderr));
    let records: Vec<Record> = String::from_utf8(events.stdout).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert!(
        records
            .iter()
            .any(|record| matches!(&record.event, Event::ProcessExited { id: exited, status } if *exited == id && status.code == Some(3))),
        "{records:?}"
    );
    assert!(records.iter().all(|record| record.cursor.starts_with(&format!("{}:", hello.boot_id))));
}

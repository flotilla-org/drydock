use axum::{
    Router,
    extract::Request,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use bytes::Bytes;
use drydock_transport::{ByteStream, Listener, http, ssh};
use http_body_util::{BodyExt, Empty, Full};
use std::{io, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};
#[path = "support/sshd.rs"]
mod sshd;

/// Raw bytes in both directions with a half-close each way.
async fn exchange(mut near: ByteStream, mut far: ByteStream, payload: &[u8]) {
    near.write_all(payload).await.unwrap();
    near.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    far.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, payload);
    // Half-close preserves traffic in the reverse direction.
    far.write_all(b"reply").await.unwrap();
    far.shutdown().await.unwrap();
    bytes.clear();
    near.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"reply");
}

/// A route that turns its request into a byte stream echoing what it reads,
/// as the agent's stream routes do: 200 to an extended CONNECT, 101 to an
/// HTTP/1.1 upgrade.
fn echo_router() -> Router {
    async fn stream(mut request: Request) -> Response {
        let Some(upgrade) = request.extensions_mut().remove::<hyper::upgrade::OnUpgrade>() else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        tokio::spawn(async move {
            let mut stream = http::upgraded(upgrade).await.unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        if request.method() == axum::http::Method::CONNECT {
            StatusCode::OK.into_response()
        } else {
            (StatusCode::SWITCHING_PROTOCOLS, [(header::CONNECTION, "upgrade"), (header::UPGRADE, http::BYTE_STREAM)]).into_response()
        }
    }
    Router::new().route("/hello", get(|| async { "hello" })).route("/stream", get(stream).connect(stream))
}

// One socket serves HTTP/1.1 and HTTP/2 by prior knowledge, as curl and
// drydock speak them, and either turns a request into a raw byte stream:
// extended CONNECT on HTTP/2, GET with Upgrade on HTTP/1.1.
#[tokio::test]
async fn one_socket_serves_both_http_versions_and_their_byte_streams() {
    let (dialer, mut listener) = drydock_transport::memory();
    tokio::spawn(async move {
        while let Ok(stream) = listener.accept().await {
            tokio::spawn(http::serve(stream, echo_router()));
        }
    });

    let (mut client, driver) = http::connect::<Empty<Bytes>>(dialer.connect().await.unwrap()).await.unwrap();
    let hello = client.send_request(hyper::Request::get("/hello").body(Empty::new()).unwrap()).await.unwrap();
    assert_eq!(hello.into_body().collect().await.unwrap().to_bytes(), "hello");
    let mut connect = hyper::Request::connect("http://agent/stream").body(Empty::new()).unwrap();
    connect.extensions_mut().insert(hyper::ext::Protocol::from_static(http::BYTE_STREAM));
    let mut response = client.send_request(connect).await.unwrap();
    assert_eq!(response.status(), 200);
    let upgrade = response.extensions_mut().remove::<hyper::upgrade::OnUpgrade>().unwrap();
    let (near, far) = tokio::io::duplex(1024);
    let echoed = tokio::spawn(async move {
        let mut stream = http::upgraded(upgrade).await.unwrap();
        let mut far: ByteStream = Box::new(far);
        tokio::io::copy_bidirectional(&mut stream, &mut far).await.unwrap();
    });
    let mut near: ByteStream = Box::new(near);
    near.write_all(b"over h2\0\xff").await.unwrap();
    near.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    near.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"over h2\0\xff");
    echoed.await.unwrap();
    driver.abort();

    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(hyper_util::rt::TokioIo::new(dialer.connect().await.unwrap()))
            .await
            .unwrap();
    tokio::spawn(connection.with_upgrades());
    let hello = sender.send_request(hyper::Request::get("/hello").header("host", "agent").body(Empty::new()).unwrap()).await.unwrap();
    assert_eq!(hello.into_body().collect().await.unwrap().to_bytes(), "hello");
    let upgrade = hyper::Request::get("/stream")
        .header("host", "agent")
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, http::BYTE_STREAM)
        .body(Empty::new())
        .unwrap();
    let response = sender.send_request(upgrade).await.unwrap();
    assert_eq!(response.status(), 101);
    let mut stream = http::upgraded(hyper::upgrade::on(response)).await.unwrap();
    stream.write_all(b"over h1").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"over h1");
}

// Clients accept streaming request bodies; both chunks must arrive intact
// through the same HTTP/2 connection rather than requiring a fully buffered body.
#[tokio::test]
async fn http2_streaming_request_body() {
    let (near, far) = tokio::io::duplex(4096);
    let server =
        tokio::spawn(http::serve(Box::new(far), Router::new().route("/upload", axum::routing::post(|body: Bytes| async move { body }))));
    let frames = ["first", "second"].map(|s| Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(Bytes::from_static(s.as_bytes()))));
    let body = http_body_util::StreamBody::new(futures::stream::iter(frames));
    let (mut client, driver) = http::connect(Box::new(near)).await.unwrap();
    let response =
        client.send_request(hyper::Request::builder().method("POST").uri("http://agent/upload").body(body).unwrap()).await.unwrap();
    assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), "firstsecond");
    driver.abort();
    server.abort();
}

// A link whose peer stops polling must fail via HTTP/2 keepalive, even when the
// underlying byte stream remains open. Paused time avoids wall-clock waits.
#[tokio::test(start_paused = true)]
async fn http2_keepalive_detects_silent_peer() {
    let (near, far) = tokio::io::duplex(4096);
    let (mut client, driver) = http::connect::<Full<Bytes>>(Box::new(near)).await.unwrap();
    let (pause, paused) = tokio::sync::oneshot::channel();
    let (ack, received) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let serve = http::serve(Box::new(far), Router::new().route("/hello", get(|| async { "hello" })));
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

// Through a real OpenSSH server that grants only local forwards, as Daytona's
// gateway does, the connection reaches the agent socket and carries raw
// bytes both ways with half-close. Dropping it ends the session, closing
// the agent's end too.
#[tokio::test]
async fn ssh_reaches_the_agent_socket_and_drop_ends_the_session() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (config, mut server) = sshd::start(dir.path(), &socket).await;
    let near = ssh::connect(config.clone()).await.unwrap();
    let (far, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await.unwrap().unwrap();
    exchange(near, Box::new(far), b"through ssh\0\xff").await;

    let near = ssh::connect(config).await.unwrap();
    let (mut far, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await.unwrap().unwrap();
    drop(near);
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), far.read_to_end(&mut rest)).await.expect("SSH session must end after drop").ok();
    server.kill().await.unwrap();
}

#[tokio::test]
async fn ssh_rejects_wrong_host_and_identity_keys() {
    for wrong_host in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let (mut config, mut child) = sshd::start(dir.path(), &socket).await;
        if wrong_host {
            config.host_key = std::fs::read_to_string(dir.path().join("user_key.pub")).unwrap().trim().into();
        } else {
            config.identity_file = dir.path().join("host_key");
        }
        let error = ssh::connect(config).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        child.kill().await.unwrap();
    }
}

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
        };
        let error = ssh::connect(config).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}

// SSH bootstrap has its own budget: a zero budget is refused and a silent
// TCP endpoint obeys it.
#[tokio::test]
async fn ssh_setup_obeys_its_connect_budget() {
    let dir = tempfile::tempdir().unwrap();
    let (mut config, mut server) = sshd::start(dir.path(), &dir.path().join("agent.sock")).await;
    let mut invalid = config.clone();
    invalid.connect_timeout = Duration::ZERO;
    assert_eq!(ssh::connect(invalid).await.err().unwrap().kind(), io::ErrorKind::InvalidInput);
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.port = silent.local_addr().unwrap().port();
    config.connect_timeout = Duration::from_millis(50);
    let error = tokio::time::timeout(Duration::from_secs(2), ssh::connect(config)).await.unwrap().err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    server.kill().await.unwrap();
}

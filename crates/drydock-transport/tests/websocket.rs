//! The WebSocket tunnel against an in-process server that, like Tensorlake's
//! tunnel proxy, refuses frames over 64 KiB by dropping the connection.
use drydock_transport::{
    ByteStream, Listener,
    websocket::{
        self, DialError, TlsDialer, WebSocketDialer,
        tokio_tungstenite::{WebSocketStream, accept_hdr_async_with_config},
        tungstenite::{
            Message, Utf8Bytes,
            handshake::server::{ErrorResponse, Request, Response},
            http::{HeaderMap, HeaderValue, StatusCode, header},
            protocol::{CloseFrame, Role, WebSocketConfig, frame::coding::CloseCode},
        },
    },
};
use futures::{SinkExt, StreamExt};
use hegel::generators as gs;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The largest frame the stand-in accepts, as Tensorlake's proxy does.
const PROXY_FRAME_LIMIT: usize = 64 << 10;
const KEY: &str = "Bearer tl_apiKey_test";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

/// The provider's side of a dial: upgrades only a request carrying `KEY`,
/// answering others 401, and enforces the frame limit.
// tungstenite's callback signature fixes the error type.
#[allow(clippy::result_large_err)]
async fn accept(stream: ByteStream) -> Option<WebSocketStream<ByteStream>> {
    let config = WebSocketConfig::default().max_frame_size(Some(PROXY_FRAME_LIMIT));
    let check = |request: &Request, response: Response| -> Result<Response, ErrorResponse> {
        if request.headers().get(header::AUTHORIZATION).is_some_and(|v| v == KEY) {
            Ok(response)
        } else {
            let mut refusal = ErrorResponse::new(Some("missing or invalid API key".into()));
            *refusal.status_mut() = StatusCode::UNAUTHORIZED;
            Err(refusal)
        }
    };
    accept_hdr_async_with_config(stream, check, Some(config)).await.ok()
}

fn authorized() -> HeaderMap {
    let mut headers = HeaderMap::new();
    let mut value = HeaderValue::from_static(KEY);
    value.set_sensitive(true);
    headers.insert(header::AUTHORIZATION, value);
    headers
}

/// A tunnel whose far end runs `serve` on the accepted WebSocket.
async fn tunnel<F, Fut>(max_frame: usize, serve: F) -> ByteStream
where
    F: FnOnce(WebSocketStream<ByteStream>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let (dialer, mut listener) = drydock_transport::memory();
    tokio::spawn(async move {
        let socket = accept(listener.accept().await.unwrap()).await.expect("authorized upgrade");
        serve(socket).await;
    });
    let socket = dialer.dial("wss://sandbox.example/api/v1/tunnels/tcp?port=7811", authorized()).await.unwrap();
    websocket::stream(socket, max_frame)
}

// Bytes written through the tunnel arrive in order and whole, in binary
// frames of at most `max_frame` bytes each, and what the far end sends back
// reads back whole. Writes span empty, sub-frame, frame-boundary and
// multi-frame sizes (past 256 KiB, the size that killed a live tunnel);
// frame limits span one byte to the proxy's own limit.
#[hegel::test]
fn tunnels_carry_bytes_in_bounded_frames(tc: hegel::TestCase) {
    let max_frame = tc.draw(gs::sampled_from(vec![1, 7, 16 << 10, PROXY_FRAME_LIMIT - 1, PROXY_FRAME_LIMIT]));
    let sizes = tc.draw(gs::vecs(gs::sampled_from(vec![0, 1, 100, max_frame, max_frame + 1, 3 * max_frame + 5, 300 << 10])).max_size(4));
    let sizes: Vec<usize> = sizes.into_iter().map(|size| if max_frame < 16 { size.min(64) } else { size }).collect();
    let seed = tc.draw(gs::integers::<u8>());
    let payload: Vec<u8> = (0..sizes.iter().sum::<usize>()).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect();
    runtime().block_on(async {
        let (frames, mut seen) = tokio::sync::mpsc::unbounded_channel();
        let stream = tunnel(max_frame, move |mut socket| async move {
            // Echo every binary frame, noting its size.
            while let Some(Ok(message)) = socket.next().await {
                if let Message::Binary(bytes) = message {
                    let _ = frames.send(bytes.len());
                    if socket.send(Message::Binary(bytes)).await.is_err() {
                        break;
                    }
                }
            }
        })
        .await;
        // Read while writing: the echo would otherwise fill both directions.
        let (mut reader, mut writer) = tokio::io::split(stream);
        let length = payload.len();
        let reading = tokio::spawn(async move {
            let mut echoed = vec![0; length];
            reader.read_exact(&mut echoed).await.map(|_| (echoed, reader))
        });
        let mut offset = 0;
        for size in &sizes {
            writer.write_all(&payload[offset..offset + size]).await.unwrap();
            offset += size;
        }
        writer.flush().await.unwrap();
        let (echoed, reader) = tokio::time::timeout(Duration::from_secs(30), reading).await.unwrap().unwrap().unwrap();
        assert_eq!(echoed, payload);
        drop(reader.unsplit(writer));
        let mut carried = 0;
        while let Some(size) = seen.recv().await {
            assert!(size > 0 && size <= max_frame, "a {size}-byte frame under a {max_frame}-byte limit");
            carried += size;
        }
        assert_eq!(carried, payload.len());
    });
}

/// How the far end ends a tunnel after sending its bytes.
#[derive(Clone, Copy, Debug)]
enum Ending {
    Normal,
    CloseWithoutCode,
    /// The connection drops with no close frame: 1006, as Tensorlake's
    /// proxy ends a tunnel.
    Dropped,
    Error,
    Text,
    /// A message over the dialers' 4 MiB incoming limit.
    Oversized,
}

// A normal close, a close without a code and a dropped connection end the
// byte stream after every byte sent before them; another close code or a
// text message is an error, after those bytes too, and so is a message
// over the incoming limit. Every ending is run
// for each drawn payload, empty included.
#[hegel::test]
fn tunnels_end_at_normal_and_abnormal_closes(tc: hegel::TestCase) {
    let sent = tc.draw(gs::vecs(gs::integers::<u8>()).max_size(100));
    for ending in [Ending::Normal, Ending::CloseWithoutCode, Ending::Dropped, Ending::Error, Ending::Text, Ending::Oversized] {
        runtime().block_on(ends(ending, &sent));
    }
}

/// One tunnel the far end ends with `ending` after sending `sent`.
async fn ends(ending: Ending, sent: &[u8]) {
    let bytes = sent.to_vec();
    let mut stream = tunnel(PROXY_FRAME_LIMIT, move |mut socket| async move {
        socket.send(Message::Binary(bytes.into())).await.unwrap();
        let close = |code, reason: &str| Message::Close(Some(CloseFrame { code, reason: Utf8Bytes::from(reason) }));
        match ending {
            Ending::Normal => socket.send(close(CloseCode::Normal, "")).await.unwrap(),
            Ending::CloseWithoutCode => socket.send(Message::Close(None)).await.unwrap(),
            Ending::Error => socket.send(close(CloseCode::Error, "agent gone")).await.unwrap(),
            Ending::Text => socket.send(Message::text("hello")).await.unwrap(),
            Ending::Oversized => {
                let _ = socket.send(Message::Binary(vec![0; (4 << 20) + 1].into())).await;
            }
            Ending::Dropped => {}
        }
        drop(socket);
    })
    .await;
    let mut received = vec![0; sent.len()];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(received, sent);
    let mut rest = Vec::new();
    let end = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut rest)).await.unwrap();
    match ending {
        Ending::Normal | Ending::CloseWithoutCode | Ending::Dropped => assert!(end.is_ok() && rest.is_empty(), "{end:?}"),
        Ending::Error | Ending::Text | Ending::Oversized => assert!(end.is_err(), "{ending:?} reads as {end:?}"),
    }
}

// A TLS connection cut without close_notify reads as UnexpectedEof beneath
// the WebSocket; that too is a dropped connection (1006), so the bytes end
// rather than fail. The raw stream stands in for rustls at that boundary.
#[tokio::test]
async fn a_truncated_tls_connection_ends_the_tunnel() {
    struct Truncated(Option<Vec<u8>>);
    impl tokio::io::AsyncRead for Truncated {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let Some(bytes) = self.0.take() else {
                return std::task::Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
            };
            buf.put_slice(&bytes);
            std::task::Poll::Ready(Ok(()))
        }
    }
    impl tokio::io::AsyncWrite for Truncated {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
    // One unmasked binary frame from the server, "tail", then the cut.
    let raw: ByteStream = Box::new(Truncated(Some(vec![0x82, 4, b't', b'a', b'i', b'l'])));
    let socket = WebSocketStream::from_raw_socket(raw, Role::Client, None).await;
    let mut stream = websocket::stream(socket, PROXY_FRAME_LIMIT);
    let mut received = Vec::new();
    stream.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, b"tail");
}

// Shutting the stream down sends a normal close, so the far end sees the
// tunnel end rather than a dropped connection; later writes are BrokenPipe.
#[tokio::test]
async fn shutdown_sends_a_normal_close() {
    let (closed, received) = tokio::sync::oneshot::channel();
    let mut stream = tunnel(PROXY_FRAME_LIMIT, move |mut socket| async move {
        let mut last = None;
        while let Some(Ok(message)) = socket.next().await {
            last = Some(message);
        }
        let _ = closed.send(last);
    })
    .await;
    stream.write_all(b"bye").await.unwrap();
    stream.shutdown().await.unwrap();
    let after = stream.write_all(b"more").await.unwrap_err();
    assert_eq!(after.kind(), std::io::ErrorKind::BrokenPipe, "{after}");
    let last = tokio::time::timeout(Duration::from_secs(10), received).await.unwrap().unwrap();
    assert!(
        matches!(last, Some(Message::Close(None)) | Some(Message::Close(Some(CloseFrame { code: CloseCode::Normal, .. })))),
        "{last:?}"
    );
}

// Both dialers send the given headers with the upgrade: with the key the
// server switches, and without it the refusal's status and body come back
// as `DialError::Refused`. The TLS dialer is exercised over plain `ws://`
// to a real loopback TCP listener; TLS itself is left to the live check.
#[tokio::test]
async fn dials_carry_headers_and_report_refusals() {
    let (memory, mut memory_listener) = drydock_transport::memory();
    tokio::spawn(async move {
        while let Ok(stream) = memory_listener.accept().await {
            tokio::spawn(accept(stream));
        }
    });
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/api/v1/tunnels/tcp?port=7811", tcp.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((stream, _)) = tcp.accept().await {
            tokio::spawn(accept(Box::new(stream)));
        }
    });
    let tls = TlsDialer::new().unwrap();
    for dialer in [&memory as &dyn WebSocketDialer, &tls] {
        dialer.dial(&url, authorized()).await.expect("the key is accepted");
        match dialer.dial(&url, HeaderMap::new()).await {
            Err(DialError::Refused { status: 401, body }) => assert!(body.contains("API key"), "{body}"),
            other => panic!("{:?}", other.map(drop)),
        }
    }
    assert!(matches!(tls.dial("https://example.invalid/", HeaderMap::new()).await, Err(DialError::Io(_))));
    // Cleartext beyond loopback is refused before any connection, and the
    // refusal leaves out the query, which may carry a credential.
    match tls.dial("ws://192.0.2.1/api/v1/tunnels/tcp?token=secret", authorized()).await {
        Err(DialError::Io(error)) => {
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(!error.to_string().contains("secret"), "{error}");
        }
        other => panic!("{:?}", other.map(drop)),
    }
}

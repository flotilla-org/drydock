//! An agent reached through a provider's HTTP edge, as Modal's connect
//! tokens do: the edge takes its own credential from the query, forwards the
//! request with the agent's `Authorization`, and splices the bytes after the
//! agent's 101, for a WebSocket upgrade only. Any other upgrade gets the
//! agent's 101 with `connection: upgrade, close` and nothing after it.
use drydock_transport::{
    ByteStream,
    tcp::{self, CONNECT_PATH, Token},
    websocket::{StreamDialer, TlsDialer},
};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const EDGE_KEY: &str = "edge-credential";

/// The edge and the agent behind it, in one: the query must carry
/// `EDGE_KEY` (else the edge's 401), the request the agent's token (else the
/// agent's 401). Upgraded connections echo, if they asked for `websocket`.
/// Each request seen is sent back to the test.
async fn serve(mut stream: ByteStream, token: Token, seen: tokio::sync::mpsc::UnboundedSender<String>) -> io::Result<()> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        if stream.read(&mut byte).await? == 0 {
            return Ok(());
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let _ = seen.send(head.clone());
    let target = head.split(' ').nth(1).unwrap_or_default().to_owned();
    let header = |name: &str| {
        head.lines().find_map(|line| line.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_owned()))
    };
    let answer = if !target.contains(&format!("_edge={EDGE_KEY}")) {
        "HTTP/1.1 401 Unauthorized\r\ncontent-length: 21\r\n\r\ninvalid connect token"
    } else if !target.starts_with(&format!("{CONNECT_PATH}?"))
        || !header("authorization").is_some_and(|v| v.strip_prefix("Bearer ").is_some_and(|t| token.admits(t.as_bytes())))
    {
        "HTTP/1.1 401 Unauthorized\r\ncontent-length: 27\r\n\r\n{\"error\":\"wrong tcp token\"}"
    } else if !header("upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket")) {
        "HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade, close\r\nupgrade: drydock-agent\r\n\r\n"
    } else {
        "HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n"
    };
    stream.write_all(answer.as_bytes()).await?;
    if answer.contains("upgrade: websocket") {
        let (mut reader, mut writer) = tokio::io::split(stream);
        tokio::io::copy(&mut reader, &mut writer).await?;
    }
    Ok(())
}

// Through both dialers, the agent's token and the edge's credential both
// pass: bytes cross after the 101 unframed, the request asks the URL's path
// and query with its authority as Host and the token as Bearer, as a
// WebSocket upgrade with a fresh key each time. A wrong token or a wrong edge
// credential is PermissionDenied with the answer's status and start, and no
// error text shows the URL's query.
#[tokio::test]
async fn an_agent_behind_an_edge_is_reached_at_its_url() {
    let token = Token::generate().unwrap();
    let (seen, mut requests) = tokio::sync::mpsc::unbounded_channel();
    let (memory, mut memory_listener) = drydock_transport::memory();
    let (served, sent) = (token.clone(), seen.clone());
    tokio::spawn(async move {
        use drydock_transport::Listener;
        while let Ok(stream) = memory_listener.accept().await {
            tokio::spawn(serve(stream, served.clone(), sent.clone()));
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let served = token.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve(Box::new(stream), served.clone(), seen.clone()));
        }
    });
    let url = |key: &str| format!("http://{authority}{CONNECT_PATH}?_edge={key}");
    let tls = TlsDialer::new().unwrap();
    let mut keys = Vec::new();
    for dialer in [&memory as &dyn StreamDialer, &tls] {
        let mut stream = tcp::connect_at(dialer.connect(&url(EDGE_KEY)).await.unwrap(), &url(EDGE_KEY), &token).await.unwrap();
        let request = requests.recv().await.unwrap();
        assert!(request.starts_with(&format!("GET {CONNECT_PATH}?_edge={EDGE_KEY} HTTP/1.1\r\n")), "{request}");
        assert!(request.to_lowercase().contains(&format!("host: {authority}\r\n")), "{request}");
        let lower = request.to_lowercase();
        assert!(lower.contains("connection: upgrade\r\n") && lower.contains("upgrade: websocket\r\n"), "{request}");
        assert!(lower.contains("sec-websocket-version: 13\r\n"), "{request}");
        let key = request.lines().find_map(|l| l.to_lowercase().strip_prefix("sec-websocket-key: ").map(|_| l[19..].to_owned())).unwrap();
        assert!(
            key.len() == 24 && key.ends_with("==") && key[..22].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/'),
            "{key}"
        );
        keys.push(key);
        let payload: Vec<u8> = (0..1 << 20).map(|i: u32| ((i * 7) >> 3) as u8).collect();
        let (mut reader, mut writer) = tokio::io::split(&mut stream);
        let (_, echoed) = tokio::join!(async { writer.write_all(&payload).await.unwrap() }, async {
            let mut echoed = vec![0; payload.len()];
            reader.read_exact(&mut echoed).await.unwrap();
            echoed
        });
        assert!(echoed == payload, "bytes cross unframed");

        let wrong = Token::generate().unwrap();
        let error = tcp::connect_at(dialer.connect(&url(EDGE_KEY)).await.unwrap(), &url(EDGE_KEY), &wrong).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("401") && error.to_string().contains("wrong tcp token"), "{error}");
        let error = tcp::connect_at(dialer.connect(&url("stolen")).await.unwrap(), &url("stolen"), &token).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("invalid connect token") && !error.to_string().contains("stolen"), "{error}");
        while requests.try_recv().is_ok() {}
    }
    assert_ne!(keys[0], keys[1], "each request has a fresh key");
    // Userinfo would go out in Host: it is refused, and not shown.
    let userinfo = format!("http://user:hunter2@{authority}{CONNECT_PATH}");
    let error = tcp::connect_at(tls.connect(&url(EDGE_KEY)).await.unwrap(), &userinfo, &token).await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(!error.to_string().contains("hunter2"), "{error}");
    // Cleartext beyond loopback is refused before any connection, without the query.
    let error = tls.connect("http://192.0.2.1/v1/connect?_edge=secret").await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(!error.to_string().contains("secret"), "{error}");
    assert_eq!(tls.connect("wss://example.invalid/").await.err().unwrap().kind(), io::ErrorKind::InvalidInput);
}

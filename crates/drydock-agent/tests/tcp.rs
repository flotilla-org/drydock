//! The TCP listener over a real loopback socket: the handshake admits the
//! vessel's token to the agent's full wire and nothing else reaches it; the
//! real executable refuses unsafe token files and keeps the token off argv
//! and its environment.
mod support;
use drydock_agent::{
    Agent, Client, Hello,
    tcp::{self, Token, TokenListener},
};
use drydock_transport::{ByteStream, http as link};
use http_body_util::{BodyExt, Empty};
use std::{net::SocketAddr, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

async fn listening(token: &Token) -> (SocketAddr, tokio::task::JoinHandle<std::io::Result<std::path::PathBuf>>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let (_, unix) = support::pair(true, dir.path());
    let listener = TokenListener::bind("127.0.0.1:0".parse().unwrap(), token.clone()).await.unwrap();
    let address = listener.local_addr();
    let mut agent = Agent::new(unix, "test-build".into(), dir.path().join("agent"));
    agent.add_listener(listener);
    (address, tokio::spawn(agent.run()), dir)
}
async fn dial(address: SocketAddr) -> ByteStream {
    Box::new(TcpStream::connect(address).await.unwrap())
}
/// `GET /hello` over HTTP/2 on a switched connection.
async fn hello_over_h2(stream: ByteStream) -> Hello {
    let (mut sender, _driver) = link::connect::<Empty<bytes::Bytes>>(stream).await.unwrap();
    let response = sender.send_request(http::Request::get("http://agent/hello").body(Empty::new()).unwrap()).await.unwrap();
    assert_eq!(response.status(), 200);
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
/// Write `request` and read everything until the agent closes.
async fn exchange(address: SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer)).await.expect("the agent closes").unwrap();
    String::from_utf8_lossy(&answer).into_owned()
}
fn handshake(authorization: Option<&str>, upgrade: &str) -> String {
    let authorization = authorization.map(|value| format!("Authorization: {value}\r\n")).unwrap_or_default();
    format!("GET /v1/connect HTTP/1.1\r\nHost: sandbox\r\nConnection: Upgrade\r\nUpgrade: {upgrade}\r\n{authorization}\r\n")
}

// The right token gets the agent's whole wire after the 101: HTTP/2 `/hello`
// directly, and the typed client, which goes on to the control connection.
// A proxy that passes only `Upgrade: websocket` gets the same raw bytes.
#[tokio::test]
async fn the_token_switches_to_the_agents_wire() {
    let token = Token::generate().unwrap();
    let (address, _agent, _dir) = listening(&token).await;
    let hello = hello_over_h2(tcp::connect(dial(address).await, &token).await.unwrap()).await;
    assert_eq!(hello.fingerprint, "test-build");
    let client = Client::connect(tcp::connect(dial(address).await, &token).await.unwrap(), "test-build").await.unwrap();
    assert!(client.is_compatible());
    client.hello();

    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(handshake(Some(&format!("Bearer {}", token.secret())), "websocket").as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
    let head = String::from_utf8(head).unwrap().to_lowercase();
    assert!(head.starts_with("http/1.1 101 "), "{head}");
    assert!(head.contains("upgrade: websocket"), "{head}");
    assert_eq!(hello_over_h2(Box::new(stream)).await.fingerprint, "test-build");
}

// A wrong, missing or non-bearer token gets 401 with a JSON problem body and
// a closed connection; bytes sent after it reach nothing. Requests other than
// the handshake, even with the token, get 404 and never the agent's routes.
#[tokio::test]
async fn anything_but_the_token_is_refused() {
    let token = Token::generate().unwrap();
    let (address, _agent, _dir) = listening(&token).await;
    let other = Token::generate().unwrap();
    let wrong = format!("Bearer {}", other.secret());
    let basic = format!("Basic {}", token.secret());
    for authorization in [Some(wrong.as_str()), None, Some(basic.as_str()), Some("Bearer ")] {
        for upgrade in ["drydock-agent", "websocket"] {
            // An HTTP/2 preface and a second request follow the handshake.
            let request = format!("{}PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nGET /hello HTTP/1.1\r\n\r\n", handshake(authorization, upgrade));
            let answer = exchange(address, request.as_bytes()).await;
            assert!(answer.starts_with("HTTP/1.1 401 "), "{authorization:?}: {answer}");
            assert!(answer.to_lowercase().contains("content-type: application/json"), "{answer}");
            assert!(answer.ends_with(r#"{"error":"unauthorized"}"#), "{answer}");
            assert_eq!(answer.matches("HTTP/").count(), 1, "one answer and no API: {answer}");
            assert!(!answer.contains("fingerprint"));
        }
    }
    let error = tcp::connect(dial(address).await, &other).await.err().expect("a wrong token is refused");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied, "{error}");

    let bearer = format!("Authorization: Bearer {}\r\n", token.secret());
    for request in [
        format!("GET /hello HTTP/1.1\r\nHost: a\r\n{bearer}\r\n"),
        format!(
            "POST /v1/connect HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nConnection: Upgrade\r\nUpgrade: drydock-agent\r\n{bearer}\r\n"
        ),
        format!("GET /v1/connect HTTP/1.1\r\nHost: a\r\n{bearer}\r\n"),
        format!("GET /v1/connect HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n{bearer}\r\n"),
    ] {
        let answer = exchange(address, request.as_bytes()).await;
        assert!(answer.starts_with("HTTP/1.1 404 "), "{request}: {answer}");
        assert!(!answer.contains("fingerprint"), "{answer}");
    }
    // HTTP/2 straight away, as on the Unix socket, is not a handshake either.
    let answer = exchange(address, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await;
    assert!(!answer.contains("fingerprint"), "{answer}");
}

fn token_file(dir: &Path, token: &Token, mode: u32) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("tcp.token");
    std::fs::write(&path, format!("{}\n", token.secret())).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}
fn free_port() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

// Startup refuses `--tcp` without a token file and the reverse, and a token
// file that is not private (mode 0644), missing, or too short; supervision
// refuses the same before it detaches anything.
#[tokio::test]
async fn startup_refuses_an_unsafe_tcp_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("run/agent.sock");
    let token = Token::generate().unwrap();
    std::fs::create_dir(dir.path().join("public")).unwrap();
    let public = token_file(&dir.path().join("public"), &token, 0o644);
    let short = dir.path().join("short.token");
    std::fs::write(&short, "c2hvcnQ").unwrap();
    std::fs::set_permissions(&short, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let address = free_port().to_string();
    let (public, short, missing) =
        (public.to_str().unwrap(), short.to_str().unwrap(), dir.path().join("missing").to_string_lossy().into_owned());
    let cases: [&[&str]; 6] = [
        &["--tcp", &address],
        &["--tcp-token-file", public],
        &["--tcp", &address, "--tcp-token-file", public],
        &["--tcp", &address, "--tcp-token-file", short],
        &["--tcp", &address, "--tcp-token-file", &missing],
        &["--tcp", "localhost", "--tcp-token-file", public],
    ];
    for args in cases {
        for supervise in [false, true] {
            let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_drydock-agent"));
            if supervise {
                command.arg("--supervise").args(args).arg("--socket").arg(&socket);
            } else {
                command.args(args).arg("--socket").arg(&socket);
            }
            let output = tokio::time::timeout(Duration::from_secs(10), command.kill_on_drop(true).output()).await.unwrap().unwrap();
            assert!(!output.status.success(), "{args:?} supervise={supervise}");
            assert!(!socket.exists(), "{args:?}: nothing was bound");
        }
    }
    // A valid token file named relatively: supervision refuses it, since the
    // agents it restarts must not depend on the bootstrap's directory.
    let private = dir.path().join("private");
    std::fs::create_dir(&private).unwrap();
    token_file(&private, &token, 0o600);
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_drydock-agent"))
        .args(["--supervise", "--tcp", &address, "--tcp-token-file", "tcp.token", "--socket"])
        .arg(&socket)
        .current_dir(&private)
        .output()
        .await
        .unwrap();
    assert!(!output.status.success() && String::from_utf8_lossy(&output.stderr).contains("absolute"), "{output:?}");
    assert!(!socket.parent().unwrap().exists());
}
// The real executable serves the handshake on its TCP address. The token is
// in neither its argv nor its environment, where other guest users could read
// it through /proc; a refused connection is logged with its peer address.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_agent_keeps_its_token_off_argv_and_environment() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("run/agent.sock");
    let token = Token::generate().unwrap();
    let file = token_file(dir.path(), &token, 0o600);
    let address = free_port();
    let mut agent = support::start(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_drydock-agent"))
            .arg("--tcp")
            .arg(address.to_string())
            .arg("--tcp-token-file")
            .arg(&file)
            .arg("--socket")
            .arg(&socket)
            .stderr(std::process::Stdio::piped()),
    );
    let hello = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(stream) = TcpStream::connect(address).await
                && let Ok(stream) = tcp::connect(Box::new(stream), &token).await
            {
                break hello_over_h2(stream).await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(!hello.fingerprint.is_empty());

    let pid = agent.id().unwrap();
    let secret = token.secret().as_bytes();
    for view in ["cmdline", "environ"] {
        let bytes = std::fs::read(format!("/proc/{pid}/{view}")).unwrap();
        assert!(!bytes.is_empty() || view == "environ");
        assert!(!bytes.windows(secret.len()).any(|w| w == secret), "the token is in /proc/{pid}/{view}");
    }
    assert!(std::fs::read(format!("/proc/{pid}/cmdline")).unwrap().windows(9).any(|w| w == b"--tcp\x00127"));

    let answer = exchange(address, handshake(Some("Bearer nope"), "drydock-agent").as_bytes()).await;
    assert!(answer.starts_with("HTTP/1.1 401 "), "{answer}");
    agent.start_kill().unwrap();
    let mut stderr = String::new();
    agent.stderr.take().unwrap().read_to_string(&mut stderr).await.unwrap();
    assert!(stderr.contains("tcp connection refused") && stderr.contains("127.0.0.1:"), "{stderr}");
    assert!(!stderr.contains(token.secret()));
}

// A connection that sends no handshake is closed at the 10-second deadline,
// and at most 64 handshakes run at once: the 65th connection gets no answer
// until a slot frees, then switches as usual.
#[tokio::test(start_paused = true)]
async fn idle_handshakes_are_bounded_in_time_and_number() {
    let token = Token::generate().unwrap();
    let mut listener = TokenListener::bind("127.0.0.1:0".parse().unwrap(), token.clone()).await.unwrap();
    let address = listener.local_addr();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok(stream) = drydock_transport::Listener::accept(&mut listener).await {
            held.push(stream);
        }
    });
    let mut idle = Vec::new();
    for _ in 0..64 {
        idle.push(TcpStream::connect(address).await.unwrap());
    }
    tokio::task::yield_now().await;
    let mut waiting = TcpStream::connect(address).await.unwrap();
    waiting.write_all(handshake(Some(&format!("Bearer {}", token.secret())), "drydock-agent").as_bytes()).await.unwrap();
    let mut byte = [0u8; 1];
    assert!(tokio::time::timeout(Duration::from_secs(5), waiting.read(&mut byte)).await.is_err(), "the 65th waits for a slot");
    for stream in &mut idle {
        let mut rest = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut rest)).await;
        assert!(matches!(read, Ok(Ok(0))), "an idle handshake is closed at its deadline: {read:?}");
    }
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tokio::time::timeout(Duration::from_secs(20), waiting.read_u8()).await.unwrap().unwrap());
    }
    assert!(head.starts_with(b"HTTP/1.1 101 "), "{}", String::from_utf8_lossy(&head));
}

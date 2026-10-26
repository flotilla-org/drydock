//! Shared harness: a real agent behind a real transport, a typed client, and
//! a raw HTTP/2 sender for requests the typed client would never make; or the
//! real agent executable as a subprocess, for restarts and re-execs.
#![allow(dead_code)]
use bytes::Bytes;
use drydock_agent::{Agent, AgentError, Client, Exec, ExecEvent};
use drydock_transport::{ByteStream, Limits, Purpose, Transport, native::UnixConnections};
use http_body_util::{BodyExt, Full};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::Command,
    task::JoinHandle,
};

pub struct Harness {
    pub client: Client,
    pub guest_opener: drydock_transport::Opener,
    pub raw: drydock_transport::http2::Client,
    pub agent: JoinHandle<std::io::Result<PathBuf>>,
    pub dir: tempfile::TempDir,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.agent.abort();
    }
}
/// A connected host and guest transport: yamux over memory, or native Unix sockets.
pub async fn pair(unix: bool, dir: &Path) -> (Transport, Transport) {
    if unix {
        let hp = dir.join("host");
        let gp = dir.join("guest");
        let hl = UnixListener::bind(&hp).unwrap();
        let gl = UnixListener::bind(&gp).unwrap();
        (
            Transport::native(Arc::new(UnixConnections::new(hl, gp)), Limits::default()).unwrap(),
            Transport::native(Arc::new(UnixConnections::new(gl, hp)), Limits::default()).unwrap(),
        )
    } else {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (a, b) =
            tokio::join!(Transport::yamux(Box::new(a), true, Limits::default()), Transport::yamux(Box::new(b), false, Limits::default()));
        (a.unwrap(), b.unwrap())
    }
}
pub async fn harness(unix: bool, expected: &str) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let (host, guest) = pair(unix, dir.path()).await;
    let guest_opener = guest.opener.clone();
    let agent = tokio::spawn(Agent::new(guest, "test-build".into(), dir.path().join("agent")).run());
    let (raw, driver) = drydock_transport::http2::connect(&host.opener, Purpose::Control).await.unwrap();
    // The raw connection lives as long as the test; its driver is detached.
    drop(driver);
    let client = Client::connect(host, expected).await.unwrap();
    Harness { client, guest_opener, raw, agent, dir }
}

/// Send a request the typed client would not, and return status, headers and body.
pub async fn raw(
    h: &Harness,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: impl Into<Bytes>,
) -> (u16, http::HeaderMap, Vec<u8>) {
    let mut request = http::Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = h.raw.clone().send_request(request.body(Full::new(body.into())).unwrap()).await.unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, headers, body)
}
/// A raw request that must be refused with `status` and a structured error.
pub async fn refused(h: &Harness, method: &str, uri: &str, headers: &[(&str, &str)], body: impl Into<Bytes>, status: u16) -> AgentError {
    let (actual, headers, body) = raw(h, method, uri, headers, body).await;
    assert_eq!(actual, status, "{method} {uri}: {}", String::from_utf8_lossy(&body));
    assert_eq!(headers.get("content-type").map(|v| v.to_str().unwrap()), Some("application/json"), "{method} {uri}");
    let error: AgentError =
        serde_json::from_slice(&body).unwrap_or_else(|e| panic!("{method} {uri}: {e}: {}", String::from_utf8_lossy(&body)));
    assert_eq!(error.status, status, "{error}");
    assert!(!error.message.is_empty(), "{error}");
    error
}
/// The structured error behind a typed client failure.
pub fn agent_error(error: &std::io::Error) -> &AgentError {
    AgentError::of(error).unwrap_or_else(|| panic!("not a structured agent error: {error}"))
}
pub fn assert_error(error: std::io::Error, kind: std::io::ErrorKind, operation: &str, subject: &str) -> AgentError {
    assert_eq!(error.kind(), kind, "{error}");
    let detail = agent_error(&error).clone();
    assert_eq!(detail.operation, operation, "{detail}");
    assert!(detail.subject.contains(subject), "{detail:?}");
    assert!(!detail.message.is_empty());
    detail
}

pub fn shell(script: &str) -> Exec {
    Exec { program: "/bin/sh".into(), args: vec!["-c".into(), script.into()], cwd: None }
}
pub async fn output(mut output: drydock_agent::ExecOutput) -> (Vec<u8>, Vec<u8>, Option<i32>) {
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

pub async fn echo(listener: UnixListener) {
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let (mut r, mut w) = stream.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
    }
}
pub async fn exchange(stream: &mut ByteStream, bytes: &[u8]) {
    stream.write_all(bytes).await.unwrap();
    stream.flush().await.unwrap();
    let mut read = vec![0; bytes.len()];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut read)).await.unwrap().unwrap();
    assert_eq!(read, bytes);
}

pub fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
/// The agent executable this package builds.
pub fn agent_binary() -> Vec<u8> {
    std::fs::read(env!("CARGO_BIN_EXE_drydock-agent")).unwrap()
}
/// Write `binary` as an executable at `path`.
pub fn install(path: &Path, binary: &[u8]) -> PathBuf {
    std::fs::write(path, binary).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path.to_path_buf()
}
/// Start an agent from an executable this test just wrote. Another test's
/// concurrent fork can briefly hold the writer's descriptor (until its exec
/// closes it), which makes exec fail with ETXTBSY; retry until it is released.
pub fn start(command: &mut Command) -> tokio::process::Child {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match command.kill_on_drop(true).spawn() {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy && std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10))
            }
            result => return result.unwrap(),
        }
    }
}
/// Start the agent at `executable` serving `socket`.
pub fn start_agent(executable: &Path, socket: &Path) -> tokio::process::Child {
    start(Command::new(executable).arg("--socket").arg(socket))
}
/// A client for the agent serving `socket`, retrying until it answers.
pub async fn connect(socket: &Path, expected: &str) -> Client {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(transport) = dial(socket).await
                && let Ok(client) = Client::connect(transport, expected).await
            {
                return client;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap()
}
/// A client for the agent serving `socket` once it reports `expected`.
pub async fn connect_compatible(socket: &Path, expected: &str) -> Client {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let client = connect(socket, expected).await;
            if client.is_compatible() {
                break client;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap()
}
/// One transport to the agent serving `socket`.
pub async fn dial(socket: &Path) -> std::io::Result<Transport> {
    let stream = UnixStream::connect(socket).await?;
    Transport::yamux(Box::new(stream), true, Limits::default()).await
}

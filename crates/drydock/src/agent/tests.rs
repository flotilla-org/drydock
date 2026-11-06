use super::{stand_in::Gateway, *};
use crate::runtime::Runtime;
use drydock_agent::{Endpoint, OutwardForward};
use drydock_protocol::{EgressRequest, PrepareRequest, ProvisionRequest, Secret, Size};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BUILD: &[u8] = b"current agent";

/// An in-process drydock with one reference provider whose vessels declare an
/// agent (or not) and whose reach names an SSH server with the given forwarding.
async fn provider(agent: bool, reach: Reach) -> (Runtime, String) {
    provider_with(serde_json::json!({"agent": agent, "reach": reach})).await
}

/// [`provider`] with the reference module's `settings`.
async fn provider_with(settings: serde_json::Value) -> (Runtime, String) {
    let runtime = Runtime::new(drydock_host::reference::registry());
    let configuration = serde_json::from_value(serde_json::json!({
        "providers": {"a": {"module": "reference", "settings": settings}}
    }))
    .unwrap();
    runtime.configure(crate::api::ConfigUpdate::Replace(configuration)).await.unwrap();
    runtime.credential("a", Secret::new("reference-only-test-key")).await.unwrap();
    let size = Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 };
    let request = PrepareRequest {
        platform: None,
        route: None,
        image_pull: None,
        size: size.clone(),
        image_digest: "sha256:image".into(),
        tools_digest: "sha256:tools".into(),
    };
    let prepared = runtime.prepare("a", &request).await.unwrap();
    let request = ProvisionRequest { label: "label".into(), prepared, size, egress: EgressRequest::default(), ssh_public_key: None };
    let environment = runtime.provision("a", &request).await.unwrap().into_inner();
    (runtime, environment.id)
}

fn ssh_reach(reverse_forwards: bool) -> Reach {
    Reach::Ssh { endpoint: "gateway.test:22".into(), user: Secret::new("minted"), host_key: "ssh-ed25519 AAAA".into(), reverse_forwards }
}

/// Serve `target` to the guest through an outward forward, and prove a guest
/// connection reaches it and hears back.
async fn guest_reaches_host(client: &drydock_agent::Client, directory: &Path) {
    let target = directory.join("target");
    let target_listener = tokio::net::UnixListener::bind(&target).unwrap();
    let forward = OutwardForward { id: "service".into(), unix: directory.join("forward"), tcp: None };
    client.put_outward_forward(forward.clone(), Endpoint::Unix(target)).await.unwrap();
    let mut guest = tokio::net::UnixStream::connect(&forward.unix).await.unwrap();
    guest.write_all(b"guest to host").await.unwrap();
    let (mut host, _) = tokio::time::timeout(Duration::from_secs(5), target_listener.accept()).await.unwrap().unwrap();
    let mut received = [0; 13];
    host.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"guest to host");
    host.write_all(b"reply").await.unwrap();
    let mut reply = [0; 5];
    guest.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"reply");
}

// Behaviour (flotilla#3980 contracts 1 and 9): the entry point connects through
// the SSH reach's local forward, whether or not its server accepts remote
// forwards, and reports what it chose: provider, module, vessel and endpoint.
// Userinfo in the endpoint is neither dialled nor reported. The guest reaches
// the host through an outward forward on the same connection.
#[tokio::test]
async fn connects_through_the_local_forward_and_reports_it() {
    for (reverse_forwards, endpoint) in [(false, "gateway.test:22"), (true, "secret@gateway.test:22")] {
        // Under /tmp, so the vessel's socket paths stay within SUN_LEN.
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let reach =
            Reach::Ssh { endpoint: endpoint.into(), user: Secret::new("minted"), host_key: "ssh-ed25519 AAAA".into(), reverse_forwards };
        let (api, environment) = provider(true, reach).await;
        let gateway = Gateway::start(directory.path(), BUILD).unwrap();
        let reach = AgentReach::new().with_dialer(gateway.clone()).with_timeout(Duration::from_secs(10));
        let identity = directory.path().join("id_ed25519");
        let vessel = Vessel { provider: "a", environment: &environment, identity: &identity, platform: &Platform::current(), build: BUILD };
        let connected = reach.connect(&api, &vessel).await.unwrap();
        let report = AgentReport {
            provider: "a".into(),
            module: "reference".into(),
            environment: environment.clone(),
            endpoint: "gateway.test:22".into(),
        };
        assert_eq!(connected.report, report, "drydock reports what it chose");
        assert_eq!(gateway.dials(), 1);
        guest_reaches_host(&connected.client, directory.path()).await;
    }
}

// Behaviour: a relay reach is followed through the provider's relay route,
// which carries the one connection to the agent; nothing is dialled over SSH,
// and drydock reports the relay. The guest reaches the host on it as well.
#[tokio::test]
async fn connects_through_the_providers_relay_and_reports_it() {
    // Under /tmp, so the vessel's socket paths stay within SUN_LEN.
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let agent_socket = directory.path().join("relayed.sock");
    let listener = tokio::net::UnixListener::bind(&agent_socket).unwrap();
    let agent = tokio::spawn(drydock_agent::Agent::new(listener, format!("{:x}", Sha256::digest(BUILD)), "/unused".into()).run());
    let (api, environment) = provider_with(serde_json::json!({"agent": true, "relay_socket": agent_socket})).await;
    let gateway = Gateway::start(directory.path(), BUILD).unwrap();
    let identity = directory.path().join("id_ed25519");
    let vessel = Vessel { provider: "a", environment: &environment, identity: &identity, platform: &Platform::current(), build: BUILD };
    let reach = AgentReach::new().with_dialer(gateway.clone()).with_timeout(Duration::from_secs(10));
    let connected = reach.connect(&api, &vessel).await.unwrap();
    assert_eq!(connected.report.endpoint, RELAY);
    assert_eq!(connected.report.to_string(), format!("relay to reference vessel {environment} (provider a)"));
    assert_eq!(gateway.dials(), 0);
    guest_reaches_host(&connected.client, directory.path()).await;
    drop(connected);
    agent.abort();
}

// Behaviour: a dial reach is followed to the agent's TCP listener at the
// reach's URL, with its token as the agent's; nothing is dialled over SSH,
// and drydock reports the URL without its query, where a provider's edge
// credential rides. A wrong token is the agent's refusal, reported masked.
#[tokio::test]
async fn connects_through_a_dial_reach_and_reports_it() {
    let token = drydock_transport::tcp::Token::generate().unwrap();
    let listener = drydock_agent::tcp::TokenListener::bind("127.0.0.1:0".parse().unwrap(), token.clone()).await.unwrap();
    let address = listener.local_addr();
    let agent = tokio::spawn(drydock_agent::Agent::new(listener, format!("{:x}", Sha256::digest(BUILD)), "/unused".into()).run());
    let url = format!("http://{address}/v1/connect?_edge=edge-credential");
    let expires_at: drydock_protocol::Timestamp = "2030-01-01T00:00:00Z".parse().unwrap();
    for (presented, refused) in
        [(token.secret().to_owned(), false), (drydock_transport::tcp::Token::generate().unwrap().secret().into(), true)]
    {
        let dial = Reach::Dial {
            url: url.clone(),
            token: Secret::new(presented),
            headers: Default::default(),
            expires_at: Some(expires_at.clone()),
        };
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let (api, environment) = provider(true, dial).await;
        let gateway = Gateway::start(directory.path(), BUILD).unwrap();
        let identity = directory.path().join("id_ed25519");
        let vessel = Vessel { provider: "a", environment: &environment, identity: &identity, platform: &Platform::current(), build: BUILD };
        let timeout = Duration::from_secs(if refused { 2 } else { 10 });
        let result = AgentReach::new().with_dialer(gateway.clone()).with_timeout(timeout).connect(&api, &vessel).await;
        assert_eq!(gateway.dials(), 0);
        if refused {
            let error = result.err().unwrap().to_string();
            assert!(error.contains("401") && !error.contains("edge-credential"), "{error}");
            continue;
        }
        let connected = result.unwrap();
        assert_eq!(connected.report.endpoint, format!("http://{address}/v1/connect"));
        assert_eq!(
            connected.report.to_string(),
            format!("dial http://{address}/v1/connect to reference vessel {environment} (provider a)")
        );
    }
    agent.abort();
}

// An edge may echo its credential when refusing it, here percent-decoded,
// and the request's `Authorization`: drydock's error masks each query value,
// raw and decoded, and the agent's token.
#[tokio::test]
async fn a_dial_reach_masks_an_echoed_edge_credential() {
    let edge = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = edge.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = edge.accept().await {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let sent = head.lines().find_map(|l| l.strip_prefix("authorization: ")).unwrap_or_default();
            let body = format!("bad connect token: s3cr+t value; you sent {sent}");
            let answer = format!("HTTP/1.1 401 Unauthorized\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
            let _ = stream.write_all(answer.as_bytes()).await;
        }
    });
    let token = drydock_transport::tcp::Token::generate().unwrap();
    let url = format!("http://{address}/v1/connect?_edge=s3cr%2Bt+value#fragment");
    let dial = Reach::Dial {
        url,
        token: Secret::new(token.secret()),
        headers: Default::default(),
        expires_at: Some("2030-01-01T00:00:00Z".parse().unwrap()),
    };
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let (api, environment) = provider(true, dial).await;
    let gateway = Gateway::start(directory.path(), BUILD).unwrap();
    let identity = directory.path().join("id_ed25519");
    let vessel = Vessel { provider: "a", environment: &environment, identity: &identity, platform: &Platform::current(), build: BUILD };
    let error = AgentReach::new().with_dialer(gateway).with_timeout(Duration::from_secs(2)).connect(&api, &vessel).await.err().unwrap();
    let error = error.to_string();
    assert!(error.contains("401"), "{error}");
    assert!(!error.contains("s3cr") && !error.contains("fragment"), "{error}");
    assert!(error.contains("you sent") && !error.contains(token.secret()), "{error}");
}

/// Where a stand-in edge wants its own credential.
#[derive(Clone, Copy)]
enum EdgeCredential {
    /// In the query's `_edge` value, as Modal's connect tokens are.
    Query,
    /// In `x-edge-token`, as E2B's traffic token and Runtime's preview token are.
    Header,
}

const EDGE_TOKEN: &str = "edge-credential";

/// The head of one HTTP message, read a byte at a time so nothing after it is taken.
async fn head(stream: &mut tokio::net::TcpStream) -> Option<String> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
            return None;
        }
        head.push(byte[0]);
    }
    Some(String::from_utf8_lossy(&head).into_owned())
}

/// A provider's HTTP edge in front of the agent's TCP listener at `agent`,
/// as strict as the strictest one drydock meets: it wants `EDGE_TOKEN` where
/// `credential` says (401 when absent, 403 when wrong, echoing what it was
/// sent), forwards only WebSocket upgrades, and will not splice a 101 that
/// says `close` (E2B's refuses one). The edge's own header is not forwarded.
async fn edge(agent: SocketAddr, credential: EdgeCredential) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Some(request) = head(&mut client).await else { return };
                let header = |name: &str| {
                    request
                        .lines()
                        .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_owned()))
                };
                let target = request.split(' ').nth(1).unwrap_or_default();
                let presented = match credential {
                    EdgeCredential::Query => target.split_once("_edge=").map(|(_, v)| v.split('&').next().unwrap_or_default().to_owned()),
                    EdgeCredential::Header => header("x-edge-token"),
                };
                let refuse = |status: &str, body: String| {
                    format!("HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len())
                };
                let refusal = match presented {
                    None => Some(refuse("401 Unauthorized", "edge credential required".into())),
                    Some(presented) if presented != EDGE_TOKEN => {
                        Some(refuse("403 Forbidden", format!("edge credential {presented} refused")))
                    }
                    Some(_) if !header("upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket")) => {
                        Some(refuse("400 Bad Request", "only websocket upgrades".into()))
                    }
                    Some(_) => None,
                };
                if let Some(refusal) = refusal {
                    let _ = client.write_all(refusal.as_bytes()).await;
                    return;
                }
                let mut upstream = tokio::net::TcpStream::connect(agent).await.unwrap();
                let forwarded: String =
                    request.split_inclusive("\r\n").filter(|l| !l.to_lowercase().starts_with("x-edge-token:")).collect();
                upstream.write_all(forwarded.as_bytes()).await.unwrap();
                let Some(answer) = head(&mut upstream).await else { return };
                let lower = answer.to_lowercase();
                if lower.starts_with("http/1.1 101") && header_lists(&lower, "connection", "close") {
                    let _ = client.write_all(refuse("502 Bad Gateway", "upstream closes its upgrade".into()).as_bytes()).await;
                    return;
                }
                client.write_all(answer.as_bytes()).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    address
}

/// Whether the lowercase `head` has a `name` header listing `token`.
fn header_lists(head: &str, name: &str, token: &str) -> bool {
    head.lines().filter_map(|l| l.split_once(':').filter(|(n, _)| n.trim() == name)).any(|(_, v)| v.split(',').any(|t| t.trim() == token))
}

// Behaviour (#230): drydockd reaches the agent through an edge that wants its
// credential in a header, given a dial reach carrying it, and through one that
// wants it in the query, given none. Neither edge splices a 101 that says
// close. A missing header is the edge's 401 and a wrong one its 403, each
// reported with the status and the URL without its query, never showing the
// header's value, the query or the agent's token.
#[tokio::test]
async fn reaches_the_agent_through_an_edge_that_wants_its_own_credential() {
    let token = drydock_transport::tcp::Token::generate().unwrap();
    let listener = drydock_agent::tcp::TokenListener::bind("127.0.0.1:0".parse().unwrap(), token.clone()).await.unwrap();
    let agent_address = listener.local_addr();
    let agent = tokio::spawn(drydock_agent::Agent::new(listener, format!("{:x}", Sha256::digest(BUILD)), "/unused".into()).run());
    let expires_at: drydock_protocol::Timestamp = "2030-01-01T00:00:00Z".parse().unwrap();
    let header_edge = edge(agent_address, EdgeCredential::Header).await;
    let query_edge = edge(agent_address, EdgeCredential::Query).await;
    let edge_header = |value: &str| [("x-edge-token".to_owned(), Secret::new(value))].into();
    let cases = [
        (query_edge, format!("?_edge={EDGE_TOKEN}"), Default::default(), None),
        (header_edge, "?unrelated=q-value".into(), edge_header(EDGE_TOKEN), None),
        (header_edge, "?unrelated=q-value".into(), Default::default(), Some("401")),
        (header_edge, "?unrelated=q-value".into(), edge_header("stolen-value"), Some("403")),
        // Values too short to be credentials leave the status readable.
        (header_edge, "?flag=&v=1&w=40".into(), Default::default(), Some("401")),
    ];
    for (edge, query, headers, refused) in cases {
        let base = format!("http://{edge}/v1/connect");
        let dial = Reach::Dial {
            url: format!("{base}{query}"),
            token: Secret::new(token.secret()),
            headers,
            expires_at: Some(expires_at.clone()),
        };
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let (api, environment) = provider(true, dial).await;
        let gateway = Gateway::start(directory.path(), BUILD).unwrap();
        let identity = directory.path().join("id_ed25519");
        let vessel = Vessel { provider: "a", environment: &environment, identity: &identity, platform: &Platform::current(), build: BUILD };
        let timeout = Duration::from_secs(if refused.is_some() { 2 } else { 10 });
        let result = AgentReach::new().with_dialer(gateway.clone()).with_timeout(timeout).connect(&api, &vessel).await;
        assert_eq!(gateway.dials(), 0);
        match refused {
            Some(status) => {
                let error = result.err().unwrap().to_string();
                assert!(error.contains(&format!("the edge at {base} refused with HTTP {status}")), "{error}");
                for secret in ["stolen-value", EDGE_TOKEN, "q-value", token.secret()] {
                    assert!(!error.contains(secret), "{error}");
                }
            }
            None => {
                let connected = result.unwrap();
                assert_eq!(connected.report.endpoint, base);
                assert_eq!(connected.client.hello().fingerprint, format!("{:x}", Sha256::digest(BUILD)));
            }
        }
    }
    agent.abort();
}

// A dial reach no fresh reach could make followable is refused at once, without
// showing what it carries: userinfo in its URL, a header that would replace the
// handshake's own, and a header name that is not one.
#[tokio::test]
async fn an_unfollowable_dial_reach_is_refused_at_once() {
    let token = drydock_transport::tcp::Token::generate().unwrap();
    // The handshake's own headers are refused once the edge is reached.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let edge = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let header = |name: &str| [(name.to_owned(), Secret::new("header-secret"))].into();
    let cases = [
        (format!("http://user:hunter2@{edge}/v1/connect"), Default::default(), "must not carry userinfo"),
        (format!("http://{edge}/v1/connect"), header("Authorization"), "must not replace the handshake's own"),
        (format!("http://{edge}/v1/connect"), header("not a name"), "is not a header name"),
        (
            format!("http://{edge}/v1/connect"),
            [("X-Edge".to_owned(), Secret::new("header-secret")), ("x-edge".to_owned(), Secret::new("header-secret"))].into(),
            "is given twice",
        ),
        ("http://192.0.2.1/v1/connect?_edge=hunter2".into(), Default::default(), "cleartext only to a loopback"),
    ];
    for (url, headers, refusal) in cases {
        let dial =
            Reach::Dial { url, token: Secret::new(token.secret()), headers, expires_at: Some("2030-01-01T00:00:00Z".parse().unwrap()) };
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let (api, environment) = provider(true, dial).await;
        let gateway = Gateway::start(directory.path(), BUILD).unwrap();
        let identity = directory.path().join("id_ed25519");
        let vessel = Vessel { provider: "a", environment: &environment, identity: &identity, platform: &Platform::current(), build: BUILD };
        let started = tokio::time::Instant::now();
        let error = AgentReach::new().with_dialer(gateway).connect(&api, &vessel).await.err().unwrap();
        assert!(matches!(&error, Error::Protocol(ProtocolError::Refused { reason }) if reason.contains(refusal)), "{error}");
        let error = error.to_string();
        assert!(!error.contains("hunter2") && !error.contains("header-secret"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(30), "refused without waiting for the readiness deadline");
    }
}

// A gateway started for a platform stands in for a guest of that platform on
// any test host: a vessel prepared for it connects, and the agent reports it.
#[tokio::test]
async fn a_gateway_stands_in_for_the_platform_it_was_started_as() {
    let current = Platform::current();
    let prepared = Platform::new("linux", if current == Platform::new("linux", "amd64") { "arm64" } else { "amd64" });
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let (api, environment) = provider(true, ssh_reach(true)).await;
    let gateway = Gateway::start_as(directory.path(), BUILD, prepared.clone()).unwrap();
    let identity = directory.path().join("id_ed25519");
    let vessel = Vessel { provider: "a", environment: &environment, identity: &identity, platform: &prepared, build: BUILD };
    let connected = AgentReach::new().with_dialer(gateway).with_timeout(Duration::from_secs(10));
    let connected = connected.connect(&api, &vessel).await.unwrap();
    assert_eq!(connected.client.hello().platform, Some(prepared));
}

// What the client cannot follow is refused at once, without dialling: a
// provider whose declaration has no agent, and a dial reach whose token
// cannot be an agent's.
#[tokio::test]
async fn an_agent_the_client_cannot_reach_is_refused_without_dialling() {
    let dial = Reach::Dial {
        url: "https://dial.test".into(),
        token: Secret::new("minted"),
        headers: Default::default(),
        expires_at: Some("2030-01-01T00:00:00Z".parse().unwrap()),
    };
    for (agent, reach, refusal) in [(false, ssh_reach(true), "declares no vessel agent"), (true, dial, "dial reach token")] {
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let (api, environment) = provider(agent, reach).await;
        let gateway = Gateway::start(directory.path(), BUILD).unwrap();
        let identity = directory.path().join("id_ed25519");
        let vessel = Vessel { provider: "a", environment: &environment, identity: &identity, platform: &Platform::current(), build: BUILD };
        let started = tokio::time::Instant::now();
        let error = AgentReach::new().with_dialer(gateway.clone()).connect(&api, &vessel).await.err().unwrap();
        assert!(matches!(&error, Error::Protocol(ProtocolError::Refused { reason }) if reason.contains(refusal)), "{error}");
        assert_eq!(gateway.dials(), 0);
        assert!(started.elapsed() < Duration::from_secs(30), "refused without waiting for the readiness deadline");
    }
}

/// A connection to a real agent served in memory. The agent task keeps a
/// dialer, so its listener stays open and the agent outlives this dial.
async fn served(fingerprint: String) -> io::Result<drydock_transport::ByteStream> {
    let (dialer, listener) = drydock_transport::memory();
    let agent = drydock_agent::Agent::new(listener, fingerprint, "/unused".into());
    let held = dialer.clone();
    tokio::spawn(async move {
        let _held = held;
        agent.run().await
    });
    dialer.connect().await
}

// A connection alone is not readiness. Fail initial opens, then serve the
// real agent API and require its compatible hello.
#[tokio::test]
async fn retries_startup_until_current_hello() {
    let mut attempts = 0;
    wait_for_agent(
        || {
            attempts += 1;
            let attempt = attempts;
            async move {
                if attempt < 3 {
                    return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
                }
                served(format!("{:x}", Sha256::digest(BUILD))).await
            }
        },
        &Platform::current(),
        BUILD,
        Duration::from_secs(5),
        str::to_owned,
    )
    .await
    .unwrap();
    assert_eq!(attempts, 3);
}

// An agent reporting another platform than the prepared one is final:
// refuse at once, before the readiness deadline, naming both platforms.
#[tokio::test]
async fn platform_mismatch_is_refused_without_waiting() {
    let current = Platform::current();
    let prepared = Platform::new("linux", if current == Platform::new("linux", "amd64") { "arm64" } else { "amd64" });
    let mut opens = 0;
    let started = tokio::time::Instant::now();
    let error = wait_for_agent(
        || {
            opens += 1;
            served("older".into())
        },
        &prepared,
        b"prepared platform build",
        Duration::from_secs(30),
        str::to_owned,
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert!(error.to_string().contains(&format!("prepared for {prepared} but its agent reports {current}")), "{error}");
    assert_eq!(opens, 1);
    assert!(started.elapsed() < Duration::from_secs(30));
}

// A reachable connection whose peer never answers hello must time out.
#[tokio::test]
async fn connection_without_hello_is_not_ready() {
    let (host, _guest) = tokio::io::duplex(4096);
    let mut host = Some(Box::new(host) as drydock_transport::ByteStream);
    let result = wait_for_agent(
        || std::future::ready(host.take().ok_or_else(|| io::Error::from(io::ErrorKind::ConnectionRefused))),
        &Platform::current(),
        b"current",
        Duration::from_millis(25),
        str::to_owned,
    )
    .await;
    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::TimedOut);
}

// Readiness failure names the last real reason, with the minted gateway
// username masked, rather than a bare "did not complete its hello".
#[tokio::test]
async fn timeout_reports_the_last_masked_error() {
    let mut masker = DiagnosticMasker::default();
    masker.remember("minted-gateway-token");
    let result = wait_for_agent(
        || std::future::ready(Err(io::Error::other("SSH forwarding rejected: remote port forwarding failed for minted-gateway-token"))),
        &Platform::current(),
        b"current",
        Duration::from_millis(100),
        |text| masker.text(text),
    )
    .await;
    let error = result.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    let message = error.to_string();
    assert!(message.contains("last error: SSH forwarding rejected: remote port forwarding failed"), "{message}");
    assert!(!message.contains("minted-gateway-token"), "{message}");
}

// The entry point against a real OpenSSH server that, like Daytona's gateway,
// grants only local Unix-socket forwards. Hello and an outward connection
// both travel on the one connection through the local forward.
#[tokio::test]
async fn agent_reach_works_through_a_gateway_with_only_local_forwards() {
    // Under /tmp, so the vessel's socket paths stay within SUN_LEN.
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let agent_socket = directory.path().join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&agent_socket).unwrap();
    let agent = tokio::spawn(drydock_agent::Agent::new(listener, format!("{:x}", Sha256::digest(BUILD)), "/unused".into()).run());
    let (sshd, mut server) = sshd::start(directory.path(), &agent_socket).await;
    let reach = Reach::Ssh {
        endpoint: format!("{}:{}", sshd.host, sshd.port),
        user: Secret::new(sshd.user.clone()),
        host_key: sshd.host_key.clone(),
        reverse_forwards: false,
    };
    let (api, environment) = provider(true, reach).await;
    let vessel =
        Vessel { provider: "a", environment: &environment, identity: &sshd.identity_file, platform: &Platform::current(), build: BUILD };
    let connected = AgentReach::new().with_timeout(Duration::from_secs(10)).connect_at(&api, &vessel, &agent_socket).await.unwrap();
    assert_eq!(connected.report.endpoint, format!("{}:{}", sshd.host, sshd.port));
    guest_reaches_host(&connected.client, directory.path()).await;
    drop(connected);
    agent.abort();
    server.kill().await.unwrap();
}

#[path = "../../../drydock-transport/tests/support/sshd.rs"]
mod sshd;

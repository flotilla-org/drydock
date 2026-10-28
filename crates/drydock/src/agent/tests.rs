use super::{stand_in::Gateway, *};
use crate::runtime::Runtime;
use drydock_agent::{Endpoint, GuestForward};
use drydock_protocol::{EgressRequest, PrepareRequest, ProvisionRequest, Secret, Size};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BUILD: &[u8] = b"current agent";

/// An in-process drydock with one reference provider whose vessels declare an
/// agent (or not) and whose reach names an SSH server with the given forwarding.
async fn provider(agent: bool, reach: Reach) -> (Runtime, String) {
    let runtime = Runtime::new(drydock_host::reference::registry());
    let configuration = serde_json::from_value(serde_json::json!({
        "providers": {"a": {"module": "reference", "settings": {"agent": agent, "reach": reach}}}
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

/// Serve `target` to the guest through the agent's guest forward, and prove a
/// guest connection reaches it and hears back.
async fn guest_reaches_host(client: &drydock_agent::Client, directory: &Path) {
    let target = directory.join("target");
    let target_listener = tokio::net::UnixListener::bind(&target).unwrap();
    let forward = GuestForward { id: "service".into(), unix: directory.join("forward"), tcp: None };
    client.put_guest_forward(forward.clone(), Endpoint::Unix(target)).await.unwrap();
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

// Behaviour (flotilla#3980 contract 8): the link follows the provider's
// preference where its SSH server allows it, and shares the local forward
// where the server refuses remote forwards, whatever the preference.
#[test]
fn the_link_follows_the_preference_where_the_server_allows_it() {
    for (preferred, reverse_forwards, link, streams) in [
        (AgentLink::ReverseForward, true, AgentLink::ReverseForward, GuestStreams::ReverseForward(HOST_SOCKET.into())),
        (AgentLink::ReverseForward, false, AgentLink::LocalForward, GuestStreams::OverLocalForward),
        (AgentLink::LocalForward, true, AgentLink::LocalForward, GuestStreams::OverLocalForward),
        (AgentLink::LocalForward, false, AgentLink::LocalForward, GuestStreams::OverLocalForward),
    ] {
        let chosen = preferred.under(reverse_forwards);
        assert_eq!(chosen, link, "{preferred} with reverse forwards {reverse_forwards}");
        let config = ssh_config("secret@gw.example:22", "u", "ssh-ed25519 AAAA".into(), "/k".into(), chosen).unwrap();
        assert_eq!(config.guest_streams, streams);
        assert_eq!((config.host.as_str(), config.port, config.user.as_str()), ("gw.example", 22, "u"), "userinfo is never dialled");
    }
}

// Behaviour (flotilla#3980 contracts 1, 8 and 9): the entry point connects through
// whichever link the provider's reach and the preference allow, and reports
// what it chose: provider, module, vessel, endpoint and link.
// Against a gateway that refuses remote forwards it never asks for one; against
// one that accepts them it uses them unless the provider prefers the local
// forward. Either way the guest reaches the host through a guest forward.
#[tokio::test]
async fn connects_through_the_link_the_reach_and_preference_allow() {
    // The last row's endpoint carries userinfo, which is neither dialled nor reported.
    for (reverse_forwards, preferred, link, endpoint) in [
        (false, AgentLink::ReverseForward, AgentLink::LocalForward, "gateway.test:22"),
        (true, AgentLink::ReverseForward, AgentLink::ReverseForward, "gateway.test:22"),
        (true, AgentLink::LocalForward, AgentLink::LocalForward, "secret@gateway.test:22"),
    ] {
        // Under /tmp, so the vessel's socket paths stay within SUN_LEN.
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let reach =
            Reach::Ssh { endpoint: endpoint.into(), user: Secret::new("minted"), host_key: "ssh-ed25519 AAAA".into(), reverse_forwards };
        let (api, environment) = provider(true, reach).await;
        let gateway = Gateway::start(directory.path(), reverse_forwards, BUILD).unwrap();
        let reach = AgentReach::new(preferred).with_dialer(gateway.clone()).with_timeout(Duration::from_secs(10));
        let identity = directory.path().join("id_ed25519");
        let vessel = Vessel { provider: "a", environment: &environment, identity: &identity, platform: &Platform::current(), build: BUILD };
        let connected = reach.connect(&api, &vessel).await.unwrap();
        let report = AgentReport {
            provider: "a".into(),
            module: "reference".into(),
            environment: environment.clone(),
            endpoint: "gateway.test:22".into(),
            link,
        };
        assert_eq!(connected.report, report, "drydock reports what it chose");
        assert_eq!(gateway.links(), vec![link], "the gateway is never asked for a link it refuses");
        guest_reaches_host(&connected.client, directory.path()).await;
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
    let gateway = Gateway::start_as(directory.path(), true, BUILD, prepared.clone()).unwrap();
    let identity = directory.path().join("id_ed25519");
    let vessel = Vessel { provider: "a", environment: &environment, identity: &identity, platform: &prepared, build: BUILD };
    let connected = AgentReach::new(AgentLink::default()).with_dialer(gateway).with_timeout(Duration::from_secs(10));
    let connected = connected.connect(&api, &vessel).await.unwrap();
    assert_eq!(connected.client.hello().platform, Some(prepared));
}

// What the client cannot follow is refused at once, without dialling: a
// provider whose declaration has no agent, and a reach that is not SSH.
#[tokio::test]
async fn an_agent_the_client_cannot_reach_is_refused_without_dialling() {
    let dial =
        Reach::Dial { url: "wss://dial.test".into(), token: Secret::new("minted"), expires_at: "2030-01-01T00:00:00Z".parse().unwrap() };
    for (agent, reach, refusal) in [(false, ssh_reach(true), "declares no vessel agent"), (true, dial, "agent hello requires an SSH reach")]
    {
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let (api, environment) = provider(agent, reach).await;
        let gateway = Gateway::start(directory.path(), true, BUILD).unwrap();
        let identity = directory.path().join("id_ed25519");
        let vessel = Vessel { provider: "a", environment: &environment, identity: &identity, platform: &Platform::current(), build: BUILD };
        let started = tokio::time::Instant::now();
        let error = AgentReach::new(AgentLink::default()).with_dialer(gateway.clone()).connect(&api, &vessel).await.err().unwrap();
        assert!(matches!(&error, Error::Protocol(ProtocolError::Refused { reason }) if reason.contains(refusal)), "{error}");
        assert!(gateway.links().is_empty());
        assert!(started.elapsed() < Duration::from_secs(30), "refused without waiting for the readiness deadline");
    }
}

// A transport connection alone is not readiness. Fail initial opens, then
// serve the real agent API over yamux and require its compatible hello.
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
                let (host, guest) = tokio::io::duplex(4096);
                let (host, guest) = tokio::join!(
                    Transport::yamux(Box::new(host), true, Default::default()),
                    Transport::yamux(Box::new(guest), false, Default::default())
                );
                tokio::spawn(drydock_agent::Agent::new(guest?, format!("{:x}", Sha256::digest(BUILD)), "/unused".into()).run());
                host
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
            async move {
                let (host, guest) = tokio::io::duplex(4096);
                let (host, guest) = tokio::join!(
                    Transport::yamux(Box::new(host), true, Default::default()),
                    Transport::yamux(Box::new(guest), false, Default::default())
                );
                tokio::spawn(drydock_agent::Agent::new(guest?, "older".into(), "/unused".into()).run());
                host
            }
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

// A reachable transport whose peer never sends hello must time out.
#[tokio::test]
async fn transport_without_hello_is_not_ready() {
    let (host, guest) = tokio::io::duplex(4096);
    let (host, _guest) = tokio::join!(
        Transport::yamux(Box::new(host), true, Default::default()),
        Transport::yamux(Box::new(guest), false, Default::default())
    );
    let mut host = Some(host.unwrap());
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
// refuses remote Unix-socket forwards. The agent listens with its fixed native
// transport and its guest-to-host socket never appears; hello and a
// guest-to-host forward stream must both work over the host's link.
#[tokio::test]
async fn agent_reach_works_through_a_gateway_without_reverse_forwards() {
    // Under /tmp, so the vessel's socket paths stay within SUN_LEN.
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let agent_socket = directory.path().join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&agent_socket).unwrap();
    let connections = drydock_transport::native::UnixConnections::new(listener, directory.path().join("host.sock"));
    let guest = Transport::native(Arc::new(connections), Default::default()).unwrap();
    let agent = tokio::spawn(drydock_agent::Agent::new(guest, format!("{:x}", Sha256::digest(BUILD)), "/unused".into()).run());
    let (sshd, mut server) = sshd::start(directory.path(), &agent_socket, GuestStreams::OverLocalForward, sshd::Forwarding::Gateway).await;
    let reach = Reach::Ssh {
        endpoint: format!("{}:{}", sshd.host, sshd.port),
        user: Secret::new(sshd.user.clone()),
        host_key: sshd.host_key.clone(),
        reverse_forwards: false,
    };
    let (api, environment) = provider(true, reach).await;
    let vessel =
        Vessel { provider: "a", environment: &environment, identity: &sshd.identity_file, platform: &Platform::current(), build: BUILD };
    let connected =
        AgentReach::new(AgentLink::default()).with_timeout(Duration::from_secs(10)).connect_at(&api, &vessel, &agent_socket).await.unwrap();
    assert_eq!(connected.report.link, AgentLink::LocalForward);
    guest_reaches_host(&connected.client, directory.path()).await;
    assert!(!directory.path().join("host.sock").exists());
    drop(connected);
    agent.abort();
    server.kill().await.unwrap();
}

#[path = "../../../drydock-transport/tests/support/sshd.rs"]
mod sshd;

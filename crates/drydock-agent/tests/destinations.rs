//! "Try these destinations" against local listeners: each outcome, the typed
//! output, and the validation of the request.
mod support;
use drydock_agent::{Attempt, Outcome, Target};
use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{RData, Record, rdata::A},
};
use std::net::{Ipv4Addr, SocketAddr};
use support::*;
use tokio::net::{TcpListener, UdpSocket};

fn tcp(port: u16) -> Target {
    Target::Tcp { host: "127.0.0.1".into(), port }
}
fn within(ms: u64, targets: Vec<Target>) -> Attempt {
    Attempt { targets, timeout_ms: Some(ms) }
}
/// A port nothing listens on.
fn closed_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}
/// A listener whose accept queue is full, so further connects get no answer.
fn blackhole() -> (std::net::TcpListener, Vec<std::net::TcpStream>) {
    use socket2::{Domain, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    socket.bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into()).unwrap();
    socket.listen(0).unwrap();
    let address = socket.local_addr().unwrap().as_socket().unwrap();
    let mut fillers = Vec::new();
    for _ in 0..4 {
        let probe = socket2::Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        probe.set_nonblocking(true).unwrap();
        let _ = probe.connect(&address.into());
        fillers.push(probe.into());
    }
    (socket.into(), fillers)
}
/// A resolver answering every query with `code` and, for NoError, 192.0.2.7.
async fn resolver(code: ResponseCode) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buffer).await {
            let query = Message::from_vec(&buffer[..n]).unwrap();
            let mut reply = Message::new();
            reply.set_id(query.id()).set_message_type(MessageType::Response).set_response_code(code);
            reply.add_queries(query.queries().iter().cloned());
            if code == ResponseCode::NoError {
                reply.add_answer(Record::from_rdata(query.queries()[0].name().clone(), 30, RData::A(A(Ipv4Addr::new(192, 0, 2, 7)))));
            }
            socket.send_to(&reply.to_vec().unwrap(), from).await.unwrap();
        }
    });
    address
}

#[tokio::test]
async fn reports_reached_refused_and_timed_out_in_request_order() {
    let h = harness(false, "test-build").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let open = listener.local_addr().unwrap();
    let shut = closed_port();
    let (queue, _fillers) = blackhole();
    let hole = queue.local_addr().unwrap().port();
    let attempts = h.client.try_destinations(&within(500, vec![tcp(open.port()), tcp(shut), tcp(hole)])).await.unwrap();
    let outcomes: Vec<_> = attempts.results.iter().map(|r| r.outcome).collect();
    assert_eq!(outcomes, [Outcome::Reached, Outcome::Refused, Outcome::TimedOut]);
    assert_eq!(attempts.results[0].address.as_deref(), Some(open.to_string().as_str()));
    assert_eq!(attempts.results[1].address.as_deref(), Some(format!("127.0.0.1:{shut}").as_str()));
    assert_eq!(attempts.results[0].target, tcp(open.port()));
    assert!(attempts.results[2].elapsed_ms >= 400, "{:?}", attempts.results[2]);
    assert_eq!(attempts.results[2].address.as_deref(), Some(format!("127.0.0.1:{hole}").as_str()));
}

#[tokio::test]
async fn says_which_user_it_ran_as() {
    let h = harness(false, "test-build").await;
    let attempts = h.client.try_destinations(&Attempt::default()).await.unwrap();
    assert_eq!(attempts.user.uid, rustix::process::geteuid().as_raw());
    assert!(attempts.results.is_empty());
}

#[tokio::test]
async fn an_unresolvable_name_is_not_resolved_for_both_kinds() {
    let h = harness(false, "test-build").await;
    let name = "no-such-host.invalid";
    let targets = vec![
        Target::Tcp { host: name.into(), port: 443 },
        Target::Dns { name: name.into(), resolver: None },
        Target::Dns { name: name.into(), resolver: Some(resolver(ResponseCode::NXDomain).await) },
    ];
    let attempts = h.client.try_destinations(&within(10_000, targets)).await.unwrap();
    // The named resolver's NXDOMAIN is exact. The vessel's own resolver may be
    // broken or slow where this runs, so it only must not claim success.
    assert_eq!(attempts.results[2].outcome, Outcome::NameNotResolved, "{:?}", attempts.results[2]);
    for result in &attempts.results {
        assert_ne!(result.outcome, Outcome::Reached, "{result:?}");
        assert!(result.address.is_none());
    }
}

#[tokio::test]
async fn a_named_resolver_answers_or_is_silent_or_closed() {
    let h = harness(false, "test-build").await;
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let closed = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let dns = |resolver| Target::Dns { name: "example.com".into(), resolver: Some(resolver) };
    let targets = vec![dns(resolver(ResponseCode::NoError).await), dns(silent.local_addr().unwrap()), dns(closed)];
    let attempts = h.client.try_destinations(&within(400, targets)).await.unwrap();
    let outcomes: Vec<_> = attempts.results.iter().map(|r| r.outcome).collect();
    assert_eq!(outcomes, [Outcome::Reached, Outcome::TimedOut, Outcome::Refused]);
    assert_eq!(attempts.results[0].address.as_deref(), Some("192.0.2.7"));
}

#[tokio::test]
async fn a_hostname_target_resolves_through_the_vessel_resolver() {
    let h = harness(false, "test-build").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Target::Tcp { host: "localhost".into(), port: listener.local_addr().unwrap().port() };
    let attempts = h.client.try_destinations(&within(2000, vec![target])).await.unwrap();
    assert_eq!(attempts.results[0].outcome, Outcome::Reached, "{:?}", attempts.results[0]);
}

#[tokio::test]
async fn refuses_a_request_it_cannot_run() {
    let h = harness(false, "test-build").await;
    for bad in [
        Attempt { targets: vec![tcp(1)], timeout_ms: Some(0) },
        Attempt { targets: vec![tcp(1)], timeout_ms: Some(drydock_agent::MAX_TIMEOUT_MS + 1) },
        Attempt { targets: vec![Target::Tcp { host: String::new(), port: 1 }], timeout_ms: None },
        Attempt { targets: vec![Target::Dns { name: String::new(), resolver: None }], timeout_ms: None },
        Attempt { targets: vec![tcp(1); 65], timeout_ms: None },
    ] {
        let error = h.client.try_destinations(&bad).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{bad:?}");
    }
}

#[test]
fn the_wire_shape_is_stable() {
    let request = Attempt {
        targets: vec![Target::Tcp { host: "example.com".into(), port: 443 }, Target::Dns { name: "example.com".into(), resolver: None }],
        timeout_ms: None,
    };
    assert_eq!(
        serde_json::to_value(&request).unwrap(),
        serde_json::json!({"targets": [{"tcp": {"host": "example.com", "port": 443}}, {"dns": {"name": "example.com"}}]})
    );
    assert_eq!(serde_json::to_value(Outcome::NameNotResolved).unwrap(), "name_not_resolved");
}

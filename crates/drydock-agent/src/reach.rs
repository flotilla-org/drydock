//! "Try these destinations": the agent attempts each target as the user it
//! runs as and reports, per target, what happened. Nothing is configured per
//! provider and no script is injected; the caller supplies the targets.
//! Callers are trusted: the route is on the agent's control socket, which only
//! drydockd reaches, and it will probe any host:port and any resolver named.
use crate::{AgentError, ErrorKind};
use axum::Json;
use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::net::{TcpStream, UdpSocket};

/// The longest a single target may take, whatever the request asks.
pub const MAX_TIMEOUT_MS: u64 = 60_000;
/// How long each target gets when the request names no timeout.
pub const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const MAX_TARGETS: usize = 64;

/// One thing to try. On the wire: `{"tcp": {"host": "example.com", "port": 443}}`
/// or `{"dns": {"name": "example.com", "resolver": "1.1.1.1:53"}}`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    /// Open a TCP connection to `host:port`, resolving `host` first when it
    /// is a name.
    Tcp { host: String, port: u16 },
    /// Look up `name`'s addresses, through the vessel's own resolver, or
    /// through `resolver` when given.
    Dns {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resolver: Option<SocketAddr>,
    },
}

/// The body of `POST /destinations/attempts`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attempt {
    pub targets: Vec<Target>,
    /// How long each target gets, in milliseconds. Absent: 5000. At most 60000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// What happened to one target.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// A TCP connection opened, or a DNS answer carried an address.
    Reached,
    /// The peer actively refused the connection (or the resolver's port was closed).
    Refused,
    /// Nothing answered within the timeout.
    TimedOut,
    /// The name has no address: the resolver said so, or no resolver could be asked.
    NameNotResolved,
    /// Any other failure, such as an unreachable network; `detail` says which.
    Failed,
}

/// The typed result for one target.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attempted {
    pub target: Target,
    pub outcome: Outcome,
    pub elapsed_ms: u64,
    /// For TCP, the address connected or last tried; for DNS, the first
    /// address the lookup returned. Absent when none was reached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The reply: which user the agent ran the attempts as, and one result per
/// target, in request order.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attempts {
    pub user: Identity,
    pub results: Vec<Attempted>,
}

/// The user the agent runs as (the effective user).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub uid: u32,
    /// Absent when the passwd database has no entry for the uid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

fn identity() -> Identity {
    let uid = rustix::process::geteuid().as_raw();
    let name = std::fs::read_to_string("/etc/passwd").ok().and_then(|passwd| {
        passwd.lines().find_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            (fields.nth(1)? == uid.to_string()).then(|| name.to_owned())
        })
    });
    Identity { uid, name }
}

/// Try every target concurrently; results keep request order.
pub async fn attempt(request: &Attempt) -> Result<Attempts, AgentError> {
    const OP: &str = "destinations.attempt";
    if request.targets.len() > MAX_TARGETS {
        return Err(AgentError::new(OP, "targets", ErrorKind::InvalidInput, format!("at most {MAX_TARGETS} targets")));
    }
    let timeout = request.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    if timeout == 0 || timeout > MAX_TIMEOUT_MS {
        return Err(AgentError::new(OP, "timeout_ms", ErrorKind::InvalidInput, format!("timeout_ms must be 1 to {MAX_TIMEOUT_MS}")));
    }
    for target in &request.targets {
        match target {
            Target::Tcp { host, .. } if host.is_empty() => {
                return Err(AgentError::new(OP, "host", ErrorKind::InvalidInput, "host must not be empty"));
            }
            Target::Dns { name, .. } if name.is_empty() => {
                return Err(AgentError::new(OP, "name", ErrorKind::InvalidInput, "name must not be empty"));
            }
            _ => {}
        }
    }
    let timeout = Duration::from_millis(timeout);
    let results = futures_util::future::join_all(request.targets.iter().map(|target| try_one(target.clone(), timeout))).await;
    let user = tokio::task::spawn_blocking(identity).await.map_err(|e| AgentError::new(OP, "user", ErrorKind::Other, e.to_string()))?;
    Ok(Attempts { user, results })
}

async fn try_one(target: Target, timeout: Duration) -> Attempted {
    let started = Instant::now();
    let work = async {
        match &target {
            Target::Tcp { host, port } => connect(host, *port, timeout).await,
            Target::Dns { name, resolver: None } => system_lookup(name).await,
            Target::Dns { name, resolver: Some(resolver) } => resolver_lookup(name, *resolver).await,
        }
    };
    let found = tokio::time::timeout(timeout, work).await.unwrap_or_else(|_| Found::of(Outcome::TimedOut, None, None));
    Attempted {
        target,
        outcome: found.outcome,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        address: found.address,
        detail: found.detail,
    }
}

struct Found {
    outcome: Outcome,
    address: Option<String>,
    detail: Option<String>,
}
impl Found {
    fn of(outcome: Outcome, address: Option<String>, detail: Option<String>) -> Self {
        Self { outcome, address, detail }
    }
}

fn classify(error: &io::Error) -> Outcome {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => Outcome::Refused,
        io::ErrorKind::TimedOut => Outcome::TimedOut,
        _ => Outcome::Failed,
    }
}

/// Why a lookup gave no addresses.
struct LookupError {
    /// The name does not exist (EAI_NONAME, EAI_NODATA), as opposed to the
    /// resolver being unreachable or broken (EAI_AGAIN and the like).
    missing: bool,
    detail: String,
}
impl LookupError {
    fn of_code(code: libc::c_int) -> Self {
        // SAFETY: gai_strerror returns a static NUL-terminated string.
        let detail = unsafe { std::ffi::CStr::from_ptr(libc::gai_strerror(code)) }.to_string_lossy().into_owned();
        Self { missing: code == libc::EAI_NONAME || code == libc::EAI_NODATA, detail }
    }
}
fn lookup_failure(error: LookupError) -> Found {
    Found::of(if error.missing { Outcome::NameNotResolved } else { Outcome::Failed }, None, Some(error.detail))
}

/// getaddrinfo itself, so the outcome rests on its error code and not on the
/// libc's wording of it.
async fn lookup(host: &str, port: u16) -> Result<Vec<SocketAddr>, LookupError> {
    let host = std::ffi::CString::new(host).map_err(|_| LookupError { missing: false, detail: "host contains NUL".into() })?;
    tokio::task::spawn_blocking(move || {
        // SAFETY: zeroed addrinfo is a valid all-defaults hints value.
        let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
        hints.ai_socktype = libc::SOCK_STREAM;
        let mut found: *mut libc::addrinfo = std::ptr::null_mut();
        // SAFETY: host is NUL-terminated; found is freed below on success.
        let code = unsafe { libc::getaddrinfo(host.as_ptr(), std::ptr::null(), &hints, &mut found) };
        if code != 0 {
            return Err(LookupError::of_code(code));
        }
        let mut addresses = Vec::new();
        let mut at = found;
        while !at.is_null() {
            // SAFETY: at walks the list getaddrinfo returned.
            let entry = unsafe { &*at };
            // SAFETY: ai_addr points at ai_addrlen bytes of the family ai_family names.
            let ip = unsafe {
                match entry.ai_family {
                    libc::AF_INET => Some(IpAddr::from(std::net::Ipv4Addr::from(u32::from_be(
                        (*(entry.ai_addr as *const libc::sockaddr_in)).sin_addr.s_addr,
                    )))),
                    libc::AF_INET6 => Some(IpAddr::from((*(entry.ai_addr as *const libc::sockaddr_in6)).sin6_addr.s6_addr)),
                    _ => None,
                }
            };
            addresses.extend(ip.map(|ip| SocketAddr::new(ip, port)));
            at = entry.ai_next;
        }
        // SAFETY: found came from a successful getaddrinfo and is freed once.
        unsafe { libc::freeaddrinfo(found) };
        Ok(addresses)
    })
    .await
    .unwrap_or_else(|e| Err(LookupError { missing: false, detail: e.to_string() }))
}

/// Each address gets an equal share of what is left of `budget`, so an
/// address that black-holes does not starve the ones after it.
async fn connect(host: &str, port: u16, budget: Duration) -> Found {
    let deadline = Instant::now() + budget;
    let addresses: Vec<SocketAddr> = match lookup(host, port).await {
        Ok(addresses) => addresses,
        Err(error) => return lookup_failure(error),
    };
    let mut last = Found::of(Outcome::NameNotResolved, None, Some("no addresses".into()));
    for (index, address) in addresses.iter().enumerate() {
        let share = deadline.saturating_duration_since(Instant::now()) / u32::try_from(addresses.len() - index).unwrap_or(u32::MAX);
        last = match tokio::time::timeout(share, TcpStream::connect(address)).await {
            Ok(Ok(_)) => return Found::of(Outcome::Reached, Some(address.to_string()), None),
            Ok(Err(error)) => Found::of(classify(&error), Some(address.to_string()), Some(error.to_string())),
            Err(_) => Found::of(Outcome::TimedOut, Some(address.to_string()), None),
        };
    }
    last
}

async fn system_lookup(name: &str) -> Found {
    match lookup(name, 0).await {
        Ok(addresses) => match addresses.first() {
            Some(address) => Found::of(Outcome::Reached, Some(address.ip().to_string()), None),
            None => Found::of(Outcome::NameNotResolved, None, Some("no addresses".into())),
        },
        Err(error) => lookup_failure(error),
    }
}

/// An A query over UDP straight to `resolver`.
async fn resolver_lookup(name: &str, resolver: SocketAddr) -> Found {
    let failed = |error: &dyn std::fmt::Display| Found::of(Outcome::Failed, None, Some(error.to_string()));
    let Ok(fqdn) = Name::from_ascii(name) else {
        return Found::of(Outcome::Failed, None, Some("not a DNS name".into()));
    };
    let mut query = Message::new();
    let id = getrandom::u32().unwrap_or(0x6472) as u16;
    query.set_id(id).set_recursion_desired(true).add_query(Query::query(fqdn, RecordType::A));
    let bytes = match query.to_vec() {
        Ok(bytes) => bytes,
        Err(error) => return failed(&error),
    };
    let bind: SocketAddr = if resolver.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { (std::net::Ipv6Addr::UNSPECIFIED, 0).into() };
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(error) => return failed(&error),
    };
    // A connected socket only hears from the resolver; an ICMP port
    // unreachable then surfaces as ConnectionRefused on the receive.
    if let Err(error) = socket.connect(resolver).await {
        return Found::of(classify(&error), None, Some(error.to_string()));
    }
    if let Err(error) = socket.send(&bytes).await {
        return Found::of(classify(&error), None, Some(error.to_string()));
    }
    let mut buffer = vec![0u8; 4096];
    loop {
        let n = match socket.recv(&mut buffer).await {
            Ok(n) => n,
            Err(error) => return Found::of(classify(&error), None, Some(error.to_string())),
        };
        let Ok(reply) = Message::from_vec(&buffer[..n]) else { continue };
        // A reachability probe: the id and response bit are enough to know the
        // resolver answered us; the question section is not compared.
        if reply.id() != id || reply.message_type() != MessageType::Response {
            continue;
        }
        let address = reply.answers().iter().find_map(|record| match record.data() {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        });
        if reply.truncated() && address.is_none() {
            return Found::of(Outcome::Failed, None, Some("truncated reply with no address".into()));
        }
        return match (reply.response_code(), address) {
            (ResponseCode::NoError, Some(address)) => Found::of(Outcome::Reached, Some(address.to_string()), None),
            (ResponseCode::NoError | ResponseCode::NXDomain, _) => {
                Found::of(Outcome::NameNotResolved, None, Some(format!("{} with no address", reply.response_code())))
            }
            (code, _) => Found::of(Outcome::Failed, None, Some(code.to_string())),
        };
    }
}

pub(crate) async fn try_destinations(Json(request): Json<Attempt>) -> Result<Json<Attempts>, AgentError> {
    attempt(&request).await.map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lookup_codes_decide_missing_versus_broken() {
        assert!(LookupError::of_code(libc::EAI_NONAME).missing);
        assert!(LookupError::of_code(libc::EAI_NODATA).missing);
        assert!(!LookupError::of_code(libc::EAI_AGAIN).missing);
        assert!(!LookupError::of_code(libc::EAI_FAIL).missing);
    }
    #[tokio::test]
    async fn an_ip_literal_resolves_without_a_resolver() {
        assert_eq!(lookup("127.0.0.1", 9).await.ok(), Some(vec!["127.0.0.1:9".parse().unwrap()]));
        assert_eq!(lookup("::1", 9).await.ok(), Some(vec!["[::1]:9".parse().unwrap()]));
    }
}

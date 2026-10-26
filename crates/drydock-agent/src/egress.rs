//! Guest capture only: destination policy belongs to the upstream and the kind.
use crate::{ByteStream, invalid};
use drydock_transport::{Opener, Purpose};
use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{RData, Record, RecordType, rdata::A},
};
use std::{
    collections::{BTreeSet, HashMap},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Mutex as AsyncMutex,
    task::JoinSet,
};

pub const CA_PATH: &str = "/opt/drydock/ca.pem";
pub const PROXY_PORT: u16 = 15002;
const CAPTURE_PORT: u16 = 15001;
const DNS_PORT: u16 = 1053;
pub(crate) const SOCKET_MARK: u32 = 0x647279;
const TTL: u32 = 30;
const LEASE_SECONDS: u64 = 60;
const FIRST: u32 = u32::from_be_bytes([198, 18, 0, 0]);
const CAPACITY: u32 = 1 << 17;
pub(crate) const RESERVED_PORTS: [u16; 3] = [DNS_PORT, CAPTURE_PORT, PROXY_PORT];
const MAX_CONNECTIONS: usize = 128;
const MAX_DNS_QUERY: usize = 4096;
const NFT: &str = "/opt/drydock/bin/nft";

/// One vessel-scoped host forward. No destination policy lives in this table.
/// Explicit clients use http://127.0.0.1:15002 as HTTPS_PROXY.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Egress {
    pub upstream: String,
}

/// Bounded fake IPv4 pool. A live lease is stable; expired slots are reusable.
/// Expiry is checked on reverse lookup too, so stale addresses never name a new
/// destination until explicitly allocated again by DNS.
#[derive(Default)]
struct FakeDns {
    names: HashMap<String, Ipv4Addr>,
    leases: HashMap<Ipv4Addr, (String, Instant)>,
    next: u32,
    expiries: BTreeSet<(Instant, Ipv4Addr)>,
}
impl FakeDns {
    fn allocate(&mut self, name: &str, now: Instant) -> io::Result<Ipv4Addr> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        // DNS permits arbitrary label octets; CONNECT authorities do not. Keep
        // common private/service names, but reject URL delimiters and escapes.
        if name.is_empty()
            || name.len() > 253
            || name.split('.').any(|label| {
                label.is_empty() || label.len() > 63 || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
        {
            return Err(invalid("DNS name is not a CONNECT hostname"));
        }
        let expires = now + Duration::from_secs(LEASE_SECONDS);
        if let Some(&address) = self.names.get(&name) {
            let lease = self.leases.get_mut(&address).unwrap();
            self.expiries.remove(&(lease.1, address));
            lease.1 = expires;
            self.expiries.insert((expires, address));
            return Ok(address);
        }
        // The index contains one entry per lease, even after renewals. Looking
        // at its first entry avoids scanning the entire pool while holding the
        // shared DNS mutex. Allocation, renewal and exhaustion inspect/update
        // the ordered index in O(log pool size), rather than walking all leases.
        let address = if let Some(&(expiry, address)) = self.expiries.first().filter(|(expiry, _)| *expiry <= now) {
            self.expiries.remove(&(expiry, address));
            let (old, _) = self.leases.remove(&address).unwrap();
            self.names.remove(&old);
            address
        } else if self.leases.len() < CAPACITY as usize {
            let address = Ipv4Addr::from(FIRST + self.next);
            self.next = (self.next + 1) % CAPACITY;
            address
        } else {
            return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "fake DNS pool exhausted"));
        };
        self.names.insert(name.clone(), address);
        self.leases.insert(address, (name, expires));
        self.expiries.insert((expires, address));
        Ok(address)
    }
    fn reverse(&self, address: Ipv4Addr, now: Instant) -> Option<&str> {
        self.leases.get(&address).filter(|(_, expiry)| *expiry > now).map(|(name, _)| name.as_str())
    }
    fn answer(&mut self, bytes: &[u8], now: Instant) -> io::Result<Vec<u8>> {
        let request = Message::from_vec(bytes).map_err(invalid)?;
        if request.message_type() != MessageType::Query || request.queries().len() != 1 {
            return Err(invalid("expected one DNS question"));
        }
        let mut reply = Message::new();
        reply
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_op_code(request.op_code())
            .set_recursion_desired(request.recursion_desired())
            .set_recursion_available(true);
        let query = &request.queries()[0];
        reply.add_query(query.clone());
        // IPv6-only clients get NODATA, never a real address or a bypass. Other
        // records (including HTTPS/SVCB hints) likewise cannot reveal real IPs.
        if query.query_type() == RecordType::A {
            match self.allocate(&query.name().to_ascii(), now) {
                Ok(address) => {
                    reply.add_answer(Record::from_rdata(query.name().clone(), TTL, RData::A(A(address))));
                }
                Err(_) => {
                    reply.set_response_code(ResponseCode::ServFail);
                }
            }
        }
        reply.to_vec().map_err(invalid)
    }
    fn authority(&self, destination: SocketAddr, now: Instant) -> io::Result<String> {
        let host = match destination.ip() {
            IpAddr::V4(ip) if u32::from(ip).wrapping_sub(FIRST) < CAPACITY => {
                self.reverse(ip, now).ok_or_else(|| invalid("unknown or expired fake address"))?.to_owned()
            }
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        Ok(format!("{host}:{}", destination.port()))
    }
}

async fn upstream(opener: &Arc<AsyncMutex<Opener>>, id: String) -> io::Result<ByteStream> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let opener = opener.lock().await.clone();
        let mut stream = opener.open(Purpose::Forward { id }).await?;
        crate::forward::opened(&mut stream).await?;
        Ok(stream)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "egress upstream opening timed out"))?
}

// Read exactly the CONNECT response head, leaving any coalesced tunnel bytes
// in the stream. Never send application bytes until the upstream accepts.
// A CONNECT upstream must send its final 2xx response directly; interim 1xx
// replies are deliberately rejected rather than treated as tunnel acceptance.
async fn connect(remote: &mut ByteStream, authority: &str) -> io::Result<()> {
    if authority.bytes().any(|b| b.is_ascii_control() || b.is_ascii_whitespace()) {
        return Err(invalid("invalid CONNECT authority"));
    }
    remote.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes()).await?;
    let head = tokio::time::timeout(Duration::from_secs(30), async {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() == 16384 {
                return Err(invalid("oversized CONNECT response"));
            }
            head.push(remote.read_u8().await?);
        }
        Ok::<_, io::Error>(head)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "CONNECT response timed out"))??;
    let line = head.split(|b| *b == b'\r').next().unwrap_or_default();
    let mut fields = line.split(|b| *b == b' ');
    let version = fields.next().unwrap_or_default();
    let status = fields.next().unwrap_or_default();
    if !matches!(version, b"HTTP/1.0" | b"HTTP/1.1") || status.len() != 3 || status[0] != b'2' || !status.iter().all(u8::is_ascii_digit) {
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "upstream refused CONNECT"));
    }
    Ok(())
}

async fn bridge(mut stream: ByteStream, mut remote: ByteStream, authority: Option<&str>) -> io::Result<()> {
    if let Some(authority) = authority {
        connect(&mut remote, authority).await?;
    }
    tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
    Ok(())
}

#[derive(Clone)]
struct CaptureState {
    opener: Arc<AsyncMutex<Opener>>,
    id: Arc<Mutex<String>>,
    map: Arc<Mutex<FakeDns>>,
    slots: Arc<tokio::sync::Semaphore>,
    rejected: Arc<std::sync::atomic::AtomicU64>,
}
impl CaptureState {
    fn try_slot(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        match self.slots.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                let count = self.rejected.fetch_add(1, std::sync::atomic::Ordering::Relaxed).wrapping_add(1);
                // Log the first refusal and powers of two: saturation remains
                // observable without producing one warning per connection.
                if count.is_power_of_two() {
                    tracing::warn!(rejected_connections = count, "egress connection budget exhausted");
                }
                None
            }
        }
    }
}

async fn serve_connection(stream: TcpStream, passthrough: bool, state: CaptureState) -> io::Result<()> {
    let authority =
        if passthrough { None } else { Some(state.map.lock().unwrap().authority(original_destination(&stream)?, Instant::now())?) };
    let id = state.id.lock().unwrap().clone();
    let remote = upstream(&state.opener, id).await?;
    bridge(Box::new(stream), remote, authority.as_deref()).await
}

async fn serve_capture(listener: TcpListener, passthrough: bool, state: CaptureState) {
    let mut streams = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            Some(_) = streams.join_next(), if !streams.is_empty() => continue,
            accepted = listener.accept() => accepted,
        };
        let stream = match accepted {
            Ok((stream, _)) => stream,
            Err(error) => {
                tracing::warn!(%error, "egress accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // Accept and immediately close overflow rather than retaining more
        // sockets or blocking the listener on a permit. All TCP listeners share
        // this budget, leaving descriptor headroom for the control path.
        let Some(permit) = state.try_slot() else {
            continue;
        };
        let state = state.clone();
        streams.spawn(async move {
            let _permit = permit;
            if let Err(error) = serve_connection(stream, passthrough, state).await {
                tracing::warn!(%error, "egress stream failed");
            }
        });
    }
}

async fn dns_exchange(stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin), map: &Mutex<FakeDns>) -> io::Result<()> {
    let length = stream.read_u16().await?;
    if usize::from(length) > MAX_DNS_QUERY {
        return Err(invalid("oversized DNS query"));
    }
    let mut bytes = vec![0; length.into()];
    stream.read_exact(&mut bytes).await?;
    let answer = map.lock().unwrap().answer(&bytes, Instant::now())?;
    stream.write_u16(answer.len() as u16).await?;
    stream.write_all(&answer).await
}

async fn dns_connection(
    mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    map: Arc<Mutex<FakeDns>>,
    idle: Duration,
) -> io::Result<()> {
    loop {
        tokio::time::timeout(idle, dns_exchange(&mut stream, &map))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS TCP query timed out"))??;
    }
}

async fn serve_dns_tcp(listener: TcpListener, state: CaptureState) {
    let mut streams = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            Some(_) = streams.join_next(), if !streams.is_empty() => continue,
            accepted = listener.accept() => accepted,
        };
        let stream = match accepted {
            Ok((stream, _)) => stream,
            Err(error) => {
                tracing::warn!(%error, "fake DNS TCP accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Some(permit) = state.try_slot() else {
            continue;
        };
        let map = state.map.clone();
        streams.spawn(async move {
            let _permit = permit;
            let _ = dns_connection(stream, map, Duration::from_secs(30)).await;
        });
    }
}

async fn serve_dns_udp(socket: UdpSocket, map: Arc<Mutex<FakeDns>>) {
    let mut buffer = [0; MAX_DNS_QUERY];
    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((n, peer)) => {
                let answer = map.lock().unwrap().answer(&buffer[..n], Instant::now());
                if let Ok(answer) = answer {
                    let _ = socket.send_to(&answer, peer).await;
                }
            }
            Err(error) => {
                tracing::warn!(%error, "fake DNS receive failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

pub(crate) struct Capture {
    tasks: JoinSet<()>,
    id: Arc<Mutex<String>>,
    #[cfg(test)]
    dns_address: SocketAddr,
    #[cfg(test)]
    proxy_address: SocketAddr,
    #[cfg(test)]
    capture_address: SocketAddr,
    #[cfg(test)]
    slots: Arc<tokio::sync::Semaphore>,
}
impl Capture {
    /// Bind all listeners before changing global guest state. Dropping a refused
    /// preparation releases every listener and connection task.
    pub(crate) async fn prepare(opener: Arc<AsyncMutex<Opener>>, id: String) -> io::Result<Self> {
        Self::prepare_at(opener, id, CAPTURE_PORT, PROXY_PORT, DNS_PORT).await
    }
    async fn prepare_at(
        opener: Arc<AsyncMutex<Opener>>,
        id: String,
        capture_port: u16,
        proxy_port: u16,
        dns_port: u16,
    ) -> io::Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "egress capture requires Linux"));
        }
        let tcp = dual_listener(capture_port)?;
        #[cfg(test)]
        let capture_address = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp.local_addr()?.port()));
        let explicit = TcpListener::bind((Ipv4Addr::LOCALHOST, proxy_port)).await?;
        let dns_tcp = dual_listener(dns_port)?;
        let dns_port = dns_tcp.local_addr()?.port();
        #[cfg(test)]
        let proxy_address = explicit.local_addr()?;
        let udp = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;
        udp.set_only_v6(false)?;
        udp.set_nonblocking(true)?;
        udp.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, dns_port)).into())?;
        let dns_udp = UdpSocket::from_std(udp.into())?;
        let map = Arc::new(Mutex::new(FakeDns::default()));
        let id = Arc::new(Mutex::new(id));
        let state = CaptureState {
            opener,
            id: id.clone(),
            map: map.clone(),
            slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS)),
            rejected: Arc::default(),
        };
        let mut tasks = JoinSet::new();
        tasks.spawn(serve_capture(tcp, false, state.clone()));
        tasks.spawn(serve_capture(explicit, true, state.clone()));
        tasks.spawn(serve_dns_tcp(dns_tcp, state.clone()));
        tasks.spawn(serve_dns_udp(dns_udp, map));
        Ok(Self {
            tasks,
            id,
            #[cfg(test)]
            dns_address: (Ipv4Addr::LOCALHOST, dns_port).into(),
            #[cfg(test)]
            proxy_address,
            #[cfg(test)]
            capture_address,
            #[cfg(test)]
            slots: state.slots,
        })
    }
    pub(crate) async fn stop(mut self) {
        self.tasks.shutdown().await;
    }
    pub(crate) fn set_upstream(&self, id: String) {
        *self.id.lock().unwrap() = id;
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}

fn dual_listener(port: u16) -> io::Result<TcpListener> {
    let socket = tokio::net::TcpSocket::new_v6()?;
    socket.set_reuseaddr(true)?;
    // Linux's default is dual-stack; explicitly set it for hosts overriding
    // bindv6only, so IPv4 redirected SYNs also reach this listener.
    set_option(&socket, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 0)?;
    socket.bind(SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)))?;
    socket.listen(128)
}

#[cfg(target_os = "linux")]
pub(crate) fn set_option(socket: &impl std::os::fd::AsRawFd, level: i32, option: i32, value: u32) -> io::Result<()> {
    // SAFETY: the live socket and the integer's exact size are supplied.
    let result =
        unsafe { libc::setsockopt(socket.as_raw_fd(), level, option, (&value as *const u32).cast(), std::mem::size_of_val(&value) as _) };
    if result == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn set_option(_: &impl std::os::fd::AsRawFd, _: i32, _: i32, _: u32) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "egress capture requires Linux"))
}

#[cfg(target_os = "linux")]
fn original_destination(stream: &TcpStream) -> io::Result<SocketAddr> {
    use std::os::fd::AsRawFd;
    // IPv4 connections on the dual-stack listener use SOL_IP; native IPv6 uses
    // SOL_IPV6. SO_ORIGINAL_DST is 80 for both conntrack families.
    let ipv4 = stream.peer_addr()?.ip().to_canonical().is_ipv4();
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&storage) as libc::socklen_t;
    // SAFETY: storage and length are writable and correctly sized for either family.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            if ipv4 { libc::SOL_IP } else { libc::SOL_IPV6 },
            80,
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    match storage.ss_family as i32 {
        libc::AF_INET if length as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
            let addr = unsafe { &*(&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            Ok(SocketAddr::from((Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()), u16::from_be(addr.sin_port))))
        }
        libc::AF_INET6 if length as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
            let addr = unsafe { &*(&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>() };
            Ok(SocketAddr::from((std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr), u16::from_be(addr.sin6_port))))
        }
        _ => Err(invalid("invalid original destination family")),
    }
}
#[cfg(not(target_os = "linux"))]
fn original_destination(_: &TcpStream) -> io::Result<SocketAddr> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "egress requires Linux"))
}

/// The capture table for this state: empty without egress, else redirects
/// with exemptions for agent sockets, the proxy and loopback forward listeners.
pub(crate) fn rules(egress: bool, exempt: &[SocketAddr]) -> String {
    // add is idempotent, flush + rebuild are a single nft transaction. Agent
    // sockets carry SO_MARK; a child with the same uid receives no exemption.
    let mut rules = String::from("add table inet drydock_egress\nflush table inet drydock_egress\n");
    if !egress {
        return rules;
    }
    rules.push_str(concat!("add chain inet drydock_egress output { ", "type nat hook output priority -100; policy accept; }\n",));
    rules.push_str(&format!("add rule inet drydock_egress output meta mark {SOCKET_MARK} return\n"));
    rules.push_str(&format!("add rule inet drydock_egress output ip daddr 127.0.0.1 tcp dport {PROXY_PORT} return\n"));
    for addr in exempt {
        let family = if addr.is_ipv4() { "ip" } else { "ip6" };
        rules.push_str(&format!("add rule inet drydock_egress output {family} daddr {} tcp dport {} return\n", addr.ip(), addr.port()));
    }
    rules.push_str(&format!(
        concat!(
            "add rule inet drydock_egress output udp dport 53 redirect to :{dns_port}\n",
            "add rule inet drydock_egress output tcp dport 53 redirect to :{dns_port}\n",
            "add rule inet drydock_egress output meta l4proto tcp redirect to :{capture_port}\n",
        ),
        dns_port = DNS_PORT,
        capture_port = CAPTURE_PORT,
    ));
    rules
}

pub(crate) struct System {
    pub(crate) nft: std::path::PathBuf,
    pub(crate) ca: std::path::PathBuf,
}
impl Default for System {
    fn default() -> Self {
        Self { nft: NFT.into(), ca: CA_PATH.into() }
    }
}
impl System {
    pub(crate) async fn install(&self, egress: bool, exempt: &[SocketAddr]) -> io::Result<()> {
        self.transaction(&rules(egress, exempt)).await
    }
    /// Remove the capture table at startup and before re-exec, so redirects
    /// never outlive the configuration that installed them. Without the nft
    /// executable the agent cannot have installed any.
    pub(crate) async fn clear(&self) -> io::Result<()> {
        if !self.nft.exists() {
            return Ok(());
        }
        self.transaction("add table inet drydock_egress\ndelete table inet drydock_egress\n").await
    }
    async fn transaction(&self, rules: &str) -> io::Result<()> {
        use std::process::Stdio;
        let mut command = tokio::process::Command::new(&self.nft);
        command.args(["-f", "-"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped());
        let mut child = command.kill_on_drop(true).spawn()?;
        child.stdin.take().unwrap().write_all(rules.as_bytes()).await?;
        let result = child.wait_with_output().await?;
        if result.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!("install guest egress redirect: {}", String::from_utf8_lossy(&result.stderr))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::generators as gs;
    use hickory_proto::{op::Query, rr::Name};

    // ADR 0069: live fake leases are unique, repeat lookups preserve identity,
    // expiry invalidates reverse lookup, and the bounded pool reuses old slots.
    #[hegel::test]
    fn fake_leases_allocate_expire_and_reuse(tc: hegel::TestCase) {
        // Span both /16 halves and both pool boundaries. The clock samples the
        // instant before expiry, exact expiry, and instants after expiry.
        let slot = tc.draw(gs::integers::<u32>().min_value(0).max_value(CAPACITY - 1));
        let advance = tc.draw(gs::integers::<u64>().min_value(LEASE_SECONDS - 1).max_value(LEASE_SECONDS + 1));
        let now = Instant::now();
        let mut dns = FakeDns { next: slot, ..FakeDns::default() };
        let a = dns.allocate("One.Example.", now).unwrap();
        assert_eq!(a, Ipv4Addr::from(FIRST + slot));
        assert_eq!(dns.allocate("one.example", now).unwrap(), a);
        assert_eq!(dns.reverse(a, now), Some("one.example"));
        let b = dns.allocate("two.example", now).unwrap();
        assert_ne!(a, b);
        let later = now + Duration::from_secs(advance);
        assert_eq!(dns.reverse(a, later).is_some(), advance < LEASE_SECONDS);
        assert_eq!(dns.reverse(b, now), Some("two.example"));
        let c = dns.allocate("three.example", later).unwrap();
        assert_eq!([a, b].contains(&c), advance >= LEASE_SECONDS);
        assert_eq!(dns.reverse(c, later), Some("three.example"));
        assert_eq!(dns.expiries.len(), dns.leases.len(), "renewals must not grow the expiry index");
    }

    // Renewed leases cannot be recycled using stale expiry-index entries, and
    // repeated lookups must not grow the bounded index independently of leases.
    #[hegel::test]
    fn renewed_leases_remain_reserved(tc: hegel::TestCase) {
        let mut dns = FakeDns::default();
        let mut now = Instant::now();
        let address = dns.allocate("retained.example", now).unwrap();
        // Draw time advances below the lease duration, crossing old expiries
        // over the generated sequence while continually renewing one name.
        let steps = tc.draw(gs::integers::<usize>().min_value(1).max_value(8));
        for index in 0..steps {
            now += Duration::from_secs(tc.draw(gs::integers::<u64>().min_value(0).max_value(LEASE_SECONDS - 1)));
            assert_eq!(dns.allocate("retained.example", now).unwrap(), address);
            let other = dns.allocate(&format!("other{index}.example"), now).unwrap();
            assert_ne!(other, address);
            assert_eq!(dns.reverse(address, now), Some("retained.example"));
            assert_eq!(dns.expiries.len(), dns.leases.len());
        }
    }

    // ADR 0069: DNS wire replies preserve the question/ID and give fake A
    // answers with a short TTL; all other types return no real addresses.
    #[hegel::test]
    fn dns_wire_answers(tc: hegel::TestCase) {
        let id = tc.draw(gs::integers::<u16>());
        let kind = [RecordType::A, RecordType::AAAA, RecordType::HTTPS, RecordType::MX]
            [tc.draw(gs::integers::<usize>().min_value(0).max_value(3))];
        let mut query = Message::new();
        query.set_id(id).add_query(Query::query(Name::from_ascii("example.org.").unwrap(), kind));
        let mut dns = FakeDns::default();
        let reply = Message::from_vec(&dns.answer(&query.to_vec().unwrap(), Instant::now()).unwrap()).unwrap();
        assert_eq!(reply.id(), id);
        assert_eq!(reply.queries(), query.queries());
        assert_eq!(reply.message_type(), MessageType::Response);
        assert_eq!(reply.answers().len(), usize::from(kind == RecordType::A));
        if let Some(record) = reply.answers().first() {
            assert_eq!(record.ttl(), TTL);
            assert_eq!(record.data(), &RData::A(A(Ipv4Addr::new(198, 18, 0, 0))));
        }
        assert!(dns.answer(&[], Instant::now()).is_err());
    }

    // Exhaustion must fail rather than alias a live name; expired leases allow
    // progress again, including at the last address in the /15 range.
    #[test]
    fn exhausted_pool_never_reassigns_live_addresses() {
        let now = Instant::now();
        let mut dns = FakeDns::default();
        for slot in 0..CAPACITY {
            assert_eq!(dns.allocate(&format!("host{slot}.example"), now).unwrap(), Ipv4Addr::from(FIRST + slot));
        }
        assert_eq!(dns.allocate("overflow.example", now).unwrap_err().kind(), io::ErrorKind::AddrNotAvailable);
        assert_eq!(dns.reverse(Ipv4Addr::new(198, 19, 255, 255), now), Some(format!("host{}.example", CAPACITY - 1).as_str()));
        assert_eq!(dns.allocate("reused.example", now + Duration::from_secs(LEASE_SECONDS)).unwrap(), Ipv4Addr::new(198, 18, 0, 0));
        assert_eq!(dns.reverse(Ipv4Addr::new(198, 18, 0, 0), now + Duration::from_secs(LEASE_SECONDS)), Some("reused.example"));
    }

    // Only mapped fake destinations may become hostnames; numeric destinations
    // remain numeric, including IPv6's bracketed CONNECT authority syntax.
    #[test]
    fn authorities_reject_unknown_fake_addresses() {
        let now = Instant::now();
        let mut dns = FakeDns::default();
        assert!(dns.authority("198.18.0.0:443".parse().unwrap(), now).is_err());
        assert!(dns.authority("198.19.255.255:443".parse().unwrap(), now).is_err());
        let ip = dns.allocate("example.org", now).unwrap();
        assert_eq!(dns.authority((ip, 8443).into(), now).unwrap(), "example.org:8443");
        assert!(dns.authority((ip, 8443).into(), now + Duration::from_secs(LEASE_SECONDS)).is_err());
        assert_eq!(dns.authority("198.20.0.0:80".parse().unwrap(), now).unwrap(), "198.20.0.0:80");
        assert_eq!(dns.authority("[2001:db8::1]:443".parse().unwrap(), now).unwrap(), "[2001:db8::1]:443");
    }

    // Socket-boundary proxy stand-in: enforce CONNECT before permitting tunnel
    // bytes. Exercise the real vessel-scoped forward and its opening handshake.
    // Explicit HTTPS_PROXY bytes must pass through byte-for-byte, without nesting.
    #[tokio::test]
    async fn redirected_and_explicit_proxy_use_vessel_forward() {
        use crate::{Agent, Client, Endpoint};
        use drydock_transport::{Limits, Transport};
        let (a, b) = tokio::io::duplex(4096);
        let (host, guest) =
            tokio::join!(Transport::yamux(Box::new(a), true, Limits::default()), Transport::yamux(Box::new(b), false, Limits::default()));
        let (host, guest) = (host.unwrap(), guest.unwrap());
        let opener = Arc::new(AsyncMutex::new(guest.opener.clone()));
        let dir = tempfile::tempdir().unwrap();
        let agent = tokio::spawn(Agent::new(guest, "test".into(), dir.path().join("agent")).run());
        let client = Client::connect(host, "test").await.unwrap();
        let proxy = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        client.register_host_endpoint("egress".into(), Endpoint::Tcp(proxy.local_addr().unwrap())).unwrap();
        let capture = Capture::prepare_at(opener.clone(), "egress".into(), 0, 0, 0).await.unwrap();
        let mut query = Message::new();
        query.set_id(123).add_query(Query::query(Name::from_ascii("original.example.").unwrap(), RecordType::A));
        let query_bytes = query.to_vec().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.send_to(&query_bytes, capture.dns_address).await.unwrap();
        let mut buffer = [0; 4096];
        let n = udp.recv(&mut buffer).await.unwrap();
        let answer = Message::from_vec(&buffer[..n]).unwrap();
        let RData::A(A(fake)) = answer.answers()[0].data() else {
            panic!("expected fake IPv4 answer");
        };
        assert_eq!(*fake, Ipv4Addr::new(198, 18, 0, 0));
        let mut dns_tcp = TcpStream::connect(capture.dns_address).await.unwrap();
        dns_tcp.write_u16(query_bytes.len() as u16).await.unwrap();
        dns_tcp.write_all(&query_bytes).await.unwrap();
        let n = dns_tcp.read_u16().await.unwrap();
        dns_tcp.read_exact(&mut buffer[..n as usize]).await.unwrap();
        assert_eq!(Message::from_vec(&buffer[..n as usize]).unwrap().answers(), answer.answers());
        // The unprivileged suite injects only the kernel's original-destination
        // result. The ignored netns test below exercises that kernel boundary.
        let mut dns = FakeDns::default();
        let now = Instant::now();
        assert_eq!(dns.allocate("original.example", now).unwrap(), *fake);
        let authority = dns.authority((*fake, 8443).into(), now).unwrap();
        for explicit in [false, true] {
            let proxy_task = tokio::spawn({
                let proxy = proxy.clone();
                // The stand-in receives only a normal HTTP CONNECT on its TCP socket.
                async move {
                    let (mut stream, _) = proxy.accept().await.unwrap();
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        head.push(stream.read_u8().await.unwrap());
                    }
                    let expected = if explicit {
                        b"CONNECT original.example:8443 HTTP/1.1\r\nProxy-Authorization: unchanged\r\n\r\n".as_slice()
                    } else {
                        b"CONNECT original.example:8443 HTTP/1.1\r\nHost: original.example:8443\r\n\r\n".as_slice()
                    };
                    assert_eq!(head, expected);
                    // Coalesced response/tunnel bytes must survive head parsing.
                    stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nwelcome").await.unwrap();
                    let mut bytes = Vec::new();
                    stream.read_to_end(&mut bytes).await.unwrap();
                    assert_eq!(bytes, b"payload\0\xff");
                    stream.write_all(&bytes).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
            });
            let (mut tool, bridge_task): (ByteStream, Option<tokio::task::JoinHandle<()>>) = if explicit {
                (Box::new(TcpStream::connect(capture.proxy_address).await.unwrap()), None)
            } else {
                let (tool, agent_stream) = tokio::io::duplex(4096);
                let remote = upstream(&opener, "egress".into()).await.unwrap();
                let authority = authority.clone();
                (
                    Box::new(tool),
                    Some(tokio::spawn(async move {
                        bridge(Box::new(agent_stream), remote, Some(&authority)).await.unwrap();
                    })),
                )
            };
            if explicit {
                tool.write_all(b"CONNECT original.example:8443 HTTP/1.1\r\nProxy-Authorization: unchanged\r\n\r\n").await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(tool.read_u8().await.unwrap());
                }
                assert_eq!(head, b"HTTP/1.1 200 Connection established\r\n\r\n");
            }
            let mut welcome = [0; 7];
            tool.read_exact(&mut welcome).await.unwrap();
            assert_eq!(&welcome, b"welcome");
            tool.write_all(b"payload\0\xff").await.unwrap();
            tool.shutdown().await.unwrap();
            let mut bytes = Vec::new();
            tool.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"payload\0\xff");
            if let Some(task) = bridge_task {
                task.await.unwrap();
            }
            proxy_task.await.unwrap();
        }
        capture.stop().await;
        agent.abort();
    }

    // ADR 0070: a same-UID process without proxy variables is still captured.
    // Run only in the disposable network+mount namespaces made by the test tool.
    #[tokio::test]
    #[ignore = "requires tools/test-agent-egress.sh (root, nftables and isolated namespaces)"]
    async fn kernel_redirect() {
        use crate::{Agent, Client, Configuration, Egress, Endpoint, Exec, HostForward};
        use drydock_transport::{Limits, Transport};
        assert!(std::env::var_os("DRYDOCK_EGRESS_NETNS").is_some(), "use tools/test-agent-egress.sh");
        assert_ne!(std::fs::read_link("/proc/self/ns/net").unwrap(), std::fs::read_link("/proc/1/ns/net").unwrap());
        let (a, b) = tokio::io::duplex(4096);
        let (host, guest) =
            tokio::join!(Transport::yamux(Box::new(a), true, Limits::default()), Transport::yamux(Box::new(b), false, Limits::default()));
        let dir = tempfile::tempdir().unwrap();
        let agent = tokio::spawn(Agent::new(guest.unwrap(), "test".into(), dir.path().join("agent")).run());
        let client = Client::connect(host.unwrap(), "test").await.unwrap();
        let proxy = tokio::net::UnixListener::bind(dir.path().join("proxy")).unwrap();
        client.register_host_endpoint("egress".into(), Endpoint::Unix(dir.path().join("proxy"))).unwrap();
        client
            .configure(Configuration {
                egress: Some(Egress { upstream: "egress".into() }),
                ca: "combined-test-trust-bundle".into(),
                ..Configuration::default()
            })
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(CA_PATH).unwrap(), "combined-test-trust-bundle");
        let mut query = Message::new();
        query.add_query(Query::query(Name::from_ascii("kernel.example.").unwrap(), RecordType::A));
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Even a resolver named by the image, rather than localhost, is captured.
        udp.send_to(&query.to_vec().unwrap(), "192.0.2.53:53").await.unwrap();
        let mut bytes = [0; 4096];
        let n = udp.recv(&mut bytes).await.unwrap();
        let reply = Message::from_vec(&bytes[..n]).unwrap();
        let RData::A(A(fake)) = reply.answers()[0].data() else {
            panic!("expected A");
        };
        let fake = *fake;
        let stand_in = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            assert_eq!(head, b"CONNECT kernel.example:8443 HTTP/1.1\r\nHost: kernel.example:8443\r\n\r\n");
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            let mut payload = [0; 5];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"hello");
            stream.write_all(b"world").await.unwrap();
        });
        // /usr/bin/python3 is a genuine launched child, with no proxy/CA env.
        let mut output = client
            .exec(Exec {
                program: "/usr/bin/python3".into(),
                args: vec![
                    "-c".into(),
                    format!(
                        "import os,socket; os.environ.clear(); s=socket.create_connection(('{fake}',8443),5); s.sendall(b'hello'); assert s.recv(5)==b'world'"
                    ),
                ],
                cwd: None,
            })
            .await
            .unwrap();
        let mut code = None;
        while let Some(event) = output.next().await.unwrap() {
            if let crate::ExecEvent::Exit { code: exit } = event {
                code = exit;
            }
        }
        assert_eq!(code, Some(0));
        stand_in.await.unwrap();
        // Agent-originated TCP sockets must escape capture, even though the
        // child's sockets (same process UID) did not.
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        client.put_host_forward(HostForward { id: "agent-tcp".into(), endpoint: Endpoint::Tcp(echo.local_addr().unwrap()) }).await.unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut b = [0; 1];
            stream.read_exact(&mut b).await.unwrap();
            stream.write_all(&b).await.unwrap();
        });
        let mut stream = client.forward("agent-tcp").await.unwrap();
        stream.write_all(b"x").await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), b'x');
        echo_task.await.unwrap();
        client.configure(Configuration::default()).await.unwrap();
        agent.abort();
    }

    // Advertise a short DNS TTL but retain mappings through a setup grace
    // period, so using an answer near TTL expiry still recovers its hostname.
    #[test]
    fn dns_answer_to_connect_has_grace_then_requires_renewal() {
        let now = Instant::now();
        let mut dns = FakeDns::default();
        let mut query = Message::new();
        query.add_query(Query::query(Name::from_ascii("cached.example.").unwrap(), RecordType::A));
        let answer = Message::from_vec(&dns.answer(&query.to_vec().unwrap(), now).unwrap()).unwrap();
        assert_eq!(answer.answers()[0].ttl(), TTL);
        let RData::A(A(address)) = answer.answers()[0].data() else {
            panic!("expected A");
        };
        let destination = (*address, 443).into();
        for elapsed in [u64::from(TTL) - 1, TTL.into(), u64::from(TTL) + 1, LEASE_SECONDS - 1] {
            assert_eq!(dns.authority(destination, now + Duration::from_secs(elapsed)).unwrap(), "cached.example:443");
        }
        assert!(dns.authority(destination, now + Duration::from_secs(LEASE_SECONDS)).is_err());
        dns.answer(&query.to_vec().unwrap(), now + Duration::from_secs(LEASE_SECONDS)).unwrap();
        assert_eq!(dns.authority(destination, now + Duration::from_secs(LEASE_SECONDS)).unwrap(), "cached.example:443");
    }

    // URL delimiters and DNS label escapes may not alter a CONNECT authority.
    #[hegel::test]
    fn dns_names_must_be_connect_hostnames(tc: hegel::TestCase) {
        let mut dns = FakeDns::default();
        // Span controls, ASCII URL delimiters, allowed label punctuation, and
        // non-ASCII bytes; also straddle the label and whole-name size limits.
        let byte = tc.draw(gs::integers::<u8>());
        let name = format!("a{}b.example", char::from(byte));
        assert_eq!(dns.allocate(&name, Instant::now()).is_ok(), byte.is_ascii_alphanumeric() || b"-_.".contains(&byte));
        let label_len = tc.draw(gs::integers::<usize>().min_value(0).max_value(65));
        assert_eq!(dns.allocate(&format!("{}.example", "a".repeat(label_len)), Instant::now()).is_ok(), (1..=63).contains(&label_len));
        let final_len = tc.draw(gs::integers::<usize>().min_value(60).max_value(63));
        let name = format!("{}{}", format!("{}.", "a".repeat(63)).repeat(3), "b".repeat(final_len));
        assert_eq!(dns.allocate(&name, Instant::now()).is_ok(), name.len() <= 253);
        for name in ["a@b.example", "a/b.example", "a,b.example", "a:b.example", "a\\032b.example", "a..example", ""] {
            assert!(dns.allocate(name, Instant::now()).is_err(), "accepted {name}");
        }
        for name in ["localhost", "_service.example", "a-b.example", "xn--bcher-kva.example"] {
            let address = dns.allocate(name, Instant::now()).unwrap();
            assert_eq!(dns.reverse(address, Instant::now()), Some(name));
        }
    }

    // DNS TCP timeout applies to each exchange, allowing repeated queries over
    // a connection whose total lifetime exceeds the 30-second idle deadline.
    #[tokio::test(start_paused = true)]
    async fn dns_tcp_timeout_resets_after_each_query() {
        let (server, mut client) = tokio::io::duplex(4096);
        let task = tokio::spawn(dns_connection(server, Arc::new(Mutex::new(FakeDns::default())), Duration::from_secs(30)));
        let mut query = Message::new();
        query.add_query(Query::query(Name::from_ascii("idle.example.").unwrap(), RecordType::A));
        let bytes = query.to_vec().unwrap();
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(20)).await;
            client.write_u16(bytes.len() as u16).await.unwrap();
            client.write_all(&bytes).await.unwrap();
            let length = client.read_u16().await.unwrap();
            let mut answer = vec![0; length.into()];
            client.read_exact(&mut answer).await.unwrap();
            assert_eq!(Message::from_vec(&answer).unwrap().answers().len(), 1);
        }
        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(task.await.unwrap().unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    // All three TCP listeners share the same bounded connection budget; holding
    // DNS sockets cannot grow an unbounded set of proxy or capture streams.
    #[tokio::test]
    async fn capture_connection_budget_is_shared_and_released() {
        use drydock_transport::{Limits, Transport};
        let (a, b) = tokio::io::duplex(4096);
        let (host, guest) =
            tokio::join!(Transport::yamux(Box::new(a), true, Limits::default()), Transport::yamux(Box::new(b), false, Limits::default()));
        let (_host, guest) = (host.unwrap(), guest.unwrap());
        let capture = Capture::prepare_at(Arc::new(AsyncMutex::new(guest.opener.clone())), "proxy".into(), 0, 0, 0).await.unwrap();
        let mut held = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            held.push(TcpStream::connect(capture.dns_address).await.unwrap());
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while capture.slots.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        for address in [capture.dns_address, capture.proxy_address, capture.capture_address] {
            let mut stream = TcpStream::connect(address).await.unwrap();
            let mut byte = [0];
            assert_eq!(tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte)).await.unwrap().unwrap(), 0);
        }
        drop(held);
        tokio::time::timeout(Duration::from_secs(5), async {
            while capture.slots.available_permits() != MAX_CONNECTIONS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // Released slots admit a new DNS exchange through the same listener.
        let mut stream = TcpStream::connect(capture.dns_address).await.unwrap();
        let mut query = Message::new();
        query.add_query(Query::query(Name::from_ascii("released.example.").unwrap(), RecordType::A));
        let bytes = query.to_vec().unwrap();
        stream.write_u16(bytes.len() as u16).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        let length = stream.read_u16().await.unwrap();
        let mut answer = vec![0; length.into()];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(Message::from_vec(&answer).unwrap().answers().len(), 1);
        capture.stop().await;
    }

    // A host endpoint that never acknowledges its forward opening must release
    // the guest's pending stream after the opening deadline, not pin it forever.
    #[tokio::test(start_paused = true)]
    async fn upstream_opening_has_a_deadline() {
        use drydock_transport::{Limits, Transport};
        let (a, b) = tokio::io::duplex(4096);
        let (host, guest) =
            tokio::join!(Transport::yamux(Box::new(a), true, Limits::default()), Transport::yamux(Box::new(b), false, Limits::default()));
        let (mut host, guest) = (host.unwrap(), guest.unwrap());
        let opener = Arc::new(AsyncMutex::new(guest.opener.clone()));
        let pending = tokio::spawn(async move { upstream(&opener, "never-acknowledges".into()).await });
        // Network-boundary stand-in: accept the real forward but never ack it.
        let _hung_endpoint = host.accept().await.unwrap().unwrap();
        tokio::time::advance(Duration::from_secs(31)).await;
        let result = tokio::time::timeout(Duration::from_secs(1), pending).await.unwrap().unwrap();
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::TimedOut);
    }

    // Reject over-limit DNS frames from their length prefix, before allocating
    // or waiting for the payload. The exact limit still accepts a DNS question.
    #[hegel::test]
    fn dns_tcp_query_size_is_bounded(tc: hegel::TestCase) {
        let oversized = tc.draw(gs::integers::<u16>().min_value(MAX_DNS_QUERY as u16 + 1));
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let map = Mutex::new(FakeDns::default());
            let (mut server, mut client) = tokio::io::duplex(MAX_DNS_QUERY + 2);
            client.write_u16(oversized).await.unwrap();
            client.shutdown().await.unwrap();
            assert_eq!(dns_exchange(&mut server, &map).await.unwrap_err().kind(), io::ErrorKind::InvalidInput);
            let mut query = Message::new();
            query.add_query(Query::query(Name::from_ascii("size.example.").unwrap(), RecordType::A));
            let mut bytes = query.to_vec().unwrap();
            bytes.resize(MAX_DNS_QUERY, 0);
            let (mut server, mut client) = tokio::io::duplex(MAX_DNS_QUERY + 2);
            client.write_u16(MAX_DNS_QUERY as u16).await.unwrap();
            client.write_all(&bytes).await.unwrap();
            dns_exchange(&mut server, &map).await.unwrap();
            assert!(client.read_u16().await.unwrap() > 0);
        });
    }

    // The HTTP boundary may reject, truncate, or oversize its CONNECT reply;
    // none of these responses may let application bytes enter the upstream.
    #[tokio::test]
    async fn connect_rejects_bad_responses() {
        for response in
            [b"HTTP/1.1 403 Denied\r\n\r\n".to_vec(), b"HTTP/1.1 200".to_vec(), vec![b'x'; 16385], b"HTTP/9 200 OK\r\n\r\n".to_vec()]
        {
            let (stream, mut proxy) = tokio::io::duplex(32768);
            let task = tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(proxy.read_u8().await.unwrap());
                }
                proxy.write_all(&response).await.unwrap();
                proxy.shutdown().await.unwrap();
            });
            assert!(connect(&mut (Box::new(stream) as ByteStream), "example.org:443").await.is_err());
            task.await.unwrap();
        }
    }

    // The redirect is capture, not policy: all TCP is redirected, DNS uses its
    // own listener, and only agent-marked sockets/local forwards bypass capture.
    #[test]
    fn nft_rules_cover_both_families_without_uid_exemption() {
        let text = rules(true, &["127.0.0.1:9000".parse().unwrap()]);
        assert!(text.contains("table inet drydock_egress"));
        assert!(text.contains(&format!("meta mark {SOCKET_MARK} return")));
        assert!(!text.contains("skuid"));
        assert!(text.contains("udp dport 53 redirect to :1053"));
        assert!(text.contains("tcp dport 53 redirect to :1053"));
        assert!(text.contains("meta l4proto tcp redirect to :15001"));
        let positions: Vec<_> = [
            "meta mark",
            "ip daddr 127.0.0.1 tcp dport 15002 return",
            "ip daddr 127.0.0.1 tcp dport 9000 return",
            "udp dport 53 redirect",
            "tcp dport 53 redirect",
            "meta l4proto tcp redirect",
        ]
        .iter()
        .map(|rule| text.find(rule).unwrap())
        .collect();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        let disabled = rules(false, &["127.0.0.1:9000".parse().unwrap()]);
        assert_eq!(disabled, "add table inet drydock_egress\nflush table inet drydock_egress\n");
        assert!(!disabled.contains("redirect"));
    }
}

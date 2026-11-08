//! Destinations in one normal form, so a policy read back compares equal to
//! the request.
use std::net::Ipv4Addr;

/// An IPv4 address or CIDR as `a.b.c.d/bits`, host bits cleared.
pub fn normal_cidr(cidr: &str) -> Option<String> {
    let (ip, bits) = cidr.split_once('/').unwrap_or((cidr, "32"));
    let (ip, bits) = (ip.parse::<Ipv4Addr>().ok()?, bits.parse::<u32>().ok().filter(|b| *b <= 32)?);
    let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
    Some(format!("{}/{bits}", Ipv4Addr::from(u32::from(ip) & mask)))
}
/// A host name as vendors compare them: lowercase, no final dot.
pub fn normal_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

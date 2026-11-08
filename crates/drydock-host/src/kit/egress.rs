//! Destinations and addresses as every vendor's rules need them: CIDRs and
//! names in one normal form, private addresses no public builder or proxy
//! reaches, and registry hosts on them.
pub use crate::module::egress::{normal_cidr, normal_host};
use async_trait::async_trait;
use std::{net::IpAddr, time::Duration};
/// Whether a host is an IPv6 literal (bare or bracketed).
pub fn ipv6(host: &str) -> bool {
    host.contains(':') || host.starts_with('[')
}

/// Addresses no public builder or proxy reaches: private, loopback,
/// link-local, unspecified, broadcast, shared (100.64/10), IETF protocol
/// (192.0.0/24) and benchmarking (198.18/15) IPv4; loopback, unique-local,
/// link- and site-local IPv6; IPv4-mapped IPv6 by its IPv4 address.
pub fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || (a == 100 && (64..128).contains(&b))
                || (a, b, c) == (192, 0, 0)
                || (a == 198 && (18..20).contains(&b))
        }
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(v4) => private(IpAddr::V4(v4)),
            None => {
                ip.is_loopback()
                    || ip.is_unspecified()
                    || (ip.segments()[0] & 0xfe00) == 0xfc00
                    || matches!(ip.segments()[0] & 0xffc0, 0xfe80 | 0xfec0)
            }
        },
    }
}

/// Name suffixes no public resolver answers.
const PRIVATE_SUFFIXES: &[&str] = &[".localhost", ".local", ".internal", ".lan", ".home.arpa", ".test", ".invalid"];

/// What makes a host private, when it plainly is.
#[derive(Debug, PartialEq)]
pub enum PrivateHost {
    /// A private address, literal or resolved.
    Address(IpAddr),
    /// `localhost`, a single-label name or a non-public suffix.
    Name,
}
impl PrivateHost {
    /// " (address)" for an address, nothing for a name.
    pub fn detail(&self) -> String {
        match self {
            Self::Address(ip) => format!(" ({ip})"),
            Self::Name => String::new(),
        }
    }
}
/// `host` (a registry's, perhaps with a port) is plainly private: a private
/// address literal or a name that cannot be public. Names are not resolved.
pub fn private_host(host: &str) -> Option<PrivateHost> {
    let host = without_port(host);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return private(ip).then_some(PrivateHost::Address(ip));
    }
    let lower = normal_host(host);
    (lower == "localhost" || !lower.contains('.') || PRIVATE_SUFFIXES.iter().any(|s| lower.ends_with(s))).then_some(PrivateHost::Name)
}
/// [`private_host`], then a name that resolves to a private address. Best
/// effort: the vendor resolves the name again, and a name that does not
/// resolve here is left to the vendor, whose resolver may see public names
/// this host's does not.
pub async fn private_registry(registry: &str, resolver: &dyn Resolver) -> Option<PrivateHost> {
    if let Some(private) = private_host(registry) {
        return Some(private);
    }
    let host = without_port(registry);
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    match resolver.resolve(host).await {
        Ok(addresses) => addresses.into_iter().find(|ip| private(*ip)).map(PrivateHost::Address),
        Err(error) => {
            tracing::debug!(registry = host, %error, "registry name did not resolve; the private-address check is skipped");
            None
        }
    }
}

/// `host` without its port or IPv6 brackets. A bare IPv6 literal is whole:
/// its last group is never a port.
fn without_port(host: &str) -> &str {
    if host.parse::<IpAddr>().is_ok() {
        return host;
    }
    let host = host.rsplit_once(':').filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit())).map_or(host, |(h, _)| h);
    host.trim_start_matches('[').trim_end_matches(']')
}

/// Resolves a host name, so prepare can refuse a registry a vendor's
/// builders cannot reach before any build starts.
#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}
/// The system resolver, bounded to five seconds.
pub struct SystemResolver;
#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        let lookup = tokio::net::lookup_host((host, 443));
        match tokio::time::timeout(Duration::from_secs(5), lookup).await {
            Ok(addresses) => Ok(addresses?.map(|a| a.ip()).collect()),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "lookup timed out")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Private-address rules, IPv4-mapped IPv6 judged by its IPv4 address.
    #[test]
    fn private_addresses() {
        for ip in [
            "10.0.0.1",
            "192.168.1.31",
            "100.64.0.1",
            "192.0.0.8",
            "198.18.0.1",
            "169.254.1.1",
            "255.255.255.255",
            "::1",
            "fd00::1",
            "fe80::1",
            "fec0::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
        ] {
            assert!(private(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "203.0.113.5", "198.20.0.1", "2606:4700::1111", "::ffff:1.1.1.1"] {
            assert!(!private(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn private_hosts() {
        for host in ["192.168.1.31:3000", "localhost:5000", "registry:5000", "forgejo.lab.internal", "[::1]:5000", "x.test"] {
            assert!(private_host(host).is_some(), "{host}");
        }
        for host in ["ghcr.io", "registry.example.com:443", "203.0.113.5", "2606:4700::1111", "[2606:4700::1111]:443"] {
            assert!(private_host(host).is_none(), "{host}");
        }
    }
}

//! Wire validation and the identical schema patterns used by other language hosts.
use crate::Period;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use utoipa::ToSchema;

pub fn ipv6_pattern() -> &'static str {
    static PATTERN: OnceLock<String> = OnceLock::new();
    PATTERN.get_or_init(|| {
        let hextet="[0-9A-Fa-f]{1,4}";
        let ipv4=r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
        let mut alternatives=vec![r"(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?:(?::[0-9A-Fa-f]{1,4}){1,6})|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:))".to_string(),format!("(?:{hextet}:){{6}}{ipv4}")];
        // Embedded IPv4 occupies two hextets. Compression must omit at least one.
        for prefix in 0..=5 {
            for suffix in 0..=5-prefix {
                let left=if prefix==0 {"::".into()}else{format!("(?:{hextet}:){{{}}}{hextet}::",prefix-1)};
                alternatives.push(format!("{left}(?:{hextet}:){{{suffix}}}{ipv4}"));
            }
        }
        format!("(?:{})",alternatives.join("|"))
    })
}
pub fn host_pattern() -> &'static str {
    static PATTERN: OnceLock<String> = OnceLock::new();
    PATTERN.get_or_init(|| {
        format!(
            r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{{0,61}}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{{0,61}}[A-Za-z0-9])?)*\.?|{v6}|\[{v6}\])$",
            v6 = ipv6_pattern()
        )
    })
}
pub fn cidr_pattern() -> &'static str {
    static PATTERN: OnceLock<String> = OnceLock::new();
    PATTERN.get_or_init(|| format!(r"^(?:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{{2}}|[1-9]?[0-9])\.){{3}}(?:25[0-5]|2[0-4][0-9]|1[0-9]{{2}}|[1-9]?[0-9])/(?:[0-9]|[12][0-9]|3[0-2])|{}/(?:[0-9]|[1-9][0-9]|1[01][0-9]|12[0-8]))$",ipv6_pattern()))
}
/// A validated DNS name or IP literal. Schema uses the exact decoder pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(try_from = "String", into = "String")]
#[schema(value_type=String)]
pub struct HostAddress(String);
/// A validated IPv4/IPv6 CIDR, preserving the caller's wire spelling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(try_from = "String", into = "String")]
#[schema(value_type=String)]
pub struct Cidr(String);
/// Zero is not a destination port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
#[schema(value_type=u16)]
pub struct Port(std::num::NonZeroU16);
impl Port {
    pub fn new(value: u16) -> Option<Self> {
        std::num::NonZeroU16::new(value).map(Self)
    }
    pub fn get(self) -> u16 {
        self.0.get()
    }
}
/// A typed UTC instant, encoded as RFC3339. Equivalent offsets compare equally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(try_from = "String", into = "String")]
#[schema(value_type=String,format=DateTime)]
pub struct Timestamp(chrono::DateTime<chrono::Utc>);
impl Timestamp {
    pub fn instant(&self) -> chrono::DateTime<chrono::Utc> {
        self.0
    }
}
impl From<chrono::DateTime<chrono::Utc>> for Timestamp {
    fn from(value: chrono::DateTime<chrono::Utc>) -> Self {
        Self(value)
    }
}
impl From<Timestamp> for String {
    fn from(value: Timestamp) -> Self {
        value.0.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
    }
}
impl std::str::FromStr for Timestamp {
    type Err = &'static str;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}
macro_rules! string_access {
    ($ty:ty) => {
        impl $ty {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl From<$ty> for String {
            fn from(value: $ty) -> Self {
                value.0
            }
        }
        impl std::str::FromStr for $ty {
            type Err = &'static str;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::try_from(value.to_string())
            }
        }
    };
}
string_access!(HostAddress);
string_access!(Cidr);

impl TryFrom<String> for HostAddress {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let ip = value.parse::<std::net::IpAddr>().is_ok()
            || value.strip_prefix('[').and_then(|v| v.strip_suffix(']')).is_some_and(|v| v.parse::<std::net::Ipv6Addr>().is_ok());
        let dns = value.strip_suffix('.').unwrap_or(&value).split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && label.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
        if value.len() <= 253 && (ip || dns) { Ok(Self(value)) } else { Err("invalid destination host") }
    }
}
impl TryFrom<String> for Cidr {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let canonical_prefix =
            value.split_once('/').is_some_and(|(_, prefix)| prefix.parse::<u8>().is_ok_and(|bits| bits.to_string() == prefix));
        if canonical_prefix && value.parse::<ipnet::IpNet>().is_ok() { Ok(Self(value)) } else { Err("invalid destination CIDR") }
    }
}
impl TryFrom<String> for Timestamp {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        chrono::DateTime::parse_from_rfc3339(&value)
            .map(|time| Self(time.with_timezone(&chrono::Utc)))
            .map_err(|_| "invalid RFC3339 timestamp")
    }
}
impl Period {
    pub fn new(start: Timestamp, end: Timestamp) -> Result<Self, &'static str> {
        if start.instant() > end.instant() {
            return Err("period start must be <= end");
        }
        Ok(Self { start, end })
    }
    pub fn start(&self) -> &Timestamp {
        &self.start
    }
    pub fn end(&self) -> &Timestamp {
        &self.end
    }
}

pub(crate) fn nonempty_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let value = String::deserialize(d)?;
    if value.is_empty() { Err(serde::de::Error::custom("must not be empty")) } else { Ok(value) }
}
pub(crate) fn is_platform_part(value: &str) -> bool {
    !value.is_empty() && value.len() <= 32 && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}
pub(crate) fn platform_part<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let value = String::deserialize(d)?;
    if is_platform_part(&value) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom("platform names are 1 to 32 lowercase letters or digits"))
    }
}
pub(crate) fn nonempty_secret<'de, D: serde::Deserializer<'de>>(d: D) -> Result<crate::Secret, D::Error> {
    nonempty_string(d).map(crate::Secret::new)
}
pub(crate) fn positive_cpus<'de, D: serde::Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
    let value = f64::deserialize(d)?;
    if value.is_finite() && value > 0.0 { Ok(value) } else { Err(serde::de::Error::custom("cpus must be positive")) }
}
pub(crate) fn command<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    let value = Vec::<String>::deserialize(d)?;
    if value.first().is_some_and(|v| !v.is_empty()) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom("command must start with a nonempty executable"))
    }
}

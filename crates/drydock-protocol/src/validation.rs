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
    PATTERN.get_or_init(|| format!(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{{0,61}}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{{0,61}}[A-Za-z0-9])?)*\.?|{v6}|\[{v6}\])$",v6=ipv6_pattern()))
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
/// Validated RFC3339 timestamp; serialization preserves the original offset/spelling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(try_from = "String", into = "String")]
#[schema(value_type=String,format=DateTime)]
pub struct Timestamp(String);
impl Timestamp {
    pub fn instant(&self) -> chrono::DateTime<chrono::FixedOffset> {
        chrono::DateTime::parse_from_rfc3339(&self.0).expect("validated timestamp")
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
string_access!(Timestamp);
impl TryFrom<String> for HostAddress {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        static HOST: OnceLock<regex::Regex> = OnceLock::new();
        if value.len() <= 253
            && HOST
                .get_or_init(|| regex::Regex::new(host_pattern()).expect("host pattern"))
                .is_match(&value)
        {
            Ok(Self(value))
        } else {
            Err("invalid destination host")
        }
    }
}
impl TryFrom<String> for Cidr {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        static CIDR: OnceLock<regex::Regex> = OnceLock::new();
        if CIDR
            .get_or_init(|| regex::Regex::new(cidr_pattern()).expect("CIDR pattern"))
            .is_match(&value)
            && value.parse::<ipnet::IpNet>().is_ok()
        {
            Ok(Self(value))
        } else {
            Err("invalid destination CIDR")
        }
    }
}
impl TryFrom<String> for Timestamp {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        chrono::DateTime::parse_from_rfc3339(&value).map_err(|_| "invalid RFC3339 timestamp")?;
        Ok(Self(value))
    }
}
impl Period {
    pub fn new(start: Timestamp, end: Timestamp) -> Result<Self, &'static str> {
        let period = Self { start, end };
        period.validate()?;
        Ok(period)
    }
    pub fn start(&self) -> &Timestamp {
        &self.start
    }
    pub fn end(&self) -> &Timestamp {
        &self.end
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.start.instant() <= self.end.instant() {
            Ok(())
        } else {
            Err("period start must be <= end")
        }
    }
}

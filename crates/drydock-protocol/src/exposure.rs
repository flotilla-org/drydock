//! Standing exposures: endpoints drydock makes between its own machine and a
//! vessel. Each is named, lives with the vessel until removed, and is carried
//! by whatever mechanism the provider allows. No type here names SSH, a token,
//! a key or how the bytes travel.
use crate::{HostAddress, Port};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use utoipa::ToSchema;

/// Which way an exposure's connections go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// An endpoint on drydock's machine reaches a target in the vessel.
    Inward,
    /// An endpoint in the vessel reaches a destination on drydock's machine.
    Outward,
}

/// Where an inward exposure's connections go, in the vessel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum InwardTarget {
    /// An absolute Unix socket path in the vessel.
    Unix(String),
    /// A numeric `ip:port` in the vessel.
    #[schema(value_type = String)]
    Tcp(SocketAddr),
}

/// How the client is handed an exposure's end on drydock's machine. Drydock
/// chooses it; only a Unix socket for now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Local {
    Unix(String),
}

/// `PUT …/exposures/inward/{name}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct InwardRequest {
    pub target: InwardTarget,
}

/// An inward exposure as it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Inward {
    pub name: String,
    pub target: InwardTarget,
    /// The endpoint on drydock's machine, under drydock's runtime directory.
    pub local: Local,
    pub ready: bool,
    /// Why the exposure is not working, when `ready` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ExposureError>,
}

/// The endpoint an outward exposure makes in the vessel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum Guest {
    /// An absolute Unix socket path in the vessel.
    Unix { unix: String },
    /// A DNS name in the vessel: drydock gives it a free loopback address and
    /// its hosts-file line, and listens there on `port`.
    Name { name: HostAddress, port: Port },
}

/// Where an outward exposure's connections go, on drydock's machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutwardDestination {
    /// An absolute Unix socket path on drydock's machine.
    Unix(String),
    /// `host:port`, where host is a DNS name or IP literal (IPv6 in brackets).
    /// A name is resolved once, when the exposure is set.
    Tcp(String),
}

/// `PUT …/exposures/outward/{name}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OutwardRequest {
    pub guest: Guest,
    pub destination: OutwardDestination,
}

/// An outward exposure as it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Outward {
    pub name: String,
    pub guest: Guest,
    pub destination: OutwardDestination,
    /// For a guest name: the loopback address and port it was given in the vessel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub address: Option<SocketAddr>,
    /// For a TCP destination: the address it resolved to when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub resolved: Option<SocketAddr>,
    pub ready: bool,
    /// Why the exposure is not working, when `ready` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ExposureError>,
}

/// Why an exposure is not working.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ExposureError {
    pub code: ExposureErrorCode,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExposureErrorCode {
    /// The vessel is not running. The exposure is set up when it runs again.
    NotRunning,
    /// The vessel is running but drydock cannot reach it yet; it keeps trying.
    VesselUnreachable,
    /// The vessel refused the exposure, or its destination is missing; drydock
    /// tries again whenever it re-establishes the vessel's exposures.
    Refused,
    /// The destination's name did not resolve when set. Set it again to retry.
    Unresolved,
}

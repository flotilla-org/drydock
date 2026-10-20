//! Candidate wire shapes for owner review on drydock PR #34, items 6 and 10.
//!
//! These types are deliberately isolated from the active protocol and its
//! OpenAPI routes. They are an executable proposal, not an approved API. The
//! host and provider modules must not consume them before the owner's ruling.
//! See `docs/protocol-proposal-34.md` for the proposed observation semantics.
use crate::{GoneCause, Period, SizeUsage, StopCause, UnknownReason};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::ToSchema;

/// A normal, in-progress provider operation is distinct from an API failure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Observation {
    Running,
    Stopped { cause: StopCause },
    Gone { cause: GoneCause },
    Transitioning { phase: TransitionPhase },
    Unknown { reason: UnknownReason },
}

/// Generic phases describe progress, not billing transitions. The host retains
/// its last stable billing observation until another stable observation arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransitionPhase {
    Preparing,
    Starting,
    Stopping,
    Reconfiguring,
    Destroying,
}

/// Initial provider-neutral vocabulary. Adding a resource is a protocol change,
/// rather than inventing provider-specific encodings inside resource names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Cpu,
    Memory,
    Disk,
    Gpu,
    SnapshotStorage,
    VolumeStorage,
    Environments,
}

/// Explicit units let providers report capacity or integrated resource usage
/// without consumers knowing a vendor's field names or GB/GiB conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceUnit {
    Count,
    Vcpu,
    Byte,
    VcpuSecond,
    ByteSecond,
    DeviceSecond,
    CountSecond,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Quantity {
    pub amount: f64,
    pub unit: ResourceUnit,
}

/// Currency is explicit, e.g. USD or EUR; the field name fixes no currency.
/// A missing cost is unknown, whereas an amount of zero is a known zero cost.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Cost {
    pub amount: f64,
    pub currency: String,
}

/// Aggregated usage must say what population it measured. In particular,
/// organisation totals cannot prove that one suspended environment stopped billing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UsageScope {
    Provider,
    Organization { id: String },
    Environment { id: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct UsageMeasurements {
    pub scope: UsageScope,
    pub resources: BTreeMap<ResourceKind, Quantity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<Cost>,
}

/// Retain the original sandbox-hours-by-size slice. Optional measurements can
/// reconcile other provider data without fabricating a distribution over sizes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Usage {
    pub period: Period,
    pub environment_hours: Vec<SizeUsage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurements: Option<UsageMeasurements>,
}

/// Scope is data, never an opaque "region/class/resource" string. Missing scope
/// components mean the provider reports the resource at a broader scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct QuotaKey {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    pub resource: ResourceKind,
}

/// The same unit applies to current use and limit. Unknown limits stay unknown.
/// A vector of these rows keeps structured keys representable as ordinary JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ResourceQuota {
    pub key: QuotaKey,
    pub unit: ResourceUnit,
    pub in_use: f64,
    pub limit: Option<f64>,
}

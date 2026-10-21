//! JSON wire contract for ADR 0070 language hosts. No provider or HTTP runtime lives here.
//! Provider IDs are opaque; labels identify a client's environment for idempotent creation.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::ToSchema;

pub mod openapi;
pub mod validation;
pub use validation::{Cidr, HostAddress, Port, Timestamp};

/// Increment when making an incompatible wire change. A mismatch is not ready.
pub const PROTOCOL_VERSION: &str = "5";

/// Secret wire string. Debug output is redacted; serialization deliberately exposes the value.
/// PartialEq is for wire-value comparisons, NOT constant-time authentication.
/// Authentication belongs to hosts, which must use constant-time token comparison.
/// This type does not promise secure erasure of strings or serialization buffers.
#[derive(Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
#[schema(value_type = String)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Explicit plaintext access for transport adapters. Never log this value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct HostConfiguration {
    pub modules: Vec<ModuleConfiguration>,
    pub providers: Vec<ProviderConfiguration>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ModuleConfiguration {
    pub name: String,
    pub entrypoint: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ProviderConfiguration {
    pub name: String,
    pub module: String,
    /// Non-secret vendor-specific configuration only.
    pub settings: BTreeMap<String, serde_json::Value>,
    pub credential: CredentialMode,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum CredentialMode {
    Direct {
        credential_reference: String,
    },
    Proxied {
        #[serde(deserialize_with = "validation::nonempty_secret")]
        #[schema(value_type = String, format = Password, min_length = 1)]
        placeholder_token: Secret,
        proxy_url: String,
    },
}
/// Delivered in memory over the authenticated host connection; never persisted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct CredentialRefresh {
    #[serde(deserialize_with = "validation::nonempty_secret")]
    #[schema(value_type = String, format = Password, min_length = 1)]
    pub value: Secret,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Hello {
    pub protocol_version: String,
    pub host_version: String,
    pub modules: Vec<LoadedModule>,
    pub providers: Vec<ProviderDeclaration>,
}
impl Hello {
    /// Whether this host speaks exactly the client's current wire version.
    /// Callers must still inspect per-provider readiness before placement.
    pub fn is_compatible(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct LoadedModule {
    pub name: String,
    pub version: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ProviderDeclaration {
    pub provider: String,
    pub module: String,
    pub capabilities: Capabilities,
    pub readiness: Readiness,
    pub rate_limits: Vec<RateLimit>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct RateLimit {
    pub operation: String,
    pub requests: u32,
    pub period_seconds: u64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Readiness {
    Ready,
    MissingTool { reason: String },
    MissingCredential { reason: String },
    VersionMismatch { reason: String },
    Unknown { reason: String },
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Capabilities {
    pub material_modes: Vec<MaterialMode>,
    pub checkout_strategies: Vec<CheckoutStrategy>,
    pub workspace_root: String,
    pub suspend_resume: bool,
    /// Whether suspend retains running processes/memory, when supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspend_preserves_memory: Option<bool>,
    pub export: bool,
    pub egress: EgressCapability,
    pub fallback_runner: bool,
    pub bootstrap: BootstrapRoute,
    pub usage: bool,
    pub quota: bool,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MaterialMode {
    Frozen,
    Pushed,
    Shared,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckoutStrategy {
    HostWorktree,
    HostClone,
    CloneInVessel,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapRoute {
    Bake,
    Upload,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct EgressCapability {
    pub routes: Vec<EgressRoute>,
    pub enforcement: Enforcement,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EgressRoute {
    None,
    ExplicitProxy,
    TransparentProxy,
    Open,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    Enforced,
    Advisory,
}
/// Deny all is the default. Providers must refuse unrepresentable destinations, never widen them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum EgressRequest {
    DenyAll {
        #[serde(default)]
        direct: Vec<Destination>,
    },
    Open,
}
impl Default for EgressRequest {
    fn default() -> Self {
        Self::DenyAll { direct: Vec::new() }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Destination {
    /// All ports to this host name; how the provider enforces the name is the provider's choice.
    Host {
        host: HostAddress,
    },
    HostPort {
        host: HostAddress,
        port: Port,
    },
    Cidr {
        cidr: Cidr,
    },
}
/// Preparation is look-up-or-build at the provider. Modules choose their key;
/// providers that fix resources at prepare include size alongside both digests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct PrepareRequest {
    pub size: Size,
    #[serde(deserialize_with = "validation::nonempty_string")]
    #[schema(min_length = 1)]
    pub image_digest: String,
    #[serde(deserialize_with = "validation::nonempty_string")]
    #[schema(min_length = 1)]
    pub tools_digest: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Prepared {
    pub provider: String,
    pub id: String,
    #[serde(deserialize_with = "validation::nonempty_string")]
    #[schema(min_length = 1)]
    pub image_digest: String,
    #[serde(deserialize_with = "validation::nonempty_string")]
    #[schema(min_length = 1)]
    pub tools_digest: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Size {
    #[serde(deserialize_with = "validation::positive_cpus")]
    #[schema(exclusive_minimum = 0)]
    pub cpus: f64,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
}
/// Repeated creation with the same label returns the existing environment (200).
/// Prepared forms belong to one provider; cross-provider use is Refused.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ProvisionRequest {
    #[serde(deserialize_with = "validation::nonempty_string")]
    #[schema(min_length = 1)]
    pub label: String,
    pub prepared: Prepared,
    pub size: Size,
    #[serde(default)]
    pub egress: EgressRequest,
    pub ssh_public_key: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Environment {
    pub id: String,
    /// Unlabelled resources are listable, inspectable and destroyable.
    pub label: Option<String>,
    pub provider: String,
    pub state: Observation,
    pub granted_size: Option<Size>,
    pub egress: Enforcement,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reach {
    Ssh {
        endpoint: String,
        /// May contain a short-lived gateway token; always redact diagnostics.
        user: Secret,
        host_key: String,
    },
    Dial {
        url: String,
        token: Secret,
        #[schema(format = DateTime)]
        expires_at: Timestamp,
    },
    Relay {
        path: String,
    },
}
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum StopCause {
    SuspendedByRequest,
    PausedByProvider,
    GuestHalted,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GoneCause {
    LifetimeCapReached,
    EvictedByProvider,
    HostOutOfMemory,
    VmmExited {
        code: i32,
    },
    GuestPoweredOff,
    /// The provider explicitly reports destruction without an attributed client request.
    DestroyedAtProvider,
    /// A previously known environment is absent from an authoritative complete list.
    MissingOnList,
    /// The provider confirmed deletion requested by the client.
    DestroyedByRequest,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    /// The provider explicitly reports an unknown state, without an API failure.
    ProviderStateUnknown,
    HostUnreachable,
    ProviderApiError,
    GuestUnresponsive,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimestampSource {
    Provider,
    Adaptor,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Event {
    /// Opaque cursor to send as `since` on reconnect; resume is exclusive.
    pub cursor: String,
    pub id: String,
    pub provider: String,
    pub label: Option<String>,
    /// RFC 3339 timestamp.
    #[schema(format = DateTime)]
    pub timestamp: Timestamp,
    pub timestamp_source: TimestampSource,
    pub event: EventKind,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    Created,
    Running {
        granted_size: Size,
    },
    Stopped {
        cause: StopCause,
    },
    /// Explicit pause transition, distinct from the more general stopped observation.
    Paused {
        cause: StopCause,
    },
    Resumed,
    Gone {
        cause: GoneCause,
    },
}
/// Hosts unable to replay emit a snapshot marking the gap. Inventory is complete
/// only for providers absent from `unavailable_providers`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ObserveRecord {
    Event {
        event: Event,
    },
    Snapshot {
        cursor: String,
        environments: Vec<Environment>,
        /// Providers omitted from this snapshot. Preserve their previous inventory;
        /// omission must not be interpreted as deletion or a billing transition.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        unavailable_providers: BTreeMap<String, ProtocolError>,
    },
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(try_from = "UncheckedPeriod")]
pub struct Period {
    #[schema(format = DateTime)]
    start: Timestamp,
    #[schema(format = DateTime)]
    end: Timestamp,
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

impl ResourceKind {
    /// Initial vocabulary's capacity and integrated-usage UCUM units.
    pub fn accepts_unit(self, unit: &str) -> bool {
        match self {
            Self::Cpu => matches!(unit, "{vCPU}" | "{vCPU}.s"),
            Self::Memory | Self::Disk | Self::SnapshotStorage | Self::VolumeStorage => matches!(unit, "By" | "By.s"),
            Self::Gpu => matches!(unit, "{GPU}" | "{GPU}.s"),
            Self::Environments => matches!(unit, "1" | "s"),
        }
    }
}
/// UCUM code. Providers use `By`, `By.s`, `{vCPU}`, `{vCPU}.s`,
/// `{GPU}.s`, and `1` for dimensionless counts. New resource variants require
/// a protocol version bump; scope ids are opaque to consumers.
pub type ResourceUnit = String;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Quantity {
    pub amount: f64,
    pub unit: ResourceUnit,
}

/// Currency is explicit, e.g. USD or EUR; the field name fixes no currency.
/// A missing cost is unknown, whereas an amount of zero is a known zero cost.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Cost {
    #[serde(deserialize_with = "decimal_amount")]
    pub amount: String,
    pub currency: String,
}

/// Aggregated usage must say what population it measured. In particular,
/// organisation totals cannot prove that one suspended environment stopped billing.
/// Organization and environment IDs are provider-opaque; consumers only compare them.
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

/// Nonnegative exact decimal money: no exponent, binary float, or NaN.
fn decimal_amount<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let value = String::deserialize(d)?;
    if !valid_decimal(&value) {
        return Err(serde::de::Error::custom("expected nonnegative exact decimal"));
    }
    Ok(value)
}
pub fn valid_decimal(value: &str) -> bool {
    let mut parts = value.split('.');
    let integer = parts.next().unwrap_or("");
    !integer.is_empty()
        && integer.bytes().all(|b| b.is_ascii_digit())
        && parts.next().is_none_or(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        && parts.next().is_none()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SizeUsage {
    pub size: Size,
    pub hours: f64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Quota {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceQuota>,
    pub credits_remaining: Option<f64>,
    pub credit_unit: Option<String>,
    pub concurrency_in_use: Option<u64>,
    pub concurrency_limit: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ExecRequest {
    #[serde(deserialize_with = "validation::command")]
    #[schema(min_items = 1)]
    pub command: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ResumeToken {
    pub token: Secret,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Export {
    pub reference: String,
}
/// Adaptors never retry. Internal preserves the vendor's raw error text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProtocolError {
    NotFound {
        reason: String,
    },
    MethodNotAllowed {
        reason: String,
    },
    Refused {
        reason: String,
    },
    Unavailable {
        reason: String,
        retry_after: Option<u64>,
        /// Optional bounded provider/transport detail; never include it in public logs.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider_error: Option<Secret>,
    },
    RateLimited {
        reason: String,
        retry_after: Option<u64>,
    },
    QuotaExhausted {
        reason: String,
    },
    CredentialRejected {
        reason: String,
    },
    /// A completed guest command failed, distinct from a vendor/transport outage.
    CommandFailed {
        reason: String,
        exit_code: i32,
        /// Vendor-merged guest output. Sensitive diagnostics; never log it.
        output: Secret,
    },
    Internal {
        reason: String,
        /// Sensitive, untrusted vendor text: never log at info level or forward to end users.
        provider_error: Secret,
    },
}

#[derive(Deserialize)]
struct UncheckedPeriod {
    start: Timestamp,
    end: Timestamp,
}
impl TryFrom<UncheckedPeriod> for Period {
    type Error = &'static str;
    fn try_from(raw: UncheckedPeriod) -> Result<Self, Self::Error> {
        Self::new(raw.start, raw.end)
    }
}
impl ProtocolError {
    /// Retryable unavailability without sensitive provider diagnostics.
    pub fn unavailable(reason: impl Into<String>, retry_after: Option<u64>) -> Self {
        Self::Unavailable { provider_error: None, reason: reason.into(), retry_after }
    }

    /// Static diagnostics label; never exposes vendor error text.
    pub const fn class(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "not_found",
            Self::MethodNotAllowed { .. } => "method_not_allowed",
            Self::Refused { .. } => "refused",
            Self::Unavailable { .. } => "unavailable",
            Self::RateLimited { .. } => "rate_limited",
            Self::QuotaExhausted { .. } => "quota_exhausted",
            Self::CredentialRejected { .. } => "credential_rejected",
            Self::CommandFailed { .. } => "command_failed",
            Self::Internal { .. } => "internal",
        }
    }

    /// HTTP status is part of the shared wire contract, independent of a host framework.
    pub const fn status(&self) -> u16 {
        match self {
            Self::Refused { .. } => 422,
            Self::NotFound { .. } => 404,
            Self::MethodNotAllowed { .. } => 405,
            Self::Unavailable { .. } => 503,
            Self::RateLimited { .. } => 429,
            Self::QuotaExhausted { .. } => 402,
            Self::CredentialRejected { .. } => 502,
            Self::CommandFailed { .. } => 424,
            Self::Internal { .. } => 500,
        }
    }
    pub const fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Unavailable { retry_after, .. } | Self::RateLimited { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

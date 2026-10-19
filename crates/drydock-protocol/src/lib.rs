//! JSON wire contract for ADR 0070 language hosts. No provider or HTTP runtime lives here.
//! Provider IDs are opaque; labels identify a client's environment for idempotent creation.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::ToSchema;

pub mod openapi;
pub mod validation;
pub use validation::{Cidr, HostAddress, Port, Timestamp};

/// Increment when making an incompatible wire change. A mismatch is not ready.
pub const PROTOCOL_VERSION: &str = "1";

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
    Direct { credential_reference: String },
    Proxied { placeholder_token: Secret, proxy_url: String },
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
    HostPort { host: HostAddress, port: Port },
    Cidr { cidr: Cidr },
}
/// Preparation is look-up-or-build at the provider, keyed by both digests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct PrepareRequest {
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
        user: String,
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
    Unknown { reason: UnknownReason },
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
    /// A previously known environment is absent from an authoritative complete list.
    MissingOnList,
    /// The provider confirmed deletion requested by the client.
    DestroyedByRequest,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
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
/// Hosts unable to replay emit one complete list snapshot, explicitly marking the gap.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ObserveRecord {
    Event { event: Event },
    Snapshot { cursor: String, environments: Vec<Environment> },
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(try_from = "UncheckedPeriod")]
pub struct Period {
    #[schema(format = DateTime)]
    start: Timestamp,
    #[schema(format = DateTime)]
    end: Timestamp,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Usage {
    pub period: Period,
    pub environment_hours: Vec<SizeUsage>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SizeUsage {
    pub size: Size,
    pub hours: f64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Quota {
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

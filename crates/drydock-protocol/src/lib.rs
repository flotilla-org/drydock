//! JSON wire contract shared by the server and language hosts. No provider or HTTP runtime lives here.
//! Provider IDs are opaque; labels identify a client's environment for idempotent creation.
mod diagnostic;
mod exposure;
pub use diagnostic::DiagnosticMasker;
pub use exposure::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::ToSchema;

pub mod openapi;
pub mod validation;
pub use validation::{Cidr, HostAddress, Port, Timestamp};

/// Increment when making an incompatible wire change. A mismatch is not ready.
pub const PROTOCOL_VERSION: &str = "10";

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

/// Credential override for one request, passed to the host as-is. Never stored or logged.
pub const CREDENTIAL_HEADER: &str = "drydock-credential";

/// The one configuration document: the TOML file and the `PUT /v1/config` body
/// in two syntaxes. Hosts receive it with server-only keys omitted.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    /// Keyed by instance name, which is arbitrary: two instances of one module are normal.
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderConfiguration>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfiguration {
    pub module: String,
    /// Non-secret vendor-specific configuration only.
    #[serde(default)]
    pub settings: BTreeMap<String, serde_json::Value>,
    /// Server only: where the server gets this provider's credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<CredentialLocation>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(untagged, deny_unknown_fields)]
pub enum CredentialLocation {
    /// A file's contents, or one top-level string field of a JSON file.
    File {
        file: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        json_field: Option<String>,
    },
    Env {
        env: String,
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
    /// Modules this server or host can configure.
    #[serde(default)]
    pub loadable_modules: Vec<LoadableModule>,
}
impl Hello {
    /// Whether this host speaks exactly the client's current wire version.
    /// Callers must still inspect per-provider readiness before placement.
    pub fn is_compatible(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct LoadableModule {
    pub name: String,
    pub version: String,
    /// Smallest supported resource request, used when the caller has no default.
    pub smallest_size: Size,
}
/// A configured provider, the same on the server and on hosts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ProviderDeclaration {
    pub provider: String,
    pub module: String,
    pub capabilities: Capabilities,
    pub readiness: Readiness,
    pub rate_limits: Vec<RateLimit>,
    pub ports: Ports,
    pub observation: ObservationMode,
}
/// Which optional operations exist.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Ports {
    pub exec: bool,
    pub suspend_resume: bool,
    pub export: bool,
    pub usage: bool,
    pub quota: bool,
}
/// How the server observes a provider: it polls the environment list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ObservationMode {
    Poll { interval_ms: u64 },
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
impl std::fmt::Display for Readiness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready => write!(f, "ready"),
            Self::MissingTool { reason } => write!(f, "missing tool: {reason}"),
            Self::MissingCredential { reason } => write!(f, "missing credential: {reason}"),
            Self::VersionMismatch { reason } => write!(f, "version mismatch: {reason}"),
            Self::Unknown { reason } => write!(f, "unknown: {reason}"),
        }
    }
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
    /// Vessels run the drydock agent from the tools image. Launch reports
    /// success only after the agent's current hello over the SSH reach.
    #[serde(default)]
    pub agent: bool,
    /// Platforms this provider can run, preferred first. A prepare request
    /// that names none gets the first; one naming another is refused.
    #[serde(default)]
    pub platforms: Vec<Platform>,
    /// How a vessel image reaches this provider, preferred first. A prepare
    /// request that names no route gets the first; one naming another is refused.
    #[serde(default)]
    pub image_routes: Vec<ImageRoute>,
    pub usage: bool,
    pub quota: bool,
    /// Vessels run on the host's own filesystem, shared with the host and with
    /// one another: a guest path is a host path. A client lays each vessel out
    /// below paths it can write, never at fixed guest locations.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub host_filesystem: bool,
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
/// One way a vessel image gets into a provider. Clients choose among declared
/// routes by these properties and their own policy, never by provider name; a
/// provider's limits stay properties of its own declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "route", rename_all = "snake_case")]
pub enum ImageRoute {
    /// The host uploads the prepared image into the provider's own registry.
    ProviderPush {
        protocol: PushProtocol,
        /// How long one minted push credential stays valid, when it expires.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credential_lifetime_seconds: Option<u64>,
        tools_layer: ToolsLayer,
    },
    /// The provider pulls the base image from a registry it can reach.
    RegistryPull {
        auth: RegistryAuthKind,
        registration: CredentialRegistration,
        /// Whether the provider accepts `name@sha256:…` references.
        digest_references: bool,
        tools_layer: ToolsLayer,
    },
    /// The provider builds the image from a recipe the host sends.
    RemoteBuild { input: BuildInput, multi_stage: bool, tools_layer: ToolsLayer },
}
impl ImageRoute {
    pub fn kind(&self) -> ImageRouteKind {
        match self {
            Self::ProviderPush { .. } => ImageRouteKind::ProviderPush,
            Self::RegistryPull { .. } => ImageRouteKind::RegistryPull,
            Self::RemoteBuild { .. } => ImageRouteKind::RemoteBuild,
        }
    }
    pub fn tools_layer(&self) -> ToolsLayer {
        match self {
            Self::ProviderPush { tools_layer, .. } | Self::RegistryPull { tools_layer, .. } | Self::RemoteBuild { tools_layer, .. } => {
                *tools_layer
            }
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImageRouteKind {
    ProviderPush,
    RegistryPull,
    RemoteBuild,
}
impl std::str::FromStr for ImageRouteKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "provider_push" => Ok(Self::ProviderPush),
            "registry_pull" => Ok(Self::RegistryPull),
            "remote_build" => Ok(Self::RemoteBuild),
            _ => Err(format!("unknown image route {s:?}; expected provider_push, registry_pull or remote_build")),
        }
    }
}
impl std::fmt::Display for ImageRouteKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ProviderPush => "provider_push",
            Self::RegistryPull => "registry_pull",
            Self::RemoteBuild => "remote_build",
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PushProtocol {
    /// The OCI distribution protocol (`/v2/` blob uploads and manifest puts).
    OciDistribution,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RegistryAuthKind {
    Anonymous,
    /// Username and password or token.
    Basic,
}
/// How the provider learns the credential for a private registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRegistration {
    NotRequired,
    /// Registered once, out of band, through the provider's own API.
    ProviderApi,
    /// Supplied alongside each image reference.
    PerRequest,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BuildInput {
    Dockerfile,
}
/// Where the drydock tools layer joins the base image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolsLayer {
    /// The provider adds it, for example in its own build.
    Provider,
    /// The host appends it to the base image's manifest before handing it over.
    Host,
}
/// Pull access to one registry. Hosts send it only to the registry that the
/// reference it accompanies names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct RegistryCredential {
    pub username: String,
    #[schema(value_type = String, format = Password)]
    pub secret: Secret,
}
/// Why a provider cannot take an image. Stable codes for client policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "cause", rename_all = "snake_case")]
pub enum ImageRefusal {
    /// The provider, or the image, offers nothing for this platform.
    UnsupportedPlatform { platform: Platform },
    /// The image is larger than the provider accepts. `bytes` is a lower bound.
    TooLarge { bytes: u64, limit_bytes: u64 },
    /// A minted push credential expired before the upload finished. Retrying
    /// mints a new one and resumes from the blobs already uploaded.
    PushCredentialExpired,
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
/// Preparation is look-up-or-build at the provider: append the tools image's
/// files under /opt/drydock to the base, preserving its entrypoint, command and
/// init. tools_digest is the build-selected bootstrap agent OCI index reference.
/// The agent it carries is only a cache: the host always upgrades the vessel's
/// agent to its own build at the first hello, so a matching agent saves an
/// upload and any other is replaced. Build at the provider where possible,
/// otherwise append its layer; Upload bootstrap installs those same files
/// under /opt/drydock before the first hello.
/// Modules choose their own provider-recorded key from the image digest and
/// any prepare-time constraints (Daytona also includes size). The tools
/// digest is not part of it, nor is configuration. Provision must match the
/// recorded prepared form. See ADR 0070 Vessel tools.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct PrepareRequest {
    pub size: Size,
    /// Omitted: the provider's first declared platform. Hosts resolve it before
    /// a module prepares, so modules always receive a declared platform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    /// Omitted: the provider's first declared image route. Hosts resolve it
    /// before a module prepares, so modules always receive a declared route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<ImageRouteKind>,
    /// Pull access to `image_digest`'s registry, for routes where the host reads
    /// the base image itself. Never sent anywhere else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_pull: Option<RegistryCredential>,
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
    /// The platform this prepared form was built for; part of the module's key.
    pub platform: Platform,
    #[serde(deserialize_with = "validation::nonempty_string")]
    #[schema(min_length = 1)]
    pub image_digest: String,
    /// The tools image the prepare request named. Not part of the key: a
    /// prepared form made with another tools image is reused, and its agent
    /// is upgraded at the first hello.
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_public_key: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Environment {
    pub id: String,
    /// Unlabelled resources are listable, inspectable and destroyable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub provider: String,
    pub state: Observation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_size: Option<Size>,
    pub egress: Enforcement,
    /// The platform the environment runs, when the provider records it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    /// True only when this observation measured the egress claim.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub egress_measured: bool,
    /// Opaque effective-policy identity, when the provider supports one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_policy: Option<String>,
    /// When the provider observed this state, if it says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(format = DateTime)]
    pub timestamp: Option<Timestamp>,
}
impl Environment {
    /// The observation without its evidence fields, for comparing states.
    pub fn without_evidence(&self) -> Self {
        Self { egress_measured: false, egress_policy: None, timestamp: None, ..self.clone() }
    }
}
/// An OCI platform: `os` and `architecture` by OCI names (`linux`, `amd64`,
/// `arm64`), each 1 to 32 lowercase letters or digits. They become agent build
/// file and variable names, so decoding refuses anything else.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct Platform {
    #[serde(deserialize_with = "validation::platform_part")]
    #[schema(pattern = "^[a-z0-9]{1,32}$")]
    pub os: String,
    #[serde(deserialize_with = "validation::platform_part")]
    #[schema(pattern = "^[a-z0-9]{1,32}$")]
    pub architecture: String,
}
impl Platform {
    pub fn new(os: impl Into<String>, architecture: impl Into<String>) -> Self {
        Self { os: os.into(), architecture: architecture.into() }
    }
    /// The platform this executable was built for. Rust target names without
    /// an OCI equivalent pass through unchanged.
    pub fn current() -> Self {
        let os = match std::env::consts::OS {
            "macos" => "darwin",
            os => os,
        };
        let architecture = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            architecture => architecture,
        };
        Self::new(os, architecture)
    }
    /// Whether both names are plain OCI names (see the type's docs).
    pub fn is_plain(&self) -> bool {
        validation::is_platform_part(&self.os) && validation::is_platform_part(&self.architecture)
    }
}
impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.os, self.architecture)
    }
}
impl std::str::FromStr for Platform {
    type Err = String;
    /// Parses `os/architecture`, for example `linux/amd64`.
    fn from_str(text: &str) -> Result<Self, String> {
        let platform = text.split_once('/').map(|(os, architecture)| Self::new(os, architecture));
        platform.filter(Platform::is_plain).ok_or_else(|| format!("platform {text:?} must be os/architecture in lowercase OCI names"))
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reach {
    Ssh {
        endpoint: String,
        /// May contain a short-lived gateway token; always redact diagnostics.
        user: Secret,
        host_key: String,
        /// Whether this SSH server accepts remote (reverse) Unix-socket forwards.
        /// Drydock reaches the agent through a local forward alone, so it does
        /// not depend on this.
        #[serde(default)]
        reverse_forwards: bool,
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
impl Reach {
    /// Relay through the public relay route of this provider and environment.
    pub fn relay(provider: &str, id: &str) -> Self {
        let segment = |s: &str| percent_encoding::utf8_percent_encode(s, diagnostic::URL_RESERVED).to_string();
        Self::Relay { path: format!("/v1/providers/{}/environments/{}/relay", segment(provider), segment(id)) }
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    /// Server only: an exposure was set or removed, or its `ready` changed.
    /// Live only: a replay from `since` does not repeat it, so read the
    /// exposure routes for the current state.
    Exposure {
        direction: Direction,
        name: String,
        ready: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<ExposureError>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        removed: bool,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credits_remaining: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credit_unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency_in_use: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    /// A refusal of the image itself, or of how it was to reach the provider.
    ImageRefused {
        reason: String,
        refusal: ImageRefusal,
    },
    Unavailable {
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after: Option<u64>,
        /// Bounded provider/transport detail, masked for credentials by the host.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        // Plain text has no type-level redaction: host boundaries must apply
        // DiagnosticMasker before serializing or logging provider explanations.
        provider_error: Option<String>,
    },
    RateLimited {
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
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
        /// Provider explanation, masked for credentials before leaving the host.
        // Plain text has no type-level redaction: host boundaries must apply
        // DiagnosticMasker before serializing or logging provider explanations.
        provider_error: String,
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
            Self::ImageRefused { .. } => "image_refused",
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
            Self::Refused { .. } | Self::ImageRefused { .. } => 422,
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

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Self::NotFound { reason }
            | Self::MethodNotAllowed { reason }
            | Self::Refused { reason }
            | Self::ImageRefused { reason, .. }
            | Self::Unavailable { reason, .. }
            | Self::RateLimited { reason, .. }
            | Self::QuotaExhausted { reason }
            | Self::CredentialRejected { reason }
            | Self::CommandFailed { reason, .. }
            | Self::Internal { reason, .. } => reason,
        };
        write!(f, "{}: {}", self.class(), diagnostic::LogText(reason))?;
        match self {
            Self::Internal { provider_error, .. } => write!(f, "; {}", diagnostic::LogText(provider_error)),
            Self::Unavailable { provider_error: Some(detail), .. } => write!(f, "; {}", diagnostic::LogText(detail)),
            _ => Ok(()),
        }
    }
}

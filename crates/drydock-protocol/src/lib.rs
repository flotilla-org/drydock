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
pub const PROTOCOL_VERSION: &str = "14";

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
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfiguration {
    pub module: String,
    /// Non-secret vendor-specific configuration only.
    #[serde(default)]
    pub settings: BTreeMap<String, serde_json::Value>,
    /// Server only: where the server gets this provider's credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<CredentialLocation>,
    /// Whether drydock owns the vendor account or shares it.
    #[serde(default, skip_serializing_if = "is_default")]
    pub ownership: Ownership,
    /// Server only: the guarantees drydockd adds for this instance where the
    /// module's operations do not give them by themselves ([`Semantics`]).
    #[serde(default, skip_serializing_if = "is_default")]
    pub semantics: SemanticOptions,
    /// Server only: the ways in this installation reads the vendor's events
    /// through, beside or instead of the module's defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<EventsConfiguration>,
}
/// How one instance hears about its environments. Without a relay drydockd
/// lists them at the module's interval; with one it reads the relay's stream
/// and lists every `poll_seconds` to fill gaps.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EventsConfiguration {
    /// The relay install the vendor's webhooks are delivered to, such as
    /// `https://relay.flotilla.work/i/lab`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// The install's source name for this vendor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The install's consumer token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<CredentialLocation>,
    /// Seconds between lists; 300 when a relay is configured, otherwise the
    /// module's own interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll_seconds: Option<u64>,
}
fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}
/// The vendor-side tag naming the drydock instance that made a resource, on
/// a shared account.
pub const OWNER_TAG: &str = "drydock.provider";
/// Who else uses the vendor account an instance works in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
    /// Others use the account too: what the instance makes carries
    /// [`OWNER_TAG`], and the instance lists, destroys, suspends and resumes
    /// only what does.
    #[default]
    SharedAccount,
    /// Drydock owns the whole account: nothing is tagged, filtered or refused.
    OwnedAccount,
}
/// What drydockd adds to a module's operations, for one instance. Each applies
/// only where the module's [`Semantics`] do not already give it; with both
/// off, a module's verbs are its own operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SemanticOptions {
    /// Provision and resume answer once drydockd observes the environment
    /// running, and suspend once it observes it stopped. drydockd waits on
    /// its own observation of the provider, so a wait can take up to one
    /// observation interval after the vendor got there. A provision whose
    /// wait fails has still made its environment, which `list` shows under
    /// the client's label.
    pub settle: bool,
    /// Resume of a running or starting environment succeeds without a vendor
    /// call, as does suspend of a stopped or stopping one when the module's
    /// resume token is the environment id; without `settle`, such a call can
    /// answer while the transition is still under way. Destroy of an absent
    /// environment, or one already being destroyed, succeeds.
    pub idempotent: bool,
    /// The longest provision, suspend or resume waits.
    pub wait_seconds: u64,
}
impl Default for SemanticOptions {
    fn default() -> Self {
        Self { settle: true, idempotent: true, wait_seconds: 120 }
    }
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
    /// The ways the vendor offers to hear about environments; absent when
    /// the provider's host did not declare them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ways_in: Option<Vec<WayIn>>,
}
/// Which optional operations exist.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Ports {
    pub exec: bool,
    pub suspend_resume: bool,
    pub export: bool,
    pub usage: bool,
    pub quota: bool,
    /// Writes a file into a guest: how drydock puts the agent in a vessel on
    /// [`BootstrapRoute::Upload`].
    #[serde(default)]
    pub files: bool,
    /// Mints push access to the provider's own registry, for the
    /// [`ImageRoute::ProviderPush`] route.
    #[serde(default)]
    pub push_access: bool,
}
/// One way a vendor offers to hear about its environments. The installation
/// chooses which drydockd uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "way", rename_all = "snake_case")]
pub enum WayIn {
    /// drydockd lists every environment, every `interval_ms`.
    Poll { interval_ms: u64 },
    /// The vendor posts these events to a receiver the installation runs;
    /// drydockd reads them from a relay and the module translates each.
    /// `registration` lists every way the vendor offers to register the
    /// webhook; drydockd registers none itself.
    Webhook { registration: Vec<WebhookRegistration>, events: Vec<String>, delivery: DeliveryGuarantee },
}
/// Where a webhook is registered with the vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebhookRegistration {
    /// By hand, in the vendor's dashboard.
    Dashboard,
    /// Through the vendor's API.
    Api,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryGuarantee {
    /// Each event arrives once or more.
    AtLeastOnce,
}
/// One delivery from the vendor, as drydockd received it, for the module to read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct VendorDelivery {
    /// The vendor's event name.
    pub event: String,
    pub delivery_id: String,
    /// When the receiver got the delivery.
    #[schema(format = DateTime)]
    pub received_at: Timestamp,
    /// The vendor's body, unchanged.
    #[schema(value_type = Object)]
    pub body: serde_json::Value,
}
/// What a delivery says of one environment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct VendorObservation {
    pub id: String,
    /// Absent when the delivery states no state drydock classes, such as a
    /// creation that gives only the vendor's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<Observation>,
    pub vendor: VendorState,
    /// When the vendor says the environment got there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(format = DateTime)]
    pub timestamp: Option<Timestamp>,
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
    /// The guest TCP port the provider's vessels are reached through, when
    /// they are; it needs `agent`. On the upload route drydock starts the
    /// agent listening on loopback there, with its token file at the fixed
    /// path `drydock::launch::AGENT_TCP_TOKEN_FILE`. The provider writes no
    /// bootstrap of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<u16>, minimum = 1, maximum = 65535)]
    pub agent_tcp_port: Option<std::num::NonZeroU16>,
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
    /// Vessels are processes on the host's own machine: the host's user and PID
    /// namespace, with nothing between a vessel and the host. The provider is
    /// not a sandbox, and nothing may treat it as one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub host_processes: bool,
    /// Provision of a label that names an environment returns it, concurrent
    /// provisions included: the module refuses a second sandbox for a label.
    /// Without it a label is only the client's name for what it made, and
    /// every provision may create an environment.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exclusive_label: bool,
    /// The ways, beyond the guest's own egress, that a vessel can reach a
    /// destination, preferred first. A client chooses among them per
    /// destination; the guest's own egress (public destinations, under the
    /// egress policy) stays described by `egress`.
    #[serde(default)]
    pub reach_ways: Vec<ReachWay>,
    /// What the module's operations guarantee by themselves.
    #[serde(default)]
    pub semantics: Semantics,
}
/// Nothing: no material, checkout, image route or optional port; open egress,
/// unfiltered; Bake bootstrap. Modules state what differs.
impl Default for Capabilities {
    fn default() -> Self {
        Self {
            material_modes: vec![],
            checkout_strategies: vec![],
            workspace_root: String::new(),
            suspend_resume: false,
            suspend_preserves_memory: None,
            export: false,
            egress: EgressCapability { routes: vec![EgressRoute::Open], model: EgressModel::unfiltered() },
            fallback_runner: false,
            bootstrap: BootstrapRoute::Bake,
            agent: false,
            agent_tcp_port: None,
            platforms: vec![],
            image_routes: vec![],
            usage: false,
            quota: false,
            host_filesystem: false,
            host_processes: false,
            exclusive_label: false,
            reach_ways: vec![],
            semantics: Semantics::default(),
        }
    }
}
/// What a module's operations guarantee by themselves. Each defaults to
/// false: no guarantee. A module states what its own operations do, and
/// drydockd adds what the instance's [`SemanticOptions`] ask for; the
/// declaration a client reads says what the operations guarantee with
/// drydockd's additions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default)]
pub struct Semantics {
    /// Provision and resume answer once the environment runs, suspend once it
    /// has stopped, and prepare once the prepared form can be used. Otherwise
    /// each answers when the request was accepted, and prepare answers
    /// unavailable while the form is being built.
    pub settles: bool,
    /// Suspend, resume or destroy of an environment already in that state (or
    /// gone) succeeds.
    pub idempotent: bool,
    /// List and destroy reach only what this instance made: the module checks
    /// its own ownership. Otherwise the module tags what it makes with
    /// [`OWNER_TAG`] on a shared account and reports the tags in
    /// [`VendorState`], and drydockd applies the instance's [`Ownership`].
    pub owner_scoped: bool,
    /// The resume token is the environment id and resume ignores it.
    pub token_is_id: bool,
}
/// One way, beyond the guest's own egress, that a vessel can reach a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReachWay {
    /// Drydock carries the connection from the vessel to drydockd's side
    /// under the destination's own name and port, as an outward exposure.
    /// Present when the module runs the agent.
    OutwardExposure,
    /// The vessel shares drydockd's host network, so a destination reachable
    /// from that host is reachable from the vessel.
    HostNetwork,
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
/// How a vessel's agent gets into it. On Upload a provider with the files and
/// exec ports has drydockd put the agent in each vessel and start it, after
/// provision and resume: its module starts none, so a caller that bypasses
/// drydockd gets a vessel without one. One without those ports places and
/// starts its own.
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
    /// The image goes into the provider's own registry first. With the
    /// push-access port drydockd copies it there with access the provider
    /// mints, and the module is handed that copy by digest.
    ProviderPush {
        protocol: PushProtocol,
        /// How long one minted push credential stays valid, when it expires.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credential_lifetime_seconds: Option<u64>,
        tools_layer: ToolsLayer,
        /// The largest image the provider takes (compressed bytes, a lower
        /// bound on its size); a larger one is refused before any upload.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_image_bytes: Option<u64>,
        /// The most bytes one upload request carries, when the registry or
        /// the link calls for other than drydockd's default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chunk_bytes: Option<u64>,
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
    /// None joins the image: it is the base alone, and drydock uploads the
    /// agent at launch ([`BootstrapRoute::Upload`]). An image staged for it is
    /// copied as it is.
    Upload,
}
/// Pull access to one registry. Hosts send it only to the registry that the
/// reference it accompanies names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct RegistryCredential {
    pub username: String,
    #[schema(value_type = String, format = Password)]
    pub secret: Secret,
}
/// Push access to a provider's own registry, minted for one prepare.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct PushAccess {
    /// `host/path`: images go under it, by digest.
    pub repository: String,
    pub credential: RegistryCredential,
    /// When the credential stops working, if it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
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
    /// The staging registry drydock copies the image into, so this provider
    /// can pull it, refused the copy. `registry` is its configured name, or
    /// the provider's for its own registry; the reason says why
    /// (authentication, permission, quota).
    StagingRefused { registry: String },
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct EgressCapability {
    /// How a guest's traffic can leave: not at all, through a proxy the client
    /// configures, or directly. Routes say nothing about filtering.
    pub routes: Vec<EgressRoute>,
    /// The policies the vendor filters that traffic with.
    pub model: EgressModel,
}
/// What a module states about its vendor's egress control, from the vendor's
/// documentation. A claim, never a verification: drydockd owns the verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct EgressModel {
    /// Policy shapes the module can apply. It refuses requests outside them.
    pub shapes: Vec<EgressShape>,
    /// Where the vendor applies a policy.
    pub enforced: EnforcementSite,
    /// Documented effects of a policy beyond what it requests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub side_effects: Vec<EgressSideEffect>,
    /// Whether the vendor can change the policy of a running sandbox.
    pub mutable_while_running: bool,
    /// Vendor documentation the declaration rests on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
}
impl EgressModel {
    /// No policy and nothing enforcing one: egress is the guest's own network.
    pub fn unfiltered() -> Self {
        Self {
            shapes: vec![EgressShape::Open],
            enforced: EnforcementSite::None,
            side_effects: vec![],
            mutable_while_running: false,
            sources: vec![],
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EgressShape {
    /// No policy: egress is unfiltered, as an `open` request asks.
    Open,
    DenyAll,
    /// Allow listed IP addresses or CIDRs.
    AllowAddresses,
    /// Allow listed domain names.
    AllowDomains,
    ExplicitProxy,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementSite {
    /// Nothing enforces a policy.
    None,
    /// The vendor's network or a proxy, beyond the reach of guest root.
    OutsideGuest,
    /// Inside the guest, where guest root can undo it.
    InsideGuest,
}
/// A documented effect of applying any of `shapes`. `opens` lists the
/// destinations it also allows, when the vendor names them; `note` says the rest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct EgressSideEffect {
    pub shapes: Vec<EgressShape>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub opens: Vec<Destination>,
    pub note: String,
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
/// Preparation is look-up-or-build at the provider. On Bake bootstrap, append
/// the tools image's files under /opt/drydock to the base, preserving its
/// entrypoint, command and init; on Upload, make the base alone available, and
/// drydock puts the agent in each vessel at launch. tools_digest is the
/// build-selected bootstrap agent OCI index reference. The agent it carries is
/// only a cache: the host always upgrades the vessel's agent to its own build
/// at the first hello, so a matching agent saves an upload and any other is
/// replaced. Build at the provider where possible, otherwise append its layer.
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
    /// What the vendor itself reports, beside the coarse `state`, from
    /// modules that report it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<VendorState>,
}
/// An environment in the vendor's own words.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct VendorState {
    /// The vendor's state name, as it gives it.
    pub state: String,
    /// The vendor's explanation of that state, when it gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The vendor-side tags, as read back; absent when they were not read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
}
impl Environment {
    /// The observation without its evidence fields, for comparing states.
    pub fn without_evidence(&self) -> Self {
        Self { egress_measured: false, egress_policy: None, timestamp: None, ..self.clone() }
    }
    /// Neither gone nor being destroyed. A vendor may keep listing an
    /// environment in either state for a while.
    pub fn live(&self) -> bool {
        !matches!(self.state, Observation::Gone { .. } | Observation::Transitioning { phase: TransitionPhase::Destroying })
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
    /// The agent's token-gated TCP listener behind a provider's HTTP edge:
    /// drydock opens `url` (`https://`, or `http://` to a loopback address)
    /// and asks for the agent's handshake at its path and query with `token`
    /// as the Bearer; the bytes after the agent's 101 are its socket's. A
    /// credential the edge wants rides in `url`'s query or in `headers`,
    /// neither of which drydock ever shows.
    Dial {
        url: String,
        /// The agent's TCP token.
        token: Secret,
        /// Headers of the edge's own, sent with the handshake, for an edge
        /// that takes its credential in one (E2B's
        /// `e2b-traffic-access-token`). They may not replace the handshake's
        /// own (`Host`, `Connection`, `Upgrade`, `Authorization`,
        /// `Sec-WebSocket-Key`, `Sec-WebSocket-Version`).
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        headers: BTreeMap<String, Secret>,
        /// When `url`'s credential stops working, when the vendor says;
        /// absent when it does not. drydock asks for a fresh reach for each
        /// connection.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schema(format = DateTime)]
        expires_at: Option<Timestamp>,
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
    /// `cause` is absent when the vendor does not say why.
    Stopped {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cause: Option<StopCause>,
    },
    /// `cause` is absent when the vendor does not say why.
    Gone {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cause: Option<GoneCause>,
    },
    Transitioning {
        phase: TransitionPhase,
    },
    Unknown {
        reason: UnknownReason,
    },
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
    /// The vendor's own state and reason for this transition, verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<VendorState>,
    /// How drydockd learnt of it. Absent on drydockd's own exposure events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<ObservedBy>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ObservedBy {
    pub way: ObservedWay,
    /// The vendor's delivery, for a webhook.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_id: Option<String>,
}
/// A `poll` or `reconstruction` event compares two lists: transitions
/// between them may be missed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObservedWay {
    Webhook,
    VendorLog,
    LongPoll,
    Poll,
    /// A list made because events may have been lost.
    Reconstruction,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    Created,
    /// The environment became running, or its granted size changed while
    /// running. The size is the vendor's, absent when it states none. A size
    /// first stated on a running row is not a change and emits nothing, so a
    /// consumer reads the current size from the row, not from this event.
    Running {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        granted_size: Option<Size>,
    },
    Stopped {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cause: Option<StopCause>,
    },
    /// Explicit pause transition, distinct from the more general stopped observation.
    Paused {
        cause: StopCause,
    },
    Resumed,
    Gone {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cause: Option<GoneCause>,
    },
    /// The vendor reports a state drydock classes as on the way to another,
    /// such as stopping or destroying. Only events from the vendor carry it.
    Transitioning {
        phase: TransitionPhase,
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
// Records are read one at a time off a stream; boxing the event buys nothing.
#[allow(clippy::large_enum_variant)]
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
/// The amount is the vendor's own number text, which may carry an exponent
/// (`1.5e-7`); it never passes through binary floating point.
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

/// Nonnegative decimal money, as a JSON number's text: digits, an optional
/// fraction and an optional exponent. Never NaN or a binary float.
fn decimal_amount<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let value = String::deserialize(d)?;
    let (mantissa, exponent) = value.split_once(['e', 'E']).unwrap_or((&value, "0"));
    let exponent = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
    if !valid_decimal(mantissa) || exponent.is_empty() || !exponent.bytes().all(|b| b.is_ascii_digit()) {
        return Err(serde::de::Error::custom("expected a nonnegative decimal number"));
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
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
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
/// Where the files port puts one file in a guest: an absolute, normal path
/// (parents are made, an existing file is replaced) and its read, write and
/// execute bits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(try_from = "validation::UncheckedGuestFile")]
pub struct GuestFile {
    #[schema(pattern = "^/")]
    pub path: String,
    #[schema(maximum = 511)]
    pub mode: u32,
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

    /// The same error, its reason saying what was being done: `"{doing}: {reason}"`.
    pub fn context(mut self, doing: &str) -> Self {
        let (Self::NotFound { reason }
        | Self::MethodNotAllowed { reason }
        | Self::Refused { reason }
        | Self::ImageRefused { reason, .. }
        | Self::Unavailable { reason, .. }
        | Self::RateLimited { reason, .. }
        | Self::QuotaExhausted { reason }
        | Self::CredentialRejected { reason }
        | Self::CommandFailed { reason, .. }
        | Self::Internal { reason, .. }) = &mut self;
        *reason = format!("{doing}: {reason}");
        self
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

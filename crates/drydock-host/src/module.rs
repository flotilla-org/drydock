//! Compiled Rust provider interface. Shared methods permit independent concurrent calls.
use crate::EventSink;
use async_trait::async_trait;
use drydock_protocol::*;
pub use rigging_http_client::HttpClient;
pub use rigging_stream::ByteStream;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
/// Errors are serialized to authenticated host clients, including snapshot readers.
/// The host masks configured credential values in reasons and provider diagnostics.
/// Credentials, tokens and reach recipes still use Secret fields.
pub type Result<T> = std::result::Result<T, ProtocolError>;
pub fn refused(reason: impl Into<String>) -> ProtocolError {
    ProtocolError::Refused { reason: reason.into() }
}
/// The platform a module prepares for. The host resolves it from the request
/// and the module's declared platforms before calling `prepare`.
pub fn prepare_platform(request: &PrepareRequest) -> Result<Platform> {
    request.platform.clone().ok_or_else(|| refused("prepare reached the module without a resolved platform"))
}
/// A requested platform, or the first declared one, provided it is declared.
pub fn resolve_platform(requested: Option<Platform>, declared: &[Platform]) -> Result<Platform> {
    let offered = || declared.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
    match requested {
        None => declared.first().cloned().ok_or_else(|| refused("provider declares no platforms it can run")),
        Some(platform) if declared.contains(&platform) => Ok(platform),
        Some(platform) if declared.is_empty() => Err(refused(format!("provider cannot run {platform}: it declares no platforms"))),
        Some(platform) => Err(refused(format!("provider cannot run {platform}; it offers {}", offered()))),
    }
}

/// Factories are transactional: do not spawn observers or publish before commit.
/// Poll modules are stateless translators; the host owns observation. Push modules
/// receive a post-commit run hook with credentials and shutdown. No module retries.
#[async_trait]
pub trait Module: Send + Sync {
    /// Modules override this when their minimum differs from one CPU/GiB.
    fn smallest_size(&self) -> Size {
        Size { cpus: 1.0, memory_bytes: 1 << 30, disk_bytes: 1 << 30 }
    }
    fn version(&self) -> &str;
    /// Cancelled when the host stops. Dropping the future must release uncommitted
    /// resources; factories must yield while waiting on external work.
    async fn configure(&self, config: &ProviderConfiguration, http: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>>;
}
#[derive(Clone)]
pub struct Credentials {
    pub mode: CredentialMode,
    pub value: Option<Secret>,
}
impl Credentials {
    pub fn new(mode: CredentialMode) -> Self {
        Self { mode, value: None }
    }
    pub fn token(&self) -> Option<&Secret> {
        match &self.mode {
            CredentialMode::Direct { .. } => self.value.as_ref(),
            CredentialMode::Proxied { placeholder_token, .. } => Some(placeholder_token),
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum ObservationMode {
    Poll { interval: Duration },
    Push,
}
/// Optional provider time travels separately from the environment wire representation.
#[derive(Clone, Debug)]
pub struct ObservedEnvironment {
    /// True only when this call measured the isolation claim; conversion from
    /// a bare Environment conservatively supplies no measurement evidence.
    pub egress_measured: bool,
    /// Opaque effective-policy identity, present on every cheap observation when supported.
    pub egress_policy: Option<String>,
    pub environment: Environment,
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
}
impl From<Environment> for ObservedEnvironment {
    fn from(environment: Environment) -> Self {
        Self { environment, timestamp: None, egress_measured: false, egress_policy: None }
    }
}
pub enum Provisioned {
    Created(ObservedEnvironment),
    Existing(ObservedEnvironment),
}
pub enum Connection {
    /// `reverse_forwards`: whether the SSH server accepts remote Unix-socket forwards.
    Ssh {
        endpoint: String,
        user: Secret,
        host_key: String,
        reverse_forwards: bool,
    },
    Dial {
        url: String,
        token: Secret,
        expires_at: Timestamp,
    },
    Relay,
}

/// Context for a push observer, handed to run only after configuration commits.
/// Observe credential changes in memory, and release resources before returning on stop.
pub struct PushContext {
    pub events: EventSink,
    pub credentials: tokio::sync::watch::Receiver<Credentials>,
    pub stopping: tokio::sync::watch::Receiver<bool>,
}
/// No host-side provider lock. Implementations own any internal synchronization.
/// Capability declarations are stable. The host gates optional calls in one place;
/// optional ports are stable for the configured lifetime. Omit unsupported ports.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Lifetime of a push observer. Poll providers never receive this hook.
    async fn run(&self, mut context: PushContext) -> Result<()> {
        if !*context.stopping.borrow() {
            let _ = context.stopping.changed().await;
        }
        Ok(())
    }
    fn operations(&self) -> Operations<'_> {
        Operations::default()
    }
    fn capabilities(&self) -> Capabilities;
    fn observation(&self) -> ObservationMode;
    fn readiness(&self, c: &Credentials) -> Readiness {
        if c.token().is_some() { Readiness::Ready } else { Readiness::MissingCredential { reason: "credential not delivered".into() } }
    }
    fn rate_limits(&self) -> Vec<RateLimit> {
        vec![]
    }
    /// Append this build's tools image under /opt/drydock, preserving the base's
    /// entrypoint, command and init. Record the provider's prepared form using
    /// the module's key (both digests, the platform and provider prepare-time
    /// constraints). The request's platform is resolved and declared; build for
    /// it (see [`prepare_platform`]) and return it in the prepared form.
    /// Upload bootstrap installs the same files at the same paths instead.
    /// See ci/tools-image/README.md for the full prepare/start outcome contract.
    async fn prepare(&self, request: PrepareRequest, c: &Credentials) -> Result<Prepared>;
    async fn provision(&self, request: ProvisionRequest, c: &Credentials) -> Result<Provisioned>;
    /// Running observations must include granted_size to emit a billing Running
    /// event, whose protocol payload requires that size. Without it, inventory is
    /// still visible but no billable Running transition can be inferred.
    async fn list(&self, c: &Credentials) -> Result<Vec<ObservedEnvironment>>;
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<ObservedEnvironment>;
    /// The safe lifecycle default reads inventory without attempting guest probes.
    /// Modules may override to enrich a cheap observation, retaining that observation
    /// if enrichment fails. Inventory failures and absence still propagate.
    async fn inspect_after_lifecycle(&self, id: &str, c: &Credentials) -> Result<ObservedEnvironment> {
        self.list(c)
            .await?
            .into_iter()
            .find(|row| row.environment.id == id)
            .ok_or_else(|| ProtocolError::NotFound { reason: "environment absent after lifecycle".into() })
    }
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()>;
    async fn reach(&self, id: &str, c: &Credentials) -> Result<Connection>;
    async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream>;
}
pub type Registry = BTreeMap<String, Arc<dyn Module>>;

/// Borrowed optional ports; calls retain shared-reference concurrency.
#[derive(Default)]
pub struct Operations<'a> {
    pub exec: Option<&'a dyn Exec>,
    pub suspend_resume: Option<&'a dyn SuspendResume>,
    pub export: Option<&'a dyn ExportOperation>,
    pub usage: Option<&'a dyn UsageOperation>,
    pub quota: Option<&'a dyn QuotaOperation>,
}
#[async_trait]
pub trait Exec: Send + Sync {
    async fn exec(&self, id: &str, request: ExecRequest, c: &Credentials) -> Result<ByteStream>;
}
#[async_trait]
pub trait SuspendResume: Send + Sync {
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken>;
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()>;
}
#[async_trait]
pub trait ExportOperation: Send + Sync {
    async fn export(&self, id: &str, c: &Credentials) -> Result<Export>;
}
#[async_trait]
pub trait UsageOperation: Send + Sync {
    async fn usage(&self, period: Period, c: &Credentials) -> Result<Usage>;
}
#[async_trait]
pub trait QuotaOperation: Send + Sync {
    async fn quota(&self, c: &Credentials) -> Result<Quota>;
}

#[cfg(test)]
mod tests {
    use super::*;
    // Omitted means the first declared platform; anything undeclared is refused
    // naming what the provider offers.
    #[test]
    fn platform_resolution() {
        let amd = Platform::new("linux", "amd64");
        let arm = Platform::new("linux", "arm64");
        let declared = [arm.clone(), amd.clone()];
        assert_eq!(resolve_platform(None, &declared).unwrap(), arm);
        assert_eq!(resolve_platform(Some(amd.clone()), &declared).unwrap(), amd);
        let reason = |e: ProtocolError| match e {
            ProtocolError::Refused { reason } => reason,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            reason(resolve_platform(Some(Platform::new("linux", "s390x")), &declared).unwrap_err()),
            "provider cannot run linux/s390x; it offers linux/arm64, linux/amd64"
        );
        assert_eq!(reason(resolve_platform(None, &[]).unwrap_err()), "provider declares no platforms it can run");
        assert_eq!(reason(resolve_platform(Some(amd), &[]).unwrap_err()), "provider cannot run linux/amd64: it declares no platforms");
        assert!(
            prepare_platform(&PrepareRequest {
                platform: None,
                size: Size { cpus: 1.0, memory_bytes: 1, disk_bytes: 1 },
                image_digest: "i".into(),
                tools_digest: "t".into()
            })
            .is_err()
        );
    }
}

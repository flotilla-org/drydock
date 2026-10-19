//! Compiled Rust provider interface. Shared methods permit independent concurrent calls.
use crate::EventSink;
use async_trait::async_trait;
use drydock_protocol::*;
pub use rigging_http_client::HttpClient;
pub use rigging_stream::ByteStream;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
pub type Result<T> = std::result::Result<T, ProtocolError>;
pub fn refused(reason: impl Into<String>) -> ProtocolError {
    ProtocolError::Refused { reason: reason.into() }
}

/// Factories are transactional: do not spawn observers or publish before commit.
/// Poll modules are stateless translators; the host owns observation. Push modules
/// receive a post-commit run hook with credentials and shutdown. No module retries.
#[async_trait]
pub trait Module: Send + Sync {
    fn version(&self) -> &str;
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
    pub environment: Environment,
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
}
impl From<Environment> for ObservedEnvironment {
    fn from(environment: Environment) -> Self {
        Self { environment, timestamp: None }
    }
}
pub enum Provisioned {
    Created(Environment),
    Existing(Environment),
}
pub enum Connection {
    Ssh { endpoint: String, user: String, host_key: String },
    Dial { url: String, token: Secret, expires_at: Timestamp },
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
/// implement every method explicitly, even when a capability is disabled.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Lifetime of a push observer. Poll providers never receive this hook.
    async fn run(&self, mut context: PushContext) -> Result<()> {
        if !*context.stopping.borrow() {
            let _ = context.stopping.changed().await;
        }
        Ok(())
    }
    fn capabilities(&self) -> Capabilities;
    fn observation(&self) -> ObservationMode;
    fn readiness(&self, c: &Credentials) -> Readiness {
        if c.token().is_some() { Readiness::Ready } else { Readiness::MissingCredential { reason: "credential not delivered".into() } }
    }
    fn rate_limits(&self) -> Vec<RateLimit> {
        vec![]
    }
    async fn prepare(&self, request: PrepareRequest, c: &Credentials) -> Result<Prepared>;
    async fn provision(&self, request: ProvisionRequest, c: &Credentials) -> Result<Provisioned>;
    /// Running observations must include granted_size to emit a billing Running
    /// event, whose protocol payload requires that size. Without it, inventory is
    /// still visible but no billable Running transition can be inferred.
    async fn list(&self, c: &Credentials) -> Result<Vec<ObservedEnvironment>>;
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<ObservedEnvironment>;
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()>;
    async fn reach(&self, id: &str, c: &Credentials) -> Result<Connection>;
    async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream>;
    async fn exec(&self, id: &str, request: ExecRequest, c: &Credentials) -> Result<ByteStream>;
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken>;
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()>;
    async fn export(&self, id: &str, c: &Credentials) -> Result<Export>;
    async fn usage(&self, period: Period, c: &Credentials) -> Result<Usage>;
    async fn quota(&self, c: &Credentials) -> Result<Quota>;
}
pub type Registry = BTreeMap<String, Arc<dyn Module>>;

//! Private REST client implementing the policy-free provider traits.
use super::module::*;
use crate::client::{Client, Error};
use async_trait::async_trait;
use drydock_protocol::*;
use std::sync::Arc;
// Keep the cause. A failed mutating call (`Gate::mutates`) uses `mutation`: its
// outcome is unknown. A malformed reply is a host defect, not an outage.
fn error(e: Error) -> ProtocolError {
    bridge(e, "provider host unavailable")
}
fn mutation(e: Error) -> ProtocolError {
    bridge(e, "provider host unavailable; operation outcome may be unknown")
}
fn bridge(e: Error, unavailable: &str) -> ProtocolError {
    match e {
        Error::Protocol(e) => e,
        Error::InvalidResponse(_) | Error::InvalidRequest(_) => {
            ProtocolError::Internal { reason: "provider host bridge failed".into(), provider_error: e.to_string() }
        }
        e => ProtocolError::Unavailable { reason: unavailable.into(), retry_after: None, provider_error: Some(e.to_string()) },
    }
}
struct RemoteModule {
    client: Client,
    module: LoadableModule,
}
pub fn registry(client: Client, hello: &Hello) -> Registry {
    hello
        .loadable_modules
        .iter()
        .map(|m| (m.name.clone(), Arc::new(RemoteModule { client: client.clone(), module: m.clone() }) as Arc<dyn Module>))
        .collect()
}
#[async_trait]
impl Module for RemoteModule {
    fn version(&self) -> &str {
        &self.module.version
    }
    fn smallest_size(&self) -> Size {
        self.module.smallest_size.clone()
    }
    async fn configure(&self, c: &ProviderConfiguration, _http: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
        let configured = self.client.configure_provider(&self.module.name, c).await.map_err(error)?;
        let facts = configured.facts;
        Ok(Arc::new(RemoteProvider {
            client: self.client.clone(),
            name: configured.instance,
            readiness: std::sync::Mutex::new(facts.readiness.clone()),
            facts,
        }))
    }
}
struct RemoteProvider {
    client: Client,
    name: String,
    facts: Facts,
    readiness: std::sync::Mutex<Readiness>,
}
impl Drop for RemoteProvider {
    fn drop(&mut self) {
        let client = self.client.clone();
        let instance = self.name.clone();
        // Releasing a loader handle is not a provider operation and never
        // destroys vendor resources. Unique handles make rollback race-free.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = client.release_provider(&instance).await;
            });
        } else {
            tracing::debug!("provider handle release skipped: no Tokio runtime");
        }
    }
}
#[async_trait]
impl Provider for RemoteProvider {
    fn capabilities(&self) -> Capabilities {
        self.facts.capabilities.clone()
    }
    fn observation(&self) -> ObservationMode {
        self.facts.observation
    }
    fn rate_limits(&self) -> Vec<RateLimit> {
        self.facts.rate_limits.clone()
    }
    fn readiness(&self, c: &Credentials) -> Readiness {
        let readiness = self.readiness.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        if !matches!(readiness, Readiness::Ready | Readiness::MissingCredential { .. }) {
            return readiness;
        }
        if c.token().is_some() { Readiness::Ready } else { Readiness::MissingCredential { reason: "credential not delivered".into() } }
    }
    async fn refresh_readiness(&self, c: &Credentials) {
        let readiness = match self.client.provider_call::<Facts, _>(&self.name, "facts", (), c).await {
            Ok(facts) => facts.readiness,
            Err(e) => Readiness::Unknown { reason: format!("provider host unavailable: {e}") },
        };
        *self.readiness.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = readiness;
    }
    fn operations(&self) -> Operations<'_> {
        let c = &self.facts.ports;
        Operations {
            exec: c.exec.then_some(self),
            suspend_resume: c.suspend_resume.then_some(self),
            export: c.export.then_some(self),
            usage: c.usage.then_some(self),
            quota: c.quota.then_some(self),
        }
    }
    async fn run(&self, context: PushContext) -> Result<()> {
        self.client.provider_updates(&self.name, &context.credentials, context.events).await.map_err(error)
    }
    async fn prepare(&self, request: PrepareRequest, c: &Credentials) -> Result<Prepared> {
        self.client.provider_call(&self.name, "prepare", request, c).await.map_err(mutation)
    }
    async fn provision(&self, request: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        self.client.provider_call(&self.name, "provision", request, c).await.map_err(mutation)
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<ObservedEnvironment>> {
        self.client.provider_call(&self.name, "list", (), c).await.map_err(error)
    }
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<ObservedEnvironment> {
        self.client.provider_call(&self.name, "inspect", id, c).await.map_err(error)
    }
    async fn inspect_after_lifecycle(&self, id: &str, c: &Credentials) -> Result<ObservedEnvironment> {
        self.client.provider_call(&self.name, "inspect-after-lifecycle", id, c).await.map_err(error)
    }
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        self.client.provider_call(&self.name, "destroy", id, c).await.map_err(mutation)
    }
    async fn reach(&self, id: &str, c: &Credentials) -> Result<Connection> {
        self.client.provider_call(&self.name, "reach", id, c).await.map_err(error)
    }
    async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream> {
        self.client.provider_stream(&self.name, "relay", id, c, "drydock-relay").await.map_err(error)
    }
}
#[async_trait]
impl Exec for RemoteProvider {
    async fn exec(&self, id: &str, request: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        self.client.provider_stream(&self.name, "exec", (id, request), c, "drydock-stream").await.map_err(mutation)
    }
}
#[async_trait]
impl SuspendResume for RemoteProvider {
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        self.client.provider_call(&self.name, "suspend", id, c).await.map_err(mutation)
    }
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()> {
        self.client.provider_call(&self.name, "resume", (id, token), c).await.map_err(mutation)
    }
}
#[async_trait]
impl ExportOperation for RemoteProvider {
    async fn export(&self, id: &str, c: &Credentials) -> Result<Export> {
        self.client.provider_call(&self.name, "export", id, c).await.map_err(mutation)
    }
}
#[async_trait]
impl UsageOperation for RemoteProvider {
    async fn usage(&self, period: Period, c: &Credentials) -> Result<Usage> {
        self.client.provider_call(&self.name, "usage", period, c).await.map_err(error)
    }
}
#[async_trait]
impl QuotaOperation for RemoteProvider {
    async fn quota(&self, c: &Credentials) -> Result<Quota> {
        self.client.provider_call(&self.name, "quota", (), c).await.map_err(error)
    }
}

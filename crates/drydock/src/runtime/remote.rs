//! Provider traits over a host's public API: the routes a client would use
//! against the server, each call carrying its credential as `Drydock-Credential`.
use super::module::*;
use crate::{
    api::ProviderApi,
    client::{Client, Error},
};
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
/// The host's modules. Configuring one configures the host's provider of that
/// name, without the server-only credential key.
pub fn registry(client: Client, hello: &Hello) -> Registry {
    // The runtime owns each call's deadline; the host transport adds none.
    let client = client.with_request_timeout(std::time::Duration::MAX);
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
    async fn configure(&self, name: &str, config: &ProviderConfiguration, _http: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
        let config = ProviderConfiguration { credential: None, ..config.clone() };
        let patch = serde_json::json!({ "providers": { name: config } });
        self.client.configure(crate::api::ConfigUpdate::MergePatch(patch)).await.map_err(error)?;
        let declaration = self.client.provider(name).await.map_err(error)?;
        Ok(Arc::new(RemoteProvider {
            client: self.client.clone(),
            readiness: std::sync::Mutex::new(declaration.readiness.clone()),
            declaration,
        }))
    }
}
struct RemoteProvider {
    client: Client,
    declaration: ProviderDeclaration,
    readiness: std::sync::Mutex<Readiness>,
}
impl RemoteProvider {
    fn host(&self, c: &Credentials) -> Client {
        self.client.clone().credentialed(c.token().cloned())
    }
    fn name(&self) -> &str {
        &self.declaration.provider
    }
}
#[async_trait]
impl Provider for RemoteProvider {
    fn capabilities(&self) -> Capabilities {
        self.declaration.capabilities.clone()
    }
    fn observation(&self) -> ObservationMode {
        self.declaration.observation
    }
    fn rate_limits(&self) -> Vec<RateLimit> {
        self.declaration.rate_limits.clone()
    }
    fn readiness(&self, c: &Credentials) -> Readiness {
        let readiness = self.readiness.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        if !matches!(readiness, Readiness::Ready | Readiness::MissingCredential { .. }) {
            return readiness;
        }
        // A host that reports a provider ready without having been given a credential
        // is one that needs none. Modules that need one must report MissingCredential until
        // it arrives, as the trait's default does; the mixed-config test in tests/local.rs pins that.
        if c.token().is_some() || matches!(readiness, Readiness::Ready) {
            Readiness::Ready
        } else {
            Readiness::MissingCredential { reason: "credential not delivered".into() }
        }
    }
    async fn refresh_readiness(&self, c: &Credentials) {
        let readiness = match self.host(c).provider(self.name()).await {
            Ok(declaration) => declaration.readiness,
            Err(e) => Readiness::Unknown { reason: format!("provider host unavailable: {e}") },
        };
        *self.readiness.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = readiness;
    }
    fn operations(&self) -> Operations<'_> {
        let ports = &self.declaration.ports;
        Operations {
            exec: ports.exec.then_some(self),
            suspend_resume: ports.suspend_resume.then_some(self),
            export: ports.export.then_some(self),
            usage: ports.usage.then_some(self),
            quota: ports.quota.then_some(self),
        }
    }
    async fn prepare(&self, request: PrepareRequest, c: &Credentials) -> Result<Prepared> {
        self.host(c).prepare(self.name(), &request).await.map_err(mutation)
    }
    async fn provision(&self, request: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        self.host(c).provision(self.name(), &request).await.map_err(mutation)
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        self.host(c).list(self.name()).await.map_err(error)
    }
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        self.host(c).inspect(self.name(), id).await.map_err(error)
    }
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        self.host(c).destroy(self.name(), id).await.map_err(mutation)
    }
    async fn reach(&self, id: &str, c: &Credentials) -> Result<Reach> {
        self.host(c).reach(self.name(), id).await.map_err(error)
    }
    async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream> {
        self.host(c).relay(self.name(), id).await.map_err(error)
    }
}
#[async_trait]
impl Exec for RemoteProvider {
    async fn exec(&self, id: &str, request: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        self.host(c).exec(self.name(), id, &request).await.map_err(mutation)
    }
}
#[async_trait]
impl SuspendResume for RemoteProvider {
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        self.host(c).suspend(self.name(), id).await.map_err(mutation)
    }
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()> {
        self.host(c).resume(self.name(), id, &token).await.map_err(mutation)
    }
}
#[async_trait]
impl ExportOperation for RemoteProvider {
    async fn export(&self, id: &str, c: &Credentials) -> Result<Export> {
        self.host(c).export(self.name(), id).await.map_err(mutation)
    }
}
#[async_trait]
impl UsageOperation for RemoteProvider {
    async fn usage(&self, period: Period, c: &Credentials) -> Result<Usage> {
        self.host(c).usage(self.name(), &period).await.map_err(error)
    }
}
#[async_trait]
impl QuotaOperation for RemoteProvider {
    async fn quota(&self, c: &Credentials) -> Result<Quota> {
        self.host(c).quota(self.name()).await.map_err(error)
    }
}

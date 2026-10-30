//! Thin Rust module loader serving the public API. Common policy lives in drydock::runtime.
pub mod daytona;
pub use drydock_provider as module;
pub mod local;
pub mod oci;
pub mod reference;
use axum::{
    Router,
    extract::Request,
    http::{StatusCode, header},
    middleware::{self, Next},
    response::IntoResponse,
};
use drydock_client::{
    Error,
    api::{ConfigUpdate, ProviderApi, router},
};
use drydock_protocol::*;
use module::*;

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{RwLock, watch};
trait RecoverLock<T> {
    fn recover(&self) -> std::sync::MutexGuard<'_, T>;
}
impl<T> RecoverLock<T> for Mutex<T> {
    fn recover(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
struct Binding {
    config: ProviderConfiguration,
    provider: Arc<dyn Provider>,
}
/// Loads modules and serves their providers through the public API. Every call
/// uses only the credential its request carries; the host holds none.
#[derive(Clone)]
pub struct Host {
    registry: Arc<Registry>,
    bindings: Arc<RwLock<BTreeMap<String, Binding>>>,
    configuring: Arc<tokio::sync::Mutex<()>>,
    stopping: watch::Sender<bool>,
    credentials: Credentials,
}
impl Host {
    pub fn new(registry: Registry) -> Self {
        Self {
            registry: Arc::new(registry),
            bindings: Arc::default(),
            configuring: Arc::default(),
            stopping: watch::channel(false).0,
            credentials: Credentials::default(),
        }
    }
    async fn instance(&self, name: &str) -> Result<Arc<dyn Provider>> {
        let bindings = self.bindings.read().await;
        bindings.get(name).map(|b| b.provider.clone()).ok_or_else(|| ProtocolError::NotFound { reason: "unknown provider".into() })
    }
    /// Declarations refresh readiness, which can be a provider network call, so
    /// they never run under the bindings lock.
    async fn declaration(&self, name: String, module: String, p: Arc<dyn Provider>) -> ProviderDeclaration {
        p.refresh_readiness(&self.credentials).await;
        ProviderDeclaration {
            provider: name,
            module,
            capabilities: p.capabilities(),
            readiness: p.readiness(&self.credentials),
            rate_limits: p.rate_limits(),
            ports: p.operations().into(),
            observation: p.observation(),
        }
    }
    async fn bindings(&self) -> Vec<(String, String, Arc<dyn Provider>)> {
        let bindings = self.bindings.read().await;
        bindings.iter().map(|(name, b)| (name.clone(), b.config.module.clone(), b.provider.clone())).collect()
    }

    pub fn router(&self) -> Router {
        router(Arc::new(self.clone()), self.stopping.subscribe())
    }
    /// The supervisor owns the private 0700 directory; the socket is 0600.
    pub async fn serve_unix<F: std::future::Future<Output = ()> + Send + 'static>(
        &self,
        path: impl AsRef<std::path::Path>,
        shutdown: F,
    ) -> std::io::Result<()> {
        use rigging_http_serve::{Caller, UnixServer};
        let stopping = self.stopping.clone();
        UnixServer::bind(path, 0o600)
            .await?
            .serve(self.router(), Caller::<()>::Unix, async move {
                shutdown.await;
                stopping.send_replace(true);
            })
            .await
    }
    pub async fn serve_tcp<F: std::future::Future<Output = ()> + Send + 'static>(
        &self,
        address: std::net::SocketAddr,
        token_file: impl AsRef<std::path::Path>,
        shutdown: F,
    ) -> std::io::Result<()> {
        let server = rigging_http_serve::TcpServer::bind(address, token_file).await?;
        self.serve_bound_tcp(server, shutdown).await
    }
    /// Serve an already-bound Rigging listener, e.g. to discover a port-0 address
    /// without dropping and racing to rebind the port. Authentication stays shared.
    pub async fn serve_bound_tcp<F: std::future::Future<Output = ()> + Send + 'static>(
        &self,
        server: rigging_http_serve::TcpServer,
        shutdown: F,
    ) -> std::io::Result<()> {
        // The host protocol specifies bearer auth, so disallow rigging's optional cookie mode.
        let router = self.router().layer(middleware::from_fn(|req: Request, next: Next| async move {
            if req.headers().contains_key(header::AUTHORIZATION) { next.run(req).await } else { StatusCode::UNAUTHORIZED.into_response() }
        }));
        let stopping = self.stopping.clone();
        server
            .serve::<(), _>(router, async move {
                shutdown.await;
                stopping.send_replace(true);
            })
            .await
    }
}
fn port<T: ?Sized>(port: Option<&T>) -> Result<&T> {
    port.ok_or_else(|| refused("operation port unavailable"))
}
#[async_trait::async_trait]
impl ProviderApi for Host {
    async fn hello(&self) -> ApiResult<Hello> {
        Ok(Hello {
            protocol_version: PROTOCOL_VERSION.into(),
            host_version: env!("CARGO_PKG_VERSION").into(),
            loadable_modules: self
                .registry
                .iter()
                .map(|(name, m)| LoadableModule { name: name.clone(), version: m.version().into(), smallest_size: m.smallest_size() })
                .collect(),
        })
    }
    /// Unchanged entries keep their provider, and with it any in-memory state.
    /// The whole document is built before any of it applies.
    async fn configure(&self, update: ConfigUpdate) -> ApiResult<()> {
        let _guard = self.configuring.lock().await;
        let current =
            Configuration { providers: self.bindings.read().await.iter().map(|(name, b)| (name.clone(), b.config.clone())).collect() };
        let document = update.apply(&current)?;
        let mut bindings = BTreeMap::new();
        for (name, config) in document.providers {
            if config.credential.is_some() {
                return Err(refused("credential is a server-only configuration key").into());
            }
            let existing = self.bindings.read().await.get(&name).filter(|b| b.config == config).map(|b| b.provider.clone());
            let provider = match existing {
                Some(provider) => provider,
                None => {
                    let module = self.registry.get(&config.module).ok_or_else(|| refused("unknown module"))?;
                    let http = rigging_http_client::ReqwestHttpClient::restricted(None, None)
                        .map_err(|error| refused(format!("invalid HTTP transport configuration: {error}")))?;
                    module.configure(&name, &config, Arc::new(http)).await?
                }
            };
            bindings.insert(name, Binding { config, provider });
        }
        *self.bindings.write().await = bindings;
        Ok(())
    }
    async fn providers(&self) -> ApiResult<Vec<ProviderDeclaration>> {
        let bindings = self.bindings().await;
        Ok(futures::future::join_all(bindings.into_iter().map(|(name, module, p)| self.declaration(name, module, p))).await)
    }
    async fn provider(&self, p: &str) -> ApiResult<ProviderDeclaration> {
        let binding = self.bindings().await.into_iter().find(|(name, ..)| name == p);
        let (name, module, provider) = binding.ok_or_else(|| ProtocolError::NotFound { reason: "unknown provider".into() })?;
        Ok(self.declaration(name, module, provider).await)
    }
    async fn prepare(&self, p: &str, r: &PrepareRequest) -> ApiResult<Prepared> {
        Ok(prepare_for_platform(&*self.instance(p).await?, r.clone(), &self.credentials).await?)
    }
    async fn provision(&self, p: &str, r: &ProvisionRequest) -> ApiResult<Provisioned<Environment>> {
        Ok(self.instance(p).await?.provision(r.clone(), &self.credentials).await?)
    }
    async fn list(&self, p: &str) -> ApiResult<Vec<Environment>> {
        Ok(self.instance(p).await?.list(&self.credentials).await?)
    }
    async fn inspect(&self, p: &str, id: &str) -> ApiResult<Environment> {
        Ok(self.instance(p).await?.inspect(id, &self.credentials).await?)
    }
    async fn destroy(&self, p: &str, id: &str) -> ApiResult<()> {
        Ok(self.instance(p).await?.destroy(id, &self.credentials).await?)
    }
    async fn reach(&self, p: &str, id: &str) -> ApiResult<Reach> {
        Ok(self.instance(p).await?.reach(id, &self.credentials).await?)
    }
    async fn suspend(&self, p: &str, id: &str) -> ApiResult<ResumeToken> {
        let provider = self.instance(p).await?;
        Ok(port(provider.operations().suspend_resume)?.suspend(id, &self.credentials).await?)
    }
    async fn resume(&self, p: &str, id: &str, token: &ResumeToken) -> ApiResult<()> {
        let provider = self.instance(p).await?;
        Ok(port(provider.operations().suspend_resume)?.resume(id, token.clone(), &self.credentials).await?)
    }
    async fn export(&self, p: &str, id: &str) -> ApiResult<Export> {
        let provider = self.instance(p).await?;
        Ok(port(provider.operations().export)?.export(id, &self.credentials).await?)
    }
    async fn quota(&self, p: &str) -> ApiResult<Quota> {
        let provider = self.instance(p).await?;
        Ok(port(provider.operations().quota)?.quota(&self.credentials).await?)
    }
    async fn usage(&self, p: &str, period: &Period) -> ApiResult<Usage> {
        let provider = self.instance(p).await?;
        Ok(port(provider.operations().usage)?.usage(period.clone(), &self.credentials).await?)
    }
    async fn relay(&self, p: &str, id: &str) -> ApiResult<ByteStream> {
        Ok(self.instance(p).await?.relay(id, &self.credentials).await?)
    }
    async fn exec(&self, p: &str, id: &str, command: &ExecRequest) -> ApiResult<ByteStream> {
        let provider = self.instance(p).await?;
        Ok(port(provider.operations().exec)?.exec(id, command.clone(), &self.credentials).await?)
    }
    fn with_credential(&self, credential: Secret) -> Arc<dyn ProviderApi> {
        Arc::new(Self { credentials: Credentials::new(Some(credential)), ..self.clone() })
    }
}
type ApiResult<T> = std::result::Result<T, Error>;

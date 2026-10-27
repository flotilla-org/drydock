//! Thin Rust module loader and private REST adapter. Common policy lives in drydock::runtime.
pub mod daytona;
pub use drydock_provider as module;
pub mod oci;
pub mod reference;
use axum::{
    Json, Router,
    body::Body,
    extract::{FromRequest, FromRequestParts, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use drydock_protocol::*;
use module::{
    rest::{ApiJson, ApiPath, Refusal, switch, upgrade},
    *,
};

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
#[derive(Default)]
struct Configuration {
    modules: Vec<LoadedModule>,
    bindings: BTreeMap<String, Binding>,
    handles: BTreeMap<String, Arc<dyn Provider>>,
}
struct Binding {
    entrypoint: String,
    config: ProviderConfiguration,
    provider: Arc<dyn Provider>,
}
#[derive(Clone)]
pub struct Host {
    registry: Arc<Registry>,
    config: Arc<RwLock<Configuration>>,
    configuring: Arc<tokio::sync::Mutex<()>>,
    proxy_ca: Option<Arc<Vec<u8>>>,
    stopping: watch::Sender<bool>,
    serial: Arc<std::sync::atomic::AtomicU64>,
    epoch: Arc<str>,
}
impl Host {
    pub fn new(registry: Registry) -> Self {
        Self {
            registry: Arc::new(registry),
            config: Arc::default(),
            configuring: Arc::default(),
            proxy_ca: None,
            stopping: watch::channel(false).0,
            serial: Arc::default(),
            epoch: format!("{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().expect("current timestamp")).into(),
        }
    }
    pub fn with_proxy_ca(mut self, pem: Vec<u8>) -> Self {
        self.proxy_ca = Some(Arc::new(pem));
        self
    }
    async fn instance(&self, name: &str) -> Result<Arc<dyn Provider>> {
        let config = self.config.read().await;
        config.handles.get(name).cloned().ok_or_else(|| ProtocolError::NotFound { reason: "unknown provider handle".into() })
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/v1/hello", get(hello))
            .route("/private/modules/{module}/configure", post(configure_provider))
            .route("/private/providers/{provider}", axum::routing::delete(release_provider))
            .route("/private/providers/{provider}/facts", post(facts))
            .route("/private/providers/{provider}/prepare", post(prepare))
            .route("/private/providers/{provider}/provision", post(provision))
            .route("/private/providers/{provider}/list", post(list))
            .route("/private/providers/{provider}/inspect", post(inspect))
            .route("/private/providers/{provider}/inspect-after-lifecycle", post(inspect_after_lifecycle))
            .route("/private/providers/{provider}/destroy", post(destroy))
            .route("/private/providers/{provider}/reach", post(reach))
            .route("/private/providers/{provider}/suspend", post(suspend))
            .route("/private/providers/{provider}/resume", post(resume))
            .route("/private/providers/{provider}/export", post(export))
            .route("/private/providers/{provider}/usage", post(usage))
            .route("/private/providers/{provider}/quota", post(quota))
            .route("/private/providers/{provider}/relay", post(relay))
            .route("/private/providers/{provider}/exec", post(exec))
            .route("/private/providers/{provider}/subscribe", post(subscribe))
            .with_state(self.clone())
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
type ApiResult<T> = std::result::Result<T, Refusal>;
async fn hello(State(h): State<Host>) -> Json<BridgeHello> {
    let c = h.config.read().await;
    Json(BridgeHello {
        incarnation: Some(h.epoch.to_string()),
        hello: Hello {
            protocol_version: PROTOCOL_VERSION.into(),
            host_version: env!("CARGO_PKG_VERSION").into(),
            modules: c.modules.clone(),
            loadable_modules: h
                .registry
                .iter()
                .map(|(name, m)| LoadableModule { name: name.clone(), version: m.version().into(), smallest_size: m.smallest_size() })
                .collect(),
            providers: c
                .bindings
                .values()
                .map(|binding| {
                    let config = &binding.config;
                    let p = &binding.provider;
                    ProviderDeclaration {
                        provider: config.name.clone(),
                        module: config.module.clone(),
                        capabilities: p.capabilities(),
                        rate_limits: p.rate_limits(),
                        readiness: p.readiness(&Credentials::new(config.credential.clone())),
                    }
                })
                .collect(),
        },
    })
}
fn operation_port<T: ?Sized>(port: Option<&T>) -> Result<&T> {
    port.ok_or_else(|| refused("operation port unavailable"))
}
fn provider_facts(p: &dyn Provider, c: &Credentials) -> Facts {
    Facts {
        ports: p.operations().into(),
        capabilities: p.capabilities(),
        observation: p.observation(),
        rate_limits: p.rate_limits(),
        readiness: p.readiness(c),
    }
}
/// A configured provider handle with this call's credential snapshot and argument.
struct Bound<A> {
    provider: Arc<dyn Provider>,
    credentials: Credentials,
    argument: A,
}
impl<A: serde::de::DeserializeOwned + Send> FromRequest<Host> for Bound<A> {
    type Rejection = Refusal;
    async fn from_request(request: Request, host: &Host) -> ApiResult<Self> {
        let (mut parts, body) = request.into_parts();
        let ApiPath(name) = ApiPath::<String>::from_request_parts(&mut parts, host).await?;
        let ApiJson(call) = ApiJson::<Call<A>>::from_request(Request::from_parts(parts, body), host).await?;
        Ok(Self { provider: host.instance(&name).await?, credentials: call.credentials, argument: call.argument })
    }
}
async fn facts(b: Bound<()>) -> Json<Facts> {
    b.provider.refresh_readiness(&b.credentials).await;
    Json(provider_facts(&*b.provider, &b.credentials))
}
async fn configure_provider(
    State(h): State<Host>,
    ApiPath(entrypoint): ApiPath<String>,
    ApiJson(config): ApiJson<ProviderConfiguration>,
) -> ApiResult<Json<ConfiguredProvider>> {
    // Deliberately host-wide and held across the factory: reuse of an identical
    // binding is atomic. Configuration is rare; ordinary calls take no lock.
    let _guard = h.configuring.lock().await;
    let module = h.registry.get(&entrypoint).ok_or_else(|| refused("unknown module entrypoint"))?;
    let existing = h
        .config
        .read()
        .await
        .bindings
        .get(&config.name)
        .filter(|old| old.config == config && old.entrypoint == entrypoint)
        .map(|binding| binding.provider.clone());
    let provider = match existing {
        Some(provider) => provider,
        None => {
            let proxy = match &config.credential {
                CredentialMode::Proxied { proxy_url, .. } => Some(proxy_url.as_str()),
                _ => None,
            };
            let http = rigging_http_client::ReqwestHttpClient::restricted(proxy, h.proxy_ca.as_deref().map(Vec::as_slice))
                .map_err(|error| refused(format!("invalid HTTP transport configuration: {error}")))?;
            module.configure(&config, Arc::new(http)).await?
        }
    };
    let facts = provider_facts(&*provider, &Credentials::new(config.credential.clone()));
    let instance = format!("instance-{}-{}", h.epoch, h.serial.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let mut loaded = h.config.write().await;
    if let Some(loaded) = loaded.modules.iter_mut().find(|m| m.name == config.module) {
        loaded.version = module.version().into();
    } else {
        loaded.modules.push(LoadedModule { name: config.module.clone(), version: module.version().into() });
    }
    // Logical bindings preserve independently owned external-host state across
    // a server disconnect. Each factory result also has its own precise handle,
    // so a rejected/corrected configuration cannot replace another live handle.
    loaded.bindings.insert(config.name.clone(), Binding { entrypoint, config, provider: provider.clone() });
    loaded.handles.insert(instance.clone(), provider);
    Ok(Json(ConfiguredProvider { instance, facts }))
}
/// Releases one handle. Its logical binding, and so its module, stays loaded.
async fn release_provider(State(h): State<Host>, ApiPath(name): ApiPath<String>) -> StatusCode {
    h.config.write().await.handles.remove(&name);
    StatusCode::NO_CONTENT
}
async fn prepare(b: Bound<PrepareRequest>) -> ApiResult<Json<Prepared>> {
    Ok(Json(b.provider.prepare(b.argument, &b.credentials).await?))
}
async fn provision(b: Bound<ProvisionRequest>) -> ApiResult<Json<Provisioned>> {
    Ok(Json(b.provider.provision(b.argument, &b.credentials).await?))
}
async fn list(b: Bound<()>) -> ApiResult<Json<Vec<ObservedEnvironment>>> {
    Ok(Json(b.provider.list(&b.credentials).await?))
}
async fn inspect(b: Bound<String>) -> ApiResult<Json<ObservedEnvironment>> {
    Ok(Json(b.provider.inspect(&b.argument, &b.credentials).await?))
}
async fn inspect_after_lifecycle(b: Bound<String>) -> ApiResult<Json<ObservedEnvironment>> {
    Ok(Json(b.provider.inspect_after_lifecycle(&b.argument, &b.credentials).await?))
}
async fn destroy(b: Bound<String>) -> ApiResult<Json<()>> {
    Ok(Json(b.provider.destroy(&b.argument, &b.credentials).await?))
}
async fn reach(b: Bound<String>) -> ApiResult<Json<Connection>> {
    Ok(Json(b.provider.reach(&b.argument, &b.credentials).await?))
}
async fn suspend(b: Bound<String>) -> ApiResult<Json<ResumeToken>> {
    Ok(Json(operation_port(b.provider.operations().suspend_resume)?.suspend(&b.argument, &b.credentials).await?))
}
async fn resume(b: Bound<(String, ResumeToken)>) -> ApiResult<Json<()>> {
    let (id, token) = b.argument;
    Ok(Json(operation_port(b.provider.operations().suspend_resume)?.resume(&id, token, &b.credentials).await?))
}
async fn export(b: Bound<String>) -> ApiResult<Json<Export>> {
    Ok(Json(operation_port(b.provider.operations().export)?.export(&b.argument, &b.credentials).await?))
}
async fn usage(b: Bound<Period>) -> ApiResult<Json<Usage>> {
    Ok(Json(operation_port(b.provider.operations().usage)?.usage(b.argument, &b.credentials).await?))
}
async fn quota(b: Bound<()>) -> ApiResult<Json<Quota>> {
    Ok(Json(operation_port(b.provider.operations().quota)?.quota(&b.credentials).await?))
}
async fn relay(State(h): State<Host>, mut request: Request) -> ApiResult<Response> {
    let on = upgrade(&mut request, "drydock-relay")?;
    let b = Bound::<String>::from_request(request, &h).await?;
    let stream = b.provider.relay(&b.argument, &b.credentials).await?;
    Ok(switch(on, "drydock-relay", stream, h.stopping.subscribe()))
}
async fn exec(State(h): State<Host>, mut request: Request) -> ApiResult<Response> {
    let on = upgrade(&mut request, "drydock-stream")?;
    let b = Bound::<(String, ExecRequest)>::from_request(request, &h).await?;
    let (id, command) = b.argument;
    let stream = operation_port(b.provider.operations().exec)?.exec(&id, command, &b.credentials).await?;
    Ok(switch(on, "drydock-stream", stream, h.stopping.subscribe()))
}
async fn subscribe(State(h): State<Host>, b: Bound<()>) -> ApiResult<Response> {
    let p = b.provider;
    let (tx, mut rx) = tokio::sync::mpsc::channel(32);
    let mut stop_rx = h.stopping.subscribe();
    let (overflow, mut overflowed) = watch::channel(false);
    let context = PushContext {
        events: EventSink::new(move |update| {
            tx.try_send(update).map_err(|_| {
                overflow.send_replace(true);
                refused("raw subscription buffer full or closed")
            })
        }),
        credentials: b.credentials,
        stopping: stop_rx.clone(),
    };
    // The response owns the provider future: disconnect drops it, propagating cancellation.
    let body = async_stream::stream! {
        let run = p.run(context);
        tokio::pin!(run);
        loop {
            // Biased: once overflow is flagged, Failed follows without further updates.
            tokio::select! {
                biased;
                _ = stop_rx.changed() => break,
                _ = async { let _ = overflowed.wait_for(|value| *value).await; } => {
                    // Updates still queued are dropped: the stream is already incomplete. The
                    // server records a failed subscription, and only a fresh one (after
                    // rotation) rebuilds its view, from a new snapshot.
                    yield Ok::<_, std::io::Error>(subscription_line(SubscriptionRecord::Failed(ProtocolError::unavailable("raw subscription overflow", None))));
                    break;
                },
                result = &mut run => {
                    // Completion must not discard observations published by
                    // the provider's final poll of its run future.
                    while let Ok(update) = rx.try_recv() {
                        yield Ok::<_, std::io::Error>(subscription_line(SubscriptionRecord::Update(update)));
                    }
                    let result = if *overflowed.borrow() { Err(ProtocolError::unavailable("raw subscription overflow", None)) } else { result };
                    if let Err(error) = result {
                        yield Ok::<_, std::io::Error>(subscription_line(SubscriptionRecord::Failed(error)));
                    }
                    break;
                },
                update = rx.recv() => match update {
                    Some(update) => yield Ok::<_, std::io::Error>(subscription_line(SubscriptionRecord::Update(update))),
                    None => break,
                },
            }
        }
    };
    Ok(Response::builder().header("content-type", "application/x-ndjson").body(Body::from_stream(body)).expect("response"))
}

fn subscription_line(record: SubscriptionRecord) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&record).expect("raw subscription record");
    bytes.push(b'\n');
    bytes
}

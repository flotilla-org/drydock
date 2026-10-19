//! Reference Rust language host. See the crate README for module and serving contracts.
pub mod module;
mod observer;
pub mod reference;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Path, Query, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use drydock_protocol::*;
use module::{
    Connection, Credentials, ObservationMode, ObservedSandbox, Provider, Provisioned, Registry,
    Result, refused,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
};
use tokio::sync::{Mutex as AsyncMutex, RwLock, watch};

const EVENT_HISTORY_CAPACITY: usize = 1024;

#[derive(Clone)]
pub struct EventSink {
    log: Arc<Mutex<Log>>,
    changed: watch::Sender<u64>,
    provider: String,
}
struct Log {
    serial: u64,
    records: VecDeque<Event>,
    epoch: String,
}
impl EventSink {
    /// Publish an observation. The host supplies the provider and opaque ordered cursor.
    pub fn publish(
        &self,
        id: String,
        label: Option<String>,
        timestamp: Option<chrono::DateTime<chrono::Utc>>,
        event: EventKind,
    ) {
        let mut log = self
            .log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        log.serial += 1;
        let cursor = format!("{}:{}", log.epoch, log.serial);
        log.records.push_back(Event {
            cursor,
            id,
            provider: self.provider.clone(),
            label,
            timestamp: timestamp.unwrap_or_else(chrono::Utc::now).to_rfc3339(),
            timestamp_source: if timestamp.is_some() {
                TimestampSource::Provider
            } else {
                TimestampSource::Adaptor
            },
            event,
        });
        if log.records.len() > EVENT_HISTORY_CAPACITY {
            log.records.pop_front();
        }
        self.changed.send_replace(log.serial);
    }
}
struct Authentication {
    credentials: Credentials,
    generation: u64,
    readiness: Readiness,
}
struct Instance {
    config: ProviderConfiguration,
    provider: Arc<dyn Provider>,
    // Synchronous metadata access only; never hold this guard across await.
    auth: Mutex<Authentication>,
    capabilities: Capabilities,
    rate_limits: Vec<RateLimit>,
    budget: Mutex<BTreeMap<String, VecDeque<tokio::time::Instant>>>,
    events: EventSink,
    observation: ObservationMode,
    destroyed: Mutex<BTreeSet<String>>,
    inspected: Mutex<BTreeMap<String, ObservedSandbox>>,
}
#[derive(Clone, Copy)]
enum Gate {
    Any(&'static str),
    Suspend,
    Resume,
    Export,
    Exec,
    Usage,
    Quota,
}
impl Gate {
    fn name(self) -> &'static str {
        match self {
            Self::Any(name) => name,
            Self::Suspend => "suspend",
            Self::Resume => "resume",
            Self::Export => "export",
            Self::Exec => "exec",
            Self::Usage => "usage",
            Self::Quota => "quota",
        }
    }
    fn supported(self, c: &Capabilities) -> bool {
        match self {
            Self::Any(_) => true,
            Self::Suspend | Self::Resume => c.suspend_resume,
            Self::Export => c.export,
            Self::Exec => c.fallback_runner,
            Self::Usage => c.usage,
            Self::Quota => c.quota,
        }
    }
}
impl Instance {
    /// Resolve readiness, gate cached capabilities, enforce declared budgets, invoke,
    /// and update credential rejection state once for every route and host poll.
    async fn call<T, F, Fut>(&self, gate: Gate, f: F) -> Result<T>
    where
        T: Send,
        F: FnOnce(Arc<dyn Provider>, Credentials) -> Fut + Send,
        Fut: std::future::Future<Output = Result<T>> + Send,
    {
        let (credentials, generation) = {
            let auth = self
                .auth
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !matches!(auth.readiness, Readiness::Ready) {
                return Err(ProtocolError::Unavailable {
                    reason: "provider is not ready; inspect hello".into(),
                    retry_after: None,
                });
            }
            (auth.credentials.clone(), auth.generation)
        };
        if !gate.supported(&self.capabilities) {
            return Err(refused("operation capability not declared"));
        }
        self.reserve(gate.name())?;
        let result = f(self.provider.clone(), credentials).await;
        let mut auth = self
            .auth
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if auth.generation == generation {
            auth.readiness = if matches!(result, Err(ProtocolError::CredentialRejected { .. })) {
                Readiness::MissingCredential {
                    reason: "credential rejected".into(),
                }
            } else {
                self.provider.readiness(&auth.credentials)
            };
        }
        result
    }
    fn reserve(&self, operation: &'static str) -> Result<()> {
        let mut budget = self
            .budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = tokio::time::Instant::now();
        let limits: Vec<_> = self
            .rate_limits
            .iter()
            .filter(|r| r.operation == operation || r.operation == "*")
            .collect();
        for limit in &limits {
            let longest = self
                .rate_limits
                .iter()
                .filter(|r| r.operation == limit.operation)
                .map(|r| r.period_seconds)
                .max()
                .unwrap_or(0);
            let times = budget.entry(limit.operation.clone()).or_default();
            while times.front().is_some_and(|at| {
                now.duration_since(*at) >= std::time::Duration::from_secs(longest)
            }) {
                times.pop_front();
            }
            let window = std::time::Duration::from_secs(limit.period_seconds);
            let active: Vec<_> = times
                .iter()
                .filter(|at| now.duration_since(**at) < window)
                .collect();
            if active.len() >= limit.requests as usize {
                let remaining = window.saturating_sub(now.duration_since(*active[0]));
                return Err(ProtocolError::RateLimited {
                    reason: "declared provider rate limit".into(),
                    retry_after: Some(remaining.as_secs().saturating_add(1)),
                });
            }
        }
        let scopes: BTreeSet<_> = limits.iter().map(|limit| limit.operation.clone()).collect();
        for scope in scopes {
            budget.entry(scope).or_default().push_back(now);
        }
        Ok(())
    }
}

#[derive(Default, Clone)]
struct Configuration {
    modules: Vec<LoadedModule>,
    entrypoints: BTreeMap<String, String>,
    providers: BTreeMap<String, Arc<Instance>>,
}
#[derive(Clone)]
pub struct Host {
    registry: Arc<Registry>,
    config: Arc<RwLock<Configuration>>,
    configuring: Arc<AsyncMutex<()>>,
    events: EventSink,
    proxy_ca: Option<Arc<Vec<u8>>>,
    stopping: watch::Sender<bool>,
}
impl Host {
    pub fn new(registry: Registry) -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            registry: Arc::new(registry),
            config: Arc::new(RwLock::new(Configuration::default())),
            configuring: Arc::new(AsyncMutex::new(())),
            events: EventSink {
                log: Arc::new(Mutex::new(Log {
                    serial: 0,
                    records: VecDeque::new(),
                    epoch: format!(
                        "{}-{}",
                        std::process::id(),
                        chrono::Utc::now()
                            .timestamp_nanos_opt()
                            .expect("current time fits nanoseconds")
                    ),
                })),
                changed,
                provider: String::new(),
            },
            proxy_ca: None,
            stopping: watch::channel(false).0,
        }
    }
    /// PEM trust root supplied out of band by the supervisor; never a vendor credential.
    pub fn with_proxy_ca(mut self, pem: Vec<u8>) -> Self {
        self.proxy_ca = Some(Arc::new(pem));
        self
    }
    pub fn router(&self) -> Router {
        Router::new()
            .route("/v1/hello", get(hello))
            .route("/v1/config", put(configure))
            .route("/v1/events", get(events))
            .route("/v1/providers/{provider}/credential", put(credential))
            .route("/v1/providers/{provider}/prepare", post(prepare))
            .route(
                "/v1/providers/{provider}/environments",
                get(list).post(provision),
            )
            .route(
                "/v1/providers/{provider}/environments/{id}",
                get(inspect).delete(destroy),
            )
            .route(
                "/v1/providers/{provider}/environments/{id}/reach",
                post(reach),
            )
            .route(
                "/v1/providers/{provider}/environments/{id}/relay",
                get(relay),
            )
            .route(
                "/v1/providers/{provider}/environments/{id}/exec",
                post(exec),
            )
            .route(
                "/v1/providers/{provider}/environments/{id}/suspend",
                post(suspend),
            )
            .route(
                "/v1/providers/{provider}/environments/{id}/resume",
                post(resume),
            )
            .route(
                "/v1/providers/{provider}/environments/{id}/export",
                post(export),
            )
            .route("/v1/providers/{provider}/usage", get(usage))
            .route("/v1/providers/{provider}/quota", get(quota))
            .fallback(|| async { ApiError(refused("unknown route")) })
            .method_not_allowed_fallback(|| async { ApiError(refused("unsupported method")) })
            .with_state(self.clone())
    }

    /// Only the specified kernel UID is admitted. TCP auth is provided by rigging.
    pub async fn serve_unix<F: std::future::Future<Output = ()> + Send + 'static>(
        &self,
        path: impl AsRef<std::path::Path>,
        uid: u32,
        shutdown: F,
    ) -> std::io::Result<()> {
        use rigging_http_serve::{Caller, UnixServer};
        let router =
            self.router().layer(middleware::from_fn(
                move |axum::Extension(caller): axum::Extension<Caller>,
                      req: Request,
                      next: Next| async move {
                    match caller {
                        Caller::Unix(peer) if peer.uid == uid => next.run(req).await,
                        _ => StatusCode::FORBIDDEN.into_response(),
                    }
                },
            ));
        UnixServer::bind(path, 0o600)
            .await?
            .serve(router, Caller::<()>::Unix, self.shutdown(shutdown))
            .await
    }
    pub async fn serve_tcp<F: std::future::Future<Output = ()> + Send + 'static>(
        &self,
        address: std::net::SocketAddr,
        token_file: impl AsRef<std::path::Path>,
        shutdown: F,
    ) -> std::io::Result<()> {
        // The host protocol specifies bearer auth, so disallow rigging's optional cookie mode.
        let router =
            self.router()
                .layer(middleware::from_fn(|req: Request, next: Next| async move {
                    if req.headers().contains_key(header::AUTHORIZATION) {
                        next.run(req).await
                    } else {
                        StatusCode::UNAUTHORIZED.into_response()
                    }
                }));
        rigging_http_serve::TcpServer::bind(address, token_file)
            .await?
            .serve::<(), _>(router, self.shutdown(shutdown))
            .await
    }
    fn shutdown<F: std::future::Future<Output = ()> + Send + 'static>(
        &self,
        signal: F,
    ) -> impl std::future::Future<Output = ()> + Send + 'static {
        let stopping = self.stopping.clone();
        async move {
            signal.await;
            stopping.send_replace(true);
        }
    }
    async fn instance(&self, name: &str) -> Result<Arc<Instance>> {
        self.config
            .read()
            .await
            .providers
            .get(name)
            .cloned()
            .ok_or_else(|| refused("unknown provider"))
    }
    async fn call<T, F, Fut>(&self, name: &str, gate: Gate, f: F) -> Result<T>
    where
        T: Send,
        F: FnOnce(Arc<dyn Provider>, Credentials) -> Fut + Send,
        Fut: std::future::Future<Output = Result<T>> + Send,
    {
        self.instance(name).await?.call(gate, f).await
    }
    async fn records(&self, cursor: Option<&str>) -> Result<Vec<ObserveRecord>> {
        let replay = {
            let log = self
                .events
                .log
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cursor.and_then(|c| {
                let serial = c
                    .strip_prefix(&format!("{}:", log.epoch))?
                    .parse::<u64>()
                    .ok()?;
                let oldest = log.serial - log.records.len() as u64;
                if serial < oldest || serial > log.serial {
                    return None;
                }
                Some(
                    log.records
                        .iter()
                        .skip((serial - oldest) as usize)
                        .cloned()
                        .map(|event| ObserveRecord::Event { event })
                        .collect::<Vec<_>>(),
                )
            })
        };
        match replay {
            Some(records) => Ok(records),
            None => Ok(vec![self.snapshot().await?]),
        }
    }
    async fn snapshot(&self) -> Result<ObserveRecord> {
        let config = self.config.read().await;
        let names: Vec<_> = config.providers.keys().cloned().collect();
        // Capture the cursor before list calls, so background observations during a slow
        // snapshot are replayed rather than silently skipped (consumers reconcile IDs).
        let cursor = {
            let log = self
                .events
                .log
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            format!("{}:{}", log.epoch, log.serial)
        };
        drop(config);
        let mut sandboxes = vec![];
        for name in names {
            let rows = self
                .call(
                    &name,
                    Gate::Any("list"),
                    |p, c| async move { p.list(&c).await },
                )
                .await?;
            sandboxes.extend(rows.into_iter().map(|row| row.sandbox));
        }
        Ok(ObserveRecord::Snapshot { cursor, sandboxes })
    }
}

struct ApiError(ProtocolError);
impl From<ProtocolError> for ApiError {
    fn from(e: ProtocolError) -> Self {
        Self(e)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, retry) = (self.0.status(), self.0.retry_after());
        let mut response = (
            StatusCode::from_u16(status).expect("protocol error status is valid HTTP"),
            Json(self.0),
        )
            .into_response();
        if let Some(seconds) = retry {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                seconds
                    .to_string()
                    .parse()
                    .expect("decimal retry seconds form a valid header"),
            );
        }
        response
    }
}
type ApiResult<T> = std::result::Result<T, ApiError>;
// Typed extraction refuses malformed input without echoing diagnostics or secrets.
struct ApiJson<T>(T);
impl<S, T> axum::extract::FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned + Send,
{
    type Rejection = ApiError;
    async fn from_request(
        request: Request,
        state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(request, state)
            .await
            .map_err(|_| ApiError(refused("invalid JSON request")))?;
        Ok(Self(value))
    }
}
struct ApiPath<T>(T);
impl<S, T> axum::extract::FromRequestParts<S> for ApiPath<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned + Send,
{
    type Rejection = ApiError;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        let Path(value) = Path::<T>::from_request_parts(parts, state)
            .await
            .map_err(|_| ApiError(refused("invalid route identifier")))?;
        Ok(Self(value))
    }
}
async fn hello(State(host): State<Host>) -> Json<Hello> {
    let config = host.config.read().await;
    Json(Hello {
        protocol_version: PROTOCOL_VERSION.into(),
        host_version: env!("CARGO_PKG_VERSION").into(),
        modules: config.modules.clone(),
        providers: config
            .providers
            .iter()
            .map(|(name, i)| ProviderDeclaration {
                provider: name.clone(),
                module: i.config.module.clone(),
                capabilities: i.capabilities.clone(),
                readiness: i
                    .auth
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .readiness
                    .clone(),
                rate_limits: i.rate_limits.clone(),
            })
            .collect(),
    })
}
async fn configure(
    State(host): State<Host>,
    ApiJson(request): ApiJson<HostConfiguration>,
) -> ApiResult<StatusCode> {
    let _transaction = host.configuring.lock().await;
    let mut config = host.config.read().await.clone();
    // Exact repeats preserve resources and delivered credentials. Changes to live providers
    // are refused: silently replacing one would lose in-memory reference resources.
    let mut modules = BTreeMap::new();
    for m in &request.modules {
        if modules
            .insert(m.name.clone(), m.entrypoint.clone())
            .is_some()
        {
            return Err(refused("duplicate module").into());
        }
        if !host.registry.contains_key(&m.entrypoint) {
            return Err(refused("unregistered module entrypoint").into());
        }
    }
    let mut names = BTreeSet::new();
    for p in &request.providers {
        if p.name.is_empty() || !names.insert(p.name.clone()) || !modules.contains_key(&p.module) {
            return Err(refused("invalid or duplicate provider/module").into());
        }
        if let Some(old) = config.providers.get(&p.name) {
            let same_entrypoint = config.entrypoints.get(&p.module) == modules.get(&p.module);
            if old.config != *p || !same_entrypoint {
                return Err(refused("cannot replace a configured provider; restart host").into());
            }
        }
    }
    if config.providers.keys().any(|name| !names.contains(name)) {
        return Err(refused("cannot remove a configured provider; restart host").into());
    }
    // Build before committing configuration, so a rejected document cannot partly apply.
    let mut additions = BTreeMap::new();
    for p in &request.providers {
        if config.providers.contains_key(&p.name) {
            continue;
        }
        let module = &host.registry[&modules[&p.module]];
        let credentials = Credentials::new(p.credential.clone());
        let proxy = match &p.credential {
            CredentialMode::Proxied { proxy_url, .. } => Some(proxy_url.as_str()),
            _ => None,
        };
        let http = Arc::new(
            rigging_http_client::ReqwestHttpClient::restricted(
                proxy,
                host.proxy_ca.as_deref().map(Vec::as_slice),
            )
            .map_err(|_| refused("invalid HTTP transport configuration"))?,
        );
        let mut sink = host.events.clone();
        sink.provider = p.name.clone();
        let provider = module.configure(p, sink.clone(), http).await?;
        let readiness = provider.readiness(&credentials);
        let capabilities = provider.capabilities();
        let rate_limits = provider.rate_limits();
        if rate_limits
            .iter()
            .any(|r| r.requests == 0 || r.period_seconds == 0)
        {
            return Err(refused("invalid declared rate limit").into());
        }
        let observation = provider.observation();
        observer::poll_interval(observation, &rate_limits)?;
        additions.insert(
            p.name.clone(),
            Arc::new(Instance {
                config: p.clone(),
                provider,
                auth: Mutex::new(Authentication {
                    credentials,
                    readiness,
                    generation: 0,
                }),
                capabilities,
                rate_limits,
                events: sink,
                observation,
                budget: Mutex::new(BTreeMap::new()),
                destroyed: Mutex::new(BTreeSet::new()),
                inspected: Mutex::new(BTreeMap::new()),
            }),
        );
    }
    config.entrypoints = modules;
    let observers: Vec<_> = additions.values().cloned().collect();
    config.providers.extend(additions);
    config.modules = request
        .modules
        .iter()
        .map(|m| LoadedModule {
            name: m.name.clone(),
            version: host.registry[&m.entrypoint].version().into(),
        })
        .collect();
    *host.config.write().await = config;
    for instance in observers {
        observer::spawn(instance, host.stopping.subscribe());
    }
    Ok(StatusCode::NO_CONTENT)
}
async fn credential(
    State(host): State<Host>,
    ApiPath(p): ApiPath<String>,
    ApiJson(refresh): ApiJson<CredentialRefresh>,
) -> ApiResult<StatusCode> {
    if refresh.value.expose().is_empty() {
        return Err(refused("credential must not be empty").into());
    }
    let instance = host
        .config
        .read()
        .await
        .providers
        .get(&p)
        .cloned()
        .ok_or_else(|| refused("unknown provider"))?;
    let mut auth = instance
        .auth
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !matches!(auth.credentials.mode, CredentialMode::Direct { .. }) {
        return Err(refused("proxied provider cannot accept direct credentials").into());
    }
    auth.credentials.value = Some(refresh.value);
    auth.generation += 1;
    // Refresh repairs authentication only. Tool/version/unknown readiness stays
    // unchanged; these modules require restart after their external prerequisites change.
    if matches!(auth.readiness, Readiness::MissingCredential { .. }) {
        auth.readiness = Readiness::Ready;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn prepare(
    State(h): State<Host>,
    ApiPath(p): ApiPath<String>,
    ApiJson(r): ApiJson<PrepareRequest>,
) -> ApiResult<Json<Prepared>> {
    if r.image_digest.is_empty() || r.tools_digest.is_empty() {
        return Err(refused("digests must not be empty").into());
    }
    Ok(Json(
        h.call(&p, Gate::Any("prepare"), |p, c| async move {
            p.prepare(r, &c).await
        })
        .await?,
    ))
}
async fn provision(
    State(h): State<Host>,
    ApiPath(p): ApiPath<String>,
    ApiJson(r): ApiJson<ProvisionRequest>,
) -> ApiResult<Response> {
    if r.prepared.provider != p
        || r.label.is_empty()
        || !r.size.cpus.is_finite()
        || r.size.cpus <= 0.0
    {
        return Err(refused("invalid size, label or prepared provider").into());
    }
    let result = h
        .call(&p, Gate::Any("provision"), |p, c| async move {
            p.provision(r, &c).await
        })
        .await?;
    Ok(match result {
        Provisioned::Created(s) => (StatusCode::CREATED, Json(s)),
        Provisioned::Existing(s) => (StatusCode::OK, Json(s)),
    }
    .into_response())
}
async fn list(State(h): State<Host>, ApiPath(p): ApiPath<String>) -> ApiResult<Json<Vec<Sandbox>>> {
    Ok(Json(
        h.call(
            &p,
            Gate::Any("list"),
            |p, c| async move { p.list(&c).await },
        )
        .await?
        .into_iter()
        .map(|r| r.sandbox)
        .collect(),
    ))
}
async fn inspect(
    State(h): State<Host>,
    ApiPath((p, id)): ApiPath<(String, String)>,
) -> ApiResult<Json<Sandbox>> {
    let instance = h.instance(&p).await?;
    let row = instance
        .call(Gate::Any("inspect"), |p, c| async move {
            p.inspect(&id, &c).await
        })
        .await?;
    if row.timestamp.is_some() {
        instance
            .inspected
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(row.sandbox.id.clone(), row.clone());
    }
    Ok(Json(row.sandbox))
}
async fn destroy(
    State(h): State<Host>,
    ApiPath((p, id)): ApiPath<(String, String)>,
) -> ApiResult<StatusCode> {
    let instance = h.instance(&p).await?;
    let removed = id.clone();
    instance
        .call(Gate::Any("destroy"), |p, c| async move {
            p.destroy(&id, &c).await
        })
        .await?;
    instance
        .destroyed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(removed);
    Ok(StatusCode::NO_CONTENT)
}
async fn reach(
    State(h): State<Host>,
    ApiPath((p, id)): ApiPath<(String, String)>,
) -> ApiResult<Json<Reach>> {
    let environment = id.clone();
    let connection = h
        .call(&p, Gate::Any("reach"), |p, c| async move {
            p.reach(&id, &c).await
        })
        .await?;
    let reach = match connection {
        Connection::Relay => {
            let mut url = reqwest::Url::parse("http://localhost").expect("static URL");
            url.path_segments_mut().expect("base URL").extend([
                "v1",
                "providers",
                &p,
                "environments",
                &environment,
                "relay",
            ]);
            Reach::Relay {
                path: url.path().into(),
            }
        }
        Connection::Ssh {
            endpoint,
            user,
            host_key,
        } => Reach::Ssh {
            endpoint,
            user,
            host_key,
        },
        Connection::Dial {
            url,
            token,
            expires_at,
        } => Reach::Dial {
            url,
            token,
            expires_at,
        },
    };
    Ok(Json(reach))
}
async fn suspend(
    State(h): State<Host>,
    ApiPath((p, id)): ApiPath<(String, String)>,
) -> ApiResult<Json<ResumeToken>> {
    Ok(Json(
        h.call(
            &p,
            Gate::Suspend,
            |p, c| async move { p.suspend(&id, &c).await },
        )
        .await?,
    ))
}
async fn resume(
    State(h): State<Host>,
    ApiPath((p, id)): ApiPath<(String, String)>,
    ApiJson(token): ApiJson<ResumeToken>,
) -> ApiResult<StatusCode> {
    h.call(&p, Gate::Resume, |p, c| async move {
        p.resume(&id, token, &c).await
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn export(
    State(h): State<Host>,
    ApiPath((p, id)): ApiPath<(String, String)>,
) -> ApiResult<Json<Export>> {
    Ok(Json(
        h.call(
            &p,
            Gate::Export,
            |p, c| async move { p.export(&id, &c).await },
        )
        .await?,
    ))
}
async fn usage(
    State(h): State<Host>,
    ApiPath(p): ApiPath<String>,
    query: std::result::Result<Query<Period>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<Usage>> {
    let Query(period) = query.map_err(|_| refused("invalid usage period"))?;
    Ok(Json(
        h.call(
            &p,
            Gate::Usage,
            |p, c| async move { p.usage(period, &c).await },
        )
        .await?,
    ))
}
async fn quota(State(h): State<Host>, ApiPath(p): ApiPath<String>) -> ApiResult<Json<Quota>> {
    Ok(Json(
        h.call(&p, Gate::Quota, |p, c| async move { p.quota(&c).await })
            .await?,
    ))
}

fn validate_upgrade(request: &Request, protocol: &str) -> Result<()> {
    let headers = request.headers();
    if !headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case(protocol))
        || !headers
            .get(header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("upgrade"))
            })
    {
        return Err(refused("missing stream upgrade headers"));
    }
    Ok(())
}
fn upgrade(
    on_upgrade: hyper::upgrade::OnUpgrade,
    protocol: &'static str,
    stream: module::ByteStream,
    mut stopping: watch::Receiver<bool>,
) -> Result<Response> {
    tokio::spawn(async move {
        if *stopping.borrow() {
            return;
        }
        let upgraded = tokio::select! {
            result = on_upgrade => match result { Ok(upgraded) => upgraded, Err(_) => return },
            _ = stopping.changed() => return,
        };
        let mut io = hyper_util::rt::TokioIo::new(upgraded);
        let mut stream = stream;
        if *stopping.borrow() {
            return;
        }
        tokio::select! {
            _ = tokio::io::copy_bidirectional(&mut io, &mut stream) => {},
            _ = stopping.changed() => {},
        }
    });
    Ok((
        StatusCode::SWITCHING_PROTOCOLS,
        [(header::CONNECTION, "Upgrade"), (header::UPGRADE, protocol)],
    )
        .into_response())
}
struct StreamUpgrade(hyper::upgrade::OnUpgrade);
struct ExecUpgrade {
    upgrade: StreamUpgrade,
    command: ExecRequest,
}
impl<S: Send + Sync> axum::extract::FromRequest<S> for ExecUpgrade {
    type Rejection = ApiError;
    async fn from_request(
        mut request: Request,
        state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        validate_upgrade(&request, "drydock-stream")?;
        let upgrade = StreamUpgrade(hyper::upgrade::on(&mut request));
        let ApiJson(command) = ApiJson::<ExecRequest>::from_request(request, state).await?;
        if command.command.is_empty() {
            return Err(refused("empty command").into());
        }
        Ok(Self { upgrade, command })
    }
}
async fn relay(
    State(h): State<Host>,
    ApiPath((p, id)): ApiPath<(String, String)>,
    mut request: Request,
) -> ApiResult<Response> {
    validate_upgrade(&request, "drydock-relay")?;
    let on = hyper::upgrade::on(&mut request);
    let stream = h
        .call(&p, Gate::Any("relay"), |p, c| async move {
            p.relay(&id, &c).await
        })
        .await?;
    Ok(upgrade(
        on,
        "drydock-relay",
        stream,
        h.stopping.subscribe(),
    )?)
}
async fn exec(
    State(h): State<Host>,
    ApiPath((p, id)): ApiPath<(String, String)>,
    request: ExecUpgrade,
) -> ApiResult<Response> {
    let stream = h
        .call(&p, Gate::Exec, |p, c| async move {
            p.exec(&id, request.command, &c).await
        })
        .await?;
    Ok(upgrade(
        request.upgrade.0,
        "drydock-stream",
        stream,
        h.stopping.subscribe(),
    )?)
}
#[derive(Deserialize)]
struct EventQuery {
    since: Option<String>,
}
async fn events(
    State(host): State<Host>,
    query: std::result::Result<Query<EventQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Response> {
    let Query(q) = query.map_err(|_| refused("invalid event cursor query"))?;
    let mut changed = host.events.changed.subscribe();
    let mut stopping = host.stopping.subscribe();
    let mut cursor = q.since;
    let initial = host.records(cursor.as_deref()).await?;
    // A watch receiver is subscribed before reading the log: events between reads
    // remain visible. Slow readers recover with a complete snapshot after eviction.
    let stream = async_stream::stream! {
        let mut initial = Some(initial);
        loop {
            let records = match initial.take() {
                Some(records) => records,
                None => match host.records(cursor.as_deref()).await {
                    Ok(records) => records,
                    Err(error) => {
                        // Protocol v1 permits only Event/Snapshot records. Fail the HTTP
                        // body rather than invent a terminal record or signal clean EOF.
                        yield Err(std::io::Error::other(stream_error_class(&error)));
                        break;
                    }
                },
            };
            for record in records {
                cursor = Some(record_cursor(&record).into());
                yield Ok::<Bytes, std::io::Error>(record_line(&record));
            }
            if *stopping.borrow() { break; }
            tokio::select! {
                result = changed.changed() => if result.is_err() { break; },
                _ = stopping.changed() => break,
            }
        }
    };
    Ok((
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        Body::from_stream(stream),
    )
        .into_response())
}

fn record_cursor(record: &ObserveRecord) -> &str {
    match record {
        ObserveRecord::Event { event } => &event.cursor,
        ObserveRecord::Snapshot { cursor, .. } => cursor,
    }
}
fn record_line(record: &ObserveRecord) -> Bytes {
    let mut line = serde_json::to_vec(record).expect("wire record serializes");
    line.push(b'\n');
    Bytes::from(line)
}
fn stream_error_class(error: &ProtocolError) -> &'static str {
    match error {
        ProtocolError::Refused { .. } => "event snapshot refused",
        ProtocolError::Unavailable { .. } => "event snapshot unavailable",
        ProtocolError::RateLimited { .. } => "event snapshot rate limited",
        ProtocolError::QuotaExhausted { .. } => "event snapshot quota exhausted",
        ProtocolError::CredentialRejected { .. } => "event snapshot credential rejected",
        ProtocolError::Internal { .. } => "event snapshot internal error",
    }
}

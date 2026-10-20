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
use module::{Connection, Credentials, ObservationMode, ObservedEnvironment, Provider, Provisioned, Registry, Result, refused};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
};
use tokio::sync::{Mutex as AsyncMutex, RwLock, watch};

pub const EVENT_HISTORY_CAPACITY: usize = 1024;

#[derive(Clone)]
struct EventLog {
    log: Arc<Mutex<Log>>,
    changed: watch::Sender<u64>,
}
#[derive(Clone)]
pub struct EventSink {
    shared: EventLog,
    provider: String,
}
struct Log {
    serial: u64,
    records: VecDeque<Event>,
    epoch: String,
    inventories: BTreeMap<String, Vec<ObservedEnvironment>>,
}
impl EventSink {
    /// Publish an observation. The host supplies the provider and opaque ordered cursor.
    pub fn publish(&self, id: String, label: Option<String>, timestamp: Option<chrono::DateTime<chrono::Utc>>, event: EventKind) {
        let mut log = self.shared.log.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::append(&mut log, &self.provider, id, label, timestamp, event);
        self.shared.changed.send_replace(log.serial);
    }
    fn append(
        log: &mut Log,
        provider: &str,
        id: String,
        label: Option<String>,
        timestamp: Option<chrono::DateTime<chrono::Utc>>,
        event: EventKind,
    ) {
        tracing::debug!(provider, environment_id = %id, route = "observe", "environment observation");
        log.serial += 1;
        let cursor = format!("{}:{}", log.epoch, log.serial);
        log.records.push_back(Event {
            cursor,
            id,
            provider: provider.to_owned(),
            label,
            timestamp: timestamp.unwrap_or_else(chrono::Utc::now).into(),
            timestamp_source: if timestamp.is_some() { TimestampSource::Provider } else { TimestampSource::Adaptor },
            event,
        });
        if log.records.len() > EVENT_HISTORY_CAPACITY {
            log.records.pop_front();
        }
    }
    fn commit(&self, rows: Vec<ObservedEnvironment>, events: Vec<PendingEvent>) {
        let mut log = self.shared.log.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        log.inventories.insert(self.provider.clone(), rows);
        for (id, label, timestamp, event) in events {
            Self::append(&mut log, &self.provider, id, label, timestamp, event);
        }
        self.shared.changed.send_replace(log.serial);
    }
}
type PendingEvent = (String, Option<String>, Option<chrono::DateTime<chrono::Utc>>, EventKind);
struct Authentication {
    credentials: Credentials,
    generation: u64,
    rejected: bool,
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
    poll_interval: Option<std::time::Duration>,
    poll_error: Mutex<Option<ProtocolError>>,
    credential_changes: watch::Sender<Credentials>,
    destroyed: Mutex<BTreeMap<String, DestroyState>>,
    inspected: Mutex<BTreeMap<String, ObservedEnvironment>>,
}
#[derive(Default)]
struct DestroyState {
    pending: usize,
    confirmed: bool,
}
struct DestroyAttempt {
    instance: Arc<Instance>,
    id: String,
    active: bool,
}
impl DestroyAttempt {
    fn begin(instance: Arc<Instance>, id: String) -> Self {
        let active = instance.poll_interval.is_some();
        if active {
            instance.destroyed.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entry(id.clone()).or_default().pending += 1;
        }
        Self { instance, id, active }
    }
    fn finish(&mut self, confirmed: bool) {
        if !self.active {
            return;
        }
        let mut states = self.instance.destroyed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(state) = states.get_mut(&self.id) {
            state.pending -= 1;
            state.confirmed |= confirmed;
            if state.pending == 0 && !state.confirmed {
                states.remove(&self.id);
            }
        }
        self.active = false;
    }
}
impl Drop for DestroyAttempt {
    fn drop(&mut self) {
        self.finish(false);
    }
}
#[derive(Clone, Copy)]
enum Gate {
    Prepare,
    Provision,
    List,
    Inspect,
    Destroy,
    Reach,
    Relay,
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
            Self::Prepare => "prepare",
            Self::Provision => "provision",
            Self::List => "list",
            Self::Inspect => "inspect",
            Self::Destroy => "destroy",
            Self::Reach => "reach",
            Self::Relay => "relay",
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
            Self::Prepare | Self::Provision | Self::List | Self::Inspect | Self::Destroy | Self::Reach | Self::Relay => true,
            Self::Suspend | Self::Resume => c.suspend_resume,
            Self::Export => c.export,
            Self::Exec => c.fallback_runner,
            Self::Usage => c.usage,
            Self::Quota => c.quota,
        }
    }
}
struct Availability {
    readiness: Readiness,
    may_call: bool,
}
impl Instance {
    // All callers, hello and refresh use this single derivation. Direct rejection
    // is sticky until a new credential generation. Proxy credentials are repaired
    // out of band, so rejection does not disable subsequent probes or route calls.
    fn availability(&self, auth: &Authentication) -> Availability {
        let module = self.provider.readiness(&auth.credentials);
        let module_ready = matches!(module, Readiness::Ready);
        if auth.rejected {
            match auth.credentials.mode {
                CredentialMode::Direct { .. } => {
                    Availability { readiness: Readiness::MissingCredential { reason: "credential rejected".into() }, may_call: false }
                }
                CredentialMode::Proxied { .. } if module_ready => Availability {
                    readiness: Readiness::Unknown { reason: "proxy credential rejected; awaiting successful probe".into() },
                    may_call: true,
                },
                CredentialMode::Proxied { .. } => Availability { readiness: module, may_call: false },
            }
        } else {
            Availability { readiness: module, may_call: module_ready }
        }
    }
    fn readiness(&self, auth: &Authentication) -> Readiness {
        self.availability(auth).readiness
    }
    fn ready(&self) -> Result<()> {
        let auth = self.auth.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(self.readiness(&auth), Readiness::Ready) {
            Ok(())
        } else {
            Err(ProtocolError::Unavailable { reason: "provider is not ready; inspect hello".into(), retry_after: None })
        }
    }

    async fn call<T, F, Fut>(&self, gate: Gate, f: F) -> Result<T>
    where
        T: Send,
        F: FnOnce(Arc<dyn Provider>, Credentials) -> Fut + Send,
        Fut: std::future::Future<Output = Result<T>> + Send,
    {
        self.call_with_budget(gate, false, f).await
    }
    /// Resolve readiness, gate cached capabilities, enforce declared budgets, invoke,
    /// and update credential rejection state once for every route and host poll.
    async fn call_with_budget<T, F, Fut>(&self, gate: Gate, poll: bool, f: F) -> Result<T>
    where
        T: Send,
        F: FnOnce(Arc<dyn Provider>, Credentials) -> Fut + Send,
        Fut: std::future::Future<Output = Result<T>> + Send,
    {
        let (credentials, generation) = {
            let auth = self.auth.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if !self.availability(&auth).may_call {
                return Err(ProtocolError::Unavailable { reason: "provider is not ready; inspect hello".into(), retry_after: None });
            }
            (auth.credentials.clone(), auth.generation)
        };
        if !gate.supported(&self.capabilities) {
            return Err(refused("operation capability not declared"));
        }
        self.reserve(gate.name(), poll)?;
        let result = f(self.provider.clone(), credentials).await;
        if let Err(error) = &result {
            tracing::warn!(provider = %self.config.name, route = gate.name(), error_class = error.class(), "provider call failed");
        }
        let mut auth = self.auth.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = self.readiness(&auth);
        if auth.generation == generation {
            if matches!(result, Err(ProtocolError::CredentialRejected { .. })) {
                auth.rejected = true;
                auth.generation += 1; // invalidate every call started before this rejection
            } else if result.is_ok() && auth.rejected && matches!(auth.credentials.mode, CredentialMode::Proxied { .. }) {
                auth.rejected = false;
                auth.generation += 1; // only a probe started after rejection can repair it
            }
        }
        let after = self.readiness(&auth);
        if before != after {
            tracing::info!(provider = %self.config.name, route = gate.name(), readiness = readiness_status(&after), "provider readiness changed");
        }
        result
    }
    fn longest_window(&self, operation: &str) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.rate_limits.iter().filter(|r| r.operation == operation).map(|r| r.period_seconds).max().unwrap_or(0),
        )
    }
    fn reserve(&self, operation: &'static str, poll: bool) -> Result<()> {
        let mut budget = self.budget.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = tokio::time::Instant::now();
        let limits: Vec<_> = self.rate_limits.iter().filter(|r| r.operation == operation || r.operation == "*").collect();
        for limit in &limits {
            let longest = self.longest_window(&limit.operation);
            if poll {
                let window = std::time::Duration::from_secs(limit.period_seconds);
                let times = budget.entry(format!("poll:{}", limit.operation)).or_default();
                times.retain(|at| now.duration_since(*at) < longest);
                if times.iter().filter(|at| now.duration_since(**at) < window).count() >= (limit.requests / 2).max(1) as usize {
                    return Err(ProtocolError::RateLimited {
                        reason: "observation share exhausted".into(),
                        retry_after: Some(limit.period_seconds),
                    });
                }
            }
            let times = budget.entry(limit.operation.clone()).or_default();
            while times.front().is_some_and(|at| now.duration_since(*at) >= longest) {
                times.pop_front();
            }
            let window = std::time::Duration::from_secs(limit.period_seconds);
            let active: Vec<_> = times.iter().filter(|at| now.duration_since(**at) < window).collect();
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
            if poll {
                budget.entry(format!("poll:{scope}")).or_default().push_back(now);
            }
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
    events: EventLog,
    proxy_ca: Option<Arc<Vec<u8>>>,
    stopping: watch::Sender<bool>,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}
impl Host {
    pub fn new(registry: Registry) -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            registry: Arc::new(registry),
            config: Arc::new(RwLock::new(Configuration::default())),
            configuring: Arc::new(AsyncMutex::new(())),
            events: EventLog {
                log: Arc::new(Mutex::new(Log {
                    serial: 0,
                    inventories: BTreeMap::new(),
                    records: VecDeque::new(),
                    epoch: format!(
                        "{}-{}",
                        std::process::id(),
                        chrono::Utc::now().timestamp_nanos_opt().expect("current time fits nanoseconds")
                    ),
                })),
                changed,
            },
            proxy_ca: None,
            stopping: watch::channel(false).0,
            tasks: Arc::new(Mutex::new(vec![])),
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
            .route("/v1/providers/{provider}/environments", get(list).post(provision))
            .route("/v1/providers/{provider}/environments/{id}", get(inspect).delete(destroy))
            .route("/v1/providers/{provider}/environments/{id}/reach", post(reach))
            .route("/v1/providers/{provider}/environments/{id}/relay", get(relay))
            .route("/v1/providers/{provider}/environments/{id}/exec", post(exec))
            .route("/v1/providers/{provider}/environments/{id}/suspend", post(suspend))
            .route("/v1/providers/{provider}/environments/{id}/resume", post(resume))
            .route("/v1/providers/{provider}/environments/{id}/export", post(export))
            .route("/v1/providers/{provider}/usage", get(usage))
            .route("/v1/providers/{provider}/quota", get(quota))
            .fallback(|| async { ApiError(ProtocolError::NotFound { reason: "unknown route".into() }) })
            .method_not_allowed_fallback(|| async { ApiError(ProtocolError::MethodNotAllowed { reason: "unsupported method".into() }) })
            .with_state(self.clone())
            .layer(middleware::from_fn(trace_request))
    }

    /// Only the specified kernel UID is admitted. TCP auth is provided by rigging.
    pub async fn serve_unix<F: std::future::Future<Output = ()> + Send + 'static>(
        &self,
        path: impl AsRef<std::path::Path>,
        uid: u32,
        shutdown: F,
    ) -> std::io::Result<()> {
        use rigging_http_serve::{Caller, UnixServer};
        let router = self.router().layer(middleware::from_fn(
            move |axum::Extension(caller): axum::Extension<Caller>, req: Request, next: Next| async move {
                match caller {
                    Caller::Unix(peer) if peer.uid == uid => next.run(req).await,
                    _ => StatusCode::FORBIDDEN.into_response(),
                }
            },
        ));
        UnixServer::bind(path, 0o600).await?.serve(router, Caller::<()>::Unix, self.shutdown(shutdown)).await
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
        server.serve::<(), _>(router, self.shutdown(shutdown)).await
    }
    fn shutdown<F: std::future::Future<Output = ()> + Send + 'static>(
        &self,
        signal: F,
    ) -> impl std::future::Future<Output = ()> + Send + 'static {
        let host = self.clone();
        async move {
            signal.await;
            host.stopping.send_replace(true);
            // Configuration never holds the task registry across vendor awaits.
            // Signalling first prevents any later observer registration.
            let tasks = std::mem::take(&mut *host.tasks.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            for mut task in tasks {
                if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
                    task.abort();
                    tracing::warn!(route = "shutdown", "observer did not stop within grace period");
                    // Abort is cooperative: never await a task that may not yield.
                }
            }
            host.config.write().await.providers.clear();
        }
    }
    async fn instance(&self, name: &str) -> Result<Arc<Instance>> {
        self.config.read().await.providers.get(name).cloned().ok_or_else(|| ProtocolError::NotFound { reason: "unknown provider".into() })
    }
    async fn call<T, F, Fut>(&self, name: &str, gate: Gate, f: F) -> Result<T>
    where
        T: Send,
        F: FnOnce(Arc<dyn Provider>, Credentials) -> Fut + Send,
        Fut: std::future::Future<Output = Result<T>> + Send,
    {
        use tracing::Instrument;
        self.instance(name)
            .await?
            .call(gate, f)
            .instrument(tracing::info_span!("provider_route", provider = name, route = gate.name()))
            .await
    }
    async fn records(&self, cursor: Option<&str>) -> Result<Vec<ObserveRecord>> {
        let replay = {
            let log = self.events.log.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            cursor.and_then(|c| {
                let serial = c.strip_prefix(&format!("{}:", log.epoch))?.parse::<u64>().ok()?;
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
        let mut changed = self.events.changed.subscribe();
        let mut stopping = self.stopping.subscribe();
        loop {
            if *stopping.borrow() {
                return Err(ProtocolError::Unavailable { reason: "host stopping".into(), retry_after: None });
            }
            let instances: Vec<_> = self.config.read().await.providers.values().cloned().collect();
            let mut unavailable_providers = BTreeMap::new();
            for instance in &instances {
                // Push list calls may repair proxied rejection; never gate them on
                // Ready, since call() already decides whether a probe is permitted.
                if instance.poll_interval.is_some()
                    && let Err(error) = instance.ready()
                {
                    unavailable_providers.insert(instance.config.name.clone(), error);
                }
            }
            let push_cursor = {
                let log = self.events.log.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                format!("{}:{}", log.epoch, log.serial)
            };
            let has_push = instances.iter().any(|i| matches!(i.observation, ObservationMode::Push));
            let mut push_rows = vec![];
            for instance in &instances {
                if matches!(instance.observation, ObservationMode::Push) {
                    let rows = tokio::select! {
                        result = instance.call(Gate::List, |p,c| async move {p.list(&c).await}) => match result {
                            Ok(rows) => rows,
                            Err(error) => {
                                unavailable_providers.insert(instance.config.name.clone(), error);
                                continue;
                            }
                        },
                        _ = stopping.changed() => return Err(ProtocolError::Unavailable {reason: "host stopping".into(), retry_after: None}),
                    };
                    push_rows.extend(rows);
                }
            }
            {
                // A poll's inventory and its events are committed under this same lock.
                let log = self.events.log.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let pending = instances.iter().fold(false, |pending, i| {
                    if i.poll_interval.is_none()
                        || unavailable_providers.contains_key(&i.config.name)
                        || log.inventories.contains_key(&i.config.name)
                    {
                        return pending;
                    }
                    if let Some(error) = i.poll_error.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone() {
                        unavailable_providers.insert(i.config.name.clone(), error);
                        return pending;
                    }
                    true
                });
                if !pending {
                    let mut environments: Vec<_> = log
                        .inventories
                        .iter()
                        .filter(|(name, _)| !unavailable_providers.contains_key(*name))
                        .flat_map(|(_, rows)| rows.iter().map(|r| r.environment.clone()))
                        .collect();
                    environments.extend(push_rows.into_iter().map(|r| r.environment));
                    return Ok(ObserveRecord::Snapshot {
                        cursor: if has_push { push_cursor } else { format!("{}:{}", log.epoch, log.serial) },
                        environments,
                        unavailable_providers,
                    });
                }
            }
            tokio::select! {
                _ = changed.changed() => {},
                _ = stopping.changed() => return Err(ProtocolError::Unavailable { reason: "host stopping".into(), retry_after: None }),
            }
        }
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
        tracing::warn!(error_class = self.0.class(), "request failed");
        let (status, retry) = (self.0.status(), self.0.retry_after());
        let mut response = (StatusCode::from_u16(status).expect("protocol error status is valid HTTP"), Json(self.0)).into_response();
        if let Some(seconds) = retry {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, seconds.to_string().parse().expect("decimal retry seconds form a valid header"));
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
    async fn from_request(request: Request, state: &S) -> std::result::Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(request, state).await.map_err(|_| ApiError(refused("invalid JSON request")))?;
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
    async fn from_request_parts(parts: &mut axum::http::request::Parts, state: &S) -> std::result::Result<Self, Self::Rejection> {
        let Path(value) = Path::<T>::from_request_parts(parts, state).await.map_err(|_| ApiError(refused("invalid route identifier")))?;
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
                readiness: i.readiness(&i.auth.lock().unwrap_or_else(std::sync::PoisonError::into_inner)),
                rate_limits: i.rate_limits.clone(),
            })
            .collect(),
    })
}
async fn configure(State(host): State<Host>, ApiJson(request): ApiJson<HostConfiguration>) -> ApiResult<StatusCode> {
    let mut stopping = host.stopping.subscribe();
    let _transaction = tokio::select! {
        biased;
        _ = stopping.wait_for(|stopped| *stopped) => return Err(ProtocolError::Unavailable { reason: "host stopping".into(), retry_after: None }.into()),
        guard = host.configuring.lock() => guard,
    };
    if *host.stopping.borrow() {
        return Err(ProtocolError::Unavailable { reason: "host stopping".into(), retry_after: None }.into());
    }
    let mut config = host.config.read().await.clone();
    // Exact repeats preserve resources and delivered credentials. Changes to live providers
    // are refused: silently replacing one would lose in-memory reference resources.
    let mut modules = BTreeMap::new();
    for m in &request.modules {
        if modules.insert(m.name.clone(), m.entrypoint.clone()).is_some() {
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
            rigging_http_client::ReqwestHttpClient::restricted(proxy, host.proxy_ca.as_deref().map(Vec::as_slice))
                .map_err(|_| refused("invalid HTTP transport configuration"))?,
        );
        let sink = EventSink { shared: host.events.clone(), provider: p.name.clone() };
        let provider = tokio::select! {
            biased;
            _ = stopping.wait_for(|stopped| *stopped) => return Err(ProtocolError::Unavailable { reason: "host stopping".into(), retry_after: None }.into()),
            result = module.configure(p, http) => result?,
        };
        let (credential_changes, _) = watch::channel(credentials.clone());
        let capabilities = provider.capabilities();
        let rate_limits = provider.rate_limits();
        if rate_limits.iter().any(|r| r.requests == 0 || r.period_seconds == 0) {
            return Err(refused("invalid declared rate limit").into());
        }
        let observation = provider.observation();
        let poll_interval = observer::poll_interval(observation, &rate_limits)?;
        additions.insert(
            p.name.clone(),
            Arc::new(Instance {
                config: p.clone(),
                provider,
                auth: Mutex::new(Authentication { credentials, rejected: false, generation: 0 }),
                capabilities,
                rate_limits,
                events: sink,
                observation,
                poll_interval,
                poll_error: Mutex::new(None),
                credential_changes,
                budget: Mutex::new(BTreeMap::new()),
                destroyed: Mutex::new(BTreeMap::new()),
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
        .map(|m| LoadedModule { name: m.name.clone(), version: host.registry[&m.entrypoint].version().into() })
        .collect();
    let mut committed = host.config.write().await;
    if *host.stopping.borrow() {
        return Err(ProtocolError::Unavailable { reason: "host stopping".into(), retry_after: None }.into());
    }
    *committed = config;
    drop(committed);
    // Serialize registration with shutdown's drain, including its stop check.
    let mut tasks = host.tasks.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if *host.stopping.borrow() {
        return Err(ProtocolError::Unavailable { reason: "host stopping".into(), retry_after: None }.into());
    }
    for instance in observers {
        tracing::info!(provider = %instance.config.name, readiness = readiness_status(&instance.readiness(&instance.auth.lock().unwrap_or_else(std::sync::PoisonError::into_inner))), "provider configured");
        let task = observer::spawn(instance, host.stopping.subscribe());
        tasks.push(task);
    }
    Ok(StatusCode::NO_CONTENT)
}
async fn credential(
    State(host): State<Host>,
    ApiPath(p): ApiPath<String>,
    ApiJson(refresh): ApiJson<CredentialRefresh>,
) -> ApiResult<StatusCode> {
    let instance = host.instance(&p).await?;
    let mut auth = instance.auth.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if !matches!(auth.credentials.mode, CredentialMode::Direct { .. }) {
        return Err(refused("proxied provider cannot accept direct credentials").into());
    }
    let before = instance.readiness(&auth);
    auth.credentials.value = Some(refresh.value);
    auth.generation += 1;
    auth.rejected = false;
    *instance.poll_error.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    instance.credential_changes.send_replace(auth.credentials.clone());
    let after = instance.readiness(&auth);
    if before != after {
        tracing::info!(provider = %p, route = "credential", readiness = readiness_status(&after), "provider readiness changed");
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn prepare(State(h): State<Host>, ApiPath(p): ApiPath<String>, ApiJson(r): ApiJson<PrepareRequest>) -> ApiResult<Json<Prepared>> {
    Ok(Json(h.call(&p, Gate::Prepare, |p, c| async move { p.prepare(r, &c).await }).await?))
}
async fn provision(State(h): State<Host>, ApiPath(p): ApiPath<String>, ApiJson(r): ApiJson<ProvisionRequest>) -> ApiResult<Response> {
    if r.prepared.provider != p {
        return Err(refused("invalid size, label or prepared provider").into());
    }
    let result = h.call(&p, Gate::Provision, |p, c| async move { p.provision(r, &c).await }).await?;
    Ok(match result {
        Provisioned::Created(s) => (StatusCode::CREATED, Json(s)),
        Provisioned::Existing(s) => (StatusCode::OK, Json(s)),
    }
    .into_response())
}
async fn list(State(h): State<Host>, ApiPath(p): ApiPath<String>) -> ApiResult<Json<Vec<Environment>>> {
    Ok(Json(h.call(&p, Gate::List, |p, c| async move { p.list(&c).await }).await?.into_iter().map(|r| r.environment).collect()))
}
async fn inspect(State(h): State<Host>, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Environment>> {
    let instance = h.instance(&p).await?;
    let row = instance.call(Gate::Inspect, |p, c| async move { p.inspect(&id, &c).await }).await?;
    if row.timestamp.is_some() && instance.poll_interval.is_some() {
        instance.inspected.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(row.environment.id.clone(), row.clone());
    }
    Ok(Json(row.environment))
}
async fn destroy(State(h): State<Host>, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<StatusCode> {
    let instance = h.instance(&p).await?;
    let mut attempt = DestroyAttempt::begin(instance.clone(), id.clone());
    let result = instance.call(Gate::Destroy, |p, c| async move { p.destroy(&id, &c).await }).await;
    attempt.finish(result.is_ok());
    result?;
    Ok(StatusCode::NO_CONTENT)
}
async fn reach(State(h): State<Host>, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Reach>> {
    let environment = id.clone();
    let connection = h.call(&p, Gate::Reach, |p, c| async move { p.reach(&id, &c).await }).await?;
    let reach = match connection {
        Connection::Relay => {
            let mut url = url::Url::parse("http://localhost").expect("static URL");
            url.path_segments_mut().expect("base URL").extend(["v1", "providers", &p, "environments", &environment, "relay"]);
            Reach::Relay { path: url.path().into() }
        }
        Connection::Ssh { endpoint, user, host_key } => Reach::Ssh { endpoint, user, host_key },
        Connection::Dial { url, token, expires_at } => Reach::Dial { url, token, expires_at },
    };
    Ok(Json(reach))
}
async fn suspend(State(h): State<Host>, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<ResumeToken>> {
    Ok(Json(h.call(&p, Gate::Suspend, |p, c| async move { p.suspend(&id, &c).await }).await?))
}
async fn resume(
    State(h): State<Host>,
    ApiPath((p, id)): ApiPath<(String, String)>,
    ApiJson(token): ApiJson<ResumeToken>,
) -> ApiResult<StatusCode> {
    h.call(&p, Gate::Resume, |p, c| async move { p.resume(&id, token, &c).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn export(State(h): State<Host>, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Export>> {
    Ok(Json(h.call(&p, Gate::Export, |p, c| async move { p.export(&id, &c).await }).await?))
}
async fn usage(
    State(h): State<Host>,
    ApiPath(p): ApiPath<String>,
    query: std::result::Result<Query<Period>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<Usage>> {
    let Query(period) = query.map_err(|_| refused("invalid usage period"))?;
    Ok(Json(h.call(&p, Gate::Usage, |p, c| async move { p.usage(period, &c).await }).await?))
}
async fn quota(State(h): State<Host>, ApiPath(p): ApiPath<String>) -> ApiResult<Json<Quota>> {
    Ok(Json(h.call(&p, Gate::Quota, |p, c| async move { p.quota(&c).await }).await?))
}

fn validate_upgrade(request: &Request, protocol: &str) -> Result<()> {
    let headers = request.headers();
    if !headers.get(header::UPGRADE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case(protocol))
        || !headers
            .get(header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|v| v.trim().eq_ignore_ascii_case("upgrade")))
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
) -> Response {
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
    (StatusCode::SWITCHING_PROTOCOLS, [(header::CONNECTION, "Upgrade"), (header::UPGRADE, protocol)]).into_response()
}
struct ExecUpgrade {
    upgrade: hyper::upgrade::OnUpgrade,
    command: ExecRequest,
}
impl<S: Send + Sync> axum::extract::FromRequest<S> for ExecUpgrade {
    type Rejection = ApiError;
    async fn from_request(mut request: Request, state: &S) -> std::result::Result<Self, Self::Rejection> {
        validate_upgrade(&request, "drydock-stream")?;
        let upgrade = hyper::upgrade::on(&mut request);
        let ApiJson(command) = ApiJson::<ExecRequest>::from_request(request, state).await?;
        Ok(Self { upgrade, command })
    }
}
async fn relay(State(h): State<Host>, ApiPath((p, id)): ApiPath<(String, String)>, mut request: Request) -> ApiResult<Response> {
    validate_upgrade(&request, "drydock-relay")?;
    let on = hyper::upgrade::on(&mut request);
    let stream = h.call(&p, Gate::Relay, |p, c| async move { p.relay(&id, &c).await }).await?;
    Ok(upgrade(on, "drydock-relay", stream, h.stopping.subscribe()))
}
async fn exec(State(h): State<Host>, ApiPath((p, id)): ApiPath<(String, String)>, request: ExecUpgrade) -> ApiResult<Response> {
    let stream = h.call(&p, Gate::Exec, |p, c| async move { p.exec(&id, request.command, &c).await }).await?;
    Ok(upgrade(request.upgrade, "drydock-stream", stream, h.stopping.subscribe()))
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
                        if *stopping.borrow() { break; }
                        // Protocol v1 permits only Event/Snapshot records. Fail the HTTP
                        // body rather than invent a terminal record or signal clean EOF.
                        yield Err(std::io::Error::other(error.class()));
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
    Ok(([(header::CONTENT_TYPE, "application/x-ndjson")], Body::from_stream(stream)).into_response())
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

async fn trace_request(request: Request, next: Next) -> Response {
    use tracing::Instrument;
    let route = request.extensions().get::<axum::extract::MatchedPath>().map(|p| p.as_str()).unwrap_or("unknown").to_owned();
    let parts: Vec<_> = request.uri().path().split('/').collect();
    let provider = if parts.get(2) == Some(&"providers") { parts.get(3).copied().unwrap_or("") } else { "" };
    let environment_id = if parts.get(4) == Some(&"environments") { parts.get(5).copied().unwrap_or("") } else { "" };
    let span = tracing::info_span!("request", route, provider, environment_id);
    async move {
        let response = next.run(request).await;
        tracing::info!(status = response.status().as_u16(), "request completed");
        response
    }
    .instrument(span)
    .await
}

fn readiness_status(value: &Readiness) -> &'static str {
    match value {
        Readiness::Ready => "ready",
        Readiness::MissingTool { .. } => "missing_tool",
        Readiness::MissingCredential { .. } => "missing_credential",
        Readiness::VersionMismatch { .. } => "version_mismatch",
        Readiness::Unknown { .. } => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Glue: once shutdown starts, the configuration path must refuse even an
    // empty document rather than creating a new generation of observers.
    #[tokio::test]
    async fn configuration_after_shutdown_is_unavailable() {
        let host = Host::new(reference::registry());
        host.shutdown(async {}).await;
        let result = configure(State(host), ApiJson(HostConfiguration { modules: vec![], providers: vec![] })).await;
        assert!(matches!(result, Err(ApiError(ProtocolError::Unavailable { .. }))));
    }
    // A vendor factory that never returns must not hold shutdown behind its transaction.
    #[tokio::test]
    async fn shutdown_cancels_hung_configuration() {
        struct HangingModule(Arc<tokio::sync::Notify>);
        #[async_trait::async_trait]
        impl module::Module for HangingModule {
            fn version(&self) -> &str {
                "test"
            }
            async fn configure(&self, _: &ProviderConfiguration, _: Arc<dyn module::HttpClient>) -> Result<Arc<dyn Provider>> {
                self.0.notify_one();
                std::future::pending().await
            }
        }
        let entered = Arc::new(tokio::sync::Notify::new());
        let host = Host::new(Registry::from([("hanging".into(), Arc::new(HangingModule(entered.clone())) as Arc<dyn module::Module>)]));
        let request = serde_json::from_value(serde_json::json!({
            "modules": [{"name":"test", "entrypoint":"hanging"}],
            "providers": [{"name":"a", "module":"test", "settings":{}, "credential":{"mode":"direct","credential_reference":"test"}}]
        }))
        .unwrap();
        let configuring = tokio::spawn(configure(State(host.clone()), ApiJson(request)));
        entered.notified().await;
        tokio::time::timeout(std::time::Duration::from_secs(1), host.shutdown(async {}))
            .await
            .expect("shutdown must cancel a hung factory");
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), configuring)
            .await
            .expect("configuration must observe shutdown")
            .unwrap();
        assert!(matches!(result, Err(ApiError(ProtocolError::Unavailable { .. }))));
        assert!(host.config.read().await.providers.is_empty());
    }

    // Several uncooperative observers share one grace period, independent of count.
    #[tokio::test(start_paused = true)]
    async fn shutdown_observers_share_grace_period() {
        for count in [0, 1, 4] {
            let host = Host::new(reference::registry());
            for _ in 0..count {
                host.tasks.lock().unwrap().push(tokio::spawn(std::future::pending()));
            }
            let start = tokio::time::Instant::now();
            host.shutdown(async {}).await;
            assert!(start.elapsed() <= std::time::Duration::from_secs(5), "observers must share one deadline");
        }
    }
    // Abort cannot force a task out of a blocking vendor poll. Shutdown returns
    // after grace even while that observer still occupies its executor thread.
    #[tokio::test(start_paused = true)]
    async fn shutdown_does_not_await_aborted_non_yielding_observer() {
        let (handle_tx, handle_rx) = std::sync::mpsc::channel();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        // Isolate the deliberately blocking vendor boundary from the test clock.
        let worker = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
            runtime.block_on(async {
                let task = tokio::spawn(async move {
                    entered_tx.send(()).unwrap();
                    let _ = release_rx.recv();
                });
                handle_tx.send(task).unwrap();
                let _ = done_rx.await;
            });
        });
        let host = Host::new(reference::registry());
        host.tasks.lock().unwrap().push(handle_rx.recv().unwrap());
        entered_rx.recv().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(6), host.shutdown(async {}))
            .await
            .expect("shutdown must not await abort completion");
        drop(release_tx);
        let _ = done_tx.send(());
        worker.join().unwrap();
    }
}

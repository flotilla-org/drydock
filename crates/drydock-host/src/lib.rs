//! Reference Rust language host. See the crate README for module and serving contracts.
pub mod module;
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
use module::{Credentials, Provider, Registry, Result, refused};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, RwLock, watch};

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
        timestamp: String,
        source: TimestampSource,
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
            timestamp,
            timestamp_source: source,
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
    provider: Arc<AsyncMutex<Box<dyn Provider>>>,
    // Short synchronous access only: release this guard before every await.
    auth: Mutex<Authentication>,
    capabilities: Capabilities,
    rate_limits: Vec<RateLimit>,
}
// Provider operations own a credential snapshot, so refresh never waits for vendor I/O.
struct Session {
    instance: Arc<Instance>,
    provider: OwnedMutexGuard<Box<dyn Provider>>,
    credentials: Credentials,
    generation: u64,
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
            .with_state(self.clone())
            .layer(middleware::from_fn(
                |request: Request, next: Next| async move {
                    let response = next.run(request).await;
                    // Module responses use ProtocolError statuses. Normalize only HTTP
                    // extraction/routing failures; never echo their diagnostics.
                    match response.status() {
                        StatusCode::BAD_REQUEST
                        | StatusCode::METHOD_NOT_ALLOWED
                        | StatusCode::PAYLOAD_TOO_LARGE
                        | StatusCode::UNSUPPORTED_MEDIA_TYPE => {
                            ApiError(refused("invalid request or unsupported method"))
                                .into_response()
                        }
                        _ => response,
                    }
                },
            ))
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
    async fn instance(&self, name: &str) -> Result<Session> {
        let instance = self
            .config
            .read()
            .await
            .providers
            .get(name)
            .cloned()
            .ok_or_else(|| refused("unknown provider"))?;
        let provider = instance.provider.clone().lock_owned().await;
        let (credentials, generation) = {
            let auth = instance
                .auth
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (auth.credentials.clone(), auth.generation)
        };
        Ok(Session {
            instance,
            provider,
            credentials,
            generation,
        })
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
            let mut session = self.instance(&name).await?;
            ready(&session)?;
            let result = session.provider.list(&session.credentials).await;
            sandboxes.extend(outcome(&mut session, result)?);
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
        let (status, retry) = match &self.0 {
            ProtocolError::Refused { .. } => (422, None),
            ProtocolError::Unavailable { retry_after, .. } => (503, *retry_after),
            ProtocolError::RateLimited { retry_after, .. } => (429, *retry_after),
            ProtocolError::QuotaExhausted { .. } => (402, None),
            ProtocolError::CredentialRejected { .. } => (502, None),
            ProtocolError::Internal { .. } => (500, None),
        };
        let mut response = (StatusCode::from_u16(status).unwrap(), Json(self.0)).into_response();
        if let Some(seconds) = retry {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, seconds.to_string().parse().unwrap());
        }
        response
    }
}
type ApiResult<T> = std::result::Result<T, ApiError>;
// Never return serde's diagnostics: malformed secret fields could otherwise appear in errors.
fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|_| refused("invalid JSON request"))
}
fn outcome<T>(session: &mut Session, result: Result<T>) -> Result<T> {
    let mut auth = session
        .instance
        .auth
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // An old rejected request must not undo a concurrently delivered refresh.
    if auth.generation == session.generation {
        auth.readiness = if matches!(result, Err(ProtocolError::CredentialRejected { .. })) {
            Readiness::MissingCredential {
                reason: "credential rejected".into(),
            }
        } else {
            session.provider.readiness(&auth.credentials)
        };
    }
    result
}
fn ready(session: &Session) -> Result<()> {
    let auth = session
        .instance
        .auth
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match &auth.readiness {
        Readiness::Ready => Ok(()),
        Readiness::MissingCredential { reason } => Err(ProtocolError::CredentialRejected {
            reason: reason.clone(),
        }),
        Readiness::MissingTool { reason }
        | Readiness::VersionMismatch { reason }
        | Readiness::Unknown { reason } => Err(ProtocolError::Unavailable {
            reason: reason.clone(),
            retry_after: None,
        }),
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
async fn configure(State(host): State<Host>, body: Bytes) -> ApiResult<StatusCode> {
    let request: HostConfiguration = decode(&body)?;
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
        let credentials = Credentials::new(
            p.credential.clone(),
            host.proxy_ca.as_deref().map(Vec::as_slice),
        )?;
        let mut sink = host.events.clone();
        sink.provider = p.name.clone();
        let provider = module.configure(p, sink).await?;
        let readiness = provider.readiness(&credentials);
        let capabilities = provider.capabilities();
        let rate_limits = provider.rate_limits();
        additions.insert(
            p.name.clone(),
            Arc::new(Instance {
                config: p.clone(),
                provider: Arc::new(AsyncMutex::new(provider)),
                auth: Mutex::new(Authentication {
                    credentials,
                    readiness,
                    generation: 0,
                }),
                capabilities,
                rate_limits,
            }),
        );
    }
    config.entrypoints = modules;
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
    Ok(StatusCode::NO_CONTENT)
}
async fn credential(
    State(host): State<Host>,
    Path(p): Path<String>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let refresh: CredentialRefresh = decode(&body)?;
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
    if matches!(auth.readiness, Readiness::MissingCredential { .. }) {
        auth.readiness = Readiness::Ready;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn prepare(
    State(host): State<Host>,
    Path(p): Path<String>,
    body: Bytes,
) -> ApiResult<Json<Prepared>> {
    let request: PrepareRequest = decode(&body)?;
    if request.image_digest.is_empty() || request.tools_digest.is_empty() {
        return Err(refused("digests must not be empty").into());
    }
    let mut i = host.instance(&p).await?;
    ready(&i)?;
    let result = i.provider.prepare(request, &i.credentials).await;
    Ok(Json(outcome(&mut i, result)?))
}
fn valid_host(host: &str) -> bool {
    if host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .is_some_and(|s| s.parse::<std::net::Ipv6Addr>().is_ok())
    {
        return true;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let dns = host.strip_suffix('.').unwrap_or(host);
    !dns.is_empty()
        && dns.len() <= 253
        && dns.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn validate_provision(p: &str, r: &ProvisionRequest) -> Result<()> {
    if r.prepared.provider != p
        || r.label.is_empty()
        || !r.size.cpus.is_finite()
        || r.size.cpus <= 0.0
    {
        return Err(refused("invalid size, label or prepared provider"));
    }
    if let EgressRequest::DenyAll { direct } = &r.egress {
        for d in direct {
            let valid = match d {
                Destination::HostPort { host, port } => *port > 0 && valid_host(host),
                Destination::Cidr { cidr } => cidr.split_once('/').is_some_and(|(ip, bits)| {
                    ip.parse::<std::net::IpAddr>().is_ok_and(|ip| {
                        bits.parse::<u8>()
                            .is_ok_and(|bits| bits <= if ip.is_ipv4() { 32 } else { 128 })
                    })
                }),
            };
            if !valid {
                return Err(refused("invalid direct destination"));
            }
        }
    }
    Ok(())
}
async fn provision(
    State(host): State<Host>,
    Path(p): Path<String>,
    body: Bytes,
) -> ApiResult<Response> {
    let request: ProvisionRequest = decode(&body)?;
    validate_provision(&p, &request)?;
    let mut i = host.instance(&p).await?;
    ready(&i)?;
    let result = i.provider.provision(request, &i.credentials).await;
    let (sandbox, created) = outcome(&mut i, result)?;
    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(sandbox),
    )
        .into_response())
}
macro_rules! simple {
    ($name:ident, $output:ty) => {
        async fn $name(
            State(host): State<Host>,
            Path((p, id)): Path<(String, String)>,
        ) -> ApiResult<Json<$output>> {
            let mut i = host.instance(&p).await?;
            ready(&i)?;
            let result = i.provider.$name(&id, &i.credentials).await;
            Ok(Json(outcome(&mut i, result)?))
        }
    };
}
simple!(inspect, Sandbox);
simple!(reach, Reach);
async fn list(State(host): State<Host>, Path(p): Path<String>) -> ApiResult<Json<Vec<Sandbox>>> {
    let mut i = host.instance(&p).await?;
    ready(&i)?;
    let result = i.provider.list(&i.credentials).await;
    Ok(Json(outcome(&mut i, result)?))
}
async fn destroy(
    State(host): State<Host>,
    Path((p, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let mut i = host.instance(&p).await?;
    ready(&i)?;
    let result = i.provider.destroy(&id, &i.credentials).await;
    outcome(&mut i, result)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn suspend(
    State(host): State<Host>,
    Path((p, id)): Path<(String, String)>,
) -> ApiResult<Json<ResumeToken>> {
    let mut i = host.instance(&p).await?;
    ready(&i)?;
    if !i.provider.capabilities().suspend_resume {
        return Err(refused("suspend unsupported").into());
    }
    let result = i.provider.suspend(&id, &i.credentials).await;
    Ok(Json(outcome(&mut i, result)?))
}
async fn resume(
    State(host): State<Host>,
    Path((p, id)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let token = decode(&body)?;
    let mut i = host.instance(&p).await?;
    ready(&i)?;
    if !i.provider.capabilities().suspend_resume {
        return Err(refused("resume unsupported").into());
    }
    let result = i.provider.resume(&id, token, &i.credentials).await;
    outcome(&mut i, result)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn export(
    State(host): State<Host>,
    Path((p, id)): Path<(String, String)>,
) -> ApiResult<Json<Export>> {
    let mut i = host.instance(&p).await?;
    ready(&i)?;
    if !i.provider.capabilities().export {
        return Err(refused("export unsupported").into());
    }
    let result = i.provider.export(&id, &i.credentials).await;
    Ok(Json(outcome(&mut i, result)?))
}
fn valid_period(period: &Period) -> bool {
    match (
        chrono::DateTime::parse_from_rfc3339(&period.start),
        chrono::DateTime::parse_from_rfc3339(&period.end),
    ) {
        (Ok(a), Ok(b)) => a <= b,
        _ => false,
    }
}
#[derive(Deserialize)]
struct UsageQuery {
    start: String,
    end: String,
}
async fn usage(
    State(host): State<Host>,
    Path(p): Path<String>,
    query: std::result::Result<Query<UsageQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<Usage>> {
    let Query(q) = query.map_err(|_| refused("invalid usage period"))?;
    let period = Period {
        start: q.start,
        end: q.end,
    };
    if !valid_period(&period) {
        return Err(refused("invalid usage period").into());
    }
    let mut i = host.instance(&p).await?;
    ready(&i)?;
    if !i.provider.capabilities().usage {
        return Err(refused("usage unsupported").into());
    }
    let result = i.provider.usage(period, &i.credentials).await;
    let usage = outcome(&mut i, result)?;
    if !valid_period(&usage.period)
        || usage.sandbox_hours.iter().any(|s| {
            !s.hours.is_finite() || s.hours < 0.0 || !s.size.cpus.is_finite() || s.size.cpus <= 0.0
        })
    {
        return Err(internal("module returned invalid usage").into());
    }
    Ok(Json(usage))
}
async fn quota(State(host): State<Host>, Path(p): Path<String>) -> ApiResult<Json<Quota>> {
    let mut i = host.instance(&p).await?;
    ready(&i)?;
    if !i.provider.capabilities().quota {
        return Err(refused("quota unsupported").into());
    }
    let result = i.provider.quota(&i.credentials).await;
    let quota = outcome(&mut i, result)?;
    if quota.credits_remaining.is_some_and(|v| !v.is_finite()) {
        return Err(internal("module returned nonfinite credits").into());
    }
    Ok(Json(quota))
}
fn internal(reason: &str) -> ProtocolError {
    ProtocolError::Internal {
        reason: reason.into(),
        provider_error: String::new(),
    }
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
    request: &mut Request,
    protocol: &'static str,
    stream: module::ByteStream,
    mut stopping: watch::Receiver<bool>,
) -> Result<Response> {
    let on_upgrade = hyper::upgrade::on(request);
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
async fn relay(
    State(host): State<Host>,
    Path((p, id)): Path<(String, String)>,
    mut request: Request,
) -> ApiResult<Response> {
    validate_upgrade(&request, "drydock-relay")?;
    let mut i = host.instance(&p).await?;
    ready(&i)?;
    let result = i.provider.relay(&id, &i.credentials).await;
    let stream = outcome(&mut i, result)?;
    Ok(upgrade(
        &mut request,
        "drydock-relay",
        stream,
        host.stopping.subscribe(),
    )?)
}
async fn exec(
    State(host): State<Host>,
    Path((p, id)): Path<(String, String)>,
    request: Request,
) -> ApiResult<Response> {
    validate_upgrade(&request, "drydock-stream")?;
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .map_err(|_| refused("exec body too large"))?;
    let command: ExecRequest = decode(&bytes)?;
    if command.command.is_empty() {
        return Err(refused("empty command").into());
    }
    let mut request = Request::from_parts(parts, Body::empty());
    let mut i = host.instance(&p).await?;
    ready(&i)?;
    if !i.provider.capabilities().fallback_runner {
        return Err(refused("exec unsupported").into());
    }
    let result = i.provider.exec(&id, command, &i.credentials).await;
    let stream = outcome(&mut i, result)?;
    Ok(upgrade(
        &mut request,
        "drydock-stream",
        stream,
        host.stopping.subscribe(),
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

#[cfg(test)]
mod tests {
    use super::*;
    // IPv4 and IPv6 destinations, including bracketed IPv6, are accepted; appending
    // URL syntax cannot turn an invalid host into a direct network destination.
    #[hegel::test]
    fn generated_ip_destination_syntax(tc: hegel::TestCase) {
        use hegel::generators as gs;
        let octets: Vec<_> = (0..4)
            .map(|_| tc.draw(gs::integers::<u8>().min_value(0).max_value(255)))
            .collect();
        let ipv4 = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
        let tail = tc.draw(gs::integers::<u16>().min_value(0).max_value(u16::MAX));
        let ipv6 = format!("2001:db8::{tail:x}");
        assert!(valid_host(&ipv4));
        assert!(valid_host(&ipv6));
        assert!(valid_host(&format!("[{ipv6}]")));
        assert!(!valid_host(&format!("{ipv4}/path")));
        assert!(!valid_host(&format!("[{ipv4}]")));
    }
}

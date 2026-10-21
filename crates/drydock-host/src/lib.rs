//! Reference Rust language host. See the crate README for module and serving contracts.
pub mod daytona;
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

trait RecoverLock<T> {
    fn recover(&self) -> std::sync::MutexGuard<'_, T>;
}
impl<T> RecoverLock<T> for Mutex<T> {
    fn recover(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// One deadline for every push list in an initial or recovery snapshot.
pub const PUSH_SNAPSHOT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
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
        let mut log = self.shared.log.recover();
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
        let mut log = self.shared.log.recover();
        log.inventories.insert(self.provider.clone(), rows);
        for (id, label, timestamp, event) in events {
            Self::append(&mut log, &self.provider, id, label, timestamp, event);
        }
        self.shared.changed.send_replace(log.serial);
    }
}
type PendingEvent = (String, Option<String>, Option<chrono::DateTime<chrono::Utc>>, EventKind);
// Keep active values plus a bounded recent history, shared across providers.
// Derive patterns at delivery; rebuild only when an old value is evicted.
const RECENT_CREDENTIAL_LIMIT: usize = 32;
#[derive(Default)]
struct DiagnosticSecrets {
    current: BTreeMap<String, Secret>,
    recent: VecDeque<Secret>,
    masker: Arc<DiagnosticMasker>,
}
impl DiagnosticSecrets {
    fn contains(&self, secret: &Secret) -> bool {
        self.current.values().any(|value| value == secret) || self.recent.contains(secret)
    }
    fn remember(&mut self, provider: &str, secret: Secret) {
        if self.current.get(provider) == Some(&secret) {
            return;
        }
        let known = self.contains(&secret);
        if let Some(previous) = self.current.insert(provider.to_owned(), secret.clone()) {
            self.recent.retain(|value| value != &previous);
            if !self.current.values().any(|value| value == &previous) {
                self.recent.push_back(previous);
            }
        }
        self.recent.retain(|value| value != &secret);
        let evicted = self.recent.len() > RECENT_CREDENTIAL_LIMIT;
        if evicted {
            self.recent.pop_front();
            self.masker = Arc::default();
            for value in self.current.values().chain(self.recent.iter()) {
                Arc::make_mut(&mut self.masker).remember(value.expose());
            }
        } else if !known {
            Arc::make_mut(&mut self.masker).remember(secret.expose());
        }
        if !known && (1..4).contains(&secret.expose().len()) {
            tracing::debug!(
                credential_bytes = secret.expose().len(),
                "short credential registered; diagnostic masking may obscure unrelated text"
            );
        }
    }
}
struct Authentication {
    credentials: Credentials,
    generation: u64,
    rejected: bool,
    rejection_error: Option<ProtocolError>,
}
struct Instance {
    diagnostic_secrets: Arc<Mutex<DiagnosticSecrets>>,
    config: ProviderConfiguration,
    provider: Arc<dyn Provider>,
    // Synchronous metadata access only; never hold this guard across await.
    auth: Mutex<Authentication>,
    capabilities: Capabilities,
    rate_limits: Vec<RateLimit>,
    poll_waiting: Mutex<BTreeSet<String>>,
    budget: Mutex<BTreeMap<String, VecDeque<tokio::time::Instant>>>,
    events: EventSink,
    observation: ObservationMode,
    poll_interval: Option<std::time::Duration>,
    poll_error: Mutex<Option<ProtocolError>>,
    credential_changes: watch::Sender<Credentials>,
    destroyed: Mutex<BTreeMap<String, DestroyState>>,
    inspected: Mutex<BTreeMap<String, ObservedEnvironment>>,
    observation_generation: Mutex<u64>,
    egress_measured_at: Mutex<BTreeMap<String, tokio::time::Instant>>,
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
            instance.destroyed.recover().entry(id.clone()).or_default().pending += 1;
        }
        Self { instance, id, active }
    }
    fn finish(&mut self, confirmed: bool) {
        if !self.active {
            return;
        }
        let mut states = self.instance.destroyed.recover();
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
                CredentialMode::Direct { .. } => Availability {
                    readiness: Readiness::MissingCredential {
                        reason: auth.rejection_error.as_ref().map(ToString::to_string).unwrap_or_else(|| "credential rejected".into()),
                    },
                    may_call: false,
                },
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
        let auth = self.auth.recover();
        if matches!(self.readiness(&auth), Readiness::Ready) {
            Ok(())
        } else {
            if auth.rejected
                && let Some(error @ ProtocolError::CredentialRejected { .. }) = self.poll_error.recover().clone()
            {
                return Err(error);
            }
            Err(ProtocolError::unavailable("provider is not ready; inspect hello", None))
        }
    }

    async fn call<T, F, Fut>(&self, gate: Gate, f: F) -> Result<T>
    where
        T: Send,
        F: FnOnce(Arc<dyn Provider>, Credentials) -> Fut + Send,
        Fut: std::future::Future<Output = Result<T>> + Send,
    {
        use tracing::Instrument;
        self.call_with_budget(gate, false, f)
            .instrument(tracing::info_span!("provider_route", provider = %self.config.name, route = gate.name()))
            .await
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
            let auth = self.auth.recover();
            // Routes and polls use exactly the same admission gate. Direct
            // rejection blocks both; proxied rejection permits both to probe.
            // A pending observation reservation can safely survive unready time:
            // no route can resume while polling remains disabled by readiness.
            let availability = self.availability(&auth);
            if !availability.may_call {
                if auth.rejected
                    && matches!(auth.credentials.mode, CredentialMode::Direct { .. })
                    && let Some(error) = &auth.rejection_error
                {
                    // Already masked and contextualized at the original failure.
                    return Err(ProtocolError::unavailable(error.to_string(), None));
                }
                let reason = format!("provider is not ready: {:?}", availability.readiness);
                return Err(self.diagnostic_error(ProtocolError::unavailable(reason, None), gate.name()));
            }
            (auth.credentials.clone(), auth.generation)
        };
        if !gate.supported(&self.capabilities) {
            return Err(refused("operation capability not declared"));
        }
        self.reserve(gate.name(), poll)?;
        let call_token = credentials.token().cloned();
        let result = f(self.provider.clone(), credentials)
            .await
            .map_err(|error| self.diagnostic_error_for_token(error, gate.name(), call_token.as_ref()));
        if let Err(error) = &result {
            tracing::warn!(provider = %self.config.name, route = gate.name(), error_class = error.class(), error = %error, "provider call failed");
        }
        let mut auth = self.auth.recover();
        let before = self.readiness(&auth);
        if auth.generation == generation {
            if poll {
                *self.poll_error.recover() = result.as_ref().err().cloned();
            }
            if matches!(result, Err(ProtocolError::CredentialRejected { .. })) {
                auth.rejection_error = result.as_ref().err().cloned();
                auth.rejected = true;
                auth.generation += 1; // invalidate every call started before this rejection
            } else if result.is_ok() && auth.rejected && matches!(auth.credentials.mode, CredentialMode::Proxied { .. }) {
                auth.rejected = false;
                auth.rejection_error = None;
                auth.generation += 1; // only a probe started after rejection can repair it
            }
        }
        let after = self.readiness(&auth);
        if before != after {
            tracing::info!(provider = %self.config.name, route = gate.name(), readiness = readiness_status(&after), "provider readiness changed");
        }
        result
    }
    fn diagnostic_error(&self, error: ProtocolError, operation: &str) -> ProtocolError {
        self.diagnostic_error_for_token(error, operation, None)
    }
    fn diagnostic_error_for_token(&self, error: ProtocolError, operation: &str, token: Option<&Secret>) -> ProtocolError {
        let (mut masker, missing_token) = {
            let secrets = self.diagnostic_secrets.recover();
            (secrets.masker.clone(), token.filter(|token| !secrets.contains(token)))
        };
        if let Some(token) = missing_token {
            // A long-running call may outlive the recent-generation window.
            Arc::make_mut(&mut masker).remember(token.expose());
        }
        masker.context(error, &self.config.name, operation)
    }

    fn longest_window(&self, operation: &str) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.rate_limits.iter().filter(|r| r.operation == operation).map(|r| r.period_seconds).max().unwrap_or(0),
        )
    }
    fn reserve(&self, operation: &'static str, poll: bool) -> Result<()> {
        let mut budget = self.budget.recover();
        let mut waiting = self.poll_waiting.recover();
        let now = tokio::time::Instant::now();
        let limits: Vec<_> = self.rate_limits.iter().filter(|r| r.operation == operation || r.operation == "*").collect();
        for limit in &limits {
            let longest = self.longest_window(&limit.operation);
            if !poll && limit.requests == 1 && waiting.contains(&limit.operation) {
                return Err(ProtocolError::RateLimited {
                    reason: "slot reserved for pending observation".into(),
                    retry_after: Some(limit.period_seconds),
                });
            }
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
                if poll && limit.requests == 1 {
                    waiting.insert(limit.operation.clone());
                }
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
                waiting.remove(&scope);
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
    diagnostic_secrets: Arc<Mutex<DiagnosticSecrets>>,
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
            diagnostic_secrets: Arc::default(),
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
            let tasks = std::mem::take(&mut *host.tasks.recover());
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            for mut task in tasks {
                if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
                    task.abort();
                    tracing::warn!(
                        route = "shutdown",
                        "observer exceeded grace period; aborted without waiting, non-yielding work may remain"
                    );
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
        self.instance(name).await?.call(gate, f).await
    }
    async fn records(&self, cursor: Option<&str>) -> Result<Vec<ObserveRecord>> {
        let replay = {
            let log = self.events.log.recover();
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
        if *stopping.borrow() {
            return Err(ProtocolError::unavailable("host stopping", None));
        }
        let instances: Vec<_> = self.config.read().await.providers.values().cloned().collect();
        let mut push_errors = BTreeMap::new();
        let push_cursor = {
            let log = self.events.log.recover();
            format!("{}:{}", log.epoch, log.serial)
        };
        let has_push = instances.iter().any(|i| matches!(i.observation, ObservationMode::Push));
        let deadline = tokio::time::Instant::now() + PUSH_SNAPSHOT_TIMEOUT;
        let lists = instances.iter().filter(|i| matches!(i.observation, ObservationMode::Push)).map(|instance| async move {
            let result = tokio::time::timeout_at(deadline, instance.call(Gate::List, |p, c| async move { p.list(&c).await }))
                .await
                .unwrap_or_else(|_| Err(ProtocolError::unavailable("snapshot list timed out", None)));
            (instance.config.name.clone(), result)
        });
        let results = tokio::select! {
            results = futures::future::join_all(lists) => results,
            _ = stopping.changed() => return Err(ProtocolError::unavailable("host stopping", None)),
        };
        let mut push_rows = vec![];
        for (name, result) in results {
            match result {
                Ok(rows) => push_rows.extend(rows),
                Err(error) => {
                    push_errors.insert(name, error);
                }
            }
        }
        loop {
            if *stopping.borrow() {
                return Err(ProtocolError::unavailable("host stopping", None));
            }
            let mut unavailable_providers = push_errors.clone();
            for instance in &instances {
                // Push list calls may repair proxied rejection; never gate them on
                // Ready, since call() already decides whether a probe is permitted.
                if instance.poll_interval.is_some()
                    && let Err(error) = instance.ready()
                {
                    unavailable_providers.insert(instance.config.name.clone(), error);
                }
            }
            {
                // A poll's inventory and its events are committed under this same lock.
                let log = self.events.log.recover();
                let mut pending = false;
                for i in &instances {
                    if i.poll_interval.is_none()
                        || unavailable_providers.contains_key(&i.config.name)
                        || log.inventories.contains_key(&i.config.name)
                    {
                        continue;
                    }
                    if let Some(error) = i.poll_error.recover().clone() {
                        unavailable_providers.insert(i.config.name.clone(), error);
                        continue;
                    }
                    pending = true;
                }
                if !pending {
                    let mut environments: Vec<_> = log
                        .inventories
                        .iter()
                        .filter(|(name, _)| !unavailable_providers.contains_key(*name))
                        .flat_map(|(_, rows)| rows.iter().map(|r| r.environment.clone()))
                        .collect();
                    environments.extend(push_rows.iter().map(|r| r.environment.clone()));
                    return Ok(ObserveRecord::Snapshot {
                        cursor: if has_push { push_cursor } else { format!("{}:{}", log.epoch, log.serial) },
                        environments,
                        unavailable_providers,
                    });
                }
            }
            tokio::select! {
                _ = changed.changed() => {},
                _ = stopping.changed() => return Err(ProtocolError::unavailable("host stopping", None)),
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
fn mask_readiness(readiness: Readiness, masker: &DiagnosticMasker) -> Readiness {
    match readiness {
        Readiness::MissingCredential { reason } => Readiness::MissingCredential { reason: masker.text(&reason) },
        Readiness::MissingTool { reason } => Readiness::MissingTool { reason: masker.text(&reason) },
        Readiness::VersionMismatch { reason } => Readiness::VersionMismatch { reason: masker.text(&reason) },
        Readiness::Unknown { reason } => Readiness::Unknown { reason: masker.text(&reason) },
        Readiness::Ready => Readiness::Ready,
    }
}
async fn hello(State(host): State<Host>) -> Json<Hello> {
    let config = host.config.read().await;
    Json(Hello {
        protocol_version: PROTOCOL_VERSION.into(),
        host_version: env!("CARGO_PKG_VERSION").into(),
        modules: config.modules.clone(),
        loadable_modules: host
            .registry
            .iter()
            .map(|(name, module)| LoadableModule {
                name: name.clone(),
                version: module.version().into(),
                smallest_size: module.smallest_size(),
            })
            .collect(),
        providers: config
            .providers
            .iter()
            .map(|(name, i)| ProviderDeclaration {
                provider: name.clone(),
                module: i.config.module.clone(),
                capabilities: i.capabilities.clone(),
                readiness: {
                    let readiness = i.readiness(&i.auth.recover());
                    let masker = host.diagnostic_secrets.recover().masker.clone();
                    mask_readiness(readiness, &masker)
                },
                rate_limits: i.rate_limits.clone(),
            })
            .collect(),
    })
}
async fn configure(State(host): State<Host>, ApiJson(request): ApiJson<HostConfiguration>) -> ApiResult<StatusCode> {
    let mut stopping = host.stopping.subscribe();
    let _transaction = tokio::select! {
        biased;
        _ = stopping.wait_for(|stopped| *stopped) => return Err(ProtocolError::unavailable("host stopping", None).into()),
        guard = host.configuring.lock() => guard,
    };
    if *host.stopping.borrow() {
        return Err(ProtocolError::unavailable("host stopping", None).into());
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
        // Also validate programmatic configurations, which can bypass the wire decoder.
        if matches!(&p.credential, CredentialMode::Proxied { placeholder_token, .. } if placeholder_token.expose().is_empty()) {
            return Err(refused("empty proxy placeholder token").into());
        }
        if let CredentialMode::Proxied { placeholder_token, .. } = &p.credential {
            host.diagnostic_secrets.recover().remember(&p.name, placeholder_token.clone());
        }
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
            _ = stopping.wait_for(|stopped| *stopped) => return Err(ProtocolError::unavailable("host stopping", None).into()),
            result = module.configure(p, http) => result.map_err(|error| {
                let masker = host.diagnostic_secrets.recover().masker.clone();
                let error = masker.context(error, &p.name, "configure");
                tracing::warn!(provider = %p.name, route = "configure", error_class = error.class(), error = %error, "provider call failed");
                error
            })?,
        };
        let (credential_changes, _) = watch::channel(credentials.clone());
        let capabilities = provider.capabilities();
        let ports = provider.operations();
        if capabilities.fallback_runner != ports.exec.is_some()
            || capabilities.suspend_resume != ports.suspend_resume.is_some()
            || capabilities.export != ports.export.is_some()
            || capabilities.usage != ports.usage.is_some()
            || capabilities.quota != ports.quota.is_some()
        {
            return Err(refused("capabilities must match optional operation ports").into());
        }
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
                diagnostic_secrets: host.diagnostic_secrets.clone(),
                provider,
                auth: Mutex::new(Authentication { credentials, rejected: false, rejection_error: None, generation: 0 }),
                capabilities,
                rate_limits,
                events: sink,
                observation,
                poll_interval,
                poll_error: Mutex::new(None),
                credential_changes,
                poll_waiting: Mutex::new(BTreeSet::new()),
                budget: Mutex::new(BTreeMap::new()),
                destroyed: Mutex::new(BTreeMap::new()),
                inspected: Mutex::new(BTreeMap::new()),
                observation_generation: Mutex::new(0),
                egress_measured_at: Mutex::new(BTreeMap::new()),
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
        return Err(ProtocolError::unavailable("host stopping", None).into());
    }
    *committed = config;
    drop(committed);
    // Serialize registration with shutdown's drain, including its stop check.
    let mut tasks = host.tasks.recover();
    if *host.stopping.borrow() {
        return Err(ProtocolError::unavailable("host stopping", None).into());
    }
    for instance in observers {
        tracing::info!(provider = %instance.config.name, readiness = readiness_status(&instance.readiness(&instance.auth.recover())), "provider configured");
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
    let mut auth = instance.auth.recover();
    if !matches!(auth.credentials.mode, CredentialMode::Direct { .. }) {
        return Err(refused("proxied provider cannot accept direct credentials").into());
    }
    let before = instance.readiness(&auth);
    host.diagnostic_secrets.recover().remember(&p, refresh.value.clone());
    auth.credentials.value = Some(refresh.value);
    auth.generation += 1;
    auth.rejected = false;
    auth.rejection_error = None;
    *instance.poll_error.recover() = None;
    instance.credential_changes.send_replace(auth.credentials.clone());
    let after = instance.readiness(&auth);
    if before != after {
        tracing::info!(provider = %p, route = "credential", readiness = readiness_status(&after), "provider readiness changed");
    }
    Ok(StatusCode::NO_CONTENT)
}

// A module violating stable port declarations must produce a typed request
// refusal rather than panic after the cached capability gate has admitted it.
fn operation_port<T: ?Sized>(port: Option<&T>) -> Result<&T> {
    port.ok_or_else(|| refused("operation port unavailable"))
}

async fn prepare(State(h): State<Host>, ApiPath(p): ApiPath<String>, ApiJson(r): ApiJson<PrepareRequest>) -> ApiResult<Json<Prepared>> {
    Ok(Json(h.call(&p, Gate::Prepare, |p, c| async move { p.prepare(r, &c).await }).await?))
}
async fn provision(State(h): State<Host>, ApiPath(p): ApiPath<String>, ApiJson(r): ApiJson<ProvisionRequest>) -> ApiResult<Response> {
    if r.prepared.provider != p {
        return Err(refused("invalid size, label or prepared provider").into());
    }
    let instance = h.instance(&p).await?;
    let generation = *instance.observation_generation.recover();
    let result = h.call(&p, Gate::Provision, |p, c| async move { p.provision(r, &c).await }).await?;
    let (Provisioned::Created(row) | Provisioned::Existing(row)) = &result;
    cache_observation(&instance, row, generation);
    Ok(match result {
        Provisioned::Created(s) => (StatusCode::CREATED, Json(s.environment)),
        Provisioned::Existing(s) => (StatusCode::OK, Json(s.environment)),
    }
    .into_response())
}
// Providers without effective-policy identities use this conservative fallback
// evidence age. Fingerprinted policies are invalidated by observed identity changes.
const EGRESS_EVIDENCE_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(60);

fn cache_observation(instance: &Instance, row: &ObservedEnvironment, generation: u64) {
    if instance.poll_interval.is_none() {
        return;
    }
    // Lock order: observation_generation -> inspected -> egress_measured_at.
    // Hold the generation through the write, so eviction cannot race the check.
    let current = instance.observation_generation.recover();
    if *current != generation {
        return;
    }
    let mut inspected = instance.inspected.recover();
    let mut times = instance.egress_measured_at.recover();
    if row.egress_measured {
        times.insert(row.environment.id.clone(), tokio::time::Instant::now());
    } else {
        times.remove(&row.environment.id);
    }
    inspected.insert(row.environment.id.clone(), row.clone());
}
fn evict_observation(instance: &Instance, id: &str) {
    // Invalidate overlapping cache writes without retaining per-ID tombstones.
    let mut generation = instance.observation_generation.recover();
    *generation = generation.wrapping_add(1);
    let mut inspected = instance.inspected.recover();
    let mut times = instance.egress_measured_at.recover();
    inspected.remove(id);
    times.remove(id);
}
// Only explicit measurements replace a measured claim. Policy fingerprints
// permit indefinite carry while unchanged; providers without them use a TTL.
fn carry_egress(instance: &Instance, rows: &mut [ObservedEnvironment], generation: u64) {
    if instance.poll_interval.is_none() {
        return;
    }
    // Same generation -> inspected -> egress_measured_at order as cache/eviction.
    let current = instance.observation_generation.recover();
    if *current != generation {
        return;
    }
    let mut measured = instance.inspected.recover();
    let mut times = instance.egress_measured_at.recover();
    // Both callers supply authoritative complete lists. Prune absent IDs here,
    // including out-of-band deletion, rather than only during poll reconciliation.
    let listed: std::collections::BTreeSet<_> = rows.iter().map(|r| r.environment.id.as_str()).collect();
    measured.retain(|id, _| listed.contains(id.as_str()));
    times.retain(|id, _| measured.contains_key(id));
    // Only the named non-starting phases preserve evidence. Starting/preparing
    // may cross a stop/start between polls; new phases invalidate by default.
    for row in rows {
        if !row.egress_measured && measured.get(&row.environment.id).is_some_and(|old| old.egress_policy != row.egress_policy) {
            // A changed policy permanently invalidates old evidence, even if it
            // later changes back. Only another measurement can restore a claim.
            measured.remove(&row.environment.id);
            times.remove(&row.environment.id);
        }
        if row.egress_measured {
            times.insert(row.environment.id.clone(), tokio::time::Instant::now());
            // This cache also preserves a matching inspect's provider timestamp
            // when a later list supplies no timestamp of its own.
            if row.timestamp.is_none() {
                row.timestamp =
                    measured.get(&row.environment.id).filter(|old| old.environment == row.environment).and_then(|old| old.timestamp);
            }
            measured.insert(row.environment.id.clone(), row.clone());
        } else if matches!(row.environment.state, Observation::Running) {
            if let Some(old) = measured.get(&row.environment.id).filter(|r| {
                matches!(r.environment.state, Observation::Running)
                    && match (&r.egress_policy, &row.egress_policy) {
                        (Some(old), Some(current)) => old == current,
                        (None, None) => times.get(&row.environment.id).is_some_and(|t| t.elapsed() < EGRESS_EVIDENCE_MAX_AGE),
                        _ => false,
                    }
            }) {
                row.environment.egress = old.environment.egress.clone();
            }
        } else if !matches!(
            row.environment.state,
            Observation::Transitioning { phase: TransitionPhase::Stopping | TransitionPhase::Reconfiguring | TransitionPhase::Destroying }
        ) {
            measured.remove(&row.environment.id);
            times.remove(&row.environment.id);
        }
    }
}
async fn list(State(h): State<Host>, ApiPath(p): ApiPath<String>) -> ApiResult<Json<Vec<Environment>>> {
    let instance = h.instance(&p).await?;
    let generation = *instance.observation_generation.recover();
    let mut rows = instance.call(Gate::List, |p, c| async move { p.list(&c).await }).await?;
    carry_egress(&instance, &mut rows, generation);
    Ok(Json(rows.into_iter().map(|r| r.environment).collect()))
}
async fn inspect(State(h): State<Host>, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Environment>> {
    let instance = h.instance(&p).await?;
    let generation = *instance.observation_generation.recover();
    let row = instance.call(Gate::Inspect, |p, c| async move { p.inspect(&id, &c).await }).await?;
    cache_observation(&instance, &row, generation);
    Ok(Json(row.environment))
}
async fn destroy(State(h): State<Host>, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<StatusCode> {
    let instance = h.instance(&p).await?;
    let mut attempt = DestroyAttempt::begin(instance.clone(), id.clone());
    let evicted_id = id.clone();
    let result = instance.call(Gate::Destroy, |p, c| async move { p.destroy(&id, &c).await }).await;
    attempt.finish(result.is_ok());
    result?;
    evict_observation(&instance, &evicted_id);
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
    Ok(Json(h.call(&p, Gate::Suspend, |p, c| async move { operation_port(p.operations().suspend_resume)?.suspend(&id, &c).await }).await?))
}
async fn resume(
    State(h): State<Host>,
    ApiPath((p, id)): ApiPath<(String, String)>,
    ApiJson(token): ApiJson<ResumeToken>,
) -> ApiResult<StatusCode> {
    let instance = h.instance(&p).await?;
    let inspect_id = id.clone();
    let generation = *instance.observation_generation.recover();
    instance.call(Gate::Resume, |p, c| async move { operation_port(p.operations().suspend_resume)?.resume(&id, token, &c).await }).await?;
    let row = instance.call(Gate::Inspect, |p, c| async move { p.inspect_after_lifecycle(&inspect_id, &c).await }).await?;
    cache_observation(&instance, &row, generation);
    Ok(StatusCode::NO_CONTENT)
}
async fn export(State(h): State<Host>, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Export>> {
    Ok(Json(h.call(&p, Gate::Export, |p, c| async move { operation_port(p.operations().export)?.export(&id, &c).await }).await?))
}
async fn usage(
    State(h): State<Host>,
    ApiPath(p): ApiPath<String>,
    query: std::result::Result<Query<Period>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<Usage>> {
    let Query(period) = query.map_err(|_| refused("invalid usage period"))?;
    Ok(Json(h.call(&p, Gate::Usage, |p, c| async move { operation_port(p.operations().usage)?.usage(period, &c).await }).await?))
}
async fn quota(State(h): State<Host>, ApiPath(p): ApiPath<String>) -> ApiResult<Json<Quota>> {
    Ok(Json(h.call(&p, Gate::Quota, |p, c| async move { operation_port(p.operations().quota)?.quota(&c).await }).await?))
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
    let stream =
        h.call(&p, Gate::Exec, |p, c| async move { operation_port(p.operations().exec)?.exec(&id, request.command, &c).await }).await?;
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

// Readiness transitions log only a static status label, never the reason.
// They are not serialized as events; hello masks reasons at its wire boundary.
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
    // A configure queued at commit when shutdown starts must observe the stop
    // under the write lock and leave neither providers nor observers behind.
    #[tokio::test]
    async fn shutdown_racing_configuration_commit_leaves_no_providers() {
        let host = Host::new(reference::registry());
        let request = serde_json::from_value(serde_json::json!({
            "modules": [{"name":"memory", "entrypoint":"reference"}],
            "providers": [{"name":"a", "module":"memory", "settings":{}, "credential":{"mode":"direct","credential_reference":"test"}}]
        }))
        .unwrap();
        let held = host.config.read().await;
        let configuring = tokio::spawn(configure(State(host.clone()), ApiJson(request)));
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            // Tokio's write-preferring lock refuses new reads once commit queues.
            while host.config.try_read().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("configure must reach commit");
        // Queue a reader after commit but before shutdown's clear, so it can
        // detect even a transient forbidden commit rather than only final state.
        let config = host.config.clone();
        let committed_state = tokio::spawn(async move { config.read().await.providers.is_empty() });
        tokio::task::yield_now().await;
        let shutdown = tokio::spawn(host.shutdown(async {}));
        let mut stopping = host.stopping.subscribe();
        stopping.wait_for(|stopped| *stopped).await.unwrap();
        drop(held);
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), configuring).await.unwrap().unwrap();
        assert!(matches!(result, Err(ApiError(ProtocolError::Unavailable { .. }))));
        tokio::time::timeout(std::time::Duration::from_secs(1), shutdown).await.unwrap().unwrap();
        assert!(host.config.read().await.providers.is_empty());
        assert!(host.tasks.lock().unwrap().is_empty());
        assert!(committed_state.await.unwrap(), "a stopping configure must never commit providers");
    }
}

#[cfg(test)]
mod operation_tests {
    use super::*;
    use module::*;

    // A basic adapter supplies only core operations, without optional method stubs.
    struct Basic(Arc<dyn Provider>, bool);
    #[async_trait::async_trait]
    impl Provider for Basic {
        fn observation(&self) -> ObservationMode {
            self.0.observation()
        }
        fn capabilities(&self) -> Capabilities {
            let mut c = self.0.capabilities();
            if self.1 {
                return c;
            }
            c.fallback_runner = false;
            c.suspend_resume = false;
            c.export = false;
            c.usage = false;
            c.quota = false;
            c
        }
        async fn prepare(&self, r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
            self.0.prepare(r, c).await
        }
        async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
            self.0.provision(r, c).await
        }
        async fn list(&self, c: &Credentials) -> Result<Vec<ObservedEnvironment>> {
            self.0.list(c).await
        }
        async fn inspect(&self, id: &str, c: &Credentials) -> Result<ObservedEnvironment> {
            self.0.inspect(id, c).await
        }
        async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
            self.0.destroy(id, c).await
        }
        async fn reach(&self, id: &str, c: &Credentials) -> Result<Connection> {
            self.0.reach(id, c).await
        }
        async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream> {
            self.0.relay(id, c).await
        }
    }

    struct BasicModule(bool);
    #[async_trait::async_trait]
    impl Module for BasicModule {
        fn version(&self) -> &str {
            "test"
        }
        async fn configure(&self, config: &ProviderConfiguration, http: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
            Ok(Arc::new(Basic(reference::ReferenceModule.configure(config, http).await?, self.0)))
        }
    }

    // Registration accepts a core-only module and transactionally refuses a
    // module advertising optional capabilities without the corresponding ports.
    #[tokio::test]
    async fn registration_requires_matching_operation_ports() {
        for advertise in [false, true] {
            let host = Host::new(Registry::from([("basic".into(), Arc::new(BasicModule(advertise)) as Arc<dyn Module>)]));
            let request = serde_json::from_value(serde_json::json!({
                "modules": [{"name":"memory", "entrypoint":"basic"}],
                "providers": [{"name":"a", "module":"memory", "settings":{},
                    "credential":{"mode":"direct","credential_reference":"test"}}]
            }))
            .unwrap();
            let result = configure(State(host.clone()), ApiJson(request)).await;
            assert_eq!(result.is_ok(), !advertise);
            assert_eq!(host.config.read().await.providers.is_empty(), advertise);
            if advertise {
                assert!(matches!(result, Err(ApiError(ProtocolError::Refused { .. }))));
            }
            host.shutdown(async {}).await;
        }
    }

    async fn instance(operation: &str) -> Arc<Instance> {
        let host = Host::new(reference::registry());
        let request = serde_json::from_value(serde_json::json!({
            "modules": [{"name":"memory", "entrypoint":"reference"}],
            "providers": [{"name":"a", "module":"memory", "settings":{"rate_limits":[{"operation":operation,"requests":1,"period_seconds":1}]},
                "credential":{"mode":"direct","credential_reference":"test"}}]
        })).unwrap();
        configure(State(host.clone()), ApiJson(request)).await.map_err(|e| e.0).unwrap();
        // Exercise admission deterministically without the automatic observation loop.
        for task in host.tasks.recover().drain(..) {
            task.abort();
        }
        credential(State(host.clone()), ApiPath("a".into()), ApiJson(CredentialRefresh { value: Secret::new("token") }))
            .await
            .map_err(|e| e.0)
            .unwrap();
        tokio::task::yield_now().await;
        host.instance("a").await.unwrap()
    }

    // A denied single-slot poll reserves the next free slot, even when routes
    // arrive first every window. Routes regain the slot after observation succeeds.
    #[tokio::test(start_paused = true)]
    async fn single_slot_poll_cannot_starve() {
        for scope in ["list", "*"] {
            let i = instance(scope).await;
            for _ in 0..3 {
                assert!(i.reserve("list", false).is_ok());
                assert!(matches!(i.reserve("list", true), Err(ProtocolError::RateLimited { .. })));
                i.auth.recover().rejected = true;
                for poll in [false, true] {
                    let result: Result<()> =
                        i.call_with_budget(Gate::List, poll, |_, _| async { panic!("unready calls must not reach provider") }).await;
                    assert!(matches!(result, Err(ProtocolError::Unavailable { .. })));
                }
                i.auth.recover().rejected = false;
                tokio::time::advance(std::time::Duration::from_secs(2)).await;
                assert!(matches!(i.reserve("list", false), Err(ProtocolError::RateLimited { .. })));
                assert!(i.reserve("list", true).is_ok());
                tokio::time::advance(std::time::Duration::from_secs(2)).await;
            }
        }
    }

    // The same host gate refuses absent optional operations without entering a
    // provider. Core-only adapters remain usable through Arc<dyn Provider>.
    #[tokio::test]
    async fn basic_provider_needs_no_optional_stubs() {
        let mut i = instance("list").await;
        let i = Arc::get_mut(&mut i).unwrap();
        i.provider = Arc::new(Basic(i.provider.clone(), false));
        i.capabilities = i.provider.capabilities();
        assert!(
            i.call(Gate::Prepare, |p, c| async move {
                p.prepare(
                    PrepareRequest {
                        size: drydock_protocol::Size { cpus: 2.0, memory_bytes: 4 << 30, disk_bytes: 10 << 30 },
                        image_digest: "image".into(),
                        tools_digest: "tools".into(),
                    },
                    &c,
                )
                .await
            })
            .await
            .is_ok()
        );
        for gate in [Gate::Exec, Gate::Suspend, Gate::Resume, Gate::Export, Gate::Usage, Gate::Quota] {
            let result: Result<()> = i.call(gate, |_, _| async { panic!("unsupported port must never be invoked") }).await;
            assert!(matches!(result, Err(ProtocolError::Refused { .. })));
        }
    }
    // One cache path is shared by provision, inspect and resume. Only explicit
    // evidence gets an age stamp; push providers retain no polling metadata.
    #[tokio::test(start_paused = true)]
    async fn measurement_cache_requires_evidence_and_polling() {
        for polling in [false, true] {
            let mut owner = instance("list").await;
            let i = Arc::get_mut(&mut owner).unwrap();
            i.poll_interval = polling.then_some(std::time::Duration::from_secs(30));
            let mut row = ObservedEnvironment {
                egress_policy: None,
                environment: Environment {
                    id: "e".into(),
                    provider: "a".into(),
                    label: None,
                    state: Observation::Running,
                    granted_size: None,
                    egress: Enforcement::Enforced,
                },
                timestamp: None,
                egress_measured: true,
            };
            let generation = *i.observation_generation.recover();
            cache_observation(i, &row, generation);
            assert_eq!(i.egress_measured_at.recover().contains_key("e"), polling);
            tokio::time::advance(EGRESS_EVIDENCE_MAX_AGE).await;
            row.egress_measured = false;
            let generation = *i.observation_generation.recover();
            cache_observation(i, &row, generation);
            assert!(!i.egress_measured_at.recover().contains_key("e"));
            let mut cheap = row.clone();
            cheap.environment.egress = Enforcement::Advisory;
            carry_egress(i, std::slice::from_mut(&mut cheap), generation);
            assert_eq!(cheap.environment.egress, Enforcement::Advisory);
            assert_eq!(i.inspected.recover().contains_key("e"), polling);
            row.egress_measured = true;
            let generation = *i.observation_generation.recover();
            cache_observation(i, &row, generation);
            evict_observation(i, "e");
            assert!(i.inspected.recover().is_empty());
            assert!(i.egress_measured_at.recover().is_empty());
            // A response begun before deletion cannot repopulate either cache.
            cache_observation(i, &row, generation);
            assert!(i.inspected.recover().is_empty());
            assert!(i.egress_measured_at.recover().is_empty());
            let generation = *i.observation_generation.recover();
            cache_observation(i, &row, generation);
            assert_eq!(i.inspected.recover().contains_key("e"), polling);
            // A complete empty inventory also forgets out-of-band deletions.
            carry_egress(i, &mut [], generation);
            assert!(i.inspected.recover().is_empty());
            assert!(i.egress_measured_at.recover().is_empty());
        }
    }
    // Identical effective policies preserve evidence beyond the fallback TTL;
    // mutation, removal, and stop invalidate it until a new measurement occurs.
    #[tokio::test(start_paused = true)]
    async fn policy_identity_controls_egress_carry() {
        let mut owner = instance("list").await;
        let i = Arc::get_mut(&mut owner).unwrap();
        i.poll_interval = Some(std::time::Duration::from_secs(30));
        let row = ObservedEnvironment {
            environment: Environment {
                id: "e".into(),
                provider: "a".into(),
                label: None,
                state: Observation::Running,
                granted_size: None,
                egress: Enforcement::Enforced,
            },
            timestamp: None,
            egress_measured: true,
            egress_policy: Some("policy-a".into()),
        };
        let generation = *i.observation_generation.recover();
        cache_observation(i, &row, generation);
        tokio::time::advance(std::time::Duration::from_secs(3600)).await;
        let mut cheap = row.clone();
        cheap.egress_measured = false;
        cheap.environment.egress = Enforcement::Advisory;
        carry_egress(i, std::slice::from_mut(&mut cheap), generation);
        assert_eq!(cheap.environment.egress, Enforcement::Enforced);
        cheap.egress_policy = Some("policy-b".into());
        cheap.environment.egress = Enforcement::Advisory;
        carry_egress(i, std::slice::from_mut(&mut cheap), generation);
        assert_eq!(cheap.environment.egress, Enforcement::Advisory);
        cheap.egress_policy = row.egress_policy.clone();
        carry_egress(i, std::slice::from_mut(&mut cheap), generation);
        assert_eq!(cheap.environment.egress, Enforcement::Advisory);
        cache_observation(i, &row, generation);
        cheap.environment.state = Observation::Stopped { cause: StopCause::SuspendedByRequest };
        carry_egress(i, std::slice::from_mut(&mut cheap), generation);
        cheap.environment.state = Observation::Running;
        carry_egress(i, std::slice::from_mut(&mut cheap), generation);
        assert_eq!(cheap.environment.egress, Enforcement::Advisory);
        cache_observation(i, &row, generation);
        cheap.egress_policy = None;
        carry_egress(i, std::slice::from_mut(&mut cheap), generation);
        assert_eq!(cheap.environment.egress, Enforcement::Advisory);
    }
    // Credential delivery wakes a host poll immediately. Advancing a paused
    // clock while unready must not attempt a call or record a spurious error.
    #[tokio::test(start_paused = true)]
    async fn poll_waits_for_credential_without_spurious_failure() {
        let host = Host::new(reference::registry());
        let config = serde_json::from_value(serde_json::json!({
            "modules":[{"name":"memory","entrypoint":"reference"}],
            "providers":[{"name":"a","module":"memory","settings":{"poll_interval_ms":3600000},
                "credential":{"mode":"direct","credential_reference":"test"}}]
        }))
        .unwrap();
        configure(State(host.clone()), ApiJson(config)).await.map_err(|e| e.0).unwrap();
        let instance = host.instance("a").await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(7200)).await;
        tokio::task::yield_now().await;
        assert!(instance.poll_error.recover().is_none());
        assert!(!host.events.log.recover().inventories.contains_key("a"));
        let mut changes = host.events.changed.subscribe();
        credential(State(host.clone()), ApiPath("a".into()), ApiJson(CredentialRefresh { value: Secret::new("token") }))
            .await
            .map_err(|e| e.0)
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !host.events.log.recover().inventories.contains_key("a") {
                changes.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(instance.poll_error.recover().is_none());
        host.shutdown(async {}).await;
    }

    // Repeated configuration and several providers sharing a placeholder must
    // retain one diagnostic secret for delayed vendor echoes.
    #[tokio::test]
    async fn repeated_proxy_configuration_deduplicates_diagnostic_secret() {
        let host = Host::new(reference::registry());
        let config: HostConfiguration = serde_json::from_value(serde_json::json!({
            "modules":[{"name":"memory","entrypoint":"reference"}],
            "providers":[{"name":"a","module":"memory","settings":{},
                "credential":{"mode":"proxied","placeholder_token":"placeholder","proxy_url":"http://127.0.0.1:1"}}]
        }))
        .unwrap();
        let mut config = config;
        for count in 1..=3 {
            let mut provider = config.providers[0].clone();
            provider.name = format!("provider-{count}");
            config.providers.push(provider);
            for _ in 0..2 {
                configure(State(host.clone()), ApiJson(config.clone())).await.map_err(|e| e.0).unwrap();
            }
        }
        {
            let secrets = host.diagnostic_secrets.recover();
            assert_eq!(secrets.current.values().map(Secret::expose).collect::<BTreeSet<_>>().len(), 1);
            assert!(secrets.recent.is_empty());
        }
        host.shutdown(async {}).await;
    }
    #[test]
    fn active_shared_values_do_not_consume_history() {
        let mut secrets = DiagnosticSecrets::default();
        secrets.remember("a", Secret::new("shared"));
        secrets.remember("b", Secret::new("shared"));
        secrets.remember("a", Secret::new("new-a"));
        assert!(secrets.recent.is_empty());
        secrets.remember("b", Secret::new("new-b"));
        assert_eq!(secrets.recent, VecDeque::from([Secret::new("shared")]));
    }

    #[test]
    fn readiness_reasons_mask_without_adding_context() {
        let mut masker = DiagnosticMasker::default();
        masker.remember("readiness-secret");
        for readiness in [
            Readiness::MissingCredential { reason: "missing readiness-secret".into() },
            Readiness::Unknown { reason: "unknown readiness-secret".into() },
        ] {
            let result = mask_readiness(readiness, &masker);
            let wire = serde_json::to_string(&result).unwrap();
            assert!(!wire.contains("readiness-secret"));
            assert!(wire.contains("<REDACTED>"));
            assert!(!wire.contains("operation"));
        }
    }

    #[tokio::test]
    async fn hello_masks_readiness_reasons_at_wire_boundary() {
        let host = Host::new(reference::registry());
        let config = serde_json::from_value(serde_json::json!({
            "modules":[{"name":"memory","entrypoint":"reference"}],
            "providers":[{"name":"a","module":"memory","settings":{},
                "credential":{"mode":"direct","credential_reference":"test"}}]
        }))
        .unwrap();
        configure(State(host.clone()), ApiJson(config)).await.map_err(|e| e.0).unwrap();
        host.diagnostic_secrets.recover().remember("a", Secret::new("readiness-secret"));
        {
            let config = host.config.read().await;
            let mut auth = config.providers["a"].auth.recover();
            auth.rejected = true;
            auth.rejection_error = Some(ProtocolError::CredentialRejected { reason: "readiness-secret rejected".into() });
        }
        let Json(result) = hello(State(host.clone())).await;
        let wire = serde_json::to_string(&result).unwrap();
        assert!(!wire.contains("readiness-secret"));
        assert!(wire.contains("<REDACTED>"));
        host.shutdown(async {}).await;
    }

    #[tokio::test]
    async fn configure_errors_mask_placeholder_and_include_context() {
        struct Failing;
        #[async_trait::async_trait]
        impl Module for Failing {
            fn version(&self) -> &str {
                "test"
            }
            async fn configure(&self, _: &ProviderConfiguration, _: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
                Err(ProtocolError::Internal { reason: "configure-secret rejected".into(), provider_error: "configure-secret body".into() })
            }
        }
        let host = Host::new(Registry::from([("failing".into(), Arc::new(Failing) as Arc<dyn Module>)]));
        let config = serde_json::from_value(serde_json::json!({
            "modules":[{"name":"memory","entrypoint":"failing"}],
            "providers":[{"name":"a","module":"memory","settings":{},
                "credential":{"mode":"proxied","placeholder_token":"configure-secret","proxy_url":"http://127.0.0.1:1"}}]
        }))
        .unwrap();
        let error = configure(State(host.clone()), ApiJson(config)).await.err().unwrap().0;
        let wire = serde_json::to_string(&error).unwrap();
        assert!(!wire.contains("configure-secret"));
        assert!(wire.contains("<REDACTED>"));
        assert!(wire.contains("provider a operation configure:"));
        host.shutdown(async {}).await;
    }

    // Glue: a unique short credential emits a debug registration note without
    // its value; delivering that same credential again emits no duplicate note.
    #[test]
    fn short_credential_note_contains_length_without_value() {
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.recover().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = Arc::new(Mutex::new(Vec::new()));
        let output = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .without_time()
            .with_writer(move || Capture(output.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let mut secrets = DiagnosticSecrets::default();
            secrets.remember("provider", Secret::new("xyz"));
            secrets.remember("provider", Secret::new("xyz"));
        });
        let text = String::from_utf8(captured.recover().clone()).unwrap();
        assert_eq!(text.matches("short credential registered").count(), 1);
        assert!(text.contains("credential_bytes=3"));
        assert!(!text.contains("xyz"));
    }
    // Credential history is bounded independently of refresh count, while every
    // active provider and the recent replacement window remain masked.
    #[test]
    fn credential_history_is_bounded_and_active_values_remain_masked() {
        for rotations in [0, 1, RECENT_CREDENTIAL_LIMIT, RECENT_CREDENTIAL_LIMIT + 1, 100] {
            let mut secrets = DiagnosticSecrets::default();
            secrets.remember("other", Secret::new("other-active-token"));
            for generation in 0..=rotations {
                secrets.remember("rotating", Secret::new(format!("generation-{generation}-token")));
            }
            assert_eq!(secrets.recent.len(), rotations.min(RECENT_CREDENTIAL_LIMIT));
            assert_eq!(secrets.current.len(), 2);
            let current = format!("generation-{rotations}-token");
            let previous = format!("generation-{}-token", rotations.saturating_sub(1));
            let oldest_recent = format!("generation-{}-token", rotations.saturating_sub(RECENT_CREDENTIAL_LIMIT));
            let error = secrets.masker.context(
                ProtocolError::Internal {
                    reason: "validation".into(),
                    provider_error: format!("other-active-token {current} {previous} {oldest_recent} generation-0-token"),
                },
                "p",
                "list",
            );
            let ProtocolError::Internal { provider_error, .. } = error else { unreachable!() };
            assert!(!provider_error.contains("other-active-token"));
            assert!(!provider_error.contains(&current));
            assert!(!provider_error.contains(&previous));
            assert!(!provider_error.contains(&oldest_recent));
            if rotations > RECENT_CREDENTIAL_LIMIT {
                assert!(provider_error.contains("generation-0-token"));
            }
        }
    }

    // A call masks its own credential even if many refreshes evict that value
    // before its vendor error returns; the retained history still stays bounded.
    #[tokio::test]
    async fn in_flight_error_masks_evicted_call_credential() {
        let instance = instance("list").await;
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let call = instance.clone();
        let started = entered.clone();
        let waiting = release.clone();
        let pending = tokio::spawn(async move {
            call.call(Gate::List, move |_, credentials| async move {
                started.notify_one();
                waiting.notified().await;
                Err::<(), _>(ProtocolError::Internal {
                    reason: "vendor failure".into(),
                    provider_error: credentials.token().unwrap().expose().into(),
                })
            })
            .await
        });
        entered.notified().await;
        for generation in 0..100 {
            instance.diagnostic_secrets.recover().remember("a", Secret::new(format!("new-{generation}")));
        }
        assert!(!instance.diagnostic_secrets.recover().contains(&Secret::new("token")));
        release.notify_one();
        let error = pending.await.unwrap().unwrap_err();
        let ProtocolError::Internal { provider_error, .. } = error else { unreachable!() };
        assert_eq!(provider_error, "<REDACTED>");
        assert!(instance.diagnostic_secrets.recover().recent.len() <= RECENT_CREDENTIAL_LIMIT);
    }
}

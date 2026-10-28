//! Server-owned provider policy, shared by the embedded and standalone Daemon.
//! `Runtime` implements `ProviderApi` once, in `operations`; the public HTTP
//! router and the Daemon call it in process. Providers in other processes are
//! reached through the policy-free trait adapter in `remote`.
pub use drydock_provider as module;
mod diagnostics;
mod events;
mod evidence;
mod instance;
mod observer;
mod operations;
pub(crate) mod remote;
#[cfg(test)]
mod tests;
use diagnostics::*;
use drydock_protocol::*;
pub use events::EVENT_HISTORY_CAPACITY;
use events::*;
use evidence::*;
use instance::*;
use module::{Credentials, Provider, Registry, Result, refused};
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

#[derive(Default, Clone)]
struct Loaded {
    providers: BTreeMap<String, Arc<Instance>>,
}
#[derive(Clone)]
pub struct Runtime {
    diagnostic_secrets: Arc<Mutex<DiagnosticSecrets>>,
    registry: Arc<Mutex<Registry>>,
    request_timeout: std::time::Duration,
    config: Arc<RwLock<Loaded>>,
    configuring: Arc<AsyncMutex<()>>,
    events: EventLog,
    stopping: watch::Sender<bool>,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    /// A request's credential, used instead of the held one; never stored.
    credential: Option<Secret>,
}
impl Runtime {
    pub fn new(registry: Registry) -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            registry: Arc::new(Mutex::new(registry)),
            request_timeout: std::time::Duration::from_secs(30),
            diagnostic_secrets: Arc::default(),
            config: Arc::new(RwLock::new(Loaded::default())),
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
            stopping: watch::channel(false).0,
            tasks: Arc::new(Mutex::new(vec![])),
            credential: None,
        }
    }
    /// Deadline for ordinary provider calls; long mutations get `LONG_CALL`.
    /// It never bounds provider polling or subscription lifetime.
    pub fn with_request_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.request_timeout = timeout;
        self
    }
    /// This runtime, calling providers with `credential` instead of the held one.
    pub fn credentialed(&self, credential: Option<Secret>) -> Self {
        Self { credential, ..self.clone() }
    }
    pub fn shutdown<F: std::future::Future<Output = ()> + Send + 'static>(
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
    pub fn stopping(&self) -> watch::Receiver<bool> {
        self.stopping.subscribe()
    }
}

impl Runtime {
    pub async fn configure(&self, update: crate::api::ConfigUpdate) -> Result<()> {
        let mut stopping = self.stopping.subscribe();
        let _transaction = tokio::select! {
            biased;
            _ = stopping.wait_for(|stopped| *stopped) => return Err(ProtocolError::unavailable("host stopping", None)),
            guard = self.configuring.lock() => guard,
        };
        if *self.stopping.borrow() {
            return Err(ProtocolError::unavailable("host stopping", None));
        }
        let registry = self.registry.recover().clone();
        let mut config = self.config.read().await.clone();
        let current = Configuration { providers: config.providers.iter().map(|(name, i)| (name.clone(), i.config.clone())).collect() };
        let request = update.apply(&current)?;
        // Exact repeats preserve resources and delivered credentials. Changes to live providers
        // are refused: silently replacing one would lose in-memory reference resources.
        for (name, p) in &request.providers {
            if name.is_empty() || !registry.contains_key(&p.module) {
                return Err(refused("invalid provider name or unregistered module"));
            }
            if config.providers.get(name).is_some_and(|old| old.config != *p) {
                return Err(refused("cannot replace a configured provider; restart host"));
            }
        }
        if config.providers.keys().any(|name| !request.providers.contains_key(name)) {
            return Err(refused("cannot remove a configured provider; restart host"));
        }
        // Build before committing configuration, so a rejected document cannot partly apply.
        let mut additions = BTreeMap::new();
        for (name, p) in &request.providers {
            if config.providers.contains_key(name) {
                continue;
            }
            let module = &registry[&p.module];
            let http = Arc::new(
                rigging_http_client::ReqwestHttpClient::restricted(None, None)
                    .map_err(|error| refused(format!("invalid HTTP transport configuration: {error}")))?,
            );
            let sink = EventSink { shared: self.events.clone(), provider: name.clone() };
            let provider = tokio::select! {
                biased;
                _ = stopping.wait_for(|stopped| *stopped) => return Err(ProtocolError::unavailable("host stopping", None)),
                result = module.configure(name, p, http) => result.map_err(|error| {
                    let masker = self.diagnostic_secrets.recover().masker.clone();
                    let error = masker.context(error, name, "configure");
                    tracing::warn!(provider = %name, route = "configure", error_class = error.class(), error = %error, "provider call failed");
                    error
                })?,
            };
            let credentials = Credentials::default();
            let (credential_changes, _) = watch::channel(credentials.clone());
            let capabilities = provider.capabilities();
            let ports = provider.operations();
            if capabilities.fallback_runner != ports.exec.is_some()
                || capabilities.suspend_resume != ports.suspend_resume.is_some()
                || capabilities.export != ports.export.is_some()
                || capabilities.usage != ports.usage.is_some()
                || capabilities.quota != ports.quota.is_some()
            {
                return Err(refused("capabilities must match optional operation ports"));
            }
            let rate_limits = provider.rate_limits();
            if rate_limits.iter().any(|r| r.requests == 0 || r.period_seconds == 0) {
                return Err(refused("invalid declared rate limit"));
            }
            let observation = provider.observation();
            let poll_interval = observer::poll_interval(observation, &rate_limits)?;
            additions.insert(
                name.clone(),
                Arc::new(Instance {
                    name: name.clone(),
                    config: p.clone(),
                    diagnostic_secrets: self.diagnostic_secrets.clone(),
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
                    lifecycle_changes: watch::channel(0).0,
                    inspected: Mutex::new(BTreeMap::new()),
                    observation_generation: Mutex::new(0),
                    egress_measured_at: Mutex::new(BTreeMap::new()),
                    request_timeout: self.request_timeout,
                }),
            );
        }
        let observers: Vec<_> = additions.values().cloned().collect();
        config.providers.extend(additions);
        let mut committed = self.config.write().await;
        if *self.stopping.borrow() {
            return Err(ProtocolError::unavailable("host stopping", None));
        }
        *committed = config;
        drop(committed);
        // Serialize registration with shutdown's drain, including its stop check.
        let mut tasks = self.tasks.recover();
        if *self.stopping.borrow() {
            return Err(ProtocolError::unavailable("host stopping", None));
        }
        for instance in observers {
            tracing::info!(provider = %instance.name, readiness = readiness_status(&instance.readiness(&instance.auth.recover())), "provider configured");
            let task = observer::spawn(instance, self.stopping.subscribe());
            tasks.push(task);
        }
        self.events.changed.send_modify(|serial| *serial += 1);
        Ok(())
    }
    pub async fn credential(&self, p: &str, value: Secret) -> Result<()> {
        let instance = self.instance(p).await?;
        let mut auth = instance.auth.recover();
        let before = instance.readiness(&auth);
        self.diagnostic_secrets.recover().remember(p, value.clone());
        auth.credentials = Credentials::new(Some(value));
        auth.generation += 1;
        auth.rejected = false;
        auth.rejection_error = None;
        *instance.poll_error.recover() = None;
        instance.credential_changes.send_replace(auth.credentials.clone());
        let after = instance.readiness(&auth);
        if before != after {
            tracing::info!(provider = %p, route = "credential", readiness = readiness_status(&after), "provider readiness changed");
        }
        Ok(())
    }
    pub(crate) async fn reconnect(&self, registry: Registry) {
        for task in std::mem::take(&mut *self.tasks.recover()) {
            task.abort();
        }
        *self.config.write().await = Loaded::default();
        *self.registry.recover() = registry;
        let mut log = self.events.log.recover();
        log.epoch = format!("{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().expect("current timestamp"));
        log.serial = 0;
        log.records.clear();
        log.inventories.clear();
    }
    pub(crate) fn stop(&self) {
        self.stopping.send_replace(true);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(self.shutdown(async {}));
        } else {
            for task in std::mem::take(&mut *self.tasks.recover()) {
                task.abort();
            }
        }
    }
}

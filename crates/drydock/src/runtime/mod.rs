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
use events::*;
pub use events::{EVENT_HISTORY_CAPACITY, PUSH_SNAPSHOT_TIMEOUT};
use evidence::*;
use instance::*;
use module::{Credentials, ObservationMode, ObservedEnvironment, Provider, Registry, Result, refused};
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
struct Configuration {
    modules: Vec<LoadedModule>,
    entrypoints: BTreeMap<String, String>,
    providers: BTreeMap<String, Arc<Instance>>,
}
#[derive(Clone)]
pub struct Runtime {
    diagnostic_secrets: Arc<Mutex<DiagnosticSecrets>>,
    registry: Arc<Mutex<Registry>>,
    request_timeout: std::time::Duration,
    config: Arc<RwLock<Configuration>>,
    configuring: Arc<AsyncMutex<()>>,
    events: EventLog,
    proxy_ca: Option<Arc<Vec<u8>>>,
    stopping: watch::Sender<bool>,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}
impl Runtime {
    pub fn new(registry: Registry) -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            registry: Arc::new(Mutex::new(registry)),
            request_timeout: std::time::Duration::from_secs(30),
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
    /// Deadline for ordinary provider calls; long mutations get `LONG_CALL`.
    /// It never bounds provider polling or subscription lifetime.
    pub fn with_request_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.request_timeout = timeout;
        self
    }
    /// PEM trust root supplied out of band by the supervisor; never a vendor credential.
    pub fn with_proxy_ca(mut self, pem: Vec<u8>) -> Self {
        self.proxy_ca = Some(Arc::new(pem));
        self
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
    pub async fn configure(&self, request: &HostConfiguration) -> Result<()> {
        let request = request.clone();
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
        // Exact repeats preserve resources and delivered credentials. Changes to live providers
        // are refused: silently replacing one would lose in-memory reference resources.
        let mut modules = BTreeMap::new();
        for m in &request.modules {
            if modules.insert(m.name.clone(), m.entrypoint.clone()).is_some() {
                return Err(refused("duplicate module"));
            }
            if !registry.contains_key(&m.entrypoint) {
                return Err(refused("unregistered module entrypoint"));
            }
        }
        let mut names = BTreeSet::new();
        for p in &request.providers {
            if p.name.is_empty() || !names.insert(p.name.clone()) || !modules.contains_key(&p.module) {
                return Err(refused("invalid or duplicate provider/module"));
            }
            if let Some(old) = config.providers.get(&p.name) {
                let same_entrypoint = config.entrypoints.get(&p.module) == modules.get(&p.module);
                if old.config != *p || !same_entrypoint {
                    return Err(refused("cannot replace a configured provider; restart host"));
                }
            }
        }
        if config.providers.keys().any(|name| !names.contains(name)) {
            return Err(refused("cannot remove a configured provider; restart host"));
        }
        // Build before committing configuration, so a rejected document cannot partly apply.
        let mut additions = BTreeMap::new();
        for p in &request.providers {
            if config.providers.contains_key(&p.name) {
                continue;
            }
            let module = &registry[&modules[&p.module]];
            // Also validate programmatic configurations, which can bypass the wire decoder.
            if matches!(&p.credential, CredentialMode::Proxied { placeholder_token, .. } if placeholder_token.expose().is_empty()) {
                return Err(refused("empty proxy placeholder token"));
            }
            if let CredentialMode::Proxied { placeholder_token, .. } = &p.credential {
                self.diagnostic_secrets.recover().remember(&p.name, placeholder_token.clone());
            }
            let credentials = Credentials::new(p.credential.clone());
            let proxy = match &p.credential {
                CredentialMode::Proxied { proxy_url, .. } => Some(proxy_url.as_str()),
                _ => None,
            };
            let http = Arc::new(
                rigging_http_client::ReqwestHttpClient::restricted(proxy, self.proxy_ca.as_deref().map(Vec::as_slice))
                    .map_err(|error| refused(format!("invalid HTTP transport configuration: {error}")))?,
            );
            let sink = EventSink { shared: self.events.clone(), provider: p.name.clone() };
            let provider = tokio::select! {
                biased;
                _ = stopping.wait_for(|stopped| *stopped) => return Err(ProtocolError::unavailable("host stopping", None)),
                result = module.configure(p, http) => result.map_err(|error| {
                    let masker = self.diagnostic_secrets.recover().masker.clone();
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
                return Err(refused("capabilities must match optional operation ports"));
            }
            let rate_limits = provider.rate_limits();
            if rate_limits.iter().any(|r| r.requests == 0 || r.period_seconds == 0) {
                return Err(refused("invalid declared rate limit"));
            }
            let observation = provider.observation();
            let poll_interval = observer::poll_interval(observation, &rate_limits)?;
            additions.insert(
                p.name.clone(),
                Arc::new(Instance {
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
        config.entrypoints = modules;
        let observers: Vec<_> = additions.values().cloned().collect();
        config.providers.extend(additions);
        config.modules = request
            .modules
            .iter()
            .map(|m| LoadedModule { name: m.name.clone(), version: registry[&m.entrypoint].version().into() })
            .collect();
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
            tracing::info!(provider = %instance.config.name, readiness = readiness_status(&instance.readiness(&instance.auth.recover())), "provider configured");
            let task = observer::spawn(instance, self.stopping.subscribe());
            tasks.push(task);
        }
        self.events.changed.send_modify(|serial| *serial += 1);
        Ok(())
    }
    pub async fn credential(&self, p: &str, value: Secret) -> Result<()> {
        let instance = self.instance(p).await?;
        let mut auth = instance.auth.recover();
        if !matches!(auth.credentials.mode, CredentialMode::Direct { .. }) {
            return Err(refused("proxied provider cannot accept direct credentials"));
        }
        let before = instance.readiness(&auth);
        self.diagnostic_secrets.recover().remember(p, value.clone());
        auth.credentials.value = Some(value);
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
        *self.config.write().await = Configuration::default();
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

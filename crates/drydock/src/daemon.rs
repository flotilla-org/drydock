//! Long-lived provider routing shared by drydockd and an embedding daemon.
use crate::{
    HostConnection, HostHandle, HostSpec, Supervisor,
    api::{ApiError, ApiJson, ApiPath, Exposed, ProvisionAnswer},
    client::{Client, Error, ProvisionError, StatusCache},
    config::{Config, Egress},
    credentials::BuiltinCredentials,
    launch::{self, ImageResolver, LaunchOptions, RegistryResolver},
};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::IntoResponse,
    routing::post,
};
use drydock_protocol::*;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path as FsPath, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;

mod carried;
pub use crate::api::ProviderApi;
use carried::{Carrier, agent_error, child_socket};
use drydock_protocol::service::{Service, ServiceInfo};
pub struct HostOption {
    pub name: String,
    pub connection: HostConnection,
    /// Discovery failures leave other hosts available when true.
    pub optional: bool,
}
impl HostOption {
    /// The Rust host is bundled; language hosts are enabled only when both their
    /// companion and their runtime are installed. No user process layout needed.
    pub async fn installed() -> Result<Vec<Self>, String> {
        let mut hosts = vec![Self {
            name: "rust".into(),
            optional: false,
            connection: HostConnection::Managed {
                command: vec![crate::local::companion("drydock-host", "DRYDOCK_HOST_BIN")?.to_string_lossy().into_owned()],
                runtime: None,
            },
        }];
        for (name, binary, runtime, override_var) in [
            ("typescript", "drydock-host-typescript", "node", "DRYDOCK_TYPESCRIPT_HOST_BIN"),
            ("python", "drydock-host-python", "uv", "DRYDOCK_PYTHON_HOST_BIN"),
        ] {
            use crate::ToolDetector;
            if crate::PathDetector.available(runtime).await
                && let Ok(path) = crate::local::companion(binary, override_var)
            {
                hosts.push(Self {
                    name: name.into(),
                    optional: true,
                    connection: HostConnection::Managed {
                        command: vec![path.to_string_lossy().into_owned()],
                        runtime: Some(runtime.into()),
                    },
                });
            }
        }
        Ok(hosts)
    }
}
struct ManagedHost {
    handle: HostHandle,
    cache: Mutex<(u64, Arc<StatusCache<crate::runtime::Runtime>>)>,
}
struct Placement {
    host: usize,
    minimum: Size,
}
/// Serves the public API for every configured provider, routing each call to
/// the host that loads its module. Clones share one daemon.
#[derive(Clone)]
pub struct Daemon {
    inner: Arc<Inner>,
    /// A request's credential, used instead of the held one; never stored.
    credential: Option<Secret>,
}
impl std::ops::Deref for Daemon {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.inner
    }
}
pub struct Inner {
    config: Config,
    modules: BTreeMap<String, (usize, LoadableModule)>,
    hosts: Vec<ManagedHost>,
    placements: BTreeMap<String, Placement>,
    unavailable: BTreeMap<String, Readiness>,
    keys: PathBuf,
    resolver: Arc<dyn ImageResolver>,
    dialer: Arc<dyn crate::agent::SshDialer>,
    builds: Arc<dyn AgentBuilds>,
    exposures: crate::exposures::Exposures,
    staging: crate::staging::Staging,
    /// One lock per label, so two first provisions of a label share one key
    /// and provisions of other labels never wait on it.
    keying: std::sync::Mutex<BTreeMap<String, std::sync::Weak<Mutex<()>>>>,
    stopping: tokio::sync::watch::Sender<bool>,
    /// Each instance with a parent, configured or carried, by name.
    carried: std::sync::RwLock<BTreeMap<String, Arc<Carrier>>>,
    /// Each carried name's turn.
    turns: std::sync::Mutex<BTreeMap<String, std::sync::Weak<tokio::sync::RwLock<()>>>>,
    run: PathBuf,
    /// This daemon, for the relays of instances carried after it started.
    this: Arc<std::sync::OnceLock<std::sync::Weak<Inner>>>,
    starting: tokio::sync::watch::Sender<BTreeMap<String, Client>>,
}
/// A child's socket, served until the daemon goes.
struct Relay {
    task: tokio::task::JoinHandle<()>,
    socket: PathBuf,
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.socket);
    }
}
/// The boundaries a daemon reaches beyond itself. Tests stand in for them.
pub struct Seams {
    /// Image tags to digests.
    pub resolver: Arc<dyn ImageResolver>,
    /// The SSH link to a vessel's agent.
    pub dialer: Arc<dyn crate::agent::SshDialer>,
    /// The agent build a vessel's older agent is upgraded to.
    pub builds: Arc<dyn AgentBuilds>,
    /// Where exposures put things in a vessel.
    pub guest: crate::exposures::GuestLayout,
    pub timing: crate::exposures::Timing,
    /// Registries, as staging reaches them.
    pub registries: crate::staging::Transfer,
}
impl Seams {
    pub fn new(resolver: Arc<dyn ImageResolver>) -> Self {
        Self {
            resolver,
            dialer: Arc::new(crate::agent::OpenSsh),
            builds: Arc::new(InstalledBuilds),
            guest: Default::default(),
            timing: Default::default(),
            registries: Default::default(),
        }
    }
}

/// Where the daemon finds the agent build for a vessel's platform. An embedding
/// daemon that ships its own agent gives it here, so the daemon and the
/// embedder never upgrade a vessel's agent to two different builds.
#[async_trait::async_trait]
pub trait AgentBuilds: Send + Sync {
    async fn build(&self, platform: &Platform) -> Result<Vec<u8>, String>;
}
/// The installed companion beside this executable, or its override variable.
pub struct InstalledBuilds;
#[async_trait::async_trait]
impl AgentBuilds for InstalledBuilds {
    async fn build(&self, platform: &Platform) -> Result<Vec<u8>, String> {
        let path = drydock_provider::agent_build::agent_build(platform)?;
        tokio::fs::read(&path).await.map_err(|error| format!("{}: {error}", path.display()))
    }
}
/// Serves a child's socket: for each connection, the parent opens a stream to
/// the child's endpoint, and the two are joined until either ends. While the
/// daemon starts, the parent's host opens it once that host is configured, so
/// a child's first connection, made while it is configured, reaches its
/// endpoint.
async fn relay(
    daemon: Arc<std::sync::OnceLock<std::sync::Weak<Inner>>>,
    starting: tokio::sync::watch::Receiver<BTreeMap<String, Client>>,
    child: String,
    carrier: (String, Carried),
    listener: tokio::net::UnixListener,
    mut stopping: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            _ = stopping.wait_for(|stopped| *stopped) => break,
            accepted = listener.accept() => accepted,
        };
        let mut connection = match accepted {
            Ok((connection, _)) => connection,
            Err(error) => {
                tracing::warn!(provider = %child, %error, "accepting on the child's socket failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let (daemon, mut starting, child, (parent, endpoint), mut stopping) =
            (daemon.clone(), starting.clone(), child.clone(), carrier.clone(), stopping.clone());
        tokio::spawn(async move {
            let opened = async {
                // Until then the parent's Runtime has not committed it, so the
                // stream skips its readiness check and rate budget.
                if daemon.get().is_none()
                    && let Ok(host) = starting.wait_for(|hosts| hosts.contains_key(&parent)).await.map(|hosts| hosts[&parent].clone())
                {
                    return host.open_stream(&parent, &endpoint).await;
                }
                let inner = daemon.get().and_then(std::sync::Weak::upgrade);
                let inner = inner.ok_or_else(|| Error::Transport("drydockd did not start".into()))?;
                Daemon::from_inner(inner).hop(&child).await
            };
            let opened = tokio::select! {
                _ = stopping.wait_for(|stopped| *stopped) => return,
                opened = opened => opened,
            };
            match opened {
                Ok(mut stream) => {
                    tokio::select! {
                        _ = stopping.wait_for(|stopped| *stopped) => {}
                        _ = tokio::io::copy_bidirectional(&mut connection, &mut stream) => {}
                    }
                }
                // The child's readiness already says its parent is not ready.
                Err(error @ Error::NotReady(_)) => {
                    tracing::debug!(provider = %child, %parent, %error, "no stream while the parent is not ready")
                }
                Err(error) => {
                    tracing::warn!(provider = %child, %parent, %error, "the parent could not open a stream to the child's endpoint")
                }
            }
        });
    }
}
impl Daemon {
    pub async fn start(config: Config, run: &FsPath, keys: PathBuf, options: Vec<HostOption>) -> Result<Arc<Self>, String> {
        let resolver = Arc::new(RegistryResolver::new().map_err(|e| e.to_string())?);
        Self::start_with_resolver(config, run, keys, options, resolver).await
    }
    /// Inject the image boundary before the daemon is shared; no Arc mutation or
    /// unique-reference runtime precondition is needed.
    pub async fn start_with_resolver(
        config: Config,
        run: &FsPath,
        keys: PathBuf,
        options: Vec<HostOption>,
        resolver: Arc<dyn ImageResolver>,
    ) -> Result<Arc<Self>, String> {
        Self::start_with_seams(config, run, keys, options, Seams::new(resolver)).await
    }
    /// Start with every outside boundary given. Stored exposures are taken up again.
    pub async fn start_with_seams(
        config: Config,
        run: &FsPath,
        keys: PathBuf,
        options: Vec<HostOption>,
        seams: Seams,
    ) -> Result<Arc<Self>, String> {
        let Seams { resolver, dialer, builds, guest, timing, registries } = seams;
        crate::local::private_dir(run)?;
        let mut supervisor = Supervisor::new(run.join("hosts"), Arc::new(BuiltinCredentials::default()));
        supervisor.state_directory = Some(run.join("events"));
        let mut discovered = Vec::new();
        let mut failed_optional = BTreeSet::new();
        for option in options {
            match discover(&option, run).await {
                Ok(hello) => discovered.push((option, hello)),
                Err(error) if option.optional => {
                    eprintln!("optional host discovery failed");
                    failed_optional.insert(if error == "host protocol version mismatch" {
                        "optional host protocol version mismatch".to_owned()
                    } else {
                        "optional host unavailable".to_owned()
                    });
                }
                Err(error) => return Err(error),
            }
        }
        // Input order is the routing priority. Select once for both routing and
        // advertisements, including modules without configured instances.
        let mut selected = BTreeMap::new();
        for (i, (_, hello)) in discovered.iter().enumerate() {
            for module in &hello.loadable_modules {
                selected.entry(module.name.clone()).or_insert((i, module.clone()));
            }
        }
        let mut assignments: Vec<Vec<String>> = (0..discovered.len()).map(|_| vec![]).collect();
        let mut chosen = BTreeMap::new();
        let mut unavailable = BTreeMap::new();
        for (name, provider) in &config.providers {
            // Stable host order prefers the bundled Rust implementation.
            if let Some((i, module)) = selected.get(&provider.module) {
                let i = *i;
                assignments[i].push(name.clone());
                chosen.insert(name.clone(), (i, module.smallest_size.clone()));
            } else {
                let mut reason = "no installed host can load configured module".to_owned();
                if !failed_optional.is_empty() {
                    reason.push_str(&format!("; {}", failed_optional.iter().map(String::as_str).collect::<Vec<_>>().join("; ")));
                }
                unavailable.insert(name.clone(), Readiness::MissingTool { reason });
            }
        }
        config.check_parents()?;
        let mut carried = BTreeMap::new();
        let daemon = Arc::new(std::sync::OnceLock::new());
        // Each parent's host, from when it is started until the daemon is.
        let starting = tokio::sync::watch::channel(BTreeMap::new()).0;
        let stopping = tokio::sync::watch::channel(false).0;
        for (name, provider) in &config.providers {
            let Some(parent) = &provider.parent else { continue };
            if let Some((_, module)) = selected.get(&provider.module)
                && !module.takes_endpoint
            {
                return Err(format!("provider {name}: module {} cannot be given its endpoint, so it has no parent", provider.module));
            }
            let endpoint = parent.endpoint.clone().expect("a configured parent names its endpoint");
            let (socket, listener) = child_socket(run, name)?;
            let carrier = (parent.instance.clone(), endpoint.clone());
            let task = tokio::spawn(relay(daemon.clone(), starting.subscribe(), name.clone(), carrier, listener, stopping.subscribe()));
            let relay = Relay { task, socket: socket.clone() };
            let carrier = Carrier { parent: parent.instance.clone(), endpoint, socket, _relay: relay, carriage: None };
            carried.insert(name.clone(), Arc::new(carrier));
        }
        let mut hosts = Vec::new();
        let mut placements = BTreeMap::new();
        let mut modules = BTreeMap::new();
        for (i, (option, _)) in discovered.into_iter().enumerate() {
            let mut providers = BTreeMap::new();
            let mut credentials = BTreeMap::new();
            for name in &assignments[i] {
                let p = &config.providers[name];
                let mut configuration = p.configuration();
                configuration.endpoint = carried.get(name).map(|c| c.local());
                providers.insert(name.clone(), configuration);
                // A credential path that cannot be resolved (for example, no
                // HOME for ~/...) is missing evidence, not a daemon failure.
                // The supervisor reports MissingCredential for absent references.
                if let Some(Ok(reference)) =
                    p.credential.as_ref().map(|source| crate::config::credential_reference(source, &rigging_process::ProcessEnvVars))
                {
                    credentials.insert(name.clone(), reference);
                }
                placements.insert(name.clone(), Placement { host: hosts.len(), minimum: chosen[name].1.clone() });
            }
            let spec =
                HostSpec { name: option.name, connection: option.connection, configuration: Configuration { providers }, credentials };
            let mut handle = match supervisor.start(spec).await {
                Ok(handle) => handle,
                Err(_) if option.optional => {
                    for name in &assignments[i] {
                        placements.remove(name);
                        unavailable.insert(name.clone(), Readiness::Unknown { reason: "optional host could not start".into() });
                    }
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            };
            starting.send_modify(|hosts| {
                for name in assignments[i].iter().filter(|name| carried.values().any(|c| &c.parent == *name)) {
                    hosts.insert(name.clone(), handle.host.clone());
                }
            });
            for (name, (selected_host, module)) in &selected {
                if *selected_host == i {
                    modules.insert(name.clone(), (hosts.len(), module.clone()));
                }
            }
            // Providers with absent credentials remain visible with their reason.
            let _ = handle.ready(Duration::from_secs(15)).await;
            let status = handle.status.borrow().clone();
            let cache = StatusCache::new(handle.client.clone(), &status.providers);
            hosts.push(ManagedHost { handle, cache: Mutex::new((status.generation, Arc::new(cache))) });
        }
        for (name, carrier) in &carried {
            let Some(placement) = placements.get(&carrier.parent) else { continue };
            let status = hosts[placement.host].handle.status.borrow().clone();
            let Some(parent) = status.providers.iter().find(|d| d.provider == carrier.parent) else { continue };
            if !parent.capabilities.carries.contains(&carrier.endpoint.kind()) {
                return Err(format!(
                    "provider {name}: parent {} (module {}) carries no {} endpoints",
                    carrier.parent,
                    parent.module,
                    carrier.endpoint.kind()
                ));
            }
        }
        let staging = crate::staging::Staging::new(registries, config.registries.clone());
        let inner = Arc::new_cyclic(|weak| Inner {
            carried: std::sync::RwLock::new(carried),
            turns: Default::default(),
            run: run.to_owned(),
            this: daemon.clone(),
            starting,
            config,
            staging,
            modules,
            hosts,
            placements,
            unavailable,
            exposures: crate::exposures::Exposures::new(weak.clone(), run, keys.clone(), guest, timing),
            keys,
            resolver,
            dialer,
            builds,
            keying: Default::default(),
            stopping,
        });
        let _ = inner.this.set(Arc::downgrade(&inner));
        inner.exposures.restore();
        Ok(Arc::new(Self { inner, credential: None }))
    }
    pub(crate) fn exposures(&self) -> &crate::exposures::Exposures {
        &self.exposures
    }
    pub(crate) fn from_inner(inner: Arc<Inner>) -> Self {
        Self { inner, credential: None }
    }
    fn host(&self, provider: &str) -> Result<&ManagedHost, Error> {
        Ok(&self.hosts[self.host_index(provider)?])
    }
    fn host_index(&self, provider: &str) -> Result<usize, Error> {
        if let Some(placement) = self.placements.get(provider) {
            return Ok(placement.host);
        }
        if let Some(carriage) = self.carrier(provider).and_then(|c| c.carriage.clone()) {
            return Ok(carriage.host);
        }
        Err(match self.unavailable.get(provider) {
            Some(readiness) => Error::NotReady(readiness.clone()),
            None => Error::Protocol(ProtocolError::unknown_provider()),
        })
    }
    fn carrier(&self, name: &str) -> Option<Arc<Carrier>> {
        self.carried.read().unwrap().get(name).cloned()
    }
    /// Host readiness gates here. Each provider's own readiness, including a
    /// stored credential rejection, is the host Runtime's admission policy.
    fn ready_host(&self, provider: &str) -> Result<&ManagedHost, Error> {
        let host = self.host(provider)?;
        match host.handle.status.borrow().readiness.clone() {
            Readiness::Ready => {}
            readiness => return Err(Error::NotReady(readiness)),
        }
        match self.parent_unready(provider, &self.statuses()) {
            Some(readiness) => Err(Error::NotReady(readiness)),
            None => Ok(host),
        }
    }
    fn runtime(&self, provider: &str) -> Result<crate::runtime::Runtime, Error> {
        Ok(self.ready_host(provider)?.handle.client.credentialed(self.credential.clone()))
    }
    /// Mutations discard cached status reads, whatever their outcome.
    async fn invalidating<T, E>(&self, provider: &str, result: Result<T, E>) -> Result<T, E> {
        if let Ok(host) = self.host(provider) {
            let cache = host.cache.lock().await.1.clone();
            cache.invalidate(provider).await;
        }
        result
    }
    async fn cache(&self, provider: &str) -> Result<Arc<StatusCache<crate::runtime::Runtime>>, Error> {
        let host = self.ready_host(provider)?;
        let status = host.handle.status.borrow().clone();
        let mut cache = host.cache.lock().await;
        if cache.0 != status.generation {
            *cache = (status.generation, Arc::new(StatusCache::new(host.handle.client.clone(), &status.providers)));
        }
        Ok(cache.1.clone())
    }
    pub fn hello(&self) -> Hello {
        let statuses: Vec<_> = self.hosts.iter().map(|h| h.handle.status.borrow().clone()).collect();
        Hello {
            protocol_version: PROTOCOL_VERSION.into(),
            host_version: env!("CARGO_PKG_VERSION").into(),
            loadable_modules: self
                .modules
                .iter()
                .filter_map(|(name, (host, module))| {
                    let status = &statuses[*host];
                    if matches!(status.readiness, Readiness::Ready) {
                        status.loadable_modules.iter().find(|m| &m.name == name).cloned()
                    } else {
                        Some(module.clone())
                    }
                })
                .collect(),
        }
    }
    /// Every configured provider, including those no host can serve, with the reason, and every carried one.
    pub fn providers(&self) -> Vec<ProviderDeclaration> {
        let statuses = self.statuses();
        self.names()
            .iter()
            .map(|name| {
                let mut declaration = self.declared(name, &statuses);
                if let Some(readiness) = self.parent_unready(name, &statuses) {
                    declaration.readiness = readiness;
                }
                declaration
            })
            .collect()
    }
    fn names(&self) -> BTreeSet<String> {
        let carried = self.carried.read().unwrap();
        let carried = carried.iter().filter(|(_, c)| c.carriage.is_some()).map(|(name, _)| name.clone());
        self.config.providers.keys().cloned().chain(carried).collect()
    }
    fn statuses(&self) -> Vec<crate::HostStatus> {
        self.hosts.iter().map(|h| h.handle.status.borrow().clone()).collect()
    }
    /// A child's readiness while its parent, or one above it, is not ready.
    fn parent_unready(&self, name: &str, statuses: &[crate::HostStatus]) -> Option<Readiness> {
        let parent = &self.carrier(name)?.parent;
        let readiness = self.parent_unready(parent, statuses).unwrap_or_else(|| self.declared(parent, statuses).readiness);
        (readiness != Readiness::Ready).then(|| Readiness::ParentNotReady { parent: parent.clone(), reason: readiness.to_string() })
    }
    /// What the provider's host declares, or why there is no declaration.
    fn declared(&self, name: &str, statuses: &[crate::HostStatus]) -> ProviderDeclaration {
        let carrier = self.carrier(name);
        let carriage = carrier.as_ref().and_then(|c| c.carriage.clone());
        let (module, parent, host) = match (self.config.providers.get(name), &carriage) {
            (Some(configured), _) => (configured.module.clone(), configured.parent.clone(), self.placements.get(name).map(|p| p.host)),
            (None, Some(carriage)) => (carriage.body.module.clone(), Some(carriage.body.parent.clone()), Some(carriage.host)),
            (None, None) => (String::new(), None, None),
        };
        let status = host.map(|host| &statuses[host]);
        let mut declaration = status
            .and_then(|s| s.providers.iter().find(|p| p.provider == name && p.module == module))
            .cloned()
            .unwrap_or_else(|| ProviderDeclaration {
                provider: name.to_owned(),
                module: module.clone(),
                capabilities: conservative_capabilities(),
                rate_limits: vec![],
                readiness: Readiness::Unknown { reason: "provider absent from its host".into() },
                ports: Ports::default(),
                ways_in: None,
                endpoint: None,
                parent: None,
            });
        declaration.endpoint = carrier.map(|c| c.local());
        declaration.parent = parent;
        if carriage.is_some() {
            // Its capacity is the parent environment's size, which drydockd states.
            declaration.capabilities.quota = true;
            declaration.ports.quota = true;
        }
        if let Some(readiness) = self.unavailable.get(name) {
            declaration.readiness = readiness.clone();
        } else if let Some(status) = status
            && !matches!(status.readiness, Readiness::Ready)
        {
            declaration.readiness = status.readiness.clone();
        }
        declaration
    }
    /// Daemon routes first; every provider operation falls through to the shared router.
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/v1/providers/{provider}/launch", post(launch_route))
            .route("/v1/providers/{provider}/prepare", post(prepare_route))
            .route("/v1/providers/{provider}/environments/{id}/shell", post(shell_route))
            .method_not_allowed_fallback(crate::api::method_not_allowed)
            .with_state(self.clone())
            .fallback_service(crate::api::server_router(self.clone(), self.stopping.subscribe()))
    }
    pub async fn serve(
        self: &Arc<Self>,
        socket: &FsPath,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> std::io::Result<()> {
        use rigging_http_serve::{Caller, UnixServer};
        let uid = rustix::process::geteuid().as_raw();
        let router = self.router().layer(middleware::from_fn(
            move |axum::Extension(caller): axum::Extension<Caller>, req: Request, next: Next| async move {
                match caller {
                    Caller::Unix(peer) if peer.uid == uid => next.run(req).await,
                    _ => StatusCode::FORBIDDEN.into_response(),
                }
            },
        ));
        let stopping = self.stopping.clone();
        UnixServer::bind(socket, 0o600)
            .await?
            .serve(router, Caller::<()>::Unix, async move {
                shutdown.await;
                stopping.send_replace(true);
            })
            .await
    }
    pub async fn prepare(&self, provider: &str, options: &LaunchOptions) -> Result<(Prepared, Size), Error> {
        let host = self.ready_host(provider)?;
        let request =
            launch::prepare_request(self.configured(provider)?, &self.placements[provider].minimum, options, self.resolver.as_ref())
                .await?;
        let request = self.staged(provider, request).await?;
        let prepared = host.handle.client.credentialed(self.credential.clone()).prepare(provider, &request).await?;
        Ok((prepared, request.size))
    }
    /// The prepare request with its image staged where the provider takes it
    /// from: into its own registry on the provider-push route, when it mints
    /// push access; into a declared registry on the registry-pull route, when
    /// this instance pulls from some. A route or platform the provider does
    /// not declare is the host's to refuse.
    async fn staged(&self, provider: &str, request: PrepareRequest) -> Result<PrepareRequest, Error> {
        let pull_from = self.config.providers.get(provider).map(|p| p.pull_from.as_slice()).unwrap_or_default();
        // An unready host is the prepare call's to report.
        let Ok(host) = self.ready_host(provider) else { return Ok(request) };
        let status = host.handle.status.borrow().clone();
        let Some(declaration) = status.providers.iter().find(|d| d.provider == provider) else { return Ok(request) };
        let capabilities = &declaration.capabilities;
        let route = crate::runtime::module::resolve_route(request.route, &capabilities.image_routes);
        let platform = crate::runtime::module::resolve_platform(request.platform.clone(), &capabilities.platforms);
        let (Ok(kind), Ok(platform)) = (route, platform) else { return Ok(request) };
        let Some(route) = capabilities.image_routes.iter().find(|r| r.kind() == kind) else { return Ok(request) };
        let request = PrepareRequest { route: Some(kind), ..request };
        match route {
            ImageRoute::ProviderPush { max_image_bytes, chunk_bytes, .. } if declaration.ports.push_access => {
                let runtime = self.runtime(provider)?;
                let mint = async {
                    runtime.push_access(provider).await.map_err(|error| match error {
                        Error::Protocol(error) => error,
                        other => ProtocolError::unavailable(format!("mint push access: {other}"), Some(5)),
                    })
                };
                let limits = crate::staging::Limits { max_image_bytes: *max_image_bytes, chunk_bytes: *chunk_bytes };
                Ok(self.staging.push(provider, mint, request, &platform, limits).await?)
            }
            ImageRoute::ProviderPush { .. } => {
                tracing::warn!(provider, "provider declares the provider-push route without the push-access port; the image is not staged");
                Ok(request)
            }
            ImageRoute::RegistryPull { .. } if !pull_from.is_empty() => Ok(self.staging.stage(pull_from, request, &platform).await?),
            _ => Ok(request),
        }
    }
    pub async fn launch(&self, provider: &str, options: &LaunchOptions) -> Result<Environment, ProvisionError> {
        let (prepared, size) = self.prepare(provider, options).await?;
        let platform = prepared.platform.clone();
        let label = uuid::Uuid::new_v4().to_string();
        let dir = self.keys.join(&label);
        let (_, public) = launch::keypair(&dir).await?;
        let request = ProvisionRequest {
            label,
            prepared,
            size,
            egress: options.egress.or(self.configured(provider)?.egress).unwrap_or(Egress::Open).request(),
            ssh_public_key: Some(public),
        };
        // Retain key and the resolved digests even on an ambiguous provision error.
        // This is launch evidence and key ownership, never desired-state reconciliation.
        tokio::fs::write(dir.join("request.json"), serde_json::to_vec(&request).expect("provision request serializes"))
            .await
            .map_err(|e| Error::Transport(format!("record launch request: {e}")))?;
        // Preparation can outlast a host generation or credential change. Use
        // this fresh readiness check and its host for the actual provision call.
        let host = self.ready_host(provider)?;
        // The provider declares whether its vessels run the agent; the module name does not.
        let agent = host.handle.status.borrow().providers.iter().any(|d| d.provider == provider && d.capabilities.agent);
        // Find the agent build for the prepared platform before creating anything.
        let agent_build = if agent { Some(self.agent_build(&platform).await?) } else { None };
        let client = host.handle.client.credentialed(self.credential.clone());
        let provisioned = self.invalidating(provider, client.provision(provider, &request).await).await?;
        if let Some(build) = agent_build {
            let (crate::api::Provisioned::Created(environment) | crate::api::Provisioned::Existing(environment)) = &provisioned;
            let left = |error| ProvisionError::made(error, provider, &environment.id);
            self.bootstrap(&client, provider, &provisioned, build.clone()).await.map_err(left)?;
            self.agent_ready(provider, environment, &platform, &build).await.map_err(left)?;
        }
        Ok(provisioned.into_inner())
    }
    /// A configured provider's launch defaults. A carried instance has none.
    fn configured(&self, provider: &str) -> Result<&crate::config::Provider, Error> {
        self.config.providers.get(provider).ok_or_else(|| match self.carrier(provider) {
            Some(_) => {
                launch::refused(format!("provider {provider} is carried and has no launch defaults; prepare it with a whole request"))
            }
            None => Error::Protocol(ProtocolError::unknown_provider()),
        })
    }
    /// Whether drydock puts and starts this provider's vessel agents itself:
    /// its vessels run one, on the upload route, through its files and exec ports.
    fn uploads(&self, provider: &str) -> bool {
        let Ok(host) = self.host(provider) else { return false };
        let status = host.handle.status.borrow();
        status.providers.iter().any(|d| {
            d.provider == provider
                && d.capabilities.agent
                && d.capabilities.bootstrap == BootstrapRoute::Upload
                && d.ports.files
                && d.ports.exec
        })
    }
    /// Upload bootstrap, for a running vessel of a provider that takes it:
    /// its agent put in place (a re-adopted or resumed vessel's only when
    /// absent) and started. Launch, a client's provision and resume all come
    /// here. Returns what the start printed, if it ran.
    async fn bootstrap(
        &self,
        api: &dyn ProviderApi,
        provider: &str,
        provisioned: &crate::api::Provisioned<Environment>,
        build: bytes::Bytes,
    ) -> Result<Option<Secret>, Error> {
        let (environment, fresh) = match provisioned {
            crate::api::Provisioned::Created(environment) => (environment, true),
            crate::api::Provisioned::Existing(environment) => (environment, false),
        };
        if !self.uploads(provider) || !matches!(environment.state, Observation::Running) {
            return Ok(None);
        }
        let tcp_port = self
            .host(provider)?
            .handle
            .status
            .borrow()
            .providers
            .iter()
            .find(|d| d.provider == provider)
            .and_then(|d| d.capabilities.agent_tcp_port);
        launch::upload_agent(api, provider, &environment.id, build, fresh, tcp_port).await.map(Some)
    }
    /// The agent build for a vessel's platform (see [`vessel_platform`]).
    async fn build_for(&self, environment: &Environment, platform: Option<&Platform>) -> Result<bytes::Bytes, Error> {
        let host = self.host(&environment.provider)?;
        let status = host.handle.status.borrow().clone();
        let declared = status.providers.iter().find(|d| d.provider == environment.provider).map(|d| &d.capabilities.platforms[..]);
        let platform = vessel_platform(platform, environment, declared.unwrap_or_default()).ok_or_else(|| {
            Error::Protocol(ProtocolError::Refused { reason: "the vessel's platform is unknown, so no agent build can be chosen".into() })
        })?;
        self.agent_build(&platform).await
    }
    /// Wait for the vessel agent's current hello, pushing `build` (the agent for
    /// the prepared `platform`) to an older one.
    async fn agent_ready(&self, provider: &str, environment: &Environment, platform: &Platform, build: &[u8]) -> Result<(), Error> {
        self.agent(provider, environment, platform, build, Duration::from_secs(60)).await.map(drop)
    }
    async fn agent(
        &self,
        provider: &str,
        environment: &Environment,
        platform: &Platform,
        build: &[u8],
        timeout: Duration,
    ) -> Result<drydock_agent::Client, Error> {
        let identity = self.key_for(environment)?;
        let client = &self.runtime(provider)?;
        let vessel = crate::agent::Vessel { provider, environment: &environment.id, identity: &identity, platform, build };
        let reach = crate::agent::AgentReach::new().with_dialer(self.dialer.clone()).with_timeout(timeout);
        Ok(reach.connect(client, &vessel).await?.client)
    }
    /// Connect to the agent of a vessel drydock launched, for the platform
    /// it was prepared for (recorded at launch).
    pub(crate) async fn connect_agent(&self, provider: &str, id: &str, timeout: Duration) -> Result<drydock_agent::Client, Error> {
        let environment = ProviderApi::inspect(self, provider, id).await?;
        let identity = self.key_for(&environment)?;
        let launch = identity.with_file_name("request.json");
        let request = tokio::fs::read(&launch).await.map_err(|e| Error::Transport(format!("launch record {}: {e}", launch.display())))?;
        let request: ProvisionRequest =
            serde_json::from_slice(&request).map_err(|e| Error::InvalidResponse(format!("launch record: {e}")))?;
        let platform = request.prepared.platform;
        let build = self.agent_build(&platform).await?;
        self.agent(provider, &environment, &platform, &build, timeout).await
    }
    async fn agent_build(&self, platform: &Platform) -> Result<bytes::Bytes, Error> {
        self.builds
            .build(platform)
            .await
            .map(bytes::Bytes::from)
            .map_err(|reason| Error::Protocol(ProtocolError::Refused { reason: format!("no vessel agent build for {platform}: {reason}") }))
    }

    /// A provision that names no public key, for a provider whose vessels run
    /// the agent: drydock holds the vessel's key, as for a launch, under the
    /// client's label. The label's key is made once and reused, so the
    /// provision stays label-idempotent; an environment the label already names
    /// that drydock holds no key for is refused, since its key cannot be rotated.
    async fn keyed(&self, provider: &str, request: &ProvisionRequest) -> Result<Option<ProvisionRequest>, Error> {
        if request.ssh_public_key.is_some() {
            return Ok(None);
        }
        let directory = self.client_key_directory(&request.label);
        let held = directory.join("id_ed25519");
        let holds = || held.is_file() && held.with_extension("pub").is_file();
        // A key drydock already holds was made for a provider that runs the agent.
        if !holds() && !ProviderApi::provider(self, provider).await?.capabilities.agent {
            return Ok(None);
        }
        let lock = {
            let mut locks = self.keying.lock().unwrap();
            locks.retain(|_, lock| lock.strong_count() > 0);
            let lock = locks.get(&request.label).and_then(std::sync::Weak::upgrade).unwrap_or_default();
            locks.insert(request.label.clone(), Arc::downgrade(&lock));
            lock
        };
        let _keying = lock.lock().await;
        let public = if holds() {
            tokio::fs::read_to_string(held.with_extension("pub"))
                .await
                .map_err(|e| Error::Transport(format!("read vessel SSH public key: {e}")))?
        } else {
            // The host's list is the provider's whole inventory, unpaged and
            // unfiltered, so a label naming an environment is found here. A client
            // provisioning the label with its own key between this check and the
            // provision below is adopted without drydock's key: labels are the
            // client's, and drydock does not arbitrate between two clients of one.
            let existing = self.runtime(provider)?.list(provider).await?;
            let named = |e: &Environment| e.live() && e.label.as_deref() == Some(request.label.as_str());
            if existing.iter().any(named) {
                return Err(Error::Protocol(ProtocolError::Refused {
                    reason: "drydock holds no SSH key for the environment this label names".into(),
                }));
            }
            for file in [held.clone(), held.with_extension("pub")] {
                match tokio::fs::remove_file(&file).await {
                    Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                        return Err(Error::Transport(format!("remove partial vessel SSH key: {error}")));
                    }
                    _ => {}
                }
            }
            launch::keypair(&directory).await?.1
        };
        let request = ProvisionRequest { ssh_public_key: Some(public), ..request.clone() };
        // The agent connection reads the prepared platform from this record. The
        // first one stands, as the environment it made does; it is written whole
        // or not at all.
        if directory.join("request.json").is_file() {
            return Ok(Some(request));
        }
        let staged = directory.join("request.json.new");
        tokio::fs::write(&staged, serde_json::to_vec(&request).expect("provision request serializes"))
            .await
            .map_err(|e| Error::Transport(format!("record provision request: {e}")))?;
        tokio::fs::rename(&staged, directory.join("request.json"))
            .await
            .map_err(|e| Error::Transport(format!("record provision request: {e}")))?;
        Ok(Some(request))
    }

    /// The directory holding a client label's key, named by the label's
    /// digest: a label never selects a filesystem path, nor a launch's key.
    fn client_key_directory(&self, label: &str) -> PathBuf {
        self.keys.join(format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(label.as_bytes())))
    }
    pub fn key_for(&self, environment: &Environment) -> Result<PathBuf, Error> {
        let label = environment
            .label
            .as_deref()
            .ok_or_else(|| Error::Protocol(ProtocolError::Refused { reason: "environment has no drydock-managed SSH key".into() }))?;
        // A launch's own UUID label names its key directory directly.
        if let Ok(uuid) = uuid::Uuid::parse_str(label)
            && uuid.hyphenated().to_string() == label
        {
            let launched = self.keys.join(label).join("id_ed25519");
            if launched.is_file() {
                return Ok(launched);
            }
        }
        Ok(self.client_key_directory(label).join("id_ed25519"))
    }
}
// Routing between per-host runtimes. Policy stays in each host's Runtime;
// the Daemon adds only placement and its existing status-read cache.
#[async_trait::async_trait]
impl ProviderApi for Daemon {
    async fn hello(&self) -> Result<Hello, Error> {
        Ok(Daemon::hello(self))
    }
    /// The daemon reads its configuration file at start: a document that
    /// changes it is refused.
    async fn configure(&self, update: crate::api::ConfigUpdate) -> Result<(), Error> {
        let current = self.config.document();
        if update.apply(&current)? != current {
            return Err(Error::Protocol(ProtocolError::Refused {
                reason: "drydockd reads its configuration file at start; edit the file and restart drydockd".into(),
            }));
        }
        Ok(())
    }
    async fn providers(&self) -> Result<Vec<ProviderDeclaration>, Error> {
        Ok(Daemon::providers(self))
    }
    async fn provider(&self, p: &str) -> Result<ProviderDeclaration, Error> {
        if self.credential.is_some() {
            return self.runtime(p)?.provider(p).await;
        }
        let declaration = Daemon::providers(self).into_iter().find(|d| d.provider == p);
        declaration.ok_or_else(|| Error::Protocol(ProtocolError::unknown_provider()))
    }
    async fn credential(&self, p: &str, value: Secret) -> Result<(), Error> {
        self.runtime(p)?.credential(p, value).await.map_err(Error::Protocol)
    }
    fn with_credential(&self, credential: Secret) -> Arc<dyn ProviderApi> {
        Arc::new(Self { inner: self.inner.clone(), credential: Some(credential) })
    }
    async fn observe(&self, since: Option<&str>) -> Result<crate::api::ObservationStream, Error> {
        Ok(self.observation_stream(since))
    }
    async fn prepare(&self, p: &str, request: &PrepareRequest) -> Result<Prepared, Error> {
        let request = self.staged(p, request.clone()).await?;
        self.runtime(p)?.prepare(p, &request).await
    }
    async fn provision(&self, p: &str, request: &ProvisionRequest) -> Result<crate::api::Provisioned<Environment>, ProvisionError> {
        let _turn = self.provisioning(p).await;
        let keyed = self.keyed(p, request).await?;
        let provisioned = self.invalidating(p, self.runtime(p)?.provision(p, keyed.as_ref().unwrap_or(request)).await).await?;
        if self.uploads(p) {
            let (crate::api::Provisioned::Created(environment) | crate::api::Provisioned::Existing(environment)) = &provisioned;
            let left = |error| ProvisionError::made(error, p, &environment.id);
            let build = self.build_for(environment, Some(&request.prepared.platform)).await.map_err(left)?;
            self.bootstrap(&self.runtime(p).map_err(left)?, p, &provisioned, build).await.map_err(left)?;
        }
        Ok(provisioned)
    }
    async fn list(&self, p: &str) -> Result<Vec<Environment>, Error> {
        if self.credential.is_some() {
            return self.runtime(p)?.list(p).await;
        }
        self.cache(p).await?.list(p).await
    }
    async fn inspect(&self, p: &str, id: &str) -> Result<Environment, Error> {
        if self.credential.is_some() {
            return environment(self.runtime(p)?.inspect(p, id).await);
        }
        environment(self.cache(p).await?.inspect(p, id).await)
    }
    async fn destroy(&self, p: &str, id: &str) -> Result<(), Error> {
        environment(self.invalidating(p, self.runtime(p)?.destroy(p, id).await).await)?;
        self.exposures.forget(p, id).await;
        self.parent_gone(p, id).await;
        Ok(())
    }
    async fn reach(&self, p: &str, id: &str) -> Result<Reach, Error> {
        environment(self.runtime(p)?.reach(p, id).await)
    }
    async fn suspend(&self, p: &str, id: &str) -> Result<ResumeToken, Error> {
        let result = self.invalidating(p, self.runtime(p)?.suspend(p, id).await).await;
        self.exposures.poke(p, id);
        environment(result)
    }
    async fn resume(&self, p: &str, id: &str, token: &ResumeToken) -> Result<(), Error> {
        let mut result = self.invalidating(p, self.runtime(p)?.resume(p, id, token).await).await;
        // The supervisor died with the vessel's processes; start it again.
        if result.is_ok() && self.uploads(p) {
            let runtime = self.runtime(p)?;
            result = async {
                let environment = runtime.inspect(p, id).await?;
                let build = self.build_for(&environment, None).await?;
                self.bootstrap(&runtime, p, &crate::api::Provisioned::Existing(environment), build).await.map(drop)
            }
            .await;
        }
        self.exposures.poke(p, id);
        if result.is_ok() {
            self.parent_resumed(p, id).await;
        }
        environment(result)
    }
    async fn export(&self, p: &str, id: &str) -> Result<Export, Error> {
        environment(self.invalidating(p, self.runtime(p)?.export(p, id).await).await)
    }
    async fn quota(&self, p: &str) -> Result<Quota, Error> {
        if let Some(carrier) = self.carrier(p)
            && let Some(link) = carrier.link()
        {
            return self.carried_quota(p, link).await;
        }
        self.runtime(p)?.quota(p).await
    }
    async fn usage(&self, p: &str, period: &Period) -> Result<Usage, Error> {
        self.runtime(p)?.usage(p, period).await
    }
    async fn relay(&self, p: &str, id: &str) -> Result<rigging_stream::ByteStream, Error> {
        environment(self.runtime(p)?.relay(p, id).await)
    }
    async fn exec(&self, p: &str, id: &str, command: &ExecRequest) -> Result<rigging_stream::ByteStream, Error> {
        environment(self.runtime(p)?.exec(p, id, command).await)
    }
    async fn put_file(&self, p: &str, id: &str, file: &GuestFile, bytes: bytes::Bytes) -> Result<(), Error> {
        environment(self.runtime(p)?.put_file(p, id, file, bytes).await)
    }
    async fn put_provider(&self, name: &str, body: &Carry) -> Result<crate::api::Provisioned<ProviderDeclaration>, ProvisionError> {
        self.carry(name, body).await
    }
    async fn remove_provider(&self, name: &str) -> Result<(), Error> {
        self.uncarry(name).await
    }
    async fn put_service(&self, p: &str, id: &str, name: &str, service: &Service) -> Result<crate::api::Provisioned<ServiceInfo>, Error> {
        crate::exposures::check_named("service", name)?;
        let (started, info) = self.vessel_agent(p, id).await?.start_service(name, service).await.map_err(agent_error)?;
        Ok(crate::api::Provisioned::new(started, info))
    }
    async fn service(&self, p: &str, id: &str, name: &str) -> Result<ServiceInfo, Error> {
        self.vessel_agent(p, id).await?.service(name).await.map_err(agent_error)
    }
    async fn services(&self, p: &str, id: &str) -> Result<Vec<ServiceInfo>, Error> {
        self.vessel_agent(p, id).await?.services().await.map_err(agent_error)
    }
    async fn remove_service(&self, p: &str, id: &str, name: &str, grace_ms: Option<u64>) -> Result<ServiceInfo, Error> {
        self.vessel_agent(p, id).await?.remove_service(name, grace_ms.map(Duration::from_millis)).await.map_err(agent_error)
    }
    async fn push_access(&self, p: &str) -> Result<PushAccess, Error> {
        self.runtime(p)?.push_access(p).await
    }
    async fn put_inward(&self, p: &str, id: &str, name: &str, request: &InwardRequest) -> Result<Exposed<Inward>, Error> {
        let (existed, exposure) = self.exposures.put_inward(self, p, id, name, request).await?;
        Ok(if existed { Exposed::Replaced(exposure) } else { Exposed::Created(exposure) })
    }
    async fn inward(&self, p: &str, id: &str, name: &str) -> Result<Inward, Error> {
        self.exposures.inward(self, p, id, name).await
    }
    async fn inwards(&self, p: &str, id: &str) -> Result<Vec<Inward>, Error> {
        self.exposures.inwards(self, p, id).await
    }
    async fn remove_inward(&self, p: &str, id: &str, name: &str) -> Result<(), Error> {
        self.exposures.remove(self, p, id, Direction::Inward, name).await
    }
    async fn put_outward(&self, p: &str, id: &str, name: &str, request: &OutwardRequest) -> Result<Exposed<Outward>, Error> {
        let (existed, exposure) = self.exposures.put_outward(self, p, id, name, request).await?;
        Ok(if existed { Exposed::Replaced(exposure) } else { Exposed::Created(exposure) })
    }
    async fn outward(&self, p: &str, id: &str, name: &str) -> Result<Outward, Error> {
        self.exposures.outward(self, p, id, name).await
    }
    async fn outwards(&self, p: &str, id: &str) -> Result<Vec<Outward>, Error> {
        self.exposures.outwards(self, p, id).await
    }
    async fn remove_outward(&self, p: &str, id: &str, name: &str) -> Result<(), Error> {
        self.exposures.remove(self, p, id, Direction::Outward, name).await
    }
}
/// A `not_found` from an environment's route, its provider found, is the environment's.
fn environment<T>(result: Result<T, Error>) -> Result<T, Error> {
    result.map_err(|error| match error {
        Error::Protocol(ProtocolError::NotFound { reason, missing: None }) => {
            Error::Protocol(ProtocolError::NotFound { reason, missing: Some(Missing::Environment) })
        }
        other => other,
    })
}
async fn discover(option: &HostOption, run: &FsPath) -> Result<Hello, String> {
    let socket = run.join(format!("discover-{}.sock", option.name));
    let mut child = None;
    let client = match &option.connection {
        HostConnection::Managed { command, .. } => {
            let (program, args) = command.split_first().ok_or("empty host command")?;
            child = Some(
                tokio::process::Command::new(program)
                    .args(args)
                    .arg("--unix")
                    .arg(&socket)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .kill_on_drop(true)
                    .spawn()
                    .map_err(|e| format!("discover {}: {e}", option.name))?,
            );
            Client::unix(&socket)
        }
        HostConnection::ExternalUnix { path } => Client::unix(path),
        HostConnection::External { url, token_file } => {
            Client::external(url, crate::read_bearer_token(token_file).await.map_err(|e| e.to_string())?)
        }
    }
    .map_err(|e| e.to_string())?;
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match client.hello().await {
                Ok(hello) => return Ok(hello),
                Err(Error::VersionMismatch) => return Err("host protocol version mismatch".to_owned()),
                Err(_) => {
                    if let Some(c) = child.as_mut()
                        && c.try_wait().map_err(|e| e.to_string())?.is_some()
                    {
                        return Err("host exited during discovery".into());
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| "host discovery timed out".to_owned())
    .and_then(|v| v);
    if let Some(mut child) = child {
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _ = tokio::fs::remove_file(socket).await;
    }
    result
}
#[derive(Deserialize)]
#[serde(untagged)]
enum PrepareInput {
    Exact(PrepareRequest),
    Defaults(LaunchOptions),
}
async fn prepare_route(
    State(d): State<Arc<Daemon>>,
    ApiPath(p): ApiPath<String>,
    ApiJson(input): ApiJson<PrepareInput>,
) -> Result<Json<Prepared>, ApiError> {
    Ok(Json(match input {
        PrepareInput::Exact(r) => ProviderApi::prepare(&*d, &p, &r).await?,
        PrepareInput::Defaults(o) => d.prepare(&p, &o).await?.0,
    }))
}
async fn launch_route(
    State(d): State<Arc<Daemon>>,
    ApiPath(p): ApiPath<String>,
    ApiJson(o): ApiJson<LaunchOptions>,
) -> Result<Json<Environment>, ProvisionAnswer> {
    Ok(Json(d.launch(&p, &o).await?))
}
async fn shell_route(
    State(d): State<Arc<Daemon>>,
    ApiPath((p, id)): ApiPath<(String, String)>,
) -> Result<Json<crate::shell::Session>, ApiError> {
    let client = d.runtime(&p)?;
    let reach = client.reach(&p, &id).await?;
    match reach {
        Reach::Ssh { .. } => {}
        Reach::Dial { .. } => {
            return Err(Error::Protocol(ProtocolError::Refused {
                reason: "shell over Dial needs the vessel agent; only SSH is available yet".into(),
            })
            .into());
        }
        Reach::Relay { .. } => {
            return Err(Error::Protocol(ProtocolError::Refused {
                reason: "shell over Relay needs the vessel agent; only SSH is available yet".into(),
            })
            .into());
        }
    }
    let environment = client.inspect(&p, &id).await?;
    Ok(Json(crate::shell::Session { reach, identity_file: d.key_for(&environment)? }))
}

impl Daemon {
    fn observation_stream(&self, since: Option<&str>) -> crate::api::ObservationStream {
        use futures::{StreamExt, stream::BoxStream};
        let mut cursors: BTreeMap<usize, String> = since.and_then(|s| serde_json::from_str(s).ok()).unwrap_or_default();
        let streams: Vec<BoxStream<'static, (usize, Result<ObserveRecord, Error>)>> = self
            .hosts
            .iter()
            .enumerate()
            .map(|(index, host)| {
                let client = host.handle.client.clone();
                let since = cursors.get(&index).cloned();
                Box::pin(async_stream::stream! {
                    match client.observe(since.as_deref()).await {
                        Ok(mut records) => loop { match records.next().await {
                            Some(Ok(record)) => yield (index,Ok(record)),
                            None => break,
                            Some(Err(error)) => {yield (index,Err(error));break;}
                        }},
                        Err(error) => yield (index,Err(error)),
                    }
                }) as BoxStream<'static, _>
            })
            .collect();
        let providers: BTreeMap<String, Option<usize>> =
            self.names().into_iter().map(|name| (name.clone(), self.host_index(&name).ok())).collect();
        let mut stopping = self.stopping.subscribe();
        let mut exposures = self.exposures.subscribe();
        Box::pin(async_stream::stream! {
            let mut streams=futures::stream::select_all(streams);
            loop {
                enum Next<T> { Host(T), Exposure(crate::exposures::Notice), Skip, End }
                let next=tokio::select! {
                    value=streams.next()=>value.map_or(Next::End, Next::Host),
                    notice=exposures.recv()=>match notice {
                        Ok(notice)=>Next::Exposure(notice),
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_))=>Next::Skip,
                        Err(tokio::sync::broadcast::error::RecvError::Closed)=>Next::End,
                    },
                    _=stopping.wait_for(|s|*s)=>Next::End,
                };
                let next=match next {
                    Next::Host(value)=>Some(value),
                    // Exposure events are live: they take the cursor as it stands.
                    Next::Exposure(notice)=>{
                        let cursor=serde_json::to_string(&cursors).expect("cursor map serializes");
                        yield Ok(ObserveRecord::Event{event:Event{
                            cursor,id:notice.id,provider:notice.provider,label:Some(notice.label),
                            timestamp:chrono::Utc::now().into(),timestamp_source:TimestampSource::Adaptor,event:notice.kind,vendor:None,observed:None,
                        }});
                        continue;
                    }
                    Next::Skip=>continue,
                    Next::End=>None,
                };
                let Some((index,record))=next else {break};
                let mut record=match record {Ok(record)=>record,Err(error)=>{yield Err(error);break;}};
                let cursor=match &record {ObserveRecord::Event{event}=>&event.cursor,ObserveRecord::Snapshot{cursor,..}=>cursor};
                cursors.insert(index,cursor.clone());
                let cursor=serde_json::to_string(&cursors).expect("cursor map serializes");
                match &mut record {
                    ObserveRecord::Event{event}=>event.cursor=cursor,
                    ObserveRecord::Snapshot{cursor:target,unavailable_providers,..}=>{
                        *target=cursor;
                        // A snapshot is complete only for its source host.
                        // Explicit omissions preserve other hosts' billing state.
                        for (provider,host) in &providers {
                            if *host!=Some(index) {unavailable_providers.insert(provider.clone(),ProtocolError::unavailable("provider omitted from this host snapshot",None));}
                        }
                    }
                }
                yield Ok(record);
            }
        })
    }
}

/// A vessel's platform: `asked` when the caller knows it, else the one the
/// provider reports for the environment, else the provider's only declared
/// platform. A vendor that states no platform per environment runs the one
/// its module declares.
fn vessel_platform(asked: Option<&Platform>, environment: &Environment, declared: &[Platform]) -> Option<Platform> {
    let only = match declared {
        [only] => Some(only),
        _ => None,
    };
    asked.or(environment.platform.as_ref()).or(only).cloned()
}

/// The host's agent build for a prepared platform. A missing build refuses the
/// launch, naming the file or variable that would supply it.
// No unknown operation or platform is advertised as supported. BootstrapRoute
// has no unknown variant; Upload is inert while readiness is unavailable.
fn conservative_capabilities() -> Capabilities {
    Capabilities {
        material_modes: vec![],
        checkout_strategies: vec![],
        workspace_root: String::new(),
        suspend_resume: false,
        suspend_preserves_memory: None,
        export: false,
        egress: EgressCapability { routes: vec![], model: EgressModel { shapes: vec![], ..EgressModel::unfiltered() } },
        fallback_runner: false,
        bootstrap: BootstrapRoute::Upload,
        agent: false,
        platforms: vec![],
        image_routes: vec![],
        usage: false,
        quota: false,
        host_filesystem: false,
        host_processes: false,
        exclusive_label: false,
        agent_tcp_port: None,
        reach_ways: vec![],
        semantics: Default::default(),
        carries: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // An environment with no stated platform runs its provider's only declared one.
    #[test]
    fn vessel_platform_falls_back_to_the_only_declared_platform() {
        let (amd, arm) = (Platform::new("linux", "amd64"), Platform::new("linux", "arm64"));
        let environment = Environment {
            id: "e".into(),
            label: None,
            provider: "p".into(),
            state: Observation::Running,
            granted_size: None,
            egress: Enforcement::Advisory,
            platform: None,
            egress_measured: false,
            egress_policy: None,
            timestamp: None,
            vendor: None,
        };
        assert_eq!(vessel_platform(None, &environment, std::slice::from_ref(&amd)), Some(amd.clone()));
        assert_eq!(vessel_platform(None, &environment, &[amd.clone(), arm.clone()]), None);
        assert_eq!(vessel_platform(Some(&arm), &environment, std::slice::from_ref(&amd)), Some(arm.clone()));
        let reported = Environment { platform: Some(arm.clone()), ..environment };
        assert_eq!(vessel_platform(None, &reported, std::slice::from_ref(&amd)), Some(arm));
    }
}

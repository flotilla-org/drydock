//! Long-lived provider routing shared by drydockd and an embedding daemon.
use crate::{
    HostConnection, HostHandle, HostSpec, Supervisor,
    api::{ApiError, ApiJson, ApiPath, Exposed},
    client::{Client, Error, StatusCache},
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

pub use crate::api::ProviderApi;
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
    /// One lock per label, so two first provisions of a label share one key
    /// and provisions of other labels never wait on it.
    keying: std::sync::Mutex<BTreeMap<String, std::sync::Weak<Mutex<()>>>>,
    stopping: tokio::sync::watch::Sender<bool>,
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
}
impl Seams {
    pub fn new(resolver: Arc<dyn ImageResolver>) -> Self {
        Self {
            resolver,
            dialer: Arc::new(crate::agent::OpenSsh),
            builds: Arc::new(InstalledBuilds),
            guest: Default::default(),
            timing: Default::default(),
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
        let path = crate::local::agent_build(platform)?;
        tokio::fs::read(&path).await.map_err(|error| format!("{}: {error}", path.display()))
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
        let Seams { resolver, dialer, builds, guest, timing } = seams;
        crate::local::private_dir(run)?;
        let supervisor = Supervisor::new(run.join("hosts"), Arc::new(BuiltinCredentials::default()));
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
        let mut hosts = Vec::new();
        let mut placements = BTreeMap::new();
        let mut modules = BTreeMap::new();
        for (i, (option, _)) in discovered.into_iter().enumerate() {
            let mut providers = BTreeMap::new();
            let mut credentials = BTreeMap::new();
            for name in &assignments[i] {
                let p = &config.providers[name];
                providers.insert(name.clone(), p.configuration());
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
        let inner = Arc::new_cyclic(|weak| Inner {
            config,
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
            stopping: tokio::sync::watch::channel(false).0,
        });
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
        let placement = self.placements.get(provider).ok_or_else(|| {
            if let Some(readiness) = self.unavailable.get(provider) {
                Error::NotReady(readiness.clone())
            } else {
                Error::Protocol(ProtocolError::NotFound { reason: "unknown provider".into() })
            }
        })?;
        Ok(&self.hosts[placement.host])
    }
    /// Host readiness gates here. Each provider's own readiness, including a
    /// stored credential rejection, is the host Runtime's admission policy.
    fn ready_host(&self, provider: &str) -> Result<&ManagedHost, Error> {
        let host = self.host(provider)?;
        match host.handle.status.borrow().readiness.clone() {
            Readiness::Ready => Ok(host),
            readiness => Err(Error::NotReady(readiness)),
        }
    }
    fn runtime(&self, provider: &str) -> Result<crate::runtime::Runtime, Error> {
        Ok(self.ready_host(provider)?.handle.client.credentialed(self.credential.clone()))
    }
    /// Mutations discard cached status reads, whatever their outcome.
    async fn invalidating<T>(&self, provider: &str, result: Result<T, Error>) -> Result<T, Error> {
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
    /// Every configured provider, including those no host can serve, with the reason.
    pub fn providers(&self) -> Vec<ProviderDeclaration> {
        let statuses: Vec<_> = self.hosts.iter().map(|h| h.handle.status.borrow().clone()).collect();
        self.config
            .providers
            .iter()
            .map(|(name, configured)| {
                let status = self.placements.get(name).map(|p| &statuses[p.host]);
                let mut declaration = status
                    .and_then(|s| s.providers.iter().find(|p| &p.provider == name && p.module == configured.module))
                    .cloned()
                    .unwrap_or_else(|| ProviderDeclaration {
                        provider: name.clone(),
                        module: configured.module.clone(),
                        capabilities: conservative_capabilities(),
                        rate_limits: vec![],
                        readiness: Readiness::Unknown { reason: "provider absent from its host".into() },
                        ports: Ports::default(),
                        observation: ObservationMode::Poll { interval_ms: 0 },
                    });
                if let Some(readiness) = self.unavailable.get(name) {
                    declaration.readiness = readiness.clone();
                } else if let Some(status) = status
                    && !matches!(status.readiness, Readiness::Ready)
                {
                    declaration.readiness = status.readiness.clone();
                }
                declaration
            })
            .collect()
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
            launch::prepare_request(&self.config.providers[provider], &self.placements[provider].minimum, options, self.resolver.as_ref())
                .await?;
        let prepared = host.handle.client.credentialed(self.credential.clone()).prepare(provider, &request).await?;
        Ok((prepared, request.size))
    }
    pub async fn launch(&self, provider: &str, options: &LaunchOptions) -> Result<Environment, Error> {
        let (prepared, size) = self.prepare(provider, options).await?;
        let platform = prepared.platform.clone();
        let label = uuid::Uuid::new_v4().to_string();
        let dir = self.key_directory(&label);
        let (_, public) = launch::keypair(&dir).await?;
        let request = ProvisionRequest {
            label,
            prepared,
            size,
            egress: options.egress.or(self.config.providers[provider].egress).unwrap_or(Egress::Open).request(),
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
        let environment = self.invalidating(provider, client.provision(provider, &request).await).await?.into_inner();
        if let Some(build) = agent_build {
            self.agent_ready(provider, &environment, &platform, &build).await?;
        }
        Ok(environment)
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
        let link = self
            .config
            .providers
            .get(provider)
            .ok_or_else(|| Error::Protocol(ProtocolError::NotFound { reason: "unknown provider".into() }))?
            .agent_link;
        let reach = crate::agent::AgentReach::new(link).with_dialer(self.dialer.clone()).with_timeout(timeout);
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
    async fn agent_build(&self, platform: &Platform) -> Result<Vec<u8>, Error> {
        self.builds
            .build(platform)
            .await
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
        let directory = self.key_directory(&request.label);
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
            let existing = self.runtime(provider)?.list(provider).await?;
            if existing.iter().any(|environment| environment.label.as_deref() == Some(request.label.as_str())) {
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
        // The agent connection reads the prepared platform from this record:
        // write it whole or not at all.
        let staged = directory.join("request.json.new");
        tokio::fs::write(&staged, serde_json::to_vec(&request).expect("provision request serializes"))
            .await
            .map_err(|e| Error::Transport(format!("record provision request: {e}")))?;
        tokio::fs::rename(&staged, directory.join("request.json"))
            .await
            .map_err(|e| Error::Transport(format!("record provision request: {e}")))?;
        Ok(Some(request))
    }

    /// The directory holding a label's key: a launch's own UUID label names it
    /// directly; any other label, chosen by a client, by its digest, so a label
    /// never selects a filesystem path.
    fn key_directory(&self, label: &str) -> PathBuf {
        match uuid::Uuid::parse_str(label) {
            Ok(uuid) if uuid.hyphenated().to_string() == label => self.keys.join(label),
            _ => self.keys.join(format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(label.as_bytes()))),
        }
    }

    pub fn key_for(&self, environment: &Environment) -> Result<PathBuf, Error> {
        let label = environment
            .label
            .as_deref()
            .ok_or_else(|| Error::Protocol(ProtocolError::Refused { reason: "environment has no drydock-managed SSH key".into() }))?;
        Ok(self.key_directory(label).join("id_ed25519"))
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
        declaration.ok_or_else(|| Error::Protocol(ProtocolError::NotFound { reason: "unknown provider".into() }))
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
        self.runtime(p)?.prepare(p, request).await
    }
    async fn provision(&self, p: &str, request: &ProvisionRequest) -> Result<crate::api::Provisioned<Environment>, Error> {
        let keyed = self.keyed(p, request).await?;
        self.invalidating(p, self.runtime(p)?.provision(p, keyed.as_ref().unwrap_or(request)).await).await
    }
    async fn list(&self, p: &str) -> Result<Vec<Environment>, Error> {
        if self.credential.is_some() {
            return self.runtime(p)?.list(p).await;
        }
        self.cache(p).await?.list(p).await
    }
    async fn inspect(&self, p: &str, id: &str) -> Result<Environment, Error> {
        if self.credential.is_some() {
            return self.runtime(p)?.inspect(p, id).await;
        }
        self.cache(p).await?.inspect(p, id).await
    }
    async fn destroy(&self, p: &str, id: &str) -> Result<(), Error> {
        self.invalidating(p, self.runtime(p)?.destroy(p, id).await).await?;
        self.exposures.forget(p, id).await;
        Ok(())
    }
    async fn reach(&self, p: &str, id: &str) -> Result<Reach, Error> {
        self.runtime(p)?.reach(p, id).await
    }
    async fn suspend(&self, p: &str, id: &str) -> Result<ResumeToken, Error> {
        let result = self.invalidating(p, self.runtime(p)?.suspend(p, id).await).await;
        self.exposures.poke(p, id);
        result
    }
    async fn resume(&self, p: &str, id: &str, token: &ResumeToken) -> Result<(), Error> {
        let result = self.invalidating(p, self.runtime(p)?.resume(p, id, token).await).await;
        self.exposures.poke(p, id);
        result
    }
    async fn export(&self, p: &str, id: &str) -> Result<Export, Error> {
        self.invalidating(p, self.runtime(p)?.export(p, id).await).await
    }
    async fn quota(&self, p: &str) -> Result<Quota, Error> {
        self.runtime(p)?.quota(p).await
    }
    async fn usage(&self, p: &str, period: &Period) -> Result<Usage, Error> {
        self.runtime(p)?.usage(p, period).await
    }
    async fn relay(&self, p: &str, id: &str) -> Result<rigging_stream::ByteStream, Error> {
        self.runtime(p)?.relay(p, id).await
    }
    async fn exec(&self, p: &str, id: &str, command: &ExecRequest) -> Result<rigging_stream::ByteStream, Error> {
        self.runtime(p)?.exec(p, id, command).await
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
) -> Result<Json<Environment>, ApiError> {
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
            self.config.providers.keys().map(|name| (name.clone(), self.placements.get(name).map(|p| p.host))).collect();
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
                            timestamp:chrono::Utc::now().into(),timestamp_source:TimestampSource::Adaptor,event:notice.kind,
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
        egress: EgressCapability { routes: vec![], enforcement: Enforcement::Advisory },
        fallback_runner: false,
        bootstrap: BootstrapRoute::Upload,
        agent: false,
        platforms: vec![],
        image_routes: vec![],
        usage: false,
        quota: false,
    }
}

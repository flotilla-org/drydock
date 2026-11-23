//! Instances with a parent: configured ones, on the parent's machine, and
//! carried ones, inside a parent environment, reached through its vessel's agent.
use super::*;
use crate::{api::Provisioned, launch::refused};
use drydock_agent::{Endpoint, Exec, InwardForward};
use drydock_protocol::service::{ServiceInfo, ServiceState};

/// How long the agent link and each wait on it may take.
const CONNECT: Duration = Duration::from_secs(20);

/// An instance's endpoint, and the socket whose connections the parent carries there.
pub(super) struct Carrier {
    pub(super) parent: String,
    pub(super) endpoint: Carried,
    pub(super) socket: PathBuf,
    pub(super) _relay: Relay,
    pub(super) carriage: Option<Arc<Carriage>>,
}
impl Carrier {
    pub(super) fn local(&self) -> Local {
        Local::Unix(self.socket.to_string_lossy().into_owned())
    }
    pub(super) fn link(&self) -> Option<&Link> {
        self.carriage.as_ref().map(|c| &c.link)
    }
}
pub(super) struct Carriage {
    pub(super) body: Carry,
    pub(super) host: usize,
    link: Link,
}
/// The parent vessel's agent, holding a forward to the instance's endpoint,
/// whose id also names the recipe's service.
pub(super) struct Link {
    provider: String,
    environment: String,
    forward: InwardForward,
    agent: Mutex<Option<Arc<drydock_agent::Client>>>,
}
impl Link {
    fn new(child: &str, provider: &str, environment: &str, endpoint: &Carried) -> Self {
        let Carried::Unix(path) = endpoint;
        let id = format!("drydock-carried-{}", digest(child));
        Self {
            provider: provider.into(),
            environment: environment.into(),
            forward: InwardForward { id, endpoint: Endpoint::Unix(path.into()) },
            agent: Mutex::default(),
        }
    }
    /// Connections wait for one link to be made rather than each making its own.
    async fn agent(&self, daemon: &Daemon) -> Result<Arc<drydock_agent::Client>, Error> {
        let mut held = self.agent.lock().await;
        if let Some(agent) = &*held {
            return Ok(agent.clone());
        }
        let agent = daemon.connect_agent(&self.provider, &self.environment, CONNECT).await?;
        agent.put_inward_forward(self.forward.clone()).await.map_err(agent_error)?;
        let agent = Arc::new(agent);
        *held = Some(agent.clone());
        Ok(agent)
    }
    async fn forget(&self) {
        *self.agent.lock().await = None;
    }
    async fn open(&self, daemon: &Daemon) -> Result<rigging_stream::ByteStream, Error> {
        let mut agent = self.agent(daemon).await?;
        let error = match agent.open_inward(&self.forward.id).await {
            Ok(stream) => return Ok(Box::new(stream)),
            Err(error) => error,
        };
        match drydock_agent::AgentError::of(&error).map(|e| e.status) {
            // A restarted agent has lost the forward.
            Some(404) => agent.put_inward_forward(self.forward.clone()).await.map_err(agent_error)?,
            // The endpoint itself refused.
            Some(_) => return Err(agent_error(error)),
            None => {
                self.forget().await;
                agent = self.agent(daemon).await?;
            }
        }
        Ok(Box::new(agent.open_inward(&self.forward.id).await.map_err(agent_error)?))
    }
}
/// 128 bits of the name's SHA-256, short enough for a service name and a socket path.
fn digest(name: &str) -> String {
    format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(name.as_bytes()))[..32].to_owned()
}
/// A child's socket, named by the child. One left here is stale: a name's
/// relay is dropped before the name can be carried again.
pub(super) fn child_socket(run: &FsPath, name: &str) -> Result<(PathBuf, tokio::net::UnixListener), String> {
    let directory = run.join("parents");
    crate::local::private_dir(&directory)?;
    let socket = directory.join(format!("{}.sock", digest(name)));
    // sun_path holds 108 bytes with the terminator.
    if socket.as_os_str().len() > 107 {
        return Err(format!("provider {name}: drydock's runtime directory is too long for the socket {}", socket.display()));
    }
    if let Err(error) = std::fs::remove_file(&socket)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(format!("provider {name}: socket {}: {error}", socket.display()));
    }
    let listener = tokio::net::UnixListener::bind(&socket).map_err(|e| format!("provider {name}: socket {}: {e}", socket.display()))?;
    std::fs::set_permissions(&socket, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .map_err(|e| format!("provider {name}: socket: {e}"))?;
    Ok((socket, listener))
}
fn left_service(error: Error, link: &Link) -> ProvisionError {
    let left = LeftService { provider: link.provider.clone(), id: link.environment.clone(), name: link.forward.id.clone() };
    ProvisionError { error, left: Left::Service(Box::new(left)) }
}
pub(super) fn agent_error(error: std::io::Error) -> Error {
    match drydock_agent::AgentError::of(&error).map(|e| e.status) {
        Some(404) => Error::Protocol(ProtocolError::not_found(error.to_string())),
        Some(400..=499) => refused(error.to_string()),
        _ => Error::Protocol(ProtocolError::unavailable(format!("vessel agent: {error}"), None)),
    }
}

impl Daemon {
    /// Carrying, removing and teardown under one name take turns.
    fn turns(&self, name: &str) -> Arc<tokio::sync::RwLock<()>> {
        let mut turns = self.turns.lock().unwrap();
        if let Some(lock) = turns.get(name).and_then(std::sync::Weak::upgrade) {
            return lock;
        }
        turns.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::default();
        turns.insert(name.to_owned(), Arc::downgrade(&lock));
        lock
    }
    /// Provisions under a carried name go together, never while it is carried or removed.
    pub(super) async fn provisioning(&self, name: &str) -> Option<tokio::sync::OwnedRwLockReadGuard<()>> {
        self.carrier(name)?.carriage.as_ref()?;
        Some(self.turns(name).read_owned().await)
    }
    pub(super) async fn hop(&self, child: &str) -> Result<rigging_stream::ByteStream, Error> {
        let carrier = self.carrier(child).ok_or_else(|| Error::Protocol(ProtocolError::unknown_provider()))?;
        match carrier.link() {
            None => self.runtime(&carrier.parent)?.stream(&carrier.parent, &carrier.endpoint).await,
            Some(link) => link.open(self).await,
        }
    }

    pub(super) async fn carry(&self, name: &str, body: &Carry) -> Result<Provisioned<ProviderDeclaration>, ProvisionError> {
        crate::exposures::check_named("provider", name)?;
        self.not_configured(name)?;
        let Some(environment) = body.parent.environment.clone() else {
            return Err(refused("a carried instance's parent names an environment").into());
        };
        let _turn = self.turns(name).write_owned().await;
        if let Some(carriage) = self.carrier(name).and_then(|c| c.carriage.clone()) {
            if carriage.body != *body {
                return Err(refused(format!("provider {name} is carried from a different body; remove it first")).into());
            }
            return Ok(Provisioned::Existing(self.declared(name, &self.statuses())));
        }
        let (host, module) =
            self.modules.get(&body.module).cloned().ok_or_else(|| refused(format!("no host loads module {}", body.module)))?;
        if !module.takes_endpoint {
            return Err(refused(format!("module {} cannot be given its endpoint, so it cannot be carried", body.module)).into());
        }
        let (endpoint, recipe) = match (&body.parent.endpoint, module.recipe) {
            (Some(endpoint), _) => (endpoint.clone(), None),
            (None, Some(recipe)) => (recipe.endpoint.clone(), Some(recipe)),
            (None, None) => {
                return Err(refused(format!("module {} has no recipe; name the endpoint its engine answers on", body.module)).into());
            }
        };
        let parent = &body.parent.instance;
        if !self.names().contains(parent) {
            return Err(refused(format!("parent {parent} is not a provider")).into());
        }
        if !ProviderApi::provider(self, parent).await?.capabilities.agent {
            return Err(refused(format!("provider {parent} declares no vessel agent, which carrying needs")).into());
        }
        self.running(parent, &environment).await?;
        let link = Link::new(name, parent, &environment, &endpoint);
        let started = match &recipe {
            Some(recipe) => self.ensure(&link, recipe).await?,
            None => false,
        };
        let left = |error: Error, link: &Link| if started { left_service(error, link) } else { error.into() };
        let (socket, listener) = child_socket(&self.run, name).map_err(|e| left(Error::Transport(e), &link))?;
        let task = tokio::spawn(relay(
            self.this.clone(),
            self.starting.subscribe(),
            name.to_owned(),
            (parent.clone(), endpoint.clone()),
            listener,
            self.stopping.subscribe(),
        ));
        let carriage = Arc::new(Carriage { body: body.clone(), host, link });
        let relay = Relay { task, socket: socket.clone() };
        let carrier = Carrier { parent: parent.clone(), endpoint, socket: socket.clone(), _relay: relay, carriage: Some(carriage.clone()) };
        // Before the host has it: configuring may already dial the endpoint.
        self.carried.write().unwrap().insert(name.to_owned(), Arc::new(carrier));
        let configuration = ProviderConfiguration {
            module: body.module.clone(),
            settings: body.settings.clone(),
            ownership: Ownership::OwnedAccount,
            endpoint: Some(Local::Unix(socket.to_string_lossy().into_owned())),
            ..Default::default()
        };
        let handle = &self.hosts[host].handle;
        if let Err(error) = handle.carry(name, configuration).await {
            self.carried.write().unwrap().remove(name);
            return Err(left(error, &carriage.link));
        }
        let mut status = handle.status.clone();
        if tokio::time::timeout(CONNECT, status.wait_for(|s| s.providers.iter().any(|p| p.provider == name))).await.is_err() {
            tracing::warn!(provider = name, "the host has not yet listed the carried instance; it reads as absent until it does");
        }
        Ok(Provisioned::Created(self.declared(name, &self.statuses())))
    }

    /// The parent environment running: a starting one is waited for, as a provision would.
    async fn running(&self, parent: &str, environment: &str) -> Result<(), Error> {
        let wait = self.config.providers.get(parent).map_or(SemanticOptions::default().wait_seconds, |p| p.semantics.wait_seconds);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
        loop {
            let gone = || refused(format!("parent environment {environment} of {parent} is gone"));
            let row = match self.runtime(parent)?.inspect(parent, environment).await {
                Err(Error::Protocol(ProtocolError::NotFound { .. })) => return Err(gone()),
                row => row?,
            };
            match row.state {
                Observation::Running => return Ok(()),
                Observation::Gone { .. } => return Err(gone()),
                Observation::Transitioning {
                    phase: TransitionPhase::Preparing | TransitionPhase::Starting | TransitionPhase::Reconfiguring,
                } if tokio::time::Instant::now() < deadline => tokio::time::sleep(Duration::from_millis(250)).await,
                other => {
                    let state = crate::exposures::describe(&other);
                    return Err(refused(format!("parent environment {environment} of {parent} is {state}; drydockd does not resume it")));
                }
            }
        }
    }

    /// An engine already answering is used as it is; otherwise the recipe's
    /// service starts, and its endpoint is waited for. Whether it started.
    async fn ensure(&self, link: &Link, recipe: &Recipe) -> Result<bool, ProvisionError> {
        let agent = link.agent(self).await?;
        if agent.open_inward(&link.forward.id).await.is_ok() {
            tracing::info!(parent = %link.provider, environment = %link.environment, "an engine already answers; carrying onto it");
            return Ok(false);
        }
        let script = r#"for p; do command -v "$p" >/dev/null 2>&1 || printf '%s ' "$p"; done"#;
        let args = ["-c", script, "sh"].into_iter().map(str::to_owned).chain(recipe.requires.iter().cloned());
        let (missing, _, _) = agent.run(Exec::new("sh", args), 4096).await.map_err(agent_error)?;
        let missing = String::from_utf8_lossy(&missing);
        if !missing.trim().is_empty() {
            return Err(refused(format!("the parent's image has no {} on its PATH", missing.trim())).into());
        }
        let service = &link.forward.id;
        // An agent's refusal started nothing; a lost answer may have started it.
        let lost = |e: std::io::Error| match drydock_agent::AgentError::of(&e) {
            Some(_) => agent_error(e).into(),
            None => left_service(agent_error(e), link),
        };
        agent.put_service(service, &recipe.service).await.map_err(lost)?;
        let waited = tokio::time::timeout(CONNECT, async {
            loop {
                let answered = agent.open_inward(&link.forward.id).await.is_ok();
                let info = agent.service(service).await.map_err(|e| left_service(agent_error(e), link))?;
                if let ServiceInfo { state: ServiceState::Exited { status }, log, .. } = info {
                    let log = log.map(|log| format!("; its log is {}", log.display())).unwrap_or_default();
                    return Err(left_service(refused(format!("the recipe's {} exited ({status:?}){log}", recipe.service.program)), link));
                }
                if answered {
                    return Ok(true);
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
        let reason = format!("the recipe's endpoint did not answer within {} s", CONNECT.as_secs());
        waited.await.unwrap_or_else(|_| Err(left_service(Error::Protocol(ProtocolError::unavailable(reason, None)), link)))
    }

    fn not_configured(&self, name: &str) -> Result<(), Error> {
        let reason = format!("provider {name} is configured; a configured instance changes only with the configuration file");
        if self.config.providers.contains_key(name) { Err(refused(reason)) } else { Ok(()) }
    }
    pub(super) async fn uncarry(&self, name: &str) -> Result<(), Error> {
        self.not_configured(name)?;
        let _turn = self.turns(name).write_owned().await;
        let Some(carriage) = self.carrier(name).and_then(|c| c.carriage.clone()) else { return Ok(()) };
        let link = &carriage.link;
        let listed = self.runtime(name)?.list(name).await;
        // The parent environment may have gone outside drydockd.
        if listed.is_err() && matches!(self.parent_state(link).await, Some(Observation::Gone { .. })) {
            drop(_turn);
            self.parent_gone(&link.provider, &link.environment).await;
            return Ok(());
        }
        let held: Vec<String> = listed?.into_iter().filter(Environment::live).map(|e| e.id).collect();
        if !held.is_empty() {
            return Err(refused(format!("{name} holds environments {}; destroy them first", held.join(", "))));
        }
        if carriage.body.parent.endpoint.is_none() {
            let service = &link.forward.id;
            match async { link.agent(self).await?.remove_service(service, None).await.map_err(agent_error) }.await {
                // None when the carry found its engine already answering.
                Ok(_) | Err(Error::Protocol(ProtocolError::NotFound { .. })) => {}
                // A service ends with its vessel; in a running one it would be left without an owner.
                Err(error) if matches!(self.parent_state(link).await, Some(state) if state != Observation::Running) => {
                    tracing::warn!(provider = name, %service, %error, "the recipe's service ends with its vessel")
                }
                Err(error) => return Err(error),
            }
        }
        self.forget_carried(name, None).await;
        Ok(())
    }

    /// The parent environment's state, gone when it is not found; None when it cannot be read.
    async fn parent_state(&self, link: &Link) -> Option<Observation> {
        match ProviderApi::inspect(self, &link.provider, &link.environment).await {
            Ok(row) if row.live() => Some(row.state),
            Ok(_) | Err(Error::Protocol(ProtocolError::NotFound { .. })) => Some(Observation::Gone { cause: None }),
            Err(_) => None,
        }
    }
    async fn forget_carried(&self, name: &str, cause: Option<GoneCause>) -> Vec<Environment> {
        let Some(carrier) = self.carried.write().unwrap().remove(name) else { return vec![] };
        let Some(carriage) = &carrier.carriage else { return vec![] };
        self.hosts[carriage.host].handle.uncarry(name, cause).await
    }
    fn children(&self, provider: &str, environment: &str) -> Vec<String> {
        let carried = self.carried.read().unwrap();
        let into = |c: &Carrier| c.link().is_some_and(|l| l.provider == provider && l.environment == environment);
        carried.iter().filter(|(_, c)| into(c)).map(|(name, _)| name.clone()).collect()
    }

    /// Every instance carried into the environment, at any depth, goes, its environments recorded gone.
    pub(super) async fn parent_gone(&self, provider: &str, id: &str) {
        let mut gone = vec![(provider.to_owned(), id.to_owned())];
        while let Some((parent, environment)) = gone.pop() {
            // Again until none is left: a carry may finish into it meanwhile.
            while let Some(child) = self.children(&parent, &environment).pop() {
                let _turn = self.turns(&child).write_owned().await;
                let cause = GoneCause::ParentGone { provider: parent.clone(), environment: environment.clone() };
                for row in self.forget_carried(&child, Some(cause)).await {
                    self.exposures.forget(&child, &row.id).await;
                    gone.push((child.clone(), row.id));
                }
            }
        }
    }

    /// The parent environment resumed: each recipe is ensured again.
    pub(super) async fn parent_resumed(&self, provider: &str, id: &str) {
        for child in self.children(provider, id) {
            let _turn = self.turns(&child).write_owned().await;
            let Some(carriage) = self.carrier(&child).and_then(|c| c.carriage.clone()) else { continue };
            let module = self.modules.get(&carriage.body.module).filter(|_| carriage.body.parent.endpoint.is_none());
            let Some(recipe) = module.and_then(|(_, m)| m.recipe.as_ref()) else { continue };
            // A connection may make the link again meanwhile; its forward is the same.
            carriage.link.forget().await;
            if let Err(failure) = self.ensure(&carriage.link, recipe).await {
                tracing::warn!(provider, environment = id, child, error = %failure.error, "the recipe did not start again after the parent resumed");
            }
        }
    }

    /// The module's own figures, and the parent environment's size as the limits.
    pub(super) async fn carried_quota(&self, name: &str, link: &Link) -> Result<Quota, Error> {
        let ports = self.host(name)?.handle.status.borrow().providers.iter().find(|d| d.provider == name).map(|d| d.ports);
        let mut quota = if ports.is_some_and(|p| p.quota) { self.runtime(name)?.quota(name).await? } else { Quota::default() };
        if let Some(size) = ProviderApi::inspect(self, &link.provider, &link.environment).await?.granted_size {
            let row = |resource, unit: &str, limit: Option<f64>| ResourceQuota {
                key: QuotaKey { region: None, class: None, resource },
                unit: unit.into(),
                in_use: None,
                limit,
            };
            quota.resources.retain(|r| !matches!(r.key.resource, ResourceKind::Cpu | ResourceKind::Memory | ResourceKind::Disk));
            quota.resources.extend([
                row(ResourceKind::Cpu, "{vCPU}", Some(size.cpus)),
                row(ResourceKind::Memory, "By", Some(size.memory_bytes as f64)),
                row(ResourceKind::Disk, "By", size.disk_bytes.map(|disk| disk as f64)),
            ]);
        }
        Ok(quota)
    }

    pub(super) async fn vessel_agent(&self, provider: &str, id: &str) -> Result<drydock_agent::Client, Error> {
        if !ProviderApi::provider(self, provider).await?.capabilities.agent {
            return Err(refused(format!("provider {provider} declares no vessel agent, which services need")));
        }
        environment(self.connect_agent(provider, id, CONNECT).await)
    }
}

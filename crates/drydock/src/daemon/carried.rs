//! Instances with a parent: configured ones, whose endpoint is on the parent
//! instance's machine, and carried ones, put while drydockd runs, whose
//! endpoint is inside an environment of the parent. Each connection to the
//! instance's socket is one hop, through the parent instance or through the
//! parent environment's vessel agent; a deeper nesting is the hop repeated.
use super::*;
use crate::api::Provisioned;
use drydock_agent::{Endpoint, Exec, InwardForward};
use drydock_protocol::service::{Service, ServiceInfo, ServiceState};

/// How long the agent link and each wait on it may take.
const CONNECT: Duration = Duration::from_secs(20);

/// An instance's endpoint, where its parent reaches it, and the socket
/// drydockd made for it, whose connections the parent carries there.
pub(super) struct Carrier {
    pub(super) parent: String,
    pub(super) endpoint: Carried,
    pub(super) socket: PathBuf,
    pub(super) _relay: Relay,
    /// The parent environment's agent, for a carried instance.
    pub(super) link: Option<Link>,
    pub(super) carriage: Option<Arc<Carriage>>,
}
impl Carrier {
    pub(super) fn local(&self) -> Local {
        Local::Unix(self.socket.to_string_lossy().into_owned())
    }
    fn environment(&self) -> Option<&str> {
        self.link.as_ref().map(|l| l.environment.as_str())
    }
}
/// What made a carried instance: the body it was put with, the host serving
/// its module, and the service its module's recipe started.
pub(super) struct Carriage {
    pub(super) body: Carry,
    pub(super) host: usize,
    service: Option<(String, Service)>,
}
/// The parent vessel's agent, holding a forward to the instance's endpoint.
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
    /// The agent, connected and holding the forward.
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
        let agent = self.agent(daemon).await?;
        if let Ok(stream) = agent.open_inward(&self.forward.id).await {
            return Ok(Box::new(stream));
        }
        // A restarted agent has lost the forward, and a lost link the agent.
        self.forget().await;
        let stream = self.agent(daemon).await?.open_inward(&self.forward.id).await.map_err(agent_error)?;
        Ok(Box::new(stream))
    }
}
fn digest(name: &str) -> String {
    format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(name.as_bytes()))[..16].to_owned()
}
/// A child's socket, named by the child so that it stays put across restarts
/// and reordered configurations.
pub(super) fn child_socket(run: &FsPath, name: &str) -> Result<(PathBuf, tokio::net::UnixListener), String> {
    let directory = run.join("parents");
    crate::local::private_dir(&directory)?;
    let socket = directory.join(format!("{}.sock", digest(name)));
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket).map_err(|e| format!("provider {name}: socket {}: {e}", socket.display()))?;
    std::fs::set_permissions(&socket, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .map_err(|e| format!("provider {name}: socket: {e}"))?;
    Ok((socket, listener))
}
fn refused(reason: impl Into<String>) -> Error {
    Error::Protocol(ProtocolError::Refused { reason: reason.into() })
}
/// An agent's refusal as the protocol states it.
pub(super) fn agent_error(error: std::io::Error) -> Error {
    match drydock_agent::AgentError::of(&error).map(|e| e.status) {
        Some(404) => Error::Protocol(ProtocolError::not_found(error.to_string())),
        Some(400..=499) => refused(error.to_string()),
        _ => Error::Protocol(ProtocolError::unavailable(format!("vessel agent: {error}"), None)),
    }
}

impl Daemon {
    /// Requests under one name take turns.
    async fn turn(&self, name: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut turns = self.turns.lock().unwrap();
            turns.retain(|_, lock| lock.strong_count() > 0);
            let lock = turns.get(name).and_then(std::sync::Weak::upgrade).unwrap_or_default();
            turns.insert(name.to_owned(), Arc::downgrade(&lock));
            lock
        };
        lock.lock_owned().await
    }
    /// A stream to a child's endpoint, through its parent.
    pub(super) async fn hop(&self, child: &str) -> Result<rigging_stream::ByteStream, Error> {
        let carrier = self.carrier(child).ok_or_else(|| Error::Protocol(ProtocolError::unknown_provider()))?;
        match &carrier.link {
            None => self.runtime(&carrier.parent)?.stream(&carrier.parent, &carrier.endpoint).await,
            Some(link) => link.open(self).await,
        }
    }

    pub(super) async fn carry(&self, name: &str, body: &Carry) -> Result<Provisioned<ProviderDeclaration>, ProvisionError> {
        crate::exposures::check_named("provider", name)?;
        if self.config.providers.contains_key(name) {
            return Err(
                refused(format!("provider {name} is configured; a configured instance changes only with the configuration file")).into()
            );
        }
        let Some(environment) = body.parent.environment.clone() else {
            return Err(refused("a carried instance's parent names an environment").into());
        };
        let _turn = self.turn(name).await;
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
        let recipe = match (&body.parent.endpoint, &module.recipe) {
            (Some(_), _) => None,
            (None, Some(recipe)) => Some(recipe.clone()),
            (None, None) => {
                return Err(refused(format!("module {} has no recipe; name the endpoint its engine answers on", body.module)).into());
            }
        };
        let endpoint = body.parent.endpoint.clone().or_else(|| recipe.as_ref().map(|r| r.endpoint.clone())).expect("one of the two");
        let parent = &body.parent.instance;
        if !self.names().contains(parent) {
            return Err(refused(format!("parent {parent} is not a provider")).into());
        }
        if !ProviderApi::provider(self, parent).await?.capabilities.agent {
            return Err(refused(format!("provider {parent} declares no vessel agent, which carrying needs")).into());
        }
        self.running(parent, &environment).await?;
        let link = Link::new(name, parent, &environment, &endpoint);
        let service = match recipe {
            Some(recipe) => Some(self.run_recipe(name, &link, recipe).await?),
            None => None,
        };
        let left = |error: Error| match &service {
            Some((service, _)) => ProvisionError {
                error,
                left: Left::Service(Box::new(LeftService { provider: parent.clone(), id: environment.clone(), name: service.clone() })),
            },
            None => error.into(),
        };
        let (socket, listener) = child_socket(&self.run, name).map_err(|e| left(Error::Transport(e)))?;
        let task = tokio::spawn(relay(
            self.this.clone(),
            self.starting.subscribe(),
            name.to_owned(),
            (parent.clone(), endpoint.clone()),
            listener,
            self.stopping.subscribe(),
        ));
        let carriage = Arc::new(Carriage { body: body.clone(), host, service: service.clone() });
        let carrier = Carrier {
            parent: parent.clone(),
            endpoint,
            socket: socket.clone(),
            _relay: Relay { task, socket: socket.clone() },
            link: Some(link),
            carriage: Some(carriage),
        };
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
            return Err(left(error));
        }
        // The host's next status lists it; until then it would read as absent.
        let mut status = handle.status.clone();
        let _ = tokio::time::timeout(CONNECT, status.wait_for(|s| s.providers.iter().any(|p| p.provider == name))).await;
        Ok(Provisioned::Created(self.declared(name, &self.statuses())))
    }

    /// The parent environment, running: one that is starting is waited for,
    /// as long as a provision would wait; any other state is refused at once.
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

    /// Run the module's recipe in the parent environment and wait for the
    /// endpoint to answer. Returns the service's name and body.
    async fn run_recipe(&self, name: &str, link: &Link, recipe: Recipe) -> Result<(String, Service), ProvisionError> {
        let agent = link.agent(self).await?;
        if !recipe.requires.is_empty() {
            let script = r#"for p; do command -v "$p" >/dev/null 2>&1 || printf '%s ' "$p"; done"#;
            let args = ["-c", script, "sh"].into_iter().map(str::to_owned).chain(recipe.requires.iter().cloned());
            let (missing, _, _) = agent.run(Exec::new("sh", args), 4096).await.map_err(agent_error)?;
            let missing = String::from_utf8_lossy(&missing);
            if !missing.trim().is_empty() {
                return Err(refused(format!("the parent's image has no {} on its PATH", missing.trim())).into());
            }
        }
        let service = format!("drydock-carried-{}", digest(name));
        agent.start_service(&service, &recipe.service).await.map_err(agent_error)?;
        let left = |error: Error| ProvisionError {
            error,
            left: Left::Service(Box::new(LeftService {
                provider: link.provider.clone(),
                id: link.environment.clone(),
                name: service.clone(),
            })),
        };
        let deadline = tokio::time::Instant::now() + CONNECT;
        loop {
            if agent.open_inward(&link.forward.id).await.is_ok() {
                return Ok((service, recipe.service));
            }
            if let ServiceInfo { state: ServiceState::Exited { status }, log, .. } =
                agent.service(&service).await.map_err(|e| left(agent_error(e)))?
            {
                let log = log.map(|log| format!("; its log is {}", log.display())).unwrap_or_default();
                return Err(left(refused(format!(
                    "the recipe's {} exited ({status:?}) before its endpoint answered{log}",
                    recipe.service.program
                ))));
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(left(Error::Protocol(ProtocolError::unavailable(
                    format!("the recipe's endpoint did not answer within {} s", CONNECT.as_secs()),
                    None,
                ))));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub(super) async fn uncarry(&self, name: &str) -> Result<(), Error> {
        if self.config.providers.contains_key(name) {
            return Err(refused(format!("provider {name} is configured; a configured instance changes only with the configuration file")));
        }
        let _turn = self.turn(name).await;
        let Some(carrier) = self.carrier(name).filter(|c| c.carriage.is_some()) else { return Ok(()) };
        let listed = self.runtime(name)?.list(name).await;
        // An engine that cannot be listed may have gone with its parent
        // environment outside drydockd; then the instance goes as it would have.
        if listed.is_err()
            && let Some(environment) = carrier.environment()
            && self.gone(&carrier.parent, environment).await
        {
            drop(_turn);
            self.parent_gone(&carrier.parent, environment).await;
            return Ok(());
        }
        let held: Vec<String> = listed?.into_iter().filter(Environment::live).map(|e| e.id).collect();
        if !held.is_empty() {
            return Err(refused(format!("{name} holds environments {}; destroy them first", held.join(", "))));
        }
        if let (Some(link), Some((service, _))) = (&carrier.link, &carrier.carriage.as_ref().and_then(|c| c.service.clone())) {
            let stopped = async { link.agent(self).await?.remove_service(service, None).await.map_err(agent_error) }.await;
            match stopped {
                Ok(_) | Err(Error::Protocol(ProtocolError::NotFound { .. })) => {}
                Err(error @ Error::Protocol(ProtocolError::Refused { .. })) => return Err(error),
                // A service of a vessel that is not reachable ends with it,
                // and no recipe runs for a forgotten instance.
                Err(error) => tracing::warn!(provider = name, %service, %error, "the recipe's service could not be stopped"),
            }
        }
        self.forget_carried(name, None).await;
        Ok(())
    }

    async fn gone(&self, provider: &str, id: &str) -> bool {
        match ProviderApi::inspect(self, provider, id).await {
            Ok(row) => !row.live(),
            Err(error) => matches!(error, Error::Protocol(ProtocolError::NotFound { missing: Some(Missing::Environment), .. })),
        }
    }
    /// Forget a carried instance, returning the environments it held.
    async fn forget_carried(&self, name: &str, cause: Option<GoneCause>) -> Vec<Environment> {
        let Some(carrier) = self.carried.write().unwrap().remove(name) else { return vec![] };
        let Some(carriage) = &carrier.carriage else { return vec![] };
        self.hosts[carriage.host].handle.uncarry(name, cause).await
    }

    /// The parent environment went: every instance carried into it goes, and
    /// every instance carried into theirs, each environment recorded gone.
    pub(super) async fn parent_gone(&self, provider: &str, id: &str) {
        let mut gone = vec![(provider.to_owned(), id.to_owned())];
        while let Some((parent, environment)) = gone.pop() {
            let children: Vec<String> = self
                .carried
                .read()
                .unwrap()
                .iter()
                .filter(|(_, c)| c.carriage.is_some() && c.parent == parent && c.environment() == Some(environment.as_str()))
                .map(|(name, _)| name.clone())
                .collect();
            for child in children {
                let _turn = self.turn(&child).await;
                let cause = GoneCause::ParentGone { provider: parent.clone(), environment: environment.clone() };
                for row in self.forget_carried(&child, Some(cause)).await {
                    self.exposures.forget(&child, &row.id).await;
                    gone.push((child.clone(), row.id));
                }
            }
        }
    }

    /// The parent environment resumed: each recipe runs again, which leaves a
    /// service still running alone.
    pub(super) async fn parent_resumed(&self, provider: &str, id: &str) {
        let children: Vec<String> = self
            .carried
            .read()
            .unwrap()
            .iter()
            .filter(|(_, c)| c.parent == provider && c.environment() == Some(id))
            .map(|(name, _)| name.clone())
            .collect();
        for child in children {
            // Under the name's turn, so a DELETE cannot forget it meanwhile.
            let _turn = self.turn(&child).await;
            let Some(carrier) = self.carrier(&child) else { continue };
            let (Some(link), Some((service, body))) = (&carrier.link, carrier.carriage.as_ref().and_then(|c| c.service.clone())) else {
                continue;
            };
            link.forget().await;
            let started = async { link.agent(self).await?.start_service(&service, &body).await.map_err(agent_error) }.await;
            if let Err(error) = started {
                tracing::warn!(provider, environment = id, %service, %error, "the recipe did not start again after the parent resumed");
            }
        }
    }

    /// A carried instance's quota: the module's own figures, and the parent
    /// environment's size as the limit of each resource it states.
    pub(super) async fn carried_quota(&self, name: &str, carrier: &Carrier) -> Result<Quota, Error> {
        let ports = self.host(name)?.handle.status.borrow().providers.iter().find(|d| d.provider == name).map(|d| d.ports);
        let mut quota = match ports {
            Some(ports) if ports.quota => self.runtime(name)?.quota(name).await?,
            _ => Quota::default(),
        };
        let environment = carrier.environment().expect("a carried instance has a parent environment");
        if let Some(size) = ProviderApi::inspect(self, &carrier.parent, environment).await?.granted_size {
            let row = |resource, unit: &str, limit: f64| ResourceQuota {
                key: QuotaKey { region: None, class: None, resource },
                unit: unit.into(),
                in_use: None,
                limit: Some(limit),
            };
            quota.resources.retain(|r| !matches!(r.key.resource, ResourceKind::Cpu | ResourceKind::Memory | ResourceKind::Disk));
            quota.resources.extend([
                row(ResourceKind::Cpu, "{vCPU}", size.cpus),
                row(ResourceKind::Memory, "By", size.memory_bytes as f64),
                row(ResourceKind::Disk, "By", size.disk_bytes as f64),
            ]);
        }
        Ok(quota)
    }

    /// The agent of a vessel drydock holds the key of, for the services routes.
    async fn vessel_agent(&self, provider: &str, id: &str) -> Result<drydock_agent::Client, Error> {
        if !ProviderApi::provider(self, provider).await?.capabilities.agent {
            return Err(refused(format!("provider {provider} declares no vessel agent, which services need")));
        }
        // Only the vessel's own not_found is the environment's; the agent's is the service's.
        environment(self.connect_agent(provider, id, CONNECT).await)
    }
    pub(super) async fn put_vessel_service(
        &self,
        p: &str,
        id: &str,
        name: &str,
        service: &Service,
    ) -> Result<Provisioned<ServiceInfo>, Error> {
        crate::exposures::check_named("service", name)?;
        let (started, info) = self.vessel_agent(p, id).await?.start_service(name, service).await.map_err(agent_error)?;
        Ok(if started { Provisioned::Created(info) } else { Provisioned::Existing(info) })
    }
    pub(super) async fn vessel_service(&self, p: &str, id: &str, name: &str) -> Result<ServiceInfo, Error> {
        self.vessel_agent(p, id).await?.service(name).await.map_err(agent_error)
    }
    pub(super) async fn vessel_services(&self, p: &str, id: &str) -> Result<Vec<ServiceInfo>, Error> {
        self.vessel_agent(p, id).await?.services().await.map_err(agent_error)
    }
    pub(super) async fn remove_vessel_service(&self, p: &str, id: &str, name: &str, grace_ms: Option<u64>) -> Result<ServiceInfo, Error> {
        let grace = grace_ms.map(Duration::from_millis);
        self.vessel_agent(p, id).await?.remove_service(name, grace).await.map_err(agent_error)
    }
}

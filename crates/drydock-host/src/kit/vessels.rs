//! Host-direct vessels: each a directory on a machine and the process tree its
//! agent starts there, with nothing between them and the machine. `local` keeps
//! them on drydock's own machine and `ssh_host` on one it reaches over SSH. The
//! flow is here; a [`Machine`] does what differs between the two.
//!
//! A vessel is the directory `<root>/<id>/`, holding a record of what was asked
//! for and granted, its own copy of `drydock-agent` and the agent's socket at
//! `run/drydock/agent.sock`. The agent runs in a scope of its own, so stopping
//! the vessel ends the agent and everything it started, and nothing else.
//! Vessels are found by their directories, so they outlive drydock.
use crate::module::*;
use async_trait::async_trait;
use drydock_protocol::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const SOCKET: &str = "run/drydock/agent.sock";
pub const AGENT: &str = "opt/drydock/drydock-agent";
pub const RECORD: &str = "environment.json";
pub const SUSPENDED: &str = "suspended";
pub const LOG: &str = "agent.log";
/// The longest Unix socket path every supported system accepts, with a margin.
const SOCKET_PATH_LIMIT: usize = 100;
const STARTUP: Duration = Duration::from_secs(30);

/// What provisioning was asked for and granted, kept beside the vessel.
#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    /// Absent for a vessel made by hand, which is listed unlabelled.
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub size: Option<Size>,
    #[serde(default)]
    pub platform: Option<Platform>,
    /// Absent where the size is only what was asked for, holding the vessel to nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Grant>,
}

/// How the machine holds a vessel to its size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Grant {
    /// The size is the vessel's limits, enforced by its scope.
    Limits,
    /// The vessel has the whole machine, shared with whatever runs there outside drydock.
    WholeMachine,
}

/// One vessel as its machine finds it.
pub struct Found {
    pub id: String,
    pub record: Record,
    /// Whether the agent's process is alive.
    pub running: bool,
    pub suspended: bool,
    /// The machine's own words for the vessel's state, where it has them.
    pub vendor: Option<VendorState>,
}

/// One machine's side of host-direct vessels: where their directories are,
/// and how their agents start and stop.
#[async_trait]
pub trait Machine: Send + Sync + 'static {
    /// The start of every vessel id, naming the module.
    fn prefix(&self) -> &'static str;
    fn capabilities(&self) -> Capabilities;
    fn readiness(&self, c: &Credentials) -> Readiness;
    async fn refresh_readiness(&self, _: &Credentials) {}
    fn ways_in(&self) -> Vec<WayIn>;
    /// The platform vessels run, once the machine has said.
    fn platform(&self) -> Option<Platform>;
    /// What a new vessel asking for `size` gets, and how it is held to it.
    /// Called with provisions serialised, so no two see the same machine.
    async fn grant(&self, size: &Size, c: &Credentials) -> Result<(Size, Option<Grant>)>;
    /// Every vessel under the root, or only `id`. A directory whose record
    /// cannot be read is skipped, or is the error when it is the one asked for.
    async fn vessels(&self, only: Option<&str>, c: &Credentials) -> Result<Vec<Found>>;
    /// Makes the vessel's directory with its own copy of the agent and the
    /// record, or leaves nothing.
    async fn create(&self, id: &str, record: &Record, c: &Credentials) -> Result<()>;
    /// Starts the agent in a scope of its own, held to the record's grant;
    /// returns once it is started, before it answers.
    async fn launch(&self, id: &str, record: &Record, c: &Credentials) -> Result<()>;
    /// Whether the agent's process is alive, or an error when the machine could
    /// not be asked. An agent mid-upgrade has no socket for a moment, so the
    /// process decides, not the socket.
    async fn running(&self, id: &str, c: &Credentials) -> Result<bool>;
    /// How long to wait between looks at an agent that is starting.
    fn startup_poll(&self) -> Duration {
        Duration::from_millis(50)
    }
    /// Ends the agent and everything in its scope, and waits until they are gone.
    async fn stop(&self, id: &str, c: &Credentials) -> Result<()>;
    /// Removes the stopped vessel's directory, whatever its contents' modes, following no link.
    async fn remove(&self, id: &str, c: &Credentials) -> Result<()>;
    async fn mark_suspended(&self, id: &str, suspended: bool, c: &Credentials) -> Result<()>;
    /// A stream to the vessel's agent socket.
    async fn connect(&self, id: &str, c: &Credentials) -> Result<ByteStream>;
    /// A stream to the Unix socket at `path` on the machine.
    async fn open(&self, path: &Path) -> Result<ByteStream>;
    /// What the machine states of its capacity, for a machine that states it.
    async fn quota(&self, _: &Credentials) -> Option<Result<Quota>> {
        None
    }
    fn states_capacity(&self) -> bool {
        false
    }
}

pub fn not_found() -> ProtocolError {
    ProtocolError::not_found("unknown environment")
}
pub fn unavailable(reason: impl Into<String>) -> ProtocolError {
    ProtocolError::Unavailable { reason: reason.into(), retry_after: None, provider_error: None }
}
pub fn internal(reason: impl Into<String>) -> ProtocolError {
    ProtocolError::Internal { reason: reason.into(), provider_error: String::new() }
}
/// An id is the prefix, `-` and 12 lowercase hex digits, never a path.
pub fn valid_id(prefix: &str, id: &str) -> bool {
    id.strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|hex| hex.len() == 12 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}
fn environment_id(prefix: &str, label: &str) -> String {
    format!("{prefix}-{}", &format!("{:x}", Sha256::digest(label.as_bytes()))[..12])
}
fn prepared_id(image_digest: &str, platform: &Platform) -> String {
    format!("prepared-{}", &format!("{:x}", Sha256::digest(format!("{image_digest}\n{platform}").as_bytes()))[..12])
}
fn resume_token(provider: &str, id: &str) -> ResumeToken {
    ResumeToken { token: Secret::new(format!("{provider}:{id}")) }
}
/// Refuses an agent socket path too long for a Unix socket, naming the setting that shortens it.
pub fn check_socket(dir: &Path, setting: &str) -> Result<()> {
    let socket = dir.join(SOCKET);
    if socket.as_os_str().len() >= SOCKET_PATH_LIMIT {
        return Err(refused(format!(
            "the agent socket path {} is too long for a Unix socket; set a shorter `{setting}`",
            socket.display()
        )));
    }
    Ok(())
}
/// What every host-direct vessel is: the machine's filesystem, processes and
/// network, open egress that is only advisory, its agent placed and started by
/// the module, and nothing pulled.
pub fn capabilities(platforms: Vec<Platform>, workspace_root: String) -> Capabilities {
    Capabilities {
        material_modes: vec![MaterialMode::Frozen],
        checkout_strategies: vec![CheckoutStrategy::CloneInVessel],
        workspace_root,
        suspend_resume: true,
        suspend_preserves_memory: Some(false),
        // No isolation: nothing is enforced, and deny-all cannot be represented.
        egress: EgressCapability { routes: vec![EgressRoute::Open], model: EgressModel::unfiltered() },
        bootstrap: BootstrapRoute::Upload,
        agent: true,
        platforms,
        // Nothing is pulled: the route only records which image was asked for.
        image_routes: vec![ImageRoute::RegistryPull {
            auth: RegistryAuthKind::Anonymous,
            registration: CredentialRegistration::NotRequired,
            digest_references: true,
            tools_layer: ToolsLayer::Provider,
        }],
        host_filesystem: true,
        host_processes: true,
        exclusive_label: true,
        reach_ways: vec![ReachWay::OutwardExposure],
        semantics: Semantics { settles: true, idempotent: true, owner_scoped: true, token_is_id: false },
        ..Capabilities::default()
    }
}

/// Whether the agent on `stream` answers `GET /hello`, which it serves over plain HTTP/1.1.
async fn hello(stream: Result<ByteStream>) -> bool {
    let attempt = async {
        let mut stream = stream.map_err(|e| std::io::Error::other(e.to_string()))?;
        stream.write_all(b"GET /hello HTTP/1.1\r\nhost: agent\r\nconnection: close\r\n\r\n").await?;
        let mut reply = Vec::new();
        (&mut stream).take(65536).read_to_end(&mut reply).await?;
        Ok::<_, std::io::Error>(reply.starts_with(b"HTTP/1.1 200"))
    };
    matches!(tokio::time::timeout(Duration::from_secs(2), attempt).await, Ok(Ok(true)))
}

/// The provider over one machine's vessels.
pub struct Vessels<M> {
    name: String,
    machine: M,
    /// Serialises changes, so a label is created once, two provisions never see
    /// the same room, and suspend, resume and destroy never interleave. Reads do
    /// not take it.
    lifecycle: tokio::sync::Mutex<()>,
}

impl<M: Machine> Vessels<M> {
    pub fn new(name: &str, machine: M) -> Self {
        Self { name: name.to_owned(), machine, lifecycle: tokio::sync::Mutex::new(()) }
    }
    async fn found(&self, id: &str, c: &Credentials) -> Result<Found> {
        if !valid_id(self.machine.prefix(), id) {
            return Err(not_found());
        }
        self.machine.vessels(Some(id), c).await?.into_iter().find(|f| f.id == id).ok_or_else(not_found)
    }
    fn environment(&self, found: Found) -> Environment {
        let state = if found.running {
            Observation::Running
        } else if found.suspended {
            Observation::Stopped { cause: Some(StopCause::SuspendedByRequest) }
        } else {
            // The agent is gone and nobody asked: reported, not restarted.
            Observation::Stopped { cause: Some(StopCause::GuestHalted) }
        };
        Environment {
            id: found.id,
            label: found.record.label,
            provider: self.name.clone(),
            state,
            granted_size: found.record.size,
            egress: Enforcement::Advisory,
            platform: found.record.platform,
            egress_measured: false,
            egress_policy: None,
            timestamp: None,
            vendor: found.vendor,
        }
    }
    /// Start the vessel's agent and return once it answers hello.
    async fn start(&self, id: &str, record: &Record, c: &Credentials) -> Result<()> {
        self.machine.launch(id, record, c).await?;
        let ready = tokio::time::timeout(STARTUP, async {
            loop {
                if hello(self.machine.connect(id, c).await).await {
                    return Ok(());
                }
                // A machine that cannot be asked is asked again until the deadline.
                if let Ok(false) = self.machine.running(id, c).await {
                    return Err(unavailable(format!("agent exited during startup; see {LOG} in the vessel's directory")));
                }
                tokio::time::sleep(self.machine.startup_poll()).await;
            }
        })
        .await;
        ready.unwrap_or_else(|_| Err(unavailable(format!("agent did not answer hello within {STARTUP:?}"))))
    }
}

#[async_trait]
impl<M: Machine> Provider for Vessels<M> {
    fn operations(&self) -> Operations<'_> {
        let quota = self.machine.states_capacity().then_some(self as &dyn QuotaOperation);
        Operations { suspend_resume: Some(self), quota, streams: Some(self), ..Default::default() }
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities { carries: vec![CarriedKind::Unix], ..self.machine.capabilities() }
    }
    fn ways_in(&self) -> Vec<WayIn> {
        self.machine.ways_in()
    }
    fn readiness(&self, c: &Credentials) -> Readiness {
        self.machine.readiness(c)
    }
    async fn refresh_readiness(&self, c: &Credentials) {
        self.machine.refresh_readiness(c).await
    }
    async fn prepare(&self, r: PrepareRequest, _: &Credentials) -> Result<Prepared> {
        let platform = prepare_platform(&r)?;
        Ok(Prepared {
            provider: self.name.clone(),
            id: prepared_id(&r.image_digest, &platform),
            platform,
            image_digest: r.image_digest,
            tools_digest: r.tools_digest,
        })
    }
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> ProvisionResult {
        let _changing = self.lifecycle.lock().await;
        let id = environment_id(self.machine.prefix(), &r.label);
        // Only an absent vessel is created. An unreadable or corrupt record is an
        // error, and a directory another label hashed to is never written over.
        match self.found(&id, c).await {
            Ok(found) if found.record.label.as_deref() == Some(r.label.as_str()) => {
                return Ok(Provisioned::Existing(self.environment(found)));
            }
            Ok(_) => {
                return Err(
                    refused(format!("label {:?} collides with the id of another environment; use a different label", r.label)).into()
                );
            }
            Err(ProtocolError::NotFound { .. }) => {}
            Err(error) => return Err(error.into()),
        }
        if r.prepared.provider != self.name
            || self.machine.platform().as_ref() != Some(&r.prepared.platform)
            || r.prepared.id != prepared_id(&r.prepared.image_digest, &r.prepared.platform)
        {
            return Err(refused("unknown prepared form").into());
        }
        if let EgressRequest::DenyAll { .. } = r.egress {
            return Err(refused(
                "host-direct vessels share their machine's network, so deny-all egress cannot be enforced; request open egress",
            )
            .into());
        }
        let (size, grant) = self.machine.grant(&r.size, c).await?;
        let record = Record { label: Some(r.label), size: Some(size), platform: Some(r.prepared.platform), grant };
        self.machine.create(&id, &record, c).await?;
        let left = |error| ProvisionFailure::made(error, &self.name, &id);
        // Reads take no lock, so a list during this start can show the new vessel
        // as stopped.
        self.start(&id, &record, c).await.map_err(left)?;
        Ok(Provisioned::Created(self.environment(self.found(&id, c).await.map_err(left)?)))
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        let mut found = self.machine.vessels(None, c).await?;
        found.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(found.into_iter().map(|f| self.environment(f)).collect())
    }
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        Ok(self.environment(self.found(id, c).await?))
    }
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        if !valid_id(self.machine.prefix(), id) {
            return Ok(());
        }
        let _changing = self.lifecycle.lock().await;
        self.machine.stop(id, c).await?;
        self.machine.remove(id, c).await
    }
    /// The agent's socket is on the vessel's machine: the host carries the connection.
    async fn reach(&self, id: &str, c: &Credentials) -> Result<Reach> {
        self.found(id, c).await?;
        Ok(Reach::relay(&self.name, id))
    }
    async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream> {
        self.found(id, c).await?;
        self.machine.connect(id, c).await
    }
}

#[async_trait]
impl<M: Machine> Streams for Vessels<M> {
    async fn open(&self, endpoint: &Carried, _: &Credentials) -> Result<ByteStream> {
        let Carried::Unix(path) = endpoint;
        self.machine.open(Path::new(path)).await
    }
}

#[async_trait]
impl<M: Machine> SuspendResume for Vessels<M> {
    /// Stops the agent and its scope; the directory and its files stay.
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        let _changing = self.lifecycle.lock().await;
        self.found(id, c).await?;
        // Marked first, so the stop in between never reads as a crash.
        self.machine.mark_suspended(id, true, c).await?;
        if let Err(error) = self.machine.stop(id, c).await {
            let _ = self.machine.mark_suspended(id, false, c).await;
            return Err(error);
        }
        Ok(resume_token(&self.name, id))
    }
    /// Starts the agent again, whether it was suspended or died.
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()> {
        let _changing = self.lifecycle.lock().await;
        let found = self.found(id, c).await?;
        if token != resume_token(&self.name, id) {
            return Err(refused("invalid resume token for this provider/environment"));
        }
        // A failed start leaves the suspension marker: the vessel stays
        // suspended, though an agent that never answered hello may run on.
        if !found.running {
            self.start(id, &found.record, c).await?;
        }
        self.machine.mark_suspended(id, false, c).await
    }
}

#[async_trait]
impl<M: Machine> QuotaOperation for Vessels<M> {
    async fn quota(&self, c: &Credentials) -> Result<Quota> {
        self.machine.quota(c).await.unwrap_or_else(|| Err(refused("this machine states no capacity")))
    }
}

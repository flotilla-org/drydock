//! Standing exposures between drydock's machine and its vessels.
//!
//! Each vessel with an exposure has one supervisor. It holds one connection to
//! the vessel's agent and carries every exposure on it: an inward exposure is
//! a Unix listener here whose connections the agent opens to the target, and
//! an outward one is an agent listener in the vessel whose connections reach
//! the destination here. The supervisor re-establishes them when the vessel
//! runs again, when the connection drops and when drydock restarts, from one
//! file per environment beside its key. Clients see only names, endpoints,
//! `ready` and a typed error; never SSH, keys, tokens or how bytes travel.
use crate::{api::ProviderApi, client::Error, daemon::Daemon};
use drydock_agent::{Endpoint, Exec, GuestForward, HostForward};
use drydock_protocol::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::sync::{Notify, broadcast, watch};

/// Where drydock puts what it makes in a vessel. Tests whose vessel is the
/// test host point both at a directory of their own.
#[derive(Clone, Debug)]
pub struct GuestLayout {
    /// The vessel's hosts file, given a line for each guest name.
    pub hosts: PathBuf,
    /// The vessel directory for the Unix listeners behind guest names.
    pub sockets: PathBuf,
}
impl Default for GuestLayout {
    fn default() -> Self {
        Self { hosts: "/etc/hosts".into(), sockets: "/run/drydock/exposures".into() }
    }
}

/// How long the supervisor waits for things.
#[derive(Clone, Debug)]
pub struct Timing {
    /// Budget for reaching a vessel's agent, including within a `PUT`.
    pub connect: Duration,
    /// Between attempts while an exposure is not ready.
    pub retry: Duration,
    /// Between checks of a working connection.
    pub heartbeat: Duration,
}
impl Default for Timing {
    fn default() -> Self {
        Self { connect: Duration::from_secs(20), retry: Duration::from_secs(5), heartbeat: Duration::from_secs(15) }
    }
}

/// One exposure event, before the daemon gives it a cursor.
#[derive(Clone, Debug)]
pub(crate) struct Notice {
    pub provider: String,
    pub id: String,
    pub label: String,
    pub kind: EventKind,
}

const AGENT_ID_PREFIX: &str = "drydock-exposure-";
const HOSTS_MARKER: &str = " # drydock-exposure";
const STORE_FILE: &str = "exposures.json";
/// Guest names get addresses from this block, which nothing else in a vessel uses.
const LOOPBACK_BLOCK: [u8; 2] = [127, 77];
/// A Unix socket path must fit in `sun_path` with its terminator.
const SUN_PATH_MAX: usize = 107;

/// The record kept per environment, beside its key.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Record {
    provider: String,
    environment: String,
    #[serde(default)]
    inward: BTreeMap<String, InwardRequest>,
    #[serde(default)]
    outward: BTreeMap<String, OutwardEntry>,
    /// A guest name was removed while its hosts line could not be: the next
    /// connection clears it, even when no exposure is left.
    #[serde(default)]
    stale_hosts: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct OutwardEntry {
    request: OutwardRequest,
    /// The loopback address a guest name was given.
    #[serde(default)]
    address: Option<IpAddr>,
    /// What a TCP destination resolved to when set.
    #[serde(default)]
    resolved: Option<SocketAddr>,
    /// Why a TCP destination did not resolve when set.
    #[serde(default)]
    unresolved: Option<String>,
}

type Key = (Direction, String);
type Status = Result<(), ExposureError>;

fn error(code: ExposureErrorCode, reason: impl Into<String>) -> ExposureError {
    ExposureError { code, reason: reason.into() }
}

pub(crate) struct Exposures {
    shared: Arc<Shared>,
    vessels: Mutex<BTreeMap<(String, String), Arc<Vessel>>>,
    /// Serializes creating a vessel, so two first `PUT`s share one.
    creating: tokio::sync::Mutex<()>,
}
struct Shared {
    daemon: Weak<crate::daemon::Inner>,
    /// `<run>/exposures`: one private directory per environment.
    local: PathBuf,
    keys: PathBuf,
    guest: GuestLayout,
    timing: Timing,
    events: broadcast::Sender<Notice>,
}
impl Shared {
    fn daemon(&self) -> Option<Daemon> {
        self.daemon.upgrade().map(Daemon::from_inner)
    }
}

impl Exposures {
    pub(crate) fn new(daemon: Weak<crate::daemon::Inner>, run: &Path, keys: PathBuf, guest: GuestLayout, timing: Timing) -> Self {
        let shared = Shared { daemon, local: run.join("exposures"), keys, guest, timing, events: broadcast::channel(256).0 };
        Self { shared: Arc::new(shared), vessels: Mutex::default(), creating: tokio::sync::Mutex::const_new(()) }
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Notice> {
        self.shared.events.subscribe()
    }

    /// Take up every stored record again, after drydock starts.
    pub(crate) fn restore(&self) {
        let Ok(entries) = std::fs::read_dir(&self.shared.keys) else { return };
        for entry in entries.flatten() {
            let label = entry.file_name().to_string_lossy().into_owned();
            let file = entry.path().join(STORE_FILE);
            let Ok(bytes) = std::fs::read(&file) else { continue };
            match serde_json::from_slice::<Record>(&bytes) {
                Ok(record) => {
                    let key = (record.provider.clone(), record.environment.clone());
                    match Vessel::start(&self.shared, label, record) {
                        Ok(vessel) => {
                            self.vessels.lock().unwrap().insert(key, vessel);
                        }
                        Err(error) => eprintln!("exposures for {}: {error}", file.display()),
                    }
                }
                Err(error) => eprintln!("unreadable exposures record {}: {error}", file.display()),
            }
        }
    }

    fn find(&self, provider: &str, id: &str) -> Option<Arc<Vessel>> {
        self.vessels.lock().unwrap().get(&(provider.to_owned(), id.to_owned())).cloned()
    }

    /// The vessel's supervisor, started on the first exposure. Only a vessel
    /// drydock launched (it holds the key) whose provider runs the agent qualifies.
    async fn vessel(&self, daemon: &Daemon, provider: &str, id: &str) -> Result<Arc<Vessel>, Error> {
        if let Some(vessel) = self.find(provider, id) {
            return Ok(vessel);
        }
        let _creating = self.creating.lock().await;
        if let Some(vessel) = self.find(provider, id) {
            return Ok(vessel);
        }
        let refused = |reason: String| Error::Protocol(ProtocolError::Refused { reason });
        if !daemon.provider(provider).await?.capabilities.agent {
            return Err(refused(format!("provider {provider} declares no vessel agent, which exposures need")));
        }
        let environment = daemon.inspect(provider, id).await?;
        let key = daemon.key_for(&environment)?;
        if !key.exists() {
            return Err(refused("environment has no drydock-managed SSH key".into()));
        }
        let label = environment.label.ok_or_else(|| refused("environment has no drydock-managed SSH key".into()))?;
        let record = Record { provider: provider.into(), environment: id.into(), ..Record::default() };
        let vessel = Vessel::start(&self.shared, label, record).map_err(|e| Error::Transport(format!("exposures: {e}")))?;
        self.vessels.lock().unwrap().insert((provider.into(), id.into()), vessel.clone());
        Ok(vessel)
    }

    /// An environment's exposures for reading: none when it has no record, and
    /// NotFound when the environment itself is unknown.
    async fn existing(&self, daemon: &Daemon, provider: &str, id: &str) -> Result<Option<Arc<Vessel>>, Error> {
        match self.find(provider, id) {
            Some(vessel) => Ok(Some(vessel)),
            None => daemon.inspect(provider, id).await.map(|_| None),
        }
    }

    pub(crate) async fn put_inward(
        &self,
        daemon: &Daemon,
        p: &str,
        id: &str,
        name: &str,
        request: &InwardRequest,
    ) -> Result<(bool, Inward), Error> {
        check_name(name)?;
        match &request.target {
            InwardTarget::Unix(path) => check_absolute("target", path)?,
            InwardTarget::Tcp(address) if address.port() == 0 => {
                return Err(Error::InvalidRequest("target TCP port must be nonzero".into()));
            }
            InwardTarget::Tcp(_) => {}
        }
        let vessel = self.vessel(daemon, p, id).await?;
        let local = vessel.local_path(name);
        if local.as_os_str().len() > SUN_PATH_MAX {
            return Err(Error::Protocol(ProtocolError::Refused {
                reason: format!("drydock's runtime directory is too long for the exposure socket {}", local.display()),
            }));
        }
        let mut state = vessel.state.lock().await;
        let listening = state.listeners.contains_key(name);
        vessel.listen(&mut state, name).map_err(|e| Error::Transport(format!("exposure listener {}: {e}", local.display())))?;
        // What is stored is what stands: memory changes only once the record is saved.
        let mut record = state.record.clone();
        let existed = record.inward.insert(name.into(), request.clone()).is_some();
        if let Err(failure) = vessel.save(&record).await {
            if !listening {
                state.listeners.remove(name);
            }
            return Err(failure);
        }
        state.record = record;
        let key = (Direction::Inward, name.to_owned());
        vessel.establish(&self.shared, &mut state, &key).await;
        vessel.announce(&self.shared, &state, &key);
        Ok((existed, vessel.inward(&state, name).expect("just set")))
    }

    pub(crate) async fn put_outward(
        &self,
        daemon: &Daemon,
        p: &str,
        id: &str,
        name: &str,
        request: &OutwardRequest,
    ) -> Result<(bool, Outward), Error> {
        check_name(name)?;
        match &request.guest {
            Guest::Unix { unix } => check_absolute("guest", unix)?,
            Guest::Name { name, .. } => {
                if name.as_str().parse::<IpAddr>().is_ok() || name.as_str().starts_with('[') {
                    return Err(Error::InvalidRequest("guest name must be a DNS name, not an address".into()));
                }
            }
        }
        let destination = match &request.destination {
            OutwardDestination::Unix(path) => {
                check_absolute("destination", path)?;
                None
            }
            OutwardDestination::Tcp(text) => Some(host_port(text)?),
        };
        let vessel = self.vessel(daemon, p, id).await?;
        // Resolved once, now; setting it again resolves it again.
        let (resolved, unresolved) = match destination {
            None => (None, None),
            Some((host, port)) => match tokio::net::lookup_host((host.as_str(), port)).await.map(|mut found| found.next()) {
                Ok(Some(address)) => (Some(address), None),
                Ok(None) => (None, Some(format!("{host} resolves to no address"))),
                Err(error) => (None, Some(format!("resolve {host}: {error}"))),
            },
        };
        let mut state = vessel.state.lock().await;
        let previous = state.record.outward.get(name).cloned();
        let address = match &request.guest {
            Guest::Unix { .. } => None,
            Guest::Name { name: guest, .. } => Some(guest_address(&state.record, name, guest, previous.as_ref()).ok_or_else(|| {
                Error::Protocol(ProtocolError::Refused { reason: "no free loopback address for another guest name".into() })
            })?),
        };
        let entry = OutwardEntry { request: request.clone(), address, resolved, unresolved };
        let mut record = state.record.clone();
        record.outward.insert(name.into(), entry);
        vessel.save(&record).await?;
        state.record = record;
        let key = (Direction::Outward, name.to_owned());
        vessel.establish(&self.shared, &mut state, &key).await;
        vessel.announce(&self.shared, &state, &key);
        Ok((previous.is_some(), vessel.outward(&state, name).expect("just set")))
    }

    pub(crate) async fn inward(&self, daemon: &Daemon, p: &str, id: &str, name: &str) -> Result<Inward, Error> {
        let vessel = self.existing(daemon, p, id).await?;
        match vessel {
            Some(vessel) => vessel.inward(&*vessel.state.lock().await, name),
            None => None,
        }
        .ok_or_else(|| Error::Protocol(ProtocolError::NotFound { reason: "no inward exposure with this name".into() }))
    }
    pub(crate) async fn inwards(&self, daemon: &Daemon, p: &str, id: &str) -> Result<Vec<Inward>, Error> {
        let Some(vessel) = self.existing(daemon, p, id).await? else { return Ok(vec![]) };
        let state = vessel.state.lock().await;
        Ok(state.record.inward.keys().filter_map(|name| vessel.inward(&state, name)).collect())
    }
    pub(crate) async fn outward(&self, daemon: &Daemon, p: &str, id: &str, name: &str) -> Result<Outward, Error> {
        let vessel = self.existing(daemon, p, id).await?;
        match vessel {
            Some(vessel) => vessel.outward(&*vessel.state.lock().await, name),
            None => None,
        }
        .ok_or_else(|| Error::Protocol(ProtocolError::NotFound { reason: "no outward exposure with this name".into() }))
    }
    pub(crate) async fn outwards(&self, daemon: &Daemon, p: &str, id: &str) -> Result<Vec<Outward>, Error> {
        let Some(vessel) = self.existing(daemon, p, id).await? else { return Ok(vec![]) };
        let state = vessel.state.lock().await;
        Ok(state.record.outward.keys().filter_map(|name| vessel.outward(&state, name)).collect())
    }

    pub(crate) async fn remove(&self, daemon: &Daemon, p: &str, id: &str, direction: Direction, name: &str) -> Result<(), Error> {
        let Some(vessel) = self.existing(daemon, p, id).await? else { return Ok(()) };
        let mut state = vessel.state.lock().await;
        let mut record = state.record.clone();
        let removed = match direction {
            Direction::Inward => record.inward.remove(name).is_some(),
            Direction::Outward => record.outward.remove(name).is_some(),
        };
        if !removed {
            return Ok(());
        }
        let hosts_line = direction == Direction::Outward && named(&state, name);
        record.stale_hosts |= hosts_line;
        vessel.save(&record).await?;
        state.record = record;
        if direction == Direction::Inward {
            state.listeners.remove(name);
        }
        let key = (direction, name.to_owned());
        state.status.remove(&key);
        if let Some(client) = state.connected.clone() {
            // A vessel that misses this is pruned when it is next re-established.
            let _ = match direction {
                Direction::Inward => client.remove_host_forward(&agent_id(&key)).await,
                Direction::Outward => client.remove_guest_forward(&agent_id(&key)).await,
            };
            if hosts_line {
                // On failure the stale mark stays, and the next connection clears the line.
                let _ = vessel.sync_hosts(&self.shared, &mut state, &client).await;
            }
        }
        vessel.notify(&self.shared, &key, false, None, true);
        Ok(())
    }

    /// Check the vessel now, as after a resume or suspend.
    pub(crate) fn poke(&self, provider: &str, id: &str) {
        if let Some(vessel) = self.find(provider, id) {
            vessel.poke.notify_one();
        }
    }

    /// The environment is gone: stop its exposures and forget them.
    pub(crate) async fn forget(&self, provider: &str, id: &str) {
        let Some(vessel) = self.vessels.lock().unwrap().remove(&(provider.to_owned(), id.to_owned())) else { return };
        vessel.stop();
        let mut state = vessel.state.lock().await;
        state.listeners.clear();
        state.connected = None;
        let _ = tokio::fs::remove_file(&vessel.file).await;
        let _ = tokio::fs::remove_dir_all(&vessel.local).await;
        let keys: Vec<Key> = state
            .record
            .inward
            .keys()
            .map(|name| (Direction::Inward, name.clone()))
            .chain(state.record.outward.keys().map(|name| (Direction::Outward, name.clone())))
            .collect();
        for key in keys {
            vessel.notify(&self.shared, &key, false, None, true);
        }
    }
}
impl Drop for Exposures {
    fn drop(&mut self) {
        for vessel in self.vessels.lock().unwrap().values() {
            vessel.stop();
        }
    }
}

struct Vessel {
    provider: String,
    id: String,
    label: String,
    file: PathBuf,
    local: PathBuf,
    state: tokio::sync::Mutex<State>,
    agent: watch::Sender<Option<Arc<drydock_agent::Client>>>,
    poke: Notify,
    task: Mutex<Option<tokio::task::AbortHandle>>,
}
struct State {
    record: Record,
    status: BTreeMap<Key, Status>,
    listeners: BTreeMap<String, Listener>,
    connected: Option<Arc<drydock_agent::Client>>,
}
/// A local inward listener; dropping it stops it and removes its socket,
/// unless another listener (a later drydock's) has bound the path since.
struct Listener {
    path: PathBuf,
    inode: (u64, u64),
    task: tokio::task::AbortHandle,
}
fn inode(path: &Path) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
        if inode(&self.path).is_ok_and(|current| current == self.inode) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Vessel {
    fn start(shared: &Arc<Shared>, label: String, record: Record) -> io::Result<Arc<Self>> {
        let digest = format!("{:x}", Sha256::digest(format!("{}\0{}", record.provider, record.environment)));
        let local = shared.local.join(&digest[..16]);
        crate::local::private_dir(&shared.local).map_err(io::Error::other)?;
        crate::local::private_dir(&local).map_err(io::Error::other)?;
        let unreached = || Err(error(ExposureErrorCode::VesselUnreachable, "not yet established"));
        let status = record
            .inward
            .keys()
            .map(|name| ((Direction::Inward, name.clone()), unreached()))
            .chain(record.outward.keys().map(|name| ((Direction::Outward, name.clone()), unreached())))
            .collect();
        let vessel = Arc::new(Self {
            provider: record.provider.clone(),
            id: record.environment.clone(),
            file: shared.keys.join(&label).join(STORE_FILE),
            label,
            local,
            state: tokio::sync::Mutex::new(State { record, status, listeners: BTreeMap::new(), connected: None }),
            agent: watch::channel(None).0,
            poke: Notify::new(),
            task: Mutex::new(None),
        });
        {
            let mut state = vessel.state.try_lock().expect("a new vessel is unshared");
            let names: Vec<String> = state.record.inward.keys().cloned().collect();
            for name in names {
                vessel.listen(&mut state, &name)?;
            }
        }
        let task = tokio::spawn(supervise(Arc::downgrade(&vessel), shared.clone()));
        *vessel.task.lock().unwrap() = Some(task.abort_handle());
        Ok(vessel)
    }

    fn stop(&self) {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
    }

    fn local_path(&self, name: &str) -> PathBuf {
        self.local.join(format!("{name}.sock"))
    }

    /// Bind the local end of an inward exposure, once. Connections reach the
    /// target while the vessel's connection is up and close at once otherwise.
    fn listen(&self, state: &mut State, name: &str) -> io::Result<()> {
        if state.listeners.contains_key(name) {
            return Ok(());
        }
        let path = self.local_path(name);
        // The directory is drydock's own, so anything here is a stale socket.
        match std::fs::remove_file(&path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        let listener = tokio::net::UnixListener::bind(&path)?;
        drydock_agent::socket::protect(&path)?;
        let id = agent_id(&(Direction::Inward, name.to_owned()));
        let agent = self.agent.subscribe();
        let task = tokio::spawn(async move {
            loop {
                // Accept errors (EMFILE, ECONNABORTED) are transient: the
                // socket stays bound, so keep serving it.
                let mut viewer = match listener.accept().await {
                    Ok((viewer, _)) => viewer,
                    Err(error) => {
                        tracing::warn!(%error, "exposure listener accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Some(client) = agent.borrow().clone() else { continue };
                let id = id.clone();
                tokio::spawn(async move {
                    if let Ok(mut stream) = client.forward(&id).await {
                        let _ = tokio::io::copy_bidirectional(&mut viewer, &mut stream).await;
                    }
                });
            }
        });
        let inode = inode(&path)?;
        state.listeners.insert(name.into(), Listener { path, inode, task: task.abort_handle() });
        Ok(())
    }

    async fn save(&self, record: &Record) -> Result<(), Error> {
        let failed = |e: io::Error| Error::Transport(format!("record exposures {}: {e}", self.file.display()));
        let bytes = serde_json::to_vec_pretty(record).expect("exposure record serializes");
        let temporary = self.file.with_extension("json.new");
        {
            use tokio::io::AsyncWriteExt;
            let mut file =
                tokio::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&temporary).await.map_err(failed)?;
            file.write_all(&bytes).await.map_err(failed)?;
            file.sync_all().await.map_err(failed)?;
        }
        tokio::fs::rename(&temporary, &self.file).await.map_err(failed)
    }

    fn inward(&self, state: &State, name: &str) -> Option<Inward> {
        let request = state.record.inward.get(name)?;
        let status = state.status.get(&(Direction::Inward, name.to_owned())).cloned().unwrap_or(Ok(()));
        Some(Inward {
            name: name.into(),
            target: request.target.clone(),
            local: Local::Unix(self.local_path(name).to_string_lossy().into_owned()),
            ready: status.is_ok(),
            error: status.err(),
        })
    }

    fn outward(&self, state: &State, name: &str) -> Option<Outward> {
        let entry = state.record.outward.get(name)?;
        let status = state.status.get(&(Direction::Outward, name.to_owned())).cloned().unwrap_or(Ok(()));
        let address = match (&entry.request.guest, entry.address) {
            (Guest::Name { port, .. }, Some(address)) => Some(SocketAddr::new(address, port.get())),
            _ => None,
        };
        Some(Outward {
            name: name.into(),
            guest: entry.request.guest.clone(),
            destination: entry.request.destination.clone(),
            address,
            resolved: entry.resolved,
            ready: status.is_ok(),
            error: status.err(),
        })
    }

    fn notify(&self, shared: &Shared, key: &Key, ready: bool, error: Option<ExposureError>, removed: bool) {
        let kind = EventKind::Exposure { direction: key.0, name: key.1.clone(), ready, error, removed };
        let _ = shared.events.send(Notice { provider: self.provider.clone(), id: self.id.clone(), label: self.label.clone(), kind });
    }

    /// The event every set fires, whatever its outcome.
    fn announce(&self, shared: &Shared, state: &State, key: &Key) {
        let status = state.status.get(key).cloned().unwrap_or(Ok(()));
        self.notify(shared, key, status.is_ok(), status.err(), false);
    }

    /// Record an outcome, firing an event when `ready` changes.
    fn report(&self, shared: &Shared, state: &mut State, key: &Key, status: Status) {
        let was = state.status.get(key).map(Result::is_ok);
        if was != Some(status.is_ok()) && was.is_some() {
            self.notify(shared, key, status.is_ok(), status.clone().err(), false);
        }
        state.status.insert(key.clone(), status);
    }

    fn keys(state: &State) -> Vec<Key> {
        let inward = state.record.inward.keys().map(|name| (Direction::Inward, name.clone()));
        inward.chain(state.record.outward.keys().map(|name| (Direction::Outward, name.clone()))).collect()
    }

    fn report_all(&self, shared: &Shared, state: &mut State, status: ExposureError) {
        for key in Self::keys(state) {
            self.report(shared, state, &key, Err(status.clone()));
        }
    }

    fn disconnect(&self, state: &mut State) {
        state.connected = None;
        self.agent.send_replace(None);
    }

    /// Set one exposure up within a request, as the supervisor would: on the
    /// open connection, or by opening one (which sets every exposure up). Its
    /// first outcome fires no event of its own, since setting it announces it.
    async fn establish(&self, shared: &Shared, state: &mut State, key: &Key) {
        state.status.remove(key);
        self.reconcile(shared, state).await;
    }

    /// Bring every exposure to the vessel's state.
    async fn reconcile(&self, shared: &Shared, state: &mut State) -> Outcome {
        let keys = Self::keys(state);
        if keys.is_empty() && !state.record.stale_hosts {
            self.disconnect(state);
            return Outcome::Ready;
        }
        let Some(daemon) = shared.daemon() else { return Outcome::Pending };
        let inspected = tokio::time::timeout(shared.timing.connect, daemon.inspect(&self.provider, &self.id)).await;
        let running = match inspected {
            Err(_) => Err(error(ExposureErrorCode::VesselUnreachable, "the provider did not report the vessel's state in time")),
            Ok(Ok(environment)) => match environment.state {
                Observation::Running | Observation::Unknown { .. } => Ok(()),
                other => Err(error(ExposureErrorCode::NotRunning, format!("the vessel is {}", describe(&other)))),
            },
            Ok(Err(Error::Protocol(ProtocolError::NotFound { reason }))) => {
                // Destroyed while drydock was not watching: forget it, unless
                // it is the provider that is unknown (its configuration changed).
                if daemon.provider(&self.provider).await.is_ok() {
                    self.disconnect(state);
                    return Outcome::Gone;
                }
                Err(error(ExposureErrorCode::NotRunning, format!("the environment is not found: {reason}")))
            }
            Ok(Err(other)) => Err(error(ExposureErrorCode::VesselUnreachable, other.to_string())),
        };
        // A connection that still answers outlives a failed status read.
        if let Err(status) = running
            && (status.code == ExposureErrorCode::NotRunning || state.connected.is_none())
        {
            self.disconnect(state);
            self.report_all(shared, state, status);
            return Outcome::Pending;
        }
        if let Some(client) = state.connected.clone() {
            if tokio::time::timeout(shared.timing.connect, client.host_forwards()).await.is_ok_and(|r| r.is_ok()) {
                // Retry only what is not ready; what works is left alone.
                let pending: Vec<Key> = keys.into_iter().filter(|key| !matches!(state.status.get(key), Some(Ok(())))).collect();
                let hosts = pending.iter().any(|key| key.0 == Direction::Outward && named(state, &key.1)) || state.record.stale_hosts;
                return self.apply_all(shared, state, &client, pending, hosts).await;
            }
            self.disconnect(state);
        }
        let client = match daemon.connect_agent(&self.provider, &self.id, shared.timing.connect).await {
            Ok(client) => Arc::new(client),
            Err(failure) => {
                self.report_all(shared, state, error(ExposureErrorCode::VesselUnreachable, failure.to_string()));
                return Outcome::Pending;
            }
        };
        state.connected = Some(client.clone());
        self.agent.send_replace(Some(client.clone()));
        prune(&client, state).await;
        // A fresh connection always brings the hosts file to the record.
        self.apply_all(shared, state, &client, keys, true).await
    }

    /// Set `keys` up on the connected agent, first bringing the hosts file to
    /// the record when `hosts`.
    async fn apply_all(&self, shared: &Shared, state: &mut State, client: &drydock_agent::Client, keys: Vec<Key>, hosts: bool) -> Outcome {
        let hosts = if hosts { self.sync_hosts(shared, state, client).await } else { Ok(BTreeSet::new()) };
        let mut ready = !state.record.stale_hosts;
        for key in keys {
            let mut status = apply(client, state, &shared.guest, &key).await;
            if let (Ok(()), Some(guest)) = (&status, guest_name(state, &key)) {
                match &hosts {
                    Err(reason) => status = Err(error(ExposureErrorCode::Refused, reason.clone())),
                    Ok(taken) if taken.contains(&guest) => {
                        status = Err(error(ExposureErrorCode::Refused, format!("{guest} is already named in the vessel's hosts file")));
                    }
                    Ok(_) => {}
                }
            }
            ready &= status.is_ok();
            self.report(shared, state, &key, status);
        }
        if ready { Outcome::Ready } else { Outcome::Pending }
    }

    /// Bring the hosts file to the record, clearing a stale mark once it does.
    /// Returns the guest names another line already holds.
    async fn sync_hosts(&self, shared: &Shared, state: &mut State, client: &drydock_agent::Client) -> Result<BTreeSet<String>, String> {
        let taken = sync_hosts(client, &shared.guest, &state.record).await?;
        if state.record.stale_hosts {
            let mut record = state.record.clone();
            record.stale_hosts = false;
            if self.save(&record).await.is_ok() {
                state.record = record;
            }
        }
        Ok(taken)
    }
}

/// What a reconcile found.
#[derive(PartialEq)]
enum Outcome {
    /// Every exposure is ready.
    Ready,
    /// Something is not ready yet; try again soon.
    Pending,
    /// The environment no longer exists.
    Gone,
}

/// Re-establish the vessel's exposures whenever they need it, until it is forgotten.
async fn supervise(vessel: Weak<Vessel>, shared: Arc<Shared>) {
    loop {
        let Some(current) = vessel.upgrade() else { return };
        let outcome = {
            let mut state = current.state.lock().await;
            current.reconcile(&shared, &mut state).await
        };
        if outcome == Outcome::Gone {
            // Forgetting aborts this task, so it runs on its own.
            if let Some(daemon) = shared.daemon() {
                let (provider, id) = (current.provider.clone(), current.id.clone());
                tokio::spawn(async move { daemon.exposures().forget(&provider, &id).await });
            }
            return;
        }
        let wait = if outcome == Outcome::Ready { shared.timing.heartbeat } else { shared.timing.retry };
        tokio::select! {
            _ = current.poke.notified() => {}
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

fn agent_id(key: &Key) -> String {
    let direction = match key.0 {
        Direction::Inward => "in",
        Direction::Outward => "out",
    };
    format!("{AGENT_ID_PREFIX}{direction}-{}", key.1)
}

fn named(state: &State, name: &str) -> bool {
    state.record.outward.get(name).is_some_and(|entry| matches!(entry.request.guest, Guest::Name { .. }))
}

/// The guest name of a named outward exposure.
fn guest_name(state: &State, key: &Key) -> Option<String> {
    match (key.0, &state.record.outward.get(&key.1)?.request.guest) {
        (Direction::Outward, Guest::Name { name, .. }) => Some(name.as_str().to_owned()),
        _ => None,
    }
}

/// Set one exposure up on a connected agent.
async fn apply(client: &drydock_agent::Client, state: &State, guest: &GuestLayout, key: &Key) -> Status {
    let refused = |e: io::Error| error(ExposureErrorCode::Refused, e.to_string());
    match key.0 {
        Direction::Inward => {
            let Some(request) = state.record.inward.get(&key.1) else { return Ok(()) };
            let endpoint = match &request.target {
                InwardTarget::Unix(path) => Endpoint::Unix(path.into()),
                InwardTarget::Tcp(address) => Endpoint::Tcp(*address),
            };
            client.put_host_forward(HostForward { id: agent_id(key), endpoint }).await.map_err(refused)
        }
        Direction::Outward => {
            let Some(entry) = state.record.outward.get(&key.1) else { return Ok(()) };
            let destination = match (&entry.request.destination, entry.resolved, &entry.unresolved) {
                (OutwardDestination::Unix(path), ..) => Endpoint::Unix(path.into()),
                (OutwardDestination::Tcp(_), Some(address), _) => Endpoint::Tcp(address),
                (OutwardDestination::Tcp(_), None, reason) => {
                    return Err(error(ExposureErrorCode::Unresolved, reason.clone().unwrap_or_else(|| "not resolved".into())));
                }
            };
            let forward = match (&entry.request.guest, entry.address) {
                (Guest::Unix { unix }, _) => GuestForward { id: agent_id(key), unix: unix.into(), tcp: None },
                (Guest::Name { port, .. }, Some(address)) => GuestForward {
                    id: agent_id(key),
                    unix: guest.sockets.join(format!("{}.sock", key.1)),
                    tcp: Some(SocketAddr::new(address, port.get())),
                },
                (Guest::Name { .. }, None) => return Err(error(ExposureErrorCode::Refused, "guest name has no address")),
            };
            client.put_shared_guest_forward(forward, destination).await.map_err(refused)
        }
    }
}

/// Remove forwards an earlier drydock left for exposures that no longer exist.
async fn prune(client: &drydock_agent::Client, state: &State) {
    let wanted: BTreeSet<String> = Vessel::keys(state).iter().map(agent_id).collect();
    if let Ok(forwards) = client.host_forwards().await {
        for forward in forwards.into_iter().filter(|f| f.id.starts_with(AGENT_ID_PREFIX) && !wanted.contains(&f.id)) {
            let _ = client.remove_host_forward(&forward.id).await;
        }
    }
    if let Ok(forwards) = client.guest_forwards().await {
        for forward in forwards.into_iter().filter(|f| f.id.starts_with(AGENT_ID_PREFIX) && !wanted.contains(&f.id)) {
            let _ = client.remove_guest_forward(&forward.id).await;
        }
    }
}

/// Make the vessel's hosts file name exactly the current guest names. Only
/// lines drydock marked are touched, and an unchanged file is not written.
async fn sync_hosts(client: &drydock_agent::Client, guest: &GuestLayout, record: &Record) -> Result<BTreeSet<String>, String> {
    // Exposures sharing a guest name share its address, so one line serves them.
    let lines: BTreeSet<String> = record
        .outward
        .values()
        .filter_map(|entry| match (&entry.request.guest, entry.address) {
            (Guest::Name { name, .. }, Some(address)) => Some(format!("{address} {}", name.as_str())),
            _ => None,
        })
        .collect();
    // Writing through the file keeps its inode, as a bind-mounted hosts file needs.
    let script = format!(
        r#"f=$1; shift; t=$(mktemp) || exit 1
{{ grep -v '{HOSTS_MARKER}$' "$f" 2>/dev/null || true; }} > "$t"
for l in "$@"; do
  n=${{l#* }}
  # A name another line already gives would shadow ours: report it instead.
  if awk -v n="$n" '$1 !~ /^#/ {{ for (i = 2; i <= NF; i++) if ($i == n) found = 1 }} END {{ exit !found }}' "$t"; then
    printf '%s\n' "$n"
  else
    printf '%s{HOSTS_MARKER}\n' "$l" >> "$t"
  fi
done
if cmp -s "$t" "$f"; then s=0; else cat "$t" > "$f"; s=$?; fi
rm -f "$t"; exit $s"#
    );
    let mut args = vec!["-c".to_owned(), script, "sh".into(), guest.hosts.to_string_lossy().into_owned()];
    args.extend(lines);
    let (stdout, stderr, status) = client.run(Exec::new("sh", args), 64 * 1024).await.map_err(|e| format!("hosts file: {e}"))?;
    if !status.success() {
        return Err(format!("hosts file {}: {}", guest.hosts.display(), String::from_utf8_lossy(&stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&stdout).lines().map(str::to_owned).collect())
}

/// The address for exposure `name` with guest name `guest`: the one another
/// exposure already gave that guest name, else its own earlier one unless
/// another name holds it, else a free one.
fn guest_address(record: &Record, name: &str, guest: &HostAddress, previous: Option<&OutwardEntry>) -> Option<IpAddr> {
    let others = || record.outward.iter().filter(|(other, _)| other.as_str() != name).map(|(_, entry)| entry);
    let shared = others().find(|entry| matches!(&entry.request.guest, Guest::Name { name, .. } if name == guest)).and_then(|e| e.address);
    let own = previous.and_then(|entry| entry.address).filter(|address| !others().any(|entry| entry.address == Some(*address)));
    shared.or(own).or_else(|| free_loopback(record, name))
}

/// The lowest loopback address in drydock's block that no other guest name has.
fn free_loopback(record: &Record, name: &str) -> Option<IpAddr> {
    let used: BTreeSet<IpAddr> = record.outward.iter().filter(|(other, _)| other.as_str() != name).filter_map(|(_, e)| e.address).collect();
    (1..=u16::MAX - 1)
        .map(|n| IpAddr::V4(Ipv4Addr::new(LOOPBACK_BLOCK[0], LOOPBACK_BLOCK[1], (n >> 8) as u8, n as u8)))
        .filter(|address| !matches!(address, IpAddr::V4(v4) if v4.octets()[3] == 0 || v4.octets()[3] == 255))
        .find(|address| !used.contains(address))
}

fn describe(observation: &Observation) -> &'static str {
    match observation {
        Observation::Running => "running",
        Observation::Stopped { .. } => "stopped",
        Observation::Gone { .. } => "gone",
        Observation::Transitioning { .. } => "changing state",
        Observation::Unknown { .. } => "in an unknown state",
    }
}

/// Names become file and agent IDs: a letter or digit, then letters, digits, `_`, `.` or `-`.
fn check_name(name: &str) -> Result<(), Error> {
    let valid = (1..=64).contains(&name.len())
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    if !valid {
        return Err(Error::InvalidRequest(
            "exposure name must be 1 to 64 letters, digits, '_', '.' or '-', starting with a letter or digit".into(),
        ));
    }
    Ok(())
}

fn check_absolute(field: &str, path: &str) -> Result<(), Error> {
    if !path.starts_with('/') || path.contains('\0') || path.len() > SUN_PATH_MAX {
        return Err(Error::InvalidRequest(format!("{field} must be an absolute Unix socket path of at most {SUN_PATH_MAX} bytes")));
    }
    Ok(())
}

/// `host:port`, with an IPv6 host in brackets.
fn host_port(text: &str) -> Result<(String, u16), Error> {
    let invalid = || Error::InvalidRequest(format!("destination {text:?} must be host:port"));
    let (host, port) = text.rsplit_once(':').ok_or_else(invalid)?;
    let port = port.parse::<u16>().ok().filter(|port| *port != 0).ok_or_else(invalid)?;
    HostAddress::try_from(host.to_owned()).map_err(|_| invalid())?;
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    Ok((host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named_entry(address: Option<IpAddr>) -> OutwardEntry {
        OutwardEntry {
            request: OutwardRequest {
                guest: Guest::Name { name: HostAddress::try_from("service.test".to_owned()).unwrap(), port: Port::new(443).unwrap() },
                destination: OutwardDestination::Tcp("127.0.0.1:443".into()),
            },
            address,
            resolved: None,
            unresolved: None,
        }
    }

    // Each guest name gets its own loopback address in drydock's block,
    // never a network or broadcast-looking one, and replacing a name may keep
    // its own. Generated: any set of names already holding any addresses.
    #[hegel::test]
    fn guest_names_get_distinct_free_loopback_addresses(tc: hegel::TestCase) {
        use hegel::generators as gs;
        let held: Vec<u16> = tc.draw(gs::vecs(gs::integers::<u16>().min_value(0).max_value(600)).max_size(40));
        let mut record = Record::default();
        for (i, n) in held.iter().enumerate() {
            let address = IpAddr::V4(Ipv4Addr::new(127, 77, (n >> 8) as u8, *n as u8));
            record.outward.insert(format!("held-{i}"), named_entry(Some(address)));
        }
        let chosen = free_loopback(&record, "new").unwrap();
        let IpAddr::V4(v4) = chosen else { panic!("IPv4 block") };
        assert!(chosen.is_loopback() && v4.octets()[..2] == LOOPBACK_BLOCK);
        assert!(v4.octets()[3] != 0 && v4.octets()[3] != 255);
        assert!(record.outward.values().all(|entry| entry.address != Some(chosen)), "{chosen} is already held");
        // A name's own address is free to it.
        if let Some(first) = record.outward.get("held-0").and_then(|e| e.address)
            && !record.outward.iter().any(|(name, e)| name != "held-0" && e.address == Some(first))
            && !matches!(first, IpAddr::V4(v4) if v4.octets()[3] == 0 || v4.octets()[3] == 255)
        {
            assert!(free_loopback(&record, "held-0").unwrap() <= first);
        }
    }

    // Names become file names and agent IDs, so only the safe alphabet passes,
    // within 1..=64 bytes and never starting with a separator.
    #[hegel::test]
    fn exposure_names_are_safe_file_names(tc: hegel::TestCase) {
        use hegel::generators as gs;
        let name: String = tc.draw(gs::text().max_size(70));
        let accepted = check_name(&name).is_ok();
        let safe = !name.is_empty()
            && name.len() <= 64
            && !name.starts_with(['.', '-', '_'])
            && name.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
        assert_eq!(accepted, safe, "{name:?}");
    }
}

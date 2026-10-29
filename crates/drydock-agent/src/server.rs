use crate::{
    query::{AttachQuery, DigestQuery},
    rest::{header_value, sf_boolean, sf_integer, structured},
    *,
};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, head, post, put},
};
use drydock_transport::{Listener as Connections, http};
use std::{collections::BTreeMap, sync::Arc};
use tokio::{
    net::{TcpListener, UnixListener},
    sync::{Mutex, mpsc},
    task::JoinSet,
};

type Refusal<T> = Result<T, AgentError>;

pub(crate) struct Target {
    pub(crate) endpoint: Endpoint,
    pub(crate) streams: JoinSet<()>,
}
impl Target {
    async fn stop(mut self) {
        self.streams.shutdown().await;
    }
}
struct GuestSocket {
    listener: UnixListener,
    path: PathBuf,
}
impl Drop for GuestSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
/// Live connections of one outward forward. They outlive a rebind of the
/// forward's listeners and end when the forward is removed.
type Bridges = Arc<std::sync::Mutex<JoinSet<()>>>;
struct Listener {
    forward: OutwardForward,
    task: tokio::task::JoinHandle<()>,
    unix: Arc<GuestSocket>,
    tcp: Option<(std::net::SocketAddr, Arc<TcpListener>)>,
    bridges: Bridges,
}
impl Listener {
    async fn stop(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}
#[derive(Default)]
pub(crate) struct Settings {
    pub(crate) config: Configuration,
    outward: BTreeMap<String, Listener>,
    pub(crate) inward: BTreeMap<String, Target>,
    capture: Option<crate::egress::Capture>,
}
impl Settings {
    /// Loopback listeners exempt from capture, optionally with one forward's
    /// listener replaced or removed.
    fn exemptions(&self, id: &str, replacement: Option<&OutwardForward>) -> Vec<std::net::SocketAddr> {
        self.outward
            .iter()
            .filter(|(other, _)| other.as_str() != id)
            .map(|(_, l)| &l.forward)
            .chain(replacement)
            .filter_map(|f| f.tcp)
            .collect()
    }
}
pub(crate) struct Shared {
    hello: Hello,
    egress_system: crate::egress::System,
    pub(crate) events: Arc<crate::events::Events>,
    pub(crate) outward: Arc<crate::streams::Outward>,
    pub(crate) settings: Mutex<Settings>,
    executable: PathBuf,
    upgrade: Mutex<()>,
    restart: mpsc::Sender<PathBuf>,
    pub(crate) store: crate::store::Store,
    processes: crate::process::Processes,
}
impl Shared {
    /// The way out for a fetch: the configured egress, as for guest traffic.
    pub(crate) async fn network(&self) -> crate::fetch::Network {
        let settings = self.settings.lock().await;
        match &settings.config.egress {
            Some(egress) => crate::fetch::Network::Upstream {
                outward: self.outward.clone(),
                id: egress.upstream.clone(),
                ca: settings.config.ca.clone(),
            },
            None => crate::fetch::Network::Direct,
        }
    }
}
/// Serves drydock's connections. Never expose this router on guest TCP.
pub struct Agent {
    listeners: Vec<Box<dyn Connections>>,
    pub(crate) shared: Arc<Shared>,
    restart: mpsc::Receiver<PathBuf>,
}
/// Output bytes held per process before the process blocks on its pipe.
const PROCESS_BUFFER: usize = 1024 * 1024;
/// 128 random bits, drawn once per agent process. Without the kernel's
/// source, time and PID still differ between boots: the ID only has to tell
/// restarts apart, not be unpredictable.
fn boot_id() -> String {
    let mut bytes = [0u8; 16];
    if let Err(error) = getrandom::fill(&mut bytes) {
        tracing::warn!(%error, "no kernel randomness for the boot ID; using time and PID");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        bytes[..8].copy_from_slice(&(now.as_nanos() as u64).to_le_bytes());
        bytes[8..12].copy_from_slice(&std::process::id().to_le_bytes());
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
impl Agent {
    /// `executable` is the installed agent path; the upgrade sidecars and the
    /// digest store (`<executable>.store`) live beside it.
    pub fn new(listener: impl Connections, fingerprint: String, executable: PathBuf) -> Self {
        Self::with_process_buffer(listener, fingerprint, executable, PROCESS_BUFFER)
    }
    /// As [`Agent::new`], holding at most `buffer` output bytes per process.
    pub fn with_process_buffer(listener: impl Connections, fingerprint: String, executable: PathBuf, buffer: usize) -> Self {
        let (tx, restart) = mpsc::channel(1);
        let boot_id = boot_id();
        let events = Arc::new(crate::events::Events::new(boot_id.clone()));
        let shared = Arc::new(Shared {
            hello: Hello {
                fingerprint,
                features: FEATURES.iter().map(|s| (*s).into()).collect(),
                platform: Some(Platform::current()),
                boot_id,
                probation: false,
            },
            egress_system: crate::egress::System::default(),
            outward: Arc::new(crate::streams::Outward::new(events.clone(), crate::streams::CLAIM_DEADLINE)),
            processes: crate::process::Processes::new(buffer, events.clone()),
            events,
            settings: Mutex::new(Settings::default()),
            store: crate::store::Store::new(crate::upgrade::sidecar(&executable, "store")),
            executable,
            upgrade: Mutex::new(()),
            restart: tx,
        });
        Self { listeners: vec![Box::new(listener)], shared, restart }
    }
    /// Close an outward connection nobody claims within `deadline`, instead
    /// of [`crate::CLAIM_DEADLINE`].
    pub fn with_claim_deadline(mut self, deadline: std::time::Duration) -> Self {
        let shared = Arc::get_mut(&mut self.shared).expect("the deadline is chosen before the agent runs");
        shared.outward = Arc::new(crate::streams::Outward::new(shared.events.clone(), deadline));
        self
    }
    /// Keep the digest store at `root` instead of beside the executable.
    /// Agents on one host may share a store, so that an artifact one vessel
    /// fetched is a lookup for the next.
    pub fn with_store(mut self, root: PathBuf) -> Self {
        Arc::get_mut(&mut self.shared).expect("the store is chosen before the agent runs").store = crate::store::Store::new(root);
        self
    }
    /// Report `platform` in the hello instead of this build's own. Only
    /// stand-in vessels use it, to model a guest of the platform their vessel
    /// was prepared for: a real agent reports the platform it runs on.
    pub fn with_platform(mut self, platform: Platform) -> Self {
        Arc::get_mut(&mut self.shared).expect("the platform is chosen before the agent runs").hello.platform = Some(platform);
        self
    }
    /// Serve another listener (e.g. vsock). All listeners share state.
    pub fn add_listener(&mut self, listener: impl Connections) {
        self.listeners.push(Box::new(listener));
    }
    fn router(&self) -> Router {
        use crate::files::*;
        Router::new()
            .route("/hello", get(hello))
            .route("/events", get(events))
            .route("/upgrade", post(activate_upgrade))
            .route("/upgrade/confirm", post(confirm_upgrade))
            .route("/configuration", get(configuration).put(configure))
            .route("/processes", get(list_processes).post(spawn))
            .route("/processes/{id}", get(process).delete(remove_process))
            .route("/processes/{id}/output", get(attach))
            .route("/processes/{id}/stdin", put(write_stdin))
            .route("/processes/{id}/signals", post(signal))
            .route("/files/{*path}", get(get_file).head(head_file).put(put_file))
            .route("/entries/", get(get_entry).delete(delete_entry).patch(patch_entry))
            .route("/entries/{*path}", get(get_entry).delete(delete_entry).patch(patch_entry))
            .route("/dirs/", get(get_dir))
            .route("/dirs/{*path}", get(get_dir).put(put_dir))
            .route("/links/{*path}", put(put_link))
            .route("/trees/{*path}", put(put_tree))
            .route("/renames", post(post_rename))
            .route("/uploads/{sha256}", head(upload_offset).patch(append_upload).delete(remove_upload))
            .route("/blobs/{sha256}", head(blob_size).put(create_upload).delete(remove_blob))
            .route("/artifacts", get(crate::artifacts::list_artifacts))
            .route(
                "/artifacts/{sha256}",
                get(crate::artifacts::get_artifact).put(crate::artifacts::put_artifact).delete(crate::artifacts::delete_artifact),
            )
            .route("/artifacts/{sha256}/links/{*path}", put(crate::artifacts::put_artifact_link))
            .route("/forwards/outward", get(outward_forwards))
            .route("/forwards/outward/{id}", get(outward_forward).put(put_outward).delete(remove_outward))
            .route("/forwards/outward/{id}/connections/{connection}", get(crate::streams::claim).connect(crate::streams::claim))
            .route("/forwards/inward", get(inward_forwards))
            .route("/forwards/inward/{id}", get(inward_forward).put(put_inward).delete(remove_inward))
            .route("/forwards/inward/{id}/stream", get(crate::streams::open_inward).connect(crate::streams::open_inward))
            // A deliberate cap on JSON control bodies only; streamed bodies have none.
            .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
            .layer(axum::middleware::from_fn(structured))
            .layer(tower_http::catch_panic::CatchPanicLayer::custom(crate::rest::panicked))
            .with_state(self.shared.clone())
    }
    /// Returns the probation candidate on upgrade. The composition root re-execs
    /// with its original fixed flags; dropping this future drops all agent streams.
    pub async fn run(mut self) -> io::Result<PathBuf> {
        if let Err(error) = self.shared.egress_system.clear().await {
            tracing::warn!(%error, "could not clear guest egress redirects left by an earlier agent");
        }
        match self.shared.store.sweep(crate::store::ABANDONED) {
            Ok(0) => {}
            Ok(removed) => tracing::info!(removed, "removed abandoned partial uploads"),
            Err(error) => tracing::warn!(%error, "could not sweep abandoned partial uploads"),
        }
        if let Err(error) = self.shared.store.sweep_staging(crate::store::ABANDONED) {
            tracing::warn!(%error, "could not sweep abandoned artifact staging");
        }
        let router = self.router();
        let mut tasks = JoinSet::new();
        for mut listener in self.listeners.drain(..) {
            let router = router.clone();
            tasks.spawn(async move {
                let mut connections = JoinSet::new();
                let mut backoff = std::time::Duration::from_millis(100);
                loop {
                    tokio::select! {
                        Some(_) = connections.join_next(), if !connections.is_empty() => {}
                        accepted = listener.accept() => match accepted {
                            Ok(stream) => {
                                backoff = std::time::Duration::from_millis(100);
                                connections.spawn(http::serve(stream, router.clone()));
                            }
                            Err(error) if retryable(&error) => {
                                tracing::warn!(%error, "agent listener accept failed");
                                tokio::time::sleep(backoff).await;
                                backoff = (backoff * 2).min(std::time::Duration::from_secs(1));
                            }
                            Err(error) => {
                                tracing::warn!(%error, "agent listener stopped");
                                break;
                            }
                        },
                    }
                }
                // Connections already accepted are served to their end.
                while connections.join_next().await.is_some() {}
            });
        }
        loop {
            tokio::select! {
                path = self.restart.recv() => {
                    tasks.shutdown().await;
                    // Remove owned guest socket paths before exec discards the
                    // runtime. Aborting tasks alone does not synchronously drop them.
                    let mut settings = self.shared.settings.lock().await;
                    for (_, listener) in std::mem::take(&mut settings.outward) { listener.stop().await; }
                    // The configuration dies with this process; so do its redirects.
                    if let Err(error) = self.shared.egress_system.clear().await {
                        tracing::warn!(%error, "could not clear guest egress redirects before re-exec");
                    }
                    return path.ok_or_else(|| io::Error::other("upgrade channel closed"));
                },
                finished = tasks.join_next() => if finished.is_none() {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "every agent listener closed"));
                },
            }
        }
    }
}

/// Transient accept failures: the listener stays bound and is served again.
fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::OutOfMemory
    ) || matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE))
}

async fn events(State(s): State<Arc<Shared>>, Query(query): Query<crate::events::Since>) -> Response {
    crate::events::follow(s.events.clone(), query.since.as_deref())
}

async fn hello(State(s): State<Arc<Shared>>) -> Json<Hello> {
    // Reading hello never changes anything; confirmation is its own call.
    Json(Hello { probation: crate::upgrade::on_probation(&s.executable), ..s.hello.clone() })
}

fn configuration_tag(s: &Shared, config: &Configuration) -> String {
    use sha2::{Digest, Sha256};
    let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(config).expect("configuration serializes")));
    format!("\"{}-{}\"", s.hello.boot_id, &digest[..16])
}
async fn configuration(State(s): State<Arc<Shared>>) -> Response {
    let config = s.settings.lock().await.config.clone();
    ([(header::ETAG, header_value(configuration_tag(&s, &config)))], Json(config)).into_response()
}
async fn configure(State(s): State<Arc<Shared>>, headers: HeaderMap, Json(config): Json<Configuration>) -> Refusal<Response> {
    const OP: &str = "configuration.replace";
    if config.environment.iter().any(|(k, v)| k.is_empty() || k.contains(['=', '\0']) || v.contains('\0')) {
        return Err(AgentError::new(
            OP,
            "environment",
            ErrorKind::InvalidInput,
            "variable names must be nonempty without = or NUL; values without NUL",
        ));
    }
    let mut settings = s.settings.lock().await;
    let current = configuration_tag(&s, &settings.config);
    if !crate::rest::if_match(OP, "configuration", &headers, Some(&current))? {
        let expected: Vec<_> = headers.get_all(header::IF_MATCH).iter().filter_map(|v| v.to_str().ok()).collect();
        let expected = expected.join(", ");
        return Err(AgentError::new(
            OP,
            "configuration",
            ErrorKind::PreconditionFailed,
            format!("configuration is now {current}, not {expected}"),
        ));
    }
    if let Some(egress) = &config.egress {
        check_id(&egress.upstream).map_err(|e| AgentError::io(OP, "egress.upstream", e))?;
        if let Some(conflict) =
            settings.outward.values().find(|l| l.forward.tcp.is_some_and(|a| crate::egress::RESERVED_PORTS.contains(&a.port())))
        {
            return Err(AgentError::new(
                OP,
                "egress",
                ErrorKind::Conflict,
                format!("outward forward {} listens on a port egress capture needs", conflict.forward.id),
            ));
        }
    }
    let mut prepared_capture = match (&settings.capture, &config.egress) {
        (None, Some(egress)) => Some(
            crate::egress::Capture::prepare(s.outward.clone(), egress.upstream.clone())
                .await
                .map_err(|e| AgentError::io("egress.prepare", "listeners", e))?,
        ),
        _ => None,
    };
    let installed: Refusal<()> = async {
        if config.egress.is_none() && settings.capture.is_none() {
            return Ok(());
        }
        let exempt = settings.exemptions("", None);
        s.egress_system.install(config.egress.is_some(), &exempt).await.map_err(|e| AgentError::io("egress.redirect", "nftables", e))?;
        // Configuration.ca is the complete combined trust bundle supplied by
        // the controller; the agent does not fetch host trust material. A
        // bundle that cannot be replaced leaves the old one; reinstall the
        // previous nft transaction before reporting the refusal, and report a
        // failed rollback separately.
        let ca_path = &s.egress_system.ca;
        if config.egress.is_some()
            && let Err(error) = crate::durable::replace(ca_path, config.ca.as_bytes(), 0o644)
        {
            s.egress_system
                .install(settings.config.egress.is_some(), &exempt)
                .await
                .map_err(|e| AgentError::io("egress.rollback", "nftables", e))?;
            return Err(AgentError::io("egress.ca", ca_path.display(), error));
        }
        Ok(())
    }
    .await;
    if let Err(error) = installed {
        if let Some(capture) = prepared_capture.take() {
            capture.stop().await;
        }
        return Err(error);
    }
    if let Some(egress) = &config.egress {
        if let Some(capture) = prepared_capture.take() {
            settings.capture = Some(capture);
        }
        settings.capture.as_ref().unwrap().set_upstream(egress.upstream.clone());
    } else if let Some(capture) = settings.capture.take() {
        capture.stop().await;
    }
    let tag = configuration_tag(&s, &config);
    settings.config = config;
    Ok((StatusCode::NO_CONTENT, [(header::ETAG, header_value(tag))]).into_response())
}

async fn listen(forward: &OutwardForward, s: &Arc<Shared>, old: Option<&Listener>) -> io::Result<Listener> {
    if forward.tcp.is_some_and(|addr| !addr.ip().is_loopback()) {
        return Err(invalid("guest TCP listener must be loopback"));
    }
    // Bind before publishing the new listener.
    let tcp = if let Some(address) = forward.tcp {
        if let Some((_, listener)) = old.and_then(|old| old.tcp.as_ref()).filter(|(previous, _)| *previous == address) {
            Some((address, listener.clone()))
        } else {
            let listener = std::net::TcpListener::bind(address)?;
            listener.set_nonblocking(true)?;
            Some((address, Arc::new(TcpListener::from_std(listener)?)))
        }
    } else {
        None
    };
    let unix = if let Some(old) = old.filter(|old| old.unix.path == forward.unix) {
        old.unix.clone()
    } else {
        crate::socket::private_directory(forward.unix.parent().ok_or_else(|| invalid("socket requires a run directory"))?)?;
        let unix = match UnixListener::bind(&forward.unix) {
            Ok(listener) => listener,
            Err(error) => {
                use std::os::unix::fs::FileTypeExt;
                let stale = std::fs::symlink_metadata(&forward.unix).is_ok_and(|m| m.file_type().is_socket())
                    && matches!(tokio::time::timeout(std::time::Duration::from_millis(100), tokio::net::UnixStream::connect(&forward.unix)).await,
                    Ok(Err(ref error)) if error.kind() == io::ErrorKind::ConnectionRefused);
                if !stale {
                    return Err(error);
                }
                std::fs::remove_file(&forward.unix)?;
                UnixListener::bind(&forward.unix)?
            }
        };
        crate::socket::protect(&forward.unix)?;
        Arc::new(GuestSocket { listener: unix, path: forward.unix.clone() })
    };
    let owned_unix = unix.clone();
    let owned_tcp = tcp.clone();
    let bridges = old.map(|old| old.bridges.clone()).unwrap_or_default();
    let streams = bridges.clone();
    let id = forward.id.clone();
    let (outward, events) = (s.outward.clone(), s.events.clone());
    let task = tokio::spawn(async move {
        loop {
            let accepted: io::Result<ByteStream> = tokio::select! {
                result = unix.listener.accept() => result.map(|(s,_)| Box::new(s) as ByteStream),
                result = async { tcp.as_ref().unwrap().1.accept().await }, if tcp.is_some() => result.map(|(s,_)| Box::new(s) as ByteStream),
            };
            let mut stream = match accepted {
                Ok(stream) => stream,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::OutOfMemory
                    ) || matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, forward = %id, "outward listener stopped");
                    events.push(crate::events::Event::ForwardFailed { forward: id.clone(), reason: format!("listener stopped: {error}") });
                    break;
                }
            };
            let (outward, id) = (outward.clone(), id.clone());
            let mut streams = streams.lock().unwrap();
            // Reap finished bridges without retaining an unbounded history.
            while streams.try_join_next().is_some() {}
            streams.spawn(async move {
                match outward.open(&id).await {
                    Ok(mut remote) => {
                        if let Err(error) = tokio::io::copy_bidirectional(&mut stream, &mut remote).await {
                            tracing::warn!(%error, forward = %id, "outward connection failed");
                        }
                    }
                    Err(error) => tracing::warn!(%error, forward = %id, "outward connection was not claimed"),
                }
            });
        }
    });
    Ok(Listener { forward: forward.clone(), task, unix: owned_unix, tcp: owned_tcp, bridges })
}
fn check_path_id(operation: &str, path_id: &str, body_id: &str) -> Refusal<()> {
    check_id(path_id).map_err(|e| AgentError::io(operation, path_id, e))?;
    if path_id != body_id {
        return Err(AgentError::new(operation, path_id, ErrorKind::InvalidInput, format!("body names forward {body_id:?}")));
    }
    Ok(())
}
async fn outward_forwards(State(s): State<Arc<Shared>>) -> Json<Vec<OutwardForward>> {
    Json(s.settings.lock().await.outward.values().map(|l| l.forward.clone()).collect())
}
async fn outward_forward(State(s): State<Arc<Shared>>, Path(id): Path<String>) -> Refusal<Json<OutwardForward>> {
    let settings = s.settings.lock().await;
    let listener = settings
        .outward
        .get(&id)
        .ok_or_else(|| AgentError::new("forward.outward.read", &id, ErrorKind::NotFound, "no outward forward with this ID"))?;
    Ok(Json(listener.forward.clone()))
}
/// Idempotent upsert. An unchanged forward with a live listener is left
/// alone, streams and all; a changed one is rebound before the old one stops.
async fn put_outward(State(s): State<Arc<Shared>>, Path(id): Path<String>, Json(forward): Json<OutwardForward>) -> Refusal<StatusCode> {
    const OP: &str = "forward.outward.put";
    check_path_id(OP, &id, &forward.id)?;
    let mut settings = s.settings.lock().await;
    let old = settings.outward.get(&id);
    if old.is_some_and(|old| old.forward == forward && !old.task.is_finished()) {
        return Ok(StatusCode::OK);
    }
    let capture = settings.capture.is_some();
    if capture && forward.tcp.is_some_and(|a| crate::egress::RESERVED_PORTS.contains(&a.port())) {
        return Err(AgentError::new(OP, &id, ErrorKind::Conflict, "forward conflicts with an egress listener"));
    }
    let existed = old.is_some();
    let tcp_changed = old.map(|old| old.forward.tcp) != Some(forward.tcp);
    let listener = listen(&forward, &s, old).await.map_err(|e| AgentError::io("forward.listen", forward.unix.display(), e))?;
    if capture && tcp_changed {
        let exempt = settings.exemptions(&id, Some(&forward));
        if let Err(error) = s.egress_system.install(true, &exempt).await {
            listener.stop().await;
            return Err(AgentError::io("egress.redirect", "nftables", error));
        }
    }
    if let Some(old) = settings.outward.insert(id, listener) {
        old.stop().await;
    }
    Ok(if existed { StatusCode::OK } else { StatusCode::CREATED })
}
async fn remove_outward(State(s): State<Arc<Shared>>, Path(id): Path<String>) -> Refusal<StatusCode> {
    let mut settings = s.settings.lock().await;
    let Some(listener) = settings.outward.remove(&id) else {
        return Err(AgentError::new("forward.outward.remove", &id, ErrorKind::NotFound, "no outward forward with this ID"));
    };
    if settings.capture.is_some() && listener.forward.tcp.is_some() {
        let exempt = settings.exemptions(&id, None);
        if let Err(error) = s.egress_system.install(true, &exempt).await {
            settings.outward.insert(id, listener);
            return Err(AgentError::io("egress.redirect", "nftables", error));
        }
    }
    listener.stop().await;
    Ok(StatusCode::NO_CONTENT)
}
async fn inward_forwards(State(s): State<Arc<Shared>>) -> Json<Vec<InwardForward>> {
    let settings = s.settings.lock().await;
    Json(settings.inward.iter().map(|(id, t)| InwardForward { id: id.clone(), endpoint: t.endpoint.clone() }).collect())
}
async fn inward_forward(State(s): State<Arc<Shared>>, Path(id): Path<String>) -> Refusal<Json<InwardForward>> {
    let settings = s.settings.lock().await;
    let target = settings
        .inward
        .get(&id)
        .ok_or_else(|| AgentError::new("forward.inward.read", &id, ErrorKind::NotFound, "no inward forward with this ID"))?;
    Ok(Json(InwardForward { id, endpoint: target.endpoint.clone() }))
}
/// A changed endpoint ends the streams to the old one, unlike an outward
/// listener's rebind: they would otherwise keep reaching a target the host
/// no longer names.
async fn put_inward(State(s): State<Arc<Shared>>, Path(id): Path<String>, Json(forward): Json<InwardForward>) -> Refusal<StatusCode> {
    const OP: &str = "forward.inward.put";
    check_path_id(OP, &id, &forward.id)?;
    if matches!(&forward.endpoint, Endpoint::Tcp(address) if address.port() == 0) {
        return Err(AgentError::new(OP, &id, ErrorKind::InvalidInput, "inward target TCP port must be nonzero"));
    }
    let mut settings = s.settings.lock().await;
    if settings.inward.get(&id).is_some_and(|t| t.endpoint == forward.endpoint) {
        return Ok(StatusCode::OK);
    }
    let old = settings.inward.insert(id, Target { endpoint: forward.endpoint, streams: JoinSet::new() });
    let existed = old.is_some();
    if let Some(old) = old {
        old.stop().await;
    }
    Ok(if existed { StatusCode::OK } else { StatusCode::CREATED })
}
async fn remove_inward(State(s): State<Arc<Shared>>, Path(id): Path<String>) -> Refusal<StatusCode> {
    let target = s
        .settings
        .lock()
        .await
        .inward
        .remove(&id)
        .ok_or_else(|| AgentError::new("forward.inward.remove", &id, ErrorKind::NotFound, "no inward forward with this ID"))?;
    target.stop().await;
    Ok(StatusCode::NO_CONTENT)
}

async fn spawn(State(s): State<Arc<Shared>>, Json(request): Json<Exec>) -> Refusal<Response> {
    let environment = s.settings.lock().await.config.environment.clone();
    let handle = s.processes.spawn(request, environment)?;
    let info = handle.info();
    Ok((StatusCode::CREATED, [(header::LOCATION, header_value(format!("/processes/{}", info.id)))], Json(info)).into_response())
}
async fn list_processes(State(s): State<Arc<Shared>>) -> Json<Vec<ProcessInfo>> {
    Json(s.processes.list())
}
async fn process(State(s): State<Arc<Shared>>, Path(id): Path<String>) -> Refusal<Json<ProcessInfo>> {
    Ok(Json(s.processes.get(&id)?.info()))
}
async fn remove_process(State(s): State<Arc<Shared>>, Path(id): Path<String>) -> Refusal<StatusCode> {
    s.processes.remove(&id)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn attach(State(s): State<Arc<Shared>>, Path(id): Path<String>, Query(query): Query<AttachQuery>) -> Refusal<Response> {
    let stream = s.processes.get(&id)?.attach([query.stdout, query.stderr])?;
    Ok(([(header::CONTENT_TYPE, crate::frames::CONTENT_TYPE)], Body::from_stream(stream)).into_response())
}
async fn write_stdin(State(s): State<Arc<Shared>>, Path(id): Path<String>, headers: HeaderMap, body: Body) -> Refusal<StatusCode> {
    crate::files::require_octet_stream("process.stdin", std::path::Path::new(&id), &headers, &["application/octet-stream"])?;
    s.processes.get(&id)?.write_stdin(body).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Signal {
    pub signal: i32,
}
async fn signal(State(s): State<Arc<Shared>>, Path(id): Path<String>, Json(request): Json<Signal>) -> Refusal<StatusCode> {
    s.processes.get(&id)?.signal(request.signal)?;
    Ok(StatusCode::NO_CONTENT)
}

fn sha256_header(digest: &str) -> [(header::HeaderName, header::HeaderValue); 1] {
    [(header::ETAG, header_value(format!("\"{digest}\"")))]
}
/// An upload's state as draft-ietf-httpbis-resumable-upload-12 headers.
fn upload_headers(response: &mut Response, progress: &crate::store::Progress) {
    let headers = response.headers_mut();
    headers.insert("upload-offset", header_value(progress.offset));
    headers.insert("upload-complete", header_value(if progress.complete { "?1" } else { "?0" }));
    if let Some(length) = progress.length {
        headers.insert("upload-length", header_value(length));
    }
    // The agent applies no size limit of its own; an incomplete upload is
    // kept for as long as it is not left untouched.
    let limit = progress.max_age.map_or("min-size=0".to_owned(), |age| format!("max-age={}", age.as_secs()));
    headers.insert("upload-limit", header_value(limit));
}
/// The reply to an upload creation or append. Completing it answers as the
/// blob resource does; otherwise it reports the upload's state. A refusal
/// carries the upload's current state too, with `Upload-Complete: ?1` only
/// when it came from processing the completed upload (a digest mismatch).
async fn upload_reply(s: &Shared, digest: &str, status: StatusCode, result: Refusal<crate::store::Progress>) -> Response {
    let (mut response, progress) = match result {
        Ok(progress) if progress.complete => {
            let written = Written { sha256: digest.to_owned(), size: progress.offset };
            ((StatusCode::CREATED, [(header::LOCATION, header_value(format!("/blobs/{digest}")))], Json(written)).into_response(), progress)
        }
        Ok(progress) => ((status, [(header::LOCATION, header_value(format!("/uploads/{digest}")))]).into_response(), progress),
        Err(error) => {
            let processed = error.kind == ErrorKind::DigestMismatch;
            let state = s.store.state(digest).await.ok().flatten().unwrap_or_default();
            (error.into_response(), crate::store::Progress { complete: processed, ..state })
        }
    };
    upload_headers(&mut response, &progress);
    response
}
/// Offset retrieval (draft section 4.3).
async fn upload_offset(State(s): State<Arc<Shared>>, Path(digest): Path<String>) -> Refusal<Response> {
    let missing = || AgentError::new("upload.stat", &digest, ErrorKind::NotFound, "no upload of this digest");
    let progress = s.store.offset(&digest).await?.ok_or_else(missing)?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    upload_headers(&mut response, &progress);
    response.headers_mut().insert(header::CACHE_CONTROL, header_value("no-store"));
    Ok(response)
}
/// Upload creation (draft section 4.2), targeting the blob the bytes become.
/// Without `Upload-Complete` it is a conventional upload of the whole blob.
async fn create_upload(State(s): State<Arc<Shared>>, Path(digest): Path<String>, headers: HeaderMap, body: Body) -> Refusal<Response> {
    const OP: &str = "upload.create";
    crate::files::require_octet_stream(OP, std::path::Path::new(&digest), &headers, &["application/octet-stream"])?;
    let complete = sf_boolean(&headers, "upload-complete").unwrap_or(true);
    let append =
        crate::store::Append { digest: digest.clone(), create: true, offset: 0, complete, length: sf_integer(&headers, "upload-length") };
    let result = s.store.append(append, body).await;
    Ok(upload_reply(&s, &digest, StatusCode::CREATED, result).await)
}
/// Upload append (draft section 4.4).
async fn append_upload(State(s): State<Arc<Shared>>, Path(digest): Path<String>, headers: HeaderMap, body: Body) -> Refusal<Response> {
    const OP: &str = "upload.append";
    crate::files::require_octet_stream(OP, std::path::Path::new(&digest), &headers, &["application/partial-upload"])?;
    let required = |name| AgentError::new(OP, &digest, ErrorKind::InvalidInput, format!("{name} is required"));
    let offset = sf_integer(&headers, "upload-offset").ok_or_else(|| required("Upload-Offset"))?;
    let complete = sf_boolean(&headers, "upload-complete").ok_or_else(|| required("Upload-Complete"))?;
    let append =
        crate::store::Append { digest: digest.clone(), create: false, offset, complete, length: sf_integer(&headers, "upload-length") };
    let result = s.store.append(append, body).await;
    Ok(upload_reply(&s, &digest, StatusCode::NO_CONTENT, result).await)
}
/// Upload cancellation (draft section 4.5).
async fn remove_upload(State(s): State<Arc<Shared>>, Path(digest): Path<String>) -> Refusal<StatusCode> {
    s.store.cancel(&digest).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn blob_size(State(s): State<Arc<Shared>>, Path(digest): Path<String>) -> Refusal<Response> {
    let size =
        s.store.blob_size(&digest).await?.ok_or_else(|| AgentError::new("blob.stat", &digest, ErrorKind::NotFound, "no such blob"))?;
    let mut response = (StatusCode::OK, sha256_header(&digest)).into_response();
    response.headers_mut().insert(header::CONTENT_LENGTH, header_value(size));
    Ok(response)
}
async fn remove_blob(State(s): State<Arc<Shared>>, Path(digest): Path<String>) -> Refusal<StatusCode> {
    s.store.remove_blob(&digest).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn activate_upgrade(State(s): State<Arc<Shared>>, Query(query): Query<DigestQuery>) -> Refusal<StatusCode> {
    let _guard = s.upgrade.lock().await;
    let path = crate::upgrade::activate(&s.executable, &s.store, &query.sha256).await?;
    let tx = s.restart.clone();
    tokio::spawn(async move {
        // Activation acknowledgement is advisory: clients reconnect and verify hello.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let _ = tx.send(path).await;
    });
    Ok(StatusCode::ACCEPTED)
}
async fn confirm_upgrade(State(s): State<Arc<Shared>>) -> Refusal<StatusCode> {
    let _guard = s.upgrade.lock().await;
    crate::upgrade::confirm(&s.executable).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    async fn agent(dir: &std::path::Path) -> (drydock_transport::MemoryDialer, Agent) {
        let (dialer, listener) = drydock_transport::memory();
        (dialer, Agent::new(listener, "build".into(), dir.join("agent")))
    }
    fn forward(id: &str, unix: PathBuf) -> OutwardForward {
        OutwardForward { id: id.into(), unix, tcp: None }
    }
    // A finished listener is rebuilt even when the desired forward is identical.
    // Aborting the task stands in for a fatal listener boundary failure.
    #[tokio::test]
    async fn identical_forward_recovers_finished_listener() {
        let dir = tempfile::tempdir().unwrap();
        let (_host, agent) = agent(dir.path()).await;
        let f = forward("recover", dir.path().join("socket"));
        put_outward(State(agent.shared.clone()), Path(f.id.clone()), Json(f.clone())).await.unwrap();
        {
            let mut settings = agent.shared.settings.lock().await;
            let listener = settings.outward.get_mut("recover").unwrap();
            listener.task.abort();
            while !listener.task.is_finished() {
                tokio::task::yield_now().await;
            }
        }
        put_outward(State(agent.shared.clone()), Path(f.id.clone()), Json(f.clone())).await.unwrap();
        let _stream = tokio::net::UnixStream::connect(f.unix).await.unwrap();
        let announced = || {
            agent
                .shared
                .events
                .after(None)
                .0
                .iter()
                .any(|record| matches!(&record.event, crate::events::Event::OutwardConnection { forward, .. } if forward == "recover"))
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !announced() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
    // Real filesystem boundary: if backup linking fails, activation must retain
    // both the uploaded image and previous rollback, and activation alone retries.
    #[tokio::test]
    async fn partial_activation_failure_retains_upload_and_previous() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let (_host, agent) = agent(dir.path()).await;
        let executable = dir.path().join("agent");
        let previous = executable.with_extension("prev");
        std::fs::write(&previous, b"previous rollback").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"new image"));
        let blob = agent.shared.store.blob(&digest).unwrap();
        std::fs::write(&blob, b"new image").unwrap();
        let query = || Query(DigestQuery { sha256: digest.clone() });
        let refused = activate_upgrade(State(agent.shared.clone()), query()).await.unwrap_err();
        assert_eq!(refused.operation, "upgrade.activate");
        assert_eq!(refused.kind, ErrorKind::NotFound);
        assert!(refused.subject.ends_with("agent"), "{refused}");
        let upgrade = executable.with_extension("upgrade");
        assert_eq!(std::fs::read(&blob).unwrap(), b"new image", "the upload must survive failed linking");
        assert_eq!(std::fs::read(&previous).unwrap(), b"previous rollback");
        std::fs::write(&executable, b"current image").unwrap();
        activate_upgrade(State(agent.shared.clone()), query()).await.unwrap();
        assert_eq!(std::fs::read(&executable).unwrap(), b"current image");
        assert_eq!(std::fs::read(&upgrade).unwrap(), b"new image");
        assert_eq!(std::fs::read(previous).unwrap(), b"current image");
    }

    // Redirects never outlive the configuration that installed them: an agent
    // starts with empty configuration, so it first removes any capture table a
    // crashed predecessor left behind. The nft stand-in records transactions.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn startup_removes_redirects_left_by_a_previous_agent() {
        let dir = tempfile::tempdir().unwrap();
        let (_host, mut agent) = agent(dir.path()).await;
        let nft = dir.path().join("nft");
        std::fs::write(&nft, "#!/bin/sh\ncat >> \"$0.log\"\n").unwrap();
        std::fs::set_permissions(&nft, std::fs::Permissions::from_mode(0o755)).unwrap();
        Arc::get_mut(&mut agent.shared).unwrap().egress_system = crate::egress::System { nft: nft.clone(), ca: dir.path().join("ca.pem") };
        let running = tokio::spawn(agent.run());
        let log = nft.with_extension("log");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !std::fs::read_to_string(&log).is_ok_and(|log| log.contains("delete table inet drydock_egress")) {
            assert!(std::time::Instant::now() < deadline, "startup must remove the capture table");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        running.abort();
    }
    // Activation rehashes the upload as it copies it out of the store, so
    // bytes changed on disk since the upload are refused (422) and discarded
    // rather than executed.
    #[tokio::test]
    async fn activation_refuses_an_upload_corrupted_on_disk() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let (_host, agent) = agent(dir.path()).await;
        let executable = dir.path().join("agent");
        std::fs::write(&executable, b"current image").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"new image"));
        std::fs::write(agent.shared.store.blob(&digest).unwrap(), b"bad image").unwrap();
        let refused = activate_upgrade(State(agent.shared.clone()), Query(DigestQuery { sha256: digest.clone() })).await.unwrap_err();
        assert_eq!((refused.operation.as_str(), refused.kind, refused.status), ("upgrade.activate", ErrorKind::DigestMismatch, 422));
        assert!(refused.message.contains(&digest), "{refused}");
        assert_eq!(agent.shared.store.blob_size(&digest).await.unwrap(), None, "the corrupted upload is discarded");
        assert!(!executable.with_extension("upgrade").exists());
        assert!(!executable.with_extension("probation").exists());
        assert_eq!(std::fs::read(&executable).unwrap(), b"current image");
    }

    // A process-boundary nft stand-in records the last committed transaction.
    // Fail once after real capture preparation and once after nft installation;
    // both refusals must free every port and preserve configuration/nft state.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn egress_configuration_failures_release_ports_and_restore_nft() {
        for fail_persist in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let (_host, mut agent) = agent(dir.path()).await;
            let nft = dir.path().join("nft");
            std::fs::write(
                &nft,
                r#"#!/bin/sh
set -eu
cat > "$0.state"
cat "$0.state" >> "$0.log"
printf '\n--transaction--\n' >> "$0.log"
"#,
            )
            .unwrap();
            std::fs::set_permissions(&nft, std::fs::Permissions::from_mode(0o755)).unwrap();
            let initial_rules = "add table inet drydock_egress\nflush table inet drydock_egress\n";
            let state_path = dir.path().join("nft.state");
            let log_path = dir.path().join("nft.log");
            std::fs::write(&state_path, initial_rules).unwrap();
            std::fs::write(&log_path, "").unwrap();
            let ca = dir.path().join("ca.pem");
            if fail_persist {
                std::fs::create_dir(&ca).unwrap();
            }
            Arc::get_mut(&mut agent.shared).unwrap().egress_system = crate::egress::System { nft, ca };
            if !fail_persist {
                // Refused before any listener is prepared: a forward holds a capture port.
                let f = OutwardForward { id: "dns".into(), unix: dir.path().join("forward"), tcp: Some("127.0.0.1:1053".parse().unwrap()) };
                put_outward(State(agent.shared.clone()), Path(f.id.clone()), Json(f)).await.unwrap();
            }
            let previous = Configuration { environment: [("OLD".into(), "kept".into())].into(), ..Configuration::default() };
            configure(State(agent.shared.clone()), HeaderMap::new(), Json(previous.clone())).await.unwrap();
            let rejected = Configuration {
                egress: Some(crate::Egress { upstream: "proxy".into() }),
                ca: "new bundle".into(),
                ..Configuration::default()
            };
            let error = configure(State(agent.shared.clone()), HeaderMap::new(), Json(rejected)).await.unwrap_err();
            if fail_persist {
                assert_eq!(error.operation, "egress.ca");
            } else {
                assert_eq!((error.kind, error.status), (ErrorKind::Conflict, 409));
                assert!(error.message.contains("dns"), "{error}");
                remove_outward(State(agent.shared.clone()), Path("dns".into())).await.unwrap();
            }
            let settings = agent.shared.settings.lock().await;
            assert_eq!(settings.config, previous);
            assert!(settings.capture.is_none());
            assert!(settings.outward.is_empty());
            assert_eq!(std::fs::read_to_string(&state_path).unwrap(), initial_rules);
            let log = std::fs::read_to_string(&log_path).unwrap();
            if fail_persist {
                assert_eq!(log.matches("--transaction--").count(), 2);
                assert!(log.contains("meta l4proto tcp redirect"));
                assert!(log.ends_with(&format!("{initial_rules}\n--transaction--\n")));
            } else {
                assert!(log.is_empty(), "preparation refusal must not touch nft");
            }
            // The agent has released every port before replying, so a caller
            // can retry at once. SO_REUSEADDR, as the agent binds, still
            // refuses a live listener. Another test forking at this moment
            // can hold a copy of a descriptor until its exec, so a bind
            // refused by that window alone is retried briefly.
            let listen = |address: &str| {
                let address: std::net::SocketAddr = address.parse().unwrap();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                loop {
                    let socket = socket2::Socket::new(socket2::Domain::for_address(address), socket2::Type::STREAM, None).unwrap();
                    socket.set_reuse_address(true).unwrap();
                    match socket.bind(&address.into()) {
                        Ok(()) => break socket,
                        Err(error) if std::time::Instant::now() < deadline && error.kind() == io::ErrorKind::AddrInUse => {
                            std::thread::sleep(std::time::Duration::from_millis(10))
                        }
                        Err(error) => panic!("{address} is still held (fail_persist {fail_persist}): {error}"),
                    }
                }
            };
            let _dns = listen("[::]:1053");
            let _capture = listen("[::]:15001");
            let _proxy = listen("127.0.0.1:15002");
            let _udp = std::net::UdpSocket::bind("[::]:1053").unwrap();
        }
    }
}

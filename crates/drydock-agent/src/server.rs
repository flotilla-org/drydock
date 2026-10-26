use crate::{
    rest::{header_value, sf_boolean, sf_integer, structured},
    *,
};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, head, post, put},
};
use drydock_transport::{Opener, Purpose, Transport, http2};
use std::{collections::BTreeMap, sync::Arc};
use tokio::{
    net::{TcpListener, UnixListener},
    sync::{Mutex, mpsc},
    task::JoinSet,
};
use tokio_stream::{StreamExt, wrappers::ReceiverStream};

type Refusal<T> = Result<T, AgentError>;

struct Target {
    endpoint: Endpoint,
    streams: JoinSet<()>,
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
/// Live guest-to-host streams of one forward ID. They outlive a rebind of
/// the forward's listeners and end when the forward is removed.
type Bridges = Arc<std::sync::Mutex<JoinSet<()>>>;
struct Listener {
    forward: GuestForward,
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
struct Settings {
    config: Configuration,
    listeners: BTreeMap<String, Listener>,
    targets: BTreeMap<String, Target>,
    capture: Option<crate::egress::Capture>,
}
impl Settings {
    /// Loopback listeners exempt from capture, optionally with one forward's
    /// listener replaced or removed.
    fn exemptions(&self, id: &str, replacement: Option<&GuestForward>) -> Vec<std::net::SocketAddr> {
        self.listeners
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
    opener: Arc<Mutex<Opener>>,
    settings: Mutex<Settings>,
    executable: PathBuf,
    staged: Mutex<Option<PathBuf>>,
    restart: mpsc::Sender<PathBuf>,
    pub(crate) store: crate::store::Store,
}
/// Owns one host-facing transport. Never expose this router on guest TCP.
pub struct Agent {
    transports: Vec<Transport>,
    shared: Arc<Shared>,
    restart: mpsc::Receiver<PathBuf>,
}
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
    pub fn new(transport: Transport, fingerprint: String, executable: PathBuf) -> Self {
        let (tx, restart) = mpsc::channel(1);
        let shared = Arc::new(Shared {
            hello: Hello {
                fingerprint,
                features: FEATURES.iter().map(|s| (*s).into()).collect(),
                platform: Some(Platform::current()),
                boot_id: boot_id(),
            },
            egress_system: crate::egress::System::default(),
            opener: Arc::new(Mutex::new(transport.opener.clone())),
            settings: Mutex::new(Settings::default()),
            store: crate::store::Store::new(crate::upgrade::sidecar(&executable, "store")),
            executable,
            staged: Mutex::new(None),
            restart: tx,
        });
        Self { transports: vec![transport], shared, restart }
    }
    /// Add another host-facing native link (e.g. vsock). All links share state.
    pub fn add_transport(&mut self, transport: Transport) {
        self.transports.push(transport);
    }
    fn router(&self) -> Router {
        use crate::files::*;
        Router::new()
            .route("/hello", get(hello))
            // Executables arrive whole, so they keep a larger cap.
            .route("/upgrade", put(stage_upgrade).post(activate_upgrade).layer(DefaultBodyLimit::max(128 * 1024 * 1024)))
            .route("/configuration", get(configuration).put(configure))
            .route("/exec", post(exec))
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
            .route("/forwards/guest", get(guest_forwards))
            .route("/forwards/guest/{id}", get(guest_forward).put(put_guest).delete(remove_guest))
            .route("/forwards/host", get(host_forwards))
            .route("/forwards/host/{id}", get(host_forward).put(put_target).delete(remove_target))
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
        let router = self.router();
        let mut controller_bound = false;
        let mut tasks = JoinSet::new();
        let (incoming_tx, mut incoming_rx) = mpsc::channel(64);
        for mut transport in self.transports.drain(..) {
            let tx = incoming_tx.clone();
            tasks.spawn(async move {
                let mut backoff = std::time::Duration::from_millis(100);
                loop {
                    let incoming = match transport.accept().await {
                        Ok(Some(incoming)) => incoming,
                        Ok(None) => break,
                        Err(error) => {
                            tracing::warn!(%error, "agent transport accept failed");
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(std::time::Duration::from_secs(1));
                            continue;
                        }
                    };
                    backoff = std::time::Duration::from_millis(100);
                    if tx.send((incoming, transport.opener.clone())).await.is_err() {
                        break;
                    }
                }
            });
        }
        drop(incoming_tx);
        loop {
            tokio::select! {
                path = self.restart.recv() => {
                    tasks.shutdown().await;
                    // Remove owned guest socket paths before exec discards the
                    // runtime. Aborting tasks alone does not synchronously drop them.
                    let mut settings = self.shared.settings.lock().await;
                    for (_, listener) in std::mem::take(&mut settings.listeners) { listener.stop().await; }
                    // The configuration dies with this process; so do its redirects.
                    if let Err(error) = self.shared.egress_system.clear().await {
                        tracing::warn!(%error, "could not clear guest egress redirects before re-exec");
                    }
                    return path.ok_or_else(|| io::Error::other("upgrade channel closed"));
                },
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                incoming = incoming_rx.recv() => {
                    let Some((incoming, opener)) = incoming else { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "host transport closed")); };
                    match incoming.purpose {
                        Purpose::Control => {
                            if !controller_bound {
                                *self.shared.opener.lock().await = opener;
                                controller_bound = true;
                            }
                            let router = router.clone();
                            tasks.spawn(async move { let _ = http2::serve(incoming, router).await; });
                        }
                        Purpose::Forward { id } => {
                            let mut settings = self.shared.settings.lock().await;
                            // Choose the dial policy from the configuration at
                            // forward acceptance, under configure's lock. Marks
                            // belong to sockets; toggles do not rewrite existing
                            // streams or retroactively change this choice.
                            let marked = settings.config.egress.is_some();
                            if let Some(target) = settings.targets.get_mut(&id) {
                                // Reap completed bridges without retaining an unbounded history.
                                while target.streams.try_join_next().is_some() {}
                                let endpoint = target.endpoint.clone();
                                target.streams.spawn(async move {
                                    if let Err(error) = crate::forward::serve_marked(incoming.stream, &id, Some(&endpoint), marked).await {
                                        tracing::warn!(%error, forward = %id, "host-to-guest forward failed");
                                    }
                                });
                            } else {
                                tasks.spawn(async move { let _ = crate::forward::serve(incoming.stream, &id, None).await; });
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn hello(State(s): State<Arc<Shared>>) -> Refusal<Json<Hello>> {
    let _guard = s.staged.lock().await;
    crate::upgrade::confirm(&s.executable).await.map_err(|e| AgentError::io("upgrade.confirm", s.executable.display(), e))?;
    Ok(Json(s.hello.clone()))
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
            settings.listeners.values().find(|l| l.forward.tcp.is_some_and(|a| crate::egress::RESERVED_PORTS.contains(&a.port())))
        {
            return Err(AgentError::new(
                OP,
                "egress",
                ErrorKind::Conflict,
                format!("guest forward {} listens on a port egress capture needs", conflict.forward.id),
            ));
        }
    }
    let mut prepared_capture = match (&settings.capture, &config.egress) {
        (None, Some(egress)) => Some(
            crate::egress::Capture::prepare(s.opener.clone(), egress.upstream.clone())
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

async fn listen(forward: &GuestForward, opener: Arc<Mutex<Opener>>, old: Option<&Listener>) -> io::Result<Listener> {
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
                    tracing::warn!(%error, forward = %id, "guest listener stopped");
                    break;
                }
            };
            let opener = opener.lock().await.clone();
            let id = id.clone();
            let mut streams = streams.lock().unwrap();
            // Reap finished bridges without retaining an unbounded history.
            while streams.try_join_next().is_some() {}
            streams.spawn(async move {
                match opener.open(Purpose::Forward { id: id.clone() }).await {
                    Ok(mut remote) => {
                        if let Err(error) = crate::forward::opened(&mut remote).await {
                            tracing::warn!(%error, forward = %id, "guest-to-host forward rejected");
                            return;
                        }
                        if let Err(error) = tokio::io::copy_bidirectional(&mut stream, &mut remote).await {
                            tracing::warn!(%error, forward = %id, "guest-to-host stream failed");
                        }
                    }
                    Err(error) => tracing::warn!(%error, forward = %id, "guest-to-host forward open failed"),
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
async fn guest_forwards(State(s): State<Arc<Shared>>) -> Json<Vec<GuestForward>> {
    Json(s.settings.lock().await.listeners.values().map(|l| l.forward.clone()).collect())
}
async fn guest_forward(State(s): State<Arc<Shared>>, Path(id): Path<String>) -> Refusal<Json<GuestForward>> {
    let settings = s.settings.lock().await;
    let listener = settings
        .listeners
        .get(&id)
        .ok_or_else(|| AgentError::new("forward.guest.read", &id, ErrorKind::NotFound, "no guest forward with this ID"))?;
    Ok(Json(listener.forward.clone()))
}
/// Idempotent upsert. An unchanged forward with a live listener is left
/// alone, streams and all; a changed one is rebound before the old one stops.
async fn put_guest(State(s): State<Arc<Shared>>, Path(id): Path<String>, Json(forward): Json<GuestForward>) -> Refusal<StatusCode> {
    const OP: &str = "forward.guest.put";
    check_path_id(OP, &id, &forward.id)?;
    let mut settings = s.settings.lock().await;
    let old = settings.listeners.get(&id);
    if old.is_some_and(|old| old.forward == forward && !old.task.is_finished()) {
        return Ok(StatusCode::OK);
    }
    let capture = settings.capture.is_some();
    if capture && forward.tcp.is_some_and(|a| crate::egress::RESERVED_PORTS.contains(&a.port())) {
        return Err(AgentError::new(OP, &id, ErrorKind::Conflict, "forward conflicts with an egress listener"));
    }
    let existed = old.is_some();
    let tcp_changed = old.map(|old| old.forward.tcp) != Some(forward.tcp);
    let listener =
        listen(&forward, s.opener.clone(), old).await.map_err(|e| AgentError::io("forward.listen", forward.unix.display(), e))?;
    if capture && tcp_changed {
        let exempt = settings.exemptions(&id, Some(&forward));
        if let Err(error) = s.egress_system.install(true, &exempt).await {
            listener.stop().await;
            return Err(AgentError::io("egress.redirect", "nftables", error));
        }
    }
    if let Some(old) = settings.listeners.insert(id, listener) {
        old.stop().await;
    }
    Ok(if existed { StatusCode::OK } else { StatusCode::CREATED })
}
async fn remove_guest(State(s): State<Arc<Shared>>, Path(id): Path<String>) -> Refusal<StatusCode> {
    let mut settings = s.settings.lock().await;
    let Some(listener) = settings.listeners.remove(&id) else {
        return Err(AgentError::new("forward.guest.remove", &id, ErrorKind::NotFound, "no guest forward with this ID"));
    };
    if settings.capture.is_some() && listener.forward.tcp.is_some() {
        let exempt = settings.exemptions(&id, None);
        if let Err(error) = s.egress_system.install(true, &exempt).await {
            settings.listeners.insert(id, listener);
            return Err(AgentError::io("egress.redirect", "nftables", error));
        }
    }
    listener.stop().await;
    Ok(StatusCode::NO_CONTENT)
}
async fn host_forwards(State(s): State<Arc<Shared>>) -> Json<Vec<HostForward>> {
    let settings = s.settings.lock().await;
    Json(settings.targets.iter().map(|(id, t)| HostForward { id: id.clone(), endpoint: t.endpoint.clone() }).collect())
}
async fn host_forward(State(s): State<Arc<Shared>>, Path(id): Path<String>) -> Refusal<Json<HostForward>> {
    let settings = s.settings.lock().await;
    let target = settings
        .targets
        .get(&id)
        .ok_or_else(|| AgentError::new("forward.host.read", &id, ErrorKind::NotFound, "no host forward with this ID"))?;
    Ok(Json(HostForward { id, endpoint: target.endpoint.clone() }))
}
/// A changed endpoint ends the streams to the old one, unlike a guest
/// listener's rebind: they would otherwise keep reaching a target the host
/// no longer names.
async fn put_target(State(s): State<Arc<Shared>>, Path(id): Path<String>, Json(forward): Json<HostForward>) -> Refusal<StatusCode> {
    const OP: &str = "forward.host.put";
    check_path_id(OP, &id, &forward.id)?;
    if matches!(&forward.endpoint, Endpoint::Tcp(address) if address.port() == 0) {
        return Err(AgentError::new(OP, &id, ErrorKind::InvalidInput, "guest target TCP port must be nonzero"));
    }
    let mut settings = s.settings.lock().await;
    if settings.targets.get(&id).is_some_and(|t| t.endpoint == forward.endpoint) {
        return Ok(StatusCode::OK);
    }
    let old = settings.targets.insert(id, Target { endpoint: forward.endpoint, streams: JoinSet::new() });
    let existed = old.is_some();
    if let Some(old) = old {
        old.stop().await;
    }
    Ok(if existed { StatusCode::OK } else { StatusCode::CREATED })
}
async fn remove_target(State(s): State<Arc<Shared>>, Path(id): Path<String>) -> Refusal<StatusCode> {
    let target = s
        .settings
        .lock()
        .await
        .targets
        .remove(&id)
        .ok_or_else(|| AgentError::new("forward.host.remove", &id, ErrorKind::NotFound, "no host forward with this ID"))?;
    target.stop().await;
    Ok(StatusCode::NO_CONTENT)
}

async fn exec(State(s): State<Arc<Shared>>, Json(request): Json<Exec>) -> Refusal<Body> {
    let environment = s.settings.lock().await.config.environment.clone();
    let program = request.program.clone();
    let rx = crate::exec::launch(request, environment).map_err(|e| AgentError::io("exec.launch", &program, e))?;
    let stream = ReceiverStream::new(rx).map(|event| {
        let mut bytes = serde_json::to_vec(&event).expect("exec event serialization");
        bytes.push(b'\n');
        Ok::<_, io::Error>(bytes)
    });
    Ok(Body::from_stream(stream))
}
async fn stage_upgrade(State(s): State<Arc<Shared>>, bytes: Bytes) -> Refusal<StatusCode> {
    let path = crate::upgrade::sidecar(&s.executable, "upgrade");
    if bytes.is_empty() {
        return Err(AgentError::new("upgrade.stage", path.display(), ErrorKind::InvalidInput, "empty agent executable"));
    }
    let mut staged = s.staged.lock().await;
    let options = FileOptions { mode: Some(0o755), ..FileOptions::default() };
    crate::files::write("upgrade.stage", &path, crate::files::Source::Body(Body::from(bytes)), &options).await?;
    *staged = Some(path);
    Ok(StatusCode::NO_CONTENT)
}
async fn activate_upgrade(State(s): State<Arc<Shared>>) -> Refusal<StatusCode> {
    let mut staged = s.staged.lock().await;
    let at = |operation: &'static str, subject: &std::path::Path| {
        let subject = subject.display().to_string();
        move |e| AgentError::io(operation, subject, e)
    };
    let path = staged
        .as_ref()
        .cloned()
        .ok_or_else(|| AgentError::new("upgrade.activate", s.executable.display(), ErrorKind::Conflict, "no staged agent"))?;
    // Keep the installed path stable over successive upgrades.
    let previous = crate::upgrade::sidecar(&s.executable, "prev");
    let parent = s.executable.parent().unwrap_or(std::path::Path::new("."));
    let backup_dir = tempfile::tempdir_in(parent).map_err(at("upgrade.backup", parent))?;
    let backup = backup_dir.path().join("previous");
    tokio::fs::hard_link(&s.executable, &backup).await.map_err(at("upgrade.backup", &s.executable))?;
    tokio::fs::rename(&backup, &previous).await.map_err(at("upgrade.backup", &previous))?;
    crate::upgrade::prepare(&s.executable, &path).await.map_err(at("upgrade.prepare", &s.executable))?;
    *staged = None;
    crate::durable::sync_directory(parent).map_err(at("upgrade.flush", parent))?;
    let tx = s.restart.clone();
    tokio::spawn(async move {
        // Activation acknowledgement is advisory: clients reconnect and verify hello.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let _ = tx.send(path).await;
    });
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    async fn agent(dir: &std::path::Path) -> (Transport, Agent) {
        let (a, b) = tokio::io::duplex(4096);
        let (host, guest) = tokio::join!(
            Transport::yamux(Box::new(a), true, drydock_transport::Limits::default()),
            Transport::yamux(Box::new(b), false, drydock_transport::Limits::default())
        );
        (host.unwrap(), Agent::new(guest.unwrap(), "build".into(), dir.join("agent")))
    }
    fn forward(id: &str, unix: PathBuf) -> GuestForward {
        GuestForward { id: id.into(), unix, tcp: None }
    }
    // A finished listener is rebuilt even when the desired forward is identical.
    // Aborting the task stands in for a fatal listener boundary failure.
    #[tokio::test]
    async fn identical_forward_recovers_finished_listener() {
        let dir = tempfile::tempdir().unwrap();
        let (mut host, agent) = agent(dir.path()).await;
        let f = forward("recover", dir.path().join("socket"));
        put_guest(State(agent.shared.clone()), Path(f.id.clone()), Json(f.clone())).await.unwrap();
        {
            let mut settings = agent.shared.settings.lock().await;
            let listener = settings.listeners.get_mut("recover").unwrap();
            listener.task.abort();
            while !listener.task.is_finished() {
                tokio::task::yield_now().await;
            }
        }
        put_guest(State(agent.shared.clone()), Path(f.id.clone()), Json(f.clone())).await.unwrap();
        let _stream = tokio::net::UnixStream::connect(f.unix).await.unwrap();
        let incoming = tokio::time::timeout(std::time::Duration::from_secs(2), host.accept()).await.unwrap().unwrap().unwrap();
        assert_eq!(incoming.purpose, Purpose::Forward { id: "recover".into() });
    }
    // Real filesystem boundary: if backup linking fails, activation must retain
    // both the staged image and previous rollback, and POST alone must retry.
    #[tokio::test]
    async fn partial_activation_failure_retains_stage_and_previous() {
        let dir = tempfile::tempdir().unwrap();
        let (_host, agent) = agent(dir.path()).await;
        let executable = dir.path().join("agent");
        let previous = executable.with_extension("prev");
        std::fs::write(&previous, b"previous rollback").unwrap();
        stage_upgrade(State(agent.shared.clone()), Bytes::from_static(b"new image")).await.unwrap();
        assert!(activate_upgrade(State(agent.shared.clone())).await.is_err());
        let staged = agent.shared.staged.lock().await.clone().expect("stage must survive failed linking");
        assert_eq!(std::fs::read(&staged).unwrap(), b"new image");
        assert_eq!(std::fs::read(&previous).unwrap(), b"previous rollback");
        std::fs::write(&executable, b"current image").unwrap();
        activate_upgrade(State(agent.shared.clone())).await.unwrap();
        assert!(agent.shared.staged.lock().await.is_none());
        assert_eq!(std::fs::read(&executable).unwrap(), b"current image");
        assert_eq!(std::fs::read(&staged).unwrap(), b"new image");
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
                let f = GuestForward { id: "dns".into(), unix: dir.path().join("forward"), tcp: Some("127.0.0.1:1053".parse().unwrap()) };
                put_guest(State(agent.shared.clone()), Path(f.id.clone()), Json(f)).await.unwrap();
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
                remove_guest(State(agent.shared.clone()), Path("dns".into())).await.unwrap();
            }
            let settings = agent.shared.settings.lock().await;
            assert_eq!(settings.config, previous);
            assert!(settings.capture.is_none());
            assert!(settings.listeners.is_empty());
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

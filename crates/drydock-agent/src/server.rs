use crate::*;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post, put},
};
use drydock_transport::{Opener, Purpose, Transport, http2};
use std::{collections::HashMap, os::unix::fs::PermissionsExt, path::Path, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, UnixListener},
    sync::{Mutex, mpsc},
    task::JoinSet,
};
use tokio_stream::{StreamExt, wrappers::ReceiverStream};

type ApiError = (StatusCode, Json<AgentError>);
enum Failure {
    Message(String),
    Io(io::Error),
}
impl From<&str> for Failure {
    fn from(s: &str) -> Self {
        Self::Message(s.into())
    }
}
impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
fn api(error: impl Into<Failure>) -> ApiError {
    let error = match error.into() {
        Failure::Message(message) => AgentError::new("control", "request", invalid(message)),
        Failure::Io(error) => error
            .get_ref()
            .and_then(|e| e.downcast_ref::<AgentError>())
            .cloned()
            .unwrap_or_else(|| AgentError::new("control", "request", error)),
    };
    let status = match io::ErrorKind::from(error.kind) {
        io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
        io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => StatusCode::BAD_REQUEST,
        io::ErrorKind::AlreadyExists | io::ErrorKind::AddrInUse => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(error))
}
fn at(operation: &'static str, subject: impl std::fmt::Display) -> impl FnOnce(io::Error) -> ApiError {
    let subject = subject.to_string();
    move |error| api(crate::error::context(operation, subject, error))
}
fn absolute(operation: &'static str, path: &Path) -> Result<(), ApiError> {
    if !path.is_absolute() {
        return Err(at(operation, path.display())(invalid("file path must be absolute")));
    }
    Ok(())
}
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
struct Listener {
    task: tokio::task::JoinHandle<()>,
    unix: Arc<GuestSocket>,
    tcp: Option<(std::net::SocketAddr, Arc<TcpListener>)>,
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
    listeners: HashMap<String, Listener>,
    targets: HashMap<String, Target>,
    capture: Option<crate::egress::Capture>,
}
struct Shared {
    hello: Hello,
    egress_system: crate::egress::System,
    opener: Arc<Mutex<Opener>>,
    settings: Mutex<Settings>,
    executable: PathBuf,
    staged: Mutex<Option<PathBuf>>,
    restart: mpsc::Sender<PathBuf>,
}
/// Owns one host-facing transport. Never expose this router on guest TCP.
pub struct Agent {
    transports: Vec<Transport>,
    shared: Arc<Shared>,
    restart: mpsc::Receiver<PathBuf>,
}
impl Agent {
    pub fn new(transport: Transport, fingerprint: String, executable: PathBuf) -> Self {
        let (tx, restart) = mpsc::channel(1);
        let shared = Arc::new(Shared {
            hello: Hello { fingerprint, features: FEATURES.iter().map(|s| (*s).into()).collect() },
            egress_system: crate::egress::System::default(),
            opener: Arc::new(Mutex::new(transport.opener.clone())),
            settings: Mutex::new(Settings::default()),
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
    /// Returns the probation candidate on upgrade. The composition root re-execs
    /// with its original fixed flags; dropping this future drops all agent streams.
    pub async fn run(mut self) -> io::Result<PathBuf> {
        let router = Router::new()
            .route("/hello", get(hello))
            .route("/upgrade", put(stage_upgrade).post(activate_upgrade))
            .route("/configure", put(configure).get(configuration))
            .route("/exec", post(exec))
            .route("/files/write", post(write_file))
            .route("/files/read", post(read_file))
            .route("/files/flush", post(flush_file))
            .route("/forwards/guest", put(add_guest).delete(remove_guest))
            .route("/forwards/host", put(add_target).delete(remove_target))
            .layer(DefaultBodyLimit::max(128 * 1024 * 1024))
            .with_state(self.shared.clone());
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
                    let listeners = std::mem::take(&mut self.shared.settings.lock().await.listeners);
                    for (_, listener) in listeners { listener.stop().await; }
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
async fn hello(State(s): State<Arc<Shared>>) -> Result<Json<Hello>, ApiError> {
    let _guard = s.staged.lock().await;
    crate::upgrade::confirm(&s.executable).await.map_err(at("upgrade.confirm", s.executable.display()))?;
    Ok(Json(s.hello.clone()))
}
async fn configuration(State(s): State<Arc<Shared>>) -> Json<Configuration> {
    Json(s.settings.lock().await.config.clone())
}
async fn configure(State(s): State<Arc<Shared>>, Json(config): Json<Configuration>) -> Result<StatusCode, ApiError> {
    if config.environment.iter().any(|(k, v)| k.is_empty() || k.contains(['=', '\0']) || v.contains('\0')) {
        return Err(api("invalid process environment"));
    }
    if let Some(egress) = &config.egress {
        check_id(&egress.upstream).map_err(api)?;
        if config.forwards.iter().filter_map(|f| f.tcp).any(|a| crate::egress::RESERVED_PORTS.contains(&a.port())) {
            return Err(api("forward conflicts with an egress listener"));
        }
    }
    let mut settings = s.settings.lock().await;
    let mut prepared_capture = if settings.capture.is_none() {
        if let Some(egress) = &config.egress {
            Some(
                crate::egress::Capture::prepare(s.opener.clone(), egress.upstream.clone())
                    .await
                    .map_err(at("egress.prepare", "listeners"))?,
            )
        } else {
            None
        }
    } else {
        None
    };
    let mut prepared = HashMap::new();
    let preparation: Result<(), ApiError> = async {
        for forward in &config.forwards {
            check_id(&forward.id).map_err(api)?;
            if prepared.contains_key(&forward.id) {
                return Err(api("duplicate forward ID"));
            }
            let unchanged = settings.config.forwards.iter().any(|old| old == forward)
                && settings.listeners.get(&forward.id).is_some_and(|listener| !listener.task.is_finished());
            let listener = if unchanged {
                None
            } else {
                Some(
                    listen(forward, s.opener.clone(), settings.listeners.get(&forward.id))
                        .await
                        .map_err(at("forward.listen", forward.unix.display()))?,
                )
            };
            prepared.insert(forward.id.clone(), listener);
        }
        if config.egress.is_some() || settings.capture.is_some() {
            // Stage the CA under the tools prefix before publishing capture.
            // Configuration.ca is the complete combined trust bundle supplied
            // by the controller; the agent does not fetch host trust material.
            let ca = if config.egress.is_some() {
                let file = tempfile::NamedTempFile::new_in(s.egress_system.ca.parent().unwrap())
                    .map_err(at("egress.ca", s.egress_system.ca.display()))?;
                std::fs::write(file.path(), config.ca.as_bytes()).map_err(at("egress.ca", s.egress_system.ca.display()))?;
                file.as_file()
                    .set_permissions(std::fs::Permissions::from_mode(0o644))
                    .map_err(at("egress.ca", s.egress_system.ca.display()))?;
                file.as_file().sync_all().map_err(at("egress.ca", s.egress_system.ca.display()))?;
                Some(file)
            } else {
                None
            };
            s.egress_system.install(&config).await.map_err(at("egress.redirect", "nftables"))?;
            if let Some(ca) = ca
                && let Err(error) = ca.persist(&s.egress_system.ca)
            {
                // persist failed before replacing the old bundle. Reinstall
                // the previous nft transaction before reporting refusal; if
                // rollback itself fails, report that separately to the caller.
                s.egress_system.install(&settings.config).await.map_err(at("egress.rollback", "nftables"))?;
                return Err(at("egress.ca", s.egress_system.ca.display())(error.error));
            }
        }
        Ok(())
    }
    .await;
    if let Err(error) = preparation {
        // A rejected transaction must release staged socket paths before its
        // response, so the caller can retry immediately without a bind race.
        for listener in prepared.into_values().flatten() {
            listener.stop().await;
        }
        if let Some(capture) = prepared_capture.take() {
            capture.stop().await;
        }
        return Err(error);
    }
    let mut listeners = HashMap::new();
    for (id, listener) in prepared {
        if let Some(listener) = listener.or_else(|| settings.listeners.remove(&id)) {
            listeners.insert(id, listener);
        }
    }
    let old = std::mem::replace(&mut settings.listeners, listeners);
    for (_, listener) in old {
        listener.stop().await;
    }
    if let Some(egress) = &config.egress {
        if let Some(capture) = prepared_capture.take() {
            settings.capture = Some(capture);
        }
        settings.capture.as_ref().unwrap().set_upstream(egress.upstream.clone());
    } else if let Some(capture) = settings.capture.take() {
        capture.stop().await;
    }
    settings.config = config;
    Ok(StatusCode::NO_CONTENT)
}
async fn listen(forward: &GuestForward, opener: Arc<Mutex<Opener>>, old: Option<&Listener>) -> io::Result<Listener> {
    if forward.tcp.is_some_and(|addr| !addr.ip().is_loopback()) {
        return Err(invalid("guest TCP listener must be loopback"));
    }
    // Bind before publishing the new listener into the configuration.
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
    let id = forward.id.clone();
    let task = tokio::spawn(async move {
        let mut streams = JoinSet::new();
        loop {
            let accepted: io::Result<ByteStream> = tokio::select! {
                Some(_) = streams.join_next(), if !streams.is_empty() => continue,
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
    Ok(Listener { task, unix: owned_unix, tcp: owned_tcp })
}
async fn add_guest(State(s): State<Arc<Shared>>, Json(forward): Json<GuestForward>) -> Result<StatusCode, ApiError> {
    check_id(&forward.id).map_err(api)?;
    let mut settings = s.settings.lock().await;
    if settings.capture.is_some() && forward.tcp.is_some() {
        return Err(api("use configure to change TCP forwards while egress capture is enabled"));
    }
    if settings.listeners.contains_key(&forward.id) {
        return Err(api("forward ID already exists"));
    }
    let listener = listen(&forward, s.opener.clone(), None).await.map_err(at("forward.listen", forward.unix.display()))?;
    settings.listeners.insert(forward.id.clone(), listener);
    settings.config.forwards.push(forward);
    Ok(StatusCode::NO_CONTENT)
}
async fn remove_guest(State(s): State<Arc<Shared>>, Json(id): Json<String>) -> Result<StatusCode, ApiError> {
    let mut settings = s.settings.lock().await;
    if settings.capture.is_some() && settings.config.forwards.iter().any(|f| f.id == id && f.tcp.is_some()) {
        return Err(api("use configure to change TCP forwards while egress capture is enabled"));
    }
    let listener = settings
        .listeners
        .remove(&id)
        .ok_or_else(|| at("forward.remove", &id)(io::Error::new(io::ErrorKind::NotFound, "unknown guest forward ID")))?;
    listener.stop().await;
    settings.config.forwards.retain(|f| f.id != id);
    Ok(StatusCode::NO_CONTENT)
}
async fn add_target(State(s): State<Arc<Shared>>, Json(target): Json<GuestTarget>) -> Result<StatusCode, ApiError> {
    check_id(&target.id).map_err(api)?;
    if matches!(&target.endpoint, Endpoint::Tcp(address) if address.port() == 0) {
        return Err(api("guest target TCP port must be nonzero"));
    }
    let mut settings = s.settings.lock().await;
    if let Some(old) = settings.targets.remove(&target.id) {
        old.stop().await;
    }
    settings.targets.insert(target.id, Target { endpoint: target.endpoint, streams: JoinSet::new() });
    Ok(StatusCode::NO_CONTENT)
}
async fn remove_target(State(s): State<Arc<Shared>>, Json(id): Json<String>) -> Result<StatusCode, ApiError> {
    let target = s
        .settings
        .lock()
        .await
        .targets
        .remove(&id)
        .ok_or_else(|| at("forward.remove", &id)(io::Error::new(io::ErrorKind::NotFound, "unknown host forward ID")))?;
    target.stop().await;
    Ok(StatusCode::NO_CONTENT)
}
async fn exec(State(s): State<Arc<Shared>>, Json(request): Json<Exec>) -> Result<Body, ApiError> {
    let environment = s.settings.lock().await.config.environment.clone();
    let program = request.program.clone();
    let rx = crate::exec::launch(request, environment).map_err(|error| {
        if error.get_ref().is_some_and(|source| source.is::<AgentError>()) { api(error) } else { at("exec.launch", &program)(error) }
    })?;
    let stream = ReceiverStream::new(rx).map(|event| {
        let mut bytes = serde_json::to_vec(&event).expect("exec event serialization");
        bytes.push(b'\n');
        Ok::<_, io::Error>(bytes)
    });
    Ok(Body::from_stream(stream))
}
/// Write a sibling, fsync it, rename atomically, then fsync the parent directory.
/// Readers always observe either the complete old file or the complete new file.
pub(crate) async fn atomic_write(path: &Path, bytes: &[u8], executable: bool) -> io::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let temporary = tempfile::NamedTempFile::new_in(parent)?;
    let mut file = tokio::fs::File::from_std(temporary.reopen()?);
    file.write_all(bytes).await?;
    file.flush().await?;
    let existing = std::fs::symlink_metadata(path).ok().filter(|m| !m.file_type().is_symlink());
    if let Some(metadata) = &existing {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        // SAFETY: the temporary file owns this open descriptor. Preserve the
        // destination's owner before chmod (chown may clear permission bits).
        let temporary_owner = temporary.as_file().metadata()?;
        if (metadata.uid(), metadata.gid()) != (temporary_owner.uid(), temporary_owner.gid()) {
            let result = if unsafe { libc::fchown(temporary.as_file().as_raw_fd(), metadata.uid(), metadata.gid()) } == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            };
            // SAFETY: geteuid has no arguments or memory effects.
            ownership_result(result, unsafe { libc::geteuid() })?;
        }
    }
    let mode = if executable { 0o755 } else { existing.map_or(0o644, |m| m.permissions().mode()) };
    file.set_permissions(std::fs::Permissions::from_mode(mode)).await?;
    file.sync_all().await?;
    temporary.persist(path).map_err(|error| error.error)?;
    tokio::fs::File::open(parent).await?.sync_all().await
}
// Unprivileged replacement may be allowed by directory permissions even when
// preserving another user's owner is not. Preserve it when permitted; root and
// non-permission failures remain strict.
fn ownership_result(result: io::Result<()>, uid: u32) -> io::Result<()> {
    match result {
        Err(error) if uid != 0 && error.kind() == io::ErrorKind::PermissionDenied => Ok(()),
        other => other,
    }
}
async fn write_file(Json(file): Json<FileWrite>) -> Result<StatusCode, ApiError> {
    absolute("file.write", &file.path)?;
    atomic_write(&file.path, &file.bytes, file.executable).await.map_err(at("file.write", file.path.display()))?;
    Ok(StatusCode::NO_CONTENT)
}
async fn read_file(Json(file): Json<FilePath>) -> Result<Vec<u8>, ApiError> {
    use tokio::io::AsyncReadExt;
    const LIMIT: u64 = 128 * 1024 * 1024;
    absolute("file.read", &file.path)?;
    let input = tokio::fs::File::open(&file.path).await.map_err(at("file.read", file.path.display()))?;
    if input.metadata().await.map_err(at("file.read", file.path.display()))?.len() > LIMIT {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(AgentError::new("file.read", file.path.display(), invalid("read exceeds 128 MiB"))),
        ));
    }
    let mut bytes = Vec::new();
    input.take(LIMIT + 1).read_to_end(&mut bytes).await.map_err(at("file.read", file.path.display()))?;
    if bytes.len() as u64 > LIMIT {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(AgentError::new("file.read", file.path.display(), invalid("read exceeds 128 MiB"))),
        ));
    }
    Ok(bytes)
}
async fn flush_file(Json(file): Json<FilePath>) -> Result<StatusCode, ApiError> {
    absolute("file.flush", &file.path)?;
    tokio::fs::File::open(&file.path)
        .await
        .map_err(at("file.flush", file.path.display()))?
        .sync_all()
        .await
        .map_err(at("file.flush", file.path.display()))?;
    Ok(StatusCode::NO_CONTENT)
}
async fn stage_upgrade(State(s): State<Arc<Shared>>, bytes: Bytes) -> Result<StatusCode, ApiError> {
    if bytes.is_empty() {
        return Err(api("empty agent executable"));
    }
    let mut staged = s.staged.lock().await;
    let path = crate::upgrade::sidecar(&s.executable, "upgrade");
    atomic_write(&path, &bytes, true).await.map_err(at("upgrade.stage", path.display()))?;
    *staged = Some(path);
    Ok(StatusCode::NO_CONTENT)
}
async fn activate_upgrade(State(s): State<Arc<Shared>>) -> Result<StatusCode, ApiError> {
    let mut staged = s.staged.lock().await;
    let path = staged.as_ref().cloned().ok_or_else(|| api("no staged agent"))?;
    // Keep the installed path stable over successive upgrades.
    let previous = crate::upgrade::sidecar(&s.executable, "prev");
    let parent = s.executable.parent().unwrap_or(Path::new("."));
    let backup_dir = tempfile::tempdir_in(parent).map_err(at("upgrade.backup", parent.display()))?;
    let backup = backup_dir.path().join("previous");
    tokio::fs::hard_link(&s.executable, &backup).await.map_err(at("upgrade.backup", s.executable.display()))?;
    tokio::fs::rename(&backup, &previous).await.map_err(at("upgrade.backup", previous.display()))?;
    crate::upgrade::prepare(&s.executable, &path).await.map_err(at("upgrade.prepare", s.executable.display()))?;
    *staged = None;
    if let Some(parent) = s.executable.parent() {
        tokio::fs::File::open(parent)
            .await
            .map_err(at("upgrade.flush", parent.display()))?
            .sync_all()
            .await
            .map_err(at("upgrade.flush", parent.display()))?;
    }
    let tx = s.restart.clone();
    tokio::spawn(async move {
        // Activation acknowledgement is advisory: clients reconnect and verify hello.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let _ = tx.send(path).await;
    });
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    // A finished listener is rebuilt even when desired configuration is identical.
    // Aborting the task stands in for a fatal listener boundary failure.
    #[tokio::test]
    async fn identical_configuration_recovers_finished_listener() {
        let (a, b) = tokio::io::duplex(4096);
        let (host, guest) = tokio::join!(
            Transport::yamux(Box::new(a), true, drydock_transport::Limits::default()),
            Transport::yamux(Box::new(b), false, drydock_transport::Limits::default())
        );
        let mut host = host.unwrap();
        let guest = guest.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let agent = Agent::new(guest, "build".into(), dir.path().join("agent"));
        let f = GuestForward { id: "recover".into(), unix: dir.path().join("socket"), tcp: None };
        let config = Configuration { forwards: vec![f.clone()], ..Configuration::default() };
        configure(State(agent.shared.clone()), Json(config.clone())).await.unwrap();
        {
            let mut settings = agent.shared.settings.lock().await;
            let listener = settings.listeners.get_mut("recover").unwrap();
            listener.task.abort();
            while !listener.task.is_finished() {
                tokio::task::yield_now().await;
            }
        }
        configure(State(agent.shared.clone()), Json(config)).await.unwrap();
        let _stream = tokio::net::UnixStream::connect(f.unix).await.unwrap();
        let incoming = tokio::time::timeout(std::time::Duration::from_secs(2), host.accept()).await.unwrap().unwrap().unwrap();
        assert_eq!(incoming.purpose, Purpose::Forward { id: "recover".into() });
    }
    // Real filesystem boundary: if backup linking fails, activation must retain
    // both the staged image and previous rollback, and POST alone must retry.
    #[tokio::test]
    async fn partial_activation_failure_retains_stage_and_previous() {
        let (a, b) = tokio::io::duplex(4096);
        let (host, guest) = tokio::join!(
            Transport::yamux(Box::new(a), true, drydock_transport::Limits::default()),
            Transport::yamux(Box::new(b), false, drydock_transport::Limits::default())
        );
        let _host = host.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("agent");
        let previous = executable.with_extension("prev");
        std::fs::write(&previous, b"previous rollback").unwrap();
        let agent = Agent::new(guest.unwrap(), "old".into(), executable.clone());
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

    // A process-boundary nft stand-in records the last committed transaction.
    // Fail once after real capture preparation and once after nft installation;
    // both refusals must free every port and preserve configuration/nft state.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn egress_configuration_failures_release_ports_and_restore_nft() {
        for fail_persist in [false, true] {
            let (a, b) = tokio::io::duplex(4096);
            let (host, guest) = tokio::join!(
                Transport::yamux(Box::new(a), true, drydock_transport::Limits::default()),
                Transport::yamux(Box::new(b), false, drydock_transport::Limits::default())
            );
            let _host = host.unwrap();
            let dir = tempfile::tempdir().unwrap();
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
            let mut agent = Agent::new(guest.unwrap(), "build".into(), dir.path().join("agent"));
            Arc::get_mut(&mut agent.shared).unwrap().egress_system = crate::egress::System { nft, ca };
            let previous = Configuration { environment: [("OLD".into(), "kept".into())].into(), ..Configuration::default() };
            configure(State(agent.shared.clone()), Json(previous.clone())).await.unwrap();
            let forward = GuestForward { id: "duplicate".into(), unix: dir.path().join("forward"), tcp: None };
            let rejected = Configuration {
                egress: Some(crate::Egress { upstream: "proxy".into() }),
                ca: "new bundle".into(),
                forwards: if fail_persist { vec![] } else { vec![forward.clone(), forward.clone()] },
                ..Configuration::default()
            };
            let error = configure(State(agent.shared.clone()), Json(rejected)).await.unwrap_err();
            if fail_persist {
                assert_eq!(error.1.0.operation, "egress.ca");
            }
            let settings = agent.shared.settings.lock().await;
            assert_eq!(settings.config, previous);
            assert!(settings.capture.is_none());
            assert!(settings.listeners.is_empty());
            assert!(!forward.unix.exists());
            assert_eq!(std::fs::read_to_string(&state_path).unwrap(), initial_rules);
            let log = std::fs::read_to_string(&log_path).unwrap();
            if fail_persist {
                assert_eq!(log.matches("--transaction--").count(), 2);
                assert!(log.contains("meta l4proto tcp redirect"));
                assert!(log.ends_with(&format!("{initial_rules}\n--transaction--\n")));
            } else {
                assert!(log.is_empty(), "preparation refusal must not touch nft");
            }
            // Rebind synchronously, before a caller retries configuration.
            let _dns = std::net::TcpListener::bind("[::]:1053").unwrap();
            let _capture = std::net::TcpListener::bind("[::]:15001").unwrap();
            let _proxy = std::net::TcpListener::bind("127.0.0.1:15002").unwrap();
            let _udp = std::net::UdpSocket::bind("[::]:1053").unwrap();
        }
    }

    // fchown is a kernel boundary: its result policy must tolerate EPERM only
    // for unprivileged replacement, never mask root or unrelated I/O failures.
    // Generate root/non-root identities and permission, I/O, missing-file errors.
    #[hegel::test]
    fn ownership_permission_policy(tc: hegel::TestCase) {
        use hegel::generators as gs;
        let uid = if tc.draw(gs::booleans()) { 0 } else { 1000 };
        let errors = [libc::EPERM, libc::EIO, libc::ENOENT, libc::EROFS];
        let errno = errors[tc.draw(gs::integers::<usize>().min_value(0).max_value(3))];
        assert_eq!(ownership_result(Err(io::Error::from_raw_os_error(errno)), uid).is_ok(), uid != 0 && errno == libc::EPERM);
        assert!(ownership_result(Ok(()), uid).is_ok());
    }
    // A failed preparation must synchronously clean its newly bound sockets.
    // Retry the same valid forward without yielding to task-drop scheduling.
    #[tokio::test]
    async fn rejected_configuration_awaits_prepared_listener_cleanup() {
        let (a, b) = tokio::io::duplex(4096);
        let (host, guest) = tokio::join!(
            Transport::yamux(Box::new(a), true, drydock_transport::Limits::default()),
            Transport::yamux(Box::new(b), false, drydock_transport::Limits::default())
        );
        let _host = host.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let agent = Agent::new(guest.unwrap(), "build".into(), dir.path().join("agent"));
        let good = GuestForward { id: "good".into(), unix: dir.path().join("good"), tcp: None };
        let occupied = dir.path().join("occupied");
        std::fs::write(&occupied, b"keep").unwrap();
        let bad = GuestForward { id: "bad".into(), unix: occupied.clone(), tcp: None };
        let rejected = Configuration { forwards: vec![good.clone(), bad], ..Configuration::default() };
        assert!(configure(State(agent.shared.clone()), Json(rejected)).await.is_err());
        assert!(!good.unix.exists(), "prepared socket must be gone before returning refusal");
        assert_eq!(std::fs::read(occupied).unwrap(), b"keep");
        let retry = Configuration { forwards: vec![good.clone()], ..Configuration::default() };
        configure(State(agent.shared.clone()), Json(retry)).await.unwrap();
        assert!(good.unix.exists());
    }
}

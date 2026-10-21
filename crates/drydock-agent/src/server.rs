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

type ApiError = (StatusCode, String);
fn api(error: impl std::fmt::Display) -> ApiError {
    (StatusCode::BAD_REQUEST, error.to_string())
}
struct Listener {
    task: tokio::task::JoinHandle<()>,
    path: PathBuf,
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}
#[derive(Default)]
struct Settings {
    config: Configuration,
    listeners: HashMap<String, Listener>,
    targets: HashMap<String, Endpoint>,
}
struct Shared {
    hello: Hello,
    opener: Mutex<Opener>,
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
            opener: Mutex::new(transport.opener.clone()),
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
    /// Returns the installed executable on upgrade. The composition root re-execs
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
        let mut tasks = JoinSet::new();
        let (incoming_tx, mut incoming_rx) = mpsc::channel(64);
        for mut transport in self.transports.drain(..) {
            let tx = incoming_tx.clone();
            tasks.spawn(async move {
                loop {
                    let incoming = match transport.accept().await {
                        Ok(Some(incoming)) => incoming,
                        Ok(None) => break,
                        Err(_) => continue,
                    };
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
                    self.shared.settings.lock().await.listeners.clear();
                    return path.ok_or_else(|| io::Error::other("upgrade channel closed"));
                },
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                incoming = incoming_rx.recv() => {
                    let Some((incoming, opener)) = incoming else { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "host transport closed")); };
                    match incoming.purpose {
                        Purpose::Control => { *self.shared.opener.lock().await = opener; let router = router.clone(); tasks.spawn(async move { let _ = http2::serve(incoming, router).await; }); }
                        Purpose::Forward { id } => {
                            let target = self.shared.settings.lock().await.targets.get(&id).cloned();
                            tasks.spawn(async move {
                                if let Some(target) = target {
                                    let _ = bridge(incoming.stream, target).await;
                                }
                            });
                        }
                        _ => {},
                    }
                }
            }
        }
    }
}
async fn bridge(mut stream: ByteStream, endpoint: Endpoint) -> io::Result<()> {
    let mut destination = endpoint.connect().await?;
    tokio::io::copy_bidirectional(&mut stream, &mut destination).await?;
    Ok(())
}
async fn hello(State(s): State<Arc<Shared>>) -> Json<Hello> {
    Json(s.hello.clone())
}
async fn configuration(State(s): State<Arc<Shared>>) -> Json<Configuration> {
    Json(s.settings.lock().await.config.clone())
}
async fn configure(State(s): State<Arc<Shared>>, Json(config): Json<Configuration>) -> Result<StatusCode, ApiError> {
    if config.environment.iter().any(|(k, v)| k.is_empty() || k.contains(['=', '\0']) || v.contains('\0')) {
        return Err(api("invalid process environment"));
    }
    let mut settings = s.settings.lock().await;
    let mut prepared = HashMap::new();
    for forward in &config.forwards {
        check_id(&forward.id).map_err(api)?;
        if prepared.contains_key(&forward.id) {
            return Err(api("duplicate forward ID"));
        }
        let unchanged = settings.config.forwards.iter().any(|old| old == forward);
        let listener = if unchanged { None } else { Some(listen(forward, s.opener.lock().await.clone()).await.map_err(api)?) };
        prepared.insert(forward.id.clone(), listener);
    }
    let mut listeners = HashMap::new();
    for (id, listener) in prepared {
        if let Some(listener) = listener.or_else(|| settings.listeners.remove(&id)) {
            listeners.insert(id, listener);
        }
    }
    settings.listeners = listeners;
    settings.config = config;
    Ok(StatusCode::NO_CONTENT)
}
async fn listen(forward: &GuestForward, opener: Opener) -> io::Result<Listener> {
    if forward.tcp.is_some_and(|addr| !addr.ip().is_loopback()) {
        return Err(invalid("guest TCP listener must be loopback"));
    }
    // Bind before publishing the new listener into the configuration.
    let tcp = if let Some(address) = forward.tcp {
        let listener = std::net::TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        Some(TcpListener::from_std(listener)?)
    } else {
        None
    };
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
    let id = forward.id.clone();
    let task = tokio::spawn(async move {
        let mut streams = JoinSet::new();
        loop {
            let accepted: io::Result<ByteStream> = tokio::select! {
                Some(_) = streams.join_next(), if !streams.is_empty() => continue,
                result = unix.accept() => result.map(|(s,_)| Box::new(s) as ByteStream),
                result = async { tcp.as_ref().unwrap().accept().await }, if tcp.is_some() => result.map(|(s,_)| Box::new(s) as ByteStream),
            };
            let Ok(mut stream) = accepted else {
                break;
            };
            let opener = opener.clone();
            let id = id.clone();
            streams.spawn(async move {
                if let Ok(mut remote) = opener.open(Purpose::Forward { id }).await {
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut remote).await;
                }
            });
        }
    });
    Ok(Listener { task, path: forward.unix.clone() })
}
async fn add_guest(State(s): State<Arc<Shared>>, Json(forward): Json<GuestForward>) -> Result<StatusCode, ApiError> {
    check_id(&forward.id).map_err(api)?;
    let mut settings = s.settings.lock().await;
    if settings.listeners.contains_key(&forward.id) {
        return Err(api("forward ID already exists"));
    }
    let listener = listen(&forward, s.opener.lock().await.clone()).await.map_err(api)?;
    settings.listeners.insert(forward.id.clone(), listener);
    settings.config.forwards.push(forward);
    Ok(StatusCode::NO_CONTENT)
}
async fn remove_guest(State(s): State<Arc<Shared>>, Json(id): Json<String>) -> StatusCode {
    let mut settings = s.settings.lock().await;
    settings.listeners.remove(&id);
    settings.config.forwards.retain(|f| f.id != id);
    StatusCode::NO_CONTENT
}
async fn add_target(State(s): State<Arc<Shared>>, Json(target): Json<GuestTarget>) -> Result<StatusCode, ApiError> {
    check_id(&target.id).map_err(api)?;
    s.settings.lock().await.targets.insert(target.id, target.endpoint);
    Ok(StatusCode::NO_CONTENT)
}
async fn remove_target(State(s): State<Arc<Shared>>, Json(id): Json<String>) -> StatusCode {
    s.settings.lock().await.targets.remove(&id);
    StatusCode::NO_CONTENT
}
async fn exec(State(s): State<Arc<Shared>>, Json(request): Json<Exec>) -> Result<Body, ApiError> {
    let environment = s.settings.lock().await.config.environment.clone();
    let rx = crate::exec::launch(request, environment).map_err(api)?;
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
    if executable {
        file.set_permissions(std::fs::Permissions::from_mode(0o755)).await?;
    }
    file.sync_all().await?;
    temporary.persist(path).map_err(|error| error.error)?;
    tokio::fs::File::open(parent).await?.sync_all().await
}
async fn write_file(Json(file): Json<FileWrite>) -> Result<StatusCode, ApiError> {
    atomic_write(&file.path, &file.bytes, file.executable).await.map_err(api)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn read_file(Json(file): Json<FilePath>) -> Result<Vec<u8>, ApiError> {
    tokio::fs::read(file.path).await.map_err(api)
}
async fn flush_file(Json(file): Json<FilePath>) -> Result<StatusCode, ApiError> {
    tokio::fs::File::open(file.path).await.map_err(api)?.sync_all().await.map_err(api)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn stage_upgrade(State(s): State<Arc<Shared>>, bytes: Bytes) -> Result<StatusCode, ApiError> {
    if bytes.is_empty() {
        return Err(api("empty agent executable"));
    }
    let mut staged = s.staged.lock().await;
    let path = s.executable.with_extension("upgrade");
    atomic_write(&path, &bytes, true).await.map_err(api)?;
    *staged = Some(path);
    Ok(StatusCode::NO_CONTENT)
}
async fn activate_upgrade(State(s): State<Arc<Shared>>) -> Result<StatusCode, ApiError> {
    let mut staged = s.staged.lock().await;
    let path = staged.take().ok_or_else(|| api("no staged agent"))?;
    // Keep the installed path stable over successive upgrades.
    tokio::fs::rename(&path, &s.executable).await.map_err(api)?;
    if let Some(parent) = s.executable.parent() {
        tokio::fs::File::open(parent).await.map_err(api)?.sync_all().await.map_err(api)?;
    }
    let path = s.executable.clone();
    let tx = s.restart.clone();
    tokio::spawn(async move {
        // Activation acknowledgement is advisory: clients reconnect and verify hello.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let _ = tx.send(path).await;
    });
    Ok(StatusCode::NO_CONTENT)
}

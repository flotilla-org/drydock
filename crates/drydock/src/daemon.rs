//! Long-lived provider routing shared by drydockd and an embedding daemon.
use crate::{
    HostConnection, HostHandle, HostSpec, Supervisor,
    client::{Client, Error, StatusCache, WireResponse},
    config::{Config, Egress},
    credentials::BuiltinCredentials,
    launch::{self, ImageResolver, LaunchOptions, RegistryResolver},
};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
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
                proxy_environment: BTreeMap::new(),
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
                        proxy_environment: BTreeMap::new(),
                    },
                });
            }
        }
        Ok(hosts)
    }
}
struct ManagedHost {
    handle: HostHandle,
    cache: Mutex<(u64, Arc<StatusCache>)>,
}
struct Placement {
    host: usize,
    minimum: Size,
}
pub struct Daemon {
    config: Config,
    modules: BTreeMap<String, (usize, LoadableModule)>,
    hosts: Vec<ManagedHost>,
    placements: BTreeMap<String, Placement>,
    unavailable: BTreeMap<String, Readiness>,
    keys: PathBuf,
    resolver: Arc<dyn ImageResolver>,
    stopping: tokio::sync::watch::Sender<bool>,
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
        for (name, provider) in &config.provider {
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
            let mut configured_modules = BTreeMap::new();
            let mut providers = vec![];
            let mut credentials = BTreeMap::new();
            for name in &assignments[i] {
                let p = &config.provider[name];
                configured_modules.insert(p.module.clone(), ModuleConfiguration { name: p.module.clone(), entrypoint: p.module.clone() });
                providers.push(ProviderConfiguration {
                    name: name.clone(),
                    module: p.module.clone(),
                    settings: p.settings.clone(),
                    credential: CredentialMode::Direct { credential_reference: name.clone() },
                });
                // A credential path that cannot be resolved (for example, no
                // HOME for ~/...) is missing evidence, not a daemon failure.
                // The supervisor reports MissingCredential for absent references.
                if let Ok(reference) = p.credential.reference(&rigging_process::ProcessEnvVars) {
                    credentials.insert(name.clone(), reference);
                }
                placements.insert(name.clone(), Placement { host: hosts.len(), minimum: chosen[name].1.clone() });
            }
            let spec = HostSpec {
                name: option.name,
                connection: option.connection,
                configuration: HostConfiguration { modules: configured_modules.into_values().collect(), providers },
                credentials,
            };
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
        Ok(Arc::new(Self {
            config,
            modules,
            hosts,
            placements,
            unavailable,
            keys,
            resolver,
            stopping: tokio::sync::watch::channel(false).0,
        }))
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
    fn ready_host(&self, provider: &str) -> Result<&ManagedHost, Error> {
        let host = self.host(provider)?;
        match host.handle.instances().remove(provider) {
            Some(Readiness::Ready) => Ok(host),
            Some(readiness) => Err(Error::NotReady(readiness)),
            None => Err(Error::Transport),
        }
    }
    async fn cache(&self, provider: &str) -> Result<Arc<StatusCache>, Error> {
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
            modules: self
                .modules
                .iter()
                .filter_map(|(name, (host, _))| statuses[*host].modules.iter().find(|m| &m.name == name).cloned())
                .collect(),
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
            providers: self
                .config
                .provider
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
                            readiness: Readiness::Unknown { reason: "instance absent from hello".into() },
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
                .collect(),
        }
    }
    pub fn providers(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.config
                .provider
                .iter()
                .map(|(name, p)| {
                    let readiness = self
                        .host(name)
                        .ok()
                        .and_then(|h| h.handle.instances().remove(name))
                        .or_else(|| self.unavailable.get(name).cloned())
                        .unwrap_or(Readiness::Unknown { reason: "connecting".into() });
                    serde_json::json!({"provider":name,"module":p.module,"readiness":readiness})
                })
                .collect(),
        )
    }
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/v1/hello", get(|State(d): State<Arc<Daemon>>| async move { Json(d.hello()) }))
            .route("/v1/events", get(events_route))
            .route("/v1/providers", get(|State(d): State<Arc<Daemon>>| async move { Json(d.providers()) }))
            .route("/v1/providers/{provider}/launch", post(launch_route))
            .route("/v1/providers/{provider}/prepare", post(prepare_route))
            .route("/v1/providers/{provider}/environments/{id}/relay", get(relay_route))
            .route("/v1/providers/{provider}/environments/{id}/exec", post(exec_route))
            .route("/v1/providers/{provider}/environments/{id}/shell", post(shell_route))
            .route("/v1/providers/{provider}/{*rest}", any(forward))
            .fallback(|| async { ApiError(Error::Protocol(ProtocolError::NotFound { reason: "unknown route".into() })) })
            .method_not_allowed_fallback(|| async {
                ApiError(Error::Protocol(ProtocolError::MethodNotAllowed { reason: "unsupported method".into() }))
            })
            .with_state(self.clone())
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
        launch::prepare(
            &host.handle.client,
            provider,
            &self.config.provider[provider],
            &self.placements[provider].minimum,
            options,
            self.resolver.as_ref(),
        )
        .await
    }
    pub async fn launch(&self, provider: &str, options: &LaunchOptions) -> Result<Environment, Error> {
        let (prepared, size) = self.prepare(provider, options).await?;
        let platform = prepared.platform.clone();
        let label = uuid::Uuid::new_v4().to_string();
        let dir = self.keys.join(&label);
        let (_, public) = launch::keypair(&dir).await?;
        let request = ProvisionRequest {
            label,
            prepared,
            size,
            egress: options.egress.or(self.config.provider[provider].egress).unwrap_or(Egress::Open).request(),
            ssh_public_key: Some(public),
        };
        // Retain key and the resolved digests even on an ambiguous provision error.
        // This is launch evidence and key ownership, never desired-state reconciliation.
        tokio::fs::write(dir.join("request.json"), serde_json::to_vec(&request).map_err(|_| Error::InvalidRequest)?)
            .await
            .map_err(|_| Error::Transport)?;
        // Preparation can outlast a host generation or credential change. Use
        // this fresh readiness check and its host for the actual provision call.
        let host = self.ready_host(provider)?;
        // The provider declares whether its vessels run the agent; the module name does not.
        let agent = host.handle.status.borrow().providers.iter().any(|d| d.provider == provider && d.capabilities.agent);
        // Find the agent build for the prepared platform before creating anything.
        let agent_build = if agent { Some(agent_build(&platform).await?) } else { None };
        let result = host.handle.client.clone().with_request_timeout(Duration::from_secs(600)).provision(provider, &request).await;
        let cache = host.cache.lock().await.1.clone();
        cache.invalidate(provider).await;
        let environment = result?;
        if let Some(build) = agent_build {
            self.agent_ready(provider, &environment, &platform, &build).await?;
        }
        Ok(environment)
    }
    /// Wait for the vessel agent's current hello, pushing `build` (the agent for
    /// the prepared `platform`) to an older one.
    async fn agent_ready(&self, provider: &str, environment: &Environment, platform: &Platform, build: &[u8]) -> Result<(), Error> {
        let identity = self.key_for(environment)?;
        let client = &self.ready_host(provider)?.handle.client;
        // Each reach mints a fresh gateway username, which is an access token.
        let masker = std::sync::Mutex::new(DiagnosticMasker::default());
        let open = || async {
            let reach = client.reach(provider, &environment.id).await.map_err(|e| std::io::Error::other(format!("agent reach: {e}")))?;
            let Reach::Ssh { endpoint, user, host_key, reverse_forwards } = reach else {
                return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "agent hello requires an SSH reach"));
            };
            masker.lock().unwrap().remember(user.expose());
            drydock_transport::ssh::connect(
                agent_ssh(&endpoint, user.expose(), host_key, identity.clone(), reverse_forwards)?,
                drydock_transport::Limits::default(),
            )
            .await
        };
        let result = wait_for_agent(open, platform, build, Duration::from_secs(60), |text| masker.lock().unwrap().text(text)).await;
        result.map(drop).map_err(|error| {
            let reason = format!("vessel agent did not complete its hello handshake: {error}");
            Error::Protocol(match error.kind() {
                std::io::ErrorKind::Unsupported => ProtocolError::Refused { reason },
                _ => ProtocolError::unavailable(reason, None),
            })
        })
    }

    pub fn key_for(&self, environment: &Environment) -> Result<PathBuf, Error> {
        let label = environment
            .label
            .as_deref()
            .ok_or_else(|| Error::Protocol(ProtocolError::Refused { reason: "environment has no drydock-managed SSH key".into() }))?;
        // Never use an arbitrary client label as a filesystem path.
        uuid::Uuid::parse_str(label).map_err(|_| Error::InvalidRequest)?;
        Ok(self.keys.join(label).join("id_ed25519"))
    }
}
#[async_trait::async_trait]
impl ProviderApi for Daemon {
    async fn hello(&self) -> Result<Hello, Error> {
        Ok(Daemon::hello(self))
    }
    async fn observe(&self, since: Option<&str>) -> Result<crate::api::ObservationStream, Error> {
        Ok(self.observation_stream(since))
    }

    async fn relay(&self, provider: &str, id: &str) -> Result<rigging_stream::ByteStream, Error> {
        self.ready_host(provider)?.handle.client.relay(provider, id).await
    }
    async fn exec(&self, provider: &str, id: &str, command: &ExecRequest) -> Result<rigging_stream::ByteStream, Error> {
        self.ready_host(provider)?.handle.client.exec(provider, id, command).await
    }

    async fn request(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<&serde_json::Value>,
    ) -> Result<WireResponse, Error> {
        let provider = *segments.get(2).ok_or(Error::InvalidRequest)?;
        if segments.get(..2) != Some(&["v1", "providers"]) || segments.get(3) == Some(&"credential") {
            return Err(Error::InvalidRequest);
        }
        let host = self.ready_host(provider)?;
        if method == Method::GET && segments.get(3) == Some(&"environments") {
            let value = match segments.len() {
                4 => Some(serde_json::to_value(self.cache(provider).await?.list(provider).await?).map_err(|_| Error::InvalidResponse)?),
                5 => Some(
                    serde_json::to_value(self.cache(provider).await?.inspect(provider, segments[4]).await?)
                        .map_err(|_| Error::InvalidResponse)?,
                ),
                _ => None,
            };
            if let Some(body) = value {
                return Ok(WireResponse { status: 200, headers: Default::default(), body });
            }
        }
        let client = if method == Method::POST {
            host.handle.client.clone().with_request_timeout(Duration::from_secs(600))
        } else {
            host.handle.client.clone()
        };
        let result = client.wire_response(method.clone(), segments, query, body).await;
        if method != Method::GET {
            let cache = host.cache.lock().await.1.clone();
            cache.invalidate(provider).await;
        }
        result
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
struct ApiError(Error);
impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        Self(e)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let error = match self.0 {
            Error::Protocol(e) => e,
            Error::InvalidRequest => ProtocolError::Refused { reason: "invalid provider request".into() },
            Error::RateLimited => ProtocolError::RateLimited { reason: "status budget exhausted".into(), retry_after: None },
            Error::NotReady(r) => ProtocolError::unavailable(format!("provider is not ready: {r:?}"), None),
            _ => ProtocolError::unavailable("provider transport failed", None),
        };
        let retry = error.retry_after();
        let mut response = (StatusCode::from_u16(error.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), Json(error)).into_response();
        if let Some(seconds) = retry {
            response.headers_mut().insert("retry-after", seconds.to_string().parse().expect("numeric header"));
        }
        response
    }
}
#[derive(Deserialize)]
#[serde(untagged)]
enum PrepareInput {
    Exact(PrepareRequest),
    Defaults(LaunchOptions),
}
async fn prepare_route(
    State(d): State<Arc<Daemon>>,
    Path(p): Path<String>,
    input: Result<Json<PrepareInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Prepared>, ApiError> {
    let Json(input) = input.map_err(|_| Error::InvalidRequest)?;
    Ok(Json(match input {
        PrepareInput::Exact(r) => {
            d.ready_host(&p)?.handle.client.clone().with_request_timeout(Duration::from_secs(600)).prepare(&p, &r).await?
        }
        PrepareInput::Defaults(o) => d.prepare(&p, &o).await?.0,
    }))
}
async fn launch_route(
    State(d): State<Arc<Daemon>>,
    Path(p): Path<String>,
    input: Result<Json<LaunchOptions>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Environment>, ApiError> {
    let Json(o) = input.map_err(|_| Error::InvalidRequest)?;
    Ok(Json(d.launch(&p, &o).await?))
}
async fn forward(
    State(d): State<Arc<Daemon>>,
    Path((provider, rest)): Path<(String, String)>,
    Query(query): Query<BTreeMap<String, String>>,
    req: Request,
) -> Result<Response, ApiError> {
    let method = req.method().clone();
    // Decode each path component separately: encoded slashes in opaque IDs must
    // remain one ID. Axum's wildcard has already decoded the rest, so use URI.
    let raw: Vec<_> = req
        .uri()
        .path()
        .split('/')
        .skip(4)
        .map(|s| percent_encoding::percent_decode_str(s).decode_utf8().map(|s| s.into_owned()))
        .collect::<Result<_, _>>()
        .map_err(|_| Error::InvalidRequest)?;
    let _ = rest;
    if !matches!(raw.first().map(String::as_str), Some("environments" | "usage" | "quota")) {
        return Err(Error::Protocol(ProtocolError::NotFound { reason: "unknown provider route".into() }).into());
    }
    let mut segments = vec!["v1", "providers", &provider];
    segments.extend(raw.iter().map(String::as_str));
    let bytes = axum::body::to_bytes(req.into_body(), 8 * 1024 * 1024).await.map_err(|_| Error::InvalidRequest)?;
    let body = if bytes.is_empty() { None } else { Some(serde_json::from_slice(&bytes).map_err(|_| Error::InvalidRequest)?) };
    let query: Vec<_> = query.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let result = d.request(method, &segments, &query, body.as_ref()).await?;
    let mut response = if result.status == 204 {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::from_u16(result.status).map_err(|_| Error::InvalidResponse)?, Json(result.body)).into_response()
    };
    if let Some(value) = result.headers.get("retry-after") {
        response.headers_mut().insert("retry-after", value.clone());
    }
    Ok(response)
}
async fn relay_route(State(d): State<Arc<Daemon>>, Path((p, id)): Path<(String, String)>, req: Request) -> Result<Response, ApiError> {
    let stream = d.ready_host(&p)?.handle.client.relay(&p, &id).await?;
    upgrade(req, stream, "drydock-relay", d.stopping.subscribe())
}
async fn exec_route(State(d): State<Arc<Daemon>>, Path((p, id)): Path<(String, String)>, req: Request) -> Result<Response, ApiError> {
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024).await.map_err(|_| Error::InvalidRequest)?;
    let command = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidRequest)?;
    let stream = d.ready_host(&p)?.handle.client.exec(&p, &id, &command).await?;
    upgrade(Request::from_parts(parts, Body::empty()), stream, "drydock-stream", d.stopping.subscribe())
}
fn upgrade(
    mut req: Request,
    mut stream: rigging_stream::ByteStream,
    protocol: &'static str,
    mut stopping: tokio::sync::watch::Receiver<bool>,
) -> Result<Response, ApiError> {
    if req.headers().get("upgrade").and_then(|v| v.to_str().ok()) != Some(protocol) {
        return Err(Error::InvalidRequest.into());
    }
    let upgraded = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        if let Ok(io) = upgraded.await {
            let mut io = hyper_util::rt::TokioIo::new(io);
            tokio::select! { _ = tokio::io::copy_bidirectional(&mut io, &mut stream) => {}, _ = stopping.wait_for(|s| *s) => {} }
        }
    });
    Ok((StatusCode::SWITCHING_PROTOCOLS, [("connection", "upgrade"), ("upgrade", protocol)]).into_response())
}

async fn shell_route(State(d): State<Arc<Daemon>>, Path((p, id)): Path<(String, String)>) -> Result<Json<crate::shell::Session>, ApiError> {
    let client = &d.ready_host(&p)?.handle.client;
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

async fn events_route(State(d): State<Arc<Daemon>>, Query(query): Query<BTreeMap<String, String>>) -> Response {
    use futures::StreamExt;
    let body = d.observation_stream(query.get("since").map(String::as_str)).map(|record| {
        record.map(|record| {
            let mut line = serde_json::to_vec(&record).expect("record serializes");
            line.push(b'\n');
            line
        })
    });
    ([("content-type", "application/x-ndjson")], Body::from_stream(body)).into_response()
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
                            Ok(Some(record)) => yield (index,Ok(record)),
                            Ok(None) => break,
                            Err(error) => {yield (index,Err(error));break;}
                        }},
                        Err(error) => yield (index,Err(error)),
                    }
                }) as BoxStream<'static, _>
            })
            .collect();
        let providers: BTreeMap<String, Option<usize>> =
            self.config.provider.keys().map(|name| (name.clone(), self.placements.get(name).map(|p| p.host))).collect();
        let mut stopping = self.stopping.subscribe();
        Box::pin(async_stream::stream! {
            let mut streams=futures::stream::select_all(streams);
            loop {
                let next=tokio::select! {value=streams.next()=>value,_=stopping.wait_for(|s|*s)=>None};
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

// Guest-to-host streams ride the host's link through the local forward. That
// works whether or not the server grants remote Unix-socket forwards, and
// Daytona's SSH gateway does not.
/// The agent link follows what the provider's SSH server accepts: guest-to-host
/// streams get their own channels through a reverse forward to the agent's fixed
/// host socket, unless the provider declares that its server refuses reverse forwards.
fn agent_ssh(
    endpoint: &str,
    user: &str,
    host_key: String,
    identity: PathBuf,
    reverse_forwards: bool,
) -> std::io::Result<drydock_transport::ssh::SshConfig> {
    let (host, port) = endpoint.rsplit_once(':').ok_or_else(|| std::io::Error::other("invalid SSH endpoint"))?;
    Ok(drydock_transport::ssh::SshConfig {
        connect_timeout: Duration::from_secs(10),
        host: host.into(),
        port: port.parse().map_err(|e| std::io::Error::other(format!("invalid SSH endpoint port: {e}")))?,
        user: user.into(),
        host_key,
        identity_file: identity,
        agent_socket: "/run/drydock/agent.sock".into(),
        guest_streams: if reverse_forwards {
            drydock_transport::ssh::GuestStreams::ReverseForward("/run/drydock/host.sock".into())
        } else {
            drydock_transport::ssh::GuestStreams::OverLocalForward
        },
    })
}

/// The host's agent build for a prepared platform. A missing build refuses the
/// launch, naming the file or variable that would supply it.
async fn agent_build(platform: &Platform) -> Result<Vec<u8>, Error> {
    let refused = |reason: String| Error::Protocol(ProtocolError::Refused { reason });
    let path = crate::local::agent_build(platform).map_err(|reason| refused(format!("no vessel agent build for {platform}: {reason}")))?;
    tokio::fs::read(&path).await.map_err(|error| refused(format!("vessel agent build {}: {error}", path.display())))
}
// Provider startup can precede the socket listener. connect_current itself owns
// upgrade/re-exec reconnects and only returns a compatible hello. Unsupported
// errors (including an agent reporting another platform than the prepared one)
// return at once; others retry until the deadline. `mask` removes credentials
// from each attempt's error before it is logged or returned.
async fn wait_for_agent<F, Fut>(
    mut open: F,
    platform: &Platform,
    executable: &[u8],
    timeout: Duration,
    mask: impl Fn(&str) -> String,
) -> std::io::Result<drydock_agent::Client>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<drydock_transport::Transport>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last = None;
    for attempt in 1.. {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, drydock_agent::Client::connect_current(&mut open, platform, executable, remaining)).await {
            Ok(Ok(client)) => return Ok(client),
            // Retrying cannot change an unsupported arrangement.
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::Unsupported => return Err(error),
            Ok(Err(error)) => {
                let interrupted = error.kind() == std::io::ErrorKind::TimedOut && tokio::time::Instant::now() >= deadline;
                let error = mask(&error.to_string());
                // Log a reason once, not on every 250ms retry.
                if last.as_deref() != Some(error.as_str()) {
                    eprintln!("agent hello attempt {attempt} failed: {error}");
                }
                // An attempt cut short by the deadline says less than the one before it.
                if !interrupted || last.is_none() {
                    last = Some(error);
                }
            }
            Err(_) => break,
        }
        tokio::time::sleep(Duration::from_millis(250).min(remaining)).await;
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("agent hello timed out after {timeout:?}; last error: {}", last.as_deref().unwrap_or("no attempt finished")),
    ))
}

#[cfg(test)]
mod agent_readiness_tests {
    use super::*;
    // A transport connection alone is not readiness. Fail initial opens, then
    // serve the real agent API over yamux and require its compatible hello.
    #[tokio::test]
    async fn retries_startup_until_current_hello() {
        use sha2::{Digest, Sha256};
        let binary = b"current agent";
        let mut attempts = 0;
        wait_for_agent(
            || {
                attempts += 1;
                let attempt = attempts;
                async move {
                    if attempt < 3 {
                        return Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
                    }
                    let (host, guest) = tokio::io::duplex(4096);
                    let (host, guest) = tokio::join!(
                        drydock_transport::Transport::yamux(Box::new(host), true, Default::default()),
                        drydock_transport::Transport::yamux(Box::new(guest), false, Default::default())
                    );
                    tokio::spawn(drydock_agent::Agent::new(guest?, format!("{:x}", Sha256::digest(binary)), "/unused".into()).run());
                    host
                }
            },
            &Platform::current(),
            binary,
            Duration::from_secs(5),
            str::to_owned,
        )
        .await
        .unwrap();
        assert_eq!(attempts, 3);
    }
    // An agent reporting another platform than the prepared one is final:
    // refuse at once, before the readiness deadline, naming both platforms.
    #[tokio::test]
    async fn platform_mismatch_is_refused_without_waiting() {
        let current = Platform::current();
        let prepared = Platform::new("linux", if current == Platform::new("linux", "amd64") { "arm64" } else { "amd64" });
        let mut opens = 0;
        let started = tokio::time::Instant::now();
        let error = wait_for_agent(
            || {
                opens += 1;
                async move {
                    let (host, guest) = tokio::io::duplex(4096);
                    let (host, guest) = tokio::join!(
                        drydock_transport::Transport::yamux(Box::new(host), true, Default::default()),
                        drydock_transport::Transport::yamux(Box::new(guest), false, Default::default())
                    );
                    tokio::spawn(drydock_agent::Agent::new(guest?, "older".into(), "/unused".into()).run());
                    host
                }
            },
            &prepared,
            b"prepared platform build",
            Duration::from_secs(30),
            str::to_owned,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert!(error.to_string().contains(&format!("prepared for {prepared} but its agent reports {current}")), "{error}");
        assert_eq!(opens, 1);
        assert!(started.elapsed() < Duration::from_secs(30));
    }
    // A reachable transport whose peer never sends hello must time out.
    #[tokio::test]
    async fn transport_without_hello_is_not_ready() {
        let (host, guest) = tokio::io::duplex(4096);
        let (host, _guest) = tokio::join!(
            drydock_transport::Transport::yamux(Box::new(host), true, Default::default()),
            drydock_transport::Transport::yamux(Box::new(guest), false, Default::default())
        );
        let mut host = Some(host.unwrap());
        let result = wait_for_agent(
            || std::future::ready(host.take().ok_or_else(|| std::io::Error::from(std::io::ErrorKind::ConnectionRefused))),
            &Platform::current(),
            b"current",
            Duration::from_millis(25),
            str::to_owned,
        )
        .await;
        assert_eq!(result.err().unwrap().kind(), std::io::ErrorKind::TimedOut);
    }
    // Readiness failure names the last real reason, with the minted gateway
    // username masked, rather than a bare "did not complete its hello".
    #[tokio::test]
    async fn timeout_reports_the_last_masked_error() {
        let mut masker = DiagnosticMasker::default();
        masker.remember("minted-gateway-token");
        let result = wait_for_agent(
            || {
                std::future::ready(Err(std::io::Error::other(
                    "SSH forwarding rejected: remote port forwarding failed for minted-gateway-token",
                )))
            },
            &Platform::current(),
            b"current",
            Duration::from_millis(100),
            |text| masker.text(text),
        )
        .await;
        let error = result.err().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        let message = error.to_string();
        assert!(message.contains("last error: SSH forwarding rejected: remote port forwarding failed"), "{message}");
        assert!(!message.contains("minted-gateway-token"), "{message}");
    }
    // The provider's declaration picks the layout: reverse forwards are the
    // default, and only a provider whose server refuses them shares the local forward.
    #[test]
    fn agent_link_layout_follows_the_reach_declaration() {
        use drydock_transport::ssh::GuestStreams;
        let config = |reverse| agent_ssh("gw.example:22", "u", "ssh-ed25519 AAAA".into(), "/k".into(), reverse).unwrap().guest_streams;
        assert_eq!(config(true), GuestStreams::ReverseForward("/run/drydock/host.sock".into()));
        assert_eq!(config(false), GuestStreams::OverLocalForward);
    }
    // The agent reach path against an OpenSSH server that, like Daytona's
    // gateway, refuses remote Unix-socket forwards. The agent listens with its
    // fixed native transport and its guest-to-host socket never appears; hello
    // and a guest-to-host forward stream must both work over the host's link.
    #[tokio::test]
    async fn agent_reach_works_through_a_gateway_without_reverse_forwards() {
        use drydock_agent::{Endpoint, GuestForward};
        use sha2::{Digest, Sha256};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = tempfile::tempdir().unwrap();
        let agent_socket = dir.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&agent_socket).unwrap();
        let connections = drydock_transport::native::UnixConnections::new(listener, dir.path().join("host.sock"));
        let guest = drydock_transport::Transport::native(std::sync::Arc::new(connections), Default::default()).unwrap();
        let binary = b"current agent";
        let agent = tokio::spawn(drydock_agent::Agent::new(guest, format!("{:x}", Sha256::digest(binary)), "/unused".into()).run());
        let (sshd_config, mut server) =
            sshd::start(dir.path(), &agent_socket, drydock_transport::ssh::GuestStreams::OverLocalForward, sshd::Forwarding::Gateway).await;
        let endpoint = format!("{}:{}", sshd_config.host, sshd_config.port);
        let mut config =
            agent_ssh(&endpoint, &sshd_config.user, sshd_config.host_key.clone(), sshd_config.identity_file.clone(), false).unwrap();
        config.agent_socket = agent_socket;
        let client = wait_for_agent(
            || drydock_transport::ssh::connect(config.clone(), Default::default()),
            &Platform::current(),
            binary,
            Duration::from_secs(10),
            str::to_owned,
        )
        .await
        .unwrap();
        let target = dir.path().join("target");
        let target_listener = tokio::net::UnixListener::bind(&target).unwrap();
        let forward = GuestForward { id: "service".into(), unix: dir.path().join("forward"), tcp: None };
        client.put_guest_forward(forward.clone(), Endpoint::Unix(target)).await.unwrap();
        assert!(!dir.path().join("host.sock").exists());
        let mut guest_stream = tokio::net::UnixStream::connect(&forward.unix).await.unwrap();
        guest_stream.write_all(b"guest to host").await.unwrap();
        let (mut host_end, _) = tokio::time::timeout(Duration::from_secs(5), target_listener.accept()).await.unwrap().unwrap();
        let mut received = [0; 13];
        host_end.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"guest to host");
        host_end.write_all(b"reply").await.unwrap();
        let mut reply = [0; 5];
        guest_stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        drop(client);
        agent.abort();
        server.kill().await.unwrap();
    }
}
#[cfg(test)]
#[path = "../../drydock-transport/tests/support/sshd.rs"]
mod sshd;

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
        usage: false,
        quota: false,
    }
}

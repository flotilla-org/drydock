//! Managed host lifecycle, injected runtime detection, and credential refresh.
//! Dropping a HostHandle cancels supervision and terminates its managed child.
pub mod api;
pub mod config;
pub mod conformance;
pub mod credentials;
pub mod daemon;
pub mod launch;
pub mod local;
pub mod shell;
use client::Client;
use credentials::*;
pub use drydock_client as client;
use drydock_protocol::*;
use rigging_process::{ChannelLabel, CommandRunner};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{sync::watch, task::JoinHandle};

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostConnection {
    Managed {
        command: Vec<String>,
        runtime: Option<String>,
        /// Non-secret proxy URLs and CA paths only. Never put credentials here:
        /// the command runner currently carries these values through env argv.
        #[serde(default)]
        proxy_environment: BTreeMap<String, String>,
    },
    ExternalUnix {
        path: PathBuf,
    },
    External {
        url: String,
        token_file: PathBuf,
    },
}
#[derive(Clone, Serialize, Deserialize)]
pub struct HostSpec {
    pub name: String,
    pub connection: HostConnection,
    pub configuration: HostConfiguration,
    /// Keys match the opaque credential_reference in Direct wire configuration.
    #[serde(default)]
    pub credentials: BTreeMap<String, CredentialReference>,
}
#[async_trait::async_trait]
pub trait ToolDetector: Send + Sync {
    async fn available(&self, tool: &str) -> bool;
}
pub struct PathDetector;
#[async_trait::async_trait]
impl ToolDetector for PathDetector {
    async fn available(&self, tool: &str) -> bool {
        let executable = |p: &Path| p.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0);
        if tool.contains('/') {
            return executable(Path::new(tool));
        }
        std::env::var_os("PATH")
            .into_iter()
            .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
            .any(|path| executable(&path.join(tool)))
    }
}
#[derive(Clone, Debug)]
pub struct HostStatus {
    pub modules: Vec<LoadedModule>,
    pub loadable_modules: Vec<LoadableModule>,
    pub readiness: Readiness,
    pub providers: Vec<ProviderDeclaration>,
    /// Incremented only after successful handshake/configuration of a new process.
    pub generation: u64,
}
impl HostStatus {
    fn new(readiness: Readiness, generation: u64) -> Self {
        Self { readiness, modules: Vec::new(), loadable_modules: Vec::new(), providers: Vec::new(), generation }
    }
}
pub struct HostHandle {
    pub client: Client,
    pub status: watch::Receiver<HostStatus>,
    instances: Vec<String>,
    task: JoinHandle<()>,
}
impl Drop for HostHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl HostHandle {
    /// Configured instances remain visible even when no host can answer hello.
    pub fn instances(&self) -> BTreeMap<String, Readiness> {
        let status = self.status.borrow();
        self.instances
            .iter()
            .map(|name| {
                let readiness = if matches!(status.readiness, Readiness::Ready) {
                    status
                        .providers
                        .iter()
                        .find(|p| &p.provider == name)
                        .map(|p| p.readiness.clone())
                        .unwrap_or(Readiness::Unknown { reason: "instance absent from hello".into() })
                } else {
                    status.readiness.clone()
                };
                (name.clone(), readiness)
            })
            .collect()
    }

    pub async fn ready(&mut self, timeout: Duration) -> Result<HostStatus, client::Error> {
        tokio::time::timeout(timeout, async {
            loop {
                let status = self.status.borrow().clone();
                match status.readiness {
                    Readiness::Ready => return Ok(status),
                    Readiness::VersionMismatch { .. } => return Err(client::Error::VersionMismatch),
                    Readiness::MissingCredential { .. } => return Err(client::Error::NotReady(status.readiness)),
                    _ => {}
                }
                self.status.changed().await.map_err(|_| client::Error::Transport)?;
            }
        })
        .await
        .map_err(|_| client::Error::ReadinessTimeout(self.status.borrow().readiness.clone()))?
    }
}
#[derive(Clone)]
pub struct Supervisor {
    pub runtime_directory: PathBuf,
    pub runner: Arc<dyn CommandRunner>,
    pub detector: Arc<dyn ToolDetector>,
    pub credentials: Arc<dyn CredentialSource>,
    pub refresh_interval: Duration,
    pub restart_delay: Duration,
    pub request_timeout: Duration,
}
impl Supervisor {
    pub fn new(runtime_directory: PathBuf, credentials: Arc<dyn CredentialSource>) -> Self {
        Self {
            runtime_directory,
            runner: Arc::new(rigging_process::ProcessCommandRunner),
            detector: Arc::new(PathDetector),
            credentials,
            refresh_interval: Duration::from_secs(1),
            restart_delay: Duration::from_millis(100),
            request_timeout: Duration::from_secs(30),
        }
    }
    pub async fn start(&self, spec: HostSpec) -> Result<HostHandle, client::Error> {
        if spec.name.is_empty() || !spec.name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
            return Err(client::Error::InvalidRequest);
        }
        let runtime_directory = std::path::absolute(&self.runtime_directory).map_err(|_| client::Error::InvalidRequest)?;
        // Own a private directory; never chmod an existing directory or follow a symlink.
        let socket = runtime_directory.join(format!("{}.sock", spec.name));
        let mut lease = None;
        let client = match &spec.connection {
            HostConnection::Managed { command, .. } => {
                if command.is_empty() {
                    return Err(client::Error::InvalidRequest);
                }
                match tokio::fs::create_dir(&self.runtime_directory).await {
                    Ok(()) => tokio::fs::set_permissions(&self.runtime_directory, std::fs::Permissions::from_mode(0o700))
                        .await
                        .map_err(|_| client::Error::Transport)?,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(_) => return Err(client::Error::Transport),
                }
                let metadata = tokio::fs::symlink_metadata(&self.runtime_directory).await.map_err(|_| client::Error::Transport)?;
                // SAFETY: geteuid has no preconditions.
                if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
                    return Err(client::Error::InvalidRequest);
                }
                use std::os::unix::fs::OpenOptionsExt;
                let lock = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(self.runtime_directory.join(format!("{}.lock", spec.name)))
                    .map_err(|_| client::Error::InvalidRequest)?;
                lock.try_lock().map_err(|_| client::Error::InvalidRequest)?;
                lease = Some(lock);
                // A live socket belongs to another supervisor. Never steal its pathname.
                if tokio::net::UnixStream::connect(&socket).await.is_ok() {
                    return Err(client::Error::InvalidRequest);
                }
                Client::unix(&socket)?
            }
            HostConnection::ExternalUnix { path } => Client::unix(path)?,
            HostConnection::External { url, token_file } => Client::external(url, read_bearer_token(token_file).await?)?,
        };
        let client = client.with_request_timeout(self.request_timeout);
        let (status, receiver) = watch::channel(HostStatus::new(Readiness::Unknown { reason: "connecting".into() }, 0));
        let mut supervisor = self.clone();
        supervisor.runtime_directory = runtime_directory;
        let host_client = client.clone();
        let instances = spec.configuration.providers.iter().map(|p| p.name.clone()).collect();
        let task = tokio::spawn(async move {
            let _lease = lease;
            supervisor.run(spec, socket, host_client, status).await;
        });
        Ok(HostHandle { client, status: receiver, instances, task })
    }
    async fn refresh(
        &self,
        spec: &HostSpec,
        client: &Client,
        previous: &mut BTreeMap<String, Secret>,
        masker: &mut DiagnosticMasker,
    ) -> Result<BTreeMap<String, Readiness>, client::Error> {
        let mut unavailable = BTreeMap::new();
        for provider in &spec.configuration.providers {
            let CredentialMode::Direct { credential_reference } = &provider.credential else { continue };
            let result = async {
                let reference = spec.credentials.get(credential_reference).ok_or_else(missing_credential)?;
                let credential = self.credentials.resolve(reference).await.map_err(|_| missing_credential())?;
                if credential.value.expose().is_empty() || credential.expires_at.is_some_and(|at| at <= SystemTime::now()) {
                    return Err(missing_credential());
                }
                masker.remember(credential.value.expose());
                if previous.get(&provider.name) != Some(&credential.value) {
                    client.credential(&provider.name, credential.value.clone()).await?;
                    previous.insert(provider.name.clone(), credential.value);
                }
                Ok(())
            }
            .await;
            match result {
                Err(client::Error::Protocol(ProtocolError::CredentialRejected { .. })) => {
                    previous.remove(&provider.name);
                    unavailable.insert(provider.name.clone(), Readiness::MissingCredential { reason: "missing credential".into() });
                }
                Err(error) => return Err(error),
                Ok(()) => {}
            }
        }
        Ok(unavailable)
    }
    async fn run(&self, spec: HostSpec, socket: PathBuf, client: Client, status: watch::Sender<HostStatus>) {
        let mut masker = DiagnosticMasker::default();
        // Settings are not diagnostics. Mask string values even if a host
        // mistakenly includes them in its readiness reason.
        fn remember_settings(value: &serde_json::Value, masker: &mut DiagnosticMasker) {
            match value {
                serde_json::Value::String(s) => masker.remember(s),
                serde_json::Value::Array(a) => {
                    for v in a {
                        remember_settings(v, masker);
                    }
                }
                serde_json::Value::Object(o) => {
                    for v in o.values() {
                        remember_settings(v, masker);
                    }
                }
                _ => {}
            }
        }
        for provider in &spec.configuration.providers {
            for value in provider.settings.values() {
                remember_settings(value, &mut masker);
            }
        }
        let mut generation = 0;
        loop {
            let mut child = None;
            if let HostConnection::Managed { command, runtime, proxy_environment } = &spec.connection {
                if let Some(runtime) = runtime
                    && !self.detector.available(runtime).await
                {
                    status.send_replace(HostStatus::new(Readiness::MissingTool { reason: format!("missing tool: {runtime}") }, generation));
                    tokio::time::sleep(self.restart_delay).await;
                    continue;
                }
                let _ = tokio::fs::remove_file(&socket).await;
                let mut args = vec![];
                // env is used solely to attach the embedder's proxy environment;
                // direct credentials always travel over the authenticated socket.
                let executable = if proxy_environment.is_empty() {
                    command[0].as_str()
                } else {
                    args.push("--".to_owned());
                    args.extend(proxy_environment.iter().map(|(k, v)| format!("{k}={v}")));
                    args.push(command[0].clone());
                    "env"
                };
                args.extend_from_slice(&command[1..]);
                args.extend(["--unix".to_owned(), socket.to_string_lossy().into_owned()]);
                let refs: Vec<_> = args.iter().map(String::as_str).collect();
                match self
                    .runner
                    .spawn_long_lived(executable, &refs, &self.runtime_directory, &ChannelLabel::Extra("drydock".into(), spec.name.clone()))
                    .await
                {
                    Ok(process) => child = Some(process),
                    Err(_) => {
                        status.send_replace(HostStatus::new(Readiness::Unknown { reason: "host spawn failed".into() }, generation));
                        tokio::time::sleep(self.restart_delay).await;
                        continue;
                    }
                }
            }
            let mut initialized = false;
            let mut previous = BTreeMap::new();
            let mut changes = self.credentials.changes();
            loop {
                if let Some(child) = &mut child
                    && !matches!(child.try_wait(), Ok(None))
                {
                    break;
                }
                let result = async {
                    let hello = client.hello().await?;
                    // External hosts can restart without a local process handle.
                    if spec.configuration.providers.iter().any(|p| !hello.providers.iter().any(|d| d.provider == p.name)) {
                        initialized = false;
                    }
                    for provider in &hello.providers {
                        if matches!(provider.readiness, Readiness::MissingCredential { .. }) {
                            previous.remove(&provider.provider);
                        }
                    }
                    if !initialized {
                        client.configure(&spec.configuration).await?;
                        generation += 1;
                        initialized = true;
                        previous.clear();
                    }
                    let mut unavailable = self.refresh(&spec, &client, &mut previous, &mut masker).await?;
                    let mut hello = client.hello().await?;
                    for provider in &mut hello.providers {
                        match &mut provider.readiness {
                            Readiness::Ready => {}
                            Readiness::MissingTool { reason }
                            | Readiness::MissingCredential { reason }
                            | Readiness::VersionMismatch { reason }
                            | Readiness::Unknown { reason } => *reason = masker.text(reason),
                        }
                        if let Some(readiness) = unavailable.remove(&provider.provider) {
                            provider.readiness = readiness;
                        }
                    }
                    Ok::<_, client::Error>(hello)
                }
                .await;
                let readiness = match result {
                    Ok(hello) => {
                        status.send_replace(HostStatus {
                            readiness: Readiness::Ready,
                            modules: hello.modules,
                            loadable_modules: hello.loadable_modules,
                            providers: hello.providers,
                            generation,
                        });
                        None
                    }
                    Err(client::Error::VersionMismatch) => {
                        Some(Readiness::VersionMismatch { reason: "incompatible hello protocol version".into() })
                    }
                    Err(client::Error::Protocol(ProtocolError::CredentialRejected { .. })) => {
                        Some(Readiness::MissingCredential { reason: "missing credential".into() })
                    }
                    Err(_) => Some(Readiness::Unknown { reason: "host unavailable".into() }),
                };
                if let Some(readiness) = readiness {
                    status.send_replace(HostStatus::new(readiness.clone(), generation));
                    // A transient credential failure must not reconfigure a live
                    // host: doing so could discard a module's in-memory state.
                    if matches!(readiness, Readiness::Unknown { .. }) {
                        initialized = false;
                        previous.clear();
                    }
                }
                tokio::select! {
                    _ = tokio::time::sleep(if initialized { self.refresh_interval } else { self.restart_delay }) => {},
                    changed = changes.changed() => { if changed.is_err() { tokio::time::sleep(self.refresh_interval).await; } },
                }
            }
            status.send_replace(HostStatus::new(Readiness::Unknown { reason: "host exited; restarting".into() }, generation));
            tokio::time::sleep(self.restart_delay).await;
        }
    }
}
fn missing_credential() -> client::Error {
    client::Error::Protocol(ProtocolError::CredentialRejected { reason: "missing credential".into() })
}

async fn read_bearer_token(path: &Path) -> Result<Secret, client::Error> {
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .await
        .map_err(|_| client::Error::InvalidRequest)?;
    let metadata = file.metadata().await.map_err(|_| client::Error::InvalidRequest)?;
    // SAFETY: geteuid has no preconditions. Validate the descriptor we will read,
    // rather than a pathname that could be replaced between metadata and open.
    if !metadata.is_file()
        || !matches!(metadata.permissions().mode() & 0o7777, 0o400 | 0o600)
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(client::Error::InvalidRequest);
    }
    let mut token = String::new();
    file.take(65537).read_to_string(&mut token).await.map_err(|_| client::Error::InvalidRequest)?;
    if token.len() > 65536 {
        return Err(client::Error::InvalidRequest);
    }
    let token = token.trim_end_matches(['\r', '\n']);
    if token.is_empty() || token.bytes().any(|c| c.is_ascii_whitespace() || c.is_ascii_control()) {
        return Err(client::Error::InvalidRequest);
    }
    Ok(Secret::new(token))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Glue: readiness errors retain the observed cause, and timeout is distinct
    // from a failed transport. No network or process is needed for this mapping.
    #[tokio::test(start_paused = true)]
    async fn ready_preserves_failure_reason() {
        for readiness in [
            Readiness::MissingCredential { reason: "missing credential".into() },
            Readiness::Unknown { reason: "connecting".into() },
            Readiness::MissingTool { reason: "missing tool: node".into() },
        ] {
            let (_sender, status) = watch::channel(HostStatus::new(readiness.clone(), 0));
            let mut handle = HostHandle {
                client: Client::unix("/unused").unwrap(),
                status,
                instances: vec![],
                task: tokio::spawn(std::future::pending()),
            };
            let error = handle.ready(Duration::from_secs(1)).await.unwrap_err();
            match (readiness, error) {
                (Readiness::MissingCredential { reason: a }, client::Error::NotReady(Readiness::MissingCredential { reason: b })) => {
                    assert_eq!(a, b)
                }
                (Readiness::Unknown { reason: a }, client::Error::ReadinessTimeout(Readiness::Unknown { reason: b })) => assert_eq!(a, b),
                (Readiness::MissingTool { reason: a }, client::Error::ReadinessTimeout(Readiness::MissingTool { reason: b })) => {
                    assert_eq!(a, b)
                }
                other => panic!("unexpected readiness mapping: {other:?}"),
            }
        }
    }
}

#[cfg(test)]
#[path = "../tools_image_pin.rs"]
mod tools_image_pin;

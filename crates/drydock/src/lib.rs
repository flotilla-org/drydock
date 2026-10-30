//! Managed host lifecycle, injected runtime detection, and credential refresh.
//! Dropping a HostHandle cancels supervision and terminates its managed child.
pub mod agent;
pub mod api;
pub mod config;
pub mod conformance;
pub mod credentials;
pub mod daemon;
pub mod exposures;
pub mod launch;
pub mod local;
pub mod runtime;
pub mod shell;
use api::{ConfigUpdate, ProviderApi};
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
    /// The host inherits this process's environment.
    Managed {
        command: Vec<String>,
        runtime: Option<String>,
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
    /// The providers this host serves. Their credentials are resolved by the
    /// server, never sent to the host as configuration.
    pub configuration: Configuration,
    /// Where each provider's credential comes from, keyed by provider name.
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
    pub loadable_modules: Vec<LoadableModule>,
    pub readiness: Readiness,
    pub providers: Vec<ProviderDeclaration>,
    /// Incremented only after successful handshake/configuration of a new process.
    pub generation: u64,
}
impl HostStatus {
    fn new(readiness: Readiness, generation: u64) -> Self {
        Self { readiness, loadable_modules: Vec::new(), providers: Vec::new(), generation }
    }
}
pub struct HostHandle {
    pub client: runtime::Runtime,
    pub status: watch::Receiver<HostStatus>,
    instances: Vec<String>,
    task: JoinHandle<()>,
}
impl Drop for HostHandle {
    fn drop(&mut self) {
        self.task.abort();
        self.client.stop();
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
                self.status.changed().await.map_err(|_| client::Error::Transport("host supervision stopped".into()))?;
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
            return Err(client::Error::InvalidRequest(format!("host name {:?} must be ASCII letters, digits, - or _", spec.name)));
        }
        let runtime_directory = std::path::absolute(&self.runtime_directory)
            .map_err(|e| client::Error::InvalidRequest(format!("host runtime directory: {e}")))?;
        // Own a private directory; never chmod an existing directory or follow a symlink.
        let socket = runtime_directory.join(format!("{}.sock", spec.name));
        let mut lease = None;
        let client = match &spec.connection {
            HostConnection::Managed { command, .. } => {
                if command.is_empty() {
                    return Err(client::Error::InvalidRequest("managed host command is empty".into()));
                }
                match tokio::fs::create_dir(&self.runtime_directory).await {
                    Ok(()) => tokio::fs::set_permissions(&self.runtime_directory, std::fs::Permissions::from_mode(0o700))
                        .await
                        .map_err(|e| client::Error::Transport(format!("host runtime directory: {e}")))?,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(client::Error::Transport(format!("host runtime directory: {e}"))),
                }
                let metadata = tokio::fs::symlink_metadata(&self.runtime_directory)
                    .await
                    .map_err(|e| client::Error::Transport(format!("host runtime directory: {e}")))?;
                if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 || metadata.uid() != rustix::process::geteuid().as_raw()
                {
                    return Err(client::Error::InvalidRequest(
                        "host runtime directory must be a private directory owned by this user".into(),
                    ));
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
                    .map_err(|e| client::Error::InvalidRequest(format!("host lease: {e}")))?;
                lock.try_lock().map_err(|_| client::Error::InvalidRequest(format!("host {} is supervised elsewhere", spec.name)))?;
                lease = Some(lock);
                // A live socket belongs to another supervisor. Never steal its pathname.
                if tokio::net::UnixStream::connect(&socket).await.is_ok() {
                    return Err(client::Error::InvalidRequest(format!("host socket {} is already served", socket.display())));
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
        let public_client = runtime::Runtime::new(Default::default()).with_request_timeout(self.request_timeout);
        let policy = public_client.clone();
        let instances = spec.configuration.providers.keys().cloned().collect();
        let task = tokio::spawn(async move {
            let _lease = lease;
            supervisor.run(spec, socket, host_client, policy, status).await;
        });
        Ok(HostHandle { client: public_client, status: receiver, instances, task })
    }
    async fn refresh(
        &self,
        spec: &HostSpec,
        client: &runtime::Runtime,
        previous: &mut BTreeMap<String, Secret>,
        masker: &mut DiagnosticMasker,
    ) -> Result<BTreeMap<String, Readiness>, client::Error> {
        let mut unavailable = BTreeMap::new();
        for (name, configured) in &spec.configuration.providers {
            // A provider configured without a credential holds none to deliver. Its
            // host decides whether it needs one: a module that does reports it missing.
            if configured.credential.is_none() && !spec.credentials.contains_key(name) {
                continue;
            }
            let result = async {
                let reference = spec.credentials.get(name).ok_or_else(missing_credential)?;
                let credential = self.credentials.resolve(reference).await.map_err(|_| missing_credential())?;
                if credential.value.expose().is_empty() || credential.expires_at.is_some_and(|at| at <= SystemTime::now()) {
                    return Err(missing_credential());
                }
                masker.remember(credential.value.expose());
                if previous.get(name) != Some(&credential.value) {
                    client.credential(name, credential.value.clone()).await.map_err(client::Error::Protocol)?;
                    previous.insert(name.clone(), credential.value);
                }
                Ok(())
            }
            .await;
            match result {
                Err(client::Error::Protocol(ProtocolError::CredentialRejected { .. })) => {
                    previous.remove(name);
                    unavailable.insert(name.clone(), Readiness::MissingCredential { reason: "missing credential".into() });
                }
                Err(error) => return Err(error),
                Ok(()) => {}
            }
        }
        Ok(unavailable)
    }
    async fn run(&self, spec: HostSpec, socket: PathBuf, raw_client: Client, client: runtime::Runtime, status: watch::Sender<HostStatus>) {
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
        for provider in spec.configuration.providers.values() {
            for value in provider.settings.values() {
                remember_settings(value, &mut masker);
            }
        }
        let mut generation = 0;
        loop {
            let mut child = None;
            if let HostConnection::Managed { command, runtime } = &spec.connection {
                if let Some(runtime) = runtime
                    && !self.detector.available(runtime).await
                {
                    status.send_replace(HostStatus::new(Readiness::MissingTool { reason: format!("missing tool: {runtime}") }, generation));
                    tokio::time::sleep(self.restart_delay).await;
                    continue;
                }
                let _ = tokio::fs::remove_file(&socket).await;
                let executable = command[0].as_str();
                let mut args = command[1..].to_vec();
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
            // The host receives the document without server-only keys.
            let mut document = spec.configuration.clone();
            for provider in document.providers.values_mut() {
                provider.credential = None;
            }
            loop {
                if let Some(child) = &mut child
                    && !matches!(child.try_wait(), Ok(None))
                {
                    break;
                }
                let result = async {
                    let raw_hello = raw_client.hello().await?;
                    // A host that lost its providers, for example by restarting,
                    // invalidates the server's remote providers.
                    let listed = raw_client.providers().await?;
                    if initialized && spec.configuration.providers.keys().any(|name| !listed.iter().any(|d| &d.provider == name)) {
                        initialized = false;
                    }
                    if !initialized {
                        raw_client.configure(ConfigUpdate::Replace(document.clone())).await?;
                        client.reconnect(runtime::remote::registry(raw_client.clone(), &raw_hello)).await;
                        // Runtime calls carry their own deadlines.
                        client.configure(ConfigUpdate::Replace(spec.configuration.clone())).await?;
                        generation += 1;
                        initialized = true;
                        previous.clear();
                    }
                    for provider in client.providers().await? {
                        if matches!(provider.readiness, Readiness::MissingCredential { .. }) {
                            previous.remove(&provider.provider);
                        }
                    }
                    let mut unavailable = self.refresh(&spec, &client, &mut previous, &mut masker).await?;
                    let mut providers = client.providers().await?;
                    for provider in &mut providers {
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
                    Ok::<_, client::Error>((raw_hello.loadable_modules, providers))
                }
                .await;
                let readiness = match result {
                    Ok((loadable_modules, providers)) => {
                        status.send_replace(HostStatus { readiness: Readiness::Ready, loadable_modules, providers, generation });
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
        .map_err(|e| client::Error::InvalidRequest(format!("bearer token file: {e}")))?;
    let metadata = file.metadata().await.map_err(|e| client::Error::InvalidRequest(format!("bearer token file: {e}")))?;
    // Validate the descriptor we will read, rather than a pathname that could
    // be replaced between metadata and open.
    if !metadata.is_file()
        || !matches!(metadata.permissions().mode() & 0o7777, 0o400 | 0o600)
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(client::Error::InvalidRequest("bearer token file must be a 0400 or 0600 file owned by this user".into()));
    }
    let mut token = String::new();
    file.take(65537).read_to_string(&mut token).await.map_err(|e| client::Error::InvalidRequest(format!("bearer token file: {e}")))?;
    if token.len() > 65536 {
        return Err(client::Error::InvalidRequest("bearer token exceeds 64 KiB".into()));
    }
    let token = token.trim_end_matches(['\r', '\n']);
    if token.is_empty() || token.bytes().any(|c| c.is_ascii_whitespace() || c.is_ascii_control()) {
        return Err(client::Error::InvalidRequest("bearer token is empty or contains whitespace".into()));
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
                client: runtime::Runtime::new(Default::default()),
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

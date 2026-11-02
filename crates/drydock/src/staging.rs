//! Staging: an image a provider cannot pull is copied, once, into a declared
//! registry it can pull from, and the host is handed that copy instead. Hosts
//! never learn staging happened.
use crate::{
    config::{Registry as Declared, RegistryAccess, credential_reference},
    credentials::{BuiltinCredentials, CredentialSource},
};
use drydock_oci::{ImageRef, Registry};
use drydock_protocol::*;
use rigging_http_client::HttpClient;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, Weak},
    time::Instant,
};

type Result<T> = std::result::Result<T, ProtocolError>;

/// How drydockd reaches registries when it stages an image.
#[derive(Clone)]
pub struct Transfer {
    pub http: Arc<dyn HttpClient>,
    /// The most bytes one blob read or upload request carries, so each request
    /// fits the client's deadline however large the layer is.
    pub chunk_bytes: u64,
}
impl Default for Transfer {
    fn default() -> Self {
        let http = rigging_http_client::ReqwestHttpClient::restricted(None, None).expect("a client without proxy or CA builds");
        Self { http: Arc::new(http), chunk_bytes: 16 << 20 }
    }
}

pub(crate) struct Staging {
    transfer: Transfer,
    registries: BTreeMap<String, Declared>,
    /// One lock per staged reference, so concurrent prepares of one image
    /// copy it once and prepares of other images never wait on it.
    copying: Mutex<BTreeMap<String, Weak<tokio::sync::Mutex<()>>>>,
}
impl Staging {
    pub(crate) fn new(transfer: Transfer, registries: BTreeMap<String, Declared>) -> Self {
        Self { transfer, registries, copying: Mutex::default() }
    }
    fn declared(&self, name: &str) -> Result<&Declared> {
        self.registries.get(name).ok_or_else(|| ProtocolError::Refused { reason: format!("unknown staging registry {name}") })
    }
    fn lock(&self, staged: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut copying = self.copying.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        copying.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = copying.get(staged).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        copying.insert(staged.to_owned(), Arc::downgrade(&lock));
        lock
    }
    /// The request for an instance that pulls from `pull_from`, on the
    /// registry-pull route and `platform`. An image already in one of those
    /// registries passes through untouched; any other is staged in the first.
    /// The tools image is public and never staged.
    pub(crate) async fn stage(&self, pull_from: &[String], mut request: PrepareRequest, platform: &Platform) -> Result<PrepareRequest> {
        let Some(name) = pull_from.first() else { return Ok(request) };
        let source = ImageRef::parse(&request.image_digest)?;
        let located = format!("{}/{}", source.registry, source.repository);
        for r in pull_from {
            if within(&located, &self.declared(r)?.repository) {
                return Ok(request);
            }
        }
        let declared = self.declared(name)?;
        let (host, repository) = declared.location().map_err(|reason| ProtocolError::Refused { reason })?;
        // Every credential is read before anything moves.
        let push = credential(name, "push", &declared.push).await?;
        let pull = match &declared.pull {
            Some(access) => Some(credential(name, "pull", access).await?),
            None => None,
        };
        // The request's pull credential goes to the source registry only, and
        // the staging registry's credential goes nowhere but there.
        let http = self.transfer.http.clone();
        let from = Registry::new(http.clone(), &source.registry, request.image_pull.take(), None)?;
        let to = Registry::new(http, &host, Some(push), None)?.staging(name);
        let started = Instant::now();
        let manifest = from.platform_manifest(&source, platform).await?;
        let staged = format!("{}@{}", declared.repository, manifest.digest);
        let lock = self.lock(&staged);
        let _copying = lock.lock().await;
        let copied = drydock_oci::copy_image(&from, &source.repository, &manifest, &to, &repository, self.transfer.chunk_bytes).await?;
        tracing::info!(
            registry = %name,
            image = %request.image_digest,
            staged = %staged,
            copied,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "{}",
            if copied { "image staged" } else { "image already staged" }
        );
        request.image_digest = staged;
        request.image_pull = pull;
        request.platform = Some(platform.clone());
        Ok(request)
    }
}
/// Whether `located` (`host/path`) is `repository` or a path below it.
fn within(located: &str, repository: &str) -> bool {
    located.strip_prefix(repository).is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}
async fn credential(registry: &str, purpose: &str, access: &RegistryAccess) -> Result<RegistryCredential> {
    let unavailable = || ProtocolError::Refused { reason: format!("staging registry {registry}: {purpose} credential unavailable") };
    let reference = credential_reference(&access.credential, &rigging_process::ProcessEnvVars).map_err(|_| unavailable())?;
    let secret = BuiltinCredentials::default().resolve(&reference).await.map_err(|_| unavailable())?.value;
    Ok(RegistryCredential { username: access.username.clone(), secret })
}

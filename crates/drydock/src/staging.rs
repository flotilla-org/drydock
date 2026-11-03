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
    future::Future,
    sync::{Arc, Mutex, Weak},
    time::Instant,
};

type Result<T> = std::result::Result<T, ProtocolError>;

/// How drydockd reaches registries when it stages an image.
#[derive(Clone)]
pub struct Transfer {
    pub http: Arc<dyn HttpClient>,
    /// The most bytes one blob read or upload request carries, so each request
    /// fits the client's deadline however large the layer is, and the
    /// registry's own limit; a registry's `chunk_bytes` overrides it.
    pub chunk_bytes: u64,
}
/// GHCR refuses an upload request over 4 MiB with 416.
pub const CHUNK_BYTES: u64 = 4 << 20;
impl Default for Transfer {
    fn default() -> Self {
        let http = rigging_http_client::ReqwestHttpClient::restricted(None, None).expect("a client without proxy or CA builds");
        Self { http: Arc::new(http), chunk_bytes: CHUNK_BYTES }
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
    /// registries passes through untouched, unless it is to be composed; any
    /// other is staged in the first. The tools image is public and never
    /// staged on its own.
    pub(crate) async fn stage(
        &self,
        pull_from: &[String],
        request: PrepareRequest,
        platform: &Platform,
        compose: bool,
    ) -> Result<PrepareRequest> {
        let Some(name) = pull_from.first() else { return Ok(request) };
        let source = ImageRef::parse(&request.image_digest)?;
        let located = format!("{}/{}", source.registry, source.repository);
        for r in pull_from {
            if !compose && within(&located, &self.declared(r)?.repository) {
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
        let target = Target {
            registry: Registry::new(self.transfer.http.clone(), &host, Some(push), None)?.staging(name),
            name: name.clone(),
            repository,
            chunk: declared.chunk_bytes.unwrap_or(self.transfer.chunk_bytes),
            retain: false,
        };
        let mut request = self.put(async { Ok(target) }, None, request, platform, compose).await?;
        request.image_pull = pull;
        Ok(request)
    }
    /// The request for a provider's own registry, on the provider-push route:
    /// the image copied (or composed) there with push access the provider
    /// mints (`mint`, called once the image is known to fit `limits.0`),
    /// tagged so the registry keeps it, and visible by digest. The provider
    /// pulls its own registry, so the request carries no pull access.
    pub(crate) async fn push(
        &self,
        provider: &str,
        mint: impl Future<Output = Result<PushAccess>>,
        request: PrepareRequest,
        platform: &Platform,
        compose: bool,
        limits: (Option<u64>, Option<u64>),
    ) -> Result<PrepareRequest> {
        let target = async {
            let access = mint.await?;
            let bad = || ProtocolError::Internal {
                reason: format!("provider {provider} minted unusable push access"),
                provider_error: String::new(),
            };
            let (host, repository) = access.repository.split_once('/').filter(|(_, path)| !path.is_empty()).ok_or_else(bad)?;
            if !drydock_oci::registry_host_valid(host) {
                return Err(bad());
            }
            let expires = access.expires_at.map(|at| at.instant());
            Ok(Target {
                registry: Registry::new(self.transfer.http.clone(), host, Some(access.credential), expires)
                    .map_err(|_| bad())?
                    .staging(provider),
                name: provider.to_owned(),
                repository: repository.to_owned(),
                chunk: limits.1.unwrap_or(self.transfer.chunk_bytes),
                retain: true,
            })
        };
        let mut request = self.put(target, limits.0, request, platform, compose).await?;
        request.image_pull = None;
        Ok(request)
    }
    /// The image for `platform`, or that image with the tools image's layers
    /// appended, put by digest once into `target` (awaited once the image is
    /// known to fit `max_bytes`); the request names the copy.
    async fn put(
        &self,
        target: impl Future<Output = Result<Target>>,
        max_bytes: Option<u64>,
        mut request: PrepareRequest,
        platform: &Platform,
        compose: bool,
    ) -> Result<PrepareRequest> {
        let http = self.transfer.http.clone();
        let source = ImageRef::parse(&request.image_digest)?;
        // The request's pull credential goes to the source registry only, and
        // the target's credential goes nowhere but there.
        let tools_credential = request.image_pull.clone();
        let from = Registry::new(http.clone(), &source.registry, request.image_pull.take(), None)?;
        let started = Instant::now();
        let manifest = from.platform_manifest(&source, platform).await?;
        // What goes in: the base's manifest, or the composition and the
        // tools registry its layer comes from.
        let composed = if compose {
            let tools = ImageRef::parse(&request.tools_digest)?;
            let tools_credential = if tools.registry == source.registry { tools_credential } else { None };
            let tools_from = Registry::new(http, &tools.registry, tools_credential, None)?;
            let base_config = from.config(&source.repository, &manifest).await?;
            let tools_manifest = tools_from.platform_manifest(&tools, platform).await?;
            let tools_config = tools_from.config(&tools.repository, &tools_manifest).await?;
            let composed = drydock_oci::compose(&manifest, &base_config, &tools_manifest, &tools_config, platform)?;
            fits(composed.bytes(), max_bytes)?;
            Some((composed, tools_from, tools.repository))
        } else {
            fits(manifest.image_bytes()?, max_bytes)?;
            None
        };
        let target = target.await?;
        let to = &target.registry;
        let (digest, copied) = match composed {
            Some((composed, tools_from, tools_repository)) => {
                let lock = self.lock(&format!("{}@{}", target.location(), composed.digest));
                let _copying = lock.lock().await;
                let copied = !to.manifest_visible(&target.repository, &composed.digest).await?;
                if copied {
                    for (origin, layer) in &composed.layers {
                        let (registry, repository) = match origin {
                            drydock_oci::Source::Base => (&from, &source.repository),
                            drydock_oci::Source::Tools => (&tools_from, &tools_repository),
                        };
                        drydock_oci::copy_blob(registry, repository, to, &target.repository, layer, target.chunk).await?;
                    }
                    to.put_blob(&target.repository, &composed.config_digest, composed.config.clone().into()).await?;
                    to.put_manifest(&target.repository, &composed.digest, &composed.media_type, composed.manifest.clone().into()).await?;
                }
                if target.retain {
                    to.put_manifest(&target.repository, &retention_tag(&composed.digest), &composed.media_type, composed.manifest.into())
                        .await?;
                }
                (composed.digest, copied)
            }
            None => {
                let lock = self.lock(&format!("{}@{}", target.location(), manifest.digest));
                let _copying = lock.lock().await;
                let copied = drydock_oci::copy_image(&from, &source.repository, &manifest, to, &target.repository, target.chunk).await?;
                if target.retain {
                    to.put_manifest(&target.repository, &retention_tag(&manifest.digest), &manifest.media_type, manifest.bytes.clone())
                        .await?;
                }
                (manifest.digest, copied)
            }
        };
        // A registry can serve a new manifest only after a delay (Daytona's
        // does), and the provider pulls it once, at its prepare.
        let visible = async || to.manifest_visible(&target.repository, &digest).await;
        let mut waited = 0;
        while !visible().await? {
            waited += 1;
            if waited >= VISIBILITY_ATTEMPTS {
                return Err(ProtocolError::unavailable(format!("the image put in {} is not yet visible", target.name), Some(5)));
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        let staged = format!("{}@{digest}", target.location());
        tracing::info!(
            registry = %target.name,
            image = %request.image_digest,
            staged = %staged,
            composed = compose,
            copied,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "{}",
            if copied { "image staged" } else { "image already staged" }
        );
        request.image_digest = staged;
        request.platform = Some(platform.clone());
        Ok(request)
    }
}
/// How many times staging reads a put manifest back before giving up, a
/// second apart.
const VISIBILITY_ATTEMPTS: u32 = 60;
/// Where staging puts an image, and what it takes there.
struct Target {
    /// Push access to the registry.
    registry: Registry,
    /// How logs and errors name it.
    name: String,
    /// The path below the registry's host.
    repository: String,
    chunk: u64,
    /// Tag the copy too, for a registry that discards untagged manifests.
    retain: bool,
}
impl Target {
    fn location(&self) -> String {
        format!("{}/{}", self.registry.host(), self.repository)
    }
}
/// A tag naming the manifest whose digest is `digest`, as cosign's do.
fn retention_tag(digest: &str) -> String {
    digest.replacen(':', "-", 1)
}
/// An image fills a provider's limit exactly; one byte more is refused.
fn fits(bytes: u64, limit: Option<u64>) -> Result<()> {
    match limit {
        Some(limit_bytes) if bytes > limit_bytes => Err(ProtocolError::ImageRefused {
            reason: format!("image needs at least {bytes} bytes; the provider takes {limit_bytes}"),
            refusal: ImageRefusal::TooLarge { bytes, limit_bytes },
        }),
        _ => Ok(()),
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

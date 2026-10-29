//! OCI distribution client and host-side layering, for image routes whose tools
//! layer is added on our side. A manifest and blob operation only: no container
//! build and no local Docker. Distribution spec v1.1:
//! https://github.com/opencontainers/distribution-spec/blob/v1.1.0/spec.md
use crate::module::{Result, refused};
use base64::Engine;
use bytes::Bytes;
use drydock_protocol::*;
use reqwest::{
    Method, Url,
    header::{self, HeaderName, HeaderValue},
};
use rigging_http_client::HttpClient;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const OCI_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const DOCKER_LAYER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
/// Registry calls are bounded by the HTTP client's per-request deadline; stop
/// using a push credential this long before it expires.
const EXPIRY_MARGIN: chrono::TimeDelta = chrono::TimeDelta::seconds(30);

/// A base or tools image reference pinned by digest.
#[derive(Debug, Clone, PartialEq)]
pub struct ImageRef {
    /// `host[:port]`, with Docker Hub spelled `docker.io`.
    pub registry: String,
    pub repository: String,
    pub digest: String,
}
impl ImageRef {
    /// `[registry/]repository[:tag]@sha256:<hex>`. Docker Hub short forms expand
    /// as Docker expands them; a tag beside the digest is ignored, as pulls do.
    pub fn parse(reference: &str) -> Result<Self> {
        let invalid = || refused("image references must be name@sha256:<64 lowercase hex>");
        let (name, digest) = reference.split_once('@').ok_or_else(invalid)?;
        if !digest_valid(digest) {
            return Err(invalid());
        }
        let (registry, repository) = match name.split_once('/') {
            Some((first, rest)) if first.contains(['.', ':']) || first == "localhost" => (first.to_owned(), rest.to_owned()),
            _ if name.contains('/') => ("docker.io".to_owned(), name.to_owned()),
            _ => ("docker.io".to_owned(), format!("library/{name}")),
        };
        let repository = match repository.rsplit_once('/') {
            Some((parent, last)) => format!("{parent}/{}", last.split(':').next().unwrap_or_default()),
            None => repository.split(':').next().unwrap_or_default().to_owned(),
        };
        let component_valid = |c: &str| {
            c.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && c.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
                && c.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        };
        if !registry_host_valid(&registry) || !repository.split('/').all(component_valid) {
            return Err(invalid());
        }
        Ok(Self { registry, repository, digest: digest.to_owned() })
    }
}
/// `host[:port]` as a reference spells it. IPv6 literals are refused.
pub fn registry_host_valid(host: &str) -> bool {
    !host.is_empty() && host.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))
}
fn digest_valid(digest: &str) -> bool {
    digest
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}
pub fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// An image manifest for one platform, exactly as the registry stored it.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub media_type: String,
    pub json: Value,
}
impl Manifest {
    pub fn parse(bytes: &[u8], content_type: Option<&str>) -> Result<Self> {
        let json: Value = serde_json::from_slice(bytes).map_err(|_| malformed("manifest is not JSON"))?;
        let media_type =
            json.get("mediaType").and_then(Value::as_str).or(content_type).ok_or_else(|| malformed("manifest has no media type"))?;
        Ok(Self { media_type: media_type.to_owned(), json })
    }
    fn config(&self) -> Result<Descriptor> {
        Descriptor::parse(&self.json["config"])
    }
    fn layers(&self) -> Result<Vec<Descriptor>> {
        self.json["layers"].as_array().ok_or_else(|| malformed("manifest has no layers"))?.iter().map(Descriptor::parse).collect()
    }
}
#[derive(Debug, Clone, PartialEq)]
pub struct Descriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}
impl Descriptor {
    fn parse(v: &Value) -> Result<Self> {
        let digest = v["digest"].as_str().filter(|d| digest_valid(d)).ok_or_else(|| malformed("descriptor digest is not sha256"))?;
        Ok(Self {
            media_type: v["mediaType"].as_str().ok_or_else(|| malformed("descriptor has no media type"))?.to_owned(),
            digest: digest.to_owned(),
            size: v["size"].as_u64().ok_or_else(|| malformed("descriptor has no size"))?,
        })
    }
}
fn malformed(reason: &str) -> ProtocolError {
    ProtocolError::Internal { reason: format!("invalid OCI image: {reason}"), provider_error: String::new() }
}
fn unsupported(platform: &Platform, reason: String) -> ProtocolError {
    ProtocolError::ImageRefused { reason, refusal: ImageRefusal::UnsupportedPlatform { platform: platform.clone() } }
}

/// Where a composed layer's bytes come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Base,
    Tools,
}
/// The base image with the tools layers appended, ready to push.
#[derive(Debug, Clone)]
pub struct Composed {
    pub media_type: String,
    pub manifest: Vec<u8>,
    pub digest: String,
    pub config: Vec<u8>,
    pub config_digest: String,
    pub layers: Vec<(Source, Descriptor)>,
}
impl Composed {
    /// Compressed bytes: a lower bound on the unpacked image's size.
    pub fn bytes(&self) -> u64 {
        self.layers.iter().map(|(_, layer)| layer.size).sum::<u64>() + self.config.len() as u64
    }
}

/// Appends the tools image's layers to the base image's manifest. The base's
/// entrypoint, command, environment and user are untouched: only the root
/// filesystem and history grow. Output is a function of the inputs alone, so
/// the composed digest is stable across hosts and retries.
pub fn compose(base: &Manifest, base_config: &[u8], tools: &Manifest, tools_config: &[u8], platform: &Platform) -> Result<Composed> {
    let image_config = |manifest: &Manifest, bytes: &[u8], what: &str| -> Result<Value> {
        if ![OCI_MANIFEST, DOCKER_MANIFEST].contains(&manifest.media_type.as_str()) {
            return Err(malformed(&format!("{what} is not a single-platform image manifest")));
        }
        let config: Value = serde_json::from_slice(bytes).map_err(|_| malformed("image config is not JSON"))?;
        if config["os"].as_str() != Some(platform.os.as_str()) || config["architecture"].as_str() != Some(platform.architecture.as_str()) {
            return Err(unsupported(platform, format!("the {what} image is not built for {platform}")));
        }
        let diff_ids = config["rootfs"]["diff_ids"].as_array().map_or(0, Vec::len);
        if diff_ids != manifest.layers()?.len() {
            return Err(malformed(&format!("{what} config and manifest list different layers")));
        }
        Ok(config)
    };
    let mut config = image_config(base, base_config, "base")?;
    let tools_image = image_config(tools, tools_config, "tools")?;
    let docker = base.media_type == DOCKER_MANIFEST;
    let mut layers: Vec<_> = base.layers()?.into_iter().map(|layer| (Source::Base, layer)).collect();
    for mut layer in tools.layers()? {
        // The same gzip tar bytes carry a different name in each manifest family.
        layer.media_type = match (layer.media_type.as_str(), docker) {
            (OCI_LAYER_GZIP | DOCKER_LAYER_GZIP, true) => DOCKER_LAYER_GZIP.into(),
            (OCI_LAYER_GZIP | DOCKER_LAYER_GZIP, false) => OCI_LAYER_GZIP.into(),
            _ => return Err(malformed("the tools layer is not a gzip tar layer")),
        };
        layers.push((Source::Tools, layer));
    }
    let tools_diff_ids = tools_image["rootfs"]["diff_ids"].as_array().cloned().unwrap_or_default();
    let added = tools_diff_ids.len();
    config["rootfs"]["diff_ids"].as_array_mut().ok_or_else(|| malformed("image config has no diff_ids"))?.extend(tools_diff_ids);
    // History is optional and also lists empty layers, so its length need not
    // match diff_ids; it gains one entry per added layer only when present.
    if let Some(history) = config.get_mut("history").and_then(Value::as_array_mut) {
        history.extend((0..added).map(|_| json!({"created_by": "drydock tools layer: /opt/drydock"})));
    }
    let config = serde_json::to_vec(&config).map_err(|_| malformed("image config cannot be encoded"))?;
    let config_digest = sha256(&config);
    let mut manifest = base.json.clone();
    // A referrer of some other image the base pointed at; the composed image is not.
    if let Some(object) = manifest.as_object_mut() {
        object.remove("subject");
    }
    manifest["config"] = json!({"mediaType": base.config()?.media_type, "digest": config_digest, "size": config.len()});
    manifest["layers"] = layers.iter().map(|(_, l)| json!({"mediaType": l.media_type, "digest": l.digest, "size": l.size})).collect();
    let manifest = serde_json::to_vec(&manifest).map_err(|_| malformed("manifest cannot be encoded"))?;
    Ok(Composed { media_type: base.media_type.clone(), digest: sha256(&manifest), manifest, config, config_digest, layers })
}

/// One registry, with pull or push access. Authentication follows the
/// registry's own challenge: Basic, or a bearer token from its realm.
pub struct Registry {
    http: Arc<dyn HttpClient>,
    host: String,
    origin: Url,
    credential: Option<RegistryCredential>,
    /// Minted push credentials expire; calls stop short of expiry with a typed refusal.
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    authorizations: Mutex<BTreeMap<String, HeaderValue>>,
}
impl Registry {
    pub fn new(
        http: Arc<dyn HttpClient>,
        registry: &str,
        credential: Option<RegistryCredential>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Self> {
        let endpoint = if registry == "docker.io" { "registry-1.docker.io" } else { registry };
        let origin = Url::parse(&format!("https://{endpoint}/")).map_err(|_| refused("invalid registry host"))?;
        if origin.host_str().is_none() || origin.path() != "/" {
            return Err(refused("invalid registry host"));
        }
        Ok(Self { http, host: registry.to_owned(), origin, credential, expires_at, authorizations: Mutex::default() })
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    fn url(&self, repository: &str, tail: &[&str]) -> Url {
        let mut url = self.origin.clone();
        url.path_segments_mut().expect("https base").pop_if_empty().push("v2").extend(repository.split('/')).extend(tail);
        url
    }
    fn expired(&self) -> bool {
        self.expires_at.is_some_and(|at| chrono::Utc::now() + EXPIRY_MARGIN >= at)
    }
    fn expired_error(&self) -> ProtocolError {
        ProtocolError::ImageRefused {
            reason: format!("push credential for {} expired before the upload finished; retry to mint a new one", self.host),
            refusal: ImageRefusal::PushCredentialExpired,
        }
    }
    /// Never carries a registry body: those can echo credentials.
    fn status_error(&self, status: u16, what: &str, retry_after: Option<u64>) -> ProtocolError {
        let reason = format!("registry {} {what} HTTP {status}", self.host);
        match status {
            401 | 403 if self.expired() => self.expired_error(),
            401 | 403 => ProtocolError::CredentialRejected { reason },
            404 => ProtocolError::NotFound { reason },
            429 => ProtocolError::RateLimited { reason, retry_after },
            408 | 500..=599 => ProtocolError::unavailable(reason, retry_after),
            _ => ProtocolError::Internal { reason, provider_error: String::new() },
        }
    }
    fn same_origin(&self, url: &Url) -> bool {
        url.origin() == self.origin.origin()
    }
    /// Whether a token realm may receive this registry's credential: its own
    /// origin, or the token service a public registry is known to delegate to.
    fn realm_trusted(&self, realm: &Url) -> bool {
        self.same_origin(realm)
            || (self.host == "docker.io" && realm.origin() == Url::parse("https://auth.docker.io/").expect("static URL").origin())
    }
    async fn execute(&self, request: reqwest::Request, what: &str) -> Result<http::Response<Bytes>> {
        rigging_http_client::http_execute!(self.http, request)
            .map_err(|_| ProtocolError::unavailable(format!("registry {} {what} transport failed", self.host), None))
    }
    /// Sends with this registry's authorization for `scope`, authenticating
    /// once on a challenge. Authorization never leaves the registry's origin.
    async fn send(
        &self,
        scope: &str,
        method: Method,
        url: Url,
        headers: &[(HeaderName, String)],
        body: Option<Bytes>,
        what: &str,
    ) -> Result<http::Response<Bytes>> {
        let mut challenged = false;
        loop {
            if self.expired() {
                return Err(self.expired_error());
            }
            let mut request = reqwest::Request::new(method.clone(), url.clone());
            for (name, value) in headers {
                request.headers_mut().insert(name, HeaderValue::from_str(value).map_err(|_| refused("invalid registry header"))?);
            }
            if let Some(body) = &body {
                request.headers_mut().insert(header::CONTENT_LENGTH, body.len().into());
                *request.body_mut() = Some(body.clone().into());
            }
            let same_origin = self.same_origin(&url);
            if same_origin && let Some(authorization) = self.authorizations.lock().unwrap().get(scope) {
                request.headers_mut().insert(header::AUTHORIZATION, authorization.clone());
            }
            let response = self.execute(request, what).await?;
            if response.status() == 401 && same_origin && !challenged {
                challenged = true;
                let authorization = self.authenticate(scope, response.headers()).await?;
                self.authorizations.lock().unwrap().insert(scope.to_owned(), authorization);
                continue;
            }
            return Ok(response);
        }
    }
    fn basic(&self) -> Option<HeaderValue> {
        let credential = self.credential.as_ref()?;
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", credential.username, credential.secret.expose()));
        let mut value = HeaderValue::from_str(&format!("Basic {token}")).ok()?;
        value.set_sensitive(true);
        Some(value)
    }
    async fn authenticate(&self, scope: &str, headers: &header::HeaderMap) -> Result<HeaderValue> {
        let rejected = || ProtocolError::CredentialRejected { reason: format!("registry {} refused access to {scope}", self.host) };
        let challenge = headers.get(header::WWW_AUTHENTICATE).and_then(|v| v.to_str().ok()).ok_or_else(rejected)?;
        let (scheme, params) = challenge.trim().split_once(' ').unwrap_or((challenge.trim(), ""));
        if scheme.eq_ignore_ascii_case("basic") {
            return self.basic().ok_or_else(rejected);
        }
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(rejected());
        }
        let params = challenge_params(params);
        let mut realm = params.get("realm").and_then(|r| Url::parse(r).ok()).filter(|r| r.scheme() == "https").ok_or_else(rejected)?;
        if let Some(service) = params.get("service") {
            realm.query_pairs_mut().append_pair("service", service);
        }
        realm.query_pairs_mut().append_pair("scope", scope);
        let mut request = reqwest::Request::new(Method::GET, realm.clone());
        // A realm elsewhere gets an anonymous token request, never our credential.
        if self.realm_trusted(&realm)
            && let Some(basic) = self.basic()
        {
            request.headers_mut().insert(header::AUTHORIZATION, basic);
        }
        let response = self.execute(request, "token").await?;
        if !response.status().is_success() {
            return Err(self.status_error(response.status().as_u16(), "token", None));
        }
        let body: Value = serde_json::from_slice(response.body()).map_err(|_| rejected())?;
        let token = body.get("token").or_else(|| body.get("access_token")).and_then(Value::as_str).ok_or_else(rejected)?;
        let mut value = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| rejected())?;
        value.set_sensitive(true);
        Ok(value)
    }
    /// GET following redirects (blob stores hand out short-lived URLs on
    /// other origins), dropping authorization at the origin boundary.
    async fn get(&self, scope: &str, url: Url, headers: &[(HeaderName, String)], what: &str) -> Result<http::Response<Bytes>> {
        let mut url = url;
        for _ in 0..5 {
            let response = if self.same_origin(&url) {
                self.send(scope, Method::GET, url.clone(), headers, None, what).await?
            } else {
                let mut request = reqwest::Request::new(Method::GET, url.clone());
                for (name, value) in headers {
                    request.headers_mut().insert(name, HeaderValue::from_str(value).map_err(|_| refused("invalid registry header"))?);
                }
                self.execute(request, what).await?
            };
            if !response.status().is_redirection() {
                return Ok(response);
            }
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| malformed("redirect without location"))?;
            url = url.join(location).map_err(|_| malformed("invalid redirect"))?;
        }
        Err(ProtocolError::Internal {
            reason: format!("registry {} {what} redirected too often", self.host),
            provider_error: String::new(),
        })
    }
    fn check(&self, response: &http::Response<Bytes>, expected: &[u16], what: &str) -> Result<()> {
        let status = response.status().as_u16();
        if expected.contains(&status) {
            return Ok(());
        }
        // Integer seconds only; an HTTP-date leaves the retry hint unset.
        let retry_after = response.headers().get(header::RETRY_AFTER).and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
        Err(self.status_error(status, what, retry_after))
    }
    /// The image manifest for `platform`, choosing from an index when the
    /// reference names one. Content is verified against its digest.
    pub async fn platform_manifest(&self, image: &ImageRef, platform: &Platform) -> Result<Manifest> {
        let manifest = self.manifest(&image.repository, &image.digest).await?;
        if ![OCI_INDEX, DOCKER_LIST].contains(&manifest.media_type.as_str()) {
            return Ok(manifest);
        }
        let entries = manifest.json["manifests"].as_array().ok_or_else(|| malformed("index has no manifests"))?;
        let entry = entries
            .iter()
            .find(|m| {
                m["platform"]["os"].as_str() == Some(platform.os.as_str())
                    && m["platform"]["architecture"].as_str() == Some(platform.architecture.as_str())
            })
            .ok_or_else(|| unsupported(platform, format!("{}/{} has no {platform} image", self.host, image.repository)))?;
        let digest = Descriptor::parse(entry)?.digest;
        let manifest = self.manifest(&image.repository, &digest).await?;
        if [OCI_INDEX, DOCKER_LIST].contains(&manifest.media_type.as_str()) {
            return Err(malformed("nested image index"));
        }
        Ok(manifest)
    }
    async fn manifest(&self, repository: &str, digest: &str) -> Result<Manifest> {
        let accept = [OCI_INDEX, OCI_MANIFEST, DOCKER_LIST, DOCKER_MANIFEST].join(", ");
        let response = self
            .get(&pull_scope(repository), self.url(repository, &["manifests", digest]), &[(header::ACCEPT, accept)], "manifest")
            .await?;
        self.check(&response, &[200], "manifest")?;
        if sha256(response.body()) != digest {
            return Err(malformed("manifest content does not match its digest"));
        }
        let content_type = response.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok());
        Manifest::parse(response.body(), content_type)
    }
    /// A small blob (an image config), verified against its digest.
    pub async fn config(&self, repository: &str, manifest: &Manifest) -> Result<Bytes> {
        let digest = manifest.config()?.digest;
        let response = self.get(&pull_scope(repository), self.url(repository, &["blobs", &digest]), &[], "config").await?;
        self.check(&response, &[200], "config")?;
        if sha256(response.body()) != digest {
            return Err(malformed("config content does not match its digest"));
        }
        Ok(response.into_body())
    }
    async fn blob_exists(&self, repository: &str, digest: &str) -> Result<bool> {
        let response =
            self.send(&push_scope(repository), Method::HEAD, self.url(repository, &["blobs", digest]), &[], None, "blob").await?;
        if response.status() == 404 {
            return Ok(false);
        }
        // Registries that keep blobs in object storage answer HEAD with a
        // redirect to it; the redirect itself says the blob exists, and we
        // never follow it so our authorization stays on this origin.
        if response.status().is_redirection() {
            return Ok(true);
        }
        self.check(&response, &[200], "blob")?;
        Ok(true)
    }
    fn location(&self, response: &http::Response<Bytes>) -> Result<Url> {
        let location =
            response.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()).ok_or_else(|| malformed("upload without location"))?;
        let url = self.origin.join(location).map_err(|_| malformed("invalid upload location"))?;
        // Upload sessions carry our authorization, so they stay on this registry.
        if !self.same_origin(&url) {
            return Err(malformed("upload location on another origin"));
        }
        Ok(url)
    }
    async fn start_upload(&self, repository: &str) -> Result<Url> {
        let mut url = self.url(repository, &["blobs", "uploads"]);
        url.path_segments_mut().expect("https base").push("");
        let response = self.send(&push_scope(repository), Method::POST, url, &[], Some(Bytes::new()), "upload").await?;
        self.check(&response, &[202], "upload")?;
        self.location(&response)
    }
    async fn finish_upload(&self, repository: &str, mut location: Url, digest: &str, body: Bytes) -> Result<()> {
        location.query_pairs_mut().append_pair("digest", digest);
        let headers = [(header::CONTENT_TYPE, "application/octet-stream".to_owned())];
        let response = self.send(&push_scope(repository), Method::PUT, location, &headers, Some(body), "upload").await?;
        self.check(&response, &[201], "upload")
    }
    /// Uploads a small blob in one request unless the registry already has it.
    pub async fn put_blob(&self, repository: &str, digest: &str, body: Bytes) -> Result<()> {
        if self.blob_exists(repository, digest).await? {
            return Ok(());
        }
        let location = self.start_upload(repository).await?;
        self.finish_upload(repository, location, digest, body).await
    }
    pub async fn put_manifest(&self, repository: &str, tag: &str, composed: &Composed) -> Result<()> {
        let headers = [(header::CONTENT_TYPE, composed.media_type.clone())];
        let url = self.url(repository, &["manifests", tag]);
        let response = self
            .send(&push_scope(repository), Method::PUT, url, &headers, Some(Bytes::from(composed.manifest.clone())), "manifest")
            .await?;
        self.check(&response, &[201], "manifest")?;
        match response.headers().get("docker-content-digest").and_then(|v| v.to_str().ok()) {
            Some(digest) if digest != composed.digest => Err(malformed("registry stored a different manifest digest")),
            _ => Ok(()),
        }
    }
    /// Whether a pull of this manifest by digest succeeds yet.
    pub async fn manifest_visible(&self, repository: &str, digest: &str) -> Result<bool> {
        let accept = [OCI_MANIFEST, DOCKER_MANIFEST].join(", ");
        let url = self.url(repository, &["manifests", digest]);
        let response = self.send(&push_scope(repository), Method::HEAD, url, &[(header::ACCEPT, accept)], None, "manifest").await?;
        if response.status() == 404 {
            return Ok(false);
        }
        self.check(&response, &[200], "manifest")?;
        Ok(true)
    }
}
fn pull_scope(repository: &str) -> String {
    format!("repository:{repository}:pull")
}
fn push_scope(repository: &str) -> String {
    format!("repository:{repository}:pull,push")
}
/// `key="value", key=value` pairs from a WWW-Authenticate challenge.
fn challenge_params(params: &str) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    let mut rest = params.trim();
    while let Some((key, after)) = rest.split_once('=') {
        let key = key.trim().trim_start_matches(',').trim().to_ascii_lowercase();
        let (value, after) = match after.strip_prefix('"') {
            Some(quoted) => quoted.split_once('"').unwrap_or((quoted, "")),
            None => after.split_once(',').unwrap_or((after, "")),
        };
        result.insert(key, value.trim().to_owned());
        rest = after.trim_start().trim_start_matches(',');
    }
    result
}

/// Copies one blob between registries in bounded chunks: ranged reads from the
/// source, a chunked upload session at the target. Each request moves at most
/// `chunk` bytes, so its duration is bounded however large the layer is. The
/// stream is verified against its digest before the upload is committed.
pub async fn copy_blob(
    source: &Registry,
    source_repository: &str,
    target: &Registry,
    target_repository: &str,
    layer: &Descriptor,
    chunk: u64,
) -> Result<()> {
    if target.blob_exists(target_repository, &layer.digest).await? {
        return Ok(());
    }
    let mut location = target.start_upload(target_repository).await?;
    let mut hasher = Sha256::new();
    let mut offset = 0;
    let url = source.url(source_repository, &["blobs", &layer.digest]);
    while offset < layer.size {
        let end = (offset + chunk).min(layer.size) - 1;
        let range = [(header::RANGE, format!("bytes={offset}-{end}"))];
        let response = source.get(&pull_scope(source_repository), url.clone(), &range, "blob").await?;
        source.check(&response, &[200, 206], "blob")?;
        // A registry may ignore Range and send the whole blob; accept that only
        // when the whole blob fits one bounded request.
        let bytes = match response.status().as_u16() {
            200 if offset == 0 && layer.size <= chunk => response.into_body(),
            206 => response.into_body(),
            _ => return Err(malformed("registry ignored a ranged blob read")),
        };
        if bytes.is_empty() || offset + bytes.len() as u64 > layer.size {
            return Err(malformed("blob size does not match its descriptor"));
        }
        hasher.update(&bytes);
        let last = offset + bytes.len() as u64 - 1;
        let headers = [(header::CONTENT_TYPE, "application/octet-stream".to_owned()), (header::CONTENT_RANGE, format!("{offset}-{last}"))];
        let response = target.send(&push_scope(target_repository), Method::PATCH, location, &headers, Some(bytes), "upload").await?;
        target.check(&response, &[202], "upload")?;
        location = target.location(&response)?;
        offset = last + 1;
    }
    if format!("sha256:{:x}", hasher.finalize()) != layer.digest {
        return Err(malformed("blob content does not match its digest"));
    }
    target.finish_upload(target_repository, location, &layer.digest, Bytes::new()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::generators as gs;

    fn descriptor(media_type: &str, content: &[u8]) -> Value {
        json!({"mediaType": media_type, "digest": sha256(content), "size": content.len()})
    }
    /// An image built from `layers` (contents), with diff_ids standing in for
    /// the uncompressed digests.
    fn image(media_type: &str, layer_type: &str, layers: &[Vec<u8>], platform: &Platform, history: bool) -> (Manifest, Vec<u8>) {
        let mut config = json!({
            "os": platform.os, "architecture": platform.architecture,
            "config": {"Entrypoint": ["/entry"], "Cmd": ["serve"], "User": "app"},
            "rootfs": {"type": "layers", "diff_ids": layers.iter().map(|l| sha256(&[l.as_slice(), b"tar"].concat())).collect::<Vec<_>>()},
        });
        if history {
            config["history"] = layers.iter().map(|_| json!({"created_by": "base"})).collect();
        }
        let config = serde_json::to_vec(&config).unwrap();
        let config_type = if media_type == DOCKER_MANIFEST {
            "application/vnd.docker.container.image.v1+json"
        } else {
            "application/vnd.oci.image.config.v1+json"
        };
        let manifest = json!({
            "schemaVersion": 2, "mediaType": media_type,
            "config": descriptor(config_type, &config),
            "layers": layers.iter().map(|l| descriptor(layer_type, l)).collect::<Vec<_>>(),
        });
        (Manifest::parse(&serde_json::to_vec(&manifest).unwrap(), None).unwrap(), config)
    }

    // The composed image is the base's layers followed by the tools layer, in
    // the base's manifest family, with the base's runtime configuration intact
    // and a config whose diff_ids grow by exactly the tools layer. Composing the
    // same inputs again yields the same digest. Generator: base layer counts
    // 0..6 (including an empty base), both manifest families for base and
    // tools, with and without history, with and without a referrer subject.
    #[hegel::test]
    fn composed_image_appends_the_tools_layer(tc: hegel::TestCase) {
        let platform = Platform::new("linux", "amd64");
        let families = [(DOCKER_MANIFEST, DOCKER_LAYER_GZIP), (OCI_MANIFEST, OCI_LAYER_GZIP)];
        let (base_type, base_layer_type) = families[usize::from(tc.draw(gs::booleans()))];
        let (tools_type, tools_layer_type) = families[usize::from(tc.draw(gs::booleans()))];
        let count = tc.draw(gs::integers::<usize>().min_value(0).max_value(6));
        // Few distinct contents, so layers repeat as they can in real images.
        let layers: Vec<Vec<u8>> = (0..count).map(|_| vec![tc.draw(gs::integers::<u8>().min_value(0).max_value(3)); 8]).collect();
        let history = tc.draw(gs::booleans());
        let (mut base, base_config) = image(base_type, base_layer_type, &layers, &platform, history);
        let subject = tc.draw(gs::booleans());
        if subject {
            base.json["subject"] = descriptor(OCI_MANIFEST, b"some other image");
        }
        let (tools, tools_config) = image(tools_type, tools_layer_type, &[b"drydock-agent".to_vec()], &platform, false);
        let composed = compose(&base, &base_config, &tools, &tools_config, &platform).unwrap();

        let manifest: Value = serde_json::from_slice(&composed.manifest).unwrap();
        assert_eq!(composed.digest, sha256(&composed.manifest));
        assert_eq!(manifest["mediaType"], base_type);
        assert!(manifest.get("subject").is_none(), "the composed image refers to nothing");
        let mut expected = base.json["layers"].as_array().unwrap().clone();
        let mut tools_layer = tools.json["layers"][0].clone();
        tools_layer["mediaType"] = json!(base_layer_type);
        expected.push(tools_layer);
        assert_eq!(manifest["layers"].as_array().unwrap(), &expected);
        assert_eq!(composed.layers.iter().filter(|(source, _)| *source == Source::Tools).count(), 1);
        assert_eq!(manifest["config"]["digest"], json!(composed.config_digest));
        assert_eq!(composed.config_digest, sha256(&composed.config));

        let config: Value = serde_json::from_slice(&composed.config).unwrap();
        let original: Value = serde_json::from_slice(&base_config).unwrap();
        let tools_original: Value = serde_json::from_slice(&tools_config).unwrap();
        assert_eq!(config["config"], original["config"]);
        let mut diff_ids = original["rootfs"]["diff_ids"].as_array().unwrap().clone();
        diff_ids.extend(tools_original["rootfs"]["diff_ids"].as_array().unwrap().iter().cloned());
        assert_eq!(config["rootfs"]["diff_ids"].as_array().unwrap(), &diff_ids);
        if history {
            assert_eq!(config["history"].as_array().unwrap().len(), count + 1);
        }
        assert_eq!(compose(&base, &base_config, &tools, &tools_config, &platform).unwrap().digest, composed.digest);
    }

    // A base or tools image built for another platform is the typed
    // unsupported-platform refusal, not a malformed-image error.
    #[test]
    fn composition_refuses_other_platforms() {
        let amd = Platform::new("linux", "amd64");
        let arm = Platform::new("linux", "arm64");
        let (good, good_config) = image(OCI_MANIFEST, OCI_LAYER_GZIP, &[b"x".to_vec()], &amd, false);
        let (other, other_config) = image(OCI_MANIFEST, OCI_LAYER_GZIP, &[b"x".to_vec()], &arm, false);
        for (base, base_config, tools, tools_config) in
            [(&other, &other_config, &good, &good_config), (&good, &good_config, &other, &other_config)]
        {
            assert!(matches!(
                compose(base, base_config, tools, tools_config, &amd),
                Err(ProtocolError::ImageRefused { refusal: ImageRefusal::UnsupportedPlatform { platform }, .. }) if platform == amd
            ));
        }
    }

    // Docker Hub short names expand as Docker expands them; other registries
    // are recognised by a dot, port or localhost; only sha256 pins are accepted.
    #[test]
    fn references_are_digest_pinned() {
        let hex = "a".repeat(64);
        let parse = |r: &str| ImageRef::parse(r).map(|i| (i.registry, i.repository));
        assert_eq!(parse(&format!("ubuntu@sha256:{hex}")).unwrap(), ("docker.io".into(), "library/ubuntu".into()));
        assert_eq!(parse(&format!("test/image:1@sha256:{hex}")).unwrap(), ("docker.io".into(), "test/image".into()));
        assert_eq!(parse(&format!("lab.test:5000/crew/image@sha256:{hex}")).unwrap(), ("lab.test:5000".into(), "crew/image".into()));
        assert_eq!(parse(&format!("localhost/image@sha256:{hex}")).unwrap(), ("localhost".into(), "image".into()));
        for invalid in [
            "ubuntu:latest".to_owned(),
            format!("ubuntu@sha256:{}", "a".repeat(63)),
            format!("ubuntu@sha256:{}", "A".repeat(64)),
            format!("Upper/image@sha256:{hex}"),
            format!("ubuntu\nRUN x@sha256:{hex}"),
        ] {
            assert!(ImageRef::parse(&invalid).is_err(), "{invalid}");
        }
    }

    // A pull credential goes to a token realm on the registry's own origin, or
    // to the token service Docker Hub delegates to, and never to anyone else.
    #[test]
    fn realms_receiving_credentials() {
        let http: Arc<dyn HttpClient> = Arc::new(rigging_http_client::ReqwestHttpClient::new());
        let trusted = |registry: &str, realm: &str| {
            Registry::new(http.clone(), registry, None, None).unwrap().realm_trusted(&Url::parse(realm).unwrap())
        };
        assert!(trusted("ghcr.io", "https://ghcr.io/token"));
        assert!(trusted("docker.io", "https://auth.docker.io/token"));
        assert!(!trusted("ghcr.io", "https://auth.docker.io/token"));
        assert!(!trusted("docker.io", "https://auth.docker.io.evil.test/token"));
        assert!(!trusted("lab.test", "https://lab.test:8443/token"));
    }

    /// Answers every request with a fixed status and optional Location,
    /// recording the methods it saw.
    struct Canned(u16, Option<&'static str>, std::sync::Mutex<Vec<String>>);
    #[async_trait::async_trait]
    impl HttpClient for Canned {
        async fn execute(
            &self,
            request: reqwest::Request,
            _: &rigging_http_client::ChannelLabel,
        ) -> std::result::Result<http::Response<Bytes>, String> {
            self.2.lock().unwrap().push(format!("{} {}", request.method(), request.url().path()));
            let mut response = http::Response::builder().status(self.0);
            if let Some(location) = self.1 {
                response = response.header(header::LOCATION, location);
            }
            Ok(response.body(Bytes::new()).unwrap())
        }
    }

    // Registries that keep blobs in object storage answer a blob HEAD with a
    // redirect (#142). That means the blob exists: the upload is skipped and
    // the redirect is not followed.
    #[tokio::test]
    async fn redirected_blob_head_counts_as_present() {
        let digest = sha256(b"layer");
        let canned = Arc::new(Canned(307, Some("https://blobs.example/signed"), Default::default()));
        let registry = Registry::new(canned.clone(), "harbor.test", None, None).unwrap();
        registry.put_blob("proj/repo", &digest, Bytes::from_static(b"layer")).await.unwrap();
        assert_eq!(*canned.2.lock().unwrap(), [format!("HEAD /v2/proj/repo/blobs/{digest}")]);
    }

    // Challenge parameters may be quoted (and contain commas) or bare.
    #[test]
    fn challenge_parameters() {
        let params = challenge_params(r#"realm="https://reg.test/token",service=reg, scope="repository:a:pull,push""#);
        assert_eq!(params["realm"], "https://reg.test/token");
        assert_eq!(params["service"], "reg");
        assert_eq!(params["scope"], "repository:a:pull,push");
    }
}

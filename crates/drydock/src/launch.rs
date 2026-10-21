//! Standalone launch policy: defaults, immutable images and per-vessel SSH keys.
use crate::{
    client::{Client, Error},
    config::{Egress, Provider, Quantity, SizeDefaults},
};
use drydock_protocol::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

/// Build-owned selection point. Issue #53 replaces this interim identifier with
/// the tools image matching the agent build. Today's modules use operator-baked tools.
pub fn build_tools_digest() -> &'static str {
    "operator-baked-agent-v1"
}
#[derive(Clone, Default, Deserialize, Serialize, clap::Args)]
#[serde(deny_unknown_fields)]
pub struct LaunchOptions {
    #[arg(long)]
    pub image: Option<String>,
    #[arg(long)]
    pub cpus: Option<f64>,
    #[arg(long)]
    pub memory: Option<String>,
    #[arg(long)]
    pub disk: Option<String>,
    #[arg(long, value_enum)]
    pub egress: Option<Egress>,
}
impl LaunchOptions {
    pub fn size(&self, provider: &Provider, minimum: &Size) -> Result<Size, String> {
        SizeDefaults {
            cpus: self.cpus.or(provider.size.cpus),
            memory: self.memory.as_ref().map(|s| Quantity::Text(s.clone())).or_else(|| provider.size.memory.clone()),
            disk: self.disk.as_ref().map(|s| Quantity::Text(s.clone())).or_else(|| provider.size.disk.clone()),
        }
        .resolve(minimum)
    }
}
fn refused(reason: impl Into<String>) -> Error {
    Error::Protocol(ProtocolError::Refused { reason: reason.into() })
}
#[async_trait::async_trait]
pub trait ImageResolver: Send + Sync {
    async fn resolve(&self, image: &str) -> Result<String, Error>;
}
/// OCI Distribution manifest lookup. Tokens are held in memory and never logged.
pub struct RegistryResolver {
    http: Arc<dyn rigging_http_client::HttpClient>,
    client: reqwest::Client,
}
impl RegistryResolver {
    pub fn new() -> Result<Self, Error> {
        let client = rigging_tls::client_builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| Error::Transport)?;
        Ok(Self { http: Arc::new(rigging_http_client::ReqwestHttpClient::restricted(None, None).map_err(|_| Error::Transport)?), client })
    }
    pub fn with_http(mut self, http: Arc<dyn rigging_http_client::HttpClient>) -> Self {
        self.http = http;
        self
    }
    async fn send(&self, request: reqwest::RequestBuilder) -> Result<http::Response<bytes::Bytes>, Error> {
        let request = request.build().map_err(|_| Error::InvalidRequest)?;
        self.http
            .execute(request, &rigging_http_client::ChannelLabel::Extra("drydock".into(), "image".into()))
            .await
            .map_err(|_| Error::Transport)
    }
}
#[async_trait::async_trait]
impl ImageResolver for RegistryResolver {
    async fn resolve(&self, image: &str) -> Result<String, Error> {
        let reference = ImageReference::parse(image)?;
        if let Some(digest) = &reference.digest {
            return Ok(format!("{}@{digest}", reference.name));
        }
        let url = format!("https://{}/v2/{}/manifests/{}", reference.registry, reference.repository, reference.tag);
        let accept = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";
        let request = || self.client.get(&url).header("accept", accept);
        let mut response = self.send(request()).await?;
        if response.status() == http::StatusCode::UNAUTHORIZED {
            let challenge = response
                .headers()
                .get("www-authenticate")
                .and_then(|s| s.to_str().ok())
                .ok_or_else(|| refused("registry requires unsupported authentication"))?;
            let challenge = challenge.strip_prefix("Bearer ").ok_or_else(|| refused("registry requires unsupported authentication"))?;
            let fields: std::collections::BTreeMap<_, _> =
                challenge.split(',').filter_map(|s| s.trim().split_once('=')).map(|(k, v)| (k, v.trim_matches('"'))).collect();
            let realm = reqwest::Url::parse(fields.get("realm").ok_or(Error::InvalidResponse)?).map_err(|_| Error::InvalidResponse)?;
            if realm.scheme() != "https" || !realm.username().is_empty() || realm.password().is_some() {
                return Err(Error::InvalidResponse);
            }
            let scope = format!("repository:{}:pull", reference.repository);
            let token = self
                .send(
                    self.client
                        .get(realm)
                        .query(&[("service", fields.get("service").copied().unwrap_or(&reference.registry)), ("scope", &scope)]),
                )
                .await?;
            if !token.status().is_success() {
                return Err(refused("registry token request failed"));
            }
            let token: serde_json::Value = serde_json::from_slice(token.body()).map_err(|_| Error::InvalidResponse)?;
            let token = token.get("token").or_else(|| token.get("access_token")).and_then(|v| v.as_str()).ok_or(Error::InvalidResponse)?;
            response = self.send(request().bearer_auth(token)).await?;
        }
        if !response.status().is_success() {
            return Err(refused(format!("image manifest lookup returned HTTP {}", response.status().as_u16())));
        }
        let digest = format!("sha256:{:x}", Sha256::digest(response.body()));
        if let Some(header) = response.headers().get("docker-content-digest")
            && header.to_str().ok() != Some(&digest)
        {
            return Err(Error::InvalidResponse);
        }
        Ok(format!("{}@{digest}", reference.name))
    }
}
struct ImageReference {
    name: String,
    registry: String,
    repository: String,
    tag: String,
    digest: Option<String>,
}
impl ImageReference {
    fn parse(image: &str) -> Result<Self, Error> {
        if image.is_empty()
            || image.contains("://")
            || image.bytes().any(|c| c.is_ascii_whitespace() || c.is_ascii_control() || matches!(c, b'?' | b'#' | b'\\'))
        {
            return Err(refused("invalid image reference"));
        }
        let (name_tag, digest) = match image.split_once('@') {
            Some((name, d)) if d.strip_prefix("sha256:").is_some_and(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())) => {
                (name, Some(d.to_lowercase()))
            }
            Some(_) => return Err(refused("image digest must be sha256 followed by 64 hex digits")),
            None => (image, None),
        };
        let last = name_tag.rsplit('/').next().unwrap_or_default();
        let (name, tag) = if let Some((_, tag)) = last.split_once(':') {
            (&name_tag[..name_tag.len() - tag.len() - 1], tag)
        } else {
            (name_tag, "latest")
        };
        let (registry, repository) = match name.split_once('/') {
            Some((first, rest)) if first.contains('.') || first.contains(':') || first == "localhost" => {
                (first.to_owned(), rest.to_owned())
            }
            _ => ("registry-1.docker.io".into(), if name.contains('/') { name.into() } else { format!("library/{name}") }),
        };
        if repository.split('/').any(|s| s.is_empty() || s == "." || s == "..") || tag.is_empty() || name.is_empty() {
            return Err(refused("invalid image reference"));
        }
        let valid_repository = repository.split('/').all(|part| {
            part.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && part.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
                && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
        });
        if !valid_repository
            || tag.len() > 128
            || !tag.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
            || tag.starts_with(['.', '-'])
        {
            return Err(refused("invalid image reference"));
        }
        Ok(Self { name: name.into(), registry, repository, tag: tag.into(), digest })
    }
}

pub async fn prepare(
    client: &Client,
    name: &str,
    provider: &Provider,
    minimum: &Size,
    options: &LaunchOptions,
    resolver: &dyn ImageResolver,
) -> Result<(Prepared, Size), Error> {
    let size = options.size(provider, minimum).map_err(refused)?;
    let image =
        options.image.as_deref().or(provider.image.as_deref()).ok_or_else(|| refused("provider needs a default image or --image"))?;
    let image_digest = resolver.resolve(image).await?;
    let prepared = client
        .clone()
        .with_request_timeout(Duration::from_secs(600))
        .prepare(name, &PrepareRequest { size: size.clone(), image_digest, tools_digest: build_tools_digest().into() })
        .await?;
    Ok((prepared, size))
}
pub async fn keypair(directory: &Path) -> Result<(PathBuf, String), Error> {
    crate::local::private_dir(directory).map_err(|_| Error::Transport)?;
    let key = directory.join("id_ed25519");
    let status = tokio::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map_err(|_| refused("ssh-keygen is required to launch"))?;
    if !status.success() {
        return Err(refused("could not generate vessel SSH key"));
    }
    let public = tokio::fs::read_to_string(key.with_extension("pub")).await.map_err(|_| Error::Transport)?;
    Ok((key, public))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::generators as gs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    // OCI registry HTTP boundary stand-in. Enforces Distribution's manifest
    // Accept header and the bearer token exchange before returning manifest bytes.
    struct Registry {
        calls: AtomicUsize,
        corrupt: bool,
    }
    #[async_trait::async_trait]
    impl rigging_http_client::HttpClient for Registry {
        async fn execute(
            &self,
            request: reqwest::Request,
            _: &rigging_http_client::ChannelLabel,
        ) -> Result<http::Response<bytes::Bytes>, String> {
            assert_eq!(request.method(), reqwest::Method::GET);
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let (status, header, body) = match call {
                0 => {
                    assert_eq!(request.url().as_str(), "https://registry-1.docker.io/v2/library/ubuntu/manifests/24.04");
                    assert!(request.headers()["accept"].to_str().unwrap().contains("application/vnd.oci.image.index.v1+json"));
                    (401,Some(("www-authenticate","Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"repository:library/ubuntu:pull\"".to_owned())),b"".to_vec())
                }
                1 => {
                    assert_eq!(request.url().host_str(), Some("auth.docker.io"));
                    let query: std::collections::BTreeMap<_, _> = request.url().query_pairs().into_owned().collect();
                    assert_eq!(query["service"], "registry.docker.io");
                    assert_eq!(query["scope"], "repository:library/ubuntu:pull");
                    (200, None, br#"{"token":"short-lived-test-token"}"#.to_vec())
                }
                2 => {
                    assert_eq!(request.headers()["authorization"], "Bearer short-lived-test-token");
                    let manifest = br#"{"schemaVersion":2,"manifests":[]}"#.to_vec();
                    (
                        200,
                        Some((
                            "docker-content-digest",
                            if self.corrupt {
                                format!("sha256:{}", "0".repeat(64))
                            } else {
                                format!("sha256:{:x}", Sha256::digest(&manifest))
                            },
                        )),
                        manifest,
                    )
                }
                _ => panic!("unexpected retry"),
            };
            let mut response = http::Response::builder().status(status);
            if let Some((key, value)) = header {
                response = response.header(key, value);
            }
            Ok(response.body(body.into()).unwrap())
        }
    }
    // A tag is resolved once at launch to the hash of the manifest bytes. An
    // inconsistent digest header must be refused instead of recording a false pin.
    #[tokio::test]
    async fn registry_tag_resolution_and_digest_validation() {
        for corrupt in [false, true] {
            let registry = Arc::new(Registry { calls: AtomicUsize::new(0), corrupt });
            let resolver = RegistryResolver::new().unwrap().with_http(registry.clone());
            let result = resolver.resolve("ubuntu:24.04").await;
            if corrupt {
                assert!(matches!(result, Err(Error::InvalidResponse)));
            } else {
                assert_eq!(result.unwrap(), format!("ubuntu@sha256:{:x}", Sha256::digest(br#"{"schemaVersion":2,"manifests":[]}"#)));
            }
            assert_eq!(registry.calls.load(Ordering::SeqCst), 3);
        }
    }
    // Pins need no registry call. Explicit generation spans every byte in a
    // SHA-256 digest and registry ports, nested repositories and optional tags.
    #[hegel::test]
    fn pinned_images_are_preserved(tc: hegel::TestCase) {
        let bytes: Vec<u8> = (0..32).map(|_| tc.draw(gs::integers::<u8>())).collect();
        let digest: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let tagged = tc.draw(gs::booleans());
        let input = format!("registry.example:5000/team/image{}@sha256:{digest}", if tagged { ":tag" } else { "" });
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let registry = Arc::new(Registry { calls: AtomicUsize::new(0), corrupt: false });
        let resolver = RegistryResolver::new().unwrap().with_http(registry.clone());
        assert_eq!(runtime.block_on(resolver.resolve(&input)).unwrap(), format!("registry.example:5000/team/image@sha256:{digest}"));
        assert_eq!(registry.calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn malformed_images_are_refused() {
        for image in ["", "-", "a@sha256:bad", "https://registry/image", "a/../b", "a?x", "a:", "a b"] {
            assert!(ImageReference::parse(image).is_err(), "{image}");
        }
    }
}

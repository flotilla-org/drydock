//! Standalone launch policy: defaults, immutable images and per-vessel SSH keys.
use crate::{
    api::ProviderApi,
    client::Error,
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

/// Checked-in tools index, optionally overridden when compiling this build.
/// The pin may be older than this build: the host upgrades after agent hello.
pub fn build_tools_digest() -> Result<&'static str, Error> {
    match env!("DRYDOCK_TOOLS_IMAGE") {
        "unpublished" => Err(refused(
            "the tools image has not been published yet; run the operator tools-image publish workflow and merge its pin PR, or rebuild with DRYDOCK_TOOLS_IMAGE set to a published registry/name@sha256 reference",
        )),
        reference => Ok(reference),
    }
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
    /// OCI os/architecture, for example linux/amd64. Defaults to the provider's
    /// first declared platform.
    #[arg(long)]
    pub platform: Option<Platform>,
    /// How the image reaches the provider: provider_push, registry_pull or
    /// remote_build. Defaults to the provider's first declared image route.
    #[arg(long)]
    pub image_route: Option<ImageRouteKind>,
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
            .map_err(|e| Error::transport(&e))?;
        Ok(Self { http: Arc::new(rigging_http_client::ReqwestHttpClient::restricted(None, None).map_err(Error::Transport)?), client })
    }
    pub fn with_http(mut self, http: Arc<dyn rigging_http_client::HttpClient>) -> Self {
        self.http = http;
        self
    }
    async fn send(&self, request: reqwest::RequestBuilder) -> Result<http::Response<bytes::Bytes>, Error> {
        let request = request.build().map_err(|e| Error::InvalidRequest(drydock_client::chain(&e)))?;
        self.http
            .execute(request, &rigging_http_client::ChannelLabel::Extra("drydock".into(), "image".into()))
            .await
            .map_err(|e| Error::Transport(format!("image registry: {e}")))
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
            let invalid = |reason: &str| Error::InvalidResponse(format!("registry authentication challenge {reason}"));
            let realm = reqwest::Url::parse(fields.get("realm").ok_or_else(|| invalid("has no realm"))?)
                .map_err(|_| invalid("realm is not a URL"))?;
            if realm.scheme() != "https" || !realm.username().is_empty() || realm.password().is_some() {
                return Err(invalid("realm is not a plain https URL"));
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
            let token: serde_json::Value =
                serde_json::from_slice(token.body()).map_err(|e| Error::InvalidResponse(format!("registry token: {e}")))?;
            let token = token
                .get("token")
                .or_else(|| token.get("access_token"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::InvalidResponse("registry token response has no token".into()))?;
            response = self.send(request().bearer_auth(token)).await?;
        }
        if !response.status().is_success() {
            return Err(refused(format!("image manifest lookup returned HTTP {}", response.status().as_u16())));
        }
        let digest = format!("sha256:{:x}", Sha256::digest(response.body()));
        if let Some(header) = response.headers().get("docker-content-digest")
            && header.to_str().ok() != Some(&digest)
        {
            return Err(Error::InvalidResponse(format!("registry manifest digest header does not match {digest}")));
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

/// Where a vessel's agent lives, as the tools image lays it out.
pub const AGENT_EXECUTABLE: &str = "/opt/drydock/drydock-agent";

/// Where a TCP-reached vessel's agent keeps its token, for a module to read
/// back with `drydock-agent --print-token --tcp-token-file`.
pub const AGENT_TCP_TOKEN_FILE: &str = "/run/drydock/tcp-token";

/// The agent's self-bootstrap: a detached singleton supervisor serving the
/// agent's socket, reached by SSH or a relay. Repeating it is harmless.
///
/// With a `tcp_port` it also serves the agent's token-gated TCP listener on
/// loopback there, its token file at [`AGENT_TCP_TOKEN_FILE`], and prints the
/// token; the socket stays last, as the agent's README requires.
pub fn supervise(tcp_port: Option<u16>) -> Vec<String> {
    let mut argv = vec![AGENT_EXECUTABLE.to_owned(), "--supervise".into()];
    if let Some(port) = tcp_port {
        argv.extend(["--tcp".into(), format!("127.0.0.1:{port}"), "--tcp-token-file".into(), AGENT_TCP_TOKEN_FILE.into()]);
        argv.push("--print-token".into());
    }
    argv.extend(["--socket".into(), crate::agent::AGENT_SOCKET.into()]);
    argv
}

/// Upload bootstrap, through the provider's files and exec ports: put `build`
/// in place, unless the vessel is not `fresh` and already holds an agent,
/// then start it. Returns what the start printed, which carries the
/// `drydock-tcp-token` line when the start asks for one. A failure names the
/// step. The exec port reports no exit status, so a start that fails shows as
/// no hello, the caller's proof that the agent runs. The presence check is
/// deliberately weak (any executable file there): the hello replaces an agent
/// that is not this build.
pub(crate) async fn upload_agent(
    api: &dyn ProviderApi,
    provider: &str,
    id: &str,
    build: bytes::Bytes,
    fresh: bool,
    tcp_port: Option<u16>,
) -> Result<Secret, Error> {
    let step = |doing: &'static str| {
        move |error: Error| match error {
            Error::Protocol(error) => Error::Protocol(error.context(doing)),
            Error::Transport(reason) => Error::Transport(format!("{doing}: {reason}")),
            Error::InvalidResponse(reason) => Error::InvalidResponse(format!("{doing}: {reason}")),
            Error::InvalidRequest(reason) => Error::InvalidRequest(format!("{doing}: {reason}")),
            other => other,
        }
    };
    let present = !fresh
        && run(api, provider, id, &["sh", "-c", &format!("if test -x {AGENT_EXECUTABLE}; then echo present; fi")])
            .await
            .map_err(step("look for the vessel agent"))?
            .trim()
            == "present";
    if !present {
        let file = GuestFile { path: AGENT_EXECUTABLE.into(), mode: 0o755 };
        api.put_file(provider, id, &file, build).await.map_err(step("upload the vessel agent"))?;
    }
    let argv = supervise(tcp_port);
    let output =
        run(api, provider, id, &argv.iter().map(String::as_str).collect::<Vec<_>>()).await.map_err(step("start the vessel agent"))?;
    Ok(Secret::new(output))
}
/// A guest command's output, up to 64 KiB, once it has ended.
async fn run(api: &dyn ProviderApi, provider: &str, id: &str, argv: &[&str]) -> Result<String, Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let command = ExecRequest { command: argv.iter().map(|s| s.to_string()).collect() };
    let mut stream = api.exec(provider, id, &command).await?;
    // The command reads nothing.
    let _ = stream.shutdown().await;
    let mut output = Vec::new();
    tokio::time::timeout(Duration::from_secs(60), (&mut stream).take(64 << 10).read_to_end(&mut output))
        .await
        .map_err(|_| Error::Transport("guest command did not end within 60s".into()))?
        .map_err(|e| Error::Transport(format!("guest command output: {e}")))?;
    Ok(String::from_utf8_lossy(&output).into_owned())
}

pub(crate) async fn prepare_request(
    provider: &Provider,
    minimum: &Size,
    options: &LaunchOptions,
    resolver: &dyn ImageResolver,
) -> Result<PrepareRequest, Error> {
    let tools_digest = build_tools_digest()?;
    let size = options.size(provider, minimum).map_err(refused)?;
    let image =
        options.image.as_deref().or(provider.image.as_deref()).ok_or_else(|| refused("provider needs a default image or --image"))?;
    let image_digest = resolver.resolve(image).await?;
    Ok(PrepareRequest {
        size,
        platform: options.platform.clone(),
        route: options.image_route,
        image_pull: None,
        image_digest,
        tools_digest: tools_digest.into(),
    })
}
pub async fn keypair(directory: &Path) -> Result<(PathBuf, String), Error> {
    crate::local::private_dir(directory).map_err(|e| Error::InvalidRequest(format!("key directory: {e}")))?;
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
    let public =
        tokio::fs::read_to_string(key.with_extension("pub")).await.map_err(|e| refused(format!("read vessel SSH public key: {e}")))?;
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
                assert!(matches!(result, Err(Error::InvalidResponse(_))));
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

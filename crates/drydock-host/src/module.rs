//! Rust modules are compiled into a registry, rather than loaded through an unstable Rust ABI.
use crate::EventSink;
use async_trait::async_trait;
use drydock_protocol::*;
use std::{collections::BTreeMap, sync::Arc};

pub type Result<T> = std::result::Result<T, ProtocolError>;
pub fn refused(reason: impl Into<String>) -> ProtocolError {
    ProtocolError::Refused {
        reason: reason.into(),
    }
}

/// A factory creates an independent configured provider. Settings must contain no secrets.
/// Configuration is transactional: factories MUST NOT spawn background observers or
/// publish events here. Start observations lazily on first operation after commit;
/// Provider::drop must cancel any background work it owns.
/// Modules must disable vendor retries, implement idempotency at the vendor, and publish
/// observed billing transitions through the supplied sink (including background observations).
#[async_trait]
pub trait Module: Send + Sync {
    fn version(&self) -> &str;
    async fn configure(
        &self,
        config: &ProviderConfiguration,
        events: EventSink,
    ) -> Result<Box<dyn Provider>>;
}

/// Context supplied to HTTP modules. Direct credentials are refreshed in memory; proxied
/// clients must use this client and placeholder rather than bypassing the supervisor proxy.
#[derive(Clone)]
pub struct Credentials {
    pub mode: CredentialMode,
    pub value: Option<Secret>,
    pub http: reqwest::Client,
}
impl Credentials {
    pub fn new(mode: CredentialMode, ca: Option<&[u8]>) -> Result<Self> {
        let mut builder = rigging_tls::client_builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .retry(reqwest::retry::never());
        if let CredentialMode::Proxied { proxy_url, .. } = &mode {
            builder = builder
                .proxy(reqwest::Proxy::all(proxy_url).map_err(|_| refused("invalid proxy URL"))?);
            if let Some(ca) = ca {
                let certificates = reqwest::Certificate::from_pem_bundle(ca)
                    .map_err(|_| refused("invalid proxy CA"))?;
                if certificates.is_empty() {
                    return Err(refused("proxy CA contains no certificates"));
                }
                for certificate in certificates {
                    builder = builder.add_root_certificate(certificate);
                }
            }
        }
        Ok(Self {
            mode,
            value: None,
            http: builder
                .build()
                .map_err(|_| refused("cannot configure HTTP client"))?,
        })
    }
    pub fn token(&self) -> Option<&Secret> {
        match &self.mode {
            CredentialMode::Direct { .. } => self.value.as_ref(),
            CredentialMode::Proxied {
                placeholder_token, ..
            } => Some(placeholder_token),
        }
    }
}

/// Provider operations are serialized per provider. A returned error is never retried.
/// Capabilities/rate limits are stable for the configured lifetime. Readiness is
/// cached for hello at configuration and after outcomes; refresh clears a missing
/// credential state without waiting on vendor I/O.
/// Credentials are deliberately passed by reference on every call, so rotation is immediate.
/// Stream methods bridge bytes only after authorization and validation have succeeded.
#[async_trait]
pub trait Provider: Send + Sync {
    fn capabilities(&self) -> Capabilities;
    fn readiness(&self, credentials: &Credentials) -> Readiness {
        if credentials.token().is_some() {
            Readiness::Ready
        } else {
            Readiness::MissingCredential {
                reason: "credential not delivered".into(),
            }
        }
    }
    fn rate_limits(&self) -> Vec<RateLimit> {
        vec![]
    }
    async fn prepare(
        &mut self,
        request: PrepareRequest,
        credentials: &Credentials,
    ) -> Result<Prepared>;
    /// The boolean reports a newly created resource (201), versus an existing label (200).
    async fn provision(
        &mut self,
        request: ProvisionRequest,
        credentials: &Credentials,
    ) -> Result<(Sandbox, bool)>;
    async fn list(&mut self, credentials: &Credentials) -> Result<Vec<Sandbox>>;
    async fn inspect(&mut self, id: &str, credentials: &Credentials) -> Result<Sandbox>;
    async fn destroy(&mut self, id: &str, credentials: &Credentials) -> Result<()>;
    async fn reach(&mut self, id: &str, credentials: &Credentials) -> Result<Reach>;
    async fn relay(&mut self, _id: &str, _credentials: &Credentials) -> Result<ByteStream> {
        Err(refused("relay unsupported"))
    }
    async fn exec(
        &mut self,
        _id: &str,
        _request: ExecRequest,
        _credentials: &Credentials,
    ) -> Result<ByteStream> {
        Err(refused("exec unsupported"))
    }
    async fn suspend(&mut self, _id: &str, _credentials: &Credentials) -> Result<ResumeToken> {
        Err(refused("suspend unsupported"))
    }
    async fn resume(
        &mut self,
        _id: &str,
        _token: ResumeToken,
        _credentials: &Credentials,
    ) -> Result<()> {
        Err(refused("resume unsupported"))
    }
    async fn export(&mut self, _id: &str, _credentials: &Credentials) -> Result<Export> {
        Err(refused("export unsupported"))
    }
    async fn usage(&mut self, _period: Period, _credentials: &Credentials) -> Result<Usage> {
        Err(refused("usage unsupported"))
    }
    async fn quota(&mut self, _credentials: &Credentials) -> Result<Quota> {
        Err(refused("quota unsupported"))
    }
}
pub trait AsyncIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncIo for T {}
pub type ByteStream = Box<dyn AsyncIo>;
pub type Registry = BTreeMap<String, Arc<dyn Module>>;

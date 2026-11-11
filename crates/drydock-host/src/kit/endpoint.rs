//! An API that drydock dials itself rather than through the host's HTTPS
//! client: a Unix socket on this machine, or TCP with TLS and a client
//! certificate. Requests still go through [`HttpClient`], HTTP/1.1 on a
//! fresh connection each, and [`Endpoint::upgrade`] takes a connection over
//! for a byte stream. Plain TCP is never dialled.
use super::Vendor;
use crate::module::{ByteStream, HttpClient, Result, refused};
use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, client::conn::http1};
use hyper_util::rt::TokioIo;
use reqwest::{
    Url,
    header::{CONNECTION, HOST, HeaderValue, UPGRADE},
};
use rigging_http_client::ChannelLabel;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use serde::Deserialize;
use std::{io, path::PathBuf, sync::Arc, time::Duration};

/// A request's deadline when it sets none, as the host's HTTPS client has.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The client certificate, its key, and the CA the server's certificate must
/// chain to, as PEM files.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

enum Address {
    Unix(PathBuf),
    Tls { host: String, port: u16, config: Arc<rustls::ClientConfig> },
}

/// One endpoint. Its requests' URLs must have [`Endpoint::base`]'s origin,
/// which names the endpoint and is never resolved.
pub struct Endpoint {
    address: Address,
    base: Url,
}

/// What an upgrade request got.
pub enum Upgrade {
    /// 101: the connection, now the stream the server switched to.
    Switched(ByteStream),
    /// Any other answer, whole.
    Answered(http::Response<Bytes>),
}

impl Endpoint {
    /// `unix://` and an absolute path, without `tls`; or `tcp://host:port`
    /// with it. The TLS files are read now.
    pub fn new(vendor: Vendor, endpoint: &str, tls: Option<&TlsFiles>) -> Result<Self> {
        let invalid = || refused(format!("{vendor} endpoint must be unix:// and an absolute path, or tcp://host:port with tls files"));
        if let Some(path) = endpoint.strip_prefix("unix://") {
            if !path.starts_with('/') {
                return Err(invalid());
            }
            if tls.is_some() {
                return Err(refused(format!("{vendor} takes tls files only with a tcp:// endpoint")));
            }
            let base = Url::parse("http://localhost/").map_err(|_| invalid())?;
            return Ok(Self { address: Address::Unix(path.into()), base });
        }
        let url = Url::parse(endpoint).ok().filter(|u| {
            u.scheme() == "tcp" && matches!(u.path(), "" | "/") && u.query().is_none() && u.username().is_empty() && u.password().is_none()
        });
        let (Some(host), Some(port)) = (url.as_ref().and_then(Url::host_str), url.as_ref().and_then(Url::port)) else {
            return Err(invalid());
        };
        let Some(tls) = tls else {
            return Err(refused(format!("{vendor} reaches a tcp:// endpoint only with TLS and a client certificate")));
        };
        let base = Url::parse(&format!("https://{host}:{port}/")).map_err(|_| invalid())?;
        let host = host.trim_start_matches('[').trim_end_matches(']').to_owned();
        Ok(Self { address: Address::Tls { host, port, config: Arc::new(tls_config(vendor, tls)?) }, base })
    }
    /// The origin every request names.
    pub fn base(&self) -> &Url {
        &self.base
    }
    async fn connect(&self) -> io::Result<ByteStream> {
        match &self.address {
            Address::Unix(path) => Ok(Box::new(tokio::net::UnixStream::connect(path).await?)),
            Address::Tls { host, port, config } => {
                let tcp = tokio::net::TcpStream::connect((host.as_str(), *port)).await?;
                tcp.set_nodelay(true)?;
                let name =
                    ServerName::try_from(host.clone()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not a TLS server name"))?;
                Ok(Box::new(tokio_rustls::TlsConnector::from(config.clone()).connect(name, tcp).await?))
            }
        }
    }
    /// `request` on a new connection, answered once its head arrives.
    async fn exchange(&self, request: reqwest::Request) -> std::result::Result<http::Response<Incoming>, String> {
        let url = request.url();
        if url.origin() != self.base.origin() {
            return Err("request names another endpoint".into());
        }
        let mut builder = http::Request::builder().method(request.method().clone()).uri(&url[url::Position::BeforePath..]);
        for (name, value) in request.headers() {
            builder = builder.header(name, value);
        }
        let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
        builder = builder.header(HOST, authority);
        let body = match request.body() {
            None => Bytes::new(),
            Some(body) => Bytes::copy_from_slice(body.as_bytes().ok_or("a streamed request body")?),
        };
        let request = builder.body(Full::new(body)).map_err(|e| e.to_string())?;
        let stream = self.connect().await.map_err(|e| e.to_string())?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await.map_err(|e| e.to_string())?;
        // The connection ends when the server closes it or `sender` is dropped.
        tokio::spawn(connection.with_upgrades());
        sender.send_request(request).await.map_err(|e| e.to_string())
    }
    /// `request` asking to switch to `protocol`, within its deadline.
    pub async fn upgrade(&self, mut request: reqwest::Request, protocol: &'static str) -> std::result::Result<Upgrade, String> {
        request.headers_mut().insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        request.headers_mut().insert(UPGRADE, HeaderValue::from_static(protocol));
        let deadline = request.timeout().copied().unwrap_or(REQUEST_TIMEOUT);
        let upgrade = async {
            let response = self.exchange(request).await?;
            if response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
                return Ok(Upgrade::Answered(whole(response).await?));
            }
            let stream = hyper::upgrade::on(response).await.map_err(|e| e.to_string())?;
            Ok(Upgrade::Switched(Box::new(TokioIo::new(stream))))
        };
        tokio::time::timeout(deadline, upgrade).await.map_err(|_| "request timed out".to_owned())?
    }
}

async fn whole(response: http::Response<Incoming>) -> std::result::Result<http::Response<Bytes>, String> {
    let (head, body) = response.into_parts();
    let body = body.collect().await.map_err(|e| e.to_string())?.to_bytes();
    Ok(http::Response::from_parts(head, body))
}

#[async_trait]
impl HttpClient for Endpoint {
    async fn execute(&self, request: reqwest::Request, _: &ChannelLabel) -> std::result::Result<http::Response<Bytes>, String> {
        let deadline = request.timeout().copied().unwrap_or(REQUEST_TIMEOUT);
        let answer = async { whole(self.exchange(request).await?).await };
        tokio::time::timeout(deadline, answer).await.map_err(|_| "request timed out".to_owned())?
    }
}

/// The server is checked against `ca` alone, and the client presents `cert`.
fn tls_config(vendor: Vendor, files: &TlsFiles) -> Result<rustls::ClientConfig> {
    let unreadable = |what: &str, path: &PathBuf, error: &dyn std::fmt::Display| {
        refused(format!("{vendor} cannot read the TLS {what} file {}: {error}", path.display()))
    };
    let certificates = |path: &PathBuf, what: &str| -> Result<Vec<CertificateDer<'static>>> {
        let certificates: Vec<_> = CertificateDer::pem_file_iter(path).and_then(|i| i.collect()).map_err(|e| unreadable(what, path, &e))?;
        if certificates.is_empty() { Err(unreadable(what, path, &"it holds no certificate")) } else { Ok(certificates) }
    };
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates(&files.ca, "CA")? {
        roots.add(certificate).map_err(|e| unreadable("CA", &files.ca, &e))?;
    }
    let chain = certificates(&files.cert, "certificate")?;
    let key = PrivateKeyDer::from_pem_file(&files.key).map_err(|e| unreadable("key", &files.key, &e))?;
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| refused(format!("{vendor} TLS: {e}")))?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .map_err(|e| refused(format!("{vendor} TLS client certificate: {e}")))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use drydock_protocol::ProtocolError;

    // A socket takes no TLS, TCP takes nothing without it, and anything
    // else is not an endpoint.
    #[test]
    fn endpoint_forms() {
        let v = Vendor("Test");
        let socket = Endpoint::new(v, "unix:///var/run/docker.sock", None).unwrap();
        assert_eq!(socket.base().as_str(), "http://localhost/");
        let files = TlsFiles { ca: "ca.pem".into(), cert: "cert.pem".into(), key: "key.pem".into() };
        for (endpoint, tls) in [
            ("unix:///var/run/docker.sock", Some(&files)),
            ("unix://docker.sock", None),
            ("tcp://engine.test:2376", None),
            ("tcp://engine.test", None),
            ("http://engine.test:2375", None),
            // TLS files that cannot be read.
            ("tcp://engine.test:2376", Some(&files)),
        ] {
            assert!(matches!(Endpoint::new(v, endpoint, tls), Err(ProtocolError::Refused { .. })), "{endpoint}");
        }
        // A user and password are not an endpoint's, and are refused before the files are read.
        let refused = Endpoint::new(v, "tcp://user:pw@engine.test:2376", Some(&files));
        assert!(matches!(refused, Err(ProtocolError::Refused { reason }) if reason.contains("must be unix://")));
    }
}

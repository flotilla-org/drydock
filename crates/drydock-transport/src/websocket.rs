//! WebSockets whose binary messages carry one byte stream, as a provider's
//! TCP tunnel does: the provider relays each binary frame's payload to a
//! guest TCP port and back. A module dials through a [`WebSocketDialer`], so
//! tests can serve the provider's side in process ([`MemoryDialer`] is one),
//! and reads and writes the tunnel as a [`ByteStream`] through [`stream`].
use crate::{ByteStream, MemoryDialer};
use async_trait::async_trait;
use futures_util::{Sink, Stream};
use std::{
    fmt, io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub use tokio_tungstenite::{self, tungstenite};
use tungstenite::{
    Message,
    client::IntoClientRequest,
    http::{HeaderMap, Uri},
    protocol::frame::coding::CloseCode,
};

pub type WebSocket = tokio_tungstenite::WebSocketStream<ByteStream>;

/// Opening the connection, TLS included, and the upgrade must finish by then.
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
/// The most of a refused upgrade's body a [`DialError`] keeps.
const REFUSAL_BODY_LIMIT: usize = 4096;
/// The most of that body its `Display` shows.
const REFUSAL_DISPLAY_CHARS: usize = 200;
/// The largest message, and frame, accepted from the far end. A tunnel's
/// proxy relays TCP reads, far smaller than this; the bound keeps a peer
/// from making the reader buffer tungstenite's default 64 MiB.
const MAX_INCOMING: usize = 4 << 20;

/// Why a dial failed.
#[derive(Debug)]
pub enum DialError {
    /// The server answered the upgrade request with `status`, not 101; `body`
    /// is the start of its answer, as text.
    Refused { status: u16, body: String },
    /// The connection, TLS or the WebSocket handshake failed.
    Io(io::Error),
}
impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { status, body } if body.is_empty() => write!(f, "upgrade refused with HTTP {status}"),
            // A proxy may echo the request into its answer, so text bound
            // for logs keeps only its start; `body` holds the rest.
            Self::Refused { status, body } => {
                let shown: String = body.chars().take(REFUSAL_DISPLAY_CHARS).collect();
                let more = if shown.len() < body.len() { "…" } else { "" };
                write!(f, "upgrade refused with HTTP {status}: {shown}{more}")
            }
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}
impl std::error::Error for DialError {}
impl From<io::Error> for DialError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<tungstenite::Error> for DialError {
    fn from(error: tungstenite::Error) -> Self {
        match error {
            tungstenite::Error::Http(response) => {
                let body = response.body().as_deref().unwrap_or_default();
                let body = String::from_utf8_lossy(&body[..body.len().min(REFUSAL_BODY_LIMIT)]).trim().to_owned();
                Self::Refused { status: response.status().as_u16(), body }
            }
            other => Self::Io(io_error(other)),
        }
    }
}

/// Opens WebSockets. `headers` join the upgrade request, e.g. the provider's
/// `Authorization`; mark secret values sensitive. A header named there
/// replaces the one WebSocket's own handshake would send under that name.
/// Redirects are not followed: a 3xx answer is [`DialError::Refused`].
#[async_trait]
pub trait WebSocketDialer: Send + Sync {
    async fn dial(&self, url: &str, headers: HeaderMap) -> Result<WebSocket, DialError>;
}

/// The upgrade request for `url` with `headers` added to WebSocket's own.
fn request(url: &str, headers: HeaderMap) -> Result<tungstenite::handshake::client::Request, DialError> {
    let mut request = url.into_client_request().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    request.headers_mut().extend(headers);
    Ok(request)
}
async fn handshake(url: &str, headers: HeaderMap, stream: ByteStream) -> Result<WebSocket, DialError> {
    let config = tungstenite::protocol::WebSocketConfig::default().max_message_size(Some(MAX_INCOMING)).max_frame_size(Some(MAX_INCOMING));
    Ok(tokio_tungstenite::client_async_with_config(request(url, headers)?, stream, Some(config)).await?.0)
}
/// `url` without its query, which may carry a credential, for error text.
fn shown(url: &str) -> &str {
    url.split_once('?').map_or(url, |(base, _)| base)
}

/// Dials `wss://` URLs over TCP, verifying TLS servers as the host's HTTP
/// client does: against the platform's trust store. `ws://` is dialled only
/// to a loopback IP address (not the name `localhost`), so headers such as a provider's key never cross a
/// network in cleartext. No proxy is consulted, and the whole dial is
/// bounded by 30 seconds.
pub struct TlsDialer {
    tls: Arc<rustls::ClientConfig>,
}
impl TlsDialer {
    pub fn new() -> io::Result<Self> {
        use rustls_platform_verifier::BuilderVerifierExt;
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .and_then(|builder| builder.with_platform_verifier())
            .map_err(io::Error::other)?
            .with_no_client_auth();
        // A WebSocket upgrade is an HTTP/1.1 request.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self { tls: Arc::new(config) })
    }
    /// The connection beneath a dial of `url`, whose scheme (in any case)
    /// must be one of `schemes`: TCP, with TLS for `wss://` and `https://`;
    /// `ws://` and `http://` only to a loopback IP address.
    async fn stream(&self, url: &str, schemes: Schemes) -> io::Result<ByteStream> {
        let invalid = |reason: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("{reason}: {}", shown(url)));
        let uri: Uri = url.parse().map_err(|_| invalid("not a URL"))?;
        let scheme = uri.scheme_str().unwrap_or_default().to_ascii_lowercase();
        let (cleartext, tls, refusal) = match schemes {
            Schemes::WebSocket => ("ws", "wss", "not a ws or wss URL"),
            Schemes::Http => ("http", "https", "not an http or https URL"),
        };
        let secure = match scheme.as_str() {
            s if s == tls => true,
            s if s == cleartext => false,
            _ => return Err(invalid(refusal)),
        };
        let host = uri.host().ok_or_else(|| invalid("no host"))?;
        let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
        if !secure && !host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
            return Err(invalid("cleartext only to a loopback IP address"));
        }
        let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
        let tcp = tokio::net::TcpStream::connect((host, port)).await?;
        tcp.set_nodelay(true)?;
        Ok(if secure {
            let name = rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|_| invalid("not a TLS server name"))?;
            Box::new(tokio_rustls::TlsConnector::from(self.tls.clone()).connect(name, tcp).await?)
        } else {
            Box::new(tcp)
        })
    }
    async fn open(&self, url: &str, headers: HeaderMap) -> Result<WebSocket, DialError> {
        let stream = self.stream(url, Schemes::WebSocket).await?;
        handshake(url, headers, stream).await
    }
}

/// The schemes a [`TlsDialer`] connection may be opened for.
#[derive(Clone, Copy)]
enum Schemes {
    /// `ws://` and `wss://`, for [`WebSocketDialer`].
    WebSocket,
    /// `http://` and `https://`, for [`StreamDialer`].
    Http,
}
#[async_trait]
impl WebSocketDialer for TlsDialer {
    async fn dial(&self, url: &str, headers: HeaderMap) -> Result<WebSocket, DialError> {
        match tokio::time::timeout(DIAL_TIMEOUT, self.open(url, headers)).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "websocket dial timed out").into()),
        }
    }
}

/// Every URL dials the one in-process listener, which serves the WebSocket
/// with [`tokio_tungstenite::accept_hdr_async`] and sees the request's URL
/// and headers there.
#[async_trait]
impl WebSocketDialer for MemoryDialer {
    async fn dial(&self, url: &str, headers: HeaderMap) -> Result<WebSocket, DialError> {
        handshake(url, headers, self.connect().await?).await
    }
}

/// Opens the plain byte connection an HTTP request to a URL travels on, for a
/// module whose provider forwards one upgraded request to a guest port and
/// splices the bytes after its 101 (as [`crate::tcp::connect_at`] asks).
/// The rules are [`TlsDialer`]'s for WebSockets: `https://` verified against
/// the platform's trust store, `http://` only to a loopback IP address, no
/// proxy, 30 seconds for the whole connection. Errors never show `url`'s
/// query, which may carry a credential.
#[async_trait]
pub trait StreamDialer: Send + Sync {
    async fn connect(&self, url: &str) -> io::Result<ByteStream>;
}
#[async_trait]
impl StreamDialer for TlsDialer {
    async fn connect(&self, url: &str) -> io::Result<ByteStream> {
        match tokio::time::timeout(DIAL_TIMEOUT, self.stream(url, Schemes::Http)).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "dial timed out")),
        }
    }
}
/// Every URL reaches the one in-process listener.
#[async_trait]
impl StreamDialer for MemoryDialer {
    async fn connect(&self, _url: &str) -> io::Result<ByteStream> {
        MemoryDialer::connect(self).await
    }
}

/// The byte stream `socket` carries in its binary messages, as a provider's
/// TCP tunnel relays them. Each write sends one binary message of at most
/// `max_frame` bytes. The stream ends at a normal close (1000, a going-away
/// 1001 as a shutting-down sandbox may send, or a close without a code) and at a connection dropped without one (1006): a
/// tunnel's proxy need not complete the close handshake. Any other close
/// code, or a text message, is an error. Shutting the stream down sends a
/// normal close; a WebSocket has no half-close, so the peer's half ends too.
/// Writes after the close are `BrokenPipe`.
///
/// A write may only queue its frame: flush before awaiting an answer to it.
pub fn stream(socket: WebSocket, max_frame: usize) -> ByteStream {
    assert!(max_frame > 0, "a tunnel frame carries at least one byte");
    Box::new(Tunnel { socket, max_frame, pending: bytes::Bytes::new(), ended: false })
}

struct Tunnel {
    socket: WebSocket,
    max_frame: usize,
    /// Received bytes the reader has not taken yet.
    pending: bytes::Bytes,
    ended: bool,
}

fn io_error(error: tungstenite::Error) -> io::Error {
    use tungstenite::error::ProtocolError;
    match error {
        tungstenite::Error::Io(error) => error,
        tungstenite::Error::AlreadyClosed
        | tungstenite::Error::ConnectionClosed
        | tungstenite::Error::Protocol(ProtocolError::SendAfterClosing) => {
            io::Error::new(io::ErrorKind::BrokenPipe, "the tunnel is closed")
        }
        other => io::Error::other(other),
    }
}
/// A connection dropped without a close frame (1006): the bytes end there.
fn abnormal_close(error: &tungstenite::Error) -> bool {
    use tungstenite::error::ProtocolError;
    match error {
        tungstenite::Error::Protocol(ProtocolError::ResetWithoutClosingHandshake) => true,
        // TLS ended without close_notify, or TCP mid-frame.
        tungstenite::Error::Io(error) => error.kind() == io::ErrorKind::UnexpectedEof,
        _ => false,
    }
}

impl AsyncRead for Tunnel {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.pending.is_empty() {
            if this.ended {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut this.socket).poll_next(cx)) {
                Some(Ok(Message::Binary(bytes))) => this.pending = bytes,
                // Answered by tungstenite itself, on the next read or write.
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Text(_))) => {
                    this.ended = true;
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "a text message on a byte tunnel")));
                }
                Some(Ok(Message::Close(frame))) => {
                    this.ended = true;
                    if let Some(frame) = frame.filter(|frame| !matches!(frame.code, CloseCode::Normal | CloseCode::Away)) {
                        let reason = format!("tunnel closed with {}: {}", u16::from(frame.code), frame.reason);
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, reason)));
                    }
                }
                None => this.ended = true,
                Some(Err(error)) if abnormal_close(&error) => this.ended = true,
                Some(Err(error)) => {
                    this.ended = true;
                    return Poll::Ready(Err(io_error(error)));
                }
            }
        }
        let n = this.pending.len().min(buf.remaining());
        buf.put_slice(&this.pending.split_to(n));
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Tunnel {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = &mut *self;
        ready!(Pin::new(&mut this.socket).poll_ready(cx)).map_err(io_error)?;
        let n = buf.len().min(this.max_frame);
        Pin::new(&mut this.socket).start_send(Message::Binary(bytes::Bytes::copy_from_slice(&buf[..n]))).map_err(io_error)?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx).map_err(io_error)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match ready!(Pin::new(&mut self.socket).poll_close(cx)) {
            Err(tungstenite::Error::AlreadyClosed) => Poll::Ready(Ok(())),
            result => Poll::Ready(result.map_err(io_error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // A refusal's text for logs shows at most the first 200 characters of
    // the body, marking a cut; the error itself keeps the whole body.
    #[test]
    fn refusal_text_shows_only_the_start_of_the_body() {
        for length in [0, 1, REFUSAL_DISPLAY_CHARS, REFUSAL_DISPLAY_CHARS + 1, REFUSAL_BODY_LIMIT] {
            let body = "é".repeat(length);
            let text = DialError::Refused { status: 401, body: body.clone() }.to_string();
            let shown = text.chars().filter(|c| *c == 'é').count();
            assert_eq!(shown, length.min(REFUSAL_DISPLAY_CHARS), "{length}");
            assert_eq!(text.ends_with('…'), length > REFUSAL_DISPLAY_CHARS, "{length}");
        }
    }
}

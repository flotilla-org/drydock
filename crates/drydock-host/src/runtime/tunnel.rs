//! Runtime's sandbox tunnel as one byte stream: a WebSocket to
//! `/v1/sandboxes/{id}/tunnel` that multiplexes TCP connections to ports on
//! the guest's loopback. Binary frames both ways are a kind byte, a 32-bit
//! big-endian stream number and a payload: the client opens a stream with
//! `o "tcp PORT"`, sends `d` (data), `e` (end of its input) and `c` (close);
//! the server answers `o` when the stream is open, `d`, `e`, `c` with a
//! reason, `l` (sshd's errors) and `a` on stream 0, the count of data bytes
//! the sandbox has taken. At most 1 MiB may be sent beyond the last `a`.
//! Text frames from the server are JSON: `ready` first, `error` before a
//! close on error, and `restart` then `resume` when Runtime's API restarts,
//! after which the client reopens with `?resume=<token>` and carries on.
//! (https://withruntime.com/docs/api#tunnels, 2026-11-03.)
//!
//! One socket carries one stream. A task owns the socket; the stream's
//! writes reach it through an in-memory pipe it reads only while the window
//! has room, and what it receives reaches the stream through a queue that
//! holds at most 1 MiB unread, as Runtime's SDKs do.
use bytes::{Buf, BufMut, Bytes, BytesMut};
use drydock_transport::{
    ByteStream,
    websocket::{DialError, WebSocket, WebSocketDialer, tungstenite::Message, tungstenite::http::HeaderMap},
};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, DuplexStream, ReadBuf},
    sync::mpsc,
};

/// The stream this module opens on each socket.
const STREAM: u32 = 1;
/// Data bytes that may be sent beyond the last acknowledgement.
pub const WINDOW: u64 = 1 << 20;
/// Received bytes the stream may hold unread before it fails.
pub const RECEIVE_LIMIT: usize = 1 << 20;
/// The most data one `d` frame carries.
pub const DATA_FRAME: usize = 64 << 10;
/// `ready`, and the stream's `o`, must arrive by then.
const OPEN_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a resume token is retried, as Runtime's docs ask.
const RESUME_RETRY: Duration = Duration::from_secs(25);

/// Why a tunnel could not be opened.
#[derive(Debug)]
pub enum OpenError {
    /// The upgrade itself: Runtime's refusal, or the connection.
    Dial(DialError),
    /// Runtime's `error` message on the socket: its code and message.
    Refused {
        code: String,
        message: String,
    },
    /// The stream closed before it opened, with Runtime's reason
    /// (`closed` when nothing listens on the port).
    NotOpened {
        reason: String,
    },
    Io(io::Error),
}
impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dial(error) => write!(f, "{error}"),
            Self::Refused { code, message } => write!(f, "{code}: {message}"),
            Self::NotOpened { reason } => write!(f, "the tunnel stream closed before it opened: {reason}"),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}
impl From<io::Error> for OpenError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn frame(kind: u8, stream: u32, payload: &[u8]) -> Message {
    let mut bytes = BytesMut::with_capacity(5 + payload.len());
    bytes.put_u8(kind);
    bytes.put_u32(stream);
    bytes.put_slice(payload);
    Message::Binary(bytes.freeze())
}
/// A binary frame's kind, stream and payload; None when shorter than a header.
pub fn parse(mut bytes: Bytes) -> Option<(u8, u32, Bytes)> {
    if bytes.len() < 5 {
        return None;
    }
    let kind = bytes.get_u8();
    let stream = bytes.get_u32();
    Some((kind, stream, bytes))
}
fn text(value: Value) -> Message {
    Message::Text(value.to_string().into())
}
fn broken(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, reason.into())
}
/// Runtime's `{"type":"error","error":{code, message}}` as (code, message).
fn server_error(value: &Value) -> (String, String) {
    let error = &value["error"];
    let code = error["code"].as_str().unwrap_or("error").to_owned();
    let message = error["message"].as_str().unwrap_or_default().to_owned();
    (code, message)
}

struct Dial {
    dialer: Arc<dyn WebSocketDialer>,
    url: String,
    headers: HeaderMap,
}
impl Dial {
    /// The socket after its `ready`; `resume` reopens a moved tunnel.
    async fn open(&self, resume: Option<&str>) -> Result<WebSocket, OpenError> {
        let url = match resume {
            Some(token) => format!("{}?resume={}", self.url, url::form_urlencoded::byte_serialize(token.as_bytes()).collect::<String>()),
            None => self.url.clone(),
        };
        let mut socket = self.dialer.dial(&url, self.headers.clone()).await.map_err(OpenError::Dial)?;
        let ready = async {
            loop {
                match socket.next().await {
                    Some(Ok(Message::Text(message))) => {
                        let value: Value = serde_json::from_str(&message).unwrap_or(Value::Null);
                        match value["type"].as_str() {
                            Some("ready") => return Ok(()),
                            Some("error") => {
                                let (code, message) = server_error(&value);
                                return Err(OpenError::Refused { code, message });
                            }
                            _ => {}
                        }
                    }
                    Some(Ok(Message::Close(frame))) => {
                        let reason = frame.map(|f| format!("{}: {}", u16::from(f.code), f.reason)).unwrap_or_default();
                        return Err(OpenError::Io(broken(format!("the tunnel closed before ready {reason}"))));
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => return Err(OpenError::Io(io::Error::other(error))),
                    None => return Err(OpenError::Io(broken("the tunnel ended before ready"))),
                }
            }
        };
        match tokio::time::timeout(OPEN_TIMEOUT, ready).await {
            Ok(result) => result.map(|()| socket),
            Err(_) => Err(OpenError::Io(io::Error::new(io::ErrorKind::TimedOut, "no ready from Runtime's tunnel"))),
        }
    }
}

/// Opens a tunnel to `port` on the guest's loopback through `url` (the
/// sandbox's `/tunnel`, with `headers` carrying the key) and returns it once
/// Runtime reports the stream open.
pub async fn open(dialer: Arc<dyn WebSocketDialer>, url: String, headers: HeaderMap, port: u16) -> Result<ByteStream, OpenError> {
    let dial = Dial { dialer, url, headers };
    let mut socket = dial.open(None).await?;
    socket.send(frame(b'o', STREAM, format!("tcp {port}").as_bytes())).await.map_err(io::Error::other)?;
    let mut acked = 0u64;
    let opened = async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Binary(bytes))) => match parse(bytes) {
                    Some((b'o', STREAM, _)) => return Ok(()),
                    Some((b'c', STREAM, reason)) => {
                        return Err(OpenError::NotOpened { reason: String::from_utf8_lossy(&reason).into_owned() });
                    }
                    Some((b'a', 0, count)) if count.len() >= 8 => acked = acked.max((&count[..8]).get_u64()),
                    _ => {}
                },
                Some(Ok(Message::Text(message))) => {
                    let value: Value = serde_json::from_str(&message).unwrap_or(Value::Null);
                    if value["type"] == "error" {
                        let (code, message) = server_error(&value);
                        return Err(OpenError::Refused { code, message });
                    }
                }
                Some(Ok(Message::Close(_))) | None => return Err(OpenError::Io(broken("the tunnel closed before the stream opened"))),
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(OpenError::Io(io::Error::other(error))),
            }
        }
    };
    match tokio::time::timeout(OPEN_TIMEOUT, opened).await {
        Ok(result) => result?,
        Err(_) => return Err(OpenError::Io(io::Error::new(io::ErrorKind::TimedOut, "Runtime's tunnel did not open the stream"))),
    }
    let (near, far) = tokio::io::duplex(DATA_FRAME);
    let (incoming, received) = mpsc::unbounded_channel();
    let unread = Arc::new(AtomicUsize::new(0));
    let task = Task { dial, socket, outgoing: far, incoming, unread: unread.clone(), sent: 0, acked, input_ended: false, restart: None };
    tokio::spawn(task.run());
    Ok(Box::new(Tunnel { writer: near, received, unread, pending: Bytes::new(), ended: false }))
}

/// A restart in progress: replying stops our sends until the resume.
#[derive(Default)]
struct Restart {
    token: Option<String>,
    replay: Option<String>,
}

struct Task {
    dial: Dial,
    socket: WebSocket,
    /// The stream's writes.
    outgoing: DuplexStream,
    /// Received data, an empty chunk at the end of output, or the error that ended it.
    incoming: mpsc::UnboundedSender<io::Result<Bytes>>,
    unread: Arc<AtomicUsize>,
    /// Data bytes sent, and the most the sandbox has acknowledged taking.
    sent: u64,
    acked: u64,
    input_ended: bool,
    restart: Option<Restart>,
}
/// What ends the task.
enum End {
    /// The stream's reader is gone: close the stream and the socket.
    Dropped,
    /// Runtime closed the stream or the socket; the reader has been told.
    Closed,
}
impl Task {
    async fn run(mut self) {
        let end = self.relay().await;
        if let End::Dropped = end {
            let _ = self.socket.send(frame(b'c', STREAM, b"")).await;
        }
        let _ = self.socket.close(None).await;
    }
    fn deliver(&self, item: io::Result<Bytes>) {
        let _ = self.incoming.send(item);
    }
    async fn relay(&mut self) -> End {
        let mut buffer = vec![0u8; DATA_FRAME];
        loop {
            let room = WINDOW.saturating_sub(self.sent.saturating_sub(self.acked));
            let sending = self.restart.is_none() && !self.input_ended && room > 0;
            let limit = (room as usize).min(DATA_FRAME);
            tokio::select! {
                message = self.socket.next() => match self.receive(message).await {
                    Ok(None) => {}
                    Ok(Some(end)) => return end,
                    Err(error) => {
                        self.deliver(Err(error));
                        return End::Closed;
                    }
                },
                read = self.outgoing.read(&mut buffer[..limit]), if sending => {
                    let sent = match read {
                        Ok(0) | Err(_) => {
                            self.input_ended = true;
                            self.socket.send(frame(b'e', STREAM, b"")).await
                        }
                        Ok(n) => {
                            self.sent += n as u64;
                            self.socket.send(frame(b'd', STREAM, &buffer[..n])).await
                        }
                    };
                    if let Err(error) = sent {
                        // A restart's close may race our send; the socket's next message says which.
                        tracing::debug!(%error, "tunnel send failed");
                    }
                }
                () = self.incoming.closed() => return End::Dropped,
            }
        }
    }
    /// One message from the socket: Some when it ends the stream.
    async fn receive(
        &mut self,
        message: Option<Result<Message, drydock_transport::websocket::tungstenite::Error>>,
    ) -> io::Result<Option<End>> {
        let message = match message {
            Some(Ok(message)) => message,
            // A dropped connection mid-restart still resumes with the token we hold.
            Some(Err(_)) | None if self.resume_token().is_some() => return self.resume().await.map(|()| None),
            Some(Err(error)) => return Err(io::Error::other(format!("Runtime's tunnel failed: {error}"))),
            None => return Err(broken("Runtime's tunnel ended without closing the stream")),
        };
        match message {
            Message::Binary(bytes) => match parse(bytes) {
                Some((b'd', STREAM, data)) => {
                    let unread = self.unread.fetch_add(data.len(), Ordering::AcqRel) + data.len();
                    if unread > RECEIVE_LIMIT {
                        self.deliver(Err(broken("tunnel_receive_overflow: more than 1 MiB of the tunnel's output went unread")));
                        return Ok(Some(End::Dropped));
                    }
                    self.deliver(Ok(data));
                }
                Some((b'e', STREAM, _)) => self.deliver(Ok(Bytes::new())),
                Some((b'c', STREAM, reason)) => {
                    let reason = String::from_utf8_lossy(&reason).into_owned();
                    if reason.is_empty() || reason == "closed" {
                        self.deliver(Ok(Bytes::new()));
                    } else {
                        self.deliver(Err(broken(format!("Runtime closed the tunnel stream: {reason}"))));
                    }
                    return Ok(Some(End::Closed));
                }
                Some((b'a', 0, count)) if count.len() >= 8 => self.acked = self.acked.max((&count[..8]).get_u64()),
                _ => {}
            },
            Message::Text(message) => {
                let value: Value = serde_json::from_str(&message).unwrap_or(Value::Null);
                match value["type"].as_str() {
                    Some("restart") => {
                        // Stop sending; what the stream writes meanwhile waits in the pipe.
                        self.restart = Some(Restart::default());
                        self.socket.send(text(json!({"type": "restart"}))).await.map_err(io::Error::other)?;
                    }
                    Some("resume") => {
                        let restart = self.restart.get_or_insert_with(Restart::default);
                        restart.token = value["token"].as_str().map(str::to_owned);
                        restart.replay = value["replay"].as_str().filter(|r| !r.is_empty()).map(str::to_owned);
                    }
                    Some("error") => {
                        let (code, message) = server_error(&value);
                        return Err(broken(format!("Runtime's tunnel: {code}: {message}")));
                    }
                    _ => {}
                }
            }
            Message::Close(frame) => {
                if self.resume_token().is_some() {
                    self.resume().await?;
                    return Ok(None);
                }
                return match frame {
                    Some(frame) if u16::from(frame.code) != 1000 => {
                        Err(broken(format!("Runtime's tunnel closed with {}: {}", u16::from(frame.code), frame.reason)))
                    }
                    _ => {
                        self.deliver(Ok(Bytes::new()));
                        Ok(Some(End::Closed))
                    }
                };
            }
            _ => {}
        }
        Ok(None)
    }
    fn resume_token(&self) -> Option<&str> {
        self.restart.as_ref().and_then(|r| r.token.as_deref())
    }
    /// Reopens the moved tunnel with its token, retrying for 25 seconds, and
    /// sends back the input Runtime had not yet delivered before anything new.
    async fn resume(&mut self) -> io::Result<()> {
        let restart = self.restart.take().unwrap_or_default();
        let token = restart.token.unwrap_or_default();
        let deadline = tokio::time::Instant::now() + RESUME_RETRY;
        let socket = loop {
            match self.dial.open(Some(&token)).await {
                Ok(socket) => break socket,
                // A used or altered token never works; anything else may, until the deadline.
                Err(OpenError::Dial(DialError::Refused { status: status @ (400 | 401 | 403 | 404 | 409), body })) => {
                    return Err(broken(format!("Runtime refused to resume the tunnel ({status}): {body}")));
                }
                Err(error) if tokio::time::Instant::now() >= deadline => {
                    return Err(broken(format!("the tunnel could not resume after Runtime's restart: {error}")));
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        };
        self.socket = socket;
        if let Some(replay) = restart.replay {
            self.socket.send(text(json!({"type": "replay", "data": replay}))).await.map_err(io::Error::other)?;
        }
        Ok(())
    }
}

/// The stream's side: reads from the task's queue, writes into its pipe.
struct Tunnel {
    writer: DuplexStream,
    received: mpsc::UnboundedReceiver<io::Result<Bytes>>,
    unread: Arc<AtomicUsize>,
    pending: Bytes,
    ended: bool,
}
impl AsyncRead for Tunnel {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.pending.is_empty() {
            if this.ended {
                return Poll::Ready(Ok(()));
            }
            match ready!(this.received.poll_recv(cx)) {
                Some(Ok(bytes)) if bytes.is_empty() => this.ended = true,
                Some(Ok(bytes)) => this.pending = bytes,
                Some(Err(error)) => {
                    this.ended = true;
                    return Poll::Ready(Err(error));
                }
                None => this.ended = true,
            }
        }
        let n = this.pending.len().min(buf.remaining());
        buf.put_slice(&this.pending.split_to(n));
        this.unread.fetch_sub(n, Ordering::AcqRel);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Tunnel {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }
    /// Ends our input (`e`); the far side's output still arrives.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::generators as gs;

    // A frame's header is its kind byte and big-endian stream number; any
    // payload follows unchanged, and a frame shorter than a header is none.
    #[hegel::test]
    fn frames_round_trip(tc: hegel::TestCase) {
        let kind = tc.draw(gs::sampled_from(vec![b'o', b'd', b'e', b'c', b'a', b'l']));
        let stream = tc.draw(gs::integers::<u32>());
        let payload = tc.draw(gs::vecs(gs::integers::<u8>()).max_size(64));
        let Message::Binary(bytes) = frame(kind, stream, &payload) else { panic!("binary") };
        assert_eq!(bytes[0], kind);
        assert_eq!(&bytes[1..5], stream.to_be_bytes());
        assert_eq!(parse(bytes.clone()), Some((kind, stream, Bytes::from(payload))));
        let short = tc.draw(gs::integers::<usize>().max_value(4));
        assert_eq!(parse(bytes.slice(..short)), None);
    }
}

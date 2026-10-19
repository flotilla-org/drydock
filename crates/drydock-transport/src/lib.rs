//! Bidirectional vessel streams (ADR 0070). No provider or vessel identity lives here.
//!
//! Keep the transport alive while using its streams. Dropping it closes its drivers.
//! `open` may be called concurrently; `accept` has one consumer. Cancellation of an
//! open drops that stream; cancellation of accept never consumes a queued stream.
use async_trait::async_trait;
use std::{
    io,
    sync::{Arc, RwLock, Weak},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
    task::JoinSet,
};

pub mod http2;
mod multiplex;
pub mod native;
pub mod ssh;
mod wire;
pub use wire::{ConnectionKind, Purpose, read_connection_kind};

pub trait RawStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> RawStream for T {}
/// The same Tokio byte-stream shape used by Tender; splice with `copy_bidirectional`.
pub type ByteStream = Box<dyn RawStream>;

pub struct Incoming {
    pub purpose: Purpose,
    pub stream: ByteStream,
}

/// Whether an accept error affects one connection, triggers listener retry, or
/// ends the driver. After Terminal, queued streams may drain before None.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorScope {
    Connection,
    Retrying,
    Terminal,
}
#[derive(Debug)]
pub struct AcceptError {
    pub scope: ErrorScope,
    source: io::Error,
}
impl AcceptError {
    pub(crate) fn new(scope: ErrorScope, source: io::Error) -> Self {
        Self { scope, source }
    }
    pub fn kind(&self) -> io::ErrorKind {
        self.source.kind()
    }
}
impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.scope, self.source)
    }
}
impl std::error::Error for AcceptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn retryable_accept(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::OutOfMemory
    ) || matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE))
}

/// A native two-way connection source. Paths, addresses and authentication belong
/// to the adapter. Each call creates/accepts an independent connection.
#[async_trait]
pub trait Connections: Send + Sync + 'static {
    async fn connect(&self) -> io::Result<ByteStream>;
    /// Must be cancellation-safe: the driver selects this against task completions.
    async fn accept(&self) -> io::Result<ByteStream>;
}

#[async_trait]
trait Open: Send + Sync {
    async fn open(&self) -> io::Result<ByteStream>;
}

/// Limits bound queues and unfinished headers, without coupling active raw streams.
#[derive(Clone, Debug)]
pub struct Limits {
    pub queue: usize,
    pub pending_headers: usize,
    pub max_sessions: usize,
    pub header_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            queue: 64,
            pending_headers: 64,
            max_sessions: 64,
            header_timeout: Duration::from_secs(10),
        }
    }
}
impl Limits {
    fn validate(&self) -> io::Result<()> {
        if self.queue == 0
            || self.pending_headers == 0
            || self.max_sessions == 0
            || self.header_timeout.is_zero()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transport limits must be nonzero",
            ));
        }
        Ok(())
    }
}

struct Driver(tokio::task::AbortHandle);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A clonable concurrent opener for a live Transport. A clone does
/// not replace Transport ownership: keep the Transport alive while using it.
#[derive(Clone)]
pub struct Opener {
    inner: Arc<dyn Open>,
    _driver: Arc<Driver>,
    timeout: Duration,
}
impl Opener {
    pub async fn open(&self, purpose: Purpose) -> io::Result<ByteStream> {
        purpose.validate()?;
        tokio::time::timeout(self.timeout, async {
            let mut stream = self.inner.open().await?;
            wire::write_purpose(&mut stream, &purpose).await?;
            Ok(stream)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "opening vessel stream"))?
    }
}

pub struct Transport {
    pub opener: Opener,
    incoming: mpsc::Receiver<Result<Incoming, AcceptError>>,
}
impl Transport {
    pub async fn open(&self, purpose: Purpose) -> io::Result<ByteStream> {
        self.opener.open(purpose).await
    }
    /// Connection errors discard only that stream. Retrying errors report a
    /// transient listener failure; resource errors back off, connection churn yields.
    /// Retrying notices are best-effort when the incoming queue is full.
    /// Terminal errors end the driver; drain any queued streams until None.
    pub async fn accept(&mut self) -> Result<Option<Incoming>, AcceptError> {
        self.incoming.recv().await.transpose()
    }

    /// Independent native connections. Partial handshakes, established fallback
    /// sessions, and established raw streams have separate lifetimes and limits.
    pub fn native(connections: Arc<dyn Connections>, limits: Limits) -> io::Result<Self> {
        limits.validate()?;
        let (tx, incoming) = mpsc::channel(limits.queue);
        let preferred = Arc::new(RwLock::new(None));
        let fallback = preferred.clone();
        let source = connections.clone();
        let settings = limits.clone();
        let task = tokio::spawn(async move {
            let mut headers: JoinSet<Option<Transport>> = JoinSet::new();
            let mut sessions = JoinSet::new();
            let mut backoff = Duration::from_millis(100);
            let mut churn = 0usize;
            loop {
                tokio::select! {
                    biased;
                    _ = tx.closed() => break,
                    Some(_) = sessions.join_next(), if !sessions.is_empty() => {},
                    Some(result) = headers.join_next(), if !headers.is_empty() => {
                        if let Ok(Some(mut mux)) = result {
                            if sessions.len() >= settings.max_sessions {
                                tracing::warn!(limit = settings.max_sessions, "vessel yamux session refused: session limit");
                                let _ = tx.try_send(Err(AcceptError::new(ErrorScope::Connection, io::Error::other("yamux session limit reached"))));
                                continue;
                            }
                            *fallback.write().unwrap() = Some(Arc::downgrade(&mux.opener.inner));
                            let tx = tx.clone();
                            sessions.spawn(async move {
                                loop {
                                    let item = match mux.accept().await {
                                        Ok(Some(incoming)) => Ok(incoming),
                                        Ok(None) => break,
                                        Err(mut error) => { error.scope = ErrorScope::Connection; Err(error) },
                                    };
                                    if tx.send(item).await.is_err() { break; }
                                }
                            });
                        }
                    },
                    result = source.accept(), if headers.len() < settings.pending_headers => {
                        match result {
                            Ok(mut stream) => {
                                backoff = Duration::from_millis(100);
                                churn = 0;
                                let tx = tx.clone();
                                let settings = settings.clone();
                                headers.spawn(async move {
                                    let kind = tokio::time::timeout(settings.header_timeout, read_connection_kind(&mut stream)).await;
                                    match kind {
                                        Ok(Ok(ConnectionKind::Single)) => receive(stream, tx, settings.header_timeout).await,
                                        Ok(Ok(ConnectionKind::Yamux)) => return Some(Self::yamux_after_preface(stream, false, settings)),
                                        Ok(Err(e)) => { let _ = tx.send(Err(AcceptError::new(ErrorScope::Connection, e))).await; }
                                        Err(_) => { let _ = tx.send(Err(AcceptError::new(ErrorScope::Connection, io::Error::new(io::ErrorKind::TimedOut, "connection preface")))).await; }
                                    }
                                    None
                                });
                            }
                            Err(e) => {
                                let retry = retryable_accept(&e);
                                let scope = if retry { ErrorScope::Retrying } else { ErrorScope::Terminal };
                                if !retry {
                                    let _ = tx.send(Err(AcceptError::new(scope, e))).await;
                                    break;
                                }
                                let connection_churn = matches!(e.kind(), io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset | io::ErrorKind::Interrupted);
                                // Transient diagnostics are best-effort: a full queue
                                // must not stop listener progress or task reaping.
                                if matches!(tx.try_send(Err(AcceptError::new(scope, e))), Err(mpsc::error::TrySendError::Closed(_))) { break; }
                                if connection_churn {
                                    backoff = Duration::from_millis(100);
                                    churn = churn.saturating_add(1);
                                    if churn >= 8 { tokio::time::sleep(Duration::from_millis(1)).await; }
                                    else { tokio::task::yield_now().await; }
                                } else {
                                    churn = 0;
                                    let delay = backoff;
                                    backoff = (backoff * 2).min(Duration::from_secs(1));
                                    tokio::select! {
                                        _ = tx.closed() => break,
                                        _ = tokio::time::sleep(delay) => {},
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        Ok(Self {
            opener: Opener {
                inner: Arc::new(NativeOpen {
                    connections,
                    preferred,
                }),
                _driver: Arc::new(Driver(task.abort_handle())),
                timeout: limits.header_timeout,
            },
            incoming,
        })
    }

    /// Dial/Relay (or native fallback). The initiator writes the connection
    /// preface. The acceptor reads and validates it before starting yamux.
    pub async fn yamux(
        mut stream: ByteStream,
        initiator: bool,
        limits: Limits,
    ) -> io::Result<Self> {
        limits.validate()?;
        tokio::time::timeout(limits.header_timeout, async {
            if initiator {
                wire::write_connection_kind(&mut stream, ConnectionKind::Yamux).await
            } else if read_connection_kind(&mut stream).await? == ConnectionKind::Yamux {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected yamux connection",
                ))
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "yamux preface"))??;
        Ok(Self::yamux_after_preface(stream, initiator, limits))
    }
}

type Preferred = Arc<RwLock<Option<Weak<dyn Open>>>>;
struct NativeOpen {
    connections: Arc<dyn Connections>,
    preferred: Preferred,
}
#[async_trait]
impl Open for NativeOpen {
    async fn open(&self) -> io::Result<ByteStream> {
        let fallback = self
            .preferred
            .read()
            .unwrap()
            .as_ref()
            .and_then(Weak::upgrade);
        if let Some(fallback) = fallback {
            return fallback.open().await;
        }
        let mut stream = self.connections.connect().await?;
        wire::write_connection_kind(&mut stream, ConnectionKind::Single).await?;
        Ok(stream)
    }
}

async fn receive(
    mut stream: ByteStream,
    tx: mpsc::Sender<Result<Incoming, AcceptError>>,
    timeout: Duration,
) {
    let result = match tokio::time::timeout(timeout, wire::read_purpose(&mut stream)).await {
        Ok(Ok(purpose)) => Ok(Incoming { purpose, stream }),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "stream purpose header",
        )),
    };
    let _ = tx
        .send(result.map_err(|e| AcceptError::new(ErrorScope::Connection, e)))
        .await;
}

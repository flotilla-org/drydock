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

/// A native two-way connection source. Paths, addresses and authentication belong
/// to the adapter. Each call creates/accepts an independent connection.
#[async_trait]
pub trait Connections: Send + Sync + 'static {
    async fn connect(&self) -> io::Result<ByteStream>;
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
    pub header_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            queue: 64,
            pending_headers: 64,
            header_timeout: Duration::from_secs(10),
        }
    }
}
impl Limits {
    fn validate(&self) -> io::Result<()> {
        if self.queue == 0 || self.pending_headers == 0 || self.header_timeout.is_zero() {
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

/// A clonable concurrent stream opener. Retains its transport driver.
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
    incoming: mpsc::Receiver<io::Result<Incoming>>,
}
impl Transport {
    pub async fn open(&self, purpose: Purpose) -> io::Result<ByteStream> {
        self.opener.open(purpose).await
    }
    pub async fn accept(&mut self) -> io::Result<Option<Incoming>> {
        self.incoming.recv().await.transpose()
    }

    /// Independent native connections. Each accepted connection is negotiated on
    /// its own task, so a partial header cannot delay another connection.
    pub fn native(connections: Arc<dyn Connections>, limits: Limits) -> io::Result<Self> {
        limits.validate()?;
        let (tx, incoming) = mpsc::channel(limits.queue);
        let preferred = Arc::new(RwLock::new(None));
        let fallback = preferred.clone();
        let source = connections.clone();
        let settings = limits.clone();
        let task = tokio::spawn(async move {
            let mut headers = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = tx.closed() => break,
                    Some(_) = headers.join_next(), if !headers.is_empty() => {},
                    result = source.accept(), if headers.len() < settings.pending_headers => {
                        match result {
                            Ok(mut stream) => {
                                let tx = tx.clone();
                                let settings = settings.clone();
                                let fallback = fallback.clone();
                                headers.spawn(async move {
                                    let kind = tokio::time::timeout(settings.header_timeout, read_connection_kind(&mut stream)).await;
                                    match kind {
                                        Ok(Ok(ConnectionKind::Single)) => receive(stream, tx, settings.header_timeout).await,
                                        Ok(Ok(ConnectionKind::Yamux)) => {
                                            // Negotiating fallback selects the same yamux session
                                            // for reverse opens, even without native reverse reach.
                                            if let Ok(mut mux) = Self::yamux_after_preface(stream, false, settings) {
                                                *fallback.write().unwrap() = Some(Arc::downgrade(&mux.opener.inner));
                                                while let Some(item) = mux.incoming.recv().await {
                                                    if tx.send(item).await.is_err() { break; }
                                                }
                                            }
                                        }
                                        Ok(Err(e)) => { let _ = tx.send(Err(e)).await; }
                                        Err(_) => { let _ = tx.send(Err(io::Error::new(io::ErrorKind::TimedOut, "connection preface"))).await; }
                                    }
                                });
                            }
                            Err(e) => { let _ = tx.send(Err(e)).await; break; }
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
        Self::yamux_after_preface(stream, initiator, limits)
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
    tx: mpsc::Sender<io::Result<Incoming>>,
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
    let _ = tx.send(result).await;
}

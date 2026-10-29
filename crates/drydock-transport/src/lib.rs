//! Byte connections between drydock and a vessel's agent, and the HTTP both
//! ends speak on them. No provider or vessel identity lives here.
//!
//! Every connection carries plain HTTP/1.1 or HTTP/2 (h2c) from its first
//! byte. Byte streams travel as upgraded requests on it, so there is no
//! framing of drydock's own and nothing beneath HTTP to multiplex.
use async_trait::async_trait;
use std::io;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
};

pub mod http;
pub mod ssh;

pub trait RawStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> RawStream for T {}
/// The same Tokio byte-stream shape used by Tender; splice with `copy_bidirectional`.
pub type ByteStream = Box<dyn RawStream>;

/// A source of incoming connections. Each accepted connection is independent.
#[async_trait]
pub trait Listener: Send + 'static {
    /// Must be cancellation-safe: callers select it against other work.
    async fn accept(&mut self) -> io::Result<ByteStream>;
}
#[async_trait]
impl Listener for Box<dyn Listener> {
    async fn accept(&mut self) -> io::Result<ByteStream> {
        (**self).accept().await
    }
}
#[async_trait]
impl Listener for tokio::net::UnixListener {
    async fn accept(&mut self) -> io::Result<ByteStream> {
        Ok(Box::new(tokio::net::UnixListener::accept(self).await?.0))
    }
}
#[cfg(target_os = "linux")]
#[async_trait]
impl Listener for tokio_vsock::VsockListener {
    async fn accept(&mut self) -> io::Result<ByteStream> {
        Ok(Box::new(tokio_vsock::VsockListener::accept(self).await?.0))
    }
}

/// Connections in memory, for tests and in-process vessels: each `connect`
/// makes a fresh duplex pair and hands one end to the listener.
pub fn memory() -> (MemoryDialer, MemoryListener) {
    let (tx, rx) = mpsc::channel(64);
    (MemoryDialer(tx), MemoryListener(rx))
}
#[derive(Clone)]
pub struct MemoryDialer(mpsc::Sender<ByteStream>);
impl MemoryDialer {
    pub async fn connect(&self) -> io::Result<ByteStream> {
        let (near, far) = tokio::io::duplex(1 << 16);
        self.0.send(Box::new(far)).await.map_err(|_| io::Error::new(io::ErrorKind::ConnectionRefused, "listener closed"))?;
        Ok(Box::new(near))
    }
}
pub struct MemoryListener(mpsc::Receiver<ByteStream>);
#[async_trait]
impl Listener for MemoryListener {
    async fn accept(&mut self) -> io::Result<ByteStream> {
        self.0.recv().await.ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "every dialer is gone"))
    }
}

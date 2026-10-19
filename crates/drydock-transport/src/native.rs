//! Native connections. The caller owns socket paths and their lifetime. No
//! existing socket is unlinked, and no permissive directory is created here.
use crate::{ByteStream, Connections};
use async_trait::async_trait;
use std::{io, path::PathBuf};
use tokio::net::{UnixListener, UnixStream};

pub struct UnixConnections {
    listener: UnixListener,
    peer: PathBuf,
}
impl UnixConnections {
    pub fn new(listener: UnixListener, peer: impl Into<PathBuf>) -> Self {
        Self { listener, peer: peer.into() }
    }
}
#[async_trait]
impl Connections for UnixConnections {
    async fn connect(&self) -> io::Result<ByteStream> {
        Ok(Box::new(UnixStream::connect(&self.peer).await?))
    }
    async fn accept(&self) -> io::Result<ByteStream> {
        Ok(Box::new(self.listener.accept().await?.0))
    }
}

#[cfg(target_os = "linux")]
pub struct VsockConnections {
    listener: tokio_vsock::VsockListener,
    peer: tokio_vsock::VsockAddr,
}
#[cfg(target_os = "linux")]
impl VsockConnections {
    pub fn new(listener: tokio_vsock::VsockListener, peer: tokio_vsock::VsockAddr) -> Self {
        Self { listener, peer }
    }
}
#[cfg(target_os = "linux")]
#[async_trait]
impl Connections for VsockConnections {
    async fn connect(&self) -> io::Result<ByteStream> {
        Ok(Box::new(tokio_vsock::VsockStream::connect(self.peer).await?))
    }
    async fn accept(&self) -> io::Result<ByteStream> {
        Ok(Box::new(self.listener.accept().await?.0))
    }
}

//! HTTP on one connection. The server speaks HTTP/1.1 and HTTP/2 without TLS
//! (h2c, by prior knowledge) on the same socket, so curl reaches it as readily
//! as drydock does; the client speaks HTTP/2, carrying every request and byte
//! stream of one host on one connection. A byte stream is an upgraded request:
//! an extended CONNECT (RFC 8441) on HTTP/2, `GET` with `Upgrade` on HTTP/1.1.
use crate::ByteStream;
use axum::Router;
use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http2;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
    service::TowerToHyperService,
};
use std::{io, time::Duration};

pub type Client<B = Full<Bytes>> = http2::SendRequest<B>;

/// The `:protocol` (HTTP/2) or `Upgrade` token (HTTP/1.1) of a raw byte stream.
pub const BYTE_STREAM: &str = "drydock-forward";

// Flow-control windows sized for large transfers over slow links. hyper's
// defaults (1 MiB server, 2 MiB client stream windows) cap a transfer at one
// window per round trip. Measured with the agent's link_throughput example
// over a shaped link, uploads went from 51% to 79% of a 100 Mbit/s link at
// 100 ms RTT and from 27% to 66% at 200 ms; hyper's adaptive window reached
// 74% and 53%. A window bounds what a peer may send before the reader drains
// it, so it also bounds per-stream receive buffering. The connection window
// is shared: two streams whose readers stall can hold all of it until they
// drain or are dropped.
const STREAM_WINDOW: u32 = 16 << 20;
const CONNECTION_WINDOW: u32 = 32 << 20;

/// An HTTP/2 client on `stream`. Both ends send keepalive pings every 15
/// seconds with a 30-second acknowledgement deadline, idle links included.
/// The caller owns the returned connection task and aborts it on shutdown.
pub async fn connect<B>(stream: ByteStream) -> io::Result<(Client<B>, tokio::task::JoinHandle<Result<(), hyper::Error>>)>
where
    B: hyper::body::Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (sender, connection) = http2::Builder::new(TokioExecutor::new())
        .initial_stream_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .timer(TokioTimer::new())
        .keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(30))
        .keep_alive_while_idle(true)
        .handshake(TokioIo::new(stream))
        .await
        .map_err(io::Error::other)?;
    Ok((sender, tokio::spawn(connection)))
}

/// Serve `router` for the connection's lifetime, HTTP/1.1 or HTTP/2 as the
/// peer's first bytes say, with upgrades and extended CONNECT enabled.
pub async fn serve(stream: ByteStream, router: Router) -> io::Result<()> {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http2()
        .initial_stream_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .timer(TokioTimer::new())
        .keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(30))
        .enable_connect_protocol();
    builder.serve_connection_with_upgrades(TokioIo::new(stream), TowerToHyperService::new(router)).await.map_err(io::Error::other)
}

/// The byte stream of an upgraded request or response.
pub async fn upgraded(upgrade: hyper::upgrade::OnUpgrade) -> io::Result<ByteStream> {
    Ok(Box::new(TokioIo::new(upgrade.await.map_err(io::Error::other)?)))
}

//! One long-lived HTTP/2 connection per Control/Router stream. Request bodies
//! and routing remain axum/hyper types; raw streams never enter HTTP framing.
use crate::{ByteStream, Incoming, Opener, Purpose};
use axum::Router;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{client::conn::http2, server::conn::http2 as server};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
use std::io;

pub type Client = http2::SendRequest<Full<Bytes>>;

/// Caller owns the returned connection task and should abort it on shutdown.
pub async fn connect(
    opener: &Opener,
    purpose: Purpose,
) -> io::Result<(Client, tokio::task::JoinHandle<Result<(), hyper::Error>>)> {
    require_link(&purpose)?;
    let stream = opener.open(purpose).await?;
    let (sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
        .await
        .map_err(io::Error::other)?;
    Ok((sender, tokio::spawn(connection)))
}

/// Serves the entire lifetime of the link, including concurrent requests.
pub async fn serve(incoming: Incoming, router: Router) -> io::Result<()> {
    require_link(&incoming.purpose)?;
    serve_stream(incoming.stream, router).await
}
async fn serve_stream(stream: ByteStream, router: Router) -> io::Result<()> {
    server::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), TowerToHyperService::new(router))
        .await
        .map_err(io::Error::other)
}
fn require_link(purpose: &Purpose) -> io::Result<()> {
    if !matches!(purpose, Purpose::Control | Purpose::Router) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTP/2 requires a link purpose",
        ));
    }
    Ok(())
}

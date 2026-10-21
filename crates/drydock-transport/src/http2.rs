//! One long-lived HTTP/2 connection per Control stream. Request bodies
//! and routing remain axum/hyper types; raw streams never enter HTTP framing.
use crate::{ByteStream, Incoming, Opener, Purpose};
use axum::Router;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{client::conn::http2, server::conn::http2 as server};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{io, time::Duration};

pub type Client<B = Full<Bytes>> = http2::SendRequest<B>;

/// Caller owns the returned connection task and should abort it on shutdown.
pub async fn connect(opener: &Opener, purpose: Purpose) -> io::Result<(Client, tokio::task::JoinHandle<Result<(), hyper::Error>>)> {
    connect_with_body::<Full<Bytes>>(opener, purpose).await
}

/// Generic-body counterpart for streaming uploads on a link.
pub async fn connect_with_body<B>(
    opener: &Opener,
    purpose: Purpose,
) -> io::Result<(Client<B>, tokio::task::JoinHandle<Result<(), hyper::Error>>)>
where
    B: hyper::body::Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    require_link(&purpose)?;
    let stream = opener.open(purpose).await?;
    let (sender, connection) = http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(30))
        .keep_alive_while_idle(true)
        .handshake(TokioIo::new(stream))
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
        .timer(TokioTimer::new())
        .keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(30))
        .serve_connection(TokioIo::new(stream), TowerToHyperService::new(router))
        .await
        .map_err(io::Error::other)
}
fn require_link(purpose: &Purpose) -> io::Result<()> {
    if !matches!(purpose, Purpose::Control) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "HTTP/2 requires a link purpose"));
    }
    Ok(())
}

use crate::{AcceptError, ByteStream, Driver, ErrorScope, Limits, Open, Opener, Transport, receive};
use async_trait::async_trait;
use futures::future::poll_fn;
use std::{io, sync::Arc};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

type Reply = oneshot::Sender<io::Result<ByteStream>>;
struct MuxOpen(mpsc::Sender<Reply>);
#[async_trait]
impl Open for MuxOpen {
    async fn open(&self) -> io::Result<ByteStream> {
        let (tx, rx) = oneshot::channel();
        self.0.send(tx).await.map_err(|_| closed())?;
        rx.await.map_err(|_| closed())?
    }
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "yamux connection closed")
}
impl Transport {
    pub(crate) fn yamux_after_preface(stream: ByteStream, initiator: bool, limits: Limits) -> Self {
        let mode = if initiator { yamux::Mode::Client } else { yamux::Mode::Server };
        let mut connection = yamux::Connection::new(stream.compat(), yamux::Config::default(), mode);
        let (requests, mut opens) = mpsc::channel::<Reply>(limits.queue);
        let (tx, incoming) = mpsc::channel(limits.queue);
        let timeout = limits.header_timeout;
        let task = tokio::spawn(async move {
            let mut pending: Option<Reply> = None;
            let mut headers = JoinSet::new();
            loop {
                // One owner polls the connection in both directions, including
                // while an outbound open is pending. Never await an application
                // reader here: yamux flow control belongs to individual streams.
                let event = poll_fn(|cx| {
                    if let std::task::Poll::Ready(item) = connection.poll_next_inbound(cx) {
                        return std::task::Poll::Ready((Some(item), None));
                    }
                    if pending.is_some()
                        && let std::task::Poll::Ready(item) = connection.poll_new_outbound(cx)
                    {
                        return std::task::Poll::Ready((None, Some(item)));
                    }
                    std::task::Poll::Pending
                });
                tokio::select! {
                    _ = tx.closed() => break,
                    Some(_) = headers.join_next(), if !headers.is_empty() => {},
                    request = opens.recv(), if pending.is_none() => {
                        match request { Some(reply) => pending = Some(reply), None => break }
                    }
                    (inbound, outbound) = event => {
                        if let Some(item) = inbound {
                            match item {
                                Some(Ok(stream)) => {
                                    if headers.len() < limits.pending_headers {
                                        headers.spawn(receive(Box::new(stream.compat()), tx.clone(), timeout));
                                    } else {
                                        tracing::warn!(limit = limits.pending_headers, "vessel yamux stream refused: unfinished-header limit");
                                    } // Overload resets the new stream, never stalls the driver.
                                }
                                Some(Err(e)) => { let _ = tx.try_send(Err(AcceptError::new(ErrorScope::Terminal, io::Error::other(e)))); break; }
                                None => break,
                            }
                        }
                        if let Some(item) = outbound {
                            let result = item.map(|s| Box::new(s.compat()) as ByteStream).map_err(io::Error::other);
                            let _ = pending.take().unwrap().send(result);
                        }
                    }
                }
            }
        });
        Self { opener: Opener { inner: Arc::new(MuxOpen(requests)), _driver: Arc::new(Driver(task.abort_handle())), timeout }, incoming }
    }
}

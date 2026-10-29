//! Byte streams as upgraded requests: an extended CONNECT with `:protocol`
//! `drydock-forward` on HTTP/2, or `GET` with `Upgrade: drydock-forward` on
//! HTTP/1.1. After the 200 (or 101) the stream carries raw bytes; the agent
//! performs no parsing, header rewriting, token checking or destination policy.
use crate::{
    events::{Event, Events},
    server::Shared,
    *,
};
use axum::{
    extract::{Path, Request, State},
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use drydock_transport::http::{BYTE_STREAM, upgraded};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::oneshot;

/// How long an outward connection waits to be claimed before it is closed.
pub const CLAIM_DEADLINE: Duration = Duration::from_secs(30);

/// The request's upgrade, and the reply that completes it. Anything other
/// than a byte-stream request is refused.
fn upgrade(operation: &str, subject: &str, request: &mut Request) -> Result<(hyper::upgrade::OnUpgrade, Response), AgentError> {
    let connect = request.method() == Method::CONNECT
        && request.extensions().get::<hyper::ext::Protocol>().is_some_and(|protocol| protocol.as_str() == BYTE_STREAM);
    let upgrade = request.method() == Method::GET
        && request
            .headers()
            .get(header::UPGRADE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.split(',').any(|token| token.trim().eq_ignore_ascii_case(BYTE_STREAM)));
    let refused = || {
        AgentError::new(
            operation,
            subject,
            ErrorKind::InvalidInput,
            format!("a byte stream is an extended CONNECT with :protocol {BYTE_STREAM}, or GET with Upgrade: {BYTE_STREAM}"),
        )
    };
    if !connect && !upgrade {
        return Err(refused());
    }
    let on_upgrade = request.extensions_mut().remove::<hyper::upgrade::OnUpgrade>().ok_or_else(refused)?;
    let response = if connect {
        // RFC 9113 section 8.5: a 2xx with no body opens the tunnel.
        StatusCode::OK.into_response()
    } else {
        (StatusCode::SWITCHING_PROTOCOLS, [(header::CONNECTION, "upgrade"), (header::UPGRADE, BYTE_STREAM)]).into_response()
    };
    Ok((on_upgrade, response))
}

/// `CONNECT /forwards/inward/{id}/stream`: one client connection to the
/// forward's target. The reply is 200 only once the target is reached;
/// otherwise it is the structured error of that attempt.
pub(crate) async fn open_inward(
    State(s): State<Arc<Shared>>,
    Path(id): Path<String>,
    mut request: Request,
) -> Result<Response, AgentError> {
    const OP: &str = "forward.inward.open";
    let (on_upgrade, response) = upgrade(OP, &id, &mut request)?;
    let (reached, outcome) = oneshot::channel();
    {
        let mut settings = s.settings.lock().await;
        // Choose the dial policy from the configuration at opening, under
        // configure's lock. Marks belong to sockets; toggles do not rewrite
        // existing streams or retroactively change this choice.
        let marked = settings.config.egress.is_some();
        let target =
            settings.inward.get_mut(&id).ok_or_else(|| AgentError::new(OP, &id, ErrorKind::NotFound, "no inward forward with this ID"))?;
        // Reap finished streams without retaining an unbounded history.
        while target.streams.try_join_next().is_some() {}
        let endpoint = target.endpoint.clone();
        let id = id.clone();
        // The stream belongs to its forward: removing or changing it ends the
        // stream, including while it is still connecting.
        target.streams.spawn(async move {
            let mut destination = match endpoint.connect_marked(marked).await {
                Ok(destination) => destination,
                Err(error) => {
                    let _ = reached.send(Err(AgentError::io(OP, format!("{id}: {endpoint:?}"), error)));
                    return;
                }
            };
            let _ = reached.send(Ok(()));
            let result = match upgraded(on_upgrade).await {
                Ok(mut stream) => tokio::io::copy_bidirectional(&mut stream, &mut destination).await.map(drop),
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                tracing::warn!(%error, forward = %id, "inward stream failed");
            }
        });
    }
    outcome.await.map_err(|_| AgentError::new(OP, &id, ErrorKind::ConnectionAborted, "the forward was removed while opening"))??;
    Ok(response)
}

/// Connections to outward forwards, each held until drydockd claims it.
pub(crate) struct Outward {
    events: Arc<Events>,
    next: AtomicU64,
    pending: Mutex<HashMap<u64, Pending>>,
    deadline: Duration,
}
struct Pending {
    forward: String,
    claim: oneshot::Sender<ByteStream>,
}
/// Forgets a connection whose waiter has gone, claimed or not.
struct Waiting<'a> {
    outward: &'a Outward,
    connection: u64,
}
impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.outward.pending.lock().unwrap().remove(&self.connection);
    }
}
impl Outward {
    pub(crate) fn new(events: Arc<Events>, deadline: Duration) -> Self {
        Self { events, next: AtomicU64::new(1), pending: Mutex::default(), deadline }
    }
    /// Announce a connection to `forward` on `/events` and wait for drydockd
    /// to claim it. The claim's stream is the connection's other end. One not
    /// claimed within the deadline fails with `TimedOut`, and is reported.
    pub(crate) async fn open(&self, forward: &str) -> io::Result<ByteStream> {
        let connection = self.next.fetch_add(1, Ordering::Relaxed);
        let (claim, claimed) = oneshot::channel();
        self.pending.lock().unwrap().insert(connection, Pending { forward: forward.into(), claim });
        let _waiting = Waiting { outward: self, connection };
        self.events.push(Event::OutwardConnection { forward: forward.into(), connection });
        match tokio::time::timeout(self.deadline, claimed).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(_)) => {
                Err(io::Error::new(io::ErrorKind::ConnectionAborted, format!("claim of {forward} connection {connection} failed")))
            }
            Err(_) => {
                let reason = format!("connection {connection} was not claimed within {:?}", self.deadline);
                self.events.push(Event::ForwardFailed { forward: forward.into(), reason: reason.clone() });
                Err(io::Error::new(io::ErrorKind::TimedOut, format!("{forward}: {reason}")))
            }
        }
    }
    fn claim(&self, forward: &str, connection: u64) -> Option<oneshot::Sender<ByteStream>> {
        let mut pending = self.pending.lock().unwrap();
        pending.get(&connection).filter(|waiting| waiting.forward == forward)?;
        pending.remove(&connection).map(|waiting| waiting.claim)
    }
}

/// `CONNECT /forwards/outward/{id}/connections/{n}`: take connection `n`,
/// announced on `/events`. A connection is claimed once.
pub(crate) async fn claim(
    State(s): State<Arc<Shared>>,
    Path((id, connection)): Path<(String, u64)>,
    mut request: Request,
) -> Result<Response, AgentError> {
    const OP: &str = "forward.outward.claim";
    let subject = format!("{id}/{connection}");
    let (on_upgrade, response) = upgrade(OP, &subject, &mut request)?;
    let claim = s
        .outward
        .claim(&id, connection)
        .ok_or_else(|| AgentError::new(OP, &subject, ErrorKind::NotFound, "no connection waiting with this number on this forward"))?;
    tokio::spawn(async move {
        // A failed upgrade drops the claim, which ends the waiting connection.
        match upgraded(on_upgrade).await {
            Ok(stream) => {
                let _ = claim.send(stream);
            }
            Err(error) => tracing::warn!(%error, forward = %id, connection, "outward claim did not upgrade"),
        }
    });
    Ok(response)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Outward connections a stand-in host claims as soon as they are
    /// announced, to a stream connected to `endpoint`, as the client does.
    pub(crate) fn claimed(endpoint: Endpoint) -> Arc<Outward> {
        let events = Arc::new(Events::new("test".into()));
        let outward = Arc::new(Outward::new(events.clone(), CLAIM_DEADLINE));
        let claimer = outward.clone();
        tokio::spawn(async move {
            let mut position = None;
            loop {
                let (records, serial) = events.after(position);
                position = Some(serial);
                for record in records {
                    if let Event::OutwardConnection { forward, connection } = record.event
                        && let Some(claim) = claimer.claim(&forward, connection)
                    {
                        let stream = endpoint.connect_marked(false).await.unwrap();
                        let _ = claim.send(stream);
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        outward
    }
}

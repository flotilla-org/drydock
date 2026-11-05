//! The webhook relay's stream, for one instance: one websocket filtered to its
//! source, resumed from the cursor stored under drydockd's state directory.
use super::*;
use crate::credentials::CredentialSource;
use drydock_transport::websocket::{
    TlsDialer, WebSocket, WebSocketDialer,
    tungstenite::{
        Message,
        http::{HeaderMap, HeaderValue, header},
    },
};
use futures::StreamExt;
use rigging_relay_protocol::{Delivery, StreamFrame};
use std::{path::PathBuf, time::Duration};
use tokio::time::Instant;

/// Seconds between gap-filling lists when a relay is configured.
pub(super) const GAP_POLL_SECONDS: u64 = 300;
const FIRST_RETRY: Duration = Duration::from_secs(1);
const LAST_RETRY: Duration = Duration::from_secs(60);

/// A relay stream an instance reads, as configured.
#[derive(Clone)]
pub(crate) struct Stream {
    url: url::Url,
    source: String,
    token: CredentialLocation,
}
/// The relay stream `events` names, if any, refused when only part of one is given.
pub(crate) fn stream(events: &EventsConfiguration) -> std::result::Result<Option<Stream>, String> {
    let (relay, source, token) = match (&events.relay, &events.source, &events.token) {
        (None, None, None) => return Ok(None),
        (Some(relay), Some(source), Some(token)) => (relay, source, token),
        _ => return Err("events: relay, source and token go together".into()),
    };
    let mut url = url::Url::parse(relay).map_err(|e| format!("events: relay {relay:?}: {e}"))?;
    if !matches!(url.scheme(), "https" | "http") || url.query().is_some() || source.is_empty() {
        return Err("events: relay must be an http(s) URL without a query, and source nonempty".into());
    }
    url.path_segments_mut().map_err(|_| "events: relay URL has no path".to_owned())?.pop_if_empty().push("stream");
    let websocket = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(websocket).map_err(|_| "events: relay URL".to_owned())?;
    if events.poll_seconds == Some(0) {
        return Err("events: poll_seconds must be positive".into());
    }
    Ok(Some(Stream { url, source: source.clone(), token: token.clone() }))
}

/// What the stream says next.
pub(super) enum Next {
    Delivery(Delivery),
    /// Deliveries may have been lost before this cursor: list, then go on from it.
    Gap(u64),
    /// Every delivery up to this cursor has been read.
    Ready(u64),
}

pub(super) struct Reader {
    stream: Stream,
    /// Where the cursor is kept across restarts, when drydockd has a state directory.
    file: Option<PathBuf>,
    /// The last cursor taken in; none until a stream has been read through.
    cursor: Option<u64>,
    /// No cursor to resume from: skip the backlog, which a list stands in for.
    fresh: bool,
    socket: Option<WebSocket>,
    retry_at: Instant,
    retry: Duration,
}
impl Reader {
    pub(super) fn new(stream: Stream, directory: Option<&std::path::Path>, provider: &str) -> Self {
        let name = percent_encoding::utf8_percent_encode(provider, percent_encoding::NON_ALPHANUMERIC);
        let file = directory.map(|d| d.join(format!("{name}.cursor")));
        let cursor = file.as_ref().and_then(|f| std::fs::read_to_string(f).ok()).and_then(|text| text.trim().parse().ok());
        Self { stream, file, cursor, fresh: cursor.is_none(), socket: None, retry_at: Instant::now(), retry: FIRST_RETRY }
    }
    /// Take `cursor` in: what came before it has been applied.
    pub(super) fn commit(&mut self, cursor: u64) {
        self.cursor = Some(cursor);
        self.fresh = false;
        let Some(file) = &self.file else { return };
        let written = file.parent().map_or(Ok(()), std::fs::create_dir_all).and_then(|()| {
            let staged = file.with_extension("cursor.new");
            std::fs::write(&staged, cursor.to_string())?;
            std::fs::rename(&staged, file)
        });
        if let Err(error) = written {
            tracing::warn!(file = %file.display(), %error, "could not store the relay cursor");
        }
    }
    /// Drop the connection; the next read reconnects from the last cursor taken in.
    pub(super) fn reconnect(&mut self) {
        self.socket = None;
        self.retry_at = Instant::now() + self.retry;
        self.retry = (self.retry * 2).min(LAST_RETRY);
    }
    /// The stream's next frame. Cancelling it loses nothing: a read is
    /// resumed, and a dial is started again.
    pub(super) async fn next(&mut self, provider: &str) -> Next {
        loop {
            if self.socket.is_none() {
                tokio::time::sleep_until(self.retry_at).await;
                let cursor = if self.fresh { 0 } else { self.cursor.unwrap_or(0) };
                match dial(&self.stream, cursor).await {
                    Ok(socket) => self.socket = Some(socket),
                    Err(error) => {
                        tracing::warn!(provider, %error, "relay stream unavailable");
                        self.reconnect();
                        continue;
                    }
                }
            }
            let Some(socket) = self.socket.as_mut() else { continue };
            let text = match socket.next().await {
                Some(Ok(Message::Text(text))) => text,
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {
                    tracing::warn!(provider, "relay stream closed");
                    self.reconnect();
                    continue;
                }
                Some(Ok(_)) => continue,
            };
            match serde_json::from_str::<StreamFrame>(text.as_str()) {
                Ok(StreamFrame::Delivery(delivery)) if !self.fresh => return Next::Delivery(delivery),
                Ok(StreamFrame::Gap { latest_cursor, .. }) if !self.fresh => return Next::Gap(latest_cursor),
                Ok(StreamFrame::Ready { cursor }) => {
                    self.retry = FIRST_RETRY;
                    return if self.fresh { Next::Gap(cursor) } else { Next::Ready(cursor) };
                }
                // The relay closes after an error, such as a cursor ahead of
                // its log: start again without one.
                Ok(StreamFrame::Error { message }) => {
                    tracing::warn!(provider, error = %message, "relay refused the stream; reading it afresh");
                    self.fresh = true;
                    self.reconnect();
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(provider, %error, "unreadable relay frame"),
            }
        }
    }
}
/// The stream from just after `cursor`, filtered to the instance's source.
async fn dial(stream: &Stream, cursor: u64) -> std::result::Result<WebSocket, String> {
    let reference = crate::config::credential_reference(&stream.token, &rigging_process::ProcessEnvVars)?;
    let token =
        crate::credentials::BuiltinCredentials::default().resolve(&reference).await.map_err(|_| "relay token unavailable".to_owned())?;
    let mut bearer = HeaderValue::from_str(&format!("Bearer {}", token.value.expose())).map_err(|_| "relay token is not a header value")?;
    bearer.set_sensitive(true);
    let mut url = stream.url.clone();
    url.query_pairs_mut().append_pair("cursor", &cursor.to_string()).append_pair("source", &stream.source);
    let dialer = TlsDialer::new().map_err(|e| e.to_string())?;
    dialer.dial(url.as_str(), HeaderMap::from_iter([(header::AUTHORIZATION, bearer)])).await.map_err(|e| e.to_string())
}

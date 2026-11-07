//! The webhook relay's stream as its README specifies it, standing in for
//! the relay over recorded frames, and the digest resolver the event tests share.
// Each test file uses its own part of it.
#![allow(dead_code)]
use drydock_transport::websocket::tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse, Request, Response},
    },
};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::watch;

pub const TOKEN: &str = "consumer-token";

/// The registry boundary: tags are already digests here.
pub struct Digests;
#[async_trait::async_trait]
impl drydock::launch::ImageResolver for Digests {
    async fn resolve(&self, image: &str) -> Result<String, drydock::client::Error> {
        Ok(image.into())
    }
}

pub fn cursor(frame: &Value) -> u64 {
    frame["cursor"].as_u64().unwrap()
}

/// The relay's stream as its README specifies it, over the recorded
/// deliveries: the backlog after the consumer's cursor, then `ready`, then
/// each delivery as it is published; `gap` for a cursor below the horizon.
#[derive(Clone)]
pub struct Relay {
    pub frames: Arc<Vec<Value>>,
    /// How many recorded frames the relay holds.
    pub published: watch::Sender<usize>,
    /// The newest cursor retention removed.
    pub horizon: Arc<Mutex<u64>>,
    /// Each connection's `cursor` and `source`, in order.
    pub connections: Arc<Mutex<Vec<(u64, String)>>>,
    /// Counts `ready` frames sent.
    pub ready: watch::Sender<usize>,
    /// Closes every open stream.
    pub kick: watch::Sender<usize>,
    /// While true, a new stream waits before sending anything.
    pub hold: watch::Sender<bool>,
}
impl Relay {
    pub async fn serving(frames: Vec<Value>) -> (Self, String) {
        let relay = Self {
            frames: Arc::new(frames),
            published: watch::channel(0).0,
            horizon: Arc::default(),
            connections: Arc::default(),
            ready: watch::channel(0).0,
            kick: watch::channel(0).0,
            hold: watch::channel(false).0,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/i/test", listener.local_addr().unwrap());
        let served = relay.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(served.clone().serve(tcp));
            }
        });
        (relay, url)
    }
    pub fn publish(&self, count: usize) {
        self.published.send_replace(count);
    }
    pub fn latest(&self) -> u64 {
        self.frames[..*self.published.borrow()].last().map_or(1, cursor)
    }
    // tungstenite's callback signature fixes the error type.
    #[allow(clippy::result_large_err)]
    async fn serve(self, tcp: tokio::net::TcpStream) {
        let query = Arc::new(Mutex::new(None));
        let seen = query.clone();
        let check = move |request: &Request, response: Response| -> Result<Response, ErrorResponse> {
            let authorized = request.headers().get("authorization").is_some_and(|v| v == &format!("Bearer {TOKEN}")[..]);
            let url = url::Url::parse(&format!("http://relay{}", request.uri())).unwrap();
            if !authorized || url.path() != "/i/test/stream" {
                let mut refused = ErrorResponse::new(Some("unauthorized".into()));
                *refused.status_mut() = http::StatusCode::UNAUTHORIZED;
                return Err(refused);
            }
            let value = |name: &str| url.query_pairs().find(|(k, _)| k == name).map(|(_, v)| v.into_owned()).unwrap();
            *seen.lock().unwrap() = Some((value("cursor").parse::<u64>().unwrap(), value("source")));
            Ok(response)
        };
        let Ok(mut socket) = accept_hdr_async(tcp, check).await else { return };
        let (mut sent, source) = query.lock().unwrap().clone().unwrap();
        self.connections.lock().unwrap().push((sent, source));
        let _ = self.hold.subscribe().wait_for(|held| !*held).await;
        let mut kick = self.kick.subscribe();
        let send = |frame: &Value| Message::Text(frame.to_string().into());
        let horizon = *self.horizon.lock().unwrap();
        if sent < horizon {
            let latest = self.latest();
            let oldest = self.frames[..*self.published.borrow()].iter().map(cursor).find(|c| *c > horizon);
            let gap = json!({"type": "gap", "oldest_cursor": oldest, "latest_cursor": latest});
            if socket.send(send(&gap)).await.is_err() {
                return;
            }
            sent = latest;
        }
        let mut published = self.published.subscribe();
        let mut first = true;
        loop {
            let count = *published.borrow_and_update();
            let after = sent;
            for frame in self.frames[..count].iter().filter(|f| cursor(f) > after) {
                if socket.send(send(frame)).await.is_err() {
                    return;
                }
                sent = cursor(frame);
            }
            if std::mem::take(&mut first) {
                if socket.send(send(&json!({"type": "ready", "cursor": self.latest()}))).await.is_err() {
                    return;
                }
                self.ready.send_modify(|n| *n += 1);
            }
            tokio::select! {
                biased;
                _ = kick.changed() => return,
                changed = published.changed() => if changed.is_err() { return },
                _ = socket.next() => return,
            }
            if kick.has_changed().unwrap_or(true) {
                return;
            }
        }
    }
    /// Waits for the `n`th `ready` the relay sends.
    pub async fn readied(&self, n: usize) {
        let mut ready = self.ready.subscribe();
        tokio::time::timeout(Duration::from_secs(20), ready.wait_for(|sent| *sent >= n)).await.unwrap().unwrap();
    }
}

//! Vendor events through the webhook relay (drydock#275), through drydockd's
//! public interface. A relay stand-in serves Daytona deliveries recorded from
//! the live relay on 2026-11-05, and the Daytona module reads them; the vendor
//! behind the module's list and provision is a stand-in the test sets.
#![cfg(unix)]
use drydock::{
    HostConnection,
    config::Config,
    daemon::{Daemon, HostOption, ProviderApi, Seams},
};
use drydock_host::module::{ByteStream, Credentials, HttpClient, Module, Operations, Provider, Provisioned, Result as ModuleResult};
use drydock_protocol::*;
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
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
    time::Duration,
};
use tokio::sync::watch;

const ORGANIZATION: &str = "9f88ac62-7a81-4056-8477-a477ab86f0f2";
/// The first recorded run's sandbox: created, stopped, deleted.
const SANDBOX: &str = "0b9b3414-e719-4784-b96d-bb7decdaba51";
const TOKEN: &str = "consumer-token";

fn recorded() -> Vec<Value> {
    serde_json::from_str(include_str!("fixtures/daytona-frames-2026-11-05.json")).unwrap()
}
fn cursor(frame: &Value) -> u64 {
    frame["cursor"].as_u64().unwrap()
}

/// The relay's stream as its README specifies it, over the recorded
/// deliveries: the backlog after the consumer's cursor, then `ready`, then
/// each delivery as it is published; `gap` for a cursor below the horizon.
#[derive(Clone)]
struct Relay {
    frames: Arc<Vec<Value>>,
    /// How many recorded frames the relay holds.
    published: watch::Sender<usize>,
    /// The newest cursor retention removed.
    horizon: Arc<Mutex<u64>>,
    /// Each connection's `cursor` and `source`, in order.
    connections: Arc<Mutex<Vec<(u64, String)>>>,
    /// Counts `ready` frames sent.
    ready: watch::Sender<usize>,
    /// Closes every open stream.
    kick: watch::Sender<usize>,
    /// While true, a new stream waits before sending anything.
    hold: watch::Sender<bool>,
}
impl Relay {
    async fn start() -> (Self, String) {
        let relay = Self {
            frames: Arc::new(recorded()),
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
    fn publish(&self, count: usize) {
        self.published.send_replace(count);
    }
    fn latest(&self) -> u64 {
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
    async fn readied(&self, n: usize) {
        let mut ready = self.ready.subscribe();
        tokio::time::timeout(Duration::from_secs(20), ready.wait_for(|sent| *sent >= n)).await.unwrap().unwrap();
    }
}

/// The vendor behind the module's list and provision, as the test sets it.
#[derive(Default)]
struct Vendor {
    rows: Mutex<Vec<Environment>>,
    lists: AtomicUsize,
}
/// Daytona's own module reads the deliveries and declares Daytona's ways in;
/// everything that would call Daytona answers from the vendor stand-in.
struct Recorded(Arc<Vendor>);
#[async_trait::async_trait]
impl Module for Recorded {
    fn version(&self) -> &str {
        "test"
    }
    async fn configure(&self, name: &str, config: &ProviderConfiguration, http: Arc<dyn HttpClient>) -> ModuleResult<Arc<dyn Provider>> {
        let daytona = ProviderConfiguration {
            module: "daytona".into(),
            settings: serde_json::from_value(json!({"organization_id": ORGANIZATION, "ssh_host_key": "unused"})).unwrap(),
            ..config.clone()
        };
        let daytona = drydock_host::daytona::DaytonaModule.configure(name, &daytona, http).await?;
        Ok(Arc::new(RecordedProvider { name: name.into(), daytona, vendor: self.0.clone() }))
    }
}
struct RecordedProvider {
    name: String,
    daytona: Arc<dyn Provider>,
    vendor: Arc<Vendor>,
}
fn sandbox(provider: &str, state: Observation, vendor: &str) -> Environment {
    Environment {
        id: SANDBOX.into(),
        label: Some("vessel".into()),
        provider: provider.into(),
        state,
        granted_size: Some(Size { cpus: 1.0, memory_bytes: 1 << 30, disk_bytes: 3 << 30 }),
        egress: Enforcement::Advisory,
        platform: None,
        egress_measured: false,
        egress_policy: None,
        timestamp: None,
        vendor: Some(VendorState { state: vendor.into(), reason: None, tags: [(OWNER_TAG.to_owned(), provider.to_owned())].into() }),
    }
}
#[async_trait::async_trait]
impl Provider for RecordedProvider {
    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }
    fn ways_in(&self) -> Vec<WayIn> {
        self.daytona.ways_in()
    }
    fn operations(&self) -> Operations<'_> {
        Operations { events: self.daytona.operations().events, ..Operations::default() }
    }
    fn readiness(&self, _: &Credentials) -> Readiness {
        Readiness::Ready
    }
    async fn prepare(&self, _: PrepareRequest, _: &Credentials) -> ModuleResult<Prepared> {
        unimplemented!()
    }
    /// Daytona answers a create while the sandbox is still being made.
    async fn provision(&self, _: ProvisionRequest, _: &Credentials) -> ModuleResult<Provisioned> {
        let preparing = Observation::Transitioning { phase: TransitionPhase::Preparing };
        Ok(Provisioned::Created(sandbox(&self.name, preparing, "creating")))
    }
    async fn list(&self, _: &Credentials) -> ModuleResult<Vec<Environment>> {
        self.vendor.lists.fetch_add(1, SeqCst);
        Ok(self.vendor.rows.lock().unwrap().clone())
    }
    async fn inspect(&self, _: &str, _: &Credentials) -> ModuleResult<Environment> {
        unimplemented!()
    }
    async fn destroy(&self, _: &str, _: &Credentials) -> ModuleResult<()> {
        unimplemented!()
    }
    async fn reach(&self, _: &str, _: &Credentials) -> ModuleResult<Reach> {
        unimplemented!()
    }
    async fn relay(&self, _: &str, _: &Credentials) -> ModuleResult<ByteStream> {
        unimplemented!()
    }
}

struct Digests;
#[async_trait::async_trait]
impl drydock::launch::ImageResolver for Digests {
    async fn resolve(&self, image: &str) -> Result<String, drydock::client::Error> {
        Ok(image.into())
    }
}

/// A host serving the module, once per test directory.
async fn host(dir: &Path, vendor: &Arc<Vendor>) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.join("host.sock");
    let module = Arc::new(Recorded(vendor.clone())) as Arc<dyn Module>;
    let host = drydock_host::Host::new([("recorded-daytona".to_owned(), module)].into());
    let served = socket.clone();
    tokio::spawn(async move { host.serve_unix(served, std::future::pending()).await.unwrap() });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !socket.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    std::fs::write(dir.join("relay.token"), format!("{TOKEN}\n")).unwrap();
}
/// drydockd with the `daytona` instance reading the relay at `url`, listing
/// only at start: every later observation comes from the relay.
async fn drydockd(dir: &Path, url: &str, ownership: &str) -> Arc<Daemon> {
    let text = format!(
        "[providers.daytona]\nmodule = 'recorded-daytona'\nownership = '{ownership}'\n\
         [providers.daytona.events]\nrelay = '{url}'\nsource = 'daytona'\ntoken = {{ file = '{}' }}\npoll_seconds = 3600\n",
        dir.join("relay.token").display()
    );
    let run = dir.join("run");
    let option =
        HostOption { optional: false, name: "rust".into(), connection: HostConnection::ExternalUnix { path: dir.join("host.sock") } };
    Daemon::start_with_seams(Config::parse(&text).unwrap(), &run, run.join("keys"), vec![option], Seams::new(Arc::new(Digests)))
        .await
        .unwrap()
}

/// Waits for drydockd's first list after a start with no stored cursor: the
/// relay's `ready` then gets a cursor stored once that list is in.
async fn caught_up(relay: &Relay, dir: &Path) {
    relay.readied(1).await;
    let cursor = dir.join("run/events/daytona.cursor");
    tokio::time::timeout(Duration::from_secs(20), async {
        while !cursor.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
/// drydockd's event stream, read past its first snapshot: what follows is new.
async fn subscribe(daemon: &Daemon) -> drydock::api::ObservationStream {
    let mut stream = ProviderApi::observe(daemon, None).await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(20), stream.next()).await.unwrap().unwrap().unwrap();
    assert!(matches!(first, ObserveRecord::Snapshot { .. }), "{first:?}");
    stream
}
/// Events about the recorded sandbox, until `until` holds of one.
async fn events(stream: &mut drydock::api::ObservationStream, until: impl Fn(&Event) -> bool) -> Vec<Event> {
    let mut events = vec![];
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(record) = stream.next().await {
            if let ObserveRecord::Event { event } = record.unwrap()
                && event.id == SANDBOX
            {
                let done = until(&event);
                events.push(event);
                if done {
                    return;
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("events so far: {events:#?}"));
    events
}
fn delivery(event: &Event) -> Option<&str> {
    event.observed.as_ref().and_then(|o| o.delivery_id.as_deref())
}

// Every state change Daytona reports arrives as its own event, the
// transitional ones included, each with Daytona's own state, its timestamp,
// and the delivery it came in. The first update for a sandbox drydockd does
// not know is its creation.
#[tokio::test]
async fn transitions_arrive_as_events_with_the_vendor_state() {
    let dir = tempfile::tempdir().unwrap();
    let vendor = Arc::new(Vendor::default());
    host(dir.path(), &vendor).await;
    let (relay, url) = Relay::start().await;
    let daemon = drydockd(dir.path(), &url, "owned_account").await;
    caught_up(&relay, dir.path()).await;
    let mut stream = subscribe(&daemon).await;
    // The first run: started, stopping, stopped, destroying, destroyed.
    relay.publish(5);
    let events = events(&mut stream, |e| matches!(e.event, EventKind::Gone { .. })).await;
    let frames = recorded();
    let kinds: Vec<_> = events.iter().map(|e| (e.event.clone(), e.vendor.as_ref().unwrap().state.as_str(), delivery(e))).collect();
    let id = |i: usize| frames[i]["delivery_id"].as_str();
    assert_eq!(
        kinds,
        [
            (EventKind::Created, "started", id(0)),
            (EventKind::Transitioning { phase: TransitionPhase::Stopping }, "stopping", id(1)),
            (EventKind::Stopped { cause: StopCause::SuspendedByRequest }, "stopped", id(2)),
            (EventKind::Transitioning { phase: TransitionPhase::Destroying }, "destroying", id(3)),
            (EventKind::Gone { cause: GoneCause::DestroyedAtProvider }, "destroyed", id(4)),
        ]
    );
    for (event, frame) in events.iter().zip(&frames) {
        assert_eq!(event.observed.as_ref().unwrap().way, ObservedWay::Webhook);
        assert_eq!(event.timestamp_source, TimestampSource::Provider);
        assert_eq!(event.timestamp, frame["body"]["updatedAt"].as_str().unwrap().parse().unwrap());
    }
    assert_eq!(relay.connections.lock().unwrap()[0].1, "daytona");
}

// The relay cursor drydockd last took in is stored under its state
// directory: a restarted drydockd resumes from it, reading what the relay
// kept while it was down and nothing it had already read.
#[tokio::test]
async fn restart_resumes_from_the_stored_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let vendor = Arc::new(Vendor::default());
    host(dir.path(), &vendor).await;
    let (relay, url) = Relay::start().await;
    let frames = recorded();
    let daemon = drydockd(dir.path(), &url, "owned_account").await;
    caught_up(&relay, dir.path()).await;
    let mut stream = subscribe(&daemon).await;
    relay.publish(3);
    events(&mut stream, |e| delivery(e) == frames[2]["delivery_id"].as_str()).await;
    drop((stream, daemon));
    // While drydockd is down Daytona destroys the sandbox; until then it lists it stopped.
    *vendor.rows.lock().unwrap() = vec![sandbox("daytona", Observation::Stopped { cause: StopCause::SuspendedByRequest }, "stopped")];
    relay.publish(5);

    relay.hold.send_replace(true);
    let daemon = drydockd(dir.path(), &url, "owned_account").await;
    let mut stream = subscribe(&daemon).await;
    relay.hold.send_replace(false);
    let events = events(&mut stream, |e| matches!(e.event, EventKind::Gone { .. })).await;
    let resumed = relay.connections.lock().unwrap().last().unwrap().0;
    assert_eq!(resumed, cursor(&frames[2]));
    let delivered: Vec<_> = events.iter().filter_map(delivery).collect();
    assert_eq!(delivered, [frames[3]["delivery_id"].as_str().unwrap(), frames[4]["delivery_id"].as_str().unwrap()]);
}

// Deliveries come at least once: when drydockd stops after applying
// deliveries but before storing their cursor, the relay sends them again. What
// is no newer than the row drydockd holds changes nothing.
#[tokio::test]
async fn a_redelivered_event_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let vendor = Arc::new(Vendor::default());
    host(dir.path(), &vendor).await;
    let (relay, url) = Relay::start().await;
    let frames = recorded();
    let daemon = drydockd(dir.path(), &url, "owned_account").await;
    caught_up(&relay, dir.path()).await;
    let mut stream = subscribe(&daemon).await;
    relay.publish(3);
    events(&mut stream, |e| delivery(e) == frames[2]["delivery_id"].as_str()).await;
    drop((stream, daemon));
    // The cursors after the first delivery were never stored; the vendor
    // lists the sandbox stopped, as of the stopped delivery.
    std::fs::write(dir.path().join("run/events/daytona.cursor"), cursor(&frames[0]).to_string()).unwrap();
    let mut stopped = sandbox("daytona", Observation::Stopped { cause: StopCause::SuspendedByRequest }, "stopped");
    stopped.timestamp = Some(frames[2]["body"]["updatedAt"].as_str().unwrap().parse().unwrap());
    *vendor.rows.lock().unwrap() = vec![stopped];
    relay.publish(4);

    relay.hold.send_replace(true);
    let daemon = drydockd(dir.path(), &url, "owned_account").await;
    let mut stream = subscribe(&daemon).await;
    relay.hold.send_replace(false);
    let events = events(&mut stream, |e| matches!(e.event, EventKind::Transitioning { phase: TransitionPhase::Destroying })).await;
    assert_eq!(relay.connections.lock().unwrap().last().unwrap().0, cursor(&frames[0]));
    let delivered: Vec<_> = events.iter().filter_map(delivery).collect();
    assert_eq!(delivered, [frames[3]["delivery_id"].as_str().unwrap()]);
}

// A cursor older than the relay's retention gets a `gap`: deliveries may have
// been lost, so drydockd lists the provider, and what the list shows changed
// is marked as a reconstruction, not as a webhook.
#[tokio::test]
async fn a_gap_yields_a_marked_reconstruction() {
    let dir = tempfile::tempdir().unwrap();
    let vendor = Arc::new(Vendor::default());
    host(dir.path(), &vendor).await;
    let (relay, url) = Relay::start().await;
    let frames = recorded();
    let daemon = drydockd(dir.path(), &url, "owned_account").await;
    caught_up(&relay, dir.path()).await;
    let mut stream = subscribe(&daemon).await;
    relay.publish(1);
    let created = events(&mut stream, |e| matches!(e.event, EventKind::Created)).await;
    assert_eq!(delivery(&created[0]), frames[0]["delivery_id"].as_str());

    // The stream drops; stopping and stopped are kept and then lost to
    // retention before drydockd reconnects. The vendor now lists the sandbox stopped.
    *relay.horizon.lock().unwrap() = cursor(&frames[2]);
    relay.kick.send_modify(|n| *n += 1);
    *vendor.rows.lock().unwrap() = vec![sandbox("daytona", Observation::Stopped { cause: StopCause::SuspendedByRequest }, "stopped")];
    relay.publish(3);
    let events = events(&mut stream, |e| matches!(e.event, EventKind::Stopped { .. })).await;
    let stopped = events.last().unwrap();
    assert_eq!(stopped.observed, Some(ObservedBy { way: ObservedWay::Reconstruction, delivery_id: None }));
    assert_eq!(stopped.vendor.as_ref().unwrap().state, "stopped");
    assert!(events.iter().all(|e| delivery(e) != frames[1]["delivery_id"].as_str()));
    assert_eq!(relay.connections.lock().unwrap().last().unwrap().0, cursor(&frames[0]));
}

// A provision that settles completes when Daytona's own event says the
// sandbox started, without asking the vendor's list: drydockd hears of the
// change through the relay.
#[tokio::test]
async fn a_wait_completes_on_a_webhook_event_without_a_poll() {
    let dir = tempfile::tempdir().unwrap();
    let vendor = Arc::new(Vendor::default());
    host(dir.path(), &vendor).await;
    let (relay, url) = Relay::start().await;
    // A shared account: the sandbox is this instance's because it provisioned it.
    let daemon = drydockd(dir.path(), &url, "shared_account").await;
    caught_up(&relay, dir.path()).await;
    let lists = vendor.lists.load(SeqCst);
    let prepared = Prepared {
        provider: "daytona".into(),
        id: "snapshot".into(),
        platform: Platform::new("linux", "amd64"),
        image_digest: "image".into(),
        tools_digest: "tools".into(),
    };
    let request = ProvisionRequest {
        label: "vessel".into(),
        prepared,
        size: Size { cpus: 1.0, memory_bytes: 1 << 30, disk_bytes: 3 << 30 },
        egress: EgressRequest::Open,
        ssh_public_key: Some("ssh-ed25519 AAAA".into()),
    };
    let provision = tokio::spawn({
        let daemon = daemon.clone();
        async move { ProviderApi::provision(&*daemon, "daytona", &request).await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!provision.is_finished(), "provision answered before the sandbox started");
    relay.publish(1);
    let environment = tokio::time::timeout(Duration::from_secs(20), provision).await.unwrap().unwrap().unwrap().into_inner();
    assert_eq!(environment.state, Observation::Running);
    assert_eq!(environment.vendor.unwrap().state, "started");
    assert_eq!(environment.label.as_deref(), Some("vessel"));
    assert_eq!(vendor.lists.load(SeqCst), lists, "the wait asked for a poll");
}

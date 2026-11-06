//! E2B's lifecycle events through the webhook relay (drydock#286), through
//! drydockd's public interface. A relay stand-in serves E2B deliveries
//! recorded from the live relay on 2026-11-06, and the E2B module reads them;
//! the vendor behind the module's list is a stand-in the test sets.
#![cfg(unix)]
use drydock::{
    HostConnection,
    config::Config,
    daemon::{Daemon, HostOption, ProviderApi, Seams},
};
use drydock_host::module::{ByteStream, Credentials, HttpClient, Module, Operations, Provider, Provisioned, Result as ModuleResult};
use drydock_protocol::*;
use futures::StreamExt;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
#[path = "support/relay.rs"]
mod relay;
use relay::{Digests, Relay, TOKEN, cursor};

/// The team the recorded sandboxes ran in.
const TEAM: &str = "01b5d4bb-e26c-4351-900e-23195a681302";
/// The first sandbox: only its kill was recorded.
const KILLED: &str = "ij793r5ew30fck59if9ts";
/// The second sandbox: created, paused, resumed, killed.
const SANDBOX: &str = "ilxmpejo4q7g46hn2yvww";

/// Relay frames recorded on 2026-11-06, each with E2B's body.
fn recorded() -> Vec<Value> {
    serde_json::from_str(include_str!("fixtures/e2b-frames-2026-11-06.json")).unwrap()
}
/// The second sandbox's frames, in order.
fn lifecycle() -> Vec<Value> {
    recorded().into_iter().filter(|f| f["body"]["sandbox_id"] == SANDBOX).collect()
}
fn body_id(frame: &Value) -> Option<&str> {
    frame["body"]["id"].as_str()
}

/// E2B's own module reads the deliveries and declares E2B's ways in, for the
/// team the test names; the list answers from the stand-in's rows.
struct Recorded {
    team: &'static str,
    rows: Arc<Mutex<Vec<Environment>>>,
}
#[async_trait::async_trait]
impl Module for Recorded {
    fn version(&self) -> &str {
        "test"
    }
    async fn configure(&self, name: &str, config: &ProviderConfiguration, http: Arc<dyn HttpClient>) -> ModuleResult<Arc<dyn Provider>> {
        let e2b = ProviderConfiguration {
            module: "e2b".into(),
            settings: serde_json::from_value(json!({"team_id": self.team})).unwrap(),
            ..config.clone()
        };
        let e2b = drydock_host::e2b::E2bModule::new().configure(name, &e2b, http).await?;
        Ok(Arc::new(RecordedProvider { e2b, rows: self.rows.clone() }))
    }
}
struct RecordedProvider {
    e2b: Arc<dyn Provider>,
    rows: Arc<Mutex<Vec<Environment>>>,
}
#[async_trait::async_trait]
impl Provider for RecordedProvider {
    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }
    fn ways_in(&self) -> Vec<WayIn> {
        self.e2b.ways_in()
    }
    fn operations(&self) -> Operations<'_> {
        Operations { events: self.e2b.operations().events, ..Operations::default() }
    }
    fn readiness(&self, _: &Credentials) -> Readiness {
        Readiness::Ready
    }
    async fn prepare(&self, _: PrepareRequest, _: &Credentials) -> ModuleResult<Prepared> {
        unimplemented!()
    }
    async fn provision(&self, _: ProvisionRequest, _: &Credentials) -> ModuleResult<Provisioned> {
        unimplemented!()
    }
    async fn list(&self, _: &Credentials) -> ModuleResult<Vec<Environment>> {
        Ok(self.rows.lock().unwrap().clone())
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

/// The second sandbox as a list reads it: running, with tags of its own.
fn listed() -> Environment {
    let tags = BTreeMap::from([(OWNER_TAG.to_owned(), "e2b".to_owned()), ("flotilla.label".to_owned(), "vessel".to_owned())]);
    Environment {
        id: SANDBOX.into(),
        label: Some("vessel".into()),
        provider: "e2b".into(),
        state: Observation::Running,
        granted_size: Some(Size { cpus: 2.0, memory_bytes: 512 << 20, disk_bytes: 10 << 30 }),
        egress: Enforcement::Advisory,
        platform: None,
        egress_measured: false,
        egress_policy: None,
        timestamp: None,
        vendor: Some(VendorState { state: "running".into(), reason: None, tags: Some(tags) }),
    }
}

/// drydockd with the `e2b` instance reading the relay at `url` on an owned
/// account, listing only at start: every later observation comes from the relay.
async fn drydockd(dir: &Path, url: &str, team: &'static str, rows: Vec<Environment>) -> Arc<Daemon> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.join("host.sock");
    let module = Arc::new(Recorded { team, rows: Arc::new(Mutex::new(rows)) }) as Arc<dyn Module>;
    let host = drydock_host::Host::new([("recorded-e2b".to_owned(), module)].into());
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
    let text = format!(
        "[providers.e2b]\nmodule = 'recorded-e2b'\nownership = 'owned_account'\n\
         [providers.e2b.events]\nrelay = '{url}'\nsource = 'e2b'\ntoken = {{ file = '{}' }}\npoll_seconds = 3600\n",
        dir.join("relay.token").display()
    );
    let run = dir.join("run");
    let option = HostOption { optional: false, name: "rust".into(), connection: HostConnection::ExternalUnix { path: socket } };
    Daemon::start_with_seams(Config::parse(&text).unwrap(), &run, run.join("keys"), vec![option], Seams::new(Arc::new(Digests)))
        .await
        .unwrap()
}

/// Waits for drydockd's first list, then its stream past the first snapshot:
/// what follows is new.
async fn subscribe(relay: &Relay, dir: &Path, daemon: &Daemon) -> drydock::api::ObservationStream {
    relay.readied(1).await;
    taken(dir, None).await;
    let mut stream = ProviderApi::observe(daemon, None).await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(20), stream.next()).await.unwrap().unwrap().unwrap();
    assert!(matches!(first, ObserveRecord::Snapshot { .. }), "{first:?}");
    stream
}
/// Waits until drydockd stores a relay cursor, `frame`'s when given: it has
/// read every delivery up to it.
async fn taken(dir: &Path, frame: Option<&Value>) {
    let file = dir.join("run/events/e2b.cursor");
    let want = frame.map(|f| cursor(f).to_string());
    tokio::time::timeout(Duration::from_secs(20), async {
        while !std::fs::read_to_string(&file).is_ok_and(|c| want.as_ref().is_none_or(|w| c.trim() == w)) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
/// Events until `until` holds of one.
async fn events(stream: &mut drydock::api::ObservationStream, until: impl Fn(&Event) -> bool) -> Vec<Event> {
    let mut events = vec![];
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(record) = stream.next().await {
            if let ObserveRecord::Event { event } = record.unwrap() {
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
/// The row drydockd holds of `id`, as a new stream's snapshot gives it.
async fn held(daemon: &Daemon, id: &str) -> Option<Environment> {
    let mut stream = ProviderApi::observe(daemon, None).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(20), stream.next()).await.unwrap().unwrap().unwrap() {
        ObserveRecord::Snapshot { environments, .. } => environments.into_iter().find(|e| e.id == id),
        other => panic!("{other:?}"),
    }
}
fn delivery(event: &Event) -> Option<&str> {
    event.observed.as_ref().and_then(|o| o.delivery_id.as_deref())
}

// Each lifecycle type arrives as its own event: created is the sandbox's
// creation, paused a stop with no cause, resumed a resume, killed a gone with
// no cause. Each carries E2B's type as its state, E2B's timestamp, and the
// body's id as its delivery.
#[tokio::test]
async fn each_lifecycle_type_arrives_as_an_event_with_the_vendor_state() {
    let dir = tempfile::tempdir().unwrap();
    let frames = lifecycle();
    let (relay, url) = Relay::serving(frames.clone()).await;
    let daemon = drydockd(dir.path(), &url, TEAM, vec![]).await;
    let mut stream = subscribe(&relay, dir.path(), &daemon).await;
    relay.publish(frames.len());
    let events = events(&mut stream, |e| matches!(e.event, EventKind::Gone { .. })).await;
    let kinds: Vec<_> = events.iter().map(|e| (e.event.clone(), e.vendor.as_ref().unwrap().state.as_str(), delivery(e))).collect();
    assert_eq!(
        kinds,
        [
            (EventKind::Created, "sandbox.lifecycle.created", body_id(&frames[0])),
            (EventKind::Stopped { cause: None }, "sandbox.lifecycle.paused", body_id(&frames[1])),
            (EventKind::Resumed, "sandbox.lifecycle.resumed", body_id(&frames[2])),
            (EventKind::Gone { cause: None }, "sandbox.lifecycle.killed", body_id(&frames[3])),
        ]
    );
    for (event, frame) in events.iter().zip(&frames) {
        assert_eq!((event.id.as_str(), event.observed.as_ref().unwrap().way), (SANDBOX, ObservedWay::Webhook));
        assert_eq!(event.timestamp_source, TimestampSource::Provider);
        assert_eq!(event.timestamp, frame["body"]["timestamp"].as_str().unwrap().parse().unwrap());
    }
}

// A kill carries E2B's kill reason verbatim as the vendor's reason, and no
// drydock cause: drydockd did not destroy the sandbox, and E2B's reason is
// not mapped to one.
#[tokio::test]
async fn a_kill_carries_its_reason_and_no_cause() {
    let dir = tempfile::tempdir().unwrap();
    let frames: Vec<_> = recorded().into_iter().filter(|f| f["body"]["sandbox_id"] == KILLED).collect();
    let (relay, url) = Relay::serving(frames.clone()).await;
    let daemon = drydockd(dir.path(), &url, TEAM, vec![]).await;
    let mut stream = subscribe(&relay, dir.path(), &daemon).await;
    relay.publish(1);
    let events = events(&mut stream, |e| matches!(e.event, EventKind::Gone { .. })).await;
    let killed = events.last().unwrap();
    assert_eq!((killed.id.as_str(), &killed.event), (KILLED, &EventKind::Gone { cause: None }));
    let vendor = killed.vendor.as_ref().unwrap();
    assert_eq!((vendor.state.as_str(), vendor.reason.as_deref()), ("sandbox.lifecycle.killed", Some("request")));
    assert_eq!(vendor.reason.as_deref(), frames[0]["body"]["event_data"]["kill_reason"].as_str());
}

// A delivery's `sandbox_metadata` are the sandbox's tags; one that states no
// metadata states no tags, and the row drydockd holds keeps the tags it had,
// taking only the delivery's state and time. The recorded creation is served
// as recorded, then the recorded pause with its `sandbox_metadata` taken out.
#[tokio::test]
async fn a_delivery_without_metadata_keeps_the_held_tags() {
    let dir = tempfile::tempdir().unwrap();
    let frames = lifecycle();
    let mut paused = frames[1].clone();
    paused["body"]["event_data"].as_object_mut().unwrap().remove("sandbox_metadata").unwrap();
    let (relay, url) = Relay::serving(vec![frames[0].clone(), paused.clone()]).await;
    let daemon = drydockd(dir.path(), &url, TEAM, vec![listed()]).await;
    let mut stream = subscribe(&relay, dir.path(), &daemon).await;
    let stated: BTreeMap<String, String> = serde_json::from_value(frames[0]["body"]["event_data"]["sandbox_metadata"].clone()).unwrap();
    assert_ne!(listed().vendor.unwrap().tags.as_ref(), Some(&stated));
    relay.publish(1);
    events(&mut stream, |e| delivery(e) == body_id(&frames[0])).await;
    assert_eq!(held(&daemon, SANDBOX).await.unwrap().vendor.unwrap().tags.as_ref(), Some(&stated));
    relay.publish(2);
    events(&mut stream, |e| matches!(e.event, EventKind::Stopped { .. })).await;
    let row = held(&daemon, SANDBOX).await.unwrap();
    assert_eq!(row.state, Observation::Stopped { cause: None });
    assert_eq!(row.timestamp, Some(paused["body"]["timestamp"].as_str().unwrap().parse().unwrap()));
    let vendor = row.vendor.unwrap();
    assert_eq!((vendor.state.as_str(), vendor.tags), ("sandbox.lifecycle.paused", Some(stated)));
}

// A delivery for another team says nothing drydock follows: the instance's
// team is not the recorded one, so reading every recorded delivery emits no
// event and makes no row.
#[tokio::test]
async fn another_teams_delivery_emits_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let frames = recorded();
    let (relay, url) = Relay::serving(frames.clone()).await;
    let daemon = drydockd(dir.path(), &url, "another-team", vec![]).await;
    let mut stream = subscribe(&relay, dir.path(), &daemon).await;
    relay.publish(frames.len());
    taken(dir.path(), frames.last()).await;
    let next = tokio::time::timeout(Duration::from_millis(500), stream.next()).await;
    assert!(!matches!(next, Ok(Some(Ok(ObserveRecord::Event { .. })))), "{next:?}");
    assert_eq!((held(&daemon, SANDBOX).await, held(&daemon, KILLED).await), (None, None));
}

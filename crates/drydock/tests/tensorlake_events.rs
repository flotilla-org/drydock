//! Tensorlake's webhooks (drydock#287), through drydockd's public interface.
//! A relay stand-in serves the deliveries recorded from the live relay on
//! 2026-11-06 for one sandbox's lifecycle, and the Tensorlake module reads
//! them; the vendor behind the module's list is a stand-in the test sets.
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
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
#[path = "support/relay.rs"]
mod relay;
use relay::{Digests, Relay, TOKEN, cursor};

/// Relay frames, each with Tensorlake's envelope: created (pending), running,
/// suspended, resumed (pending), running, terminated.
fn recorded() -> Vec<Value> {
    serde_json::from_str(include_str!("fixtures/tensorlake-frames-2026-11-06.json")).unwrap()
}
fn sandbox_of(frame: &Value) -> &Value {
    &frame["body"]["data"]["sandbox"]
}
/// The recorded sandbox's id, which is its environment's.
fn recorded_id() -> String {
    sandbox_of(&recorded()[0])["id"].as_str().unwrap().to_owned()
}
fn project() -> String {
    recorded()[0]["body"]["project_id"].as_str().unwrap().to_owned()
}
fn occurred(frame: &Value) -> Timestamp {
    frame["body"]["occurred_at"].as_str().unwrap().parse().unwrap()
}
const SIZE: Size = Size { cpus: 1.0, memory_bytes: 1 << 30, disk_bytes: 10 << 30 };

/// What the vendor stand-in lists.
#[derive(Default)]
struct Vendor {
    rows: Mutex<Vec<Environment>>,
}
/// Tensorlake's own module reads the deliveries and declares Tensorlake's
/// ways in; the list answers from the vendor stand-in.
struct Recorded {
    vendor: Arc<Vendor>,
    project: String,
}
#[async_trait::async_trait]
impl Module for Recorded {
    fn version(&self) -> &str {
        "test"
    }
    async fn configure(&self, name: &str, config: &ProviderConfiguration, http: Arc<dyn HttpClient>) -> ModuleResult<Arc<dyn Provider>> {
        let tensorlake = ProviderConfiguration {
            module: "tensorlake".into(),
            settings: serde_json::from_value(json!({"project_id": self.project})).unwrap(),
            ..config.clone()
        };
        let tensorlake = drydock_host::tensorlake::TensorlakeModule::new().unwrap().configure(name, &tensorlake, http).await?;
        Ok(Arc::new(RecordedProvider { tensorlake, vendor: self.vendor.clone() }))
    }
}
struct RecordedProvider {
    tensorlake: Arc<dyn Provider>,
    vendor: Arc<Vendor>,
}
/// The recorded sandbox as a list shows it once it is made: pending, with its size.
fn listed(provider: &str) -> Environment {
    Environment {
        id: recorded_id(),
        label: Some("vessel".into()),
        provider: provider.into(),
        state: Observation::Transitioning { phase: TransitionPhase::Starting },
        granted_size: Some(SIZE),
        egress: Enforcement::Advisory,
        platform: None,
        egress_measured: false,
        egress_policy: None,
        timestamp: None,
        vendor: Some(VendorState { state: "pending".into(), reason: None, tags: None }),
    }
}
#[async_trait::async_trait]
impl Provider for RecordedProvider {
    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }
    fn ways_in(&self) -> Vec<WayIn> {
        self.tensorlake.ways_in()
    }
    fn operations(&self) -> Operations<'_> {
        Operations { events: self.tensorlake.operations().events, ..Operations::default() }
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

/// drydockd with the `tensorlake` instance reading the relay at `url`, its
/// module configured for `project`, listing only at start.
async fn drydockd(dir: &Path, url: &str, project: &str) -> Arc<Daemon> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let vendor = Arc::new(Vendor { rows: Mutex::new(vec![listed("tensorlake")]) });
    let socket = dir.join("host.sock");
    let module = Arc::new(Recorded { vendor, project: project.into() }) as Arc<dyn Module>;
    let host = drydock_host::Host::new([("recorded-tensorlake".to_owned(), module)].into());
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
        "[providers.tensorlake]\nmodule = 'recorded-tensorlake'\nownership = 'owned_account'\n\
         [providers.tensorlake.events]\nrelay = '{url}'\nsource = 'tensorlake'\ntoken = {{ file = '{}' }}\npoll_seconds = 3600\n",
        dir.join("relay.token").display()
    );
    let run = dir.join("run");
    let option = HostOption { optional: false, name: "rust".into(), connection: HostConnection::ExternalUnix { path: socket } };
    Daemon::start_with_seams(Config::parse(&text).unwrap(), &run, run.join("keys"), vec![option], Seams::new(Arc::new(Digests)))
        .await
        .unwrap()
}
/// Waits until drydockd has taken in the relay up to `frame`.
async fn taken(dir: &Path, frame: &Value) {
    let file = dir.join("run/events/tensorlake.cursor");
    let want = cursor(frame).to_string();
    tokio::time::timeout(Duration::from_secs(20), async {
        while std::fs::read_to_string(&file).ok().as_deref() != Some(want.as_str()) {
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
/// The row drydockd holds of the recorded sandbox, as a new stream's snapshot gives it.
async fn held(daemon: &Daemon) -> Option<Environment> {
    let mut stream = ProviderApi::observe(daemon, None).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(20), stream.next()).await.unwrap().unwrap().unwrap() {
        ObserveRecord::Snapshot { environments, .. } => environments.into_iter().find(|e| e.id == recorded_id()),
        other => panic!("{other:?}"),
    }
}
/// Events about the recorded sandbox, until `until` holds of one.
async fn events(stream: &mut drydock::api::ObservationStream, until: impl Fn(&Event) -> bool) -> Vec<Event> {
    let mut events = vec![];
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(record) = stream.next().await {
            if let ObserveRecord::Event { event } = record.unwrap()
                && event.id == recorded_id()
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

// Each change Tensorlake reports arrives as an event with Tensorlake's own
// status, the time it gives and the delivery it came in; the termination
// carries its outcome and reason. Tensorlake says whose neither the
// suspension nor the termination was, so neither event claims a cause.
#[tokio::test]
async fn a_lifecycle_arrives_as_events_with_tensorlake_status() {
    let dir = tempfile::tempdir().unwrap();
    let frames = recorded();
    let (relay, url) = Relay::serving(frames.clone()).await;
    let daemon = drydockd(dir.path(), &url, &project()).await;
    relay.readied(1).await;
    let mut stream = subscribe(&daemon).await;
    relay.publish(frames.len());
    let events = events(&mut stream, |e| matches!(e.event, EventKind::Gone { .. })).await;
    let seen: Vec<_> = events.iter().map(|e| (e.event.clone(), e.vendor.as_ref().unwrap().state.as_str(), delivery(e))).collect();
    let id = |i: usize| frames[i]["delivery_id"].as_str();
    let starting = EventKind::Transitioning { phase: TransitionPhase::Starting };
    assert_eq!(
        seen,
        [
            (starting.clone(), "pending", id(0)),
            (EventKind::Running { granted_size: SIZE }, "running", id(1)),
            (EventKind::Stopped { cause: None }, "suspended", id(2)),
            (starting, "pending", id(3)),
            (EventKind::Resumed, "running", id(4)),
            (EventKind::Running { granted_size: SIZE }, "running", id(4)),
            (EventKind::Gone { cause: None }, "terminated", id(5)),
        ]
    );
    for event in &events {
        let frame = frames.iter().find(|f| f["delivery_id"].as_str() == delivery(event)).unwrap();
        assert_eq!(event.observed.as_ref().unwrap().way, ObservedWay::Webhook);
        assert_eq!((event.timestamp_source.clone(), event.timestamp.clone()), (TimestampSource::Provider, occurred(frame)));
    }
    let last = sandbox_of(frames.last().unwrap());
    let reason = format!("{}: {}", last["outcome"].as_str().unwrap(), last["outcome_reason"].as_str().unwrap());
    assert_eq!(events.last().unwrap().vendor.as_ref().unwrap().reason.as_deref(), Some(reason.as_str()));
}

// Deliveries are not ordered: one that arrives after a newer one, by
// Tensorlake's time, changes nothing.
#[tokio::test]
async fn a_late_delivery_does_not_overtake_a_newer_one() {
    let dir = tempfile::tempdir().unwrap();
    let recorded = recorded();
    // The suspension arrives, then the running that came before it.
    let mut frames = vec![recorded[2].clone(), recorded[1].clone()];
    frames[1]["cursor"] = json!(cursor(&frames[0]) + 1);
    let (relay, url) = Relay::serving(frames.clone()).await;
    let daemon = drydockd(dir.path(), &url, &project()).await;
    relay.readied(1).await;
    let mut stream = subscribe(&daemon).await;
    relay.publish(2);
    let stopped = events(&mut stream, |e| matches!(e.event, EventKind::Stopped { .. })).await;
    assert_eq!(delivery(stopped.last().unwrap()), frames[0]["delivery_id"].as_str());
    taken(dir.path(), &frames[1]).await;
    let row = held(&daemon).await.unwrap();
    assert_eq!((row.state, row.vendor.unwrap().state), (Observation::Stopped { cause: None }, "suspended".to_owned()));
    assert_eq!(row.timestamp, Some(occurred(&frames[0])));
}

// A delivery for another project says nothing drydock follows.
#[tokio::test]
async fn a_delivery_for_another_project_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let frames = recorded();
    let (relay, url) = Relay::serving(frames.clone()).await;
    let daemon = drydockd(dir.path(), &url, "another-project").await;
    relay.readied(1).await;
    relay.publish(frames.len());
    taken(dir.path(), frames.last().unwrap()).await;
    assert_eq!(held(&daemon).await, Some(listed("tensorlake")));
}

// Tensorlake sandboxes carry no labels: a delivery states the instance and
// label the module decodes from the name this instance gave the sandbox, and
// the row drydockd holds carries them, for its shared-account check.
#[tokio::test]
async fn a_delivery_carries_the_instance_and_label_its_name_holds() {
    let dir = tempfile::tempdir().unwrap();
    let frames = recorded();
    let (relay, url) = Relay::serving(frames.clone()).await;
    let daemon = drydockd(dir.path(), &url, &project()).await;
    relay.readied(1).await;
    relay.publish(1);
    taken(dir.path(), &frames[0]).await;
    let name = sandbox_of(&frames[0])["name"].as_str().unwrap();
    let label = name.split_once("-r-").unwrap().1;
    let tags = held(&daemon).await.unwrap().vendor.unwrap().tags.unwrap();
    assert_eq!(tags, [(OWNER_TAG.to_owned(), "tensorlake".to_owned()), ("flotilla.label".to_owned(), label.to_owned())].into());
}

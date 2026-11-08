//! E2B's lifecycle events through the webhook relay (drydock#286), through
//! drydockd's public interface. A relay stand-in serves E2B deliveries
//! recorded from the live relay on 2026-11-06, and the E2B module reads them;
//! the vendor behind the module's list is a stand-in the test sets.
#![cfg(unix)]
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
#[path = "support/webhooks.rs"]
mod webhooks;
use relay::Relay;
use webhooks::{Recorded, delivery, events, held, subscribe};

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
/// account for `team`, listing `rows` only at start; past its first list,
/// its stream is read past the first snapshot.
async fn drydockd(
    dir: &Path,
    relay: &Relay,
    url: &str,
    team: &str,
    rows: Vec<Environment>,
) -> (Arc<drydock::daemon::Daemon>, drydock::api::ObservationStream) {
    let module = Arc::new(drydock_host::e2b::E2bModule::new());
    let settings = json!({"team_id": team});
    webhooks::host(dir, "e2b", Arc::new(Recorded { module, module_name: "e2b", settings, stand_in: Arc::new(Mutex::new(rows)) })).await;
    let daemon = webhooks::drydockd(dir, "e2b", url, "owned_account").await;
    webhooks::caught_up(relay, dir, "e2b").await;
    let stream = subscribe(&daemon).await;
    (daemon, stream)
}

// Each lifecycle type arrives as an event: created is the sandbox's creation
// and running, paused a stop with no cause, resumed a resume and running,
// killed a gone with no cause. E2B states no size, so running carries none.
// Each carries E2B's type as its state, E2B's timestamp, and the body's id as
// its delivery.
#[tokio::test]
async fn each_lifecycle_type_arrives_as_an_event_with_the_vendor_state() {
    let dir = tempfile::tempdir().unwrap();
    let frames = lifecycle();
    let (relay, url) = Relay::serving(frames.clone()).await;
    let (_daemon, mut stream) = drydockd(dir.path(), &relay, &url, TEAM, vec![]).await;
    relay.publish(frames.len());
    let events = events(&mut stream, |e| matches!(e.event, EventKind::Gone { .. })).await;
    let kinds: Vec<_> = events.iter().map(|e| (e.event.clone(), e.vendor.as_ref().unwrap().state.as_str(), delivery(e))).collect();
    assert_eq!(
        kinds,
        [
            (EventKind::Created, "sandbox.lifecycle.created", body_id(&frames[0])),
            (EventKind::Running { granted_size: None }, "sandbox.lifecycle.created", body_id(&frames[0])),
            (EventKind::Stopped { cause: None }, "sandbox.lifecycle.paused", body_id(&frames[1])),
            (EventKind::Resumed, "sandbox.lifecycle.resumed", body_id(&frames[2])),
            (EventKind::Running { granted_size: None }, "sandbox.lifecycle.resumed", body_id(&frames[2])),
            (EventKind::Gone { cause: None }, "sandbox.lifecycle.killed", body_id(&frames[3])),
        ]
    );
    for event in &events {
        let frame = frames.iter().find(|f| body_id(f) == delivery(event)).unwrap();
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
    let (_daemon, mut stream) = drydockd(dir.path(), &relay, &url, TEAM, vec![]).await;
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
    let (daemon, mut stream) = drydockd(dir.path(), &relay, &url, TEAM, vec![listed()]).await;
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
    let (daemon, mut stream) = drydockd(dir.path(), &relay, &url, "another-team", vec![]).await;
    relay.publish(frames.len());
    webhooks::taken(dir.path(), "e2b", frames.last()).await;
    let next = tokio::time::timeout(Duration::from_millis(500), stream.next()).await;
    assert!(!matches!(next, Ok(Some(Ok(ObserveRecord::Event { .. })))), "{next:?}");
    assert_eq!((held(&daemon, SANDBOX).await, held(&daemon, KILLED).await), (None, None));
}

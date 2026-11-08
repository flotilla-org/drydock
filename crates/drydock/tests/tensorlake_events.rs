//! Tensorlake's webhooks (drydock#287), through drydockd's public interface.
//! A relay stand-in serves the deliveries recorded from the live relay on
//! 2026-11-06 for one sandbox's lifecycle, and the Tensorlake module reads
//! them; the vendor behind the module's list is a stand-in the test sets.
#![cfg(unix)]
use drydock_protocol::*;
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
#[path = "support/relay.rs"]
mod relay;
#[path = "support/webhooks.rs"]
mod webhooks;
use drydock::daemon::ProviderApi;
use drydock_host::module::Provisioned;
use relay::{Relay, cursor};
use webhooks::{Recorded, delivery, events, held, subscribe, taken};

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

/// The recorded sandbox as a list shows it once it is made: pending.
fn listed(provider: &str) -> Environment {
    Environment {
        id: recorded_id(),
        label: Some("vessel".into()),
        provider: provider.into(),
        state: Observation::Transitioning { phase: TransitionPhase::Starting },
        granted_size: None,
        egress: Enforcement::Advisory,
        platform: None,
        egress_measured: false,
        egress_policy: None,
        timestamp: None,
        vendor: Some(VendorState { state: "pending".into(), reason: None, tags: None }),
    }
}
/// drydockd with the `tensorlake` instance reading the relay at `url`, its
/// module configured for `project`, listing only at start, past its first list.
async fn drydockd(dir: &Path, relay: &Relay, url: &str, project: &str) -> Arc<drydock::daemon::Daemon> {
    let module = Arc::new(drydock_host::tensorlake::TensorlakeModule::new().unwrap());
    let settings = json!({"project_id": project});
    let stand_in = Arc::new(Mutex::new(vec![listed("tensorlake")]));
    webhooks::host(dir, "tensorlake", Arc::new(Recorded { module, module_name: "tensorlake", settings, stand_in })).await;
    let daemon = webhooks::drydockd(dir, "tensorlake", url, "owned_account").await;
    webhooks::caught_up(relay, dir, "tensorlake").await;
    daemon
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
    let daemon = drydockd(dir.path(), &relay, &url, &project()).await;
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
            (EventKind::Running { granted_size: None }, "running", id(1)),
            (EventKind::Stopped { cause: None }, "suspended", id(2)),
            (starting, "pending", id(3)),
            (EventKind::Resumed, "running", id(4)),
            (EventKind::Running { granted_size: None }, "running", id(4)),
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
    let daemon = drydockd(dir.path(), &relay, &url, &project()).await;
    let mut stream = subscribe(&daemon).await;
    relay.publish(2);
    let stopped = events(&mut stream, |e| matches!(e.event, EventKind::Stopped { .. })).await;
    assert_eq!(delivery(stopped.last().unwrap()), frames[0]["delivery_id"].as_str());
    taken(dir.path(), "tensorlake", Some(&frames[1])).await;
    let row = held(&daemon, &recorded_id()).await.unwrap();
    assert_eq!((row.state, row.vendor.unwrap().state), (Observation::Stopped { cause: None }, "suspended".to_owned()));
    assert_eq!(row.timestamp, Some(occurred(&frames[0])));
}

// A delivery for another project says nothing drydock follows.
#[tokio::test]
async fn a_delivery_for_another_project_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let frames = recorded();
    let (relay, url) = Relay::serving(frames.clone()).await;
    let daemon = drydockd(dir.path(), &relay, &url, "another-project").await;
    relay.publish(frames.len());
    taken(dir.path(), "tensorlake", frames.last()).await;
    assert_eq!(held(&daemon, &recorded_id()).await, Some(listed("tensorlake")));
}

// Tensorlake sandboxes carry no labels: a delivery states the instance and
// label the module decodes from the name this instance gave the sandbox, and
// the row drydockd holds carries them, for its shared-account check.
#[tokio::test]
async fn a_delivery_carries_the_instance_and_label_its_name_holds() {
    let dir = tempfile::tempdir().unwrap();
    let frames = recorded();
    let (relay, url) = Relay::serving(frames.clone()).await;
    let daemon = drydockd(dir.path(), &relay, &url, &project()).await;
    relay.publish(1);
    taken(dir.path(), "tensorlake", Some(&frames[0])).await;
    let name = sandbox_of(&frames[0])["name"].as_str().unwrap();
    let label = name.split_once("-r-").unwrap().1;
    let tags = held(&daemon, &recorded_id()).await.unwrap().vendor.unwrap().tags.unwrap();
    assert_eq!(tags, [(OWNER_TAG.to_owned(), "tensorlake".to_owned()), ("flotilla.label".to_owned(), label.to_owned())].into());
}

/// Tensorlake behind the module: it lists nothing yet, and a create answers
/// with the recorded sandbox, pending.
struct Creating;
#[async_trait::async_trait]
impl webhooks::Vendor for Creating {
    async fn list(&self) -> Vec<Environment> {
        vec![]
    }
    async fn provision(&self, instance: &str) -> Provisioned {
        Provisioned::Created(listed(instance))
    }
}

// With every option off on an owned account, a sandbox this instance made
// and no list has shown yet is still held from its provision on: its resume
// is reported as a resume, as it is with the default options.
#[tokio::test]
async fn a_resume_is_reported_with_every_option_off() {
    let dir = tempfile::tempdir().unwrap();
    let frames = recorded();
    let (relay, url) = Relay::serving(frames.clone()).await;
    let module = Arc::new(drydock_host::tensorlake::TensorlakeModule::new().unwrap());
    let settings = json!({"project_id": project()});
    webhooks::host(
        dir.path(),
        "tensorlake",
        Arc::new(Recorded { module, module_name: "tensorlake", settings, stand_in: Arc::new(Creating) }),
    )
    .await;
    let options = "ownership = 'owned_account'\nsemantics = { settle = false, idempotent = false }";
    let daemon = webhooks::drydockd_configured(dir.path(), "tensorlake", &url, options).await;
    webhooks::caught_up(&relay, dir.path(), "tensorlake").await;
    let mut stream = subscribe(&daemon).await;
    let prepared = Prepared {
        provider: "tensorlake".into(),
        id: "image".into(),
        platform: Platform::new("linux", "amd64"),
        image_digest: "image".into(),
        tools_digest: "tools".into(),
    };
    let request = ProvisionRequest {
        label: "vessel".into(),
        prepared,
        size: Size { cpus: 1.0, memory_bytes: 1 << 30, disk_bytes: 10 << 30 },
        egress: EgressRequest::Open,
        ssh_public_key: None,
    };
    ProviderApi::provision(&*daemon, "tensorlake", &request).await.unwrap();
    relay.publish(frames.len());
    let events = events(&mut stream, |e| matches!(e.event, EventKind::Gone { .. })).await;
    let kinds: Vec<_> = events.iter().map(|e| (e.event.clone(), delivery(e))).collect();
    let id = |i: usize| frames[i]["delivery_id"].as_str();
    let starting = EventKind::Transitioning { phase: TransitionPhase::Starting };
    assert_eq!(
        kinds,
        [
            (EventKind::Created, id(0)),
            (starting.clone(), id(0)),
            (EventKind::Running { granted_size: None }, id(1)),
            (EventKind::Stopped { cause: None }, id(2)),
            (starting, id(3)),
            (EventKind::Resumed, id(4)),
            (EventKind::Running { granted_size: None }, id(4)),
            (EventKind::Gone { cause: None }, id(5)),
        ]
    );
}

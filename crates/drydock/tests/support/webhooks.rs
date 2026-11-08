//! drydockd reading a vendor's webhooks from the relay stand-in, through its
//! public interface: a vendor's own module reads the deliveries, and the
//! vendor behind its list and provision is a stand-in the test sets.
// Each test file uses its own part of it.
#![allow(dead_code)]
use super::relay::{Digests, Relay, TOKEN, cursor};
use drydock::{
    HostConnection,
    config::Config,
    daemon::{Daemon, HostOption, ProviderApi, Seams},
};
use drydock_host::module::{ByteStream, Credentials, HttpClient, Module, Operations, Provider, Provisioned, Result as ModuleResult};
use drydock_protocol::*;
use futures::StreamExt;
use serde_json::Value;
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

/// The vendor behind a module's list and provision.
#[async_trait::async_trait]
pub trait Vendor: Send + Sync + 'static {
    async fn list(&self) -> Vec<Environment>;
    async fn provision(&self, _instance: &str) -> Provisioned {
        unimplemented!()
    }
}
/// A vendor that lists these rows.
#[async_trait::async_trait]
impl Vendor for Mutex<Vec<Environment>> {
    async fn list(&self) -> Vec<Environment> {
        self.lock().unwrap().clone()
    }
}

/// `module`, configured as `module_name` with `settings`, reads the deliveries and
/// declares the vendor's ways in; the list and provision answer from `stand_in`.
pub struct Recorded<V> {
    pub module: Arc<dyn Module>,
    pub module_name: &'static str,
    pub settings: Value,
    pub stand_in: Arc<V>,
}
#[async_trait::async_trait]
impl<V: Vendor> Module for Recorded<V> {
    fn version(&self) -> &str {
        "test"
    }
    async fn configure(&self, name: &str, config: &ProviderConfiguration, http: Arc<dyn HttpClient>) -> ModuleResult<Arc<dyn Provider>> {
        let own = ProviderConfiguration {
            module: self.module_name.into(),
            settings: serde_json::from_value(self.settings.clone()).unwrap(),
            ..config.clone()
        };
        let module = self.module.configure(name, &own, http).await?;
        Ok(Arc::new(RecordedProvider { name: name.into(), module, stand_in: self.stand_in.clone() }))
    }
}
struct RecordedProvider<V> {
    name: String,
    module: Arc<dyn Provider>,
    stand_in: Arc<V>,
}
#[async_trait::async_trait]
impl<V: Vendor> Provider for RecordedProvider<V> {
    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }
    fn ways_in(&self) -> Vec<WayIn> {
        self.module.ways_in()
    }
    fn operations(&self) -> Operations<'_> {
        Operations { events: self.module.operations().events, ..Operations::default() }
    }
    fn readiness(&self, _: &Credentials) -> Readiness {
        Readiness::Ready
    }
    async fn prepare(&self, _: PrepareRequest, _: &Credentials) -> ModuleResult<Prepared> {
        unimplemented!()
    }
    async fn provision(&self, _: ProvisionRequest, _: &Credentials) -> ModuleResult<Provisioned> {
        Ok(self.stand_in.provision(&self.name).await)
    }
    async fn list(&self, _: &Credentials) -> ModuleResult<Vec<Environment>> {
        Ok(self.stand_in.list().await)
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

/// A host serving `module` as `recorded-{instance}`, once per test directory.
pub async fn host(dir: &Path, instance: &str, module: Arc<dyn Module>) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.join("host.sock");
    let host = drydock_host::Host::new([(format!("recorded-{instance}"), module)].into());
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
/// drydockd with `instance` on the host's module, reading the relay at `url`
/// as its source, listing only at start: every later observation comes from the relay.
pub async fn drydockd(dir: &Path, instance: &str, url: &str, ownership: &str) -> Arc<Daemon> {
    drydockd_configured(dir, instance, url, &format!("ownership = '{ownership}'")).await
}
/// [`drydockd`], with `settings` (TOML keys) in the instance's table.
pub async fn drydockd_configured(dir: &Path, instance: &str, url: &str, settings: &str) -> Arc<Daemon> {
    let text = format!(
        "[providers.{instance}]\nmodule = 'recorded-{instance}'\n{settings}\n\
         [providers.{instance}.events]\nrelay = '{url}'\nsource = '{instance}'\ntoken = {{ file = '{}' }}\npoll_seconds = 3600\n",
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
pub async fn caught_up(relay: &Relay, dir: &Path, instance: &str) {
    relay.readied(1).await;
    taken(dir, instance, None).await;
}
/// Waits until drydockd stores a relay cursor, `frame`'s when given: it has
/// read every delivery up to it.
pub async fn taken(dir: &Path, instance: &str, frame: Option<&Value>) {
    let file = dir.join(format!("run/events/{instance}.cursor"));
    let want = frame.map(|f| cursor(f).to_string());
    tokio::time::timeout(Duration::from_secs(20), async {
        while !std::fs::read_to_string(&file).is_ok_and(|c| want.as_ref().is_none_or(|w| c.trim() == w)) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
/// drydockd's event stream, read past its first snapshot: what follows is new.
pub async fn subscribe(daemon: &Daemon) -> drydock::api::ObservationStream {
    let mut stream = ProviderApi::observe(daemon, None).await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(20), stream.next()).await.unwrap().unwrap().unwrap();
    assert!(matches!(first, ObserveRecord::Snapshot { .. }), "{first:?}");
    stream
}
/// Events until `until` holds of one.
pub async fn events(stream: &mut drydock::api::ObservationStream, until: impl Fn(&Event) -> bool) -> Vec<Event> {
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
pub async fn held(daemon: &Daemon, id: &str) -> Option<Environment> {
    let mut stream = ProviderApi::observe(daemon, None).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(20), stream.next()).await.unwrap().unwrap().unwrap() {
        ObserveRecord::Snapshot { environments, .. } => environments.into_iter().find(|e| e.id == id),
        other => panic!("{other:?}"),
    }
}
/// The delivery an event came in.
pub fn delivery(event: &Event) -> Option<&str> {
    event.observed.as_ref().and_then(|o| o.delivery_id.as_deref())
}

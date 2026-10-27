//! Event history, cursors, replay and aggregate snapshots.
use super::*;
use crate::{api::ObservationStream, client::Error};

/// One deadline for every push list in an initial or recovery snapshot.
pub const PUSH_SNAPSHOT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub const EVENT_HISTORY_CAPACITY: usize = 1024;

#[derive(Clone)]
pub(super) struct EventLog {
    pub(super) log: Arc<Mutex<Log>>,
    pub(super) changed: watch::Sender<u64>,
}
#[derive(Clone)]
pub(super) struct EventSink {
    pub(super) shared: EventLog,
    pub(super) provider: String,
}
pub(super) struct Log {
    pub(super) serial: u64,
    pub(super) records: VecDeque<Event>,
    pub(super) epoch: String,
    pub(super) inventories: BTreeMap<String, Vec<ObservedEnvironment>>,
}
impl EventSink {
    fn append(
        log: &mut Log,
        provider: &str,
        id: String,
        label: Option<String>,
        timestamp: Option<chrono::DateTime<chrono::Utc>>,
        event: EventKind,
    ) {
        tracing::debug!(provider, environment_id = %id, route = "observe", "environment observation");
        log.serial += 1;
        let cursor = format!("{}:{}", log.epoch, log.serial);
        log.records.push_back(Event {
            cursor,
            id,
            provider: provider.to_owned(),
            label,
            timestamp: timestamp.unwrap_or_else(chrono::Utc::now).into(),
            timestamp_source: if timestamp.is_some() { TimestampSource::Provider } else { TimestampSource::Adaptor },
            event,
        });
        if log.records.len() > EVENT_HISTORY_CAPACITY {
            log.records.pop_front();
        }
    }
    pub(super) fn commit(&self, rows: Vec<ObservedEnvironment>, events: Vec<PendingEvent>) {
        let mut log = self.shared.log.recover();
        log.inventories.insert(self.provider.clone(), rows);
        for (id, label, timestamp, event) in events {
            Self::append(&mut log, &self.provider, id, label, timestamp, event);
        }
        self.shared.changed.send_replace(log.serial);
    }
}
pub(super) type PendingEvent = (String, Option<String>, Option<chrono::DateTime<chrono::Utc>>, EventKind);

impl Runtime {
    /// Replay from a retained cursor, otherwise start from a snapshot; then follow new events.
    pub(super) async fn observation(&self, since: Option<&str>) -> Result<ObservationStream> {
        let host = self.clone();
        let mut changed = self.events.changed.subscribe();
        let mut stopping = self.stopping.subscribe();
        let mut cursor = since.map(str::to_owned);
        let initial = self.records(cursor.as_deref()).await?;
        Ok(Box::pin(async_stream::stream! {
            let mut initial = Some(initial);
            loop {
                let records = match initial.take() {
                    Some(records) => records,
                    None => match host.records(cursor.as_deref()).await {
                        Ok(records) => records,
                        Err(error) => { if !*stopping.borrow() { yield Err(Error::Protocol(error)); } break; }
                    },
                };
                for record in records {
                    cursor = Some(record_cursor(&record).into());
                    yield Ok(record);
                }
                if *stopping.borrow() { break; }
                tokio::select! { result = changed.changed() => if result.is_err() { break; }, _ = stopping.changed() => break, }
            }
        }))
    }
    async fn records(&self, cursor: Option<&str>) -> Result<Vec<ObserveRecord>> {
        let replay = {
            let log = self.events.log.recover();
            cursor.and_then(|c| {
                let serial = c.strip_prefix(&format!("{}:", log.epoch))?.parse::<u64>().ok()?;
                let oldest = log.serial - log.records.len() as u64;
                if serial < oldest || serial > log.serial {
                    return None;
                }
                Some(
                    log.records
                        .iter()
                        .skip((serial - oldest) as usize)
                        .cloned()
                        .map(|event| ObserveRecord::Event { event })
                        .collect::<Vec<_>>(),
                )
            })
        };
        match replay {
            Some(records) => Ok(records),
            None => Ok(vec![self.snapshot().await?]),
        }
    }
    async fn snapshot(&self) -> Result<ObserveRecord> {
        let mut changed = self.events.changed.subscribe();
        let mut stopping = self.stopping.subscribe();
        if *stopping.borrow() {
            return Err(ProtocolError::unavailable("host stopping", None));
        }
        let instances: Vec<_> = self.config.read().await.providers.values().cloned().collect();
        let mut push_errors = BTreeMap::new();
        let push_cursor = {
            let log = self.events.log.recover();
            format!("{}:{}", log.epoch, log.serial)
        };
        let has_push = instances.iter().any(|i| matches!(i.observation, ObservationMode::Push));
        let deadline = tokio::time::Instant::now() + PUSH_SNAPSHOT_TIMEOUT;
        let lists = instances.iter().filter(|i| matches!(i.observation, ObservationMode::Push)).map(|instance| async move {
            let result = tokio::time::timeout_at(deadline, instance.call(Gate::List, |p, c| async move { p.list(&c).await }))
                .await
                .unwrap_or_else(|_| Err(ProtocolError::unavailable("snapshot list timed out", None)));
            (instance.config.name.clone(), result)
        });
        let results = tokio::select! {
            results = futures::future::join_all(lists) => results,
            _ = stopping.changed() => return Err(ProtocolError::unavailable("host stopping", None)),
        };
        let mut push_rows = vec![];
        for (name, result) in results {
            match result {
                Ok(rows) => push_rows.extend(rows),
                Err(error) => {
                    push_errors.insert(name, error);
                }
            }
        }
        loop {
            if *stopping.borrow() {
                return Err(ProtocolError::unavailable("host stopping", None));
            }
            let mut unavailable_providers = push_errors.clone();
            for instance in &instances {
                // Push list calls may repair proxied rejection; never gate them on
                // Ready, since call() already decides whether a probe is permitted.
                if instance.poll_interval.is_some()
                    && let Err(error) = instance.ready()
                {
                    unavailable_providers.insert(instance.config.name.clone(), error);
                }
            }
            {
                // A poll's inventory and its events are committed under this same lock.
                let log = self.events.log.recover();
                let mut pending = false;
                for i in &instances {
                    if i.poll_interval.is_none()
                        || unavailable_providers.contains_key(&i.config.name)
                        || log.inventories.contains_key(&i.config.name)
                    {
                        continue;
                    }
                    if let Some(error) = i.poll_error.recover().clone() {
                        unavailable_providers.insert(i.config.name.clone(), error);
                        continue;
                    }
                    pending = true;
                }
                if !pending {
                    let mut environments: Vec<_> = log
                        .inventories
                        .iter()
                        .filter(|(name, _)| {
                            !unavailable_providers.contains_key(*name)
                                && instances.iter().any(|i| &i.config.name == *name && i.poll_interval.is_some())
                        })
                        .flat_map(|(_, rows)| rows.iter().map(|r| r.environment.clone()))
                        .collect();
                    environments.extend(push_rows.iter().map(|r| r.environment.clone()));
                    return Ok(ObserveRecord::Snapshot {
                        cursor: if has_push { push_cursor } else { format!("{}:{}", log.epoch, log.serial) },
                        environments,
                        unavailable_providers,
                    });
                }
            }
            tokio::select! {
                _ = changed.changed() => {},
                _ = stopping.changed() => return Err(ProtocolError::unavailable("host stopping", None)),
            }
        }
    }
}
fn record_cursor(record: &ObserveRecord) -> &str {
    match record {
        ObserveRecord::Event { event } => &event.cursor,
        ObserveRecord::Snapshot { cursor, .. } => cursor,
    }
}

//! What the agent tells drydockd: a log of vessel events, read as NDJSON from
//! `GET /events?since=<cursor>`, one `{"cursor", "event"}` per line, held open
//! for new ones. Cursors are `<boot_id>:<serial>`, so one from an earlier agent
//! process is never mistaken for a position in this one.
use crate::ExitStatus;
use axum::{
    body::Body,
    http::header,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;

/// Events kept for a reader that resumes from a cursor.
pub const RETAINED: usize = 1024;
pub(crate) const CONTENT_TYPE: &str = "application/x-ndjson";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// A connection to an outward forward is waiting for drydockd to claim it
    /// with `CONNECT /forwards/outward/{forward}/connections/{connection}`.
    OutwardConnection { forward: String, connection: u64 },
    /// A process the agent started has exited.
    ProcessExited { id: String, status: ExitStatus },
    /// A forward stopped working: its listener failed, or a connection to it
    /// was closed because nobody claimed it in time.
    ForwardFailed { forward: String, reason: String },
}
/// One line of `/events`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    pub cursor: String,
    pub event: Event,
}

pub(crate) struct Events {
    boot_id: String,
    log: Mutex<Log>,
    changed: watch::Sender<u64>,
}
#[derive(Default)]
struct Log {
    serial: u64,
    records: VecDeque<Record>,
}
impl Events {
    pub(crate) fn new(boot_id: String) -> Self {
        Self { boot_id, log: Mutex::default(), changed: watch::channel(0).0 }
    }
    pub(crate) fn push(&self, event: Event) {
        let mut log = self.log.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        log.serial += 1;
        let cursor = format!("{}:{}", self.boot_id, log.serial);
        log.records.push_back(Record { cursor, event });
        if log.records.len() > RETAINED {
            log.records.pop_front();
        }
        self.changed.send_replace(log.serial);
    }
    /// Records after `since`. A cursor this process did not issue, or one
    /// older than what is retained, reads everything retained. The same holds
    /// for a live reader that falls more than [`RETAINED`] events behind: it
    /// skips to the oldest retained event, and what fell out is gone.
    pub(crate) fn after(&self, since: Option<u64>) -> (Vec<Record>, u64) {
        let log = self.log.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let oldest = log.serial - log.records.len() as u64;
        let skip = since.filter(|serial| (oldest..=log.serial).contains(serial)).map_or(0, |serial| serial - oldest);
        (log.records.iter().skip(skip as usize).cloned().collect(), log.serial)
    }
    fn serial(&self, cursor: &str) -> Option<u64> {
        cursor.strip_prefix(&self.boot_id)?.strip_prefix(':')?.parse().ok()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Since {
    pub since: Option<String>,
}

/// The log from `since` on, then each new event as it happens.
pub(crate) fn follow(events: Arc<Events>, since: Option<&str>) -> Response {
    let position = since.and_then(|cursor| events.serial(cursor));
    let changed = events.changed.subscribe();
    let lines = futures_util::stream::unfold((events, changed, position, VecDeque::new()), |state| async move {
        let (events, mut changed, mut position, mut pending) = state;
        loop {
            if let Some(line) = pending.pop_front() {
                return Some((Ok::<_, std::convert::Infallible>(line), (events, changed, position, pending)));
            }
            // Seen before reading, so an event pushed after the read wakes us.
            changed.borrow_and_update();
            let (records, serial) = events.after(position);
            position = Some(serial);
            pending.extend(records.iter().map(|record| {
                let mut line = serde_json::to_vec(record).expect("events serialize");
                line.push(b'\n');
                line
            }));
            if pending.is_empty() && changed.changed().await.is_err() {
                return None;
            }
        }
    });
    ([(header::CONTENT_TYPE, CONTENT_TYPE), (header::CACHE_CONTROL, "no-store")], Body::from_stream(lines)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::generators as gs;

    // A reader resumes exactly after its cursor while it is retained; a cursor
    // fallen out of retention, from another boot, or malformed reads all that
    // is retained. Generated: any number of events around the retention bound.
    #[hegel::test]
    fn cursors_resume_after_their_event_or_replay_what_is_retained(tc: hegel::TestCase) {
        let events = Events::new("boot".into());
        let count = tc.draw(gs::integers::<u64>().min_value(0).max_value(RETAINED as u64 + 40));
        for n in 0..count {
            events.push(Event::ForwardFailed { forward: format!("f{n}"), reason: String::new() });
        }
        let retained = count.min(RETAINED as u64);
        let oldest = count - retained;
        let at = tc.draw(gs::integers::<u64>().min_value(0).max_value(count));
        let cursor = format!("boot:{at}");
        let (records, serial) = events.after(events.serial(&cursor));
        assert_eq!(serial, count);
        let expected = if at >= oldest { count - at } else { retained };
        assert_eq!(records.len() as u64, expected);
        if let Some(first) = records.first() {
            let first: u64 = first.cursor.strip_prefix("boot:").unwrap().parse().unwrap();
            assert_eq!(first, if at >= oldest { at + 1 } else { oldest + 1 });
        }
        for foreign in ["other:1", "boot", "boot:x", ""] {
            assert_eq!(events.after(events.serial(foreign)).0.len() as u64, retained, "{foreign}");
        }
    }
}

//! Host-owned polling: retain last-seen vendor state and emit billing transitions.
use super::*;
use std::{sync::Weak, time::Duration};

pub(super) fn poll_interval(
    mode: ObservationMode,
    limits: &[RateLimit],
) -> Result<Option<Duration>> {
    let ObservationMode::Poll { mut interval } = mode else {
        return Ok(None);
    };
    // Limits are cached at configuration time; credential refresh does not change them.
    // A poll never consumes more than its share of a declared list/global budget.
    for limit in limits {
        if limit.operation == "list" || limit.operation == "*" {
            // Configure validates these too; keep this helper safe in isolation.
            if limit.requests == 0 || limit.period_seconds == 0 {
                return Err(refused("invalid polling rate limit"));
            }
            let nanos = (u128::from(limit.period_seconds) * 1_000_000_000)
                .div_ceil(u128::from(limit.requests));
            interval = interval.max(Duration::new(
                (nanos / 1_000_000_000) as u64,
                (nanos % 1_000_000_000) as u32,
            ));
        }
    }
    if interval.is_zero() || tokio::time::Instant::now().checked_add(interval).is_none() {
        return Err(refused("invalid polling interval"));
    }
    Ok(Some(interval))
}
pub(super) fn spawn(instance: Arc<Instance>, mut stopping: watch::Receiver<bool>) {
    let Ok(Some(interval)) = poll_interval(instance.observation, &instance.rate_limits) else {
        return;
    };
    let weak: Weak<Instance> = Arc::downgrade(&instance);
    tokio::spawn(async move {
        let mut seen: BTreeMap<String, ObservedSandbox> = BTreeMap::new();
        let mut clock = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if *stopping.borrow() {
                break;
            }
            tokio::select! {_=clock.tick()=>{},_=stopping.changed()=>break}
            let Some(instance) = weak.upgrade() else {
                break;
            };
            // Cancellation on shutdown releases an outstanding vendor future. Modules
            // must own no detached retry or mutation task on this list-only path.
            let rows = tokio::select! {
                result=instance.call(Gate::Any("list"),|p,c|async move {p.list(&c).await})=>match result {Ok(rows)=>rows,Err(_)=>continue},
                _=stopping.changed()=>break,
            };
            reconcile(&instance, &mut seen, rows);
        }
    });
}
fn reconcile(
    instance: &Instance,
    seen: &mut BTreeMap<String, ObservedSandbox>,
    rows: Vec<ObservedSandbox>,
) {
    let mut current: BTreeMap<_, _> = rows
        .into_iter()
        .map(|row| (row.sandbox.id.clone(), row))
        .collect();
    {
        let mut inspected = instance
            .inspected
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (id, row) in &mut current {
            if row.timestamp.is_none() {
                row.timestamp = inspected
                    .get(id)
                    .filter(|old| old.sandbox == row.sandbox)
                    .and_then(|old| old.timestamp);
            }
        }
        inspected.retain(|id, _| current.contains_key(id));
    }
    for (id, row) in &current {
        let s = &row.sandbox;
        let mut kinds = vec![];
        let previous = seen.get(id);
        if previous.is_none() {
            kinds.push(EventKind::Created);
        }
        let old = previous.map(|row| &row.sandbox);
        match &s.state {
            Observation::Running => {
                if old.is_some_and(|s| matches!(s.state, Observation::Stopped { .. })) {
                    kinds.push(EventKind::Resumed);
                }
                if old.is_none_or(|old| {
                    !matches!(old.state, Observation::Running) || old.granted_size != s.granted_size
                }) && let Some(granted_size) = s.granted_size.clone()
                {
                    kinds.push(EventKind::Running { granted_size });
                }
            }
            Observation::Stopped { cause } if old.is_none_or(|old| old.state != s.state) => {
                kinds.push(if matches!(cause, StopCause::PausedByProvider) {
                    EventKind::Paused {
                        cause: cause.clone(),
                    }
                } else {
                    EventKind::Stopped {
                        cause: cause.clone(),
                    }
                });
            }
            Observation::Gone { cause } if old.is_none_or(|old| old.state != s.state) => kinds
                .push(EventKind::Gone {
                    cause: cause.clone(),
                }),
            _ => {}
        }
        for kind in kinds {
            instance
                .events
                .publish(id.clone(), s.label.clone(), row.timestamp, kind);
        }
    }
    let mut destroyed = instance
        .destroyed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for (id, row) in seen.iter() {
        if !current.contains_key(id) && !matches!(row.sandbox.state, Observation::Gone { .. }) {
            let cause = if destroyed.remove(id) {
                GoneCause::DestroyedByRequest
            } else {
                GoneCause::MissingOnList
            };
            instance.events.publish(
                id.clone(),
                row.sandbox.label.clone(),
                None,
                EventKind::Gone { cause },
            );
        }
    }
    destroyed.clear();
    // Replace the inventory, pruning every row no longer returned, including Gone.
    *seen = current;
}

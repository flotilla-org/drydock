//! Host-owned polling: retain last-seen vendor state and emit billing transitions.
use super::*;
use std::{sync::Weak, time::Duration};

pub(super) fn poll_interval(mode: ObservationMode, limits: &[RateLimit]) -> Result<Option<Duration>> {
    let ObservationMode::Poll { mut interval } = mode else {
        return Ok(None);
    };
    // Limits are cached at configuration time; credential refresh does not change them.
    // Polling uses at most half the long-run list/global rate. The rolling
    // observation allowance also caps it at max(1, requests/2) per window.
    // A one-request window cannot be split: polling runs at most every two windows.
    for limit in limits {
        if limit.operation == "list" || limit.operation == "*" {
            // Declared rate limits have already been validated by configure.
            let multiplier = if limit.requests == 1 { 2 } else { 1 };
            let nanos = (u128::from(limit.period_seconds) * multiplier * 1_000_000_000).div_ceil(u128::from((limit.requests / 2).max(1)));
            interval = interval.max(Duration::new(
                u64::try_from(nanos / 1_000_000_000).map_err(|_| refused("polling period overflows"))?,
                (nanos % 1_000_000_000) as u32,
            ));
        }
    }
    if interval.is_zero() || tokio::time::Instant::now().checked_add(interval).is_none() {
        return Err(refused("invalid polling interval"));
    }
    Ok(Some(interval))
}
pub(super) fn spawn(instance: Arc<Instance>, mut stopping: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
    let interval = instance.poll_interval;
    let weak: Weak<Instance> = Arc::downgrade(&instance);
    tokio::spawn(async move {
        let Some(interval) = interval else {
            let context = module::PushContext {
                events: instance.events.clone(),
                credentials: instance.credential_changes.subscribe(),
                stopping: stopping.clone(),
            };
            if let Err(error) = instance.provider.run(context).await {
                tracing::error!(provider = %instance.config.name, route = "observer", error_class = error.class(), "push observer stopped");
            }
            return;
        };
        drop(instance);
        let mut seen: BTreeMap<String, ObservedEnvironment> = BTreeMap::new();
        let mut clock = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if *stopping.borrow() {
                break;
            }
            tokio::select! { _ = clock.tick() => {}, _ = stopping.changed() => break, }
            let Some(instance) = weak.upgrade() else {
                break;
            };
            let rows = tokio::select! {
                result = instance.call_with_budget(Gate::List, true, |p,c| async move { p.list(&c).await }) => match result {
                    Ok(rows) => rows,
                    Err(error) => {
                        tracing::warn!(provider = %instance.config.name, route = "poll", error_class = error.class(), "poll failed; retaining inventory");
                        *instance.poll_error.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
                        instance.events.shared.changed.send_modify(|_| {});
                        continue;
                    },
                },
                _ = stopping.changed() => break,
            };
            *instance.poll_error.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            reconcile(&instance, &mut seen, rows);
        }
    })
}

fn reconcile(instance: &Instance, seen: &mut BTreeMap<String, ObservedEnvironment>, rows: Vec<ObservedEnvironment>) {
    let mut pending = vec![];
    let mut current: BTreeMap<_, _> = rows.into_iter().map(|row| (row.environment.id.clone(), row)).collect();
    {
        let mut inspected = instance.inspected.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for (id, row) in &mut current {
            if row.timestamp.is_none() {
                row.timestamp = inspected.get(id).filter(|old| old.environment == row.environment).and_then(|old| old.timestamp);
            }
        }
        inspected.retain(|id, _| current.contains_key(id));
    }
    for (id, row) in &current {
        let s = &row.environment;
        let mut kinds = vec![];
        let previous = seen.get(id);
        if previous.is_none() {
            kinds.push(EventKind::Created);
        }
        let old = previous.map(|row| &row.environment);
        match &s.state {
            Observation::Running => {
                if old.is_some_and(|s| matches!(s.state, Observation::Stopped { .. })) {
                    kinds.push(EventKind::Resumed);
                }
                // Restart emits Running even with unchanged size; a running row
                // also emits it when the granted size changes.
                if old.is_none_or(|old| !matches!(old.state, Observation::Running) || old.granted_size != s.granted_size)
                    && let Some(granted_size) = s.granted_size.clone()
                {
                    kinds.push(EventKind::Running { granted_size });
                }
            }
            Observation::Stopped { cause } if old.is_none_or(|old| old.state != s.state) => {
                kinds.push(if matches!(cause, StopCause::PausedByProvider) {
                    EventKind::Paused { cause: cause.clone() }
                } else {
                    EventKind::Stopped { cause: cause.clone() }
                });
            }
            Observation::Gone { cause } if old.is_none_or(|old| old.state != s.state) => {
                kinds.push(EventKind::Gone { cause: cause.clone() })
            }
            _ => {}
        }
        for kind in kinds {
            pending.push((id.clone(), s.label.clone(), row.timestamp, kind));
        }
    }
    let mut destroyed = instance.destroyed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for (id, row) in seen.iter() {
        if !current.contains_key(id) && !matches!(row.environment.state, Observation::Gone { .. }) {
            let cause = if destroyed.remove(id) { GoneCause::DestroyedByRequest } else { GoneCause::MissingOnList };
            pending.push((id.clone(), row.environment.label.clone(), None, EventKind::Gone { cause }));
        }
    }
    // A list may predate a concurrent successful destroy. Keep its marker while
    // that stale inventory still contains the resource; consume it on disappearance.
    destroyed.retain(|id| current.get(id).is_some_and(|row| !matches!(row.environment.state, Observation::Gone { .. })));
    // Replace the inventory, pruning every row no longer returned, including Gone.
    instance.events.commit(current.values().cloned().collect(), pending);
    *seen = current;
}

#[cfg(test)]
mod tests {
    use super::*;
    // Across declared list/global windows, polling gets at most half the long-run
    // rate, leaving route headroom; a single-slot budget is sampled every two windows.
    #[hegel::test]
    fn polling_leaves_route_headroom(tc: hegel::TestCase) {
        use hegel::generators as gs;
        let requests = tc.draw(gs::integers::<u32>().min_value(1).max_value(100));
        let seconds = tc.draw(gs::integers::<u64>().min_value(1).max_value(100));
        let interval = poll_interval(
            ObservationMode::Poll { interval: Duration::from_nanos(1) },
            &[RateLimit { operation: "list".into(), requests, period_seconds: seconds }],
        )
        .unwrap()
        .unwrap();
        assert!(interval.as_nanos() * u128::from(requests) >= u128::from(seconds) * 2_000_000_000);
    }
}

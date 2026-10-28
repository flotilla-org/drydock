//! Server-owned polling: retain last-seen vendor state and emit billing transitions.
use super::*;
use std::{sync::Weak, time::Duration};

pub(super) fn poll_interval(mode: ObservationMode, limits: &[RateLimit]) -> Result<Duration> {
    let ObservationMode::Poll { interval_ms } = mode;
    let mut interval = Duration::from_millis(interval_ms);
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
    Ok(interval)
}
pub(super) fn spawn(instance: Arc<Instance>, mut stopping: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
    let interval = instance.poll_interval;
    let mut credentials = instance.credential_changes.subscribe();
    let weak: Weak<Instance> = Arc::downgrade(&instance);
    drop(instance);
    tokio::spawn(async move {
        let mut seen: BTreeMap<String, Environment> = BTreeMap::new();
        let mut clock = tokio::time::interval_at(tokio::time::Instant::now(), interval);
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if *stopping.borrow() {
                break;
            }
            tokio::select! {
                _ = clock.tick() => {},
                result = credentials.changed() => { if result.is_err() { break; } clock.reset(); },
                _ = stopping.changed() => break,
            }
            let Some(instance) = weak.upgrade() else {
                break;
            };
            instance.refresh_readiness().await;
            if !instance.availability(&instance.auth.recover()).may_call {
                continue;
            }
            let generation = instance.auth.recover().generation;
            let observation_generation = *instance.observation_generation.recover();
            let rows = tokio::select! {
                result = instance.call_with_budget(Gate::List, true, None, |p,c| async move { p.list(&c).await }) => match result {
                    Ok(rows) => rows,
                    Err(error) => {
                        tracing::warn!(provider = %instance.name, route = "poll", error_class = error.class(), error = %error, "poll failed; retaining inventory");
                        let auth = instance.auth.recover();
                        if auth.generation == generation && !auth.rejected {
                            *instance.poll_error.recover() = Some(error);
                        }
                        drop(auth);
                        instance.events.shared.changed.send_modify(|_| {});
                        continue;
                    },
                },
                _ = stopping.changed() => break,
            };
            reconcile(&instance, &mut seen, rows, observation_generation);
        }
    })
}

fn reconcile(instance: &Instance, seen: &mut BTreeMap<String, Environment>, mut rows: Vec<Environment>, generation: u64) {
    carry_egress(instance, &mut rows, generation);
    let mut pending = vec![];
    let mut current: BTreeMap<_, _> = rows.into_iter().map(|row| (row.id.clone(), row)).collect();
    {
        let inspected = instance.inspected.recover();
        for (id, row) in &mut current {
            if row.timestamp.is_none() {
                row.timestamp =
                    inspected.get(id).filter(|old| old.without_evidence() == row.without_evidence()).and_then(|old| old.timestamp.clone());
            }
        }
    }
    for (id, row) in &current {
        let s = row;
        let mut kinds = vec![];
        let old = seen.get(id);
        if old.is_none() {
            kinds.push(EventKind::Created);
        }
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
            pending.push((id.clone(), s.label.clone(), row.timestamp.as_ref().map(Timestamp::instant), kind));
        }
    }
    let mut destroyed = instance.destroyed.recover();
    let mut deferred = vec![];
    for (id, row) in seen.iter() {
        if !current.contains_key(id) && !matches!(row.state, Observation::Gone { .. }) {
            if destroyed.get(id).is_some_and(|state| state.pending > 0 && !state.confirmed) {
                // Vendor deletion may be visible before its call returns. Defer the
                // billing cause until confirmation, failure or cancellation is known.
                deferred.push((id.clone(), row.clone()));
                continue;
            }
            let cause = if destroyed.get(id).is_some_and(|state| state.confirmed) {
                GoneCause::DestroyedByRequest
            } else {
                GoneCause::MissingOnList
            };
            pending.push((id.clone(), row.label.clone(), None, EventKind::Gone { cause }));
        }
    }
    destroyed.retain(|id, state| state.pending > 0 || current.get(id).is_some_and(|row| !matches!(row.state, Observation::Gone { .. })));
    // Snapshot inventory stays authoritative while only the pending billing diff
    // retains an absent row awaiting a concurrent deletion outcome.
    instance.events.commit(current.values().cloned().collect(), pending);
    current.extend(deferred);
    // Inventory records progress, while billing retains the last stable row
    // across known transitions only. Unknown deliberately breaks that baseline.
    for (id, row) in &mut current {
        if matches!(row.state, Observation::Transitioning { .. })
            && let Some(old) = seen.get(id)
        {
            *row = old.clone();
        }
    }
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
            ObservationMode::Poll { interval_ms: 1 },
            &[RateLimit { operation: "list".into(), requests, period_seconds: seconds }],
        )
        .unwrap();
        assert!(interval.as_nanos() * u128::from(requests) >= u128::from(seconds) * 2_000_000_000);
    }
}

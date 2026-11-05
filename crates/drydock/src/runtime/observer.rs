//! Server-owned observation: list polling and the relay's vendor events, one
//! task per instance. Retains last-seen vendor state and emits transitions.
use super::*;
use std::{sync::Weak, time::Duration};

/// How often to list: the installation's `poll_seconds`, else every
/// [`relay::GAP_POLL_SECONDS`] beside a relay, else the module's interval.
pub(super) fn listing_interval(ways_in: &[WayIn], events: Option<&EventsConfiguration>, relayed: bool) -> Result<Duration> {
    if let Some(seconds) = events.and_then(|e| e.poll_seconds) {
        return Ok(Duration::from_secs(seconds));
    }
    if relayed {
        return Ok(Duration::from_secs(relay::GAP_POLL_SECONDS));
    }
    ways_in
        .iter()
        .find_map(|way| match way {
            WayIn::Poll { interval_ms } => Some(Duration::from_millis(*interval_ms)),
            _ => None,
        })
        .ok_or_else(|| refused("the module declares no list polling"))
}
pub(super) fn poll_interval(mut interval: Duration, limits: &[RateLimit]) -> Result<Duration> {
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
pub(super) fn spawn(
    instance: Arc<Instance>,
    mut stopping: watch::Receiver<bool>,
    state: Option<std::path::PathBuf>,
) -> tokio::task::JoinHandle<()> {
    let interval = instance.poll_interval;
    let mut credentials = instance.credential_changes.subscribe();
    let observed = instance.observed.clone();
    let mut relay = instance.relay.clone().map(|stream| relay::Reader::new(stream, state.as_deref(), &instance.name));
    let name = instance.name.clone();
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
            let frame = async {
                match relay.as_mut() {
                    Some(reader) => reader.next(&name).await,
                    None => std::future::pending().await,
                }
            };
            let mut way = ObservedWay::Poll;
            let mut gap = None;
            tokio::select! {
                // A due list goes first, so the first list precedes a relay's backlog.
                biased;
                _ = clock.tick() => {},
                result = credentials.changed() => { if result.is_err() { break; } clock.reset(); },
                // A wait asks for a poll now; the next one is an interval later.
                _ = observed.poll_now.notified() => clock.reset(),
                next = frame => match next {
                    relay::Next::Gap(cursor) => (way, gap) = (ObservedWay::Reconstruction, Some(cursor)),
                    relay::Next::Ready(cursor) => { relay.as_mut().expect("a frame came from the relay").commit(cursor); continue; }
                    relay::Next::Delivery(delivery) => {
                        let Some(instance) = weak.upgrade() else { break };
                        let reader = relay.as_mut().expect("a frame came from the relay");
                        match deliver(&instance, &mut seen, &delivery).await {
                            Ok(()) => reader.commit(delivery.cursor),
                            Err(()) => reader.reconnect(),
                        }
                        continue;
                    }
                },
                _ = stopping.changed() => break,
            }
            let Some(instance) = weak.upgrade() else {
                break;
            };
            instance.refresh_readiness().await;
            if !instance.availability(&instance.auth.recover()).may_call {
                // A gap is listed once the provider can be called again.
                if gap.is_some() {
                    relay.as_mut().expect("a gap came from the relay").reconnect();
                }
                continue;
            }
            let generation = instance.auth.recover().generation;
            let observation_generation = *instance.observation_generation.recover();
            let rows = tokio::select! {
                result = instance.call_with_budget(Gate::List, true, None, |p,c| async move { p.list(&c).await }) => match result {
                    Ok(rows) => rows,
                    Err(error) => {
                        let error_for_waits = error.clone();
                        tracing::warn!(provider = %instance.name, route = "poll", error_class = error.class(), error = %error, "poll failed; retaining inventory");
                        let auth = instance.auth.recover();
                        if auth.generation == generation && !auth.rejected {
                            *instance.poll_error.recover() = Some(error);
                        }
                        drop(auth);
                        instance.events.shared.changed.send_modify(|_| {});
                        observed.polls.send_replace(Some(error_for_waits));
                        if gap.is_some() {
                            relay.as_mut().expect("a gap came from the relay").reconnect();
                        }
                        continue;
                    },
                },
                _ = stopping.changed() => break,
            };
            reconcile(&instance, &mut seen, rows, observation_generation, way);
            if let (Some(cursor), Some(reader)) = (gap, relay.as_mut()) {
                reader.commit(cursor);
            }
            // Sent on every poll, changed or not: the last poll's outcome is
            // what a wait that runs out reports.
            observed.polls.send_replace(None);
        }
    })
}

/// Apply one relay delivery, as the module reads it. A delivery the module
/// cannot read is skipped; one it could not be asked about now is read again.
async fn deliver(
    instance: &Instance,
    seen: &mut BTreeMap<String, Environment>,
    delivery: &rigging_relay_protocol::Delivery,
) -> std::result::Result<(), ()> {
    let Some(body) = delivery.body.clone() else { return Ok(()) };
    let Ok(received_at) = delivery.received_at.parse::<Timestamp>() else {
        tracing::warn!(provider = %instance.name, delivery_id = %delivery.delivery_id, "relay delivery has no valid received_at; skipped");
        return Ok(());
    };
    let request = VendorDelivery { event: delivery.event.clone(), delivery_id: delivery.delivery_id.clone(), received_at, body };
    let port = instance.provider.clone();
    let read = async {
        let events = port.operations().events.ok_or_else(|| refused("operation port unavailable"))?;
        events.event(request).await
    };
    let observations = match tokio::time::timeout(instance.request_timeout, read).await {
        Ok(Ok(observations)) => observations,
        Ok(Err(error @ ProtocolError::Unavailable { .. })) | Ok(Err(error @ ProtocolError::RateLimited { .. })) => {
            tracing::warn!(provider = %instance.name, error = %instance.diagnostic_error(error, "event"), "could not read a vendor event; reading it again");
            return Err(());
        }
        Err(_) => {
            tracing::warn!(provider = %instance.name, "reading a vendor event timed out; reading it again");
            return Err(());
        }
        Ok(Err(error)) => {
            tracing::warn!(provider = %instance.name, delivery_id = %delivery.delivery_id, error = %instance.diagnostic_error(error, "event"), "vendor event skipped");
            return Ok(());
        }
    };
    let observed = ObservedBy { way: ObservedWay::Webhook, delivery_id: Some(delivery.delivery_id.clone()) };
    for observation in observations {
        apply(instance, seen, observation, &observed);
    }
    Ok(())
}

/// One environment as the vendor reports it, with every transition it makes.
fn apply(instance: &Instance, seen: &mut BTreeMap<String, Environment>, v: VendorObservation, observed: &ObservedBy) {
    let current = instance.observed.row(&v.id).or_else(|| seen.get(&v.id).cloned());
    let base = match current {
        Some(row) => row,
        // What drydockd provisioned is known in full; anything else is new
        // here, unless it may be another instance's on a shared account.
        None => match instance.observed.claimed.recover().remove(&v.id) {
            Some(row) => row,
            None if instance.foreign_possible => {
                tracing::debug!(provider = %instance.name, environment_id = %v.id, "vendor event for an environment not known to be this instance's; left to the next list");
                return;
            }
            None => Environment {
                id: v.id.clone(),
                label: None,
                provider: instance.name.clone(),
                state: v.state.clone(),
                granted_size: None,
                // The weaker claim, until a list says otherwise.
                egress: Enforcement::Advisory,
                platform: None,
                egress_measured: false,
                egress_policy: None,
                timestamp: None,
                vendor: None,
            },
        },
    };
    let row = Environment { state: v.state, vendor: Some(v.vendor), timestamp: v.timestamp, ..base };
    let confirmed = instance.destroyed.recover().get(&row.id).is_some_and(|s| s.confirmed);
    let old = seen.get(&row.id);
    let events = transitions(old, &row, confirmed, true)
        .into_iter()
        .map(|kind| Pending {
            id: row.id.clone(),
            label: row.label.clone(),
            timestamp: row.timestamp.clone(),
            vendor: row.vendor.clone(),
            kind,
        })
        .collect();
    // Billing keeps the last stable row across transitions, as a list does.
    if !(matches!(row.state, Observation::Transitioning { .. }) && old.is_some()) {
        seen.insert(row.id.clone(), row.clone());
    }
    instance.events.update(row, events, observed);
}

/// What `row` is a transition to from `old`, the last stable row. A list
/// reports changes; a `pushed` vendor event reports its state every time,
/// transitional states included.
fn transitions(old: Option<&Environment>, row: &Environment, confirmed: bool, pushed: bool) -> Vec<EventKind> {
    let mut kinds = vec![];
    if old.is_none() {
        kinds.push(EventKind::Created);
    }
    let changed = pushed || old.is_none_or(|old| old.state != row.state);
    match &row.state {
        Observation::Running => {
            if old.is_some_and(|s| matches!(s.state, Observation::Stopped { .. })) {
                kinds.push(EventKind::Resumed);
            }
            // Restart emits Running even with unchanged size; a running row
            // also emits it when the granted size changes.
            if (pushed || old.is_none_or(|old| !matches!(old.state, Observation::Running) || old.granted_size != row.granted_size))
                && let Some(granted_size) = row.granted_size.clone()
            {
                kinds.push(EventKind::Running { granted_size });
            }
        }
        Observation::Stopped { cause } if changed => {
            kinds.push(if matches!(cause, StopCause::PausedByProvider) {
                EventKind::Paused { cause: cause.clone() }
            } else {
                EventKind::Stopped { cause: cause.clone() }
            });
        }
        Observation::Gone { cause } if changed => {
            // A vendor that keeps listing what it destroyed reports the
            // destruction drydock asked for as its own.
            let cause = match cause {
                GoneCause::DestroyedAtProvider if confirmed => GoneCause::DestroyedByRequest,
                cause => cause.clone(),
            };
            kinds.push(EventKind::Gone { cause })
        }
        Observation::Transitioning { phase } if pushed => kinds.push(EventKind::Transitioning { phase: *phase }),
        _ => {}
    }
    kinds
}

fn reconcile(instance: &Instance, seen: &mut BTreeMap<String, Environment>, mut rows: Vec<Environment>, generation: u64, way: ObservedWay) {
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
    let confirmed: BTreeSet<String> = instance.destroyed.recover().iter().filter(|(_, s)| s.confirmed).map(|(id, _)| id.clone()).collect();
    for (id, row) in &current {
        for kind in transitions(seen.get(id), row, confirmed.contains(id), false) {
            pending.push(Pending {
                id: id.clone(),
                label: row.label.clone(),
                timestamp: row.timestamp.clone(),
                vendor: row.vendor.clone(),
                kind,
            });
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
            pending.push(Pending {
                id: id.clone(),
                label: row.label.clone(),
                timestamp: None,
                vendor: None,
                kind: EventKind::Gone { cause },
            });
        }
    }
    destroyed.retain(|id, state| state.pending > 0 || current.get(id).is_some_and(|row| !matches!(row.state, Observation::Gone { .. })));
    instance.observed.claimed.recover().retain(|id, _| !current.contains_key(id));
    // Snapshot inventory stays authoritative while only the pending billing diff
    // retains an absent row awaiting a concurrent deletion outcome.
    instance.events.commit(current.values().cloned().collect(), pending, &ObservedBy { way, delivery_id: None });
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
        let interval =
            poll_interval(Duration::from_millis(1), &[RateLimit { operation: "list".into(), requests, period_seconds: seconds }]).unwrap();
        assert!(interval.as_nanos() * u128::from(requests) >= u128::from(seconds) * 2_000_000_000);
    }
}

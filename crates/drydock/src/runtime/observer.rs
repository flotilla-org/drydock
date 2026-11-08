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
        let mut pushed = Pushed::default();
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
                _ = observed.claimed_now.notified() => {
                    let Some(instance) = weak.upgrade() else { break };
                    claim(&instance, &mut seen, &mut pushed);
                    continue;
                }
                next = frame => match next {
                    relay::Next::Gap(cursor) => (way, gap) = (ObservedWay::Reconstruction, Some(cursor)),
                    relay::Next::Ready(cursor) => { relay.as_mut().expect("a frame came from the relay").commit(cursor); continue; }
                    relay::Next::Delivery(delivery) => {
                        let Some(instance) = weak.upgrade() else { break };
                        let reader = relay.as_mut().expect("a frame came from the relay");
                        match deliver(&instance, &mut seen, &mut pushed, &delivery).await {
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
            reconcile(&instance, &mut seen, &mut pushed, rows, observation_generation, way);
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
    pushed: &mut Pushed,
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
        apply(instance, seen, pushed, observation, &observed);
    }
    Ok(())
}

/// What deliveries said of environments no list has shown yet. A list clears it.
#[derive(Default)]
struct Pushed {
    /// The last delivery for each environment drydockd holds no row of, with
    /// the last stable state it stated.
    announced: BTreeMap<String, VendorObservation>,
    /// Deliveries that may be about another instance's environments, in order,
    /// until this instance's provision returns the id.
    unclaimed: BTreeMap<String, Vec<(VendorObservation, ObservedBy)>>,
}

/// Apply, in order, what was held back for each environment this instance's
/// provision has since returned.
fn claim(instance: &Instance, seen: &mut BTreeMap<String, Environment>, pushed: &mut Pushed) {
    let ids: Vec<_> = {
        let claimed = instance.observed.claimed.recover();
        pushed.unclaimed.keys().filter(|id| claimed.contains_key(*id)).cloned().collect()
    };
    for id in ids {
        for (v, observed) in pushed.unclaimed.remove(&id).unwrap_or_default() {
            apply(instance, seen, pushed, v, &observed);
        }
    }
}

/// One environment as the vendor reports it, with every transition it makes.
/// What the delivery states replaces what drydockd holds of the row; the rest
/// stays. An environment drydockd holds no row of gets its events alone, and
/// the next list makes its row.
fn apply(instance: &Instance, seen: &mut BTreeMap<String, Environment>, pushed: &mut Pushed, v: VendorObservation, observed: &ObservedBy) {
    claim(instance, seen, pushed);
    let row = instance.observed.row(&v.id).or_else(|| seen.get(&v.id).cloned());
    // Deliveries come at least once and in no promised order: one older than
    // what drydockd holds, or as old and in the same state, is overtaken by a
    // list or a redelivery. What a provision answered emitted nothing, so only
    // an older delivery yields to it.
    let newest = match (&row, pushed.announced.get(&v.id)) {
        (Some(row), _) => row.timestamp.as_ref().map(|at| (at, row.vendor.as_ref().map(|v| &v.state))),
        (None, Some(a)) => a.timestamp.as_ref().map(|at| (at, Some(&a.vendor.state))),
        (None, None) => None,
    };
    let claimed = if row.is_none() { instance.observed.claimed.recover().get(&v.id).cloned() } else { None };
    let stale = v.timestamp.as_ref().is_some_and(|at| {
        newest
            .is_some_and(|(held, state)| at.instant() < held.instant() || at.instant() == held.instant() && state == Some(&v.vendor.state))
            || claimed.as_ref().and_then(|row| row.timestamp.as_ref()).is_some_and(|held| at.instant() < held.instant())
    });
    if stale {
        tracing::debug!(provider = %instance.name, environment_id = %v.id, "vendor event already held or overtaken; skipped");
        return;
    }
    let held = row.or_else(|| instance.observed.claimed.recover().remove(&v.id));
    let confirmed = instance.destroyed.recover().get(&v.id).is_some_and(|s| s.confirmed);
    let known = seen.get(&v.id).map(last).or_else(|| pushed.announced.get(&v.id).map(|a| (a.state.as_ref(), None)));
    let pending = |label: Option<String>, kinds: Vec<EventKind>| -> Vec<Pending> {
        kinds
            .into_iter()
            .map(|kind| Pending {
                id: v.id.clone(),
                label: label.clone(),
                timestamp: v.timestamp.clone(),
                vendor: Some(v.vendor.clone()),
                kind,
            })
            .collect()
    };
    let Some(held) = held else {
        if instance.foreign_possible {
            pushed.unclaimed.entry(v.id.clone()).or_default().push((v, observed.clone()));
            return;
        }
        let events = pending(None, transitions(known, v.state.as_ref(), None, confirmed, true));
        instance.events.update(None, events, observed);
        // As a held row does, keep the last stable state through a transition.
        let mut v = v;
        if matches!(v.state, Some(Observation::Transitioning { .. }))
            && let Some(stable) = pushed.announced.get(&v.id).and_then(|a| a.state.clone())
            && !matches!(stable, Observation::Transitioning { .. })
        {
            v.state = Some(stable);
        }
        pushed.announced.insert(v.id.clone(), v);
        return;
    };
    let events = pending(held.label.clone(), transitions(known, v.state.as_ref(), held.granted_size.as_ref(), confirmed, true));
    let tags = v.vendor.tags.clone().or_else(|| held.vendor.as_ref().and_then(|h| h.tags.clone()));
    let vendor = VendorState { tags, ..v.vendor.clone() };
    let state = v.state.clone().unwrap_or_else(|| held.state.clone());
    let row = Environment { state, vendor: Some(vendor), timestamp: v.timestamp.clone(), ..held };
    pushed.announced.remove(&row.id);
    // Billing keeps the last stable row across transitions, as a list does.
    if !(matches!(row.state, Observation::Transitioning { .. }) && seen.contains_key(&row.id)) {
        seen.insert(row.id.clone(), row.clone());
    }
    instance.events.update(Some(row), events, observed);
}

/// What drydockd last held of an environment: its state when stated, and its
/// granted size when known.
type Last<'a> = (Option<&'a Observation>, Option<&'a Size>);
fn last(row: &Environment) -> Last<'_> {
    (Some(&row.state), row.granted_size.as_ref())
}

/// What `state` is a transition to from `old`, the last stable state. A list
/// reports changes; a `pushed` vendor event reports its state every time,
/// transitional states included.
fn transitions(old: Option<Last>, state: Option<&Observation>, size: Option<&Size>, confirmed: bool, pushed: bool) -> Vec<EventKind> {
    let mut kinds = vec![];
    if old.is_none() {
        kinds.push(EventKind::Created);
    }
    let Some(state) = state else { return kinds };
    let changed = pushed || old.is_none_or(|(old, _)| old != Some(state));
    match state {
        Observation::Running => {
            if old.is_some_and(|(old, _)| matches!(old, Some(Observation::Stopped { .. }))) {
                kinds.push(EventKind::Resumed);
            }
            // Becoming running emits Running, with the size only when stated.
            // A running row whose size is stated for the first time, or
            // differs from the one stated before, reports that size, not a
            // transition; a size no longer stated reports nothing.
            if pushed || old.is_none_or(|(old, _)| !matches!(old, Some(Observation::Running))) {
                kinds.push(EventKind::Running { granted_size: size.cloned() });
            } else if let (Some((_, old_size)), Some(size)) = (old, size)
                && old_size != Some(size)
            {
                kinds.push(EventKind::SizeChanged { granted_size: size.clone() });
            }
        }
        Observation::Stopped { cause } if changed => {
            kinds.push(match cause {
                Some(StopCause::PausedByProvider) => EventKind::Paused { cause: StopCause::PausedByProvider },
                cause => EventKind::Stopped { cause: cause.clone() },
            });
        }
        Observation::Gone { cause } if changed => {
            // A destruction drydock asked for is its own, whatever the vendor says of it.
            let cause = match cause {
                Some(GoneCause::DestroyedAtProvider) | None if confirmed => Some(GoneCause::DestroyedByRequest),
                cause => cause.clone(),
            };
            kinds.push(EventKind::Gone { cause })
        }
        Observation::Transitioning { phase } if pushed => kinds.push(EventKind::Transitioning { phase: *phase }),
        _ => {}
    }
    kinds
}

/// `row`, with what it doesn't state taken from `held`: its label, granted
/// size, platform and the vendor's tags. Absent means not stated, so a list
/// cannot clear one of these; only a value it states replaces the held one.
/// Tags are taken whole: a list that states any tags states them all.
fn merge(row: &mut Environment, held: &Environment) {
    row.label = row.label.take().or_else(|| held.label.clone());
    row.granted_size = row.granted_size.take().or_else(|| held.granted_size.clone());
    row.platform = row.platform.take().or_else(|| held.platform.clone());
    if let Some(vendor) = &mut row.vendor
        && vendor.tags.is_none()
    {
        vendor.tags = held.vendor.as_ref().and_then(|h| h.tags.clone());
    }
}

fn reconcile(
    instance: &Instance,
    seen: &mut BTreeMap<String, Environment>,
    pushed: &mut Pushed,
    mut rows: Vec<Environment>,
    generation: u64,
    way: ObservedWay,
) {
    carry_egress(instance, &mut rows, generation);
    let mut pending = vec![];
    let mut current: BTreeMap<_, _> = rows.into_iter().map(|row| (row.id.clone(), row)).collect();
    {
        // What a listed row doesn't state keeps what drydockd holds of it, as
        // with a delivery, which reads the same rows first. The inventory row
        // is never older than `seen`, which keeps a stable row through a
        // transition; `seen` serves only before the first list's inventory.
        let log = instance.events.shared.log.recover();
        let inventory: BTreeMap<_, _> = log.inventories.get(&instance.name).into_iter().flatten().map(|r| (&r.id, r)).collect();
        for (id, row) in &mut current {
            if let Some(held) = inventory.get(id).copied().or_else(|| seen.get(id)) {
                merge(row, held);
            }
        }
    }
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
        let old = seen.get(id).map(last).or_else(|| pushed.announced.get(id).map(|a| (a.state.as_ref(), None)));
        for kind in transitions(old, Some(&row.state), row.granted_size.as_ref(), confirmed.contains(id), false) {
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
    let held = seen.iter().map(|(id, row)| (id, Some(&row.state), row.label.clone(), Some(row)));
    let announced = pushed.announced.iter().filter(|(id, _)| !seen.contains_key(*id)).map(|(id, a)| (id, a.state.as_ref(), None, None));
    for (id, state, label, row) in held.chain(announced) {
        if !current.contains_key(id) && !matches!(state, Some(Observation::Gone { .. })) {
            if destroyed.get(id).is_some_and(|state| state.pending > 0 && !state.confirmed) {
                // Vendor deletion may be visible before its call returns. Defer the
                // billing cause until confirmation, failure or cancellation is known.
                if let Some(row) = row {
                    deferred.push((id.clone(), row.clone()));
                    continue;
                }
            }
            let cause = if destroyed.get(id).is_some_and(|state| state.confirmed) {
                GoneCause::DestroyedByRequest
            } else {
                GoneCause::MissingOnList
            };
            pending.push(Pending { id: id.clone(), label, timestamp: None, vendor: None, kind: EventKind::Gone { cause: Some(cause) } });
        }
    }
    destroyed.retain(|id, state| state.pending > 0 || current.get(id).is_some_and(|row| !matches!(row.state, Observation::Gone { .. })));
    instance.observed.claimed.recover().retain(|id, _| !current.contains_key(id));
    *pushed = Pushed::default();
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

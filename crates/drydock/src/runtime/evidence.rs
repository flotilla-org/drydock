//! Observation cache: lifecycle inspection and egress-measurement evidence.
use super::*;

// Providers without effective-policy identities use this conservative fallback
// evidence age. Fingerprinted policies are invalidated by observed identity changes.
pub(super) const EGRESS_EVIDENCE_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(60);

pub(super) fn cache_observation(instance: &Instance, row: &Environment, generation: u64) {
    // Lock order: observation_generation -> inspected -> egress_measured_at.
    // Hold the generation through the write, so eviction cannot race the check.
    let current = instance.observation_generation.recover();
    if *current != generation {
        return;
    }
    let mut inspected = instance.inspected.recover();
    let mut times = instance.egress_measured_at.recover();
    if row.egress_measured {
        times.insert(row.id.clone(), tokio::time::Instant::now());
    } else {
        times.remove(&row.id);
    }
    inspected.insert(row.id.clone(), row.clone());
}
pub(super) fn evict_observation(instance: &Instance, id: &str) {
    // Invalidate overlapping cache writes without retaining per-ID tombstones.
    let mut generation = instance.observation_generation.recover();
    *generation = generation.wrapping_add(1);
    let mut inspected = instance.inspected.recover();
    let mut times = instance.egress_measured_at.recover();
    inspected.remove(id);
    times.remove(id);
}
// Only explicit measurements replace a measured claim. Policy fingerprints
// permit indefinite carry while unchanged; providers without them use a TTL.
pub(super) fn carry_egress(instance: &Instance, rows: &mut [Environment], generation: u64) {
    // Same generation -> inspected -> egress_measured_at order as cache/eviction.
    let current = instance.observation_generation.recover();
    if *current != generation {
        return;
    }
    let mut measured = instance.inspected.recover();
    let mut times = instance.egress_measured_at.recover();
    // Both callers supply authoritative complete lists. Prune absent IDs here,
    // including out-of-band deletion, rather than only during poll reconciliation.
    let listed: std::collections::BTreeSet<_> = rows.iter().map(|r| r.id.as_str()).collect();
    measured.retain(|id, _| listed.contains(id.as_str()));
    times.retain(|id, _| measured.contains_key(id));
    // Only the named non-starting phases preserve evidence. Starting/preparing
    // may cross a stop/start between polls; new phases invalidate by default.
    for row in rows {
        if !row.egress_measured && measured.get(&row.id).is_some_and(|old| old.egress_policy != row.egress_policy) {
            // A changed policy permanently invalidates old evidence, even if it
            // later changes back. Only another measurement can restore a claim.
            measured.remove(&row.id);
            times.remove(&row.id);
        }
        if row.egress_measured {
            times.insert(row.id.clone(), tokio::time::Instant::now());
            // This cache also preserves a matching inspect's provider timestamp
            // when a later list supplies no timestamp of its own.
            if row.timestamp.is_none() {
                row.timestamp = measured
                    .get(&row.id)
                    .filter(|old| old.without_evidence() == row.without_evidence())
                    .and_then(|old| old.timestamp.clone());
            }
            measured.insert(row.id.clone(), row.clone());
        } else if matches!(row.state, Observation::Running) {
            if let Some(old) = measured.get(&row.id).filter(|r| {
                matches!(r.state, Observation::Running)
                    && match (&r.egress_policy, &row.egress_policy) {
                        (Some(old), Some(current)) => old == current,
                        (None, None) => times.get(&row.id).is_some_and(|t| t.elapsed() < EGRESS_EVIDENCE_MAX_AGE),
                        _ => false,
                    }
            }) {
                row.egress = old.egress.clone();
            }
        } else if !matches!(
            row.state,
            Observation::Transitioning { phase: TransitionPhase::Stopping | TransitionPhase::Reconfiguring | TransitionPhase::Destroying }
        ) {
            measured.remove(&row.id);
            times.remove(&row.id);
        }
    }
}

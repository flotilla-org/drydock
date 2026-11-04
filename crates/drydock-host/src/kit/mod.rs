//! What every Rust provider module needs and none should write again: the
//! vendor's HTTP API with typed bodies and answers ([`api`]), commands run
//! in a guest ([`guest`]), destinations and addresses ([`egress`]),
//! prepared-form names and prepare's checks ([`image`]), and sizes, waits,
//! lifecycle state tables and ownership tags (here). A module keeps only
//! what differs: its endpoints, its wire types, its states, its quirks.
pub mod api;
pub mod egress;
pub mod guest;
pub mod image;
pub mod state;

use crate::module::{Result, refused};
use drydock_protocol::*;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt, future::Future, time::Duration};

pub const MIB: u64 = 1 << 20;
pub const GIB: u64 = 1 << 30;

/// The provider-side tag naming the drydock instance that made a resource.
pub const PROVIDER_TAG: &str = OWNER_TAG;
/// The provider-side tag holding the environment's label.
pub const LABEL_TAG: &str = "flotilla.label";

/// A lock held across no `.await`, taken whether or not a panicking holder
/// poisoned it: the state under it is a cache or a record, never an invariant
/// a panic could leave half-made.
pub trait Recover<T> {
    fn recover(&self) -> std::sync::MutexGuard<'_, T>;
}
impl<T> Recover<T> for std::sync::Mutex<T> {
    fn recover(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A vendor's display name, as errors and refusals say it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vendor(pub &'static str);
impl fmt::Display for Vendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl Vendor {
    /// A successful answer missing what drydock needs. Its contents are
    /// never diagnostic text: they can hold reach recipes or guest output.
    pub fn bad_response(self) -> ProtocolError {
        ProtocolError::Internal {
            reason: format!("incomplete {self} response"),
            provider_error: "required field missing or invalid".into(),
        }
    }
    /// A 2xx answer to `operation` that is not the JSON drydock expects.
    pub fn incomplete(self, operation: &str) -> ProtocolError {
        ProtocolError::Internal {
            reason: format!("incomplete {self} response to {operation}"),
            provider_error: "required field missing or invalid".into(),
        }
    }
    /// A deterministic continuation marker binding instance and environment.
    /// It is not a credential: every resume still needs the key.
    pub fn resume_marker(self, prefix: &str, instance: &str, id: &str) -> ResumeToken {
        ResumeToken { token: Secret::new(format!("{prefix}{}", &digest(&format!("{instance}\0{id}"))[..40])) }
    }
    /// Refuses a resume token minted for another environment.
    pub fn check_resume(self, prefix: &str, instance: &str, id: &str, token: &ResumeToken) -> Result<()> {
        if token.token.expose() != self.resume_marker(prefix, instance, id).token.expose() {
            return Err(refused("resume token belongs to another environment"));
        }
        Ok(())
    }
}

/// Lowercase hex SHA-256 of `input`.
pub fn digest(input: &str) -> String {
    format!("{:x}", Sha256::digest(input.as_bytes()))
}

/// What one reading of a vendor's state means to a wait.
pub enum Verdict<T> {
    /// The state wanted: the wait ends with this value.
    Done(T),
    /// Not yet: look again after the interval.
    Pending,
    /// A state it cannot leave for the wanted one: the wait ends with this error.
    Failed(ProtocolError),
}

/// A wait's budget: how often to look, how long between looks, and the
/// retry hint (seconds) when the budget runs out. Every wait in a module is
/// one of these; a vendor's own long-poll or SDK wait stays the vendor's.
#[derive(Clone, Copy)]
pub struct Wait {
    pub attempts: u32,
    pub interval: Duration,
    pub retry_after: u64,
}
impl Wait {
    /// Reads the vendor's state (`read`) up to `attempts` times, `interval` apart,
    /// until `judge` says [`Verdict::Done`]. A failed read or [`Verdict::Failed`] ends
    /// the wait at once: retrying failures is the caller's policy, not this
    /// loop's. A spent budget is Unavailable with `still` as its reason.
    pub async fn until<S, T, F, Fut>(&self, still: impl Into<String>, mut read: F, judge: impl Fn(S) -> Verdict<T>) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<S>>,
    {
        for attempt in 0..self.attempts {
            if attempt > 0 {
                tokio::time::sleep(self.interval).await;
            }
            match judge(read().await?) {
                Verdict::Done(value) => return Ok(value),
                Verdict::Failed(error) => return Err(error),
                Verdict::Pending => {}
            }
        }
        Err(ProtocolError::unavailable(still, Some(self.retry_after)))
    }
}

/// A vendor's size limits, checked before any request.
pub struct SizeLimits {
    /// Whole vCPUs in this range.
    pub cpus: (u64, u64),
    /// Memory in this range of bytes, a multiple of `memory_step`.
    pub memory: (u64, u64),
    pub memory_step: u64,
    /// Disk in this range of bytes, a multiple of `disk_step`.
    pub disk: (u64, u64),
    pub disk_step: u64,
}
impl SizeLimits {
    /// The size, refused naming the limits when it doesn't fit them.
    pub fn check(&self, vendor: Vendor, size: &Size) -> Result<()> {
        let within = |v: u64, (lo, hi): (u64, u64), step: u64| (lo..=hi).contains(&v) && v.is_multiple_of(step);
        let cpus_ok = size.cpus.is_finite() && size.cpus.fract() == 0.0 && (self.cpus.0 as f64..=self.cpus.1 as f64).contains(&size.cpus);
        if cpus_ok && within(size.memory_bytes, self.memory, self.memory_step) && within(size.disk_bytes, self.disk, self.disk_step) {
            return Ok(());
        }
        Err(refused(format!(
            "{vendor} sandbox size: {}..{} whole vCPUs, {} to {} of memory in steps of {}, {} to {} of disk in steps of {}",
            self.cpus.0,
            self.cpus.1,
            bytes(self.memory.0),
            bytes(self.memory.1),
            bytes(self.memory_step),
            bytes(self.disk.0),
            bytes(self.disk.1),
            bytes(self.disk_step)
        )))
    }
}
fn bytes(n: u64) -> String {
    if n == u64::MAX {
        "any".into()
    } else if !n.is_multiple_of(MIB) || n == 0 {
        format!("{n} bytes")
    } else if n.is_multiple_of(GIB) {
        format!("{} GiB", n / GIB)
    } else {
        format!("{} MiB", n / MIB)
    }
}

/// The identity of an egress policy, which a module normalizes first (sorted
/// sets, canonical hosts and CIDRs) so the same request always has the same one:
/// 128 bits of the digest of its JSON. It is what [`Environment`]'s
/// `egress_policy` reports and what [`check_readopt`] compares. Sets and maps in
/// it must be BTree collections: a hash collection serializes in no fixed order.
pub fn fingerprint(normalized_policy: &impl serde::Serialize) -> String {
    digest(&serde_json::to_string(normalized_policy).expect("a policy is JSON"))[..32].to_owned()
}

/// Whether a disk read back may be larger than the request (a vendor whose
/// disk comes with the prepared form), or must equal it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DiskMatch {
    Exact,
    AtLeast,
}
/// Re-adoption of a label: the environment the module read back for it holds
/// the size and egress policy now requested, else it is refused and the caller
/// provisions a new label. `held` is the module's own reading of the vendor's
/// resource (its `granted_size` and `egress_policy`); `egress_policy` is what
/// [`fingerprint`] says of the request.
pub fn check_readopt(vendor: Vendor, held: &Environment, size: &Size, egress_policy: &str, disk: DiskMatch) -> Result<()> {
    let same_size = held.granted_size.as_ref().is_some_and(|g| {
        g.cpus == size.cpus
            && g.memory_bytes == size.memory_bytes
            && match disk {
                DiskMatch::Exact => g.disk_bytes == size.disk_bytes,
                DiskMatch::AtLeast => size.disk_bytes <= g.disk_bytes,
            }
    });
    if same_size && held.egress_policy.as_deref() == Some(egress_policy) {
        return Ok(());
    }
    Err(refused(format!("an existing {vendor} sandbox holds this label with a different size or egress policy; provision a new label")))
}

/// A size read back from the vendor in whole units: all three positive, or
/// none. A size too large for bytes is a bad response.
pub fn granted(
    vendor: Vendor,
    cpus: Option<u64>,
    memory: Option<u64>,
    memory_unit: u64,
    disk: Option<u64>,
    disk_unit: u64,
) -> Result<Option<Size>> {
    let (Some(cpus), Some(memory), Some(disk)) = (cpus.filter(|n| *n > 0), memory.filter(|n| *n > 0), disk.filter(|n| *n > 0)) else {
        return Ok(None);
    };
    let bytes = |n: u64, unit: u64| n.checked_mul(unit).ok_or_else(|| vendor.bad_response());
    Ok(Some(Size { cpus: cpus as f64, memory_bytes: bytes(memory, memory_unit)?, disk_bytes: bytes(disk, disk_unit)? }))
}

/// Lifecycle states as a table: the vendor's state name, and the observation.
pub type StateTable = &'static [(&'static str, Observation)];
/// The observation `state` maps to, or ProviderStateUnknown.
pub fn observe(table: StateTable, state: &str) -> Observation {
    table
        .iter()
        .find(|(name, _)| *name == state)
        .map_or(Observation::Unknown { reason: UnknownReason::ProviderStateUnknown }, |(_, o)| o.clone())
}
pub const fn starting() -> Observation {
    Observation::Transitioning { phase: TransitionPhase::Starting }
}
pub const fn stopping() -> Observation {
    Observation::Transitioning { phase: TransitionPhase::Stopping }
}
pub const fn stopped(cause: StopCause) -> Observation {
    Observation::Stopped { cause }
}

/// Whether a resource's tags name this instance, and the label they hold.
/// A resource is ours only with both (drydock#168).
pub fn ours(tags: &BTreeMap<String, String>, instance: &str) -> Option<String> {
    (tags.get(PROVIDER_TAG).map(String::as_str) == Some(instance)).then(|| tags.get(LABEL_TAG).cloned()).flatten()
}

/// The refusal for a resource this instance did not make. One rule for every
/// module: destroy and inspect of a foreign resource are refused, and it is
/// left alone. A resource that is absent is not foreign (destroy of it is done).
pub fn not_ours(vendor: Vendor, id: &str, instance: &str) -> ProtocolError {
    refused(format!("{vendor} resource {id} was not made by provider {instance}; it is left alone"))
}
/// The label of a resource whose tags make it this instance's, else
/// [`not_ours`].
pub fn require_ours(vendor: Vendor, id: &str, tags: &BTreeMap<String, String>, instance: &str) -> Result<String> {
    ours(tags, instance).ok_or_else(|| not_ours(vendor, id, instance))
}

/// `argv` as one POSIX shell command line.
pub fn shell_command(argv: &[String]) -> String {
    argv.iter().map(|s| format!("'{}'", s.replace('\'', "'\\''"))).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    // Each argument survives sh -c as itself, quotes included.
    #[test]
    fn shell_commands_round_trip() {
        let argv: Vec<String> = ["printf", "%s|", "it's", "a b", "$HOME", ""].map(str::to_owned).to_vec();
        let out = std::process::Command::new("sh").args(["-c", &shell_command(&argv)]).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "it's|a b|$HOME||");
    }

    // A resource is ours only when both tags are there and name us.
    #[test]
    fn ownership_needs_both_tags() {
        let tags = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<BTreeMap<_, _>>();
        assert_eq!(ours(&tags(&[(PROVIDER_TAG, "a"), (LABEL_TAG, "l")]), "a").as_deref(), Some("l"));
        for other in [tags(&[(PROVIDER_TAG, "b"), (LABEL_TAG, "l")]), tags(&[(PROVIDER_TAG, "a")]), tags(&[(LABEL_TAG, "l")])] {
            assert_eq!(ours(&other, "a"), None, "{other:?}");
            assert!(matches!(require_ours(Vendor("Test"), "x", &other, "a"), Err(ProtocolError::Refused { .. })), "{other:?}");
        }
    }

    // Pending until the state is wanted, then its value; a failure or a spent
    // budget ends the wait, and a zero budget never reads.
    #[tokio::test(start_paused = true)]
    async fn waits_end_on_done_failure_or_budget() {
        let wait = Wait { attempts: 3, interval: Duration::from_secs(1), retry_after: 7 };
        let judge = |n: u32| match n {
            2 => Verdict::Done("up"),
            9 => Verdict::Failed(refused("down")),
            _ => Verdict::Pending,
        };
        for states in [[1, 2, 2], [1, 1, 2]] {
            let states = std::cell::RefCell::new(states.into_iter());
            assert_eq!(wait.until("slow", async || Ok(states.borrow_mut().next().unwrap()), judge).await.unwrap(), "up");
        }
        let reads = std::cell::Cell::new(0);
        let spent = wait
            .until(
                "slow",
                async || {
                    reads.set(reads.get() + 1);
                    Ok(1)
                },
                judge,
            )
            .await
            .unwrap_err();
        assert_eq!(reads.get(), 3);
        assert!(matches!(spent, ProtocolError::Unavailable { retry_after: Some(7), .. }));
        assert!(matches!(wait.until("slow", async || Ok(9), judge).await, Err(ProtocolError::Refused { .. })));
        let none = Wait { attempts: 0, ..wait };
        assert!(none.until("slow", async || -> Result<u32> { panic!("read") }, judge).await.is_err());
    }

    // A policy has one identity however its sets were written down, and a
    // label is re-adopted only when size and policy both match.
    #[test]
    fn readoption_compares_size_and_policy() {
        let v = Vendor("Test");
        let id = fingerprint(&(true, BTreeSet::from(["a".to_owned(), "b".to_owned()])));
        assert_eq!(id, fingerprint(&(true, BTreeSet::from(["b".to_owned(), "a".to_owned()]))));
        assert_ne!(id, fingerprint(&(false, BTreeSet::from(["a".to_owned(), "b".to_owned()]))));
        let size = Size { cpus: 2.0, memory_bytes: GIB, disk_bytes: 4 * GIB };
        let held = |size: Size, policy: &str| Environment {
            id: "x".into(),
            provider: "p".into(),
            label: None,
            state: Observation::Running,
            granted_size: Some(size),
            egress: Enforcement::Advisory,
            platform: None,
            egress_measured: false,
            egress_policy: Some(policy.into()),
            timestamp: None,
        };
        assert!(check_readopt(v, &held(size.clone(), &id), &size, &id, DiskMatch::Exact).is_ok());
        let bigger = Size { disk_bytes: 8 * GIB, ..size.clone() };
        assert!(check_readopt(v, &held(bigger.clone(), &id), &size, &id, DiskMatch::Exact).is_err());
        assert!(check_readopt(v, &held(bigger, &id), &size, &id, DiskMatch::AtLeast).is_ok());
        let smaller = Size { disk_bytes: 2 * GIB, ..size.clone() };
        assert!(check_readopt(v, &held(smaller, &id), &size, &id, DiskMatch::AtLeast).is_err());
        assert!(check_readopt(v, &held(size.clone(), "other"), &size, &id, DiskMatch::Exact).is_err());
        let mut unsized_ = held(size.clone(), &id);
        unsized_.granted_size = None;
        assert!(check_readopt(v, &unsized_, &size, &id, DiskMatch::Exact).is_err());
    }

    #[test]
    fn size_limits_and_markers() {
        let limits = SizeLimits { cpus: (1, 4), memory: (GIB, 8 * GIB), memory_step: GIB, disk: (GIB, 10 * GIB), disk_step: GIB };
        let v = Vendor("Test");
        assert!(limits.check(v, &Size { cpus: 2.0, memory_bytes: 4 * GIB, disk_bytes: 10 * GIB }).is_ok());
        for bad in [
            Size { cpus: 1.5, memory_bytes: GIB, disk_bytes: GIB },
            Size { cpus: 5.0, memory_bytes: GIB, disk_bytes: GIB },
            Size { cpus: 1.0, memory_bytes: GIB + 1, disk_bytes: GIB },
            Size { cpus: 1.0, memory_bytes: GIB, disk_bytes: 11 * GIB },
        ] {
            assert!(limits.check(v, &bad).is_err(), "{bad:?}");
        }
        let marker = v.resume_marker("t-", "a", "x");
        assert!(v.check_resume("t-", "a", "x", &marker).is_ok());
        assert!(v.check_resume("t-", "a", "y", &marker).is_err());
    }
}

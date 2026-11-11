//! What every Rust provider module needs and none should write again: the
//! vendor's HTTP API with typed bodies and answers ([`api`]), reached over
//! HTTPS or an endpoint drydock dials itself ([`endpoint`]), commands run
//! in a guest ([`guest`]), destinations and addresses ([`egress`]),
//! prepared-form names and prepare's checks ([`image`]), a relay over a
//! JSON-framed process stream ([`relay`]), credentials exchanged for
//! short-lived tokens ([`exchange`]), and sizes, waits,
//! lifecycle state tables and ownership tags (here). A module keeps only
//! what differs: its endpoints, its wire types, its states, its quirks.
pub mod api;
pub mod egress;
pub mod endpoint;
pub mod exchange;
pub mod guest;
pub mod image;
pub mod relay;

use crate::module::{Result, refused};
use drydock_protocol::*;
use sha2::{Digest, Sha256};
use std::{fmt, future::Future, time::Duration};

pub const MIB: u64 = 1 << 20;
pub const GIB: u64 = 1 << 30;

/// The provider-side tag naming the drydock instance that made a resource.
pub const PROVIDER_TAG: &str = OWNER_TAG;
/// The provider-side tag holding the environment's label.
pub const LABEL_TAG: &str = "flotilla.label";

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
}

/// Lowercase hex SHA-256 of `input`.
pub fn digest(input: &str) -> String {
    format!("{:x}", Sha256::digest(input.as_bytes()))
}

/// `body` is called up to `attempts` times, `interval` apart, until it
/// returns a value; Ok(None) when it never did. An error ends the wait at
/// once: retrying failures is the caller's policy, not this loop's. Zero
/// attempts never call `body`.
pub async fn poll<T, F, Fut>(attempts: u32, interval: Duration, mut body: F) -> Result<Option<T>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>>>,
{
    for attempt in 0..attempts {
        if attempt > 0 {
            tokio::time::sleep(interval).await;
        }
        if let Some(value) = body().await? {
            return Ok(Some(value));
        }
    }
    Ok(None)
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

/// What a remote sandbox declares unless its vendor differs: a frozen
/// material cloned in the vessel under `/workspace`, the fallback runner,
/// egress denied, through a proxy or open under `model`, and the agent, which
/// carries outward exposures since the sandbox has no network of drydockd's.
pub fn remote_sandbox(model: EgressModel) -> Capabilities {
    Capabilities {
        material_modes: vec![MaterialMode::Frozen],
        checkout_strategies: vec![CheckoutStrategy::CloneInVessel],
        workspace_root: "/workspace".into(),
        egress: EgressCapability { routes: vec![EgressRoute::None, EgressRoute::ExplicitProxy, EgressRoute::Open], model },
        fallback_runner: true,
        agent: true,
        reach_ways: vec![ReachWay::OutwardExposure],
        ..Capabilities::default()
    }
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
    Observation::Stopped { cause: Some(cause) }
}

/// `argv` as one POSIX shell command line.
pub fn shell_command(argv: &[String]) -> String {
    argv.iter().map(|s| format!("'{}'", s.replace('\'', "'\\''"))).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each argument survives sh -c as itself, quotes included.
    #[test]
    fn shell_commands_round_trip() {
        let argv: Vec<String> = ["printf", "%s|", "it's", "a b", "$HOME", ""].map(str::to_owned).to_vec();
        let out = std::process::Command::new("sh").args(["-c", &shell_command(&argv)]).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "it's|a b|$HOME||");
    }

    #[test]
    fn size_limits() {
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
    }
}

//! What every Rust provider module needs and none should write again: the
//! vendor HTTP plumbing ([`api`]), starting and reaching the agent in a guest
//! ([`guest`]), destinations and addresses ([`egress`]), prepared-form names
//! and prepare's checks ([`image`]), and settings, sizes, waits and
//! ownership tags (here). A module keeps only what differs: its endpoints,
//! its bodies, its states, its quirks.
pub mod api;
pub mod egress;
pub mod guest;
pub mod image;

use crate::module::{Result, refused};
use drydock_protocol::*;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fmt, future::Future, time::Duration};

pub const MIB: u64 = 1 << 20;
pub const GIB: u64 = 1 << 30;

/// The provider-side tag naming the drydock instance that made a resource.
pub const PROVIDER_TAG: &str = "drydock.provider";
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
    /// A non-empty string field, or a bad response.
    pub fn text<'a>(self, v: &'a Value, key: &str) -> Result<&'a str> {
        v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| self.bad_response())
    }
    /// A finite, non-negative number field, or a bad response.
    pub fn number(self, v: &Value, key: &str) -> Result<f64> {
        v.get(key).and_then(Value::as_f64).filter(|n| n.is_finite() && *n >= 0.0).ok_or_else(|| self.bad_response())
    }
    /// Module settings, refused with serde's reason when they don't parse.
    pub fn settings<T: DeserializeOwned>(self, config: &ProviderConfiguration) -> Result<T> {
        serde_json::from_value(json!(config.settings)).map_err(|e| refused(format!("invalid {self} settings: {e}")))
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

/// `body` is called up to `attempts` times, `interval` apart, until it
/// returns a value; Ok(None) when it never did. An error ends the wait at
/// once: retrying failures is the caller's policy, not this loop's.
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

/// A size read back from the vendor in whole units: all three positive, or none.
pub fn granted(cpus: Option<u64>, memory: Option<u64>, memory_unit: u64, disk: Option<u64>, disk_unit: u64) -> Option<Size> {
    match (cpus.filter(|n| *n > 0), memory.filter(|n| *n > 0), disk.filter(|n| *n > 0)) {
        (Some(cpus), Some(memory), Some(disk)) => {
            Some(Size { cpus: cpus as f64, memory_bytes: memory.checked_mul(memory_unit)?, disk_bytes: disk.checked_mul(disk_unit)? })
        }
        _ => None,
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
    Observation::Stopped { cause }
}

/// A row for an environment the vendor no longer knows.
pub fn gone(provider: &str, id: &str, egress: Enforcement, platform: Platform) -> Environment {
    Environment {
        id: id.to_owned(),
        label: None,
        provider: provider.to_owned(),
        state: Observation::Gone { cause: GoneCause::DestroyedAtProvider },
        granted_size: None,
        egress,
        platform: Some(platform),
        egress_measured: false,
        egress_policy: None,
        timestamp: None,
    }
}

/// Whether a resource's tags (a JSON object) name this instance, and the
/// label they hold. A resource is ours only with both (drydock#168).
pub fn ours(tags: &Value, instance: &str) -> Option<String> {
    (tags[PROVIDER_TAG].as_str() == Some(instance)).then(|| tags[LABEL_TAG].as_str().map(str::to_owned)).flatten()
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

//! What a module must remember across a host restart that the vendor cannot
//! hold for it: which suspends were ours.
use super::{Recover, Vendor, digest};
use std::{collections::HashSet, path::PathBuf, sync::Mutex};

/// The resources this host suspended, so a vendor's "paused" reads as
/// suspended by request rather than by the provider. Vendors that cannot
/// change a resource's tags after it is made (E2B, Namespace) have nowhere to
/// put it, so it is a file per resource under the host's state directory,
/// `<state>/suspensions/<vendor>/<instance>/`, and survives a restart. With no
/// state directory it is in memory only: a restart then reads a suspend as the
/// provider's, which is still resumable.
pub struct Suspensions {
    dir: Option<PathBuf>,
    memory: Mutex<HashSet<String>>,
}
impl Suspensions {
    /// The record of `instance`'s suspends at `vendor`, in the host's state directory.
    pub fn new(vendor: Vendor, instance: &str) -> Self {
        let state = rigging_paths::PathPolicy::from_env("drydock", &rigging_process::ProcessEnvVars).ok().map(|p| p.state_dir);
        Self::in_dir(state.map(|state| state.join("suspensions").join(vendor.0.to_ascii_lowercase()).join(&digest(instance)[..16])))
    }
    /// The record kept in `dir`, or in memory alone.
    pub fn in_dir(dir: Option<PathBuf>) -> Self {
        Self { dir, memory: Mutex::default() }
    }
    // A resource id is a vendor's text: the file is named by its digest.
    fn file(&self, id: &str) -> Option<PathBuf> {
        self.dir.as_ref().map(|dir| dir.join(&digest(id)[..32]))
    }
    pub fn record(&self, id: &str) {
        self.memory.recover().insert(id.to_owned());
        if let Some(file) = self.file(id) {
            let _ = file.parent().map(std::fs::create_dir_all);
            let _ = std::fs::write(file, b"");
        }
    }
    pub fn forget(&self, id: &str) {
        self.memory.recover().remove(id);
        if let Some(file) = self.file(id) {
            let _ = std::fs::remove_file(file);
        }
    }
    pub fn contains(&self, id: &str) -> bool {
        self.memory.recover().contains(id) || self.file(id).is_some_and(|file| file.exists())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A record outlives the host that made it: a new one over the same directory
    // reads it, and what it forgets the next one does not read.
    #[test]
    fn suspensions_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let before = Suspensions::in_dir(Some(dir.path().join("e2b")));
        before.record("sandbox/1");
        assert!(before.contains("sandbox/1") && !before.contains("sandbox/2"));
        let after = Suspensions::in_dir(Some(dir.path().join("e2b")));
        assert!(after.contains("sandbox/1") && !after.contains("sandbox/2"));
        after.forget("sandbox/1");
        assert!(!Suspensions::in_dir(Some(dir.path().join("e2b"))).contains("sandbox/1"));
        let memory = Suspensions::in_dir(None);
        memory.record("a");
        assert!(memory.contains("a"));
        memory.forget("a");
        assert!(!memory.contains("a"));
    }
}

//! Suspends this host made, kept across a restart for vendors that cannot tag a resource afterwards.
use super::{Recover, Vendor, digest};
use std::{collections::HashSet, path::PathBuf, sync::Mutex};

/// One file per resource under `<state>/suspensions/<vendor>/<instance>/`, and in memory when there is no state directory.
pub struct Suspensions {
    dir: Option<PathBuf>,
    memory: Mutex<HashSet<String>>,
}
impl Suspensions {
    pub fn new(vendor: Vendor, instance: &str) -> Self {
        let state = rigging_paths::PathPolicy::from_env("drydock", &rigging_process::ProcessEnvVars).ok().map(|p| p.state_dir);
        Self::in_dir(state.map(|state| state.join("suspensions").join(vendor.0.to_ascii_lowercase()).join(&digest(instance)[..16])))
    }
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
            let written = file.parent().map_or(Ok(()), std::fs::create_dir_all).and_then(|()| std::fs::write(&file, b""));
            if let Err(error) = written {
                tracing::warn!(%error, "could not record a suspend");
            }
        }
    }
    pub fn forget(&self, id: &str) {
        self.memory.recover().remove(id);
        if let Some(file) = self.file(id)
            && let Err(error) = std::fs::remove_file(file)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(%error, "could not clear a suspend record");
        }
    }
    pub fn contains(&self, id: &str) -> bool {
        self.memory.recover().contains(id) || self.file(id).is_some_and(|file| file.exists())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

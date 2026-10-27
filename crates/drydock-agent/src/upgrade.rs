//! Durable probation keeps the provider's installed entry point runnable until
//! the host confirms the candidate. Even a loader failure after successful exec
//! therefore cannot prevent the next provider start from rolling back.
//!
//! The image to activate is a completed upload in the agent's blob store,
//! resumable and digest-checked, which survives an agent restart; activation
//! names its digest.
use crate::{
    durable::{replace, sync_directory},
    *,
};
use std::path::Path;
#[derive(Serialize, Deserialize)]
struct Probation {
    installed: PathBuf,
    candidate: PathBuf,
}
pub(crate) fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}
fn marker(path: &Path) -> PathBuf {
    sidecar(path, "probation")
}
fn read(path: &Path) -> io::Result<Option<Probation>> {
    match std::fs::read(marker(path)) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(invalid)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
pub(crate) async fn prepare(installed: &Path, candidate: &Path) -> io::Result<()> {
    let bytes = serde_json::to_vec(&Probation { installed: installed.into(), candidate: candidate.into() }).map_err(invalid)?;
    replace(&marker(installed), &bytes, 0o600)
}
/// Called after exclusively binding the control socket, before serving clients.
/// Returns the stable install path, including when running a probation candidate.
pub fn startup(current: &Path) -> io::Result<PathBuf> {
    let state = match read(current)? {
        Some(state) => Some(state),
        None if current.extension().is_some_and(|extension| extension == "upgrade") => read(&current.with_extension(""))?,
        None => None,
    };
    let Some(state) = state else {
        return Ok(current.into());
    };
    // Confirmation renames the candidate onto the installed path before it
    // removes the marker, and rollback removes the candidate before the
    // marker. A marker whose candidate is gone is the tail of either, already
    // settled; rolling back then would revert a confirmed upgrade.
    if !state.candidate.exists() {
        std::fs::remove_file(marker(&state.installed))?;
        sync_directory(state.installed.parent().unwrap())?;
        return Ok(state.installed);
    }
    if current != state.candidate {
        rollback(&state.installed)?;
    }
    Ok(state.installed)
}
/// Restore a candidate rejected by exec, or one which nobody confirmed.
pub fn rollback(installed: &Path) -> io::Result<bool> {
    let Some(state) = read(installed)? else {
        return Ok(false);
    };
    let previous = sidecar(installed, "prev");
    // rename of two links to the same inode is a no-op; explicitly unlink the
    // backup afterwards so a failed activation does not look like a live one.
    // Activation writes `.prev` before the marker, so a marker without it
    // means an earlier rollback already restored it and was interrupted.
    if previous.exists() {
        std::fs::rename(&previous, installed)?;
    }
    if previous.exists() {
        std::fs::remove_file(previous)?;
    }
    if state.candidate.exists() {
        std::fs::remove_file(state.candidate)?;
    }
    std::fs::remove_file(marker(installed))?;
    sync_directory(installed.parent().unwrap())?;
    Ok(true)
}
/// This process is the unconfirmed candidate of `installed`.
pub(crate) fn on_probation(installed: &Path) -> bool {
    match read(installed) {
        Ok(state) => state.is_some_and(|state| std::env::current_exe().is_ok_and(|exe| exe == state.candidate)),
        Err(error) => {
            tracing::warn!(%error, "the probation marker is unreadable; reporting no probation");
            false
        }
    }
}
/// Promote the running candidate to the installed entry point. Refused
/// unless this process is that candidate.
pub(crate) async fn confirm(installed: &Path) -> Result<(), AgentError> {
    const OP: &str = "upgrade.confirm";
    let state = read(installed).map_err(|e| AgentError::io(OP, installed.display(), e))?;
    let Some(state) = state.filter(|_| on_probation(installed)) else {
        return Err(AgentError::new(OP, installed.display(), ErrorKind::Conflict, "this agent is not an unconfirmed upgrade candidate"));
    };
    let at = |e| AgentError::io(OP, installed.display(), e);
    tokio::fs::rename(&state.candidate, installed).await.map_err(at)?;
    tokio::fs::remove_file(marker(installed)).await.map_err(at)?;
    sync_directory(installed.parent().unwrap()).map_err(at)
}
/// Make the completed upload named by `sha256` the next candidate. It is
/// copied out of the store to `.upgrade`, hashed again as it is copied, so a
/// blob changed on disk since its upload is refused (and removed) rather
/// than executed. Returns the candidate's path for the re-exec.
pub(crate) async fn activate(installed: &Path, store: &crate::store::Store, sha256: &str) -> Result<PathBuf, AgentError> {
    const OP: &str = "upgrade.activate";
    if store.blob_size(sha256).await?.is_none() {
        let message = format!("no completed upload {sha256}; upload the agent first");
        return Err(AgentError::new(OP, installed.display(), ErrorKind::NotFound, message));
    }
    let blob = store.blob(sha256).map_err(|e| AgentError::io(OP, sha256, e))?;
    let path = sidecar(installed, "upgrade");
    let options = FileOptions { mode: Some(0o755), sha256: Some(sha256.into()), ..FileOptions::default() };
    let written = match crate::files::write(OP, &path, crate::files::Source::File(blob), &options).await {
        Ok((written, _)) => written,
        Err(error) if error.kind == ErrorKind::DigestMismatch => {
            let _ = store.remove_blob(sha256).await;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    if written.size == 0 {
        let _ = std::fs::remove_file(&path);
        return Err(AgentError::new(OP, path.display(), ErrorKind::InvalidInput, "empty agent executable"));
    }
    // Keep the installed path stable over successive upgrades.
    let previous = sidecar(installed, "prev");
    let parent = installed.parent().unwrap_or(Path::new("."));
    let at = |subject: &Path| {
        let subject = subject.display().to_string();
        move |e| AgentError::io(OP, subject, e)
    };
    let backup_dir = tempfile::tempdir_in(parent).map_err(at(parent))?;
    let backup = backup_dir.path().join("previous");
    tokio::fs::hard_link(installed, &backup).await.map_err(at(installed))?;
    tokio::fs::rename(&backup, &previous).await.map_err(at(&previous))?;
    prepare(installed, &path).await.map_err(at(installed))?;
    sync_directory(parent).map_err(at(parent))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Crash ordering over the real filesystem. Confirmation renames the
    // candidate onto the installed path, then removes the marker; a start
    // between the two must keep the confirmed image, not roll it back. A
    // start before confirmation, with the candidate still present, rolls back.
    // A start after a rollback that restored `.prev` but stopped before
    // removing the candidate and marker finishes that rollback.
    #[test]
    fn startup_settles_an_interrupted_confirmation_and_rolls_back_an_unconfirmed_one() {
        for (confirmed, interrupted_rollback) in [(true, false), (false, false), (false, true)] {
            let dir = tempfile::tempdir().unwrap();
            let installed = dir.path().join("agent");
            let candidate = sidecar(&installed, "upgrade");
            std::fs::write(&installed, b"old").unwrap();
            std::fs::write(sidecar(&installed, "prev"), b"old").unwrap();
            std::fs::write(&candidate, b"new").unwrap();
            let bytes = serde_json::to_vec(&Probation { installed: installed.clone(), candidate: candidate.clone() }).unwrap();
            std::fs::write(marker(&installed), bytes).unwrap();
            if confirmed {
                std::fs::rename(&candidate, &installed).unwrap();
            }
            if interrupted_rollback {
                std::fs::rename(sidecar(&installed, "prev"), &installed).unwrap();
            }
            assert_eq!(startup(&installed).unwrap(), installed);
            assert_eq!(std::fs::read(&installed).unwrap(), if confirmed { &b"new"[..] } else { &b"old"[..] });
            assert!(!marker(&installed).exists());
            assert!(!candidate.exists());
            assert!(!sidecar(&installed, "prev").exists() || confirmed);
        }
    }
}

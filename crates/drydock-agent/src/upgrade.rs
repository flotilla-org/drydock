//! Durable probation keeps the provider's installed entry point runnable until
//! the candidate has served hello. Even a loader failure after successful exec
//! therefore cannot prevent the next provider start from rolling back.
use crate::*;
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
    crate::server::atomic_write(&marker(installed), &bytes, false).await
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
    if current != state.candidate {
        rollback(&state.installed)?;
    }
    Ok(state.installed)
}
/// Restore a candidate rejected by exec, or one which never served its hello.
pub fn rollback(installed: &Path) -> io::Result<bool> {
    let Some(state) = read(installed)? else {
        return Ok(false);
    };
    let previous = sidecar(installed, "prev");
    // rename of two links to the same inode is a no-op; explicitly unlink the
    // backup afterwards so a failed activation does not look like a live one.
    std::fs::rename(&previous, installed)?;
    if previous.exists() {
        std::fs::remove_file(previous)?;
    }
    if state.candidate.exists() {
        std::fs::remove_file(state.candidate)?;
    }
    std::fs::remove_file(marker(installed))?;
    std::fs::File::open(installed.parent().unwrap())?.sync_all()?;
    Ok(true)
}
pub(crate) async fn confirm(installed: &Path) -> io::Result<()> {
    let Some(state) = read(installed)? else {
        return Ok(());
    };
    if std::env::current_exe()? != state.candidate {
        return Ok(());
    }
    tokio::fs::rename(&state.candidate, installed).await?;
    tokio::fs::remove_file(marker(installed)).await?;
    tokio::fs::File::open(installed.parent().unwrap()).await?.sync_all().await
}

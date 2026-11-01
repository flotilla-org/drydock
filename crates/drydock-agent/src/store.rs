//! The digest-named staging store, and resumable uploads into it following
//! draft-ietf-httpbis-resumable-upload-12. A partial upload lives under
//! `partial/<sha256>`, named after the digest the finished bytes must have;
//! its length is the upload's offset, and a declared representation length
//! is recorded beside it. When the client completes the upload the agent
//! checks the digest once and either moves the bytes to `blobs/<sha256>` or
//! discards them. Blobs are content-addressed, so any operation that produces
//! verified bytes for a digest (an upload today, a fetch by digest later) can
//! fill the same slot, and every consumer can install from it.
//!
//! Several agents may share one store (`--store`), as vessels on one host
//! do. Each digest then also has a lock file under `locks/`, held by
//! whichever agent is using that digest, so their uploads, fetches and
//! artifact entries never interleave.
use crate::{
    AgentError, ErrorKind, check_sha256,
    durable::sync_directory,
    files::{Copy, copy_body, hash_file},
};
use axum::body::Body;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio_util::sync::CancellationToken;

/// Partial uploads untouched this long are abandoned and removed at startup.
pub(crate) const ABANDONED: Duration = Duration::from_secs(7 * 24 * 3600);

/// One digest's upload, used by one request at a time. A new request ends
/// the one before it (draft section 4.6, the recommended approach): it
/// cancels the holder, then waits for the holder's last write to land.
struct Slot {
    lock: Arc<tokio::sync::Mutex<()>>,
    holder: CancellationToken,
    generation: u64,
}
#[derive(Clone)]
pub(crate) struct Store {
    root: PathBuf,
    slots: Arc<Mutex<HashMap<String, Slot>>>,
}
/// The use of one digest's upload, ended early when `superseded` fires.
pub(crate) struct Held {
    slots: Arc<Mutex<HashMap<String, Slot>>>,
    digest: String,
    generation: u64,
    superseded: CancellationToken,
    _guard: tokio::sync::OwnedMutexGuard<()>,
    _shared: std::fs::File,
}
impl Drop for Held {
    fn drop(&mut self) {
        let mut slots = self.slots.lock().unwrap();
        if slots.get(&self.digest).is_some_and(|slot| slot.generation == self.generation) {
            slots.remove(&self.digest);
        }
    }
}
/// An upload's state as the protocol reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Progress {
    pub offset: u64,
    pub complete: bool,
    /// The representation's length, once the client has declared it.
    pub length: Option<u64>,
    /// How much longer the agent keeps an incomplete upload left untouched.
    pub max_age: Option<Duration>,
}
/// One upload creation or append request.
pub(crate) struct Append {
    pub digest: String,
    /// Upload creation rather than an append to an existing upload.
    pub create: bool,
    pub offset: u64,
    /// The request carries the end of the representation.
    pub complete: bool,
    /// A declared representation length.
    pub length: Option<u64>,
}
/// Bytes available to an unprivileged writer on the filesystem holding `path`.
pub(crate) fn free_space(path: &Path) -> Option<u64> {
    rustix::fs::statvfs(path).ok().map(|stat| stat.f_bavail * stat.f_frsize)
}
impl Store {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self { root, slots: Arc::default() }
    }
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
    /// Remove partial uploads not appended to for `age`, with their recorded
    /// lengths. Returns how many uploads went.
    pub(crate) fn sweep(&self, age: Duration) -> io::Result<usize> {
        let directory = self.root.join("partial");
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error),
        };
        let mut removed = 0;
        // One entry that cannot be read or removed does not stop the rest.
        for entry in entries {
            let swept = (|| -> io::Result<bool> {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let digest = name.split('.').next().unwrap_or_default().to_owned();
                let stale = entry.metadata()?.modified()?.elapsed().is_ok_and(|elapsed| elapsed >= age);
                if !stale || self.slots.lock().unwrap().contains_key(&digest) {
                    return Ok(false);
                }
                std::fs::remove_file(entry.path())?;
                Ok(!name.contains('.'))
            })();
            match swept {
                Ok(upload) => removed += usize::from(upload),
                Err(error) => tracing::warn!(%error, "could not sweep a partial upload"),
            }
        }
        Ok(removed)
    }
    /// Remove artifact staging directories left by a crash, untouched for
    /// `age`. Staging in progress is younger: its unpack keeps writing.
    pub(crate) fn sweep_staging(&self, age: Duration) -> io::Result<usize> {
        let entries = match std::fs::read_dir(self.root.join("artifacts")) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error),
        };
        let mut removed = 0;
        for entry in entries.flatten() {
            let stale = entry.metadata().and_then(|m| m.modified()).is_ok_and(|m| m.elapsed().is_ok_and(|e| e >= age));
            if entry.file_name().to_string_lossy().starts_with('.') && stale {
                let _ = crate::files::open_up(&entry.path());
                match std::fs::remove_dir_all(entry.path()) {
                    Ok(()) => removed += 1,
                    Err(error) => tracing::warn!(%error, "could not sweep artifact staging"),
                }
            }
        }
        Ok(removed)
    }
    pub(crate) fn directory(&self, name: &str) -> io::Result<PathBuf> {
        use std::os::unix::fs::DirBuilderExt;
        let path = self.root.join(name);
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&path)?;
        Ok(path)
    }
    pub(crate) fn partial(&self, digest: &str) -> io::Result<PathBuf> {
        Ok(self.directory("partial")?.join(digest))
    }
    fn declared(&self, digest: &str) -> io::Result<PathBuf> {
        Ok(self.directory("partial")?.join(format!("{digest}.length")))
    }
    pub(crate) fn blob(&self, digest: &str) -> io::Result<PathBuf> {
        Ok(self.directory("blobs")?.join(digest))
    }
    /// Take the digest's upload, ending any request still using it.
    async fn take(&self, operation: &str, digest: &str) -> Result<Held, AgentError> {
        self.hold(operation, digest, true).await
    }
    /// Use the digest after whatever is using it now has finished, without
    /// ending it: a fetch neither ends nor is ended by another request.
    pub(crate) async fn wait_for(&self, operation: &str, digest: &str) -> Result<Held, AgentError> {
        self.hold(operation, digest, false).await
    }
    async fn hold(&self, operation: &str, digest: &str, supersede: bool) -> Result<Held, AgentError> {
        check_sha256(digest).map_err(|e| AgentError::io(operation, digest, e))?;
        let superseded = CancellationToken::new();
        let (lock, generation) = {
            let mut slots = self.slots.lock().unwrap();
            let slot = slots.entry(digest.to_owned()).or_insert_with(|| Slot {
                lock: Arc::default(),
                holder: CancellationToken::new(),
                generation: 0,
            });
            if supersede {
                std::mem::replace(&mut slot.holder, superseded.clone()).cancel();
            }
            slot.generation += 1;
            (slot.lock.clone(), slot.generation)
        };
        let guard = lock.lock_owned().await;
        // Another agent sharing the store may hold the digest; this one
        // waits for it off the runtime. A request cancelled meanwhile drops
        // the lock as soon as the blocking wait ends.
        let path = self.directory("locks").map(|locks| locks.join(digest)).map_err(|e| AgentError::io(operation, digest, e))?;
        let shared = tokio::task::spawn_blocking(move || -> io::Result<std::fs::File> {
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new().create(true).truncate(false).write(true).mode(0o600).open(path)?;
            rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)?;
            Ok(file)
        })
        .await
        .map_err(|e| AgentError::new(operation, digest, ErrorKind::Other, "lock task failed").with_cause(e))?
        .map_err(|e| AgentError::io(operation, digest, e))?;
        Ok(Held { slots: self.slots.clone(), digest: digest.to_owned(), generation, superseded, _guard: guard, _shared: shared })
    }
    /// A completed blob's size, if the store holds one.
    pub(crate) async fn blob_size(&self, digest: &str) -> Result<Option<u64>, AgentError> {
        check_sha256(digest).map_err(|e| AgentError::io("blob.stat", digest, e))?;
        let path = self.blob(digest).map_err(|e| AgentError::io("blob.stat", digest, e))?;
        match tokio::fs::metadata(&path).await {
            Ok(metadata) => Ok(Some(metadata.len())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(AgentError::io("blob.stat", path.display(), error)),
        }
    }
    /// An upload's state without waiting for a request using it: a blob's
    /// whole size once complete, None when there is no such upload.
    pub(crate) async fn state(&self, digest: &str) -> Result<Option<Progress>, AgentError> {
        const OP: &str = "upload.stat";
        if let Some(size) = self.blob_size(digest).await? {
            return Ok(Some(Progress { offset: size, complete: true, length: Some(size), max_age: None }));
        }
        let path = self.partial(digest).map_err(|e| AgentError::io(OP, digest, e))?;
        let metadata = match tokio::fs::metadata(&path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(AgentError::io(OP, path.display(), error)),
        };
        let declared = self.declared(digest).map_err(|e| AgentError::io(OP, digest, e))?;
        let length = match tokio::fs::read_to_string(&declared).await {
            Ok(text) => Some(
                text.trim()
                    .parse()
                    .map_err(|e| AgentError::new(OP, digest, ErrorKind::InvalidData, "unreadable recorded length").with_cause(e))?,
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(AgentError::io(OP, declared.display(), error)),
        };
        let idle = metadata.modified().ok().and_then(|modified| SystemTime::now().duration_since(modified).ok()).unwrap_or_default();
        Ok(Some(Progress { offset: metadata.len(), complete: false, length, max_age: Some(ABANDONED.saturating_sub(idle)) }))
    }
    /// Offset retrieval: the state once any request using the upload has
    /// been ended, so the offset reported is the one the next append needs.
    pub(crate) async fn offset(&self, digest: &str) -> Result<Option<Progress>, AgentError> {
        let _held = self.take("upload.stat", digest).await?;
        self.state(digest).await
    }
    /// Upload creation or append: continue from exactly `offset`, and when
    /// `complete` verify the digest and keep the bytes as a blob. Bytes
    /// received before a disconnect stay, so the next request resumes from
    /// the new offset.
    ///
    /// The append runs as its own task holding the digest until its last
    /// write has landed. A client that resets the stream cancels the request
    /// handler; were the append cancelled with it, writes already handed to
    /// the blocking pool could extend the file after the digest was released,
    /// moving the offset under the next request.
    pub(crate) async fn append(&self, append: Append, body: Body) -> Result<Progress, AgentError> {
        let store = self.clone();
        let digest = append.digest.clone();
        tokio::spawn(async move { store.append_whole(append, body).await })
            .await
            .map_err(|e| AgentError::new("upload.append", digest, ErrorKind::Other, "append task failed").with_cause(e))?
    }
    async fn append_whole(&self, append: Append, body: Body) -> Result<Progress, AgentError> {
        const OP: &str = "upload.append";
        let Append { ref digest, create, offset, complete, length } = append;
        let held = self.take(OP, digest).await?;
        let at = |e| AgentError::io(OP, digest, e);
        let current = self.state(digest).await?;
        if let Some(blob) = current.filter(|state| state.complete) {
            // A completed upload replays its completion to a valid append.
            if !create && offset == blob.offset && complete {
                return Ok(blob);
            }
            return Err(AgentError::new(OP, digest, ErrorKind::Conflict, format!("upload is complete at {} bytes", blob.offset)));
        }
        let (start, recorded) = match (create, current) {
            (true, Some(state)) => {
                let message = format!("an upload of this digest is at {} bytes; resume it", state.offset);
                return Err(AgentError::new(OP, digest, ErrorKind::Conflict, message));
            }
            (true, None) => (0, None),
            (false, None) => return Err(AgentError::new(OP, digest, ErrorKind::NotFound, "no upload of this digest")),
            (false, Some(state)) => (state.offset, state.length),
        };
        if offset != start {
            return Err(AgentError::new(OP, digest, ErrorKind::Conflict, format!("upload is at {start} bytes, not {offset}")));
        }
        if let (Some(recorded), Some(length)) = (recorded, length)
            && recorded != length
        {
            let message = format!("Upload-Length {length} differs from the recorded {recorded}");
            return Err(AgentError::new(OP, digest, ErrorKind::InvalidInput, message));
        }
        let length = recorded.or(length);
        if let Some(length) = length
            && length < start
        {
            let message = format!("Upload-Length {length} is less than the {start} bytes already uploaded");
            return Err(AgentError::new(OP, digest, ErrorKind::InvalidInput, message));
        }
        let path = self.partial(digest).map_err(at)?;
        // A declared length the disk cannot hold is refused up front, before
        // a partial upload fills the guest's filesystem.
        if let Some(length) = length
            && let Some(free) = free_space(path.parent().unwrap())
            && length.saturating_sub(start) > free
        {
            let message = format!(
                "{} more bytes do not fit in the {free} free on the filesystem of the store at {}",
                length - start,
                self.root.display()
            );
            return Err(AgentError::new(OP, digest, ErrorKind::StorageFull, message));
        }
        if recorded.is_none()
            && let Some(length) = length
        {
            crate::durable::replace(&self.declared(digest).map_err(at)?, length.to_string().as_bytes(), 0o600).map_err(at)?;
        }
        let mut file = tokio::fs::OpenOptions::new().create(create).append(true).mode(0o600).open(&path).await.map_err(at)?;
        let mut hasher = (start == 0).then(Sha256::new);
        let limit = length.map(|length| length - start);
        let received = copy_body(body, &mut file, hasher.as_mut(), limit, Some(&held.superseded)).await;
        let synced = file.sync_all().await;
        drop(file);
        match received {
            Ok(_) => synced.map_err(at)?,
            Err(Copy::TooLong) => {
                // The offset would pass the declared length: the upload is
                // invalid and goes (draft section 4.4.2).
                self.discard(digest).await;
                let message = format!("body runs past Upload-Length {}; the upload was discarded", length.unwrap_or_default());
                return Err(AgentError::new(OP, digest, ErrorKind::PayloadTooLarge, message));
            }
            Err(error) => return Err(error.refusal(OP, digest)),
        }
        let state = self.state(digest).await?.unwrap_or_default();
        if !complete {
            return Ok(state);
        }
        if let Some(length) = length
            && state.offset != length
        {
            let message = format!("completed at {} bytes, not the declared {length}", state.offset);
            return Err(AgentError::new(OP, digest, ErrorKind::InvalidInput, message));
        }
        let actual = match hasher {
            Some(hasher) => format!("{:x}", hasher.finalize()),
            None => hash_file(&path).await.map_err(|e| AgentError::io("upload.verify", path.display(), e))?,
        };
        if actual != *digest {
            self.discard(digest).await;
            return Err(AgentError::new(
                "upload.verify",
                digest,
                ErrorKind::DigestMismatch,
                format!("expected sha256 {digest}, but the {} uploaded bytes have sha256 {actual}; the upload was discarded", state.offset),
            ));
        }
        let blob = self.blob(digest).map_err(|e| AgentError::io("upload.complete", digest, e))?;
        tokio::fs::rename(&path, &blob).await.map_err(|e| AgentError::io("upload.complete", blob.display(), e))?;
        forget(self.declared(digest)).await;
        sync_directory(blob.parent().unwrap()).map_err(|e| AgentError::io("upload.complete", blob.display(), e))?;
        Ok(Progress { offset: state.offset, complete: true, length: Some(state.offset), max_age: None })
    }
    /// Keep verified bytes staged under `partial/<sha256>` as the blob.
    pub(crate) async fn keep(&self, digest: &str) -> io::Result<PathBuf> {
        let blob = self.blob(digest)?;
        tokio::fs::rename(self.partial(digest)?, &blob).await?;
        forget(self.declared(digest)).await;
        sync_directory(blob.parent().unwrap())?;
        Ok(blob)
    }
    pub(crate) async fn discard(&self, digest: &str) {
        forget(self.partial(digest)).await;
        forget(self.declared(digest)).await;
    }
    /// Upload cancellation: end any request using it, then remove it.
    pub(crate) async fn cancel(&self, digest: &str) -> Result<(), AgentError> {
        const OP: &str = "upload.remove";
        let _held = self.take(OP, digest).await?;
        match self.state(digest).await? {
            Some(state) if !state.complete => {
                self.discard(digest).await;
                Ok(())
            }
            _ => Err(AgentError::new(OP, digest, ErrorKind::NotFound, "no incomplete upload of this digest")),
        }
    }
    /// Installs from a blob (`?blob=`) do not take its slot: a removal that
    /// wins the race leaves them a NotFound when they open it.
    pub(crate) async fn remove_blob(&self, digest: &str) -> Result<(), AgentError> {
        const OP: &str = "blob.remove";
        let _held = self.take(OP, digest).await?;
        let path = self.blob(digest).map_err(|e| AgentError::io(OP, digest, e))?;
        tokio::fs::remove_file(&path).await.map_err(|e| AgentError::io(OP, digest, e))
    }
}
/// Remove an upload's file if it is there. A file that cannot go is left
/// for the sweep, and said so.
async fn forget(path: std::io::Result<PathBuf>) {
    let removed = match path {
        Ok(path) => tokio::fs::remove_file(&path).await.map_err(|error| (path.display().to_string(), error)),
        Err(error) => Err(("upload".into(), error)),
    };
    if let Err((path, error)) = removed
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(%path, %error, "could not remove upload file");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Abandoned partial uploads go at startup with their recorded lengths;
    // recent ones and uploads in use stay, so a resume after an ordinary
    // restart still finds its bytes.
    #[tokio::test]
    async fn sweep_removes_only_abandoned_partials() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("store"));
        assert_eq!(store.sweep(ABANDONED).unwrap(), 0, "a store never used has nothing to sweep");
        let [old, busy, recent] = ["a", "b", "c"].map(|c| c.repeat(64));
        for digest in [&old, &busy, &recent] {
            std::fs::write(store.partial(digest).unwrap(), b"partial").unwrap();
            std::fs::write(store.declared(digest).unwrap(), b"9").unwrap();
        }
        let long_ago = SystemTime::now() - ABANDONED - Duration::from_secs(60);
        for digest in [&old, &busy] {
            for path in [store.partial(digest).unwrap(), store.declared(digest).unwrap()] {
                std::fs::File::options().write(true).open(path).unwrap().set_modified(long_ago).unwrap();
            }
        }
        let _in_use = store.take("upload.append", &busy).await.unwrap();
        assert_eq!(store.sweep(ABANDONED).unwrap(), 1);
        assert!(!store.partial(&old).unwrap().exists() && !store.declared(&old).unwrap().exists());
        assert!(store.partial(&busy).unwrap().exists());
        assert!(store.partial(&recent).unwrap().exists());
    }
}

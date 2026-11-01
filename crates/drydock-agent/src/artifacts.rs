//! Artifacts fetched by digest into the store, and kept there as read-only
//! entries. A fetch tries the caller's sources in order, downloading into
//! the same digest-named staging that uploads use, so each source meets one
//! final check: the bytes hash to the digest, or nothing is stored. The
//! verified bytes become the entry `artifacts/<sha256>`: the file itself, or
//! the directory they unpack into. A record in `index/<sha256>`, written
//! once the entry is complete, makes a repeat fetch a lookup that reads and
//! hashes nothing.
//!
//! Links placed through the agent are recorded under `uses/<sha256>/`, and
//! an entry is in use while any recorded link still points into it. Removal
//! refuses an entry in use. An agent that names itself (its holder, as
//! `drydock-agent` names it by its socket) records that name beside each
//! link it places, so that once it is retired a collection
//! ([`collect`]) can release its uses without touching the links of the
//! agents still sharing the store.
use crate::{
    AgentError, Artifact, ArtifactLink, ArtifactSource, ErrorKind, Fetch, Fetched, Origin, Unpack,
    durable::{rename_noreplace, replace, sync_directory},
    fetch::{Failure, Fetcher, Network, Remote, redact},
    files::{open_up, place_link, sync_filesystem},
    query::LinkQuery,
    rest::tail_path,
    server::Shared,
    store::Store,
};
use axum::{
    Json,
    extract::{Path as Route, Query, State},
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io,
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

type Refusal<T> = Result<T, AgentError>;

/// What the index keeps for a complete entry.
#[derive(Serialize, Deserialize)]
struct Record {
    sha256: String,
    size: u64,
    unpack: Unpack,
}

/// The directory holding entries. Guest processes reach entries through
/// links, so it is readable and searchable by everyone, and the store root
/// gains search permission only (its listing stays as it was); uploads,
/// blobs, the index and the use records stay private.
fn entries(store: &Store) -> io::Result<PathBuf> {
    let path = store.directory("artifacts")?;
    for (directory, bits) in [(store.root(), 0o011), (path.as_path(), 0o055)] {
        let mode = std::fs::metadata(directory)?.permissions().mode();
        if mode & bits != bits {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode((mode | bits) & 0o7777))?;
        }
    }
    Ok(path)
}
fn entry(store: &Store, digest: &str) -> io::Result<PathBuf> {
    Ok(entries(store)?.join(digest))
}
fn record_path(store: &Store, digest: &str) -> io::Result<PathBuf> {
    Ok(store.directory("index")?.join(digest))
}
fn uses(store: &Store, digest: &str) -> io::Result<PathBuf> {
    Ok(store.directory("uses")?.join(digest))
}
fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}
fn read_record(store: &Store, operation: &str, digest: &str) -> Refusal<Option<Record>> {
    let path = record_path(store, digest).map_err(|e| AgentError::io(operation, digest, e))?;
    match std::fs::read(&path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes)
                .map_err(|e| AgentError::new(operation, digest, ErrorKind::InvalidData, "unreadable index record").with_cause(e))?,
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(AgentError::io(operation, path.display(), error)),
    }
}
/// The complete entry for `digest`, if the index has one.
fn indexed(store: &Store, operation: &str, digest: &str) -> Refusal<Option<Artifact>> {
    let Some(record) = read_record(store, operation, digest)? else { return Ok(None) };
    let path = entry(store, digest).map_err(|e| AgentError::io(operation, digest, e))?;
    if !exists(&path) {
        return Ok(None);
    }
    let links = links(store, digest, &path).map_err(|e| AgentError::io(operation, digest, e))?.into_iter().map(|(_, link)| link).collect();
    Ok(Some(Artifact { sha256: record.sha256, size: record.size, unpack: record.unpack, path, links }))
}
/// Recorded links still pointing into `entry`, with their record files.
/// Records of links since removed or pointed elsewhere are dropped.
fn links(store: &Store, digest: &str, entry: &Path) -> io::Result<Vec<(PathBuf, PathBuf)>> {
    let directory = uses(store, digest)?;
    let records = match std::fs::read_dir(&directory) {
        Ok(records) => records,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        Err(error) => return Err(error),
    };
    let mut live = Vec::new();
    for record in records {
        let record = record?.path();
        if is_holder(&record) {
            continue;
        }
        let link = PathBuf::from(<std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(std::fs::read(&record)?));
        match std::fs::read_link(&link) {
            Ok(target) if target.starts_with(entry) => live.push((record, link)),
            _ => forget_use(&record),
        }
    }
    live.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(live)
}
/// The holder recorded beside the use `record`.
fn holder_of(record: &Path) -> PathBuf {
    crate::upgrade::sidecar(record, "holder")
}
fn is_holder(record: &Path) -> bool {
    record.extension().is_some_and(|extension| extension == "holder")
}
/// Drop a use record and the holder beside it.
fn forget_use(record: &Path) {
    let _ = std::fs::remove_file(record);
    let _ = std::fs::remove_file(holder_of(record));
}
/// Remove an entry, write-protected as it is.
fn remove_entry(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            open_up(path)?;
            std::fs::remove_dir_all(path)
        }
        Ok(_) => std::fs::remove_file(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
/// `path` as components inside a tree: relative, without `..`. `.` parts
/// are dropped; an empty result names the tree itself.
pub(crate) fn inside(path: &Path) -> Option<PathBuf> {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => result.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(result)
}
/// Whether a symlink at `link` (inside the tree) pointing at `target`
/// resolves inside the tree by its own path alone. This is the early check
/// with the clearer message; [`contained`] is the one that decides, since
/// a target can pass through other symlinks.
pub(crate) fn resolves_inside(link: &Path, target: &Path) -> bool {
    if target.as_os_str().is_empty() {
        return false;
    }
    let mut depth = link.components().count().saturating_sub(1);
    for component in target.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

/// Whether the symlink at `link` (relative to `root`) resolves inside the
/// tree as the kernel resolves it: following every symlink met on the way,
/// so a target such as `s/../x` with `s -> .` is seen to climb out. A
/// resolution that would leave the tree, or loops, is refused; one that
/// reaches a missing name inside it is a dangling link, and inside.
fn contained(root: &Path, link: &Path) -> io::Result<bool> {
    enum Part {
        Up,
        Name(std::ffi::OsString),
        Root,
    }
    // Parts still to resolve, the next one last.
    fn push(pending: &mut Vec<Part>, target: &Path) {
        let parts = target.components().filter_map(|c| match c {
            Component::Normal(name) => Some(Part::Name(name.to_owned())),
            Component::ParentDir => Some(Part::Up),
            Component::CurDir => None,
            Component::RootDir | Component::Prefix(_) => Some(Part::Root),
        });
        pending.extend(parts.collect::<Vec<_>>().into_iter().rev());
    }
    let mut position: Vec<std::ffi::OsString> =
        link.parent().unwrap_or(Path::new("")).components().map(|c| c.as_os_str().to_owned()).collect();
    let mut pending = Vec::new();
    push(&mut pending, &std::fs::read_link(root.join(link))?);
    let mut hops = 0;
    while let Some(part) = pending.pop() {
        match part {
            Part::Up => {
                if position.pop().is_none() {
                    return Ok(false);
                }
            }
            Part::Name(name) => {
                position.push(name);
                let here: PathBuf = position.iter().fold(root.to_path_buf(), |path, part| path.join(part));
                if std::fs::symlink_metadata(&here).is_ok_and(|m| m.file_type().is_symlink()) {
                    hops += 1;
                    if hops > 40 {
                        return Ok(false);
                    }
                    position.pop();
                    push(&mut pending, &std::fs::read_link(&here)?);
                }
            }
            Part::Root => return Ok(false),
        }
    }
    Ok(true)
}
/// Every symlink under `into`, relative to it.
fn symlinks(into: &Path, at: &Path, found: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in std::fs::read_dir(at)? {
        let path = entry?.path();
        let kind = std::fs::symlink_metadata(&path)?.file_type();
        if kind.is_symlink() {
            found.push(path.strip_prefix(into).unwrap().to_path_buf());
        } else if kind.is_dir() {
            symlinks(into, &path, found)?;
        }
    }
    Ok(())
}
/// A refusal of the archive's content, as opposed to a filesystem error.
fn refuse(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
/// Unpack a tar archive into `into`, refusing any entry that would leave
/// the tree: a path with `..` or a root, a symlink pointing outside it, a
/// hard link to outside it, and device files and FIFOs. An entry under a
/// symlink the archive made is refused too, wherever the symlink points:
/// the entry's path would no longer say where it lands. So is a second
/// entry at a symlink's own path. Entries keep their
/// modes without setuid and setgid, and belong to the agent.
pub(crate) fn unpack_archive(reader: impl io::Read, gzip: bool, into: &Path) -> io::Result<()> {
    let reader: Box<dyn io::Read> = if gzip { Box::new(flate2::read::GzDecoder::new(reader)) } else { Box::new(reader) };
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_mask(0o6000);
    archive.set_preserve_ownerships(false);
    archive.set_unpack_xattrs(false);
    archive.set_overwrite(true);
    // Directories come last, as tar's own unpack does, so a directory
    // archived without write permission still receives its entries.
    let mut directories = Vec::new();
    let mut links = std::collections::HashSet::new();
    let under_link = |links: &std::collections::HashSet<PathBuf>, path: &Path| path.ancestors().skip(1).any(|a| links.contains(a));
    for entry in archive.entries()? {
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        let named = entry.path()?.into_owned();
        let shown = named.display().to_string();
        let path = inside(&named).ok_or_else(|| refuse(format!("{shown}: the path leaves the tree")))?;
        if under_link(&links, &path) {
            return Err(refuse(format!("{shown}: the path passes through a symlink in the archive")));
        }
        // A second entry at a symlink's own path would act through it (a
        // directory entry sets its mode on the link's target).
        if links.contains(&path) {
            return Err(refuse(format!("{shown}: the archive already made this path a symlink")));
        }
        use tar::EntryType::*;
        match kind {
            Directory => {
                directories.push(entry);
                continue;
            }
            Regular | Continuous | GNUSparse => {}
            Symlink => {
                let target = entry.link_name()?.ok_or_else(|| refuse(format!("{shown}: a symlink without a target")))?;
                if !resolves_inside(&path, &target) {
                    return Err(refuse(format!("{shown}: the symlink to {} points outside the tree", target.display())));
                }
                links.insert(path.clone());
            }
            Link => {
                let target = entry.link_name()?.ok_or_else(|| refuse(format!("{shown}: a hard link without a target")))?;
                let within = inside(&target).filter(|target| !target.as_os_str().is_empty());
                if within.is_none_or(|target| under_link(&links, &target.join("x"))) {
                    return Err(refuse(format!("{shown}: the hard link to {} points outside the tree", target.display())));
                }
            }
            Char | Block => return Err(refuse(format!("{shown}: device files are refused"))),
            Fifo => return Err(refuse(format!("{shown}: FIFOs are refused"))),
            XGlobalHeader => continue,
            other => return Err(refuse(format!("{shown}: entry type {other:?} is refused"))),
        }
        if path.as_os_str().is_empty() {
            return Err(refuse(format!("{shown}: names the tree itself")));
        }
        if !entry.unpack_in(into)? {
            return Err(refuse(format!("{shown}: the path leaves the tree")));
        }
    }
    for mut directory in directories {
        directory.unpack_in(into)?;
    }
    let mut found = Vec::new();
    symlinks(into, into, &mut found)?;
    for link in found {
        if !contained(into, &link)? {
            return Err(refuse(format!("{}: the symlink resolves outside the tree", link.display())));
        }
    }
    Ok(())
}
/// Clear every write bit under `root`; symlinks have no mode of their own.
fn read_only(root: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_dir() {
        for child in std::fs::read_dir(root)? {
            read_only(&child?.path())?;
        }
    }
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(metadata.permissions().mode() & 0o7555))
}

/// Turn the verified blob into the entry, then index it. The blob goes: a
/// file entry is the blob renamed, and an archive's bytes are no longer
/// needed once unpacked. A refused unpack keeps the blob, so asking again
/// reads it instead of downloading it.
async fn materialize(store: &Store, digest: &str, unpack: Unpack) -> Result<Artifact, Failure> {
    let disk = |error: io::Error| Failure { fatal: true, ..Failure::new("disk", error.kind().into(), error.to_string()) };
    let blob = store.blob(digest).map_err(disk)?;
    let size = std::fs::metadata(&blob).map_err(disk)?.len();
    let directory = entries(store).map_err(disk)?;
    let path = directory.join(digest);
    match unpack {
        Unpack::File { mode } => {
            std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(mode & 0o1555)).map_err(disk)?;
            std::fs::rename(&blob, &path).map_err(disk)?;
        }
        Unpack::Tar | Unpack::TarGz => {
            let staging = tempfile::Builder::new().prefix(&format!(".{digest}.")).tempdir_in(&directory).map_err(disk)?.keep();
            let (source, into) = (blob.clone(), staging.clone());
            let unpacked = tokio::task::spawn_blocking(move || -> io::Result<()> {
                let reader = io::BufReader::with_capacity(256 * 1024, std::fs::File::open(source)?);
                unpack_archive(reader, unpack == Unpack::TarGz, &into)?;
                read_only(&into)?;
                // Every unpacked byte is durable before the entry appears.
                sync_filesystem(&into)
            })
            .await
            .unwrap_or_else(|e| Err(io::Error::other(e)));
            if let Err(error) = unpacked {
                let _ = remove_entry(&staging);
                return Err(match error.kind() {
                    io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => disk(error),
                    _ => Failure {
                        fatal: true,
                        ..Failure::new(
                            "unpack",
                            ErrorKind::InvalidData,
                            format!("{error}; nothing was stored, the verified bytes are kept"),
                        )
                    },
                });
            }
            if let Err(error) = rename_noreplace(&staging, &path) {
                let _ = remove_entry(&staging);
                return Err(disk(error));
            }
            std::fs::remove_file(&blob).map_err(disk)?;
        }
    }
    sync_directory(&directory).map_err(disk)?;
    let record = serde_json::to_vec(&Record { sha256: digest.to_owned(), size, unpack }).expect("a record serializes");
    replace(&record_path(store, digest).map_err(disk)?, &record, 0o600).map_err(disk)?;
    Ok(Artifact { sha256: digest.to_owned(), size, unpack, path, links: vec![] })
}

fn describe(index: usize, source: &ArtifactSource) -> String {
    match source {
        ArtifactSource::Upstream { url } => match url::Url::parse(url) {
            Ok(url) => format!("[{index}] upstream {}", redact(&url)),
            Err(_) => format!("[{index}] upstream (not a URL)"),
        },
        ArtifactSource::Oci { registry, repository, .. } => format!("[{index}] oci {registry}/{repository}"),
        ArtifactSource::Push => format!("[{index}] push"),
    }
}
/// The refusal when no source gave the artifact: it names each source,
/// the step that failed and why. The last failure gives its kind; when it
/// was the push, the operation is `artifact.push`, which asks the caller to
/// upload the bytes and fetch again.
fn failed(digest: &str, failures: Vec<(String, Failure)>) -> AgentError {
    let Some((_, last)) = failures.last() else {
        return AgentError::new(
            "artifact.fetch",
            digest,
            ErrorKind::NotFound,
            "the store holds no entry or upload of this digest, and no source was named",
        );
    };
    let operation = if last.step == "push" { "artifact.push" } else { "artifact.fetch" };
    let kind = last.kind;
    let lines: Vec<String> = failures.iter().map(|(source, failure)| format!("{source}: {failure}")).collect();
    if let [line] = &lines[..] {
        return AgentError::new(operation, digest, kind, format!("sha256 {digest}: {line}"));
    }
    let mut error = AgentError::new(operation, digest, kind, format!("sha256 {digest}: all {} sources failed", lines.len()));
    error.causes = lines;
    error
}

async fn fetch(store: Store, network: Network, digest: String, request: Fetch) -> Refusal<Fetched> {
    const OP: &str = "artifact.fetch";
    let at = |e| AgentError::io(OP, &digest, e);
    let _held = store.wait_for(OP, &digest).await?;
    if let Some(artifact) = indexed(&store, OP, &digest)? {
        if artifact.unpack != request.unpack {
            let message = format!("already stored as {:?}; remove it to store it differently", artifact.unpack);
            return Err(AgentError::new(OP, &digest, ErrorKind::Conflict, message));
        }
        // A hit is a use about to be linked: a collection leaves the entry
        // alone for a while after it (see [`collect`]).
        touch(&record_path(&store, &digest).map_err(at)?);
        return Ok(Fetched { artifact, origin: Origin::Index });
    }
    // Anything here without a record is the remains of an interrupted
    // fetch: a half-made entry or its staging. The digest is held, so no
    // other fetch is making them.
    let directory = entries(&store).map_err(at)?;
    for leftover in std::fs::read_dir(&directory).map_err(at)? {
        let leftover = leftover.map_err(at)?;
        let name = leftover.file_name().to_string_lossy().into_owned();
        if name == digest || name.starts_with(&format!(".{digest}.")) {
            remove_entry(&leftover.path()).map_err(at)?;
        }
    }
    let _ = std::fs::remove_file(record_path(&store, &digest).map_err(at)?);
    let mut failures = Vec::new();
    if store.blob_size(&digest).await?.is_some() {
        match materialize(&store, &digest, request.unpack).await {
            Ok(artifact) => return Ok(Fetched { artifact, origin: Origin::Blob }),
            Err(failure) => return Err(failed(&digest, vec![("stored upload".into(), failure)])),
        }
    }
    let staging = store.partial(&digest).map_err(at)?;
    let mut fetcher = Fetcher::new(network);
    for (index, source) in request.sources.iter().enumerate() {
        let described = describe(index, source);
        let remote = match source {
            ArtifactSource::Upstream { url } => Remote::upstream(url),
            ArtifactSource::Oci { registry, repository, credential } => Remote::oci(registry, repository, credential.clone(), &digest),
            ArtifactSource::Push => {
                let staged = store.state(&digest).await?.map_or(0, |state| state.offset);
                let message = format!("no completed upload; upload it to /blobs/{digest} ({staged} bytes staged), then fetch again");
                failures.push((described, Failure::new("push", ErrorKind::NotFound, message)));
                continue;
            }
        };
        let downloaded = match remote {
            Ok(mut remote) => fetcher.download(&mut remote, &staging, &digest).await,
            Err(failure) => Err(failure),
        };
        let result = match downloaded {
            Ok(_) => match store.keep(&digest).await {
                Ok(_) => materialize(&store, &digest, request.unpack).await,
                Err(error) => Err(Failure { fatal: true, ..Failure::new("disk", error.kind().into(), error.to_string()) }),
            },
            Err(failure) => Err(failure),
        };
        match result {
            Ok(artifact) => return Ok(Fetched { artifact, origin: Origin::Source(index) }),
            Err(failure) => {
                let fatal = failure.fatal;
                failures.push((described, failure));
                if fatal {
                    break;
                }
            }
        }
    }
    Err(failed(&digest, failures))
}

/// Fetch an artifact into the store: 200 when the index already had it,
/// 201 when it was stored now. The fetch runs as its own task, so a caller
/// that goes away leaves it to finish for the next call.
pub(crate) async fn put_artifact(
    State(shared): State<Arc<Shared>>,
    Route(digest): Route<String>,
    Json(request): Json<Fetch>,
) -> Refusal<Response> {
    const OP: &str = "artifact.fetch";
    crate::check_sha256(&digest).map_err(|e| AgentError::io(OP, &digest, e))?;
    if let Unpack::File { mode } = request.unpack
        && mode > 0o7777
    {
        return Err(AgentError::new(OP, &digest, ErrorKind::InvalidInput, format!("mode {mode:o} has bits beyond 07777")));
    }
    let network = shared.network().await;
    let store = shared.store.clone();
    let task = tokio::spawn(fetch(store, network, digest.clone(), request));
    let fetched = task.await.map_err(|e| AgentError::new(OP, &digest, ErrorKind::Other, "fetch task failed").with_cause(e))??;
    let status = if fetched.origin == Origin::Index { StatusCode::OK } else { StatusCode::CREATED };
    Ok((status, Json(fetched)).into_response())
}
pub(crate) async fn get_artifact(State(shared): State<Arc<Shared>>, Route(digest): Route<String>) -> Refusal<Json<Artifact>> {
    const OP: &str = "artifact.stat";
    crate::check_sha256(&digest).map_err(|e| AgentError::io(OP, &digest, e))?;
    let artifact = indexed(&shared.store, OP, &digest)?;
    Ok(Json(artifact.ok_or_else(|| AgentError::new(OP, &digest, ErrorKind::NotFound, "no stored artifact of this digest"))?))
}
/// Complete entries, by digest.
pub(crate) async fn list_artifacts(State(shared): State<Arc<Shared>>) -> Refusal<Json<Vec<Artifact>>> {
    const OP: &str = "artifact.list";
    let directory = shared.store.directory("index").map_err(|e| AgentError::io(OP, "index", e))?;
    let mut digests: Vec<String> = std::fs::read_dir(&directory)
        .map_err(|e| AgentError::io(OP, directory.display(), e))?
        .filter_map(|entry| entry.ok().map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .filter(|name| crate::check_sha256(name).is_ok())
        .collect();
    digests.sort();
    let mut listed = Vec::new();
    // One unreadable record is skipped, not a reason to list nothing.
    for digest in digests {
        match indexed(&shared.store, OP, &digest) {
            Ok(artifact) => listed.extend(artifact),
            Err(error) => tracing::warn!(%error, "skipping an unreadable artifact record"),
        }
    }
    Ok(Json(listed))
}
/// Remove an entry no link uses (409 naming the links otherwise).
pub(crate) async fn delete_artifact(State(shared): State<Arc<Shared>>, Route(digest): Route<String>) -> Refusal<StatusCode> {
    const OP: &str = "artifact.remove";
    let _held = shared.store.wait_for(OP, &digest).await?;
    remove_unused(&shared.store, OP, &digest)?;
    Ok(StatusCode::NO_CONTENT)
}
/// Remove the entry for `digest`, held by the caller, unless a link uses it.
fn remove_unused(store: &Store, operation: &str, digest: &str) -> Refusal<()> {
    let at = |e| AgentError::io(operation, digest, e);
    let Some(artifact) = indexed(store, operation, digest)? else {
        return Err(AgentError::new(operation, digest, ErrorKind::NotFound, "no stored artifact of this digest"));
    };
    if !artifact.links.is_empty() {
        let names: Vec<String> = artifact.links.iter().map(|link| link.display().to_string()).collect();
        return Err(AgentError::new(operation, digest, ErrorKind::ResourceBusy, format!("in use by {}", names.join(", "))));
    }
    // The record goes first: from then on the entry is no longer a hit.
    let record = record_path(store, digest).map_err(at)?;
    std::fs::remove_file(&record).map_err(at)?;
    sync_directory(record.parent().unwrap()).map_err(at)?;
    remove_entry(&artifact.path).map_err(at)?;
    let _ = std::fs::remove_dir_all(uses(store, digest).map_err(at)?);
    Ok(())
}
/// Set a file's modification time to now, if it is there.
fn touch(path: &Path) {
    if let Ok(file) = std::fs::File::options().write(true).open(path) {
        let _ = file.set_modified(std::time::SystemTime::now());
    }
}
/// What one [`collect`] removed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Collected {
    /// Entries removed, by digest.
    pub artifacts: Vec<String>,
    /// Completed uploads removed, by digest.
    pub blobs: Vec<String>,
    /// Uses of the released holders that were dropped.
    pub released: usize,
}
/// One bounded pass over the store at `root`, which other agents may be
/// using. First the uses recorded by any of `released` (agents retired for
/// good) are dropped; their links stay where they are. Then every entry no
/// remaining link uses goes, and every completed upload nothing made an
/// entry of, unless it was stored, hit or uploaded within `idle`: a fetch
/// that has just hit an entry links it next, and an upload just completed is
/// fetched or activated next. Each digest is held while it is looked at, as
/// every agent sharing the store holds it, so no fetch, link or upload
/// interleaves. Entries are removed write-protected as they are.
pub async fn collect(root: PathBuf, released: &[String], idle: std::time::Duration) -> io::Result<Collected> {
    const OP: &str = "artifact.collect";
    let store = Store::new(root);
    let idle_for = |path: &Path| {
        std::fs::metadata(path).and_then(|m| m.modified()).is_ok_and(|modified| modified.elapsed().is_ok_and(|elapsed| elapsed >= idle))
    };
    let digests = |directory: &str| -> io::Result<Vec<String>> {
        let mut names: Vec<String> = match std::fs::read_dir(store.root().join(directory)) {
            Ok(entries) => entries.filter_map(|entry| entry.ok().map(|entry| entry.file_name().to_string_lossy().into_owned())).collect(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => vec![],
            Err(error) => return Err(error),
        };
        names.retain(|name| crate::check_sha256(name).is_ok());
        names.sort();
        Ok(names)
    };
    let mut collected = Collected::default();
    for digest in digests("uses")? {
        let _held = store.wait_for(OP, &digest).await.map_err(AgentError::into_io)?;
        let Ok(records) = std::fs::read_dir(uses(&store, &digest)?) else { continue };
        for record in records.flatten().map(|record| record.path()).filter(|record| !is_holder(record)) {
            let holder = std::fs::read(holder_of(&record)).ok().map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
            if holder.is_some_and(|holder| released.contains(&holder)) {
                forget_use(&record);
                collected.released += 1;
            }
        }
    }
    // One entry that cannot be looked at or removed does not stop the rest.
    for digest in digests("index")? {
        let _held = store.wait_for(OP, &digest).await.map_err(AgentError::into_io)?;
        if !idle_for(&record_path(&store, &digest)?) {
            continue;
        }
        match remove_unused(&store, OP, &digest) {
            Ok(()) => collected.artifacts.push(digest),
            Err(error) if matches!(error.kind, ErrorKind::ResourceBusy | ErrorKind::NotFound) => {}
            Err(error) => tracing::warn!(%error, "could not collect an artifact"),
        }
    }
    for digest in digests("blobs")? {
        let _held = store.wait_for(OP, &digest).await.map_err(AgentError::into_io)?;
        let blob = store.blob(&digest)?;
        if idle_for(&blob) {
            match std::fs::remove_file(&blob) {
                Ok(()) => collected.blobs.push(digest),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => tracing::warn!(%error, %digest, "could not collect a completed upload"),
            }
        }
    }
    Ok(collected)
}
/// Place a symlink to an entry, or to a member inside it, atomically, and
/// record it as a use of the entry.
pub(crate) async fn put_artifact_link(
    State(shared): State<Arc<Shared>>,
    uri: Uri,
    Query(query): Query<LinkQuery>,
    Json(link): Json<ArtifactLink>,
) -> Refusal<Response> {
    const OP: &str = "artifact.link";
    let digest = uri.path().strip_prefix("/artifacts/").and_then(|rest| rest.split_once('/')).map(|(digest, _)| digest).unwrap_or_default();
    let digest = digest.to_owned();
    crate::check_sha256(&digest).map_err(|e| AgentError::io(OP, &digest, e))?;
    let path = tail_path(OP, &uri, &format!("/artifacts/{digest}/links"))?;
    let member = inside(&link.member)
        .filter(|_| !link.member.as_os_str().as_encoded_bytes().contains(&0))
        .ok_or_else(|| AgentError::new(OP, link.member.display(), ErrorKind::InvalidInput, "member must be a relative path without .."))?;
    let store = &shared.store;
    let _held = store.wait_for(OP, &digest).await?;
    let Some(artifact) = indexed(store, OP, &digest)? else {
        return Err(AgentError::new(OP, &digest, ErrorKind::NotFound, "no stored artifact of this digest; fetch it first"));
    };
    let target = if member.as_os_str().is_empty() { artifact.path.clone() } else { artifact.path.join(&member) };
    if !exists(&target) {
        return Err(AgentError::new(OP, target.display(), ErrorKind::NotFound, "the artifact has no such member"));
    }
    // The use is recorded before the link exists, so no removal can miss it.
    let records = uses(store, &digest).map_err(|e| AgentError::io(OP, &digest, e))?;
    std::fs::create_dir_all(&records).map_err(|e| AgentError::io(OP, records.display(), e))?;
    let name = format!("{:x}", Sha256::digest(path.as_os_str().as_encoded_bytes()));
    let record = records.join(name);
    let recorded = match &shared.holder {
        Some(holder) => replace(&holder_of(&record), holder.as_bytes(), 0o600),
        None => std::fs::remove_file(holder_of(&record)).or_else(|e| if e.kind() == io::ErrorKind::NotFound { Ok(()) } else { Err(e) }),
    };
    recorded
        .and_then(|()| replace(&record, path.as_os_str().as_encoded_bytes(), 0o600))
        .map_err(|e| AgentError::io(OP, records.display(), e))?;
    let existed = place_link(OP, &path, &target, &query)?;
    Ok(if existed { StatusCode::OK } else { StatusCode::CREATED }.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::{Generator, generators as gs};

    /// A raw tar path: relative, of `a` and `b`, or with `hostile` also
    /// absolute and with `..` and `.` parts. Written straight into the
    /// header, so no builder can tidy it first.
    fn raw_path(tc: &hegel::TestCase, hostile: bool) -> String {
        let absolute = hostile && tc.draw(gs::booleans());
        let count = tc.draw(gs::integers::<usize>().min_value(1).max_value(3));
        let alphabet = if hostile { vec!["a", "b", "..", "."] } else { vec!["a", "b"] };
        let parts: Vec<&str> = (0..count).map(|_| tc.draw(gs::sampled_from(alphabet.clone()))).collect();
        format!("{}{}", if absolute { "/" } else { "" }, parts.join("/"))
    }
    fn escapes(path: &str) -> bool {
        path.starts_with('/') || path.split('/').any(|part| part == "..")
    }
    fn header(kind: tar::EntryType, path: &str, target: &str, content: &[u8]) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.as_gnu_mut().unwrap().name[..path.len()].copy_from_slice(path.as_bytes());
        header.as_gnu_mut().unwrap().linkname[..target.len()].copy_from_slice(target.as_bytes());
        header.set_entry_type(kind);
        header.set_mode(0o755);
        header.set_size(content.len() as u64);
        header.set_cksum();
        let mut bytes = header.as_bytes().to_vec();
        bytes.extend_from_slice(content);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
        bytes
    }

    // Unpacking never creates anything outside the tree: every symlink
    // left in it resolves inside it. An entry whose path is absolute or
    // climbs, a symlink with an absolute target, a hard link whose target
    // climbs or is absolute, and any device file or FIFO are refused.
    // Generated: up to four benign entries (files, directories and symlinks
    // to `a`, `b` and `.`) around one hazard of a drawn shape: none, a
    // hostile path, a symlink or hard link with a hostile target, a chain
    // (a symlink to the root, then a path or target through it), or a
    // special file. Hostile paths and targets have up to three parts of {a,
    // b, .., .}, absolute or relative. The tree sits three levels below
    // the sandbox, beside bait files named `a` and `b` at every level, so a
    // link that got out resolves to bait and is seen.
    #[hegel::test]
    fn unpacking_never_leaves_the_tree(tc: hegel::TestCase) {
        use tar::EntryType;
        let sandbox = tempfile::tempdir().unwrap();
        let into = sandbox.path().join("l1/l2/into");
        std::fs::create_dir_all(&into).unwrap();
        let leading = [sandbox.path().to_path_buf(), sandbox.path().join("l1"), sandbox.path().join("l1/l2")];
        let mut outside = leading.to_vec();
        for level in &leading {
            for bait in ["a", "b"] {
                std::fs::write(level.join(bait), b"bait").unwrap();
                outside.push(level.join(bait));
            }
        }
        outside.sort();
        let benign = tc.draw(gs::integers::<usize>().min_value(0).max_value(4));
        let at = tc.draw(gs::integers::<usize>().min_value(0).max_value(benign));
        let mut archive = Vec::new();
        let mut refused = false;
        for index in 0..=benign {
            if index == at {
                let hazard = tc.draw(gs::sampled_from(vec!["none", "path", "symlink", "chain", "hard link", "char", "block", "fifo"]));
                if hazard == "chain" {
                    // A symlink to the tree's root, then one whose target
                    // or path goes through it.
                    let name = tc.draw(gs::sampled_from(vec!["a", "b"]));
                    archive.extend(header(EntryType::Symlink, name, ".", b""));
                    let through = tc.draw(gs::booleans());
                    let path = if through { format!("{name}/{}", raw_path(&tc, false)) } else { raw_path(&tc, false) };
                    let target = if through { raw_path(&tc, true) } else { format!("{name}/{}", raw_path(&tc, true)) };
                    refused = through || target.starts_with('/');
                    archive.extend(header(EntryType::Symlink, &path, &target, b""));
                    continue;
                }
                let (kind, path, target) = match hazard {
                    "none" => (EntryType::Regular, raw_path(&tc, false), String::new()),
                    "path" => (
                        tc.draw(gs::sampled_from(vec![EntryType::Regular, EntryType::Directory]).print_as_debug()),
                        raw_path(&tc, true),
                        String::new(),
                    ),
                    "symlink" => (EntryType::Symlink, raw_path(&tc, false), raw_path(&tc, true)),
                    "hard link" => (EntryType::Link, raw_path(&tc, false), raw_path(&tc, true)),
                    "char" => (EntryType::Char, raw_path(&tc, false), String::new()),
                    "block" => (EntryType::Block, raw_path(&tc, false), String::new()),
                    _ => (EntryType::Fifo, raw_path(&tc, false), String::new()),
                };
                refused = escapes(&path)
                    || matches!(kind, EntryType::Char | EntryType::Block | EntryType::Fifo)
                    || (kind == EntryType::Symlink && target.starts_with('/'))
                    || (kind == EntryType::Link && escapes(&target));
                let content: &[u8] = if kind == EntryType::Regular { b"bytes" } else { b"" };
                archive.extend(header(kind, &path, &target, content));
            } else {
                let kind = tc.draw(gs::sampled_from(vec![EntryType::Regular, EntryType::Directory, EntryType::Symlink]).print_as_debug());
                let target =
                    if kind == EntryType::Symlink { tc.draw(gs::sampled_from(vec!["a", "b", "."])).to_owned() } else { String::new() };
                let content: &[u8] = if kind == EntryType::Regular { b"bytes" } else { b"" };
                archive.extend(header(kind, &raw_path(&tc, false), &target, content));
            }
        }
        archive.resize(archive.len() + 1024, 0);
        let result = unpack_archive(archive.as_slice(), false, &into);
        // A benign entry may fail first for an ordinary reason, such as a
        // file where a directory must go; either way nothing is accepted.
        assert!(!refused || result.is_err(), "an escaping or special entry is refused");
        // Nothing beside the tree but the directories leading to it and the bait.
        let found: Vec<PathBuf> = walk(sandbox.path()).into_iter().filter(|path| !path.starts_with(&into)).collect();
        assert_eq!(found, outside, "created outside the tree");
        // Every link that resolves at all resolves inside, as the kernel sees it.
        let root = into.canonicalize().unwrap();
        for path in walk(&into) {
            if std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink()
                && let Ok(real) = path.canonicalize()
            {
                assert!(real.starts_with(&root), "{} resolves to {}", path.display(), real.display());
            }
        }
    }

    // A symlink is judged where it physically lands and by what its target
    // resolves through: an entry under a symlink the archive made is
    // refused, as is a second entry at its own path, and so is a target that
    // climbs out through one, while a target through an in-tree symlink that
    // stays inside is kept.
    #[test]
    fn symlink_chains_are_resolved_as_the_kernel_resolves_them() {
        use tar::EntryType::{Directory, Regular, Symlink};
        type Entries<'a> = &'a [(tar::EntryType, &'a str, &'a str)];
        let cases: [(Entries, bool); 5] = [
            (&[(Symlink, "s", "."), (Symlink, "s/t", "../x")], false),
            (&[(Symlink, "s", "."), (Regular, "s/f", "")], false),
            (&[(Symlink, "s", "."), (Symlink, "t", "s/../x")], false),
            (&[(Directory, "a", ""), (Symlink, "s", "a"), (Directory, "s", "")], false),
            (&[(Directory, "d", ""), (Regular, "d/f", ""), (Symlink, "s", "d"), (Symlink, "t", "s/f"), (Symlink, "u", "s/../d")], true),
        ];
        for (entries, accepted) in cases {
            let sandbox = tempfile::tempdir().unwrap();
            let into = sandbox.path().join("into");
            std::fs::create_dir(&into).unwrap();
            let mut archive: Vec<u8> = entries.iter().flat_map(|(kind, path, target)| header(*kind, path, target, b"")).collect();
            archive.resize(archive.len() + 1024, 0);
            let result = unpack_archive(archive.as_slice(), false, &into);
            assert_eq!(result.is_ok(), accepted, "{entries:?}: {result:?}");
            if let Err(error) = result {
                assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
            }
        }
    }
    fn walk(root: &Path) -> Vec<PathBuf> {
        let mut found = vec![root.to_path_buf()];
        if std::fs::symlink_metadata(root).unwrap().is_dir() {
            let mut children: Vec<_> = std::fs::read_dir(root).unwrap().map(|e| e.unwrap().path()).collect();
            children.sort();
            for child in children {
                found.extend(walk(&child));
            }
        }
        found
    }
}

//! File operations. Bytes travel as `application/octet-stream` request and
//! response bodies, streamed straight to and from disk.
use crate::{
    AgentError, Attributes, Compression, Entry, EntryKind, ErrorKind, FileOptions, Link, Rename, TreeOptions, Written,
    durable::{exchange, rename_noreplace, sync_directory},
    query::{DirQuery, LinkQuery, RemoveQuery, WithBlob},
    rest::{check_path, header_value, if_match, tail_path},
    server::Shared,
};
use axum::{
    Json,
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use std::{
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

type Refusal<T> = Result<T, AgentError>;

fn check_mode(operation: &str, path: &Path, mode: Option<u32>) -> Refusal<()> {
    if mode.is_some_and(|mode| mode > 0o7777) {
        return Err(AgentError::new(
            operation,
            path.display(),
            ErrorKind::InvalidInput,
            format!("mode {:o} has bits beyond 07777", mode.unwrap()),
        ));
    }
    Ok(())
}
/// The permission bits the agent sets: setuid and setgid are never granted
/// through it, whatever a request or an existing file carries.
fn permitted(mode: u32) -> u32 {
    mode & 0o1777
}
fn check_digest(operation: &str, digest: &Option<String>) -> Refusal<()> {
    if let Some(digest) = digest {
        crate::check_sha256(digest).map_err(|e| AgentError::io(operation, digest, e))?;
    }
    Ok(())
}
pub(crate) fn require_octet_stream(operation: &str, path: &Path, headers: &HeaderMap, allowed: &[&str]) -> Refusal<()> {
    let found = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let essence = found.split(';').next().unwrap_or("").trim();
    if !allowed.iter().any(|allowed| allowed.eq_ignore_ascii_case(essence)) {
        return Err(AgentError::new(
            operation,
            path.display(),
            ErrorKind::UnsupportedMediaType,
            format!("content type must be {}, not {found:?}", allowed.join(" or ")),
        ));
    }
    Ok(())
}
/// Validator for a file's current bytes. Writes replace the inode, so inode,
/// size and modification time together change with the content. It is best
/// effort: an in-place rewrite of the same size within one timestamp tick
/// onto the same inode would keep the tag.
pub(crate) fn etag(metadata: &std::fs::Metadata) -> String {
    let modified = metadata.mtime() as i128 * 1_000_000_000 + metadata.mtime_nsec() as i128;
    format!("\"{:x}-{:x}-{:x}\"", metadata.ino(), metadata.len(), modified)
}
pub(crate) fn entry(name: String, metadata: &std::fs::Metadata, path: &Path) -> Entry {
    let kind = if metadata.file_type().is_symlink() {
        EntryKind::Symlink
    } else if metadata.is_dir() {
        EntryKind::Directory
    } else if metadata.is_file() {
        EntryKind::File
    } else {
        EntryKind::Other
    };
    Entry {
        name,
        kind,
        size: metadata.len(),
        mode: metadata.mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        modified_ns: metadata.mtime() as i128 * 1_000_000_000 + metadata.mtime_nsec() as i128,
        target: if kind == EntryKind::Symlink { std::fs::read_link(path).ok() } else { None },
    }
}
/// The entry at `path`, named by its last component, or `/` for the root.
fn entry_at(operation: &str, path: &Path) -> Refusal<Entry> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| AgentError::io(operation, path.display(), e))?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "/".into());
    Ok(entry(name, &metadata, path))
}
fn chown(file: &std::fs::File, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
    std::os::unix::fs::fchown(file, uid, gid)
}
/// `path` itself, opened to change its mode and owner through the
/// descriptor, never a symlink's target: a check and a change then always
/// concern the same inode. A symlink is ELOOP (ENOTDIR for a `directory`).
/// On Linux the descriptor is `O_PATH`, which needs no read permission, so
/// an owner can still change an entry whose mode lets nobody read it; it
/// neither blocks on a FIFO nor acquires a terminal.
fn open_nofollow(path: &Path, directory: bool) -> io::Result<rustix::fd::OwnedFd> {
    use rustix::fs::{FileType, Mode, OFlags};
    #[cfg(target_os = "linux")]
    let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let fd = rustix::fs::open(path, if directory { flags | OFlags::DIRECTORY } else { flags }, Mode::empty())?;
    // O_PATH opens a symlink itself rather than refusing it.
    if FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode) == FileType::Symlink {
        return Err(io::Error::from_raw_os_error(libc::ELOOP));
    }
    Ok(fd)
}
fn change(fd: &rustix::fd::OwnedFd, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
    use rustix::fs::{Gid, Mode, Uid};
    if uid.is_some() || gid.is_some() {
        let (uid, gid) = (uid.map(Uid::from_raw_unchecked), gid.map(Gid::from_raw_unchecked));
        // An O_PATH descriptor's owner changes through chownat on itself.
        #[cfg(target_os = "linux")]
        rustix::fs::chownat(fd, "", uid, gid, rustix::fs::AtFlags::EMPTY_PATH)?;
        #[cfg(not(target_os = "linux"))]
        rustix::fs::fchown(fd, uid, gid)?;
    }
    if let Some(mode) = mode {
        let mode = Mode::from_raw_mode(permitted(mode) as _);
        // fchmod refuses an O_PATH descriptor; its /proc link names the same inode.
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            rustix::fs::chmod(format!("/proc/self/fd/{}", fd.as_raw_fd()), mode)?;
        }
        #[cfg(not(target_os = "linux"))]
        rustix::fs::fchmod(fd, mode)?;
    }
    Ok(())
}
/// Create each missing ancestor with mode 0755 and the requested owner.
pub(crate) fn create_parents(operation: &str, directory: &Path, uid: Option<u32>, gid: Option<u32>) -> Refusal<()> {
    let mut missing = Vec::new();
    let mut current = Some(directory);
    while let Some(path) = current {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() => break,
            Ok(metadata) if metadata.file_type().is_symlink() && std::fs::metadata(path).is_ok_and(|m| m.is_dir()) => break,
            Ok(_) => return Err(AgentError::new(operation, path.display(), ErrorKind::NotADirectory, "an ancestor is not a directory")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => missing.push(path),
            Err(error) => return Err(AgentError::io(operation, path.display(), error)),
        }
        current = path.parent();
    }
    for path in missing.into_iter().rev() {
        make_directory(operation, path, None, 0o755, uid, gid, false)?;
    }
    Ok(())
}
/// mkdir with an exact mode (umask does not apply) and owner: `mode`, or
/// `default` for a new directory. An existing directory is accepted unless
/// `exclusive`; its mode and owner change only when the caller named them.
fn make_directory(
    operation: &str,
    path: &Path,
    mode: Option<u32>,
    default: u32,
    uid: Option<u32>,
    gid: Option<u32>,
    exclusive: bool,
) -> Refusal<bool> {
    use std::os::unix::fs::DirBuilderExt;
    let created = match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists && !exclusive => false,
        Err(error) => return Err(AgentError::io(operation, path.display(), error)),
    };
    let directory = open_nofollow(path, true).map_err(|error| match error.raw_os_error() {
        Some(libc::ELOOP | libc::ENOTDIR) => {
            AgentError::new(operation, path.display(), ErrorKind::AlreadyExists, "exists and is not a directory")
        }
        _ => AgentError::io(operation, path.display(), error),
    })?;
    let mode = if created { Some(mode.unwrap_or(default)) } else { mode };
    change(&directory, mode, uid, gid).map_err(|e| AgentError::io(operation, path.display(), e))?;
    Ok(created)
}
fn parent_of(operation: &str, path: &Path) -> Refusal<PathBuf> {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .ok_or_else(|| AgentError::new(operation, path.display(), ErrorKind::InvalidInput, "path needs a parent directory"))
}
pub(crate) fn prepare_parent(operation: &str, path: &Path, parents: bool, uid: Option<u32>, gid: Option<u32>) -> Refusal<PathBuf> {
    let parent = parent_of(operation, path)?;
    if parents {
        create_parents(operation, &parent, uid, gid)?;
    } else if !parent.is_dir() {
        return Err(AgentError::new(
            operation,
            path.display(),
            ErrorKind::NotFound,
            format!("parent directory {} does not exist; ask for parents to create it", parent.display()),
        ));
    }
    Ok(parent)
}
// Unprivileged replacement may be allowed by directory permissions even when
// preserving another user's owner is not. Preserve it when permitted; root and
// non-permission failures remain strict.
pub(crate) fn ownership_result(result: io::Result<()>, uid: u32) -> io::Result<()> {
    match result {
        Err(error) if uid != 0 && error.kind() == io::ErrorKind::PermissionDenied => {
            tracing::debug!(%error, "an unprivileged agent could not keep a replaced file's owner");
            Ok(())
        }
        other => other,
    }
}

/// Where a write's bytes come from.
pub(crate) enum Source {
    Body(Body),
    File(PathBuf),
}
/// A completed upload to install at `path`, refused if the store lacks it.
async fn blob_source(shared: &Shared, operation: &str, path: &Path, blob: &str) -> Refusal<Source> {
    if shared.store.blob_size(blob).await?.is_none() {
        return Err(AgentError::new(operation, path.display(), ErrorKind::NotFound, format!("no completed upload {blob}")));
    }
    Ok(Source::File(shared.store.blob(blob).map_err(|e| AgentError::io(operation, blob, e))?))
}
/// Write a sibling, hash while writing, fsync, rename atomically, then fsync
/// the parent. Readers observe either the complete old file or the complete
/// new one; a refused write leaves nothing behind.
pub(crate) async fn write(operation: &str, path: &Path, source: Source, options: &FileOptions) -> Refusal<(Written, bool)> {
    check_path(operation, path)?;
    check_mode(operation, path, options.mode)?;
    check_digest(operation, &options.sha256)?;
    let parent = prepare_parent(operation, path, options.parents, options.uid, options.gid)?;
    let existing = std::fs::symlink_metadata(path).ok();
    if let Some(metadata) = &existing {
        if options.exclusive {
            return Err(AgentError::new(operation, path.display(), ErrorKind::AlreadyExists, "file exists"));
        }
        if metadata.is_dir() {
            return Err(AgentError::new(operation, path.display(), ErrorKind::IsADirectory, "a directory is in the way"));
        }
    }
    let existing = existing.filter(|m| !m.file_type().is_symlink());
    let at = |e| AgentError::io(operation, path.display(), e);
    let temporary = tempfile::Builder::new().prefix(".drydock-").tempfile_in(&parent).map_err(at)?;
    let mut file = tokio::fs::File::from_std(temporary.reopen().map_err(at)?);
    let mut hasher = Sha256::new();
    let size = match source {
        Source::Body(body) => {
            copy_body(body, &mut file, Some(&mut hasher), None, None).await.map_err(|e| e.refusal(operation, path.display()))?
        }
        Source::File(from) => {
            let input = tokio::fs::File::open(&from).await.map_err(|e| AgentError::io(operation, from.display(), e))?;
            copy_body(
                Body::from_stream(tokio_util::io::ReaderStream::with_capacity(input, 256 * 1024)),
                &mut file,
                Some(&mut hasher),
                None,
                None,
            )
            .await
            .map_err(|e| e.refusal(operation, from.display()))?
        }
    };

    let sha256 = format!("{:x}", hasher.finalize());
    if let Some(expected) = &options.sha256
        && *expected != sha256
    {
        return Err(AgentError::new(
            operation,
            path.display(),
            ErrorKind::DigestMismatch,
            format!("expected sha256 {expected}, received {size} bytes with sha256 {sha256}; nothing was written"),
        ));
    }
    if options.uid.is_some() || options.gid.is_some() {
        chown(temporary.as_file(), options.uid, options.gid).map_err(at)?;
    } else if let Some(metadata) = &existing {
        // Preserve the destination's owner before chmod (chown may clear bits).
        let own = temporary.as_file().metadata().map_err(at)?;
        if (metadata.uid(), metadata.gid()) != (own.uid(), own.gid()) {
            let euid = rustix::process::geteuid().as_raw();
            ownership_result(chown(temporary.as_file(), Some(metadata.uid()), Some(metadata.gid())), euid).map_err(at)?;
        }
    }
    let mode = options.mode.or(existing.as_ref().map(|m| m.permissions().mode())).unwrap_or(0o600);
    file.set_permissions(std::fs::Permissions::from_mode(permitted(mode))).await.map_err(at)?;
    file.sync_all().await.map_err(at)?;
    drop(file);
    if options.exclusive {
        temporary.persist_noclobber(path).map_err(|e| {
            if e.error.kind() == io::ErrorKind::AlreadyExists {
                AgentError::new(operation, path.display(), ErrorKind::AlreadyExists, "file appeared while writing")
            } else {
                AgentError::io(operation, path.display(), e.error)
            }
        })?;
    } else {
        temporary.persist(path).map_err(|e| AgentError::io(operation, path.display(), e.error))?;
    }
    sync_directory(&parent).map_err(at)?;
    Ok((Written { sha256, size }, existing.is_none()))
}

pub(crate) async fn put_file(
    State(shared): State<Arc<Shared>>,
    uri: Uri,
    Query(WithBlob { mut options, blob }): Query<WithBlob<FileOptions>>,
    headers: HeaderMap,
    body: Body,
) -> Refusal<Response> {
    const OP: &str = "file.write";
    let path = tail_path(OP, &uri, "/files")?;
    let source = match &blob {
        Some(blob) => {
            crate::check_sha256(blob).map_err(|e| AgentError::io(OP, blob, e))?;
            // An installed blob is checked against its own digest unless the
            // caller named one.
            options.sha256.get_or_insert_with(|| blob.clone());
            blob_source(&shared, OP, &path, blob).await?
        }
        None => {
            require_octet_stream(OP, &path, &headers, &["application/octet-stream"])?;
            Source::Body(body)
        }
    };
    // The precondition is checked before writing; a concurrent writer can
    // still replace the file between the check and the rename.
    // The tag is the entry the write replaces: a symlink is replaced, not
    // followed, so it has no current tag.
    let current = std::fs::symlink_metadata(&path).ok().filter(|m| m.is_file()).map(|m| etag(&m));
    if !if_match(OP, path.display(), &headers, current.as_deref())? {
        let now = current.as_deref().unwrap_or("absent");
        return Err(AgentError::new(OP, path.display(), ErrorKind::PreconditionFailed, format!("file is now {now}")));
    }
    let (written, created) = write(OP, &path, source, &options).await?;
    let metadata = std::fs::metadata(&path).map_err(|e| AgentError::io(OP, path.display(), e))?;
    let status = if created { StatusCode::CREATED } else { StatusCode::OK };
    Ok((status, [(header::ETAG, header_value(etag(&metadata)))], Json(written)).into_response())
}

/// Why streaming a request body into a file stopped.
pub(crate) enum Copy {
    /// The client's body failed, usually because it disconnected.
    Body(axum::Error),
    Write(io::Error),
    TooLong,
    /// A later request for the same upload took it over.
    Superseded,
}
impl Copy {
    pub(crate) fn refusal(self, operation: &str, subject: impl std::fmt::Display) -> AgentError {
        match self {
            Copy::Body(error) => {
                AgentError::new(operation, subject, ErrorKind::ConnectionAborted, "request body ended early").with_cause(error)
            }
            Copy::Write(error) => AgentError::io(operation, subject, error),
            Copy::TooLong => AgentError::new(operation, subject, ErrorKind::PayloadTooLarge, "request body is longer than allowed"),
            Copy::Superseded => AgentError::new(operation, subject, ErrorKind::Conflict, "a later request for this upload took it over"),
        }
    }
}
/// Stream a body to a file as it arrives, holding at most one frame and the
/// write buffer in memory. Stops before writing past `limit`, and when
/// `superseded` fires, keeping what was written.
pub(crate) async fn copy_body(
    body: Body,
    file: &mut (impl tokio::io::AsyncWrite + Unpin),
    mut hasher: Option<&mut Sha256>,
    limit: Option<u64>,
    superseded: Option<&tokio_util::sync::CancellationToken>,
) -> Result<u64, Copy> {
    let mut writer = tokio::io::BufWriter::with_capacity(256 * 1024, file);
    let mut body = body.into_data_stream();
    let mut total = 0u64;
    use futures_util::StreamExt;
    let ended = async {
        match superseded {
            Some(token) => token.cancelled().await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(ended);
    loop {
        let chunk = tokio::select! {
            biased;
            () = &mut ended => {
                writer.flush().await.map_err(Copy::Write)?;
                return Err(Copy::Superseded);
            }
            chunk = body.next() => match chunk {
                Some(chunk) => chunk,
                None => break,
            },
        };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) => {
                writer.flush().await.map_err(Copy::Write)?;
                return Err(Copy::Body(error));
            }
        };
        if limit.is_some_and(|limit| total + chunk.len() as u64 > limit) {
            writer.flush().await.map_err(Copy::Write)?;
            return Err(Copy::TooLong);
        }
        if let Some(hasher) = hasher.as_mut() {
            hasher.update(&chunk);
        }
        writer.write_all(&chunk).await.map_err(Copy::Write)?;
        total += chunk.len() as u64;
    }
    writer.flush().await.map_err(Copy::Write)?;
    Ok(total)
}
/// The sha256 of a file's bytes, hashed off the async runtime.
pub(crate) async fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    tokio::task::spawn_blocking(move || {
        let mut hasher = Sha256::new();
        io::copy(&mut file, &mut hasher)?;
        Ok(format!("{:x}", hasher.finalize()))
    })
    .await?
}
/// The one byte range, first and last byte, that a `Range` header selects
/// in a file of `size` bytes. `Ok(None)` serves the whole file: there is no
/// header, or none that parses as a byte range (RFC 9110 ignores those).
/// Several ranges, and ranges outside the file, are refused.
fn requested_range(headers: &HeaderMap, size: u64) -> Result<Option<(u64, u64)>, String> {
    use headers::HeaderMapExt;
    use std::ops::Bound::{Included, Unbounded};
    let Ok(Some(range)) = headers.typed_try_get::<headers::Range>() else { return Ok(None) };
    match range.satisfiable_ranges(u64::MAX).count() {
        0 => return Ok(None),
        1 => {}
        _ => return Err("multiple ranges are not supported".into()),
    }
    let outside = || format!("the range is outside the {size} bytes");
    match range.satisfiable_ranges(size).next() {
        Some((Included(start), end)) if start < size => match end {
            Included(end) if end >= start => Ok(Some((start, end.min(size - 1)))),
            Unbounded => Ok(Some((start, size - 1))),
            _ => Err(outside()),
        },
        // headers drops a suffix longer than the file; RFC 9110 serves the
        // whole file for it. Only a lone suffix range qualifies.
        None if size > 0
            && headers
                .get(header::RANGE)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().strip_prefix("bytes=-"))
                .and_then(|n| n.parse::<u64>().ok())
                .is_some_and(|n| n > size) =>
        {
            Ok(Some((0, size - 1)))
        }
        _ => Err(outside()),
    }
}
async fn open_regular(operation: &str, path: &Path) -> Refusal<(tokio::fs::File, std::fs::Metadata)> {
    let file = tokio::fs::File::open(path).await.map_err(|e| AgentError::io(operation, path.display(), e))?;
    let metadata = file.metadata().await.map_err(|e| AgentError::io(operation, path.display(), e))?;
    if !metadata.is_file() {
        let kind = if metadata.is_dir() { ErrorKind::IsADirectory } else { ErrorKind::InvalidInput };
        return Err(AgentError::new(operation, path.display(), kind, "not a regular file"));
    }
    Ok((file, metadata))
}
async fn read(path: &Path, headers: &HeaderMap, head: bool) -> Refusal<Response> {
    const OP: &str = "file.read";
    let (mut file, metadata) = open_regular(OP, path).await?;
    let tag = etag(&metadata);
    if !if_match(OP, path.display(), headers, Some(&tag))? {
        return Err(AgentError::new(OP, path.display(), ErrorKind::PreconditionFailed, format!("file is now {tag}")));
    }
    use headers::{ContentRange, HeaderMapExt};
    let size = metadata.len();
    let span = match requested_range(headers, size) {
        Ok(span) => span,
        Err(message) => {
            let mut response = AgentError::new(OP, path.display(), ErrorKind::RangeNotSatisfiable, message).into_response();
            response.headers_mut().typed_insert(ContentRange::unsatisfied_bytes(size));
            return Ok(response);
        }
    };
    let (status, start, length) = match span {
        Some((start, end)) => (StatusCode::PARTIAL_CONTENT, start, end - start + 1),
        None => (StatusCode::OK, 0, size),
    };
    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, length)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::ETAG, header_value(&tag));
    if let (Some((start, end)), Some(headers)) = (span, response.headers_mut()) {
        headers.typed_insert(ContentRange::bytes(start..=end, size).expect("an inclusive range with a length"));
    }
    if head {
        return Ok(response.body(Body::empty()).unwrap());
    }
    file.seek(io::SeekFrom::Start(start)).await.map_err(|e| AgentError::io(OP, path.display(), e))?;
    let stream = tokio_util::io::ReaderStream::with_capacity(file.take(length), 256 * 1024);
    Ok(response.body(Body::from_stream(stream)).unwrap())
}
pub(crate) async fn get_file(uri: Uri, headers: HeaderMap) -> Refusal<Response> {
    read(&tail_path("file.read", &uri, "/files")?, &headers, false).await
}
pub(crate) async fn head_file(uri: Uri, headers: HeaderMap) -> Refusal<Response> {
    read(&tail_path("file.read", &uri, "/files")?, &headers, true).await
}

pub(crate) async fn get_entry(uri: Uri) -> Refusal<Json<Entry>> {
    const OP: &str = "entry.stat";
    Ok(Json(entry_at(OP, &tail_path(OP, &uri, "/entries")?)?))
}
pub(crate) async fn delete_entry(uri: Uri, Query(query): Query<RemoveQuery>) -> Refusal<StatusCode> {
    const OP: &str = "entry.remove";
    let path = tail_path(OP, &uri, "/entries")?;
    if path.parent().is_none() {
        return Err(AgentError::new(OP, "/", ErrorKind::PermissionDenied, "the root directory cannot be removed"));
    }
    let metadata = std::fs::symlink_metadata(&path).map_err(|e| AgentError::io(OP, path.display(), e))?;
    let result = if !metadata.is_dir() {
        tokio::fs::remove_file(&path).await
    } else if query.recursive {
        tokio::fs::remove_dir_all(&path).await
    } else {
        tokio::fs::remove_dir(&path).await
    };
    result.map_err(|e| AgentError::io(OP, path.display(), e))?;
    sync_directory(path.parent().unwrap()).map_err(|e| AgentError::io(OP, path.display(), e))?;
    Ok(StatusCode::NO_CONTENT)
}
pub(crate) async fn patch_entry(uri: Uri, Json(attributes): Json<Attributes>) -> Refusal<Json<Entry>> {
    const OP: &str = "entry.update";
    let path = tail_path(OP, &uri, "/entries")?;
    check_mode(OP, &path, attributes.mode)?;
    let at = |e| AgentError::io(OP, path.display(), e);
    match open_nofollow(&path, false) {
        Ok(file) => change(&file, attributes.mode, attributes.uid, attributes.gid).map_err(at)?,
        // A symlink: refuse a mode before changing anything, so a refusal
        // changes nothing. lchown never follows the link.
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            if attributes.mode.is_some() {
                return Err(AgentError::new(OP, path.display(), ErrorKind::InvalidInput, "a symlink has no mode of its own"));
            }
            std::os::unix::fs::lchown(&path, attributes.uid, attributes.gid).map_err(at)?;
        }
        Err(error) => return Err(at(error)),
    }
    Ok(Json(entry_at(OP, &path)?))
}

pub(crate) async fn get_dir(uri: Uri) -> Refusal<Json<Vec<Entry>>> {
    const OP: &str = "dir.list";
    let path = tail_path(OP, &uri, "/dirs")?;
    let listed = tokio::task::spawn_blocking(move || -> Refusal<Vec<Entry>> {
        let mut entries = Vec::new();
        for item in std::fs::read_dir(&path).map_err(|e| AgentError::io(OP, path.display(), e))? {
            let item = item.map_err(|e| AgentError::io(OP, path.display(), e))?;
            let child = item.path();
            // An entry removed while listing is simply not listed.
            let Ok(metadata) = std::fs::symlink_metadata(&child) else { continue };
            entries.push(entry(item.file_name().to_string_lossy().into_owned(), &metadata, &child));
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    })
    .await
    .map_err(|e| AgentError::new(OP, uri.path(), ErrorKind::Other, "listing task failed").with_cause(e))??;
    Ok(Json(listed))
}
pub(crate) async fn put_dir(uri: Uri, Query(query): Query<DirQuery>) -> Refusal<Response> {
    const OP: &str = "dir.create";
    let path = tail_path(OP, &uri, "/dirs")?;
    check_mode(OP, &path, query.mode)?;
    let parent = prepare_parent(OP, &path, query.parents, query.uid, query.gid)?;
    let created = make_directory(OP, &path, query.mode, 0o700, query.uid, query.gid, query.exclusive)?;
    sync_directory(&parent).map_err(|e| AgentError::io(OP, path.display(), e))?;
    let status = if created { StatusCode::CREATED } else { StatusCode::OK };
    Ok((status, Json(entry_at(OP, &path)?)).into_response())
}

/// A symlink, replacing any non-directory at the path atomically.
pub(crate) async fn put_link(uri: Uri, Query(query): Query<LinkQuery>, Json(link): Json<Link>) -> Refusal<StatusCode> {
    const OP: &str = "link.create";
    let path = tail_path(OP, &uri, "/links")?;
    if link.target.as_os_str().is_empty() || link.target.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(AgentError::new(OP, path.display(), ErrorKind::InvalidInput, "link target must be nonempty and contain no NUL"));
    }
    let existed = place_link(OP, &path, &link.target, &query)?;
    Ok(if existed { StatusCode::OK } else { StatusCode::CREATED })
}
/// Place a symlink at `path`: a uniquely named sibling renamed over it, so
/// the path names the old entry or the new link, never nothing. Returns
/// whether something was there.
pub(crate) fn place_link(operation: &str, path: &Path, target: &Path, query: &LinkQuery) -> Refusal<bool> {
    let parent = prepare_parent(operation, path, query.parents, query.uid, query.gid)?;
    let existing = std::fs::symlink_metadata(path).ok();
    if existing.as_ref().is_some_and(|m| m.is_dir()) {
        return Err(AgentError::new(operation, path.display(), ErrorKind::IsADirectory, "a directory is in the way"));
    }
    let at = |e| AgentError::io(operation, path.display(), e);
    if query.exclusive {
        std::os::unix::fs::symlink(target, path).map_err(at)?;
        if let Err(error) = std::os::unix::fs::lchown(path, query.uid, query.gid) {
            let _ = std::fs::remove_file(path);
            return Err(at(error));
        }
    } else {
        let temporary = tempfile::Builder::new()
            .prefix(".drydock-link-")
            .make_in(&parent, |name| std::os::unix::fs::symlink(target, name))
            .map_err(at)?;
        let installed = std::os::unix::fs::lchown(temporary.path(), query.uid, query.gid);
        installed.map_err(at)?;
        temporary.persist(path).map_err(|e| at(e.error))?;
    }
    sync_directory(&parent).map_err(at)?;
    Ok(existing.is_some())
}

pub(crate) async fn post_rename(Json(rename): Json<Rename>) -> Refusal<StatusCode> {
    const OP: &str = "entry.rename";
    let subject = format!("{} -> {}", rename.from.display(), rename.to.display());
    check_path(OP, &rename.from)?;
    check_path(OP, &rename.to)?;
    std::fs::symlink_metadata(&rename.from).map_err(|e| AgentError::io(OP, rename.from.display(), e))?;
    let parent = prepare_parent(OP, &rename.to, rename.parents, None, None)?;
    let result = if rename.exclusive { rename_noreplace(&rename.from, &rename.to) } else { std::fs::rename(&rename.from, &rename.to) };
    result.map_err(|e| AgentError::io(OP, &subject, e))?;
    sync_directory(&parent).map_err(|e| AgentError::io(OP, &subject, e))?;
    if let Some(source) = rename.from.parent()
        && source != parent
    {
        sync_directory(source).map_err(|e| AgentError::io(OP, &subject, e))?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// A staging directory, removed with whatever it holds when dropped, even
/// directories an archive left without write permission.
struct Staging(Option<PathBuf>);
impl Staging {
    fn path(&self) -> &Path {
        self.0.as_deref().expect("a staging directory still held")
    }
    /// Keep the directory: it was renamed into place.
    fn release(mut self) {
        self.0 = None;
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = open_up(&path);
            if let Err(error) = std::fs::remove_dir_all(&path) {
                tracing::warn!(%error, path = %path.display(), "could not remove a staging directory");
            }
        }
    }
}
/// Give the owner write and search permission on every directory under
/// `root`, so the tree can be removed.
pub(crate) fn open_up(root: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(root)?;
    if metadata.is_dir() {
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(metadata.mode() | 0o700))?;
        for entry in std::fs::read_dir(root)? {
            let _ = open_up(&entry?.path());
        }
    }
    Ok(())
}
/// Make everything written on the filesystem holding `path` durable.
pub(crate) fn sync_filesystem(path: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let directory = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        Ok(rustix::fs::syncfs(directory)?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        rustix::fs::sync();
        Ok(())
    }
}
/// Hashes every byte read through it, including bytes the unpacker skips.
struct Hashing<R> {
    inner: R,
    hasher: Sha256,
    count: u64,
}
impl<R: std::io::Read> std::io::Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.count += n as u64;
        Ok(n)
    }
}
fn unpack_into(reader: &mut impl std::io::Read, compression: Compression, into: &Path) -> io::Result<()> {
    let mut archive = match compression {
        Compression::None => tar::Archive::new(Box::new(reader) as Box<dyn std::io::Read>),
        Compression::Gzip => tar::Archive::new(Box::new(flate2::read::GzDecoder::new(reader)) as Box<dyn std::io::Read>),
    };
    archive.set_preserve_permissions(true);
    // An archive cannot install privileged executables through an agent
    // that runs as root: setuid and setgid are masked from every entry.
    archive.set_mask(0o6000);
    archive.set_preserve_ownerships(false);
    archive.set_unpack_xattrs(false);
    archive.set_overwrite(true);
    archive.unpack(into)
}
fn unpack(reader: impl std::io::Read, compression: Compression, into: &Path) -> (io::Result<()>, String, u64) {
    let mut hashing = Hashing { inner: reader, hasher: Sha256::new(), count: 0 };
    let result = unpack_into(&mut hashing, compression, into);
    // The digest covers the whole archive, including any trailing padding
    // the unpacker did not need to read.
    let drained = std::io::copy(&mut hashing, &mut std::io::sink());
    let result = result.and(drained.map(drop));
    (result, format!("{:x}", hashing.hasher.finalize()), hashing.count)
}
/// Why the bytes, whose digest matched, did not unpack. Format errors from
/// the tar and gzip readers are faults in the archive (422); filesystem
/// errors such as a full disk keep their own kind.
fn unpack_refusal(operation: &str, path: &Path, error: io::Error) -> AgentError {
    let format = matches!(
        error.kind(),
        io::ErrorKind::Other | io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput | io::ErrorKind::UnexpectedEof
    );
    let mut refusal = AgentError::io(operation, path.display(), error);
    if format {
        refusal.kind = ErrorKind::InvalidData;
        refusal.status = ErrorKind::InvalidData.status();
    }
    refusal.message = format!("the archive could not be unpacked; the target is unchanged: {}", refusal.message);
    refusal
}
fn chown_tree(root: &Path, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
    std::os::unix::fs::lchown(root, uid, gid)?;
    if std::fs::symlink_metadata(root)?.is_dir() {
        for entry in std::fs::read_dir(root)? {
            chown_tree(&entry?.path(), uid, gid)?;
        }
    }
    Ok(())
}
/// Unpack a tar archive into a new directory. It is unpacked beside the
/// target and appears there, whole, only after the archive's digest matched.
pub(crate) async fn put_tree(
    State(shared): State<Arc<Shared>>,
    uri: Uri,
    Query(WithBlob { options, blob }): Query<WithBlob<TreeOptions>>,
    headers: HeaderMap,
    body: Body,
) -> Refusal<Response> {
    const OP: &str = "tree.unpack";
    let path = tail_path(OP, &uri, "/trees")?;
    crate::check_sha256(&options.sha256).map_err(|e| AgentError::io(OP, path.display(), e))?;
    check_mode(OP, &path, options.mode)?;
    let source = match &blob {
        Some(blob) => {
            if *blob != options.sha256 {
                return Err(AgentError::new(OP, path.display(), ErrorKind::InvalidInput, "blob and sha256 must name the same digest"));
            }
            blob_source(&shared, OP, &path, blob).await?
        }
        None => {
            require_octet_stream(OP, &path, &headers, &["application/x-tar", "application/gzip", "application/octet-stream"])?;
            Source::Body(body)
        }
    };
    let parent = prepare_parent(OP, &path, options.parents, options.uid, options.gid)?;
    let existed = match std::fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(AgentError::new(OP, path.display(), ErrorKind::AlreadyExists, "exists and is not a directory"));
        }
        Ok(_) if !options.replace => {
            return Err(AgentError::new(OP, path.display(), ErrorKind::AlreadyExists, "directory exists; ask to replace it"));
        }
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(AgentError::io(OP, path.display(), error)),
    };
    let at = |e| AgentError::io(OP, path.display(), e);
    let staging = Staging(Some(tempfile::Builder::new().prefix(".drydock-tree-").tempdir_in(&parent).map_err(at)?.keep()));
    let compression = options.compression;
    // The unpacking task owns the staging directory and hands it back. If the
    // client resets the stream, this handler is cancelled but the blocking
    // unpack runs on until its body fails; only then may the staging
    // directory be removed, or entries it creates afterwards would stay.
    let (unpacked, sha256, size, staging) = match source {
        Source::Body(body) => {
            let stream = futures_util::TryStreamExt::map_err(body.into_data_stream(), io::Error::other);
            let reader = tokio_util::io::SyncIoBridge::new(tokio_util::io::StreamReader::new(stream));
            tokio::task::spawn_blocking(move || {
                let (unpacked, sha256, size) = unpack(reader, compression, staging.path());
                (unpacked, sha256, size, staging)
            })
            .await
        }
        Source::File(file) => {
            tokio::task::spawn_blocking(move || {
                let (unpacked, sha256, size) = match std::fs::File::open(&file) {
                    Ok(reader) => unpack(std::io::BufReader::new(reader), compression, staging.path()),
                    Err(error) => (Err(error), String::new(), 0),
                };
                (unpacked, sha256, size, staging)
            })
            .await
        }
    }
    .map_err(|e| AgentError::new(OP, path.display(), ErrorKind::Other, "unpack task failed").with_cause(e))?;
    // A blob that could not even be opened (removed meanwhile) reports that,
    // not a digest of no bytes.
    if sha256.is_empty() {
        return Err(AgentError::io(OP, path.display(), unpacked.err().unwrap_or_else(|| io::Error::other("blob unreadable"))));
    }
    if sha256 != options.sha256 {
        let mut refusal = AgentError::new(
            OP,
            path.display(),
            ErrorKind::DigestMismatch,
            format!("expected sha256 {}, received {size} bytes with sha256 {sha256}; the target is unchanged", options.sha256),
        );
        if let Err(error) = unpacked {
            refusal = refusal.with_cause(error);
        }
        return Err(refusal);
    }
    unpacked.map_err(|e| unpack_refusal(OP, &path, e))?;
    if options.uid.is_some() || options.gid.is_some() {
        chown_tree(staging.path(), options.uid, options.gid).map_err(at)?;
    }
    std::fs::set_permissions(staging.path(), std::fs::Permissions::from_mode(options.mode.unwrap_or(0o755))).map_err(at)?;
    // Every unpacked byte is durable before the tree appears.
    let synced = staging.path().to_path_buf();
    tokio::task::spawn_blocking(move || sync_filesystem(&synced))
        .await
        .map_err(|e| AgentError::new(OP, path.display(), ErrorKind::Other, "sync task failed").with_cause(e))?
        .map_err(at)?;
    // The target was checked above; one created or removed meanwhile makes
    // the rename or exchange fail with its own error.
    if existed {
        exchange(staging.path(), &path).map_err(at)?;
        // The staging name now holds the previous tree; dropping removes it.
    } else {
        rename_noreplace(staging.path(), &path).map_err(at)?;
        staging.release();
    }
    sync_directory(&parent).map_err(at)?;
    Ok((StatusCode::CREATED, Json(Written { sha256, size })).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    // fchown is a kernel boundary: its result policy must tolerate EPERM only
    // for unprivileged replacement, never mask root or unrelated I/O failures.
    #[hegel::test]
    fn ownership_permission_policy(tc: hegel::TestCase) {
        use hegel::generators as gs;
        let uid = if tc.draw(gs::booleans()) { 0 } else { 1000 };
        let errors = [libc::EPERM, libc::EIO, libc::ENOENT, libc::EROFS];
        let errno = errors[tc.draw(gs::integers::<usize>().min_value(0).max_value(3))];
        assert_eq!(ownership_result(Err(io::Error::from_raw_os_error(errno)), uid).is_ok(), uid != 0 && errno == libc::EPERM);
        assert!(ownership_result(Ok(()), uid).is_ok());
    }
}

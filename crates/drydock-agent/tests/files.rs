//! File, upload and tree operations against a real agent, on a real
//! filesystem in a tempdir. Bytes travel as streamed
//! `application/octet-stream` bodies. How a refusal is encoded belongs to the
//! error layer (`contract.rs`); these tests check which refusal each
//! operation chooses and that it changes nothing.
mod support;
use drydock_agent::{Attributes, Compression, EntryKind, ErrorKind, FileOptions, Rename, TreeOptions, Written};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    future::Future,
    io::{self, Cursor},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use support::*;
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

/// The route for `path`, percent-encoded the way the client encodes it.
fn route(prefix: &str, path: &Path) -> String {
    const SET: &AsciiSet = &NON_ALPHANUMERIC.remove(b'/').remove(b'-').remove(b'_').remove(b'.').remove(b'~');
    format!("{prefix}{}", percent_encode(path.as_os_str().as_bytes(), SET))
}
fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}
async fn agent() -> Harness {
    harness(false, "test-build").await
}

/// Every entry under a directory, keyed by relative path: what "unchanged"
/// means for a tree, down to modes, bytes and link targets.
#[derive(Debug, PartialEq, Eq)]
enum Node {
    File { mode: u32, bytes: Vec<u8> },
    Dir { mode: u32 },
    Link { target: PathBuf },
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Node> {
    fn walk(root: &Path, at: &Path, into: &mut BTreeMap<PathBuf, Node>) {
        let metadata = std::fs::symlink_metadata(at).unwrap();
        let relative = at.strip_prefix(root).unwrap().to_path_buf();
        let mode = metadata.mode() & 0o7777;
        if metadata.file_type().is_symlink() {
            into.insert(relative, Node::Link { target: std::fs::read_link(at).unwrap() });
        } else if metadata.is_dir() {
            into.insert(relative, Node::Dir { mode });
            for entry in std::fs::read_dir(at).unwrap() {
                walk(root, &entry.unwrap().path(), into);
            }
        } else {
            into.insert(relative, Node::File { mode, bytes: std::fs::read(at).unwrap() });
        }
    }
    let mut nodes = BTreeMap::new();
    walk(root, root, &mut nodes);
    nodes
}

/// Yields the inner reader's bytes, then fails where it would have ended,
/// optionally only once `gate` opens. It stands in for a host whose source
/// breaks partway through an upload.
struct FailAtEnd<R> {
    inner: R,
    gate: Option<tokio::sync::oneshot::Receiver<()>>,
}
impl<R: AsyncRead + Unpin> AsyncRead for FailAtEnd<R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() == before => {
                if let Some(gate) = self.gate.as_mut() {
                    std::task::ready!(Pin::new(gate).poll(cx)).ok();
                }
                Poll::Ready(Err(io::Error::other("source failed")))
            }
            other => other,
        }
    }
}
/// Bytes the agent has stored for an incomplete upload, read from its store
/// directly: asking the agent would end the request still appending.
fn stored(h: &Harness, digest: &str) -> u64 {
    std::fs::metadata(h.dir.path().join("agent.store/partial").join(digest)).map_or(0, |m| m.len())
}
// A file created without an explicit mode is not world-readable: 0600. An
// explicit mode is applied exactly (umask does not apply), except that
// setuid and setgid are never set. Replacing a file
// keeps its mode and owner. `exclusive` refuses an existing file and leaves
// it alone. `parents` creates missing ancestors as 0755; without it a missing
// parent is NotFound naming that parent.
#[tokio::test]
async fn write_modes_parents_and_exclusive() {
    let h = agent().await;
    let root = h.vessel();
    let fresh = root.join("fresh");
    let written = h.client.write_bytes(&fresh, b"secret".to_vec(), &FileOptions::default()).await.unwrap();
    assert_eq!(written, Written { sha256: sha256(b"secret"), size: 6 });
    assert_eq!(std::fs::read(&fresh).unwrap(), b"secret");
    assert_eq!(mode_of(&fresh), 0o600, "a new file must not be group or world readable");

    for (mode, applied) in [(0o666, 0o666), (0o1777, 0o1777), (0o6711, 0o711)] {
        let explicit = root.join(format!("explicit-{mode:o}"));
        h.client.write_bytes(&explicit, b"x".to_vec(), &FileOptions { mode: Some(mode), ..FileOptions::default() }).await.unwrap();
        assert_eq!(mode_of(&explicit), applied);
    }

    std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o644)).unwrap();
    let before = std::fs::metadata(&fresh).unwrap();
    h.client.write_bytes(&fresh, b"replaced".to_vec(), &FileOptions::default()).await.unwrap();
    let after = std::fs::metadata(&fresh).unwrap();
    assert_eq!(std::fs::read(&fresh).unwrap(), b"replaced");
    assert_eq!(after.mode() & 0o7777, 0o644, "a replaced file keeps its mode");
    assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()), "a replaced file keeps its owner");
    assert_ne!(after.ino(), before.ino(), "replacement is a new inode renamed into place");
    // An explicit mode on replacement wins over the existing one.
    h.client.write_bytes(&fresh, b"again".to_vec(), &FileOptions { mode: Some(0o600), ..FileOptions::default() }).await.unwrap();
    assert_eq!(mode_of(&fresh), 0o600);

    let exclusive = FileOptions { exclusive: true, ..FileOptions::default() };
    let error = h.client.write_bytes(&fresh, b"clobber".to_vec(), &exclusive).await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&fresh).unwrap(), b"again");
    h.client.write_bytes(&root.join("exclusive-new"), b"new".to_vec(), &exclusive).await.unwrap();
    assert_eq!(std::fs::read(root.join("exclusive-new")).unwrap(), b"new");

    let deep = root.join("a/b/c/file");
    h.client.write_bytes(&deep, b"deep".to_vec(), &FileOptions { parents: true, ..FileOptions::default() }).await.unwrap();
    assert_eq!(std::fs::read(&deep).unwrap(), b"deep");
    for parent in ["a", "a/b", "a/b/c"] {
        assert_eq!(mode_of(&root.join(parent)), 0o755, "{parent}");
    }

    let orphan = root.join("missing/file");
    let error = h.client.write_bytes(&orphan, b"x".to_vec(), &FileOptions::default()).await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::NotFound);
    assert!(agent_error(&error).message.contains(&root.join("missing").display().to_string()), "{error}");
    assert!(!root.join("missing").exists());

    let error = h.client.write_bytes(&root.join("a"), b"x".to_vec(), &FileOptions::default()).await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::IsADirectory);
    assert!(leftovers(&root, ".drydock-").is_empty());
}

// Writing with the right sha256 succeeds and reports it; a wrong one is a
// DigestMismatch naming both digests, and leaves the destination as it was
// (absent or with its old bytes) with no temporary sibling behind.
#[tokio::test]
async fn write_digest_check() {
    let h = agent().await;
    let root = h.vessel();
    let content = pattern(7, 700_000);
    let path = root.join("checked");
    let options = FileOptions { sha256: Some(sha256(&content)), ..FileOptions::default() };
    let written = h.client.write(&path, Cursor::new(content.clone()), &options).await.unwrap();
    assert_eq!(written, Written { sha256: sha256(&content), size: content.len() as u64 });

    let wrong = sha256(b"something else");
    let other = pattern(8, 300_000);
    let options = FileOptions { sha256: Some(wrong.clone()), ..FileOptions::default() };
    for target in [path.clone(), root.join("never")] {
        let error = h.client.write(&target, Cursor::new(other.clone()), &options).await.unwrap_err();
        assert_eq!(kind(&error), ErrorKind::DigestMismatch);
        let message = &agent_error(&error).message;
        assert!(message.contains(&wrong) && message.contains(&sha256(&other)), "{message}");
    }
    assert_eq!(std::fs::read(&path).unwrap(), content);
    assert!(!root.join("never").exists());
    assert!(leftovers(&root, ".drydock-").is_empty());
}

// A write with If-Match replaces the file only while it still has one of the
// listed tags; `*` needs the file to exist. Otherwise it is refused and the
// file is unchanged. An If-Match that is not a list of tags is refused.
#[tokio::test]
async fn conditional_writes() {
    let h = agent().await;
    let path = h.vessel().join("conditional");
    let options = FileOptions::default();
    let write_if = |etag: &'static str| h.client.write_if(&path, Cursor::new(b"next".to_vec()), &options, etag);
    assert_eq!(kind(&write_if("*").await.unwrap_err()), ErrorKind::PreconditionFailed, "an absent file matches nothing");
    h.client.write_bytes(&path, b"first".to_vec(), &FileOptions::default()).await.unwrap();
    let (_, etag) = h.client.head(&path).await.unwrap();
    assert_eq!(kind(&write_if("\"stale\"").await.unwrap_err()), ErrorKind::PreconditionFailed);
    assert_eq!(kind(&write_if("stale").await.unwrap_err()), ErrorKind::InvalidInput);
    assert_eq!(std::fs::read(&path).unwrap(), b"first");
    let listed = format!("\"stale\", {etag}");
    h.client.write_if(&path, Cursor::new(b"second".to_vec()), &FileOptions::default(), &listed).await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"second");
    write_if("*").await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"next");
    // A symlink is replaced, not followed, so its target's tag is not its own.
    let link = h.vessel().join("conditional-link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let error = h.client.write_if(&link, Cursor::new(b"x".to_vec()), &options, "*").await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::PreconditionFailed);
}

// Reads stream a file back whole or by range, with its size and a strong
// entity tag that changes when the file is replaced. A ranged read carries
// 206 metadata; `If-Match` with a stale tag is refused naming the current
// tag; an unsatisfiable range carries `Content-Range: bytes */size`. A
// directory and a missing file are refused (HEAD with no body), and an empty
// file reads back empty. Which ranges are satisfiable is the range parser's
// property (`files::tests`); which bytes come back is the generated test below.
#[tokio::test]
async fn reads_heads_and_ranges() {
    let h = agent().await;
    let root = h.vessel();
    let path = root.join("data");
    let content = pattern(3, 600_000);
    h.client.write_bytes(&path, content.clone(), &FileOptions::default()).await.unwrap();
    let (size, etag) = h.client.head(&path).await.unwrap();
    assert_eq!(size, content.len() as u64);
    assert!(etag.starts_with('"') && etag.ends_with('"'), "{etag}");

    let download = h.client.read(&path).await.unwrap();
    assert_eq!((download.length, download.etag.as_str(), download.range), (size, etag.as_str(), None));
    assert_eq!(download.bytes().await.unwrap(), content);
    assert_eq!(h.client.read_bytes(&path, size).await.unwrap(), content);
    assert_eq!(h.client.read_bytes(&path, size - 1).await.unwrap_err().kind(), io::ErrorKind::FileTooLarge);

    let ranged = h.client.read_range(&path, 262_100, Some(100), Some(&etag)).await.unwrap();
    assert_eq!((ranged.length, ranged.range, ranged.etag.clone()), (100, Some((262_100, 262_199, size)), etag.clone()));
    assert_eq!(ranged.bytes().await.unwrap(), &content[262_100..262_200]);

    let (status, headers, _) = raw(&h, "GET", &route("/files", &path), &[("range", &format!("bytes={size}-"))], vec![]).await;
    assert_eq!((status, headers["content-range"].to_str().unwrap()), (416, format!("bytes */{size}").as_str()));
    assert_eq!(raw(&h, "GET", &route("/files", &path), &[("range", "bytes=-0")], vec![]).await.0, 416);
    let (status, _, body) = raw(&h, "GET", &route("/files", &path), &[("range", &format!("bytes=-{}", size + 9))], vec![]).await;
    assert_eq!((status, body.len() as u64), (206, size), "a suffix longer than the file selects all of it");
    let (status, _, body) = raw(&h, "GET", &route("/files", &path), &[("range", "bytes=-abc")], vec![]).await;
    assert_eq!((status, body.len() as u64), (200, size), "an unparseable range is ignored");
    let joined = format!("bytes=-{},junk", size + 9);
    assert_eq!(
        raw(&h, "GET", &route("/files", &path), &[("range", &joined)], vec![]).await.0,
        416,
        "only a lone suffix selects the whole file"
    );

    let listed = format!("\"stale\", {etag}");
    assert_eq!(h.client.read_range(&path, 0, Some(10), Some(&listed)).await.unwrap().length, 10, "any listed tag matches");
    assert_eq!(kind(&failed(h.client.read_range(&path, 0, Some(10), Some("stale")).await)), ErrorKind::InvalidInput);
    let error = failed(h.client.read_range(&path, 0, Some(10), Some("\"stale\"")).await);
    assert_eq!(kind(&error), ErrorKind::PreconditionFailed);
    assert!(agent_error(&error).message.contains(&etag), "the refusal names the current tag: {error}");

    h.client.write_bytes(&path, b"new".to_vec(), &FileOptions::default()).await.unwrap();
    let (size, new_etag) = h.client.head(&path).await.unwrap();
    assert_eq!(size, 3);
    assert_ne!(new_etag, etag);
    assert_eq!(kind(&failed(h.client.read_range(&path, 0, Some(1), Some(&etag)).await)), ErrorKind::PreconditionFailed);

    assert_eq!(kind(&failed(h.client.read(&root).await)), ErrorKind::IsADirectory);
    let missing = root.join("absent");
    assert_eq!(kind(&failed(h.client.read(&missing).await)), ErrorKind::NotFound);
    assert_eq!(kind(&h.client.head(&missing).await.unwrap_err()), ErrorKind::NotFound);
    let (status, _, body) = raw(&h, "HEAD", &route("/files", &missing), &[], vec![]).await;
    assert_eq!((status, body.len()), (404, 0));

    let empty = root.join("empty");
    let written = h.client.write_bytes(&empty, Vec::new(), &FileOptions::default()).await.unwrap();
    assert_eq!(written, Written { sha256: sha256(b""), size: 0 });
    let download = h.client.read(&empty).await.unwrap();
    assert_eq!(download.length, 0);
    assert!(download.bytes().await.unwrap().is_empty());
}

// Generated sizes (empty, around the 256 KiB read chunk, larger) and ranges
// (inside, clipped at the end, starting at or past the end, suffixes longer
// than the file): every satisfiable range returns exactly the selected bytes
// with matching 206 metadata, and every other one is refused for that size.
#[hegel::test]
fn generated_ranges_return_exactly_the_selected_bytes(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let size = tc.draw(gs::sampled_from(vec![0usize, 1, 262_143, 262_144, 262_145, 700_001]));
    // Starts counted from the beginning or back from just past the end.
    let start = tc.draw(gs::integers::<u64>().min_value(0).max_value(size as u64 + 2));
    let start = if tc.draw(gs::booleans()) { start } else { size as u64 + 2 - start };
    let length = tc.draw(gs::optional(gs::integers::<u64>().min_value(1).max_value(size as u64 + 2)));
    let suffix = tc.draw(gs::integers::<u64>().min_value(1).max_value(size as u64 + 2));
    runtime().block_on(async {
        let h = agent().await;
        let path = h.vessel().join("generated");
        let content = pattern(size as u64, size);
        h.client.write_bytes(&path, content.clone(), &FileOptions::default()).await.unwrap();
        let size = size as u64;
        match h.client.read_range(&path, start, length, None).await {
            Ok(download) => {
                assert!(start < size);
                let end = length.map_or(size - 1, |length| (start + length - 1).min(size - 1));
                assert_eq!((download.length, download.range), (end - start + 1, Some((start, end, size))));
                assert_eq!(download.bytes().await.unwrap(), &content[start as usize..=end as usize]);
            }
            Err(error) => {
                assert!(start >= size, "{error}");
                assert_eq!(kind(&error), ErrorKind::RangeNotSatisfiable);
            }
        }
        let (status, headers, body) = raw(&h, "GET", &route("/files", &path), &[("range", &format!("bytes=-{suffix}"))], vec![]).await;
        if size == 0 {
            assert_eq!(status, 416);
            assert_eq!(headers["content-range"], "bytes */0");
        } else {
            let first = size.saturating_sub(suffix);
            assert_eq!(status, 206);
            assert_eq!(headers["content-range"], format!("bytes {first}-{}/{size}", size - 1));
            assert_eq!(body, &content[first as usize..]);
        }
    });
}

// Stat describes one entry without following symlinks: kind, size, mode,
// owner, mtime and a link's target (even a dangling one). Listing returns the
// directory's entries sorted by name with the same descriptions.
#[tokio::test]
async fn stat_and_list() {
    let h = agent().await;
    let root = h.vessel();
    std::fs::write(root.join("b-file"), b"12345").unwrap();
    std::fs::set_permissions(root.join("b-file"), std::fs::Permissions::from_mode(0o640)).unwrap();
    std::fs::create_dir(root.join("c-dir")).unwrap();
    std::os::unix::fs::symlink("b-file", root.join("a-link")).unwrap();
    std::os::unix::fs::symlink("/nonexistent/target", root.join("d-dangling")).unwrap();

    let file = h.client.stat(&root.join("b-file")).await.unwrap();
    let metadata = std::fs::metadata(root.join("b-file")).unwrap();
    assert_eq!((file.name.as_str(), file.kind, file.size, file.mode), ("b-file", EntryKind::File, 5, 0o640));
    assert_eq!((file.uid, file.gid), (metadata.uid(), metadata.gid()));
    assert_eq!(file.modified_ns, metadata.mtime() as i128 * 1_000_000_000 + metadata.mtime_nsec() as i128);
    assert_eq!(file.target, None);
    let link = h.client.stat(&root.join("a-link")).await.unwrap();
    assert_eq!((link.kind, link.size, link.target), (EntryKind::Symlink, 6, Some(PathBuf::from("b-file"))));
    let dangling = h.client.stat(&root.join("d-dangling")).await.unwrap();
    assert_eq!((dangling.kind, dangling.target), (EntryKind::Symlink, Some(PathBuf::from("/nonexistent/target"))));
    assert_eq!(h.client.stat(&root.join("c-dir")).await.unwrap().kind, EntryKind::Directory);
    assert_eq!(h.client.stat(Path::new("/")).await.unwrap().name, "/");
    assert_eq!(kind(&h.client.stat(&root.join("absent")).await.unwrap_err()), ErrorKind::NotFound);

    let listed = h.client.list(&root).await.unwrap();
    let names: Vec<_> = listed.iter().map(|e| (e.name.as_str(), e.kind)).collect();
    assert_eq!(
        names,
        [("a-link", EntryKind::Symlink), ("b-file", EntryKind::File), ("c-dir", EntryKind::Directory), ("d-dangling", EntryKind::Symlink)]
    );
    assert_eq!(listed[1], file);
    assert!(h.client.list(&root.join("c-dir")).await.unwrap().is_empty());
    assert_eq!(kind(&h.client.list(&root.join("b-file")).await.unwrap_err()), ErrorKind::NotADirectory);
}

// Remove deletes a file, a symlink (not its target), an empty directory, or
// with `recursive` a whole tree. A non-empty directory without `recursive`
// is DirectoryNotEmpty and stays; a missing entry is NotFound; the root
// directory is refused even with `recursive`.
#[tokio::test]
async fn remove_entries() {
    let h = agent().await;
    let root = h.vessel();
    std::fs::write(root.join("file"), b"x").unwrap();
    std::os::unix::fs::symlink("file", root.join("link")).unwrap();
    std::fs::create_dir(root.join("empty")).unwrap();
    std::fs::create_dir_all(root.join("tree/a/b")).unwrap();
    std::fs::write(root.join("tree/a/b/leaf"), b"x").unwrap();

    h.client.remove(&root.join("link"), false).await.unwrap();
    assert!(std::fs::symlink_metadata(root.join("link")).is_err());
    assert!(root.join("file").exists(), "removing a link leaves its target");
    h.client.remove(&root.join("file"), false).await.unwrap();
    assert!(!root.join("file").exists());
    h.client.remove(&root.join("empty"), false).await.unwrap();
    assert!(!root.join("empty").exists());

    assert_eq!(kind(&h.client.remove(&root.join("tree"), false).await.unwrap_err()), ErrorKind::DirectoryNotEmpty);
    assert!(root.join("tree/a/b/leaf").exists());
    h.client.remove(&root.join("tree"), true).await.unwrap();
    assert!(!root.join("tree").exists());

    assert_eq!(kind(&h.client.remove(&root.join("absent"), false).await.unwrap_err()), ErrorKind::NotFound);
    assert_eq!(kind(&h.client.remove(Path::new("/"), true).await.unwrap_err()), ErrorKind::PermissionDenied);
}

// Rename replaces an existing destination by default; `exclusive` refuses an
// existing one and moves nothing; `parents` creates a missing destination
// parent. A missing source is NotFound.
#[tokio::test]
async fn renames() {
    let h = agent().await;
    let root = h.vessel();
    std::fs::write(root.join("from"), b"source").unwrap();
    std::fs::write(root.join("to"), b"old").unwrap();
    let rename =
        |from: &str, to: &str, exclusive: bool, parents: bool| Rename { from: root.join(from), to: root.join(to), exclusive, parents };

    h.client.rename(&rename("from", "to", false, false)).await.unwrap();
    assert_eq!(std::fs::read(root.join("to")).unwrap(), b"source");
    assert!(!root.join("from").exists());

    std::fs::write(root.join("from"), b"second").unwrap();
    assert_eq!(kind(&h.client.rename(&rename("from", "to", true, false)).await.unwrap_err()), ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(root.join("to")).unwrap(), b"source");
    assert_eq!(std::fs::read(root.join("from")).unwrap(), b"second");
    h.client.rename(&rename("from", "fresh", true, false)).await.unwrap();
    assert_eq!(std::fs::read(root.join("fresh")).unwrap(), b"second");

    h.client.rename(&rename("fresh", "new/parent/file", false, true)).await.unwrap();
    assert_eq!(std::fs::read(root.join("new/parent/file")).unwrap(), b"second");
    assert_eq!(kind(&h.client.rename(&rename("absent", "elsewhere", false, false)).await.unwrap_err()), ErrorKind::NotFound);
}

// A symlink is created with its exact target, and atomically replaces an
// existing link or file unless `exclusive`. A directory in the way and an
// empty target are refused.
#[tokio::test]
async fn symlinks() {
    let h = agent().await;
    let root = h.vessel();
    let link = root.join("link");
    h.client.symlink(&link, Path::new("first"), &FileOptions::default()).await.unwrap();
    assert_eq!(std::fs::read_link(&link).unwrap(), Path::new("first"));
    h.client.symlink(&link, Path::new("/second/target"), &FileOptions::default()).await.unwrap();
    assert_eq!(std::fs::read_link(&link).unwrap(), Path::new("/second/target"));
    std::fs::write(root.join("file"), b"x").unwrap();
    h.client.symlink(&root.join("file"), Path::new("link"), &FileOptions::default()).await.unwrap();
    assert_eq!(std::fs::read_link(root.join("file")).unwrap(), Path::new("link"));

    let exclusive = FileOptions { exclusive: true, ..FileOptions::default() };
    assert_eq!(kind(&h.client.symlink(&link, Path::new("third"), &exclusive).await.unwrap_err()), ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read_link(&link).unwrap(), Path::new("/second/target"));
    h.client.symlink(&root.join("exclusive"), Path::new("x"), &exclusive).await.unwrap();

    std::fs::create_dir(root.join("dir")).unwrap();
    let error = h.client.symlink(&root.join("dir"), Path::new("x"), &FileOptions::default()).await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::IsADirectory);
    let error = h.client.symlink(&root.join("empty-target"), Path::new(""), &FileOptions::default()).await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::InvalidInput);
    let parents = FileOptions { parents: true, ..FileOptions::default() };
    h.client.symlink(&root.join("with/parent"), Path::new("x"), &parents).await.unwrap();
    assert_eq!(std::fs::read_link(root.join("with/parent")).unwrap(), Path::new("x"));
    assert!(leftovers(&root, ".drydock-").is_empty());
}

// Creating a directory defaults to 0700 and is idempotent: an existing
// directory is accepted (taking a newly given mode), unless `exclusive`. A
// file in the way is refused. Set_attributes changes a mode and reports the
// entry; a symlink has no mode of its own, so asking for one changes nothing.
#[tokio::test]
async fn directories_and_attributes() {
    let h = agent().await;
    let root = h.vessel();
    let dir = root.join("dir");
    let entry = h.client.create_dir(&dir, &FileOptions::default()).await.unwrap();
    assert_eq!((entry.name.as_str(), entry.kind, entry.mode), ("dir", EntryKind::Directory, 0o700));
    assert_eq!(mode_of(&dir), 0o700);
    std::fs::write(dir.join("kept"), b"x").unwrap();
    h.client.create_dir(&dir, &FileOptions::default()).await.unwrap();
    assert!(dir.join("kept").exists(), "an idempotent create leaves the contents alone");
    let changed = h.client.create_dir(&dir, &FileOptions { mode: Some(0o750), ..FileOptions::default() }).await.unwrap();
    assert_eq!((changed.mode, mode_of(&dir)), (0o750, 0o750));
    let error = h.client.create_dir(&dir, &FileOptions { exclusive: true, ..FileOptions::default() }).await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::AlreadyExists);
    std::fs::write(root.join("file"), b"x").unwrap();
    assert_eq!(kind(&h.client.create_dir(&root.join("file"), &FileOptions::default()).await.unwrap_err()), ErrorKind::AlreadyExists);
    h.client.create_dir(&root.join("x/y"), &FileOptions { parents: true, ..FileOptions::default() }).await.unwrap();
    assert!(root.join("x/y").is_dir());

    let mode = |mode| Attributes { mode: Some(mode), ..Attributes::default() };
    let updated = h.client.set_attributes(&root.join("file"), &mode(0o6604)).await.unwrap();
    assert_eq!((updated.name.as_str(), updated.mode), ("file", 0o604), "setuid and setgid are never set");
    assert_eq!(mode_of(&root.join("file")), 0o604);
    std::fs::set_permissions(root.join("file"), std::fs::Permissions::from_mode(0o000)).unwrap();
    h.client.set_attributes(&root.join("file"), &mode(0o604)).await.unwrap();
    assert_eq!(mode_of(&root.join("file")), 0o604, "an owner changes a mode nobody can read");
    std::os::unix::fs::symlink("file", root.join("link")).unwrap();
    assert_eq!(kind(&h.client.set_attributes(&root.join("link"), &mode(0o600)).await.unwrap_err()), ErrorKind::InvalidInput);
    assert_eq!(mode_of(&root.join("file")), 0o604, "the link's target is untouched");
}

// Any Unix name can be addressed: names needing percent-encoding (space,
// `%`, `?`, `#`, `+`, `&`, `=`) and non-UTF-8 bytes round-trip through write,
// read, head and stat, and appear in a listing.
#[tokio::test]
async fn unusual_names_round_trip() {
    let h = agent().await;
    let root = h.vessel();
    let names: Vec<&[u8]> = vec![
        b"with space",
        b"per%cent",
        b"%2e%2e",
        b"quest?ion",
        b"hash#tag",
        b"a+b&c=d",
        b"caf\xc3\xa9",
        b"raw\x80\xfe\xff",
        b"\xe9t\xe9",
    ];
    for name in &names {
        let path = root.join(OsStr::from_bytes(name));
        h.client.write_bytes(&path, name.to_vec(), &FileOptions::default()).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), *name, "{path:?} written at the exact name");
        assert_eq!(h.client.read_bytes(&path, 1024).await.unwrap(), *name);
        assert_eq!(h.client.head(&path).await.unwrap().0, name.len() as u64);
        let entry = h.client.stat(&path).await.unwrap();
        assert_eq!((entry.name, entry.size), (String::from_utf8_lossy(name).into_owned(), name.len() as u64));
    }
    let listed: Vec<String> = h.client.list(&root).await.unwrap().into_iter().map(|e| e.name).collect();
    let mut expected: Vec<String> = names.iter().map(|n| String::from_utf8_lossy(n).into_owned()).collect();
    expected.sort();
    assert_eq!(listed, expected);
}

// Paths must be absolute and free of `.`, `..` and NUL, whether written
// plainly or percent-encoded: a client refuses a relative path before sending
// it, and the agent's path decoder refuses the rest.
#[tokio::test]
async fn path_components_are_checked() {
    let h = agent().await;
    let root = h.vessel();
    let error = h.client.write_bytes(Path::new("relative/file"), b"x".to_vec(), &FileOptions::default()).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

    std::fs::write(root.join("target"), b"secret").unwrap();
    let encoded = route("/files", &root);
    for (method, uri) in [
        ("GET", format!("{encoded}/sub/../target")),
        ("GET", format!("{encoded}/sub/%2E%2E/target")),
        ("PUT", format!("{encoded}/../escape")),
    ] {
        let error = refused(&h, method, &uri, &[("content-type", "application/octet-stream")], b"x".to_vec(), 400).await;
        assert!(error.message.contains(".. components"), "{error}");
    }
    assert!(!h.dir.path().join("escape").exists());
    let error = refused(&h, "GET", &route("/files", &root.join("nul%00byte")).replace("%2500", "%00"), &[], vec![], 400).await;
    assert!(error.message.contains("NUL"), "{error}");
}

// Malformed write requests are refused before any file appears: a body that
// is not an octet stream, naming what was expected and what came; a sha256
// that is not 64 lowercase hex; a mode beyond 07777.
#[tokio::test]
async fn malformed_writes_are_refused() {
    let h = agent().await;
    let root = h.vessel();
    let path = root.join("never");
    let uri = route("/files", &path);
    let octet = [("content-type", "application/octet-stream")];

    let (status, _, _) = raw(&h, "PUT", &format!("{uri}-cased"), &[("content-type", "Application/Octet-Stream")], b"x".to_vec()).await;
    assert_eq!(status, 201, "media types compare case-insensitively");
    let error = refused(&h, "PUT", &uri, &[("content-type", "text/plain")], b"x".to_vec(), 415).await;
    assert!(error.message.contains("application/octet-stream") && error.message.contains("text/plain"), "{error}");
    for digest in ["abc", &"A".repeat(64), &"g".repeat(64), &"a".repeat(65)] {
        let error = refused(&h, "PUT", &format!("{uri}?sha256={digest}"), &octet, b"x".to_vec(), 400).await;
        assert!(error.message.contains("64 lowercase hex"), "{error}");
    }
    let error =
        h.client.write_bytes(&path, b"x".to_vec(), &FileOptions { mode: Some(0o17777), ..FileOptions::default() }).await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::InvalidInput);
    assert!(agent_error(&error).message.contains("17777"), "{error}");

    assert!(!path.exists());
    assert!(leftovers(&root, ".drydock-").is_empty());
}

// Interrupted uploads resume: generated sizes and interruption points. A
// source that fails partway leaves the agent holding a prefix of what it was
// sent (offset <= sent), and bytes the agent had already stored survive the
// interruption (offset > 0 once some were stored before the failure; earlier
// failures may lose bytes still in flight). Resuming from the offset
// completes the upload, the digest is verified, and installing the blob
// yields exactly the bytes.
#[hegel::test]
fn interrupted_uploads_resume_from_the_offset(tc: hegel::TestCase) {
    use hegel::generators as gs;
    // Sizes from tiny to several write buffers; cuts near the start, around
    // the middle and just before the end.
    let size =
        tc.draw(gs::sampled_from(vec![2usize, 70_000, 1 << 20, 3 << 20])) + tc.draw(gs::integers::<usize>().min_value(0).max_value(65_536));
    let jitter = tc.draw(gs::integers::<usize>().min_value(0).max_value(size / 4));
    let cut = match tc.draw(gs::integers::<u8>().min_value(0).max_value(2)) {
        0 => 1 + jitter.min(16_384),
        1 => size / 2 + jitter / 2,
        _ => size - 1 - jitter,
    };
    let seekable = tc.draw(gs::booleans());
    // Past the agent's 256 KiB write buffer, stored bytes appear while the
    // request is still streaming, so the failure can wait for them.
    let wait = cut >= 600_000;
    runtime().block_on(async {
        let h = agent().await;
        let root = h.vessel();
        let content = pattern(size as u64 ^ cut as u64, size);
        let digest = sha256(&content);
        let length = size as u64;
        let (open, gate) = tokio::sync::oneshot::channel();
        let source = FailAtEnd { inner: Cursor::new(content[..cut].to_vec()), gate: wait.then_some(gate) };
        let watch = async {
            if wait {
                let deadline = Instant::now() + Duration::from_secs(20);
                while stored(&h, &digest) == 0 {
                    assert!(Instant::now() < deadline, "no bytes were stored");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
            let _ = open.send(());
        };
        let (interrupted, ()) = tokio::join!(h.client.create_upload(&digest, Some(length), source, true), watch);
        let error = interrupted.unwrap_err();
        let (offset, complete) = h.client.upload_offset(&digest).await.unwrap();
        assert!(!complete);
        assert!(offset <= cut as u64, "offset {offset} after sending {cut} of {size}: {error}");
        assert!(!wait || offset > 0, "stored bytes were lost: sent {cut} of {size}: {error}");

        let (offset, complete) = if seekable {
            let source = root.join("source");
            std::fs::write(&source, &content).unwrap();
            h.client.resume_upload(&digest, length, tokio::fs::File::open(&source).await.unwrap()).await.unwrap()
        } else {
            h.client.append_upload(&digest, offset, Cursor::new(content[offset as usize..].to_vec()), true).await.unwrap()
        };
        assert_eq!((offset, complete), (length, true));
        assert_eq!(h.client.upload_offset(&digest).await.unwrap(), (length, true));
        assert_eq!(h.client.blob_size(&digest).await.unwrap(), Some(length));

        let installed = root.join("installed");
        let written =
            h.client.install_blob(&installed, &digest, &FileOptions { mode: Some(0o640), ..FileOptions::default() }).await.unwrap();
        assert_eq!(written, Written { sha256: digest.clone(), size: length });
        assert_eq!(sha256(&std::fs::read(&installed).unwrap()), digest);
        assert_eq!(mode_of(&installed), 0o640);
    });
}

// The upload resource follows draft-ietf-httpbis-resumable-upload-12. Offset
// retrieval reports the offset, completeness, declared length and limits,
// uncached. An append must be application/partial-upload with Upload-Offset
// and Upload-Complete; at another offset it is a 409 that carries the right
// one. Completing short of the declared length is refused; a body past it
// discards the upload; a length beyond the store's free space, or below the
// offset already reached, is refused before any byte is stored. Bytes that do not match the digest are refused
// at completion and discarded. A completed upload replays its completion to
// a valid append, and incomplete uploads and blobs can be removed.
#[tokio::test]
async fn upload_protocol_and_refusals() {
    let h = agent().await;
    let root = h.vessel();
    let content = pattern(11, 1 << 20);
    let digest = sha256(&content);
    let length = content.len() as u64;
    let half = length / 2;
    let uri = format!("/uploads/{digest}");
    assert_eq!(h.client.upload_offset(&digest).await.unwrap(), (0, false));
    assert_eq!(kind(&h.client.append_upload(&digest, 0, Cursor::new(vec![1]), false).await.unwrap_err()), ErrorKind::NotFound);

    let first = Cursor::new(content[..half as usize].to_vec());
    assert_eq!(h.client.create_upload(&digest, Some(length), first, false).await.unwrap(), (half, false));
    let (status, headers, _) = raw(&h, "HEAD", &uri, &[], vec![]).await;
    assert_eq!(status, 204);
    let field = |name: &str| headers[name].to_str().unwrap().to_owned();
    assert_eq!(
        (field("upload-offset"), field("upload-complete"), field("upload-length")),
        (half.to_string(), "?0".into(), length.to_string())
    );
    assert!(field("upload-limit").starts_with("max-age="), "{}", field("upload-limit"));
    assert_eq!(field("cache-control"), "no-store");
    let again = h.client.create_upload(&digest, Some(length), tokio::io::empty(), false).await.unwrap_err();
    assert_eq!(kind(&again), ErrorKind::Conflict, "an existing upload is resumed, not created again");

    for wrong in [0, half - 1, half + 1] {
        let error = h.client.append_upload(&digest, wrong, Cursor::new(vec![1]), false).await.unwrap_err();
        assert_eq!(kind(&error), ErrorKind::Conflict);
        assert!(agent_error(&error).message.contains(&format!("at {half} bytes")), "names the current offset: {error}");
    }
    let (harness, target) = (&h, &uri);
    let append = |offset: u64, complete: &'static str, content_type: &'static str| {
        let offset = offset.to_string();
        async move {
            let headers = [("content-type", content_type), ("upload-offset", offset.as_str()), ("upload-complete", complete)];
            raw(harness, "PATCH", target, &headers, vec![]).await
        }
    };
    let (status, headers, _) = append(0, "?0", "application/partial-upload").await;
    assert_eq!(
        (status, headers["upload-offset"].to_str().unwrap(), headers["upload-complete"].to_str().unwrap()),
        (409, half.to_string().as_str(), "?0")
    );
    assert_eq!(append(half, "?0", "application/octet-stream").await.0, 415);
    assert_eq!(append(half, "yes", "application/partial-upload").await.0, 400, "Upload-Complete is a structured boolean");
    let short = h.client.append_upload(&digest, half, tokio::io::empty(), true).await.unwrap_err();
    assert_eq!(kind(&short), ErrorKind::InvalidInput, "completion contradicts the declared length");

    let rest = Cursor::new(content[half as usize..].to_vec());
    assert_eq!(h.client.append_upload(&digest, half, rest, true).await.unwrap(), (length, true));
    assert_eq!(h.client.append_upload(&digest, length, tokio::io::empty(), true).await.unwrap(), (length, true), "completion replays");
    assert_eq!(kind(&h.client.append_upload(&digest, 0, tokio::io::empty(), false).await.unwrap_err()), ErrorKind::Conflict);

    let past = sha256(b"past its length");
    let error = h.client.create_upload(&past, Some(10), Cursor::new(vec![0; 20]), false).await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::PayloadTooLarge);
    assert_eq!(h.client.upload_offset(&past).await.unwrap(), (0, false), "an upload run past its length is discarded");
    let huge = sha256(b"never sent");
    let error = h.client.create_upload(&huge, Some(1 << 48), tokio::io::empty(), false).await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::StorageFull);
    let store = h.dir.path().join("agent.store");
    assert!(agent_error(&error).message.contains("free") && agent_error(&error).message.contains(&store.display().to_string()), "{error}");
    assert_eq!(h.client.upload_offset(&huge).await.unwrap(), (0, false));

    // Bytes resumed under the wrong digest are checked once, at the end.
    let claimed = sha256(b"what the host promised");
    let wrong = pattern(12, 600_000);
    h.client.create_upload(&claimed, None, Cursor::new(wrong[..250_000].to_vec()), false).await.unwrap();
    let below =
        [("content-type", "application/partial-upload"), ("upload-offset", "250000"), ("upload-complete", "?0"), ("upload-length", "50")];
    assert_eq!(raw(&h, "PATCH", &format!("/uploads/{claimed}"), &below, vec![1]).await.0, 400, "a length below the offset is refused");
    let error = h.client.append_upload(&claimed, 250_000, Cursor::new(wrong[250_000..].to_vec()), true).await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::DigestMismatch);
    let message = &agent_error(&error).message;
    assert!(message.contains(&claimed) && message.contains(&sha256(&wrong)), "{message}");
    assert_eq!(h.client.upload_offset(&claimed).await.unwrap(), (0, false), "the upload is discarded");
    assert_eq!(h.client.blob_size(&claimed).await.unwrap(), None);

    // Removing an incomplete upload forgets it; removing the blob forgets it.
    h.client.create_upload(&claimed, None, Cursor::new(wrong[..10].to_vec()), false).await.unwrap();
    h.client.remove_upload(&claimed).await.unwrap();
    assert_eq!(h.client.upload_offset(&claimed).await.unwrap(), (0, false));
    assert_eq!(kind(&h.client.remove_upload(&claimed).await.unwrap_err()), ErrorKind::NotFound);
    h.client.install_blob(&root.join("installed"), &digest, &FileOptions::default()).await.unwrap();
    assert_eq!(std::fs::read(root.join("installed")).unwrap(), content);
    h.client.remove_blob(&digest).await.unwrap();
    assert_eq!(h.client.blob_size(&digest).await.unwrap(), None);
    assert_eq!(h.client.upload_offset(&digest).await.unwrap(), (0, false));
    assert_eq!(kind(&h.client.remove_blob(&digest).await.unwrap_err()), ErrorKind::NotFound);

    // Installing a blob the store does not hold writes nothing.
    let error = h.client.install_blob(&root.join("unknown"), &digest, &FileOptions::default()).await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::NotFound);
    assert!(agent_error(&error).message.contains(&digest), "{error}");
    assert!(!root.join("unknown").exists());
}

// One upload is served by one request at a time, and a later request takes
// over (draft section 4.6): offset retrieval while an upload is still
// streaming ends that request, keeps what it stored, and reports the offset
// the next append needs. The upload then completes intact.
#[tokio::test]
async fn a_later_request_takes_over_an_upload() {
    let h = agent().await;
    let content = pattern(13, 1 << 20);
    let digest = sha256(&content);
    let length = content.len() as u64;
    let (mut writer, reader) = tokio::io::duplex(64 * 1024);
    let first = h.client.create_upload(&digest, Some(length), reader, true);
    let second = async {
        writer.write_all(&content[..300_000]).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while stored(&h, &digest) == 0 {
            assert!(Instant::now() < deadline, "no bytes were stored");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let asked = tokio::time::timeout(Duration::from_secs(10), h.client.upload_offset(&digest));
        let offset = asked.await.expect("the later request must end the earlier one").unwrap();
        drop(writer);
        offset
    };
    let (first, (offset, complete)) = tokio::join!(first, second);
    let error = first.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::Conflict, "{error}");
    assert!(!complete && offset > 0 && offset <= 300_000, "{offset}");
    let rest = Cursor::new(content[offset as usize..].to_vec());
    assert_eq!(h.client.append_upload(&digest, offset, rest, true).await.unwrap(), (length, true));
    assert_eq!(h.client.blob_size(&digest).await.unwrap(), Some(length));
}

/// A tar archive with nested directories, files with distinct modes and a
/// symlink, and the tree it should unpack to.
fn archive(seed: u64) -> (Vec<u8>, BTreeMap<PathBuf, Node>) {
    let mut builder = tar::Builder::new(Vec::new());
    let mut expected = BTreeMap::new();
    expected.insert(PathBuf::new(), Node::Dir { mode: 0o755 });
    for (path, mode) in [("bin", 0o755), ("etc", 0o750), ("etc/nested", 0o700)] {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_mode(mode);
        header.set_size(0);
        builder.append_data(&mut header, path, io::empty()).unwrap();
        expected.insert(PathBuf::from(path), Node::Dir { mode });
    }
    for (path, mode, size) in [("bin/run", 0o755, 70_000), ("etc/config", 0o640, 513), ("etc/nested/secret", 0o600, 0), ("top", 0o644, 3)] {
        let bytes = pattern(seed ^ size as u64, size);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(mode);
        header.set_size(size as u64);
        builder.append_data(&mut header, path, &bytes[..]).unwrap();
        expected.insert(PathBuf::from(path), Node::File { mode, bytes });
    }
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_mode(0o777);
    header.set_size(0);
    builder.append_link(&mut header, "bin/config", "../etc/config").unwrap();
    expected.insert(PathBuf::from("bin/config"), Node::Link { target: PathBuf::from("../etc/config") });
    (builder.into_inner().unwrap(), expected)
}
fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}
fn tree(sha256: String, compression: Compression, replace: bool) -> TreeOptions {
    TreeOptions { sha256, compression, replace, ..TreeOptions::default() }
}

// A streamed archive unpacks into a new directory whose contents, modes and
// links are exactly the archive's, plain or gzip, except that no entry keeps
// a setuid or setgid bit. An existing target is refused unless `replace`,
// which swaps the whole tree for the new one. A wrong sha256 leaves an
// existing target byte-for-byte unchanged, or a missing one missing, with no
// staging directory left. A body that is not an archive is refused,
// explaining that it could not be unpacked, and also changes nothing. A
// completed upload can be unpacked by its digest.
#[tokio::test]
async fn tree_unpack_with_digest_check() {
    let h = agent().await;
    let root = h.vessel();
    let (plain, expected) = archive(1);
    let target = root.join("tree");
    let written = h.client.unpack(&target, Cursor::new(plain.clone()), &tree(sha256(&plain), Compression::None, false)).await.unwrap();
    assert_eq!(written, Written { sha256: sha256(&plain), size: plain.len() as u64 });
    assert_eq!(snapshot(&target), expected);

    let (second, expected_second) = archive(2);
    let compressed = gzip(&second);
    let gz_target = root.join("gz");
    h.client.unpack(&gz_target, Cursor::new(compressed.clone()), &tree(sha256(&compressed), Compression::Gzip, false)).await.unwrap();
    assert_eq!(snapshot(&gz_target), expected_second);

    // An existing target needs `replace`.
    let error = h.client.unpack(&target, Cursor::new(second.clone()), &tree(sha256(&second), Compression::None, false)).await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::AlreadyExists);
    assert_eq!(snapshot(&target), expected);
    std::fs::write(target.join("stale"), b"from before").unwrap();
    h.client.unpack(&target, Cursor::new(second.clone()), &tree(sha256(&second), Compression::None, true)).await.unwrap();
    assert_eq!(snapshot(&target), expected_second, "replace leaves only the new tree");

    // A digest mismatch leaves the existing tree and a missing target alone.
    let before = snapshot(&target);
    let wrong = sha256(b"not this archive");
    let error = h.client.unpack(&target, Cursor::new(plain.clone()), &tree(wrong.clone(), Compression::None, true)).await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::DigestMismatch);
    let message = &agent_error(&error).message;
    assert!(message.contains(&wrong) && message.contains(&sha256(&plain)), "{message}");
    assert_eq!(snapshot(&target), before);
    let absent = root.join("absent");
    let error = h.client.unpack(&absent, Cursor::new(plain.clone()), &tree(wrong.clone(), Compression::None, false)).await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::DigestMismatch);
    assert!(std::fs::symlink_metadata(&absent).is_err(), "a refused unpack creates nothing");

    // A body that is not a tar archive, sent with its own correct digest.
    for (junk, compression) in [(pattern(5, 4096), Compression::None), (pattern(6, 4096), Compression::Gzip)] {
        let error = h.client.unpack(&target, Cursor::new(junk.clone()), &tree(sha256(&junk), compression, true)).await.unwrap_err();
        assert_eq!(kind(&error), ErrorKind::InvalidData);
        assert!(agent_error(&error).to_string().contains("could not be unpacked"), "{error}");
        assert_eq!(snapshot(&target), before);
    }
    assert!(leftovers(&root, ".drydock-").is_empty(), "{:?}", leftovers(&root, ""));

    // Nothing an archive declares grants privilege: only setuid and setgid go.
    let mut builder = tar::Builder::new(Vec::new());
    for (path, mode) in [("setuid", 0o4755), ("setgid", 0o2755), ("sticky-dir", 0o1777)] {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(if path == "sticky-dir" { tar::EntryType::Directory } else { tar::EntryType::Regular });
        header.set_mode(mode);
        header.set_size(0);
        builder.append_data(&mut header, path, io::empty()).unwrap();
    }
    let privileged = builder.into_inner().unwrap();
    let modes = root.join("modes");
    h.client.unpack(&modes, Cursor::new(privileged.clone()), &tree(sha256(&privileged), Compression::None, false)).await.unwrap();
    let unpacked: Vec<_> = ["setuid", "setgid", "sticky-dir"].iter().map(|p| mode_of(&modes.join(p))).collect();
    assert_eq!(unpacked, [0o755, 0o755, 0o1777]);

    // Replacing a tree whose root lets nobody write still removes the old one.
    let locked = root.join("locked");
    let locked_tree = TreeOptions { mode: Some(0o555), ..tree(sha256(&plain), Compression::None, false) };
    h.client.unpack(&locked, Cursor::new(plain.clone()), &locked_tree).await.unwrap();
    let replacing = TreeOptions { replace: true, ..locked_tree };
    h.client.unpack(&locked, Cursor::new(plain.clone()), &replacing).await.unwrap();
    assert!(leftovers(&root, ".drydock-").is_empty(), "{:?}", leftovers(&root, ""));
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Unpack a completed upload by digest.
    let (third, expected_third) = archive(3);
    let digest = sha256(&third);
    h.client.upload(&digest, third.len() as u64, Cursor::new(third.clone())).await.unwrap();
    let from_blob = root.join("from-blob");
    let written = h.client.unpack_blob(&from_blob, &tree(digest.clone(), Compression::None, false)).await.unwrap();
    assert_eq!(written.sha256, digest);
    assert_eq!(snapshot(&from_blob), expected_third);
    let error = h.client.unpack_blob(&root.join("no-blob"), &tree(sha256(b"unknown"), Compression::None, false)).await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::NotFound);
    assert!(!root.join("no-blob").exists());
}

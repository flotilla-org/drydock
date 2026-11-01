//! Fetching artifacts by digest into the agent's store, against in-process
//! stand-ins for an upstream download host and an OCI registry (see
//! `support/origin.rs` for what each request must carry). Egress through
//! the configured upstream is covered beside the fetcher (`src/fetch.rs`),
//! and a fetch larger than 512 MiB in `large_fetch.rs`.
mod support;
use drydock_agent::{ArtifactSource, ErrorKind, Fetch, FileOptions, Origin as Served, RegistryCredential, Unpack};
use std::{
    collections::BTreeMap,
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use support::{origin::*, *};

fn store(h: &Harness) -> PathBuf {
    h.dir.path().join("agent.store")
}
fn upstream(url: String) -> ArtifactSource {
    ArtifactSource::Upstream { url }
}
fn file(mode: u32) -> Unpack {
    Unpack::File { mode }
}
fn fetch(sources: Vec<ArtifactSource>, unpack: Unpack) -> Fetch {
    Fetch { sources, unpack }
}
fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}
/// Names under one of the store's directories.
fn names(h: &Harness, directory: &str) -> Vec<String> {
    match std::fs::read_dir(store(h).join(directory)) {
        Ok(entries) => entries.map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect(),
        Err(_) => vec![],
    }
}
/// A download host serving `content` at `/download`, with ranges.
async fn download_host(content: Vec<u8>) -> Origin {
    let content = Content::bytes(content);
    Origin::start(move |request| match request.target.as_str() {
        "/download" => Reply::content(content.clone()),
        other => Reply::Status(404, vec![], format!("no {other}").into_bytes()),
    })
    .await
}

/// Every entry of a tree: mode and bytes, or a link target.
#[derive(Debug, PartialEq, Eq)]
enum Node {
    Dir(u32),
    File(u32, Vec<u8>),
    Link(PathBuf),
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Node> {
    fn walk(root: &Path, at: &Path, into: &mut BTreeMap<PathBuf, Node>) {
        let metadata = std::fs::symlink_metadata(at).unwrap();
        let relative = at.strip_prefix(root).unwrap().to_path_buf();
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.file_type().is_symlink() {
            into.insert(relative, Node::Link(std::fs::read_link(at).unwrap()));
        } else if metadata.is_dir() {
            into.insert(relative, Node::Dir(mode));
            for entry in std::fs::read_dir(at).unwrap() {
                walk(root, &entry.unwrap().path(), into);
            }
        } else {
            into.insert(relative, Node::File(mode, std::fs::read(at).unwrap()));
        }
    }
    let mut nodes = BTreeMap::new();
    walk(root, root, &mut nodes);
    nodes
}
/// A tar.gz release package: directories, an executable, a data file, a
/// setuid file and a symlink within the tree; and the read-only tree it
/// becomes in the store, without write, setuid or setgid bits.
fn package(seed: u64) -> (Vec<u8>, BTreeMap<PathBuf, Node>) {
    let mut builder = tar::Builder::new(Vec::new());
    let mut expected = BTreeMap::from([(PathBuf::new(), Node::Dir(0o755 & 0o555))]);
    for (path, mode) in [("codex", 0o755), ("codex/bin", 0o750)] {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_mode(mode);
        header.set_size(0);
        builder.append_data(&mut header, path, io::empty()).unwrap();
        expected.insert(PathBuf::from(path), Node::Dir(mode & 0o555));
    }
    for (path, mode, size) in [("codex/bin/codex", 0o755, 90_000), ("codex/README", 0o644, 300), ("codex/bin/helper", 0o4755, 5)] {
        let bytes = pattern(seed ^ size as u64, size);
        let mut header = tar::Header::new_gnu();
        header.set_mode(mode);
        header.set_size(size as u64);
        builder.append_data(&mut header, path, &bytes[..]).unwrap();
        expected.insert(PathBuf::from(path), Node::File(mode & 0o555, bytes));
    }
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    builder.append_link(&mut header, "codex/docs", "README").unwrap();
    expected.insert(PathBuf::from("codex/docs"), Node::Link(PathBuf::from("README")));
    let tar = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    io::Write::write_all(&mut encoder, &tar).unwrap();
    (encoder.finish().unwrap(), expected)
}

// A single binary from an upstream URL becomes a read-only file entry with
// the requested mode, less its write bits, recorded in the index. A repeat
// fetch is a lookup that makes no request, and so is a fetch racing the
// first one: it waits for it rather than downloading again. A fetch asking
// for the same digest stored another way is refused.
#[tokio::test]
async fn upstream_binary_is_stored_once_and_then_served_from_the_index() {
    let h = harness(false, "test-build").await;
    let content = pattern(1, 300_000);
    let digest = sha256(&content);
    let host = download_host(content.clone()).await;
    let request = fetch(vec![upstream(host.url("/download"))], file(0o755));

    let (first, second) = tokio::join!(h.client.fetch_artifact(&digest, &request), h.client.fetch_artifact(&digest, &request));
    let mut origins = [first.as_ref().unwrap().origin, second.as_ref().unwrap().origin];
    origins.sort_by_key(|origin| *origin == Served::Index);
    assert_eq!(origins, [Served::Source(0), Served::Index]);
    let artifact = first.unwrap().artifact;
    assert_eq!((artifact.sha256.as_str(), artifact.size, artifact.unpack), (digest.as_str(), content.len() as u64, file(0o755)));
    assert_eq!(std::fs::read(&artifact.path).unwrap(), content);
    assert_eq!(mode_of(&artifact.path), 0o555);
    assert_eq!(host.requests().len(), 1, "one download for two fetches");

    let again = h.client.fetch_artifact(&digest, &request).await.unwrap();
    assert_eq!((again.origin, again.artifact), (Served::Index, artifact.clone()));
    assert_eq!(host.requests().len(), 1, "a repeat fetch makes no request");
    assert_eq!(h.client.artifacts().await.unwrap(), vec![artifact.clone()]);
    assert_eq!(h.client.artifact(&digest).await.unwrap(), artifact);

    let refused = failed(h.client.fetch_artifact(&digest, &fetch(vec![], Unpack::TarGz)).await);
    assert_eq!(kind(&refused), ErrorKind::Conflict);
    assert_eq!(std::fs::read(&artifact.path).unwrap(), content);
}

// An upstream tar.gz unpacks into a read-only directory entry holding
// exactly the archive's tree, minus write, setuid and setgid bits; the
// archive's own bytes are not kept once unpacked.
#[tokio::test]
async fn upstream_tar_gz_unpacks_into_a_read_only_tree() {
    let h = harness(false, "test-build").await;
    let (bytes, expected) = package(2);
    let digest = sha256(&bytes);
    let host = download_host(bytes.clone()).await;
    let fetched = h.client.fetch_artifact(&digest, &fetch(vec![upstream(host.url("/download"))], Unpack::TarGz)).await.unwrap();
    assert_eq!((fetched.origin, fetched.artifact.size), (Served::Source(0), bytes.len() as u64));
    assert_eq!(snapshot(&fetched.artifact.path), expected);
    assert_eq!(names(&h, "blobs"), Vec::<String>::new());
    assert_eq!(names(&h, "partial"), Vec::<String>::new());
}

// The OCI distribution API, as ghcr.io serves a public blob: the blob URL
// answers 401 with a Bearer challenge; the token service requires the
// challenge's service and scope; the blob URL then requires the token and
// redirects to a CDN on another origin, which must not receive the token.
// A Basic credential, when given, goes to the token service only.
#[tokio::test]
async fn oci_blob_is_fetched_by_digest_through_the_token_flow() {
    let h = harness(false, "test-build").await;
    let (bytes, expected) = package(3);
    let digest = sha256(&bytes);
    let content = Content::bytes(bytes);
    let cdn = Origin::start(move |request| match request.header("authorization") {
        Some(_) => Reply::bad("the CDN must not receive the registry token"),
        None if request.target.starts_with("/blob?signature=") => Reply::content(content.clone()),
        None => Reply::Status(404, vec![], vec![]),
    })
    .await;
    let redirect = cdn.url("/blob?signature=s3cret");
    let blob = format!("/v2/team/codex/blobs/sha256:{digest}");
    let registry = Origin::start({
        let blob = blob.clone();
        move |request| {
            let host = request.header("host").unwrap().to_owned();
            if request.target == blob {
                match request.header("authorization") {
                    Some("Bearer pull-token") => Reply::Status(307, vec![("Location", redirect.clone())], vec![]),
                    _ => Reply::Status(
                        401,
                        vec![(
                            "WWW-Authenticate",
                            format!(r#"Bearer realm="http://{host}/token",service="registry.test",scope="repository:team/codex:pull""#),
                        )],
                        vec![],
                    ),
                }
            } else if request.target == "/token?service=registry.test&scope=repository%3Ateam%2Fcodex%3Apull" {
                Reply::Status(200, vec![("Content-Type", "application/json".into())], br#"{"token":"pull-token"}"#.to_vec())
            } else {
                Reply::bad(format!("unexpected {}", request.target))
            }
        }
    })
    .await;
    let source = ArtifactSource::Oci { registry: registry.url(""), repository: "team/codex".into(), credential: None };
    let fetched = h.client.fetch_artifact(&digest, &fetch(vec![source], Unpack::TarGz)).await.unwrap();
    assert_eq!(fetched.origin, Served::Source(0));
    assert_eq!(snapshot(&fetched.artifact.path), expected);
    let targets: Vec<String> = registry.requests().into_iter().map(|r| r.target).collect();
    assert_eq!(targets, [blob.clone(), "/token?service=registry.test&scope=repository%3Ateam%2Fcodex%3Apull".into(), blob]);
    assert_eq!(cdn.requests().len(), 1);

    // Credentials only ever travel to an https registry.
    let credential = Some(RegistryCredential::Basic { username: "u".into(), password: "p".into() });
    let source = ArtifactSource::Oci { registry: registry.url(""), repository: "team/codex".into(), credential };
    let refused = failed(h.client.fetch_artifact(&"1".repeat(64), &fetch(vec![source], Unpack::TarGz)).await);
    assert_eq!(kind(&refused), ErrorKind::InvalidInput);
}

// Sources are tried in the caller's order: one that refuses (403), one that
// is missing (404) and one that cannot be reached each fall through to the
// next. When every source fails, the refusal names each source with the
// step that failed, and the digest. Bytes that hash to another digest store
// nothing at all: no entry, record, blob or staged bytes.
#[tokio::test]
async fn sources_fall_through_and_a_mismatch_stores_nothing() {
    let h = harness(false, "test-build").await;
    let content = pattern(4, 70_000);
    let digest = sha256(&content);
    let good = download_host(content.clone()).await;
    let refusing = Origin::start(|_| Reply::Status(403, vec![], b"forbidden".to_vec())).await;
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let sources = vec![
        upstream(refusing.url("/download")),
        upstream(good.url("/missing")),
        upstream(format!("http://{closed}/download")),
        upstream(good.url("/download")),
    ];
    let fetched = h.client.fetch_artifact(&digest, &fetch(sources.clone(), file(0o644))).await.unwrap();
    assert_eq!(fetched.origin, Served::Source(3));
    assert_eq!(std::fs::read(&fetched.artifact.path).unwrap(), content);

    let other = pattern(5, 70_001);
    let wrong = sha256(&other);
    let error = failed(h.client.fetch_artifact(&wrong, &fetch(sources, file(0o644))).await);
    let detail = agent_error(&error);
    assert_eq!(
        (detail.operation.as_str(), detail.subject.as_str(), detail.kind),
        ("artifact.fetch", wrong.as_str(), ErrorKind::DigestMismatch)
    );
    let steps: Vec<_> = detail.causes.iter().map(|cause| cause.split(": ").nth(1).unwrap().to_owned()).collect();
    assert_eq!(steps, ["http", "http", "connect", "verify"], "{detail}");
    assert!(detail.causes.iter().enumerate().all(|(i, cause)| cause.starts_with(&format!("[{i}] upstream http://"))), "{detail}");
    assert!(detail.causes[0].contains("403") && detail.causes[1].contains("404"), "{detail}");
    assert_eq!(h.client.artifacts().await.unwrap().len(), 1);
    assert_eq!(names(&h, "partial"), Vec::<String>::new());
    assert_eq!(names(&h, "blobs"), Vec::<String>::new());
    assert!(!store(&h).join("artifacts").join(&wrong).exists() && !store(&h).join("index").join(&wrong).exists());
}

// An interrupted body leaves its bytes staged and the fetch continues. A
// source that honours Range is asked for exactly the rest; one that ignores
// it sends everything again and the staged bytes are replaced. Either way
// the entry has exactly the content.
#[hegel::test]
fn interrupted_downloads_resume_or_restart(tc: hegel::TestCase) {
    use hegel::generators as gs;
    // Sizes around and past the agent's 256 KiB write buffer; cuts from the
    // first byte to the last.
    let size = tc.draw(gs::sampled_from(vec![2usize, 300_000, 1 << 20])) + tc.draw(gs::integers::<usize>().min_value(0).max_value(4096));
    let cut = tc.draw(gs::integers::<usize>().min_value(1).max_value(size - 1)) as u64;
    let ranges = tc.draw(gs::booleans());
    runtime().block_on(async {
        let h = harness(false, "test-build").await;
        let content = pattern(size as u64 ^ cut, size);
        let digest = sha256(&content);
        let first = Arc::new(AtomicBool::new(true));
        let served = Content::bytes(content.clone());
        let host = Origin::start(move |_| Reply::Content {
            content: served.clone(),
            ranges,
            cut_after: first.swap(false, Ordering::SeqCst).then_some(cut),
        })
        .await;
        let fetched = h.client.fetch_artifact(&digest, &fetch(vec![upstream(host.url("/x"))], file(0o444))).await.unwrap();
        assert_eq!(std::fs::read(&fetched.artifact.path).unwrap(), content);
        let starts: Vec<_> = host.requests().iter().map(Request::range_start).collect();
        assert_eq!(starts, [None, Some(cut)], "the second request asks for the rest");
    });
}

// The push source is the last resort: reaching it without a completed
// upload is refused as `artifact.push`, naming how many bytes are staged.
// The caller then pushes through the resumable upload protocol into the
// same staging, continuing from what a broken download left there, and the
// next fetch stores the pushed bytes without asking any source again.
#[tokio::test]
async fn a_push_continues_the_staged_bytes_and_completes_the_fetch() {
    let h = harness(false, "test-build").await;
    let content = pattern(6, 600_000);
    let digest = sha256(&content);
    let cut = Content::bytes(content.clone());
    let host = Origin::start(move |_| Reply::Content { content: cut.clone(), ranges: false, cut_after: Some(400_000) }).await;
    let request = fetch(vec![upstream(host.url("/x")), ArtifactSource::Push], file(0o555));
    let error = failed(h.client.fetch_artifact(&digest, &request).await);
    let detail = agent_error(&error);
    assert_eq!((detail.operation.as_str(), detail.kind), ("artifact.push", ErrorKind::NotFound), "{detail}");
    assert!(detail.causes[1].contains("(400000 bytes staged)"), "{detail}");
    let requests = host.requests().len();

    let source = h.vessel().join("package");
    std::fs::write(&source, &content).unwrap();
    let push = fetch(vec![ArtifactSource::Push], file(0o555));
    let file = tokio::fs::File::open(&source).await.unwrap();
    let fetched = h.client.fetch_artifact_or_push(&digest, &push, content.len() as u64, file).await.unwrap();
    assert_eq!(fetched.origin, Served::Blob);
    assert_eq!(std::fs::read(&fetched.artifact.path).unwrap(), content);
    assert_eq!(host.requests().len(), requests);
}

// An archive whose entry would leave the tree is refused before the entry
// appears: nothing is stored under the digest, and the verified bytes are
// kept so that asking again reads them rather than downloading.
// (`src/artifacts.rs` generates escapes of every shape.)
#[tokio::test]
async fn an_escaping_archive_is_refused_and_stores_no_entry() {
    let h = harness(false, "test-build").await;
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    builder.append_link(&mut header, "bin/sh", "/bin/sh").unwrap();
    let bytes = builder.into_inner().unwrap();
    let digest = sha256(&bytes);
    let host = download_host(bytes).await;
    let request = fetch(vec![upstream(host.url("/download"))], Unpack::Tar);
    let error = failed(h.client.fetch_artifact(&digest, &request).await);
    let detail = agent_error(&error);
    assert_eq!((detail.kind, detail.status), (ErrorKind::InvalidData, 422));
    assert!(detail.message.contains("unpack: bin/sh: the symlink to /bin/sh points outside the tree"), "{detail}");
    assert_eq!(names(&h, "artifacts"), Vec::<String>::new());
    assert_eq!(h.client.artifacts().await.unwrap(), vec![]);
    let again = failed(h.client.fetch_artifact(&digest, &request).await);
    assert_eq!(agent_error(&again).kind, ErrorKind::InvalidData);
    assert_eq!(host.requests().len(), 1, "the kept bytes are unpacked again, not downloaded");
}

// A link to an entry, or to a member inside it, appears in one step: a
// reader watching the path while it is moved between two versions never
// finds it missing. An entry a link still points into is in use and its
// removal is refused, naming the link; once the link points elsewhere the
// entry can go, and a removed entry is fetched again.
#[tokio::test]
async fn links_are_atomic_and_an_entry_in_use_is_not_removed() {
    let h = harness(false, "test-build").await;
    let (old, _) = package(7);
    let (new, _) = package(8);
    let (old_digest, new_digest) = (sha256(&old), sha256(&new));
    let (old_host, new_host) = (download_host(old).await, download_host(new).await);
    for (digest, host) in [(&old_digest, &old_host), (&new_digest, &new_host)] {
        h.client.fetch_artifact(digest, &fetch(vec![upstream(host.url("/download"))], Unpack::TarGz)).await.unwrap();
    }
    let bin = h.vessel().join("path/codex");
    let member = Path::new("codex/bin/codex");
    let options = FileOptions { parents: true, ..FileOptions::default() };
    h.client.link_artifact(&bin, &old_digest, member, &options).await.unwrap();
    let old_entry = h.client.artifact(&old_digest).await.unwrap();
    assert_eq!(old_entry.links, vec![bin.clone()]);
    assert_eq!(std::fs::read_link(&bin).unwrap(), old_entry.path.join(member));

    let watching = Arc::new(AtomicBool::new(true));
    let watcher = std::thread::spawn({
        let (watching, bin) = (watching.clone(), bin.clone());
        move || {
            let mut reads = 0u64;
            while watching.load(Ordering::SeqCst) {
                assert!(std::fs::symlink_metadata(&bin).is_ok(), "the link was missing after {reads} reads");
                reads += 1;
            }
        }
    });
    for round in 0..40 {
        let digest = if round % 2 == 0 { &new_digest } else { &old_digest };
        h.client.link_artifact(&bin, digest, member, &FileOptions::default()).await.unwrap();
    }
    watching.store(false, Ordering::SeqCst);
    watcher.join().unwrap();

    // The link now points into the old entry again.
    let error = failed(h.client.remove_artifact(&old_digest).await);
    let detail = agent_error(&error);
    assert_eq!((detail.kind, detail.status), (ErrorKind::ResourceBusy, 409));
    assert!(detail.message.contains(&bin.display().to_string()), "{detail}");
    assert!(old_entry.path.join(member).exists());

    h.client.link_artifact(&bin, &new_digest, member, &FileOptions::default()).await.unwrap();
    h.client.remove_artifact(&old_digest).await.unwrap();
    assert!(!old_entry.path.exists());
    assert_eq!(h.client.artifacts().await.unwrap().into_iter().map(|a| a.sha256).collect::<Vec<_>>(), std::slice::from_ref(&new_digest));
    assert_eq!(kind(&failed(h.client.remove_artifact(&new_digest).await)), ErrorKind::ResourceBusy);
    assert_eq!(kind(&failed(h.client.link_artifact(&bin, &old_digest, member, &options).await)), ErrorKind::NotFound);
    assert_eq!(kind(&failed(h.client.link_artifact(&bin, &new_digest, Path::new("../x"), &options).await)), ErrorKind::InvalidInput);

    let again = h.client.fetch_artifact(&old_digest, &fetch(vec![upstream(old_host.url("/download"))], Unpack::TarGz)).await.unwrap();
    assert_eq!(again.origin, Served::Source(0));
}

// Agents sharing a store (`--store`), as vessels on one host do, share its
// entries: what one fetched is a lookup for the other, which asks no source.
#[tokio::test]
async fn agents_sharing_a_store_fetch_once() {
    let shared = tempfile::tempdir().unwrap();
    let root = shared.path().join("store");
    let content = pattern(9, 100_000);
    let digest = sha256(&content);
    let host = download_host(content).await;
    let request = fetch(vec![upstream(host.url("/download"))], file(0o555));
    let mut origins = Vec::new();
    for _ in 0..2 {
        let root = root.clone();
        let h = harness_with(false, "test-build", move |guest, dir| {
            drydock_agent::Agent::new(guest, "test-build".into(), dir.join("agent")).with_store(root)
        })
        .await;
        origins.push(h.client.fetch_artifact(&digest, &request).await.unwrap().origin);
    }
    assert_eq!(origins, [Served::Source(0), Served::Index]);
    assert_eq!(host.requests().len(), 1);
}

// #4087: agents sharing a store each name a holder directory, as vessels on
// one host name their state directories. An entry linked through two
// holders survives a collection while either lives; once both are gone a
// collection removes it, read-only tree and all, with its record, so the
// next fetch downloads again. An entry fetched within the grace survives a
// collection unlinked, and goes once the grace is spent, as does a
// completed upload such as an agent upgrade image. Mutation check: counting
// a gone holder's records as uses keeps the entry and fails this scenario.
#[tokio::test]
async fn a_collection_removes_what_no_live_holder_uses() {
    let shared = tempfile::tempdir().unwrap();
    let root = shared.path().join("store");
    let (package, _) = package(11);
    let digest = sha256(&package);
    let host = download_host(package).await;
    let request = fetch(vec![upstream(host.url("/download"))], Unpack::TarGz);
    let mut vessels = Vec::new();
    for name in ["a", "b"] {
        let holder = shared.path().join(name);
        std::fs::create_dir(&holder).unwrap();
        let root = root.clone();
        let agent = {
            let holder = holder.clone();
            harness_with(false, "test-build", move |guest, dir| {
                drydock_agent::Agent::new(guest, "test-build".into(), dir.join("agent")).with_store(root).with_holder(holder)
            })
            .await
        };
        agent.client.fetch_artifact(&digest, &request).await.unwrap();
        let link = agent.vessel().join("home/codex");
        agent.client.link_artifact(&link, &digest, Path::new(""), &FileOptions { parents: true, ..FileOptions::default() }).await.unwrap();
        vessels.push((agent, holder, link));
    }
    let entry = vessels[0].0.client.artifact(&digest).await.unwrap();
    assert_eq!(entry.links.len(), 2);
    assert_eq!(host.requests().len(), 1, "the second agent's fetch is a lookup");

    std::fs::remove_dir(&vessels[0].1).unwrap();
    assert_eq!(drydock_agent::collect(root.clone(), std::time::Duration::ZERO).await.unwrap().entries, 0);
    assert_eq!(vessels[1].0.client.artifact(&digest).await.unwrap().links, vec![vessels[1].2.clone()]);
    // A gone holder's agent places no use that would never count.
    let refused = failed(vessels[0].0.client.link_artifact(&vessels[0].2, &digest, Path::new(""), &FileOptions::default()).await);
    assert_eq!(kind(&refused), ErrorKind::NotFound);

    std::fs::remove_dir(&vessels[1].1).unwrap();
    let collected = drydock_agent::collect(root.clone(), std::time::Duration::ZERO).await.unwrap();
    assert_eq!(collected.entries, 1);
    assert!(!entry.path.exists());
    assert_eq!(vessels[1].0.client.artifacts().await.unwrap(), vec![]);
    assert!(std::fs::read_dir(root.join("holders")).unwrap().next().is_none(), "gone holders are forgotten");

    // Unlinked: kept within the grace after its fetch, then removed.
    let (agent, holder, _) = &vessels[1];
    std::fs::create_dir(holder).unwrap();
    assert_eq!(agent.client.fetch_artifact(&digest, &request).await.unwrap().origin, Served::Source(0));
    let image = pattern(12, 4096);
    agent.client.resume_upload(&sha256(&image), image.len() as u64, io::Cursor::new(image.clone())).await.unwrap();
    let hour = std::time::Duration::from_secs(3600);
    assert_eq!(drydock_agent::collect(root.clone(), hour).await.unwrap(), drydock_agent::Collected::default());
    assert_eq!(agent.client.blob_size(&sha256(&image)).await.unwrap(), Some(image.len() as u64));
    let collected = drydock_agent::collect(root.clone(), std::time::Duration::ZERO).await.unwrap();
    assert_eq!(collected, drydock_agent::Collected { entries: 1, blobs: 1, skipped: 0 });
    assert_eq!(agent.client.blob_size(&sha256(&image)).await.unwrap(), None);
}

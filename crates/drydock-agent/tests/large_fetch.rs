//! One fetch larger than 512 MiB, alone in its test binary so that no other
//! test moves the process's peak RSS while it is measured.
mod support;
use drydock_agent::{ArtifactSource, Fetch, Origin as Served, Unpack};
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path, time::Instant};
use support::{origin::*, *};

const MIB: u64 = 1 << 20;
/// Past 512 MiB and not a multiple of any buffer size.
const SIZE: u64 = 520 * MIB + 12_345;

/// The process's peak resident set (VmHWM) in bytes. The agent and the
/// download host run in this process, so this covers both.
fn peak_rss() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("VmHWM:")).expect("VmHWM in /proc/self/status");
    line.split_whitespace().nth(1).unwrap().parse::<u64>().unwrap() * 1024
}
fn reset_peak() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}
/// SIZE pseudo-random bytes written a MiB at a time, and their digest.
fn generate(path: &Path) -> String {
    let mut file = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    let mut hasher = Sha256::new();
    let mut state = 0x5eed_u64;
    let mut buffer = vec![0u8; MIB as usize];
    let mut left = SIZE;
    while left > 0 {
        for word in buffer.as_chunks_mut::<8>().0 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *word = state.to_le_bytes();
        }
        let n = left.min(MIB) as usize;
        hasher.update(&buffer[..n]);
        file.write_all(&buffer[..n]).unwrap();
        left -= n as u64;
    }
    file.into_inner().unwrap().sync_all().unwrap();
    format!("{:x}", hasher.finalize())
}

// An artifact larger than 512 MiB streams from the source to the store
// with bounded memory: the peak RSS of agent and source together grows by
// a small fraction of it. That the bytes are exactly the source's is
// checked by the digest the store enforces, and here once more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_fetch_streams_with_bounded_memory() {
    let scratch = tempfile::tempdir().unwrap();
    let source = scratch.path().join("source");
    let started = Instant::now();
    let digest = generate(&source);
    let content = Content::File(source.clone(), SIZE);
    let host = Origin::start(move |_| Reply::content(content.clone())).await;
    let h = harness(false, "test-build").await;
    reset_peak();
    let baseline = peak_rss();
    let generated = started.elapsed();

    let request = Fetch { sources: vec![ArtifactSource::Upstream { url: host.url("/large") }], unpack: Unpack::File { mode: 0o555 } };
    let fetched = h.client.fetch_artifact(&digest, &request).await.unwrap();
    assert_eq!((fetched.origin, fetched.artifact.size), (Served::Source(0), SIZE));
    let growth = peak_rss().saturating_sub(baseline);
    eprintln!(
        "peak RSS growth {:.1} MiB over a {:.1} MiB baseline; fetch {:?}",
        growth as f64 / MIB as f64,
        baseline as f64 / MIB as f64,
        started.elapsed() - generated
    );
    assert!(growth < 64 * MIB, "peak RSS grew by {growth} bytes while fetching {SIZE}");
    let mut stored = std::fs::File::open(&fetched.artifact.path).unwrap();
    let mut hasher = Sha256::new();
    std::io::copy(&mut stored, &mut hasher).unwrap();
    assert_eq!(format!("{:x}", hasher.finalize()), digest);
}

//! One transfer larger than 512 MiB, alone in its test binary so that no
//! other test moves the process's peak RSS while it is measured.
mod support;
use drydock_agent::{FileOptions, Written};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    time::Instant,
};
use support::*;

const MIB: u64 = 1 << 20;
/// Past 512 MiB and not a multiple of any buffer size, so the last chunk of
/// every stream is a partial one.
const SIZE: u64 = 520 * MIB + 12_345;

/// The process's peak resident set (VmHWM) in bytes. The agent runs in this
/// process, so this covers the client and the agent together.
fn peak_rss() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("VmHWM:")).expect("VmHWM in /proc/self/status");
    line.split_whitespace().nth(1).unwrap().parse::<u64>().unwrap() * 1024
}
/// Reset the peak to the current RSS, where the kernel allows it, so the
/// baseline excludes whatever setup touched.
fn reset_peak() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}
/// Stream SIZE pseudo-random bytes (xorshift64) to `path` a MiB at a time,
/// hashing as they are written; the content is never held in memory.
fn generate(path: &Path, seed: u64) -> String {
    let mut file = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    let mut hasher = Sha256::new();
    let mut state = seed | 1;
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
fn source_bytes(path: &Path, start: u64, length: u64) -> Vec<u8> {
    let mut file = std::fs::File::open(path).unwrap();
    file.seek(SeekFrom::Start(start)).unwrap();
    let mut bytes = vec![0; length as usize];
    file.read_exact(&mut bytes).unwrap();
    bytes
}

// A file larger than 512 MiB streams through a digest-checked PUT and back
// through GET, whole and by an open-ended Range, on both transports, with
// bounded memory: the peak RSS of client and agent together grows by a small
// fraction of the file. Range and digest semantics belong to `files.rs`; this
// test owns only that nothing is held whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_file_streams_with_bounded_memory() {
    let started = Instant::now();
    let scratch = tempfile::tempdir().unwrap();
    let source = scratch.path().join("source");
    let digest = generate(&source, 0x5eed);
    eprintln!("generated {SIZE} bytes in {:?}", started.elapsed());
    for unix in [false, true] {
        transfer(unix, &source, &digest).await;
    }
}
async fn transfer(unix: bool, source: &Path, digest: &str) {
    let source = source.to_path_buf();
    let digest = digest.to_owned();
    let started = Instant::now();
    let h = harness(unix, "test-build").await;
    let destination = h.vessel().join("large");
    let generated = started.elapsed();
    reset_peak();
    let baseline = peak_rss();

    let options = FileOptions { sha256: Some(digest.clone()), ..FileOptions::default() };
    let written = h.client.write(&destination, tokio::fs::File::open(&source).await.unwrap(), &options).await.unwrap();
    assert_eq!(written, Written { sha256: digest.clone(), size: SIZE });
    assert_eq!(std::fs::metadata(&destination).unwrap().len(), SIZE);
    let put = started.elapsed();

    let (size, etag) = h.client.head(&destination).await.unwrap();
    assert_eq!(size, SIZE);
    let mut download = h.client.read(&destination).await.unwrap();
    assert_eq!((download.length, download.range, download.etag.as_str()), (SIZE, None, etag.as_str()));
    let mut hasher = Sha256::new();
    let (mut received, mut largest) = (0u64, 0usize);
    while let Some(chunk) = download.chunk().await.unwrap() {
        hasher.update(&chunk);
        received += chunk.len() as u64;
        largest = largest.max(chunk.len());
    }
    assert_eq!(received, SIZE);
    assert_eq!(format!("{:x}", hasher.finalize()), digest, "the GET returns the bytes that were PUT");
    let get = started.elapsed();

    // Open-ended to the end, streamed and compared chunk by chunk.
    let start = SIZE - 3 * MIB - 7;
    let mut download = h.client.read_range(&destination, start, None, None).await.unwrap();
    assert_eq!((download.length, download.range), (SIZE - start, Some((start, SIZE - 1, SIZE))));
    let mut at = start;
    while let Some(chunk) = download.chunk().await.unwrap() {
        assert!(chunk[..] == source_bytes(&source, at, chunk.len() as u64)[..], "open range at {at}");
        at += chunk.len() as u64;
    }
    assert_eq!(at, SIZE);
    let ranged = started.elapsed();

    let growth = peak_rss().saturating_sub(baseline);
    eprintln!(
        "unix={unix}: peak RSS growth {:.1} MiB over a {:.1} MiB baseline, largest chunk {largest} B; put {:?}, get {:?}, range {:?}",
        growth as f64 / MIB as f64,
        baseline as f64 / MIB as f64,
        put - generated,
        get - put,
        ranged - get,
    );
    assert!(growth < 64 * MIB, "peak RSS grew by {growth} bytes while streaming {SIZE}");
}

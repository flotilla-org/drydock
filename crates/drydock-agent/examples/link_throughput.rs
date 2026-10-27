//! Measure file transfer throughput through the real agent and client over a
//! shaped in-process link: a fixed one-way delay and a bandwidth cap in each
//! direction, carrying yamux like a provider relay. HTTP/2 flow-control
//! windows were sized from these numbers.
//!
//! `cargo run --release -p drydock-agent --example link_throughput -- RTT_MS MBIT MIB`
use drydock_agent::{Agent, Client, FileOptions};
use drydock_transport::{Limits, Transport};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// Forward bytes from `from` to `to`, each delayed by `delay` and paced to
/// `bytes_per_second`, without limiting how many are in flight.
fn shape(mut from: tokio::io::ReadHalf<DuplexStream>, mut to: tokio::io::WriteHalf<DuplexStream>, delay: Duration, bytes_per_second: f64) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    tokio::spawn(async move {
        let mut buffer = vec![0; 64 * 1024];
        let mut next = Instant::now();
        loop {
            let n = match from.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            next = next.max(Instant::now()) + Duration::from_secs_f64(n as f64 / bytes_per_second);
            tokio::time::sleep_until(next.into()).await;
            if tx.send((Instant::now() + delay, buffer[..n].to_vec())).is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some((due, bytes)) = rx.recv().await {
            tokio::time::sleep_until(due.into()).await;
            if to.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });
}
async fn link(rtt: Duration, bytes_per_second: f64) -> (Transport, Transport) {
    let (host, host_side) = tokio::io::duplex(1 << 20);
    let (guest, guest_side) = tokio::io::duplex(1 << 20);
    let (host_read, host_write) = tokio::io::split(host_side);
    let (guest_read, guest_write) = tokio::io::split(guest_side);
    shape(host_read, guest_write, rtt / 2, bytes_per_second);
    shape(guest_read, host_write, rtt / 2, bytes_per_second);
    let (a, b) = tokio::join!(
        Transport::yamux(Box::new(host), true, Limits::default()),
        Transport::yamux(Box::new(guest), false, Limits::default())
    );
    (a.unwrap(), b.unwrap())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<f64> = std::env::args().skip(1).map(|a| a.parse().expect("numeric argument")).collect();
    let [rtt_ms, mbit, mib] = args[..] else { panic!("usage: link_throughput RTT_MS MBIT MIB") };
    let dir = tempfile::tempdir()?;
    let (host, guest) = link(Duration::from_secs_f64(rtt_ms / 1000.0), mbit * 1e6 / 8.0).await;
    tokio::spawn(Agent::new(guest, "probe".into(), dir.path().join("agent")).run());
    let client = Client::connect(host, "probe").await?;
    let size = (mib * 1024.0 * 1024.0) as usize;
    let source = dir.path().join("source");
    std::fs::write(&source, vec![7u8; size])?;
    let started = Instant::now();
    client.write(&dir.path().join("uploaded"), tokio::fs::File::open(&source).await?, &FileOptions::default()).await?;
    let upload = started.elapsed();
    let started = Instant::now();
    let mut sink = tokio::io::sink();
    client.read(&dir.path().join("uploaded")).await?.copy_to(&mut sink).await?;
    let download = started.elapsed();
    let link = mbit / 8.0;
    let rate = |elapsed: Duration| mib * 1.048576 / elapsed.as_secs_f64();
    println!(
        "rtt {rtt_ms} ms, link {link:.1} MB/s, {mib} MiB: upload {:.1} MB/s ({:.0}% of link), download {:.1} MB/s ({:.0}% of link)",
        rate(upload),
        100.0 * rate(upload) / link,
        rate(download),
        100.0 * rate(download) / link
    );
    Ok(())
}

//! Stock-Ubuntu acceptance helper, built for the same architecture as the tools.
//! Reads hello from the running agent; does not add a diagnostic flag to it.
use drydock_agent::Client;
use drydock_transport::{Limits, Transport, native::UnixConnections};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::net::UnixListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    assert_eq!(args.len(), 2, "tools_probe SOCKET EXECUTABLE");
    let socket = PathBuf::from(&args[0]);
    let executable = PathBuf::from(&args[1]);
    let current = std::fs::read(&executable)?;
    let host = socket.parent().unwrap().join("host.sock");
    let listener = UnixListener::bind(&host)?;
    let connections = Arc::new(UnixConnections::new(listener, &socket));
    let client = Client::connect_current(
        || std::future::ready(Transport::native(connections.clone(), Limits::default())),
        &current,
        Duration::from_secs(30),
    )
    .await?;
    assert!(client.is_compatible(), "hello fingerprint differs from installed agent");
    // The provider starts the fixed binary alongside the base's own process.
    let mut found = false;
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        if std::fs::read_link(entry.path().join("exe")).ok().as_ref() == Some(&executable) {
            assert_ne!(entry.file_name(), "1");
            let argv = std::fs::read(entry.path().join("cmdline"))?;
            let mut fixed = executable.as_os_str().as_encoded_bytes().to_vec();
            fixed.push(0);
            assert_eq!(argv, fixed, "agent must have no extra flags");
            found = true;
        }
    }
    assert!(found, "agent process missing");
    println!("{}", serde_json::to_string(client.hello())?);
    drop(client);
    std::fs::remove_file(host)?;
    Ok(())
}

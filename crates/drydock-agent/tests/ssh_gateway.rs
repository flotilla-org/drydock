use drydock_agent::{Client, Endpoint, OutwardForward};
use drydock_transport::ssh;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::Command,
};
#[path = "../../drydock-transport/tests/support/sshd.rs"]
mod sshd;

// Actual process boundary: the shipped agent binary, started with only its
// fixed flags, behind an OpenSSH server that grants only local forwards, as
// Daytona's gateway does. Hello, exec and outward connections all travel on
// the one HTTP/2 connection through the local forward.
#[tokio::test]
async fn agent_serves_hello_and_outward_connections_through_a_local_forward() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("run/agent.sock");
    let mut agent = Command::new(env!("CARGO_BIN_EXE_drydock-agent")).arg("--socket").arg(&socket).kill_on_drop(true).spawn().unwrap();
    let (config, mut server) = sshd::start(dir.path(), &socket).await;
    let binary = std::fs::read(env!("CARGO_BIN_EXE_drydock-agent")).unwrap();
    let client = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match Client::connect_current(
                || ssh::connect(config.clone()),
                &drydock_agent::Platform::current(),
                &binary,
                Duration::from_secs(5),
            )
            .await
            {
                Ok(client) => return client,
                // The agent may not have bound its socket yet.
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await
    .unwrap();
    assert!(client.is_compatible());
    let mut output = client.exec(drydock_agent::Exec::new("/bin/sh", ["-c", "printf ready"])).await.unwrap();
    let mut stdout = Vec::new();
    while let Some(event) = output.next().await.unwrap() {
        if let drydock_agent::ExecEvent::Stdout(bytes) = event {
            stdout.extend(bytes);
        }
    }
    assert_eq!(stdout, b"ready");
    let target = dir.path().join("target");
    let target_listener = UnixListener::bind(&target).unwrap();
    let forward = OutwardForward { id: "service".into(), unix: dir.path().join("forward"), tcp: None };
    client.put_outward_forward(forward.clone(), Endpoint::Unix(target)).await.unwrap();
    for round in 0..3u8 {
        let mut guest = UnixStream::connect(&forward.unix).await.unwrap();
        guest.write_all(&[round; 4]).await.unwrap();
        let (mut host, _) = tokio::time::timeout(Duration::from_secs(5), target_listener.accept()).await.unwrap().unwrap();
        let mut received = [0; 4];
        host.read_exact(&mut received).await.unwrap();
        assert_eq!(received, [round; 4]);
        host.write_all(b"reply").await.unwrap();
        let mut reply = [0; 5];
        guest.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
    }
    drop(client);
    agent.kill().await.unwrap();
    server.kill().await.unwrap();
}

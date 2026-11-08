use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

// Actual process boundary: the shipped agent binary, reached through
// `--bridge` as Namespace's SSH exec channel runs it. The client keeps its
// side of the channel open while it reads the reply to the end, as the relay
// conformance check does; the bridge must still exit once the agent closes,
// or the channel, and the relay behind it, never ends.
#[tokio::test]
async fn bridge_exits_when_the_agent_closes_while_its_input_stays_open() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("run/agent.sock");
    let mut agent = Command::new(env!("CARGO_BIN_EXE_drydock-agent")).arg("--socket").arg(&socket).kill_on_drop(true).spawn().unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while tokio::net::UnixStream::connect(&socket).await.is_err() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let mut bridge = Command::new(env!("CARGO_BIN_EXE_drydock-agent"))
        .arg("--bridge")
        .arg("--socket")
        .arg(&socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = bridge.stdin.take().unwrap();
    input.write_all(b"GET /hello HTTP/1.1\r\nhost: agent\r\nconnection: close\r\n\r\n").await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), bridge.stdout.take().unwrap().read_to_end(&mut reply))
        .await
        .expect("the bridge's stdout must end once the agent closes")
        .unwrap();
    let reply = String::from_utf8_lossy(&reply);
    assert!(reply.starts_with("HTTP/1.1 200") && reply.contains("fingerprint"), "{reply}");
    let status = tokio::time::timeout(Duration::from_secs(10), bridge.wait()).await.unwrap().unwrap();
    assert!(status.success(), "{status}");
    drop(input);
    agent.kill().await.unwrap();
}

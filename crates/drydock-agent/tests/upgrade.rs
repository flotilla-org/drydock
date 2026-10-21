use drydock_agent::{Client, Configuration, Endpoint, Exec, ExecEvent, GuestForward};
use drydock_transport::{Limits, Transport};
use sha2::{Digest, Sha256};
use std::{os::unix::fs::PermissionsExt, path::Path, time::Duration};
use tokio::{net::UnixStream, process::Command};
async fn connect(socket: &Path, expected: &str) -> Client {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(stream) = UnixStream::connect(socket).await
                && let Ok(transport) = Transport::yamux(Box::new(stream), true, Limits::default()).await
                && let Ok(client) = Client::connect(transport, expected).await
            {
                return client;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap()
}
struct ReleaseOnDrop(std::path::PathBuf);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.0, []);
    }
}
// Actual process boundary: run an old ELF, push a distinct new ELF, re-exec in
// the same PID, reconnect, and verify the new fingerprint. No fake re-executor.
// A mismatched client refuses EVERY generation-specific operation. The launched
// child inherits the pushed env and writes after the original agent is gone.
#[tokio::test]
async fn binary_upgrade_preserves_children_and_gates_mismatched_client() {
    let dir = tempfile::tempdir().unwrap();
    let executable = dir.path().join("drydock-agent");
    let binary = std::fs::read(env!("CARGO_BIN_EXE_drydock-agent")).unwrap();
    let old = format!("{:x}", Sha256::digest(&binary));
    std::fs::write(&executable, &binary).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    let socket = dir.path().join("control");
    let mut child = Command::new(&executable).arg("--socket").arg(&socket).kill_on_drop(true).spawn().unwrap();
    let pid = child.id().unwrap();
    let client = connect(&socket, &old).await;
    assert!(client.is_compatible());
    client
        .configure(Configuration { environment: [("TOKEN".into(), "placeholder".into())].into(), ..Configuration::default() })
        .await
        .unwrap();
    let gate = dir.path().join("gate");
    let _release = ReleaseOnDrop(gate.clone());
    let marker = dir.path().join("survived");
    let child_pid_file = dir.path().join("child-pid");
    let guest_socket = dir.path().join("guest-forward");
    let endpoint = dir.path().join("host-endpoint");
    let _listener = tokio::net::UnixListener::bind(&endpoint).unwrap();
    client
        .add_guest_forward(GuestForward { id: "restart-forward".into(), unix: guest_socket.clone(), tcp: None }, Endpoint::Unix(endpoint))
        .await
        .unwrap();
    let mut output = client
        .exec(Exec {
            program: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                format!(
                    "echo $$ > '{}'; printf started; while test ! -f '{}'; do sleep 0.01; done; printf after; printf '%s' \"$TOKEN\" > '{}'",
                    child_pid_file.display(),
                    gate.display(),
                    marker.display()
                ),
            ],
            cwd: None,
        })
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), output.next()).await.unwrap().unwrap(),
        Some(ExecEvent::Stdout(b"started".to_vec()))
    );
    let launched_pid = std::fs::read_to_string(&child_pid_file).unwrap().trim().to_owned();
    drop(output);
    drop(client);
    let mut new_binary = binary.clone();
    new_binary.extend_from_slice(b"drydock upgrade contract test");
    let new = format!("{:x}", Sha256::digest(&new_binary));
    assert_ne!(old, new);
    let mismatch = connect(&socket, &new).await;
    assert_eq!(mismatch.hello().fingerprint, old);
    assert!(!mismatch.is_compatible());
    let file = dir.path().join("forbidden");
    assert!(mismatch.configure(Configuration::default()).await.is_err());
    assert!(mismatch.configuration().await.is_err());
    assert!(mismatch.exec(Exec { program: "/bin/true".into(), args: vec![], cwd: None }).await.is_err());
    assert!(mismatch.write(file.clone(), vec![], false).await.is_err());
    assert!(mismatch.read(file.clone()).await.is_err());
    assert!(mismatch.flush(file.clone()).await.is_err());
    assert!(mismatch.forward("x").await.is_err());
    assert!(mismatch.add_host_forward("x".into(), Endpoint::Unix(file.clone())).await.is_err());
    assert!(mismatch.remove_host_forward("x").await.is_err());
    assert!(
        mismatch
            .add_guest_forward(GuestForward { id: "x".into(), unix: file.clone(), tcp: None }, Endpoint::Unix(file.clone()))
            .await
            .is_err()
    );
    assert!(mismatch.remove_guest_forward("x").await.is_err());
    assert!(mismatch.register_host_endpoint("x".into(), Endpoint::Unix(file.clone())).is_err());
    assert!(!file.exists());
    mismatch.upgrade(new_binary).await.unwrap();
    drop(mismatch);
    let upgraded = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let client = connect(&socket, &new).await;
            if client.is_compatible() {
                break client;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(child.id(), Some(pid));
    assert!(child.try_wait().unwrap().is_none());
    assert_eq!(upgraded.hello().fingerprint, new);
    assert!(!guest_socket.exists(), "old forward paths must be removed before re-exec");
    assert_eq!(upgraded.configuration().await.unwrap(), Configuration::default());
    std::fs::write(gate, []).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if std::fs::read(&marker).ok().as_deref() == Some(b"placeholder") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    #[cfg(target_os = "linux")]
    tokio::time::timeout(Duration::from_secs(5), async {
        while std::path::Path::new(&format!("/proc/{launched_pid}")).exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("inherited child must be reaped after exiting");
    // An executable rejected by exec(2) must restore and re-run the previous
    // generation, rather than leaving a vessel without its control agent.
    upgraded.upgrade(b"not an executable".to_vec()).await.unwrap();
    drop(upgraded);
    tokio::time::timeout(Duration::from_secs(10), async {
        while executable.with_extension("prev").exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("failed exec must restore the previous binary");
    let upgraded = connect(&socket, &new).await;
    assert!(upgraded.is_compatible());
    let crash_socket = dir.path().join("crash-forward");
    let crash_target = dir.path().join("crash-target");
    let _crash_listener = tokio::net::UnixListener::bind(&crash_target).unwrap();
    upgraded
        .add_guest_forward(GuestForward { id: "crash".into(), unix: crash_socket.clone(), tcp: None }, Endpoint::Unix(crash_target))
        .await
        .unwrap();
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    assert!(crash_socket.exists(), "SIGKILL leaves a stale socket to recover");
    drop(upgraded);
    let mut replacement = Command::new(&executable).arg("--socket").arg(&socket).kill_on_drop(true).spawn().unwrap();
    let recovered = connect(&socket, &new).await;
    let recovered_target = dir.path().join("recovered-target");
    let _recovered_listener = tokio::net::UnixListener::bind(&recovered_target).unwrap();
    recovered
        .add_guest_forward(GuestForward { id: "crash".into(), unix: crash_socket, tcp: None }, Endpoint::Unix(recovered_target))
        .await
        .unwrap();
    replacement.kill().await.unwrap();
    replacement.wait().await.unwrap();
}

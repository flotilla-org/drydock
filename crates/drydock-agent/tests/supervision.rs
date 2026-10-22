//! Real process boundary: exercise the baked executable without guest utilities.
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

struct ProcessGroup(Child);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        // SAFETY: this child was created as leader of a dedicated process group.
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGKILL);
        }
        let _ = self.0.wait();
    }
}
fn supervisor(socket: &Path) -> ProcessGroup {
    use std::os::unix::process::CommandExt;
    ProcessGroup(
        Command::new(env!("CARGO_BIN_EXE_drydock-agent"))
            .arg("--supervisor")
            .arg("--socket")
            .arg(socket)
            .env("PATH", "/nonexistent")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}
fn agents(socket: &Path) -> Vec<i32> {
    let suffix = format!("--socket\0{}\0", socket.display());
    std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|entry| {
            let pid = entry.file_name().to_str()?.parse().ok()?;
            let command = std::fs::read(entry.path().join("cmdline")).ok()?;
            let command = String::from_utf8_lossy(&command);
            (command.ends_with(&suffix) && !command.contains("--supervisor") && !command.contains("--supervise\0")).then_some(pid)
        })
        .collect()
}
async fn hello(socket: &Path) -> String {
    use drydock_transport::{Limits, Transport};
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let result = async {
            let stream = tokio::net::UnixStream::connect(socket).await?;
            let transport = Transport::yamux(Box::new(stream), true, Limits::default()).await?;
            drydock_agent::Client::connect(transport, "hello-only").await
        };
        if let Ok(Ok(client)) = tokio::time::timeout(Duration::from_secs(2), result).await {
            return client.hello().fingerprint.clone();
        }
        assert!(tokio::time::Instant::now() < deadline, "agent did not say hello");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// ADR 0070: concurrent bootstraps leave one agent; crashes and provider restarts
// bring it back without Python/flock or changes to PID 1. Exercise real hello,
// including a stale socket left by SIGKILL, after every lifecycle transition.
#[tokio::test]
async fn singleton_recovers_after_crash_and_start_resume() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let mut first = supervisor(&socket);
    let mut duplicate = supervisor(&socket);
    hello(&socket).await;
    // Either competing supervisor may win; the loser must exit successfully.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let loser = loop {
        if let Some(status) = first.0.try_wait().unwrap() {
            break status;
        }
        if let Some(status) = duplicate.0.try_wait().unwrap() {
            break status;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert!(loser.success(), "the competing supervisor must exit successfully");
    let before = agents(&socket);
    assert_eq!(before.len(), 1);
    // SAFETY: PID belongs to the agent in this test's private socket directory.
    assert_eq!(unsafe { libc::kill(before[0], libc::SIGKILL) }, 0);
    hello(&socket).await;
    let after = agents(&socket);
    assert_eq!(after.len(), 1);
    assert_ne!(before, after);
    drop(first);
    drop(duplicate);
    // Simulate provider stop/start and resume: both supervisor and child die,
    // while their filesystem and lock inode persist.
    for _ in 0..2 {
        let running = supervisor(&socket);
        hello(&socket).await;
        assert_eq!(agents(&socket).len(), 1);
        drop(running);
    }
}

// The public bootstrap detaches from toolbox exec even with no guest PATH.
// Two invocations must return and leave one supervisor and one helloing agent.
#[tokio::test]
async fn public_bootstrap_detaches_without_guest_packages() {
    struct Detached(std::path::PathBuf);
    impl Drop for Detached {
        fn drop(&mut self) {
            for entry in std::fs::read_dir("/proc").unwrap().flatten() {
                let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
                    continue;
                };
                let Ok(command) = std::fs::read(entry.path().join("cmdline")) else {
                    continue;
                };
                let command = String::from_utf8_lossy(&command);
                if command.contains("--supervisor\0") && command.ends_with(&format!("{}\0", self.0.display())) {
                    // SAFETY: supervisor uses setsid; its child shares this group.
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                    }
                }
            }
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let _cleanup = Detached(socket.clone());
    let invoke = || async {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_drydock-agent"))
            .args(["--supervise", "--socket"])
            .arg(&socket)
            .env("PATH", "/nonexistent")
            .status()
            .await
            .unwrap()
    };
    let (first, second) = tokio::join!(invoke(), invoke());
    assert!(first.success() && second.success());
    hello(&socket).await;
    assert_eq!(agents(&socket).len(), 1);
}

// A lagging tools binary upgrades through the normal handshake. Supervision
// then restarts the installed current path, preserving the upgraded generation.
#[tokio::test]
async fn supervised_tools_upgrade_and_restart_current_agent() {
    use drydock_transport::{Limits, Transport};
    use sha2::{Digest, Sha256};
    use std::os::unix::{fs::PermissionsExt, process::CommandExt};
    let directory = tempfile::tempdir().unwrap();
    let installed = directory.path().join("drydock-agent");
    let current = std::fs::read(env!("CARGO_BIN_EXE_drydock-agent")).unwrap();
    let mut old = current.clone();
    old.extend_from_slice(b"older tools generation");
    std::fs::write(&installed, old).unwrap();
    std::fs::set_permissions(&installed, std::fs::Permissions::from_mode(0o755)).unwrap();
    let socket = directory.path().join("agent.sock");
    let _supervisor = ProcessGroup(
        Command::new(installed)
            .args(["--supervisor", "--socket"])
            .arg(&socket)
            .env("PATH", "/nonexistent")
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    let desired = format!("{:x}", Sha256::digest(&current));
    assert_ne!(hello(&socket).await, desired);
    let client = drydock_agent::Client::connect_current(
        || async {
            let stream = tokio::net::UnixStream::connect(&socket).await?;
            Transport::yamux(Box::new(stream), true, Limits::default()).await
        },
        &current,
        Duration::from_secs(15),
    )
    .await
    .unwrap();
    assert_eq!(client.hello().fingerprint, desired);
    drop(client);
    let pid = agents(&socket)[0];
    // SAFETY: PID is the child belonging to this test's private socket.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
    assert_eq!(hello(&socket).await, desired);
}

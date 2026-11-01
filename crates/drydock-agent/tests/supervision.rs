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
// A concurrent test's fork can briefly hold the descriptor that wrote an
// executable (until its exec closes it), so exec fails with ETXTBSY; retry.
fn spawn(command: &mut Command) -> Child {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match command.spawn() {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy && std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10))
            }
            result => return result.unwrap(),
        }
    }
}
// Every process's PID and space-joined argv, from ps rather than /proc so the
// listing (and cleanup that depends on it) also works off Linux.
fn processes() -> Vec<(i32, String)> {
    let output = Command::new("ps").args(["-axww", "-o", "pid=,command="]).output().expect("ps lists processes");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let (pid, command) = line.trim_start().split_once(' ')?;
            Some((pid.parse().ok()?, command.trim().to_owned()))
        })
        .collect()
}
fn agents(socket: &Path) -> Vec<i32> {
    let suffix = format!("--socket {}", socket.display());
    processes()
        .into_iter()
        .filter(|(_, command)| command.ends_with(&suffix) && !command.contains("--supervisor ") && !command.contains("--supervise "))
        .map(|(pid, _)| pid)
        .collect()
}
async fn hello(socket: &Path) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let result = async {
            let stream = tokio::net::UnixStream::connect(socket).await?;
            drydock_agent::Client::connect(Box::new(stream), "hello-only").await
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
    // Runs even when an assertion fails, so detached supervisors never outlive
    // the test and hold its output pipe open.
    struct Detached(std::path::PathBuf);
    impl Drop for Detached {
        fn drop(&mut self) {
            let suffix = format!("--supervisor --socket {}", self.0.display());
            for (pid, _) in processes().into_iter().filter(|(_, command)| command.ends_with(&suffix)) {
                // SAFETY: supervisor uses setsid; its child shares this group.
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
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
    let _supervisor = ProcessGroup(spawn(
        Command::new(installed).args(["--supervisor", "--socket"]).arg(&socket).env("PATH", "/nonexistent").process_group(0),
    ));
    let desired = format!("{:x}", Sha256::digest(&current));
    assert_ne!(hello(&socket).await, desired);
    let client = drydock_agent::Client::connect_current(
        || async { Ok(Box::new(tokio::net::UnixStream::connect(&socket).await?) as drydock_transport::ByteStream) },
        &drydock_agent::Platform::current(),
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

// Killing only the supervisor leaves an orphan agent. Bootstrap must preserve
// that live agent and its socket; once it exits, the new supervisor recovers it.
#[tokio::test]
async fn bootstrap_beside_orphan_preserves_live_socket_and_recovers_after_exit() {
    use std::os::unix::{fs::MetadataExt, process::CommandExt};
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let mut original = supervisor(&socket);
    let fingerprint = hello(&socket).await;
    let orphan = agents(&socket);
    assert_eq!(orphan.len(), 1);
    let inode = std::fs::metadata(&socket).unwrap().ino();
    original.0.kill().unwrap();
    original.0.wait().unwrap();

    let log_path = directory.path().join("replacement.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let _replacement = ProcessGroup(
        Command::new(env!("CARGO_BIN_EXE_drydock-agent"))
            .args(["--supervisor", "--socket"])
            .arg(&socket)
            .env("PATH", "/nonexistent")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            // Observe a real duplicate-agent startup refusal and its exit,
            // rather than passing before the new supervisor attempts startup.
            if std::fs::read_to_string(&log_path).unwrap().contains("already in use") && agents(&socket) == orphan {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("duplicate agent must refuse the orphan's listening socket");
    assert_eq!(std::fs::metadata(&socket).unwrap().ino(), inode);
    assert_eq!(hello(&socket).await, fingerprint);
    assert_eq!(agents(&socket), orphan);

    // SAFETY: this is the orphan belonging to the private test socket.
    assert_eq!(unsafe { libc::kill(orphan[0], libc::SIGKILL) }, 0);
    assert_eq!(hello(&socket).await, fingerprint);
    let recovered = agents(&socket);
    assert_eq!(recovered.len(), 1);
    assert_ne!(recovered, orphan);
}

// Vessels on one host share a store (`--supervise --store DIR --socket PATH`).
// Every agent the supervisor starts, a restart included, keeps that store, and
// each still ends its argv with `--socket PATH`, as hosts find them by it.
#[tokio::test]
async fn supervised_agents_keep_the_named_store_across_restarts() {
    use sha2::{Digest, Sha256};
    use std::os::unix::process::CommandExt;
    let directory = tempfile::tempdir().unwrap();
    let (socket, store) = (directory.path().join("run/agent.sock"), directory.path().join("shared/store"));
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let _supervisor = ProcessGroup(spawn(
        Command::new(env!("CARGO_BIN_EXE_drydock-agent"))
            .arg("--supervisor")
            .arg("--store")
            .arg(&store)
            .arg("--socket")
            .arg(&socket)
            .env("PATH", "/nonexistent")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    ));
    for round in 0..2u8 {
        hello(&socket).await;
        let stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let client = drydock_agent::Client::connect(Box::new(stream), "any").await.unwrap();
        let content = vec![round; 4096];
        let digest = format!("{:x}", Sha256::digest(&content));
        client.upload(&digest, content.len() as u64, std::io::Cursor::new(content)).await.unwrap();
        assert!(store.join("blobs").join(&digest).is_file(), "round {round}: the upload lands in the named store");
        assert!(!socket.parent().unwrap().join("drydock-agent.store").exists());
        drop(client);
        let agents = agents(&socket);
        assert_eq!(agents.len(), 1, "round {round}");
        // SAFETY: PID is the child belonging to this test's private socket.
        assert_eq!(unsafe { libc::kill(agents[0], libc::SIGKILL) }, 0);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// Options other than `--store`, or a socket that is not last, are refused.
#[test]
fn supervision_refuses_options_it_would_not_pass_on() {
    for args in [&["--socket", "/s", "--store", "/d"][..], &["--store", "/d"], &["--idle", "1", "--socket", "/s"]] {
        let status = Command::new(env!("CARGO_BIN_EXE_drydock-agent"))
            .arg("--supervise")
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success(), "{args:?}");
    }
}

// `--collect` runs one collection and reports it as JSON: over a store no
// agent made yet it removes nothing, and bad options are refused.
#[test]
fn collect_reports_what_it_removed() {
    let directory = tempfile::tempdir().unwrap();
    let collect = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_drydock-agent")).arg("--collect").args(args).stdin(Stdio::null()).output().unwrap()
    };
    let store = directory.path().join("store");
    std::fs::create_dir_all(store.join("blobs")).unwrap();
    std::fs::write(store.join("blobs").join("a".repeat(64)), b"abandoned").unwrap();
    for (root, removed) in [(directory.path().join("absent"), 0), (store, 1)] {
        let output = collect(&["--store", root.to_str().unwrap(), "--release", "/run/v/a/agent.sock", "--idle", "0"]);
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let collected: drydock_agent::Collected = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(collected.blobs.len(), removed, "{collected:?}");
    }
    for args in [&[][..], &["--store"], &["--store", "/s", "--idle", "soon"], &["--store", "/s", "--holder", "x"]] {
        assert!(!collect(args).status.success(), "{args:?}");
    }
}

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

// #4087: a supervisor passes `--store` and `--holder` on to its agent, which
// keeps what it is given in that shared store and records its links for
// that holder; the agent's argv still ends with its socket, as teardown
// matches it. Once the holder is gone and the agents have stopped,
// `--collect` removes the entry only that holder linked.
#[tokio::test]
async fn a_supervised_agent_shares_the_named_store_and_collect_empties_it() {
    use sha2::{Digest, Sha256};
    use std::os::unix::process::CommandExt;
    let directory = tempfile::tempdir().unwrap();
    let (socket, store, holder) =
        (directory.path().join("run/agent.sock"), directory.path().join("store"), directory.path().join("holder"));
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    std::fs::create_dir(&holder).unwrap();
    let supervisor = ProcessGroup(spawn(
        Command::new(env!("CARGO_BIN_EXE_drydock-agent"))
            .arg("--supervisor")
            .arg("--store")
            .arg(&store)
            .arg("--holder")
            .arg(&holder)
            .arg("--socket")
            .arg(&socket)
            .env("PATH", "/nonexistent")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    ));
    let fingerprint = hello(&socket).await;
    assert_eq!(agents(&socket).len(), 1);
    let client =
        drydock_agent::Client::connect(Box::new(tokio::net::UnixStream::connect(&socket).await.unwrap()), fingerprint).await.unwrap();
    let tool = b"#!/bin/sh\necho shared\n".to_vec();
    let digest = format!("{:x}", Sha256::digest(&tool));
    let request =
        drydock_agent::Fetch { sources: vec![drydock_agent::ArtifactSource::Push], unpack: drydock_agent::Unpack::File { mode: 0o555 } };
    client.fetch_artifact_or_push(&digest, &request, tool.len() as u64, std::io::Cursor::new(tool)).await.unwrap();
    let link = directory.path().join("home/tool");
    let options = drydock_agent::FileOptions { parents: true, ..Default::default() };
    client.link_artifact(&link, &digest, Path::new(""), &options).await.unwrap();
    assert!(store.join("artifacts").join(&digest).exists(), "the entry is in the named store");
    drop((client, supervisor));

    std::fs::remove_dir(&holder).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_drydock-agent"))
        .arg("--collect")
        .arg("--store")
        .arg(&store)
        .args(["--grace", "0"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("removed 1 entries and 0 blobs"), "{output:?}");
    assert!(!store.join("artifacts").join(&digest).exists());
}

// `--collect` and `--supervise` refuse malformed options, saying which part
// was wrong, and remove nothing.
#[test]
fn malformed_store_options_are_refused_with_the_reason() {
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_drydock-agent")).args(args).output().unwrap();
        assert!(!output.status.success(), "{args:?} was accepted");
        String::from_utf8_lossy(&output.stderr).into_owned()
    };
    assert!(run(&["--collect"]).contains("--store is required"));
    assert!(run(&["--collect", "--store"]).contains("--store requires a directory"));
    assert!(run(&["--collect", "--store", "/nonexistent", "--grace", "soon"]).contains("--grace soon is not a number of seconds"));
    assert!(run(&["--collect", "--store", "/nonexistent", "--holder", "/h"]).contains("unknown option --holder"));
    assert!(run(&["--supervise", "--store", "--socket", "/tmp/x.sock"]).contains("--store requires a directory"));
    assert!(run(&["--supervise", "--socket", "/tmp/x.sock", "--store", "/s"]).contains("--socket PATH must come last"));
    assert!(run(&["--supervise", "--store", "--holder", "--socket", "/tmp/x.sock"]).contains("--store requires a directory"));
    assert!(run(&["--supervise", "--vsock-port", "1", "--socket", "/tmp/x.sock"]).contains("unknown option --vsock-port"));
}

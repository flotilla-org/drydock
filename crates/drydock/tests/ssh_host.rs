//! drydockd with an `ssh_host` instance against a loopback sshd.
#![cfg(target_os = "linux")]
#[path = "../../drydock-transport/tests/support/sshd.rs"]
mod sshd;
use std::{path::Path, time::Duration};

fn parent(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(") ")?.1.split(' ').nth(1)?.parse().ok()
}
fn running(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .is_ok_and(|stat| stat.rsplit_once(") ").is_some_and(|(_, rest)| !rest.starts_with('Z')))
}
fn descendants(root: u32) -> Vec<(u32, String)> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|name| name.parse().ok()) else { continue };
        let mut ancestor = pid;
        while let Some(next) = parent(ancestor).filter(|&next| next > 1) {
            if next == root {
                let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
                found.push((pid, comm.trim().to_owned()));
                break;
            }
            ancestor = next;
        }
    }
    found
}
/// Kills what drydockd started if the test fails while drydockd still runs:
/// `kill_on_drop` kills drydockd alone, the very case under test.
struct Reap(u32);
impl Drop for Reap {
    fn drop(&mut self) {
        for (pid, _) in descendants(self.0) {
            unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        }
    }
}

// Killed outright, drydockd runs no cleanup of its own; its host and the SSH
// session to the machine must still end with it.
#[tokio::test]
async fn ssh_sessions_end_when_drydockd_is_killed() {
    let dir = tempfile::tempdir().unwrap();
    let (ssh, _sshd) = sshd::start(dir.path(), Path::new("/unused")).await;
    let config = dir.path().join("drydock.toml");
    std::fs::write(
        &config,
        format!(
            "[providers.machine]\nmodule = \"ssh_host\"\nsettings = {{ address = {:?}, port = {}, user = {:?}, host_key = {:?}, identity_file = {:?} }}\n",
            ssh.host,
            ssh.port,
            ssh.user,
            ssh.host_key,
            ssh.identity_file.to_str().unwrap()
        ),
    )
    .unwrap();
    let host = Path::new(env!("CARGO_BIN_EXE_drydockd")).with_file_name("drydock-host");
    assert!(host.is_file(), "build drydock-host first: cargo test --workspace builds it");
    let socket = dir.path().join("run/drydock.sock");
    let mut drydockd = tokio::process::Command::new(env!("CARGO_BIN_EXE_drydockd"))
        .arg("--config")
        .arg(&config)
        .arg("--socket")
        .arg(&socket)
        .env("DRYDOCK_HOST_BIN", &host)
        .env_remove("DRYDOCK_TYPESCRIPT_HOST_BIN")
        .env_remove("DRYDOCK_PYTHON_HOST_BIN")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = drydockd.id().unwrap();
    let _reap = Reap(pid);
    // Readiness is known once the machine has answered over the session.
    let mut last = String::new();
    let ready = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let providers = tokio::process::Command::new(env!("CARGO_BIN_EXE_drydock"))
                .arg("--config")
                .arg(&config)
                .arg("--socket")
                .arg(&socket)
                .env("DRYDOCK_DAEMON_BIN", "/not-installed/drydockd")
                .arg("providers")
                .output()
                .await
                .unwrap();
            last = format!("{}{}", String::from_utf8_lossy(&providers.stdout), String::from_utf8_lossy(&providers.stderr));
            let providers: serde_json::Value = serde_json::from_slice(&providers.stdout).unwrap_or_default();
            if providers[0]["readiness"]["status"].as_str().is_some_and(|status| status != "unknown") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(ready.is_ok(), "drydockd never heard from the machine; `drydock providers` last said: {last}");
    let started = descendants(pid);
    assert!(started.iter().any(|(_, comm)| comm == "ssh"), "no SSH session: {started:?}");
    drydockd.start_kill().unwrap();
    drydockd.wait().await.unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        while started.iter().any(|&(pid, _)| running(pid)) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let left: Vec<_> = started.iter().filter(|&&(pid, _)| running(pid)).collect();
    for &&(pid, _) in &left {
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
    assert!(ended.is_ok(), "still running after drydockd was killed: {left:?}");
}

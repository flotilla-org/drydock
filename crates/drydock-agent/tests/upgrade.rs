mod support;
use drydock_agent::{Client, Configuration, Endpoint, ErrorKind, Exec, ExecEvent, FileOptions, InwardForward, OutwardForward, Platform};
use std::{os::unix::fs::PermissionsExt, time::Duration};
use support::*;
use tokio::process::Command;
/// A Linux platform whose build the test process cannot be running.
fn foreign() -> Platform {
    let current = Platform::current();
    Platform::new("linux", if current.os == "linux" && current.architecture == "amd64" { "arm64" } else { "amd64" })
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
// child inherits the pushed env and keeps running after the original agent is
// gone; it lost its output reader, so it writes only to a file afterwards.
#[tokio::test]
async fn binary_upgrade_preserves_children_and_gates_mismatched_client() {
    let dir = tempfile::tempdir().unwrap();
    // Match the tools layer's installation layout, leaving room beside the
    // executable for .prev, .upgrade and .probation during upgrade/rollback.
    let install_dir = dir.path().join("opt/drydock");
    std::fs::create_dir_all(&install_dir).unwrap();
    let binary = agent_binary();
    let executable = install(&install_dir.join("drydock-agent"), &binary);
    let old = sha256(&binary);
    let socket = dir.path().join("control");
    let mut child = start_agent(&executable, &socket);
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
        .put_outward_forward(
            OutwardForward { id: "restart-forward".into(), unix: guest_socket.clone(), tcp: None },
            Endpoint::Unix(endpoint),
        )
        .await
        .unwrap();
    let mut output = client
        .exec(Exec::new(
            "/bin/sh",
            [
                "-c".to_owned(),
                format!(
                    "echo $$ > '{}'; printf started; while test ! -f '{}'; do sleep 0.01; done; printf '%s' \"$TOKEN\" > '{}'",
                    child_pid_file.display(),
                    gate.display(),
                    marker.display()
                ),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), output.next()).await.unwrap().unwrap(),
        Some(ExecEvent::Stdout(bytes::Bytes::from_static(b"started")))
    );
    let launched_pid = std::fs::read_to_string(&child_pid_file).unwrap().trim().to_owned();
    drop(output);
    drop(client);
    let mut new_binary = binary.clone();
    new_binary.extend_from_slice(b"drydock upgrade contract test");
    let new = sha256(&new_binary);
    assert_ne!(old, new);
    let mismatch = connect(&socket, &new).await;
    assert_eq!(mismatch.hello().fingerprint, old);
    assert!(!mismatch.is_compatible());
    let file = dir.path().join("forbidden");
    assert_mismatch(mismatch.configure(Configuration::default()).await);
    assert_mismatch(mismatch.configuration().await);
    assert_mismatch(mismatch.exec(Exec::new("/bin/true", [""; 0])).await);
    assert_mismatch(mismatch.write_bytes(&file, vec![], &FileOptions::default()).await);
    assert_mismatch(mismatch.read(&file).await);
    assert_mismatch(mismatch.open_inward("x").await);
    assert_mismatch(mismatch.put_inward_forward(InwardForward { id: "x".into(), endpoint: Endpoint::Unix(file.clone()) }).await);
    assert_mismatch(mismatch.remove_inward_forward("x").await);
    assert_mismatch(
        mismatch.put_outward_forward(OutwardForward { id: "x".into(), unix: file.clone(), tcp: None }, Endpoint::Unix(file.clone())).await,
    );
    assert_mismatch(mismatch.remove_outward_forward("x").await);
    assert_mismatch(mismatch.register_host_endpoint("x".into(), Endpoint::Unix(file.clone())));
    assert!(!file.exists());
    mismatch.upgrade(new_binary).await.unwrap();
    drop(mismatch);
    let upgraded = connect_compatible(&socket, &new).await;
    assert_eq!(child.id(), Some(pid));
    assert!(child.try_wait().unwrap().is_none());
    assert_eq!(upgraded.hello().fingerprint, new);
    upgraded.confirm_upgrade().await.unwrap();
    assert_eq!(std::fs::read(executable.with_extension("prev")).unwrap(), binary);
    assert!(!guest_socket.exists(), "old forward paths must be removed before re-exec");
    assert_eq!(upgraded.configuration().await.unwrap().value, Configuration::default());
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
        .put_outward_forward(OutwardForward { id: "crash".into(), unix: crash_socket.clone(), tcp: None }, Endpoint::Unix(crash_target))
        .await
        .unwrap();
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    assert!(crash_socket.exists(), "SIGKILL leaves a stale socket to recover");
    drop(upgraded);
    let mut replacement = start_agent(&executable, &socket);
    let recovered = connect(&socket, &new).await;
    let recovered_target = dir.path().join("recovered-target");
    let _recovered_listener = tokio::net::UnixListener::bind(&recovered_target).unwrap();
    recovered
        .put_outward_forward(OutwardForward { id: "crash".into(), unix: crash_socket, tcp: None }, Endpoint::Unix(recovered_target))
        .await
        .unwrap();
    replacement.kill().await.unwrap();
    replacement.wait().await.unwrap();
}

// Exercise Tokio's deferred write error in a separate process, without changing
// limits or signal handling in the parallel test runner.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn failed_file_write_never_publishes_a_partial_file_or_upgrade() {
    let dir = tempfile::tempdir().unwrap();
    let binary = agent_binary();
    let fingerprint = sha256(&binary);
    let executable = install(&dir.path().join("agent"), &binary);
    let path = dir.path().join("destination");
    std::fs::write(&path, b"original").unwrap();
    let socket = dir.path().join("control");
    let mut command = Command::new(&executable);
    command.arg("--socket").arg(&socket);
    // SAFETY: the child changes only its own kernel limits and signal disposition.
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit { rlim_cur: 4096, rlim_max: 4096 };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            Ok(())
        });
    }
    let mut child = start(&mut command);
    let client = connect(&socket, &fingerprint).await;
    let error = client.write_bytes(&path, vec![7; 8192], &FileOptions::default()).await.expect_err("failed write must be reported");
    assert_eq!(error.kind(), std::io::ErrorKind::FileTooLarge);
    let detail = agent_error(&error);
    assert_eq!(detail.operation, "file.write");
    assert_eq!(detail.subject, path.display().to_string());
    assert_eq!(std::fs::read(&path).unwrap(), b"original");
    let error = client.upgrade(vec![7; 8192]).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::FileTooLarge, "{error}");
    assert!(error.to_string().contains("upload.append"), "{error}");
    assert!(!executable.with_extension("upgrade").exists());
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

// A candidate whose exec succeeds but exits before confirmation must not strand
// the provider's fixed entry point. The next ordinary start restores the old image.
#[tokio::test]
async fn candidate_that_dies_before_confirmation_rolls_back_on_next_start() {
    let dir = tempfile::tempdir().unwrap();
    let binary = agent_binary();
    let fingerprint = sha256(&binary);
    let executable = install(&dir.path().join("agent.upgrade"), &binary);
    let run = dir.path().join("run");
    std::fs::create_dir(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o755)).unwrap();
    let socket = run.join("control");
    let mut child = start_agent(&executable, &socket);
    let client = connect(&socket, &fingerprint).await;
    assert_eq!(std::fs::metadata(&run).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777, 0o600);
    client.upgrade(b"#!/bin/sh\nexit 42\n".to_vec()).await.unwrap();
    drop(client);
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait()).await.unwrap().unwrap();
    assert_eq!(status.code(), Some(42));
    assert!(dir.path().join("agent.upgrade.probation").exists());
    assert!(dir.path().join("agent.upgrade.prev").exists());
    let mut replacement = start_agent(&executable, &socket);
    let recovered = connect(&socket, &fingerprint).await;
    assert!(recovered.is_compatible());
    assert_eq!(std::fs::read(&executable).unwrap(), binary);
    assert!(!dir.path().join("agent.upgrade.probation").exists());
    assert!(!dir.path().join("agent.upgrade.upgrade").exists());
    replacement.kill().await.unwrap();
    replacement.wait().await.unwrap();
}

// Startup failures identify the directory the provider must fix. This is thin
// binary composition glue; one actual subprocess exercises the diagnostic.
#[tokio::test]
async fn startup_directory_failure_names_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path().join("absent-parent/run");
    let output = Command::new(env!("CARGO_BIN_EXE_drydock-agent")).arg("--socket").arg(run.join("agent.sock")).output().await.unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("socket.directory"), "{error}");
    assert!(error.contains(run.to_str().unwrap()), "{error}");
    assert!(error.contains("NotFound"), "{error}");
}

fn assert_mismatch<T>(result: std::io::Result<T>) {
    let error = match result {
        Ok(_) => panic!("mismatched generation unexpectedly allowed"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert!(error.to_string().contains("agent fingerprint mismatch"), "{error}");
}

// A checked-in tools pin can predate the host. The normal handshake must push
// the current binary on mismatched hello, re-exec in place, and return a usable
// client only after the new hello. A matching pin must not rewrite rollback.
// The host holds a build per guest platform; the guest's hello picks the one
// pushed. The foreign platform's "build" exits at once, so pushing it fails.
#[tokio::test]
async fn older_tools_pin_is_upgraded_during_connect() {
    let dir = tempfile::tempdir().unwrap();
    let install_dir = dir.path().join("opt/drydock");
    std::fs::create_dir_all(&install_dir).unwrap();
    let current = agent_binary();
    let mut older = current.clone();
    older.extend_from_slice(b"older tools pin");
    let executable = install(&install_dir.join("drydock-agent"), &older);
    let socket = dir.path().join("agent.sock");
    let mut child = start_agent(&executable, &socket);
    let desired = sha256(&current);
    let initial = connect(&socket, &desired).await;
    assert!(!initial.is_compatible());
    drop(initial);
    let pid = child.id();
    for _ in 0..2 {
        let client = Client::connect_current(|| dial(&socket), &Platform::current(), &current, Duration::from_secs(10)).await.unwrap();
        assert!(client.is_compatible());
        assert_eq!(client.hello().fingerprint, desired);
        client.configure(Configuration::default()).await.unwrap();
        assert_eq!(child.id(), pid);
        assert!(child.try_wait().unwrap().is_none());
        assert_eq!(std::fs::read(&executable).unwrap(), current);
        assert_eq!(std::fs::read(executable.with_extension("prev")).unwrap(), older);
    }
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

// If the candidate is rejected and the old binary rolls back, the bounded
// handshake must explain which fingerprint kept answering hello, not merely
// report that the deadline expired. This uses the real loader/rollback process.
#[tokio::test]
async fn upgrade_timeout_reports_the_last_hello_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    let old = agent_binary();
    let fingerprint = sha256(&old);
    let executable = install(&dir.path().join("drydock-agent"), &old);
    let socket = dir.path().join("agent.sock");
    let mut child = start_agent(&executable, &socket);
    drop(connect(&socket, &fingerprint).await);
    let error = Client::connect_current(|| dial(&socket), &Platform::current(), b"not an executable", Duration::from_secs(3))
        .await
        .err()
        .expect("a rejected candidate cannot become the current agent");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(error.to_string().contains(&format!("last hello fingerprint {fingerprint}")), "{error}");
    assert_eq!(std::fs::read(&executable).unwrap(), old);
    assert!(child.try_wait().unwrap().is_none());
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

// Provider transport failures during reconnect must survive in the timeout
// diagnostic. Only the provider connection boundary is unavailable here; the
// real guest upgrades successfully and is independently reachable afterwards.
#[tokio::test]
async fn upgrade_timeout_reports_the_last_transport_error() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let old = agent_binary();
    let old_fingerprint = sha256(&old);
    let executable = install(&dir.path().join("drydock-agent"), &old);
    let socket = dir.path().join("agent.sock");
    let mut child = start_agent(&executable, &socket);
    drop(connect(&socket, &old_fingerprint).await);
    let mut desired = old;
    desired.extend_from_slice(b"transport failure test");
    let calls = AtomicUsize::new(0);
    let error = Client::connect_current(
        || async {
            if calls.fetch_add(1, Ordering::Relaxed) > 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "provider reconnect unavailable"));
            }
            dial(&socket).await
        },
        &Platform::current(),
        &desired,
        Duration::from_secs(3),
    )
    .await
    .err()
    .expect("an unavailable provider reconnect must time out");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("last transport error: provider reconnect unavailable"), "{error}");
    assert!(calls.load(Ordering::Relaxed) > 1);
    let current = connect(&socket, &sha256(&desired)).await;
    assert!(current.is_compatible());
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

// A vessel prepared for one platform whose agent reports another: fail naming
// both, push nothing, and leave the running generation untouched. The build
// offered is for the prepared platform, so pushing it would not run here.
#[tokio::test]
async fn prepared_platform_mismatch_pushes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let old = agent_binary();
    let fingerprint = sha256(&old);
    let executable = install(&dir.path().join("drydock-agent"), &old);
    let socket = dir.path().join("agent.sock");
    let mut child = start_agent(&executable, &socket);
    drop(connect(&socket, &fingerprint).await);
    let mut newer = old.clone();
    newer.extend_from_slice(b"newer build for another platform");
    let error = Client::connect_current(|| dial(&socket), &foreign(), &newer, Duration::from_secs(5))
        .await
        .err()
        .expect("an agent on another platform than the prepared one cannot be upgraded");
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert!(error.to_string().contains(&format!("prepared for {} but its agent reports {}", foreign(), Platform::current())), "{error}");
    assert_eq!(std::fs::read(&executable).unwrap(), old);
    for suffix in ["upgrade", "prev", "probation"] {
        assert!(!dir.path().join(format!("drydock-agent.{suffix}")).exists(), "{suffix} must not exist");
    }
    assert_eq!(connect(&socket, &fingerprint).await.hello().fingerprint, fingerprint);
    assert!(child.try_wait().unwrap().is_none());
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

// Reading hello never confirms a candidate: one that runs and answers any
// number of hellos, but that nobody confirms, is still on probation, and when
// it dies the provider's next ordinary start restores the previous executable.
#[tokio::test]
async fn unconfirmed_candidate_rolls_back_even_after_serving_hello() {
    let dir = tempfile::tempdir().unwrap();
    let binary = agent_binary();
    let executable = install(&dir.path().join("drydock-agent"), &binary);
    let old = sha256(&binary);
    let socket = dir.path().join("agent.sock");
    let mut child = start_agent(&executable, &socket);
    let client = connect(&socket, &old).await;
    let mut candidate = binary.clone();
    candidate.extend_from_slice(b"unconfirmed candidate");
    let new = sha256(&candidate);
    client.upgrade(candidate).await.unwrap();
    drop(client);
    let probe = connect_compatible(&socket, &new).await;
    for _ in 0..5 {
        assert!(probe.hello().probation);
        drop(connect(&socket, &new).await);
    }
    drop(probe);
    assert_eq!(std::fs::read(&executable).unwrap(), binary);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    let mut restarted = start_agent(&executable, &socket);
    let recovered = connect(&socket, &old).await;
    assert!(recovered.is_compatible(), "the previous executable must be back");
    assert!(!recovered.hello().probation);
    for suffix in ["probation", "upgrade", "prev"] {
        assert!(!executable.with_extension(suffix).exists(), "{suffix} must be gone after rollback");
    }
    restarted.kill().await.unwrap();
    restarted.wait().await.unwrap();
}

// The upgrade image is a blob: uploaded resumably and digest-checked, kept
// across an agent restart, and activated only by naming its digest. Without
// a completed upload of that digest activation is NotFound; an upload that
// does not match its digest never becomes one. A confirmed candidate
// confirms only once.
#[tokio::test]
async fn upgrades_activate_a_durable_verified_upload() {
    let dir = tempfile::tempdir().unwrap();
    let binary = agent_binary();
    let executable = install(&dir.path().join("drydock-agent"), &binary);
    let old = sha256(&binary);
    let socket = dir.path().join("agent.sock");
    let mut child = start_agent(&executable, &socket);
    let client = connect(&socket, &old).await;
    let mut candidate = binary.clone();
    candidate.extend_from_slice(b"durable upload");
    let new = sha256(&candidate);
    let length = candidate.len() as u64;
    assert_eq!(kind(&client.activate_upgrade(&new).await.unwrap_err()), ErrorKind::NotFound);
    let error = client.upload(&new, 5, std::io::Cursor::new(b"other".to_vec())).await.unwrap_err();
    assert_eq!(kind(&error), ErrorKind::DigestMismatch);
    assert_eq!(kind(&client.activate_upgrade(&new).await.unwrap_err()), ErrorKind::NotFound);
    client.upload(&new, length, std::io::Cursor::new(candidate.clone())).await.unwrap();
    drop(client);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    let mut child = start_agent(&executable, &socket);
    let client = connect(&socket, &old).await;
    assert_eq!(client.blob_size(&new).await.unwrap(), Some(length), "the upload survives a restart");
    assert_eq!(kind(&client.activate_upgrade(&old).await.unwrap_err()), ErrorKind::NotFound);
    client.activate_upgrade(&new).await.unwrap();
    drop(client);
    let candidate_client = connect_compatible(&socket, &new).await;
    assert!(candidate_client.hello().probation);
    candidate_client.confirm_upgrade().await.unwrap();
    assert_eq!(std::fs::read(&executable).unwrap(), candidate);
    assert_eq!(kind(&candidate_client.confirm_upgrade().await.unwrap_err()), ErrorKind::Conflict);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

// An upgrade whose upload was cut off partway leaves an incomplete upload of
// the digest; the next upgrade continues it rather than being refused.
#[tokio::test]
async fn upgrade_resumes_a_partial_upload_of_the_same_digest() {
    let dir = tempfile::tempdir().unwrap();
    let binary = agent_binary();
    let executable = install(&dir.path().join("drydock-agent"), &binary);
    let old = sha256(&binary);
    let socket = dir.path().join("agent.sock");
    let mut child = start_agent(&executable, &socket);
    let client = connect(&socket, &old).await;
    let mut candidate = binary.clone();
    candidate.extend_from_slice(b"resumed upgrade");
    let new = sha256(&candidate);
    let length = candidate.len() as u64;
    let half = candidate.len() / 2;
    let _ = client.upload(&new, length, std::io::Cursor::new(candidate[..half].to_vec())).await;
    assert_eq!(client.upload_offset(&new).await.unwrap(), (half as u64, false), "the cut-off upload is left incomplete");
    client.upgrade(candidate.clone()).await.unwrap();
    drop(client);
    let candidate_client = connect_compatible(&socket, &new).await;
    candidate_client.confirm_upgrade().await.unwrap();
    assert_eq!(std::fs::read(&executable).unwrap(), candidate);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

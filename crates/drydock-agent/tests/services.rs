//! Services end to end through the typed client: in-process agents for output
//! and idempotence, the agent executable for re-execs.
mod support;
use drydock_agent::{Client, ErrorKind, ExitStatus, Service, ServiceOutput, ServiceState};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use support::*;

const WAIT: Duration = Duration::from_secs(20);

fn shell(script: &str) -> Service {
    Service { program: "/bin/sh".into(), args: vec!["-c".into(), script.into()], ..Service::default() }
}
async fn until(what: &str, mut done: impl AsyncFnMut() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !done().await {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting until {what}"));
}

// Output nobody reads goes to the log, so a service writing far more than a
// process's buffer holds is never blocked by it.
#[tokio::test]
async fn unread_output_never_blocks_a_service() {
    let h = harness(false, "test-build").await;
    let marker = h.vessel().join("written");
    let script = format!("head -c 8000000 /dev/zero; touch '{}'; exec sleep 60", marker.display());
    let info = h.client.put_service("chatty", &shell(&script)).await.unwrap();
    assert_eq!(info.state, ServiceState::Running);
    until("the service wrote past its output", async || marker.exists()).await;
    assert_eq!(h.client.service("chatty").await.unwrap().state, ServiceState::Running);
    assert_eq!(std::fs::metadata(info.log.unwrap()).unwrap().len(), 8_000_000);
    h.client.remove_service("chatty", None).await.unwrap();
}

// A log past 64 MiB is copied aside once and emptied in place.
#[tokio::test]
async fn a_full_log_is_rotated_keeping_one_previous_file() {
    let h = harness(false, "test-build").await;
    let info = h
        .client
        .put_service(
            "big",
            &shell(&format!("yes 0123456 | head -c 70000000; touch '{}'; exec sleep 60", h.vessel().join("done").display())),
        )
        .await
        .unwrap();
    let log = info.log.unwrap();
    let previous = PathBuf::from(format!("{}.1", log.display()));
    let size = |path: &Path| std::fs::metadata(path).map_or(0, |m| m.len());
    let done = h.vessel().join("done");
    until("the log was rotated", async || done.exists() && size(&previous) > 64 * 1024 * 1024).await;
    // Rotation may come mid-write, so the rest of the output is in the log.
    assert!(size(&log) + size(&previous) <= 70_000_000 && size(&log) < 64 * 1024 * 1024);
    let kept = std::fs::read(&previous).unwrap();
    assert!(kept.chunks(8).all(|line| line == &b"0123456\n"[..line.len()]), "the previous log holds the service's output");
    h.client.remove_service("big", None).await.unwrap();
}

// A repeat start of a running service leaves it alone, a different request
// under its name is refused, and once it has exited it is started again.
#[tokio::test]
async fn starting_a_service_is_idempotent_by_name() {
    let h = harness(false, "test-build").await;
    let gate = h.vessel().join("gate");
    let service = shell(&format!("while test ! -f '{}'; do sleep 0.02; done", gate.display()));
    let first = h.client.put_service("engine", &service).await.unwrap();
    assert_eq!(h.client.put_service("engine", &service).await.unwrap().pid, first.pid);
    let other = Service { output: ServiceOutput::Discard, ..service.clone() };
    assert_eq!(h.client.put_service("engine", &other).await.unwrap_err().kind(), std::io::ErrorKind::from(ErrorKind::Conflict));
    std::fs::write(&gate, []).unwrap();
    until("the service exited", async || h.client.service("engine").await.unwrap().state != ServiceState::Running).await;
    assert_eq!(
        h.client.service("engine").await.unwrap().state,
        ServiceState::Exited { status: Some(ExitStatus { code: Some(0), signal: None, timed_out: false }) }
    );
    std::fs::remove_file(&gate).unwrap();
    let again = h.client.put_service("engine", &service).await.unwrap();
    assert_eq!(again.state, ServiceState::Running);
    assert_ne!(again.pid, first.pid);
    assert_eq!(h.client.services().await.unwrap().len(), 1);
    h.client.remove_service("engine", None).await.unwrap();
    assert_eq!(h.client.service("engine").await.unwrap_err().kind(), std::io::ErrorKind::NotFound);
}

// A start that cannot spawn keeps the previous run's log, however often it fails.
#[tokio::test]
async fn a_failed_start_keeps_the_previous_log() {
    let h = harness(false, "test-build").await;
    let first = h.client.put_service("engine", &shell("echo first")).await.unwrap();
    until("the first run exited", async || h.client.service("engine").await.unwrap().state != ServiceState::Running).await;
    let missing = Service { program: "/nonexistent/engine".into(), ..Service::default() };
    for _ in 0..2 {
        assert_eq!(h.client.put_service("engine", &missing).await.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }
    let log = first.log.unwrap();
    assert_eq!(std::fs::read(format!("{}.1", log.display())).unwrap(), b"first\n");
}

// A service that ignores SIGTERM is killed once the grace runs out.
#[tokio::test]
async fn stopping_escalates_to_sigkill() {
    let h = harness(false, "test-build").await;
    let ready = h.vessel().join("ready");
    let script = format!("trap '' TERM; touch '{}'; while :; do sleep 0.02; done", ready.display());
    h.client.put_service("stubborn", &shell(&script)).await.unwrap();
    until("the trap was set", async || ready.exists()).await;
    let stopped = h.client.remove_service("stubborn", Some(Duration::from_millis(200))).await.unwrap();
    assert_eq!(stopped.state, ServiceState::Exited { status: Some(ExitStatus { code: None, signal: Some(9), timed_out: false }) });
}

// A name is one safe file name: no path, no leading dot, at most 64 bytes.
#[tokio::test]
async fn names_are_refused_unless_one_safe_file_name() {
    let h = harness(false, "test-build").await;
    for name in ["a/b", ".hidden", "-flag", &"x".repeat(65)] {
        let refused = h.client.put_service(name, &shell("true")).await.unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::InvalidInput, "{name}");
    }
    assert!(h.client.services().await.unwrap().is_empty());
}

/// An agent executable serving `socket`, upgraded once to another build.
struct Upgraded {
    client: Client,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    socket: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    dir: tempfile::TempDir,
    _agent: tokio::process::Child,
}
async fn re_exec_with(name: &str, service: impl FnOnce(&Path) -> Service) -> Upgraded {
    let dir = tempfile::tempdir().unwrap();
    let binary = agent_binary();
    let executable = install(&dir.path().join("drydock-agent"), &binary);
    let socket = dir.path().join("agent.sock");
    let agent = start_agent(&executable, &socket);
    let client = connect(&socket, &sha256(&binary)).await;
    let started = client.put_service(name, &service(dir.path())).await.unwrap();
    let mut new_binary = binary.clone();
    new_binary.extend_from_slice(b"drydock services test");
    client.upgrade(new_binary.clone()).await.unwrap();
    drop(client);
    let client = connect_compatible(&socket, &sha256(&new_binary)).await;
    client.confirm_upgrade().await.unwrap();
    let after = client.service(name).await.unwrap();
    assert_eq!((after.pid, after.state), (started.pid, ServiceState::Running));
    Upgraded { client, socket, dir, _agent: agent }
}

// A service outlives an agent re-exec, and the new agent still reports and
// stops it, though it no longer knows how it ended.
#[tokio::test]
async fn a_service_survives_a_re_exec_and_is_stopped_there() {
    let upgraded = re_exec_with("engine", |_| shell("exec sleep 300")).await;
    let pid = upgraded.client.service("engine").await.unwrap().pid;
    let stopped = upgraded.client.remove_service("engine", None).await.unwrap();
    assert_eq!(stopped.state, ServiceState::Exited { status: None });
    until("the service was reaped", async || process_state(&pid.to_string()) == Pid::Gone).await;
}

// The new agent watches a service it took over, so its exit is announced.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_service_exit_after_a_re_exec_is_announced() {
    let upgraded =
        re_exec_with("engine", |dir| shell(&format!("while test ! -f '{}'; do sleep 0.02; done", dir.join("gate").display()))).await;
    let pid = upgraded.client.service("engine").await.unwrap().pid;
    std::fs::write(upgraded.dir.path().join("gate"), []).unwrap();
    let mut events = tokio::io::AsyncBufReadExt::lines(events(&upgraded.socket).await);
    let announced = tokio::time::timeout(WAIT, async {
        loop {
            let line = events.next_line().await.unwrap().expect("/events ended");
            let record: drydock_agent::events::Record = serde_json::from_str(&line).unwrap();
            if let drydock_agent::events::Event::ServiceExited { name, pid, status } = record.event {
                return (name, pid, status);
            }
        }
    })
    .await
    .expect("no service exit was announced");
    assert_eq!(announced, ("engine".to_owned(), pid, None));
    assert_eq!(upgraded.client.service("engine").await.unwrap().state, ServiceState::Exited { status: None });
}
/// `/events` from the start, as lines.
#[cfg(target_os = "linux")]
async fn events(socket: &Path) -> impl tokio::io::AsyncBufRead + Unpin {
    use futures_util::{StreamExt, TryStreamExt};
    use http_body_util::BodyExt;
    let request = http::Request::get("/events").body(http_body_util::Full::new(bytes::Bytes::new())).unwrap();
    let response = raw_client(&Dial::Unix(socket.into())).await.send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    tokio_util::io::StreamReader::new(response.into_body().into_data_stream().map_err(std::io::Error::other).boxed())
}

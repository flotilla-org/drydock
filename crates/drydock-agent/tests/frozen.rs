//! The frozen upgrade path: hello, the resumable blob upload, activation and
//! confirmation, over plain HTTP/1.1, which every agent release serves the
//! same way. A released agent kept as a fixture is brought to the current
//! build by the current client, so a change that breaks the path fails here.
mod support;
use drydock_agent::{Agent, ArtifactSource, Client, Configuration, ErrorKind, Exec, Fetch, Platform, ProcessState, Unpack};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use support::*;

/// The released agent named by `tests/fixtures/previous-agent.json` for this
/// platform, fetched from its tools image layer through an in-process agent's
/// own OCI fetch and kept in a store under Cargo's target directory, so a
/// later run reads it from the store's index. `DRYDOCK_PREVIOUS_AGENT` names
/// a local copy instead, for working offline; it must be that same release.
/// None on a platform the release was not built for.
async fn previous_agent() -> Option<Vec<u8>> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/previous-agent.json")).expect("the previous-agent fixture is JSON");
    let platform = fixture["platforms"].get(Platform::current().to_string())?;
    let (layer, agent) = (platform["layer"].as_str().unwrap(), platform["agent"].as_str().unwrap());
    let binary = match std::env::var_os("DRYDOCK_PREVIOUS_AGENT") {
        Some(path) => std::fs::read(&path).unwrap_or_else(|e| panic!("DRYDOCK_PREVIOUS_AGENT {}: {e}", Path::new(&path).display())),
        None => {
            let store = Path::new(env!("CARGO_TARGET_TMPDIR")).join("previous-agent-store");
            let dir = tempfile::tempdir().unwrap();
            let (dialer, listener) = drydock_transport::memory();
            let fetcher = tokio::spawn(Agent::new(listener, "fetcher".into(), dir.path().join("agent")).with_store(store).run());
            let client = Client::connect(dialer.connect().await.unwrap(), "fetcher").await.unwrap();
            let source = ArtifactSource::Oci {
                registry: fixture["registry"].as_str().unwrap().into(),
                repository: fixture["repository"].as_str().unwrap().into(),
                credential: None,
            };
            let fetched = client.fetch_artifact(layer, &Fetch { sources: vec![source], unpack: Unpack::TarGz }).await.unwrap_or_else(|e| {
                panic!(
                    "fetch the previous release's agent ({}): {e}; set DRYDOCK_PREVIOUS_AGENT to a local copy to work offline",
                    fixture["release"]
                )
            });
            fetcher.abort();
            std::fs::read(fetched.artifact.path.join("opt/drydock/drydock-agent")).unwrap()
        }
    };
    assert_eq!(sha256(&binary), agent, "the previous agent is not the release the fixture names");
    Some(binary)
}

/// An agent installed as the tools layer installs it, started on `socket`.
fn vessel(dir: &Path, binary: &[u8]) -> (PathBuf, PathBuf, tokio::process::Child) {
    let install_dir = dir.join("opt/drydock");
    std::fs::create_dir_all(&install_dir).unwrap();
    let executable = install(&install_dir.join("drydock-agent"), binary);
    let socket = dir.join("agent.sock");
    let child = start_agent(&executable, &socket);
    (executable, socket, child)
}

// The released agent answers hello over HTTP/1.1, takes the current build as
// a resumable blob, activates it and re-execs in the same process, and the
// candidate it becomes is confirmed: hello through confirm, then the current
// wire on the same connection. A second contact finds the current build and
// uploads nothing.
#[tokio::test]
async fn a_released_agent_is_upgraded_from_hello_through_confirm() {
    let Some(previous) = previous_agent().await else {
        eprintln!("no previous release of the agent for {}; skipping", Platform::current());
        return;
    };
    let current = agent_binary();
    assert_ne!(sha256(&previous), sha256(&current));
    let dir = tempfile::tempdir().unwrap();
    let (executable, socket, mut child) = vessel(dir.path(), &previous);
    let pid = child.id();
    drop(connect(&socket, "").await);
    let client = Client::connect_current(|| dial(&socket), &Platform::current(), &current, Duration::from_secs(30)).await.unwrap();
    assert!(client.is_compatible());
    assert_eq!(client.hello().fingerprint, sha256(&current));
    assert!(!client.hello().probation, "the candidate is confirmed");
    client.configure(Configuration::default()).await.unwrap();
    assert_eq!(std::fs::read(&executable).unwrap(), current, "confirmation installs the current build");
    assert_eq!(std::fs::read(executable.with_extension("prev")).unwrap(), previous);
    assert_eq!(child.id(), pid, "the agent re-execs in place");
    assert!(child.try_wait().unwrap().is_none());
    let boot = client.hello().boot_id.clone();
    drop(client);
    let again = Client::connect_current(|| dial(&socket), &Platform::current(), &current, Duration::from_secs(10)).await.unwrap();
    assert_eq!(again.hello().boot_id, boot, "a matching hello needs no upgrade");
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

// Activation drains: the agent starts no more processes and waits for the
// running ones to exit before it re-execs, up to the limit the request
// gives. One that outlives the limit is named in the reply, and keeps running
// across the re-exec without its handle.
#[tokio::test]
async fn drain_waits_for_running_processes_and_reports_those_past_the_limit() {
    let binary = agent_binary();
    let dir = tempfile::tempdir().unwrap();
    let (_, socket, mut child) = vessel(dir.path(), &binary);
    let client = connect(&socket, &sha256(&binary)).await;
    let mut candidate = binary.clone();
    candidate.extend_from_slice(b"drained candidate");
    let digest = sha256(&candidate);
    client.upload(&digest, candidate.len() as u64, std::io::Cursor::new(candidate.clone())).await.unwrap();
    let marker = dir.path().join("finished");
    let short = client.spawn(shell(&format!("sleep 1; touch '{}'", marker.display()))).await.unwrap();
    let observer = connect(&socket, &sha256(&binary)).await;
    let started = Instant::now();
    let activation = tokio::spawn(async move { client.activate_upgrade_draining(&digest, Duration::from_secs(20)).await });
    // While draining, the agent refuses to start anything new.
    let refused = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match observer.spawn(Exec::new("/bin/true", [""; 0])).await {
                Err(error) => break error,
                Ok(process) => {
                    let _ = process.remove().await;
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    })
    .await
    .expect("a draining agent must refuse new processes");
    assert_eq!(kind(&refused), ErrorKind::Conflict, "{refused}");
    assert!(observer.process(short.id()).await.unwrap().info().await.unwrap().state == ProcessState::Running);
    let activated = activation.await.unwrap().unwrap();
    assert!(started.elapsed() >= Duration::from_millis(900), "the reply waited for the running process");
    assert!(marker.exists(), "the process ran to its end before the re-exec");
    assert_eq!(activated.running, vec![]);
    drop(observer);
    let upgraded = connect_compatible(&socket, &sha256(&candidate)).await;
    upgraded.confirm_upgrade().await.unwrap();
    let mut newer = candidate.clone();
    newer.extend_from_slice(b"past the limit");
    let digest = sha256(&newer);
    upgraded.upload(&digest, newer.len() as u64, std::io::Cursor::new(newer.clone())).await.unwrap();
    let survivor = dir.path().join("survivor");
    let long = upgraded.spawn(shell(&format!("sleep 2; touch '{}'", survivor.display()))).await.unwrap();
    let started = Instant::now();
    let activated = upgraded.activate_upgrade_draining(&digest, Duration::from_millis(300)).await.unwrap();
    assert!(started.elapsed() >= Duration::from_millis(300) && started.elapsed() < Duration::from_secs(2));
    assert_eq!(activated.sha256, digest);
    assert_eq!(activated.running.len(), 1, "{activated:?}");
    assert_eq!((activated.running[0].id.as_str(), activated.running[0].program.as_str()), (long.id(), "/bin/sh"));
    drop(upgraded);
    let newest = connect_compatible(&socket, &sha256(&newer)).await;
    assert!(newest.processes().await.unwrap().is_empty(), "handles end with the agent that held them");
    tokio::time::timeout(Duration::from_secs(10), async {
        while !survivor.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("a process past the drain limit keeps running across the re-exec");
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

// The hello fields of the frozen path keep their names and meanings over
// plain HTTP/1.1, as curl sees them. Fields can be added; these stay.
#[tokio::test]
async fn hello_keeps_its_fields_over_http1() {
    let binary = agent_binary();
    let dir = tempfile::tempdir().unwrap();
    let (_, socket, mut child) = vessel(dir.path(), &binary);
    drop(connect(&socket, "").await);
    let output = tokio::process::Command::new("curl")
        .args(["--silent", "--show-error", "--fail", "--http1.1", "--unix-socket"])
        .arg(&socket)
        .arg("http://agent/hello")
        .output()
        .await
        .expect("curl is required");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let hello: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(hello["fingerprint"], sha256(&binary));
    assert!(hello["features"].as_array().is_some_and(|f| f.iter().all(serde_json::Value::is_string)), "{hello}");
    let platform = Platform::current();
    assert_eq!(hello["platform"], serde_json::json!({"os": platform.os, "architecture": platform.architecture}));
    assert!(hello["boot_id"].as_str().is_some_and(|id| id.len() == 32), "{hello}");
    assert_eq!(hello["probation"], false);
    // The current wire on an HTTP/1.1 connection is an explicit upgrade.
    let output = tokio::process::Command::new("curl")
        .args(["--silent", "--http1.1", "--unix-socket"])
        .arg(&socket)
        .arg("http://agent/control")
        .output()
        .await
        .unwrap();
    let refusal: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!((refusal["operation"].as_str(), refusal["status"].as_u64()), (Some("control.upgrade"), Some(400)), "{refusal}");
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

// An upgrade cut off partway leaves an incomplete upload of the build; the
// next contact continues it from the offset the agent reports, over the
// frozen path, rather than being refused or starting again.
#[tokio::test]
async fn the_next_contact_resumes_a_partial_upload() {
    let current = agent_binary();
    let mut older = current.clone();
    older.extend_from_slice(b"older agent");
    let dir = tempfile::tempdir().unwrap();
    let (executable, socket, mut child) = vessel(dir.path(), &older);
    let client = connect(&socket, "").await;
    let digest = sha256(&current);
    let half = current.len() / 2;
    let _ = client.upload(&digest, current.len() as u64, std::io::Cursor::new(current[..half].to_vec())).await;
    assert_eq!(client.upload_offset(&digest).await.unwrap(), (half as u64, false));
    drop(client);
    let upgraded = Client::connect_current(|| dial(&socket), &Platform::current(), &current, Duration::from_secs(30)).await.unwrap();
    assert_eq!(upgraded.hello().fingerprint, digest);
    assert_eq!(std::fs::read(&executable).unwrap(), current);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

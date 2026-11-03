//! Upload bootstrap through drydockd, against the reference module's model of
//! a guest's files and commands. The stand-in gateway serves a real agent on
//! this host and stands in only for the SSH process boundary.
use drydock::{
    HostConnection,
    agent::stand_in::Gateway,
    client::Error,
    config::Config,
    daemon::{Daemon, HostOption, ProviderApi, Seams},
};
use drydock_protocol::*;
use serde_json::{Value, json};
use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
use tokio::io::AsyncReadExt;

const BUILD: &[u8] = b"upload test agent";
const PROVIDER: &str = "vessels";
const AGENT: &str = "/opt/drydock/drydock-agent";
const START: &str = "start /opt/drydock/drydock-agent --supervise --socket /run/drydock/agent.sock";

struct Digests;
#[async_trait::async_trait]
impl drydock::launch::ImageResolver for Digests {
    async fn resolve(&self, image: &str) -> Result<String, Error> {
        Ok(image.into())
    }
}
struct Build;
#[async_trait::async_trait]
impl drydock::daemon::AgentBuilds for Build {
    async fn build(&self, _: &Platform) -> Result<Vec<u8>, String> {
        Ok(BUILD.to_vec())
    }
}

struct Harness {
    // Under /tmp, so socket paths stay within SUN_LEN.
    _dir: tempfile::TempDir,
    gateway: Arc<Gateway>,
    host: tokio::task::JoinHandle<()>,
    daemon: Arc<Daemon>,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.host.abort();
    }
}
impl Harness {
    /// A daemon whose provider takes upload bootstrap, with `settings` added
    /// to the reference module's.
    async fn start(settings: &str) -> Self {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let vessel = dir.path().join("vessel");
        std::fs::create_dir(&vessel).unwrap();
        let gateway = Gateway::start_as(&vessel, BUILD, Platform::new("linux", "amd64")).unwrap();
        let reference = dir.path().join("reference.sock");
        let socket = reference.clone();
        let host = tokio::spawn(async move {
            drydock_host::Host::new(drydock_host::reference::registry()).serve_unix(socket, std::future::pending()).await.unwrap();
        });
        for _ in 0..200 {
            if drydock::client::Client::unix(&reference).unwrap().hello().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let text = format!(
            "[providers.{PROVIDER}]\nmodule='reference'\ncredential={{env='PATH'}}\nimage='image@sha256:{}'\n\
             settings={{agent=true, upload=true, fixture=true, poll_interval_ms=10, \
             reach={{kind='ssh', endpoint='gateway.test:22', user='minted', host_key='ssh-ed25519 AAAA'}}{settings}}}\n",
            "a".repeat(64)
        );
        let run = dir.path().join("run");
        let seams = Seams {
            dialer: gateway.clone(),
            builds: Arc::new(Build),
            hello_timeout: Duration::from_secs(2),
            ..Seams::new(Arc::new(Digests))
        };
        let option = HostOption { optional: false, name: "rust".into(), connection: HostConnection::ExternalUnix { path: reference } };
        let daemon = Daemon::start_with_seams(Config::parse(&text).unwrap(), &run, run.join("keys"), vec![option], seams).await.unwrap();
        Self { _dir: dir, gateway, host, daemon }
    }
    /// The guest's files and the guest commands drydock ran, as the module models them.
    async fn guest(&self, id: &str) -> Value {
        let command = ExecRequest { command: vec!["drydock-fixture".into(), "guest".into()] };
        let mut output = String::new();
        ProviderApi::exec(&*self.daemon, PROVIDER, id, &command).await.unwrap().read_to_string(&mut output).await.unwrap();
        serde_json::from_str(&output).unwrap()
    }
    /// The one environment the provider holds.
    async fn environment(&self) -> Environment {
        let mut environments = ProviderApi::list(&*self.daemon, PROVIDER).await.unwrap();
        assert_eq!(environments.len(), 1);
        environments.remove(0)
    }
}

// A launch puts the host's agent build in the vessel, moves it into place
// whole, starts its supervisor, and returns only after the agent's hello.
// Re-adopting the label or resuming the vessel finds the agent there and
// starts it again without uploading it.
#[tokio::test]
async fn launch_uploads_then_starts_the_agent() {
    let h = Harness::start("").await;
    let launched = h.daemon.launch(PROVIDER, &Default::default()).await.unwrap();
    let guest = h.guest(&launched.id).await;
    let log: Vec<String> = serde_json::from_value(guest["log"].clone()).unwrap();
    let upload = log[1].strip_prefix("put ").and_then(|put| put.strip_suffix(" 755")).unwrap();
    assert!(upload.starts_with(&format!("{AGENT}.upload-")), "{upload}");
    assert_eq!(log, [format!("probe {AGENT}"), format!("put {upload} 755"), format!("mv {upload} {AGENT}"), START.into()]);
    assert_eq!(guest["files"], json!({AGENT: {"bytes": String::from_utf8_lossy(BUILD), "mode": 0o755}}));
    assert!(h.gateway.dials() > 0, "the launch waited for the agent's hello");

    // A client's provision of a label runs the same bootstrap.
    let prepared = ProviderApi::prepare(
        &*h.daemon,
        PROVIDER,
        &PrepareRequest {
            size: launched.granted_size.clone().unwrap(),
            platform: None,
            route: None,
            image_pull: None,
            image_digest: format!("image@sha256:{}", "a".repeat(64)),
            tools_digest: format!("tools@sha256:{}", "b".repeat(64)),
        },
    )
    .await
    .unwrap();
    let request = ProvisionRequest {
        label: launched.label.clone().unwrap(),
        prepared,
        size: launched.granted_size.clone().unwrap(),
        egress: EgressRequest::Open,
        ssh_public_key: Some("ssh-ed25519 AAAA test".into()),
    };
    assert!(matches!(ProviderApi::provision(&*h.daemon, PROVIDER, &request).await.unwrap(), drydock::api::Provisioned::Existing(_)));
    let token = ProviderApi::suspend(&*h.daemon, PROVIDER, &launched.id).await.unwrap();
    ProviderApi::resume(&*h.daemon, PROVIDER, &launched.id, &token).await.unwrap();
    let log = h.guest(&launched.id).await["log"].as_array().unwrap()[4..].to_vec();
    assert_eq!(log, [json!(format!("probe {AGENT}")), json!(START), json!(format!("probe {AGENT}")), json!(START)]);
}

// A failed upload fails the launch with the provider's own error, saying the
// upload is what failed; nothing is started.
#[tokio::test]
async fn a_failed_upload_names_its_cause() {
    let h = Harness::start(", upload_fault={kind='refused', reason='guest disk is full'}").await;
    let error = h.daemon.launch(PROVIDER, &Default::default()).await.unwrap_err();
    let Error::Protocol(ProtocolError::Refused { reason }) = &error else { panic!("{error:?}") };
    assert_eq!(reason, "upload the vessel agent: provider vessels operation files: guest disk is full");
    let environment = h.environment().await;
    assert_eq!(h.guest(&environment.id).await["log"], json!([format!("probe {AGENT}")]));
    assert_eq!(h.gateway.dials(), 0, "no hello is attempted without an agent");
}

// An agent that is put in place and started but never says hello fails the
// launch once the hello deadline passes, saying so, rather than reporting a
// vessel nothing can reach.
#[tokio::test]
async fn an_agent_that_does_not_hello_fails_the_launch() {
    let h = Harness::start("").await;
    h.gateway.stop();
    let error = h.daemon.launch(PROVIDER, &Default::default()).await.unwrap_err();
    let Error::Protocol(ProtocolError::Unavailable { reason, .. }) = &error else { panic!("{error:?}") };
    assert!(reason.starts_with("vessel agent did not complete its hello handshake"), "{reason}");
    let environment = h.environment().await;
    let log = h.guest(&environment.id).await["log"].clone();
    assert_eq!(log.as_array().unwrap().last().unwrap(), START);
    assert!(h.gateway.dials() > 0);
}

// Two bootstraps of one vessel at once (a client's provision retried while
// the first is under way) both find no agent and both upload, each under its
// own name, so both succeed and the vessel holds one whole agent.
#[tokio::test]
async fn concurrent_bootstraps_each_install_a_whole_agent() {
    let h = Harness::start("").await;
    let size = Size { cpus: 1.0, memory_bytes: 1 << 30, disk_bytes: 1 << 30 };
    let prepare = PrepareRequest {
        size: size.clone(),
        platform: None,
        route: None,
        image_pull: None,
        image_digest: format!("image@sha256:{}", "a".repeat(64)),
        tools_digest: format!("tools@sha256:{}", "b".repeat(64)),
    };
    let prepared = ProviderApi::prepare(&*h.daemon, PROVIDER, &prepare).await.unwrap();
    let request = ProvisionRequest {
        label: "twice".into(),
        prepared,
        size,
        egress: EgressRequest::Open,
        ssh_public_key: Some("ssh-ed25519 AAAA test".into()),
    };
    let (first, second) =
        tokio::join!(ProviderApi::provision(&*h.daemon, PROVIDER, &request), ProviderApi::provision(&*h.daemon, PROVIDER, &request));
    first.unwrap();
    second.unwrap();
    let guest = h.guest(&h.environment().await.id).await;
    assert_eq!(guest["files"], json!({AGENT: {"bytes": String::from_utf8_lossy(BUILD), "mode": 0o755}}));
    let log: Vec<String> = serde_json::from_value(guest["log"].clone()).unwrap();
    assert_eq!(log.iter().filter(|line| line.as_str() == START).count(), 2);
}

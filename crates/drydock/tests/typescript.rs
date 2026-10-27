//! Optional-language integration enabled explicitly by the TypeScript CI command.
//! Public conformance runs at Daemon; the child implements only the provider trait.
use drydock::{
    HostConnection,
    api::ProviderApi,
    client::Client,
    config::Config,
    conformance::{self, Options, Scenario},
    daemon::{Daemon, HostOption},
};
use drydock_protocol::*;
use std::{os::unix::fs::PermissionsExt, time::Duration};

#[tokio::test]
#[ignore = "requires the built companion; run by hosts/typescript pnpm check"]
async fn typescript_reference_conforms_through_main_server() {
    let binary = std::env::var_os("DRYDOCK_TYPESCRIPT_TEST_BIN").expect("set by the TypeScript conformance script");
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let private_socket = dir.path().join("typescript.sock");
    let mut child = tokio::process::Command::new(binary)
        .arg("--unix")
        .arg(&private_socket)
        .env_remove("DRYDOCK_TYPESCRIPT_MODULES")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let private = Client::unix(&private_socket).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if private.hello().await.is_ok() {
                break;
            }
            assert!(child.try_wait().unwrap().is_none(), "TypeScript child exited before hello");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let credential = dir.path().join("credential");
    std::fs::write(&credential, "test-only-reference-token").unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
[provider.a]
module = "reference"
credential = {{ file = {:?} }}
settings = {{ seed_unlabelled = true }}
"#,
        credential
    ))
    .unwrap();
    let daemon = Daemon::start(
        config,
        &dir.path().join("server"),
        dir.path().join("keys"),
        vec![HostOption { name: "typescript".into(), optional: false, connection: HostConnection::ExternalUnix { path: private_socket } }],
    )
    .await
    .unwrap();
    // Embedded entry reaches the same server policy: optional ports are absent,
    // so it refuses before attempting a TypeScript optional route.
    let err = ProviderApi::quota(&*daemon, "a").await.unwrap_err();
    assert!(matches!(err, drydock::client::Error::Protocol(ProtocolError::Refused { .. })), "{err}");
    let public_socket = dir.path().join("public.sock");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let d = daemon.clone();
    let socket = public_socket.clone();
    let server = tokio::spawn(async move {
        d.serve(&socket, async {
            let _ = stopped.await;
        })
        .await
        .unwrap();
    });
    let client = Client::unix(&public_socket).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while client.hello().await.is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let size = Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 };
    let options = Options {
        request: ProvisionRequest {
            label: "typescript-conformance".into(),
            prepared: Prepared {
                provider: "a".into(),
                id: "to-be-prepared".into(),
                platform: Platform::new("linux", "amd64"),
                image_digest: "image".into(),
                tools_digest: "tools".into(),
            },
            size,
            egress: EgressRequest::default(),
            ssh_public_key: None,
        },
        // Managed private UDS is filesystem-authorized; network authentication is
        // covered by main serving tests. Exec-based host fixtures wait for #85.
        scenarios: Scenario::ALL.iter().copied().filter(|s| !matches!(s, Scenario::Authentication | Scenario::HostFixtures)).collect(),
        fixture_configuration: None,
        null_environment_id: Some("unlabelled".into()),
        auth_audit: None,
        billing_sample_millis: 25,
        billing_settle_millis: 0,
        timeouts: Default::default(),
        echo_relay: true,
        reach_probe: None,
        egress_probe: None,
    };
    let report = conformance::run(&client, "a", &options).await;
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(10), server).await.unwrap().unwrap();
    child.kill().await.unwrap();
    let output = child.wait_with_output().await.unwrap();
    assert!(output.stdout.is_empty() && output.stderr.is_empty(), "bridge must not log requests/credentials");
    assert!(report.passed(), "{}", serde_json::to_string_pretty(&report).unwrap());
}

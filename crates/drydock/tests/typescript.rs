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
        // covered by main serving tests. Exec-based host fixtures wait for #85, and
        // reach waits for the exposure redesign in #132.
        scenarios: Scenario::ALL
            .iter()
            .copied()
            .filter(|s| !matches!(s, Scenario::Authentication | Scenario::HostFixtures | Scenario::Reach))
            .collect(),
        fixture_configuration: None,
        auth_audit: None,
        billing_sample_millis: 25,
        billing_settle_millis: 0,
        timeouts: Default::default(),
        echo_relay: false,
        reach_probe: None,
        egress_probe: None,
    };
    let report = conform(None, "reference", "test-only-reference-token", "seed_unlabelled = true", &options, |daemon| async move {
        // Embedded entry reaches the same server policy: optional ports are absent,
        // so it refuses before attempting a TypeScript optional route.
        let err = ProviderApi::quota(&*daemon, "a").await.unwrap_err();
        assert!(matches!(err, drydock::client::Error::Protocol(ProtocolError::Refused { .. })), "{err}");
    })
    .await;
    assert!(report.passed(), "{}", serde_json::to_string_pretty(&report).unwrap());
}

// The Modal module, with only its vendor (the SDK) stood in, passes drydock's
// conformance suite through drydockd. Reach needs a real agent behind Modal's
// edge, so it is left to the operator's live pass; host fixtures need an exec
// port (#85), and private-socket authentication is the server's.
#[tokio::test]
#[ignore = "requires the built companion; run by hosts/typescript pnpm check"]
async fn typescript_modal_conforms_through_main_server() {
    let entry = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../hosts/typescript/test/support/modal-host.ts");
    let entry = entry.canonicalize().expect("the Modal stand-in module");
    let digest = |c: char| format!("sha256:{}", c.to_string().repeat(64));
    let options = Options {
        request: ProvisionRequest {
            label: "modal-conformance".into(),
            prepared: Prepared {
                provider: "a".into(),
                id: "to-be-prepared".into(),
                platform: Platform::new("linux", "amd64"),
                image_digest: format!("docker.io/library/alpine@{}", digest('a')),
                tools_digest: format!("ghcr.io/flotilla-org/drydock-tools@{}", digest('b')),
            },
            size: Size { cpus: 1., memory_bytes: 2 << 30, disk_bytes: 0 },
            egress: EgressRequest::default(),
            ssh_public_key: None,
        },
        scenarios: Scenario::ALL
            .iter()
            .copied()
            .filter(|s| !matches!(s, Scenario::Authentication | Scenario::HostFixtures | Scenario::Reach))
            .collect(),
        fixture_configuration: None,
        auth_audit: None,
        billing_sample_millis: 25,
        billing_settle_millis: 0,
        // The module polls Modal every 30 s; a record or transition takes up to one poll.
        timeouts: conformance::Timeouts { record_seconds: 75, transition_seconds: 75, ..Default::default() },
        echo_relay: false,
        reach_probe: None,
        egress_probe: None,
    };
    let credential = r#"{"token_id":"ak-test-only","token_secret":"as-test-only"}"#;
    let report = conform(Some(entry.as_os_str()), "modal-stand-in", credential, "", &options, |_| async {}).await;
    assert!(report.passed(), "{}", serde_json::to_string_pretty(&report).unwrap());
}

/// Runs conformance for provider `a` (module `module`, with `settings` as
/// inline TOML) through drydockd's public server, in front of the built
/// TypeScript host with `modules` loaded beside its own. `embedded` runs
/// against the daemon before it serves.
async fn conform<F, Fut>(
    modules: Option<&std::ffi::OsStr>,
    module: &str,
    credential_text: &str,
    settings: &str,
    options: &Options,
    embedded: F,
) -> conformance::Report
where
    F: FnOnce(std::sync::Arc<Daemon>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let binary = std::env::var_os("DRYDOCK_TYPESCRIPT_TEST_BIN").expect("set by the TypeScript conformance script");
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let private_socket = dir.path().join("typescript.sock");
    let mut command = tokio::process::Command::new(binary);
    command.arg("--unix").arg(&private_socket).env_remove("DRYDOCK_TYPESCRIPT_MODULES");
    if let Some(modules) = modules {
        command.env("DRYDOCK_TYPESCRIPT_MODULES", modules);
    }
    let mut child = command.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).kill_on_drop(true).spawn().unwrap();
    // Drain without retaining diagnostics/credentials or risking a full child pipe.
    let mut stdout = child.stdout.take().unwrap();
    let stdout = tokio::spawn(async move { tokio::io::copy(&mut stdout, &mut tokio::io::sink()).await.unwrap() });
    let mut stderr = child.stderr.take().unwrap();
    let stderr = tokio::spawn(async move { tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await.unwrap() });
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
    .expect("TypeScript child did not answer hello within 10s");
    let credential = dir.path().join("credential");
    std::fs::write(&credential, credential_text).unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
[providers.a]
module = "{module}"
credential = {{ file = {credential:?} }}
settings = {{ {settings} }}
"#
    ))
    .unwrap();
    let daemon = Daemon::start(
        config,
        &dir.path().join("server"),
        dir.path().join("keys"),
        vec![HostOption { name: "typescript".into(), optional: false, connection: HostConnection::ExternalUnix { path: private_socket } }],
    )
    .await
    .expect("public server did not answer hello within 10s");
    embedded(daemon.clone()).await;
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
    let report = conformance::run(&client, "a", options).await;
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(10), server).await.expect("public server did not stop within 10s").unwrap();
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    assert_eq!(stdout.await.unwrap(), 0, "bridge must not log requests/credentials");
    assert_eq!(stderr.await.unwrap(), 0, "bridge must not log requests/credentials");
    report
}

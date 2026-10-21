use drydock::{HostConnection, HostSpec};
use drydock_protocol::*;
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};

// All five commands drive a real externally owned Rust reference host. Separate
// invocations share only provider state; the CLI never creates a local store.
#[tokio::test]
async fn cli_lifecycle_against_reference_host() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("host.sock");
    let path = socket.clone();
    let server = tokio::spawn(async move {
        drydock_host::Host::new(drydock_host::reference::registry())
            .serve_unix(path, unsafe { libc::geteuid() }, std::future::pending())
            .await
            .unwrap()
    });
    let config = dir.path().join("hosts.json");
    let spec = HostSpec { name: "rust".into(), connection: HostConnection::ExternalUnix { path: socket.clone() }, configuration: serde_json::from_value(serde_json::json!({"modules":[{"name":"memory","entrypoint":"reference"}],"providers":[{"name":"a","module":"memory","settings":{},"credential":{"mode":"direct","credential_reference":"test"}}]})).unwrap(), credentials: BTreeMap::from([("test".into(), drydock::credentials::CredentialReference::Env { name: "PATH".into() })]) };
    std::fs::write(&config, serde_json::to_vec(&vec![spec]).unwrap()).unwrap();
    let run = |args: Vec<String>| {
        let config = config.clone();
        let runtime = dir.path().join("run");
        async move {
            let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_drydock"))
                .arg("--config")
                .arg(config)
                .arg("--runtime-directory")
                .arg(runtime)
                .args(&args)
                .output()
                .await
                .unwrap();
            if args.first().is_some_and(|arg| arg == "conformance") {
                // Settle progress belongs on stderr; the caller still parses stdout as one JSON report.
                assert!(String::from_utf8_lossy(&output.stderr).contains("Billing checks wait 1 ms"));
            }
            assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stderr), String::from_utf8_lossy(&output.stdout));
            String::from_utf8(output.stdout).unwrap()
        }
    };
    assert!(run(vec!["hosts".into()]).await.contains("ready"));
    assert!(run(vec!["instances".into()]).await.contains("\"instance\":\"a\""));
    let client = drydock::client::Client::unix(socket).unwrap();
    let prepared: Prepared = serde_json::from_str(
        &run(vec![
            "prepare".into(),
            "rust".into(),
            "a".into(),
            "sha256:image".into(),
            "sha256:tools".into(),
            "1".into(),
            "1024".into(),
            "0".into(),
        ])
        .await,
    )
    .unwrap();
    let request = dir.path().join("launch.json");
    std::fs::write(
        &request,
        serde_json::to_vec(&ProvisionRequest {
            label: "test".into(),
            prepared,
            size: Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
            egress: EgressRequest::default(),
            ssh_public_key: None,
        })
        .unwrap(),
    )
    .unwrap();
    let environment: Environment =
        serde_json::from_str(&run(vec!["launch".into(), "rust".into(), "a".into(), request.to_string_lossy().into_owned()]).await).unwrap();
    let list: Vec<Environment> = serde_json::from_str(&run(vec!["list".into(), "rust".into(), "a".into()]).await).unwrap();
    assert_eq!(list, vec![environment.clone()]);
    let options = drydock::conformance::Options {
        request: ProvisionRequest {
            label: "cli-conformance".into(),
            prepared: client
                .prepare(
                    "a",
                    &PrepareRequest {
                        size: drydock_protocol::Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
                        image_digest: "image".into(),
                        tools_digest: "tools".into(),
                    },
                )
                .await
                .unwrap(),
            size: Size { cpus: 2., memory_bytes: 1024, disk_bytes: 0 },
            egress: EgressRequest::default(),
            ssh_public_key: None,
        },
        scenarios: vec![
            drydock::conformance::Scenario::Prepare,
            drydock::conformance::Scenario::Lifecycle,
            drydock::conformance::Scenario::Observation,
            drydock::conformance::Scenario::Reach,
            drydock::conformance::Scenario::Refusal,
            drydock::conformance::Scenario::Destroy,
            drydock::conformance::Scenario::Metering,
        ],
        fixture_configuration: None,
        billing_sample_millis: 25,
        billing_settle_millis: 1,
        null_environment_id: None,
        auth_audit: None,
        timeouts: Default::default(),
        echo_relay: true,
        reach_probe: None,
        egress_probe: None,
    };
    let options_file = dir.path().join("conformance.json");
    std::fs::write(&options_file, serde_json::to_vec(&options).unwrap()).unwrap();
    let report: serde_json::Value = serde_json::from_str(
        &run(vec!["conformance".into(), "--provider".into(), "a".into(), "--options".into(), options_file.to_string_lossy().into_owned()])
            .await,
    )
    .unwrap();
    assert!(report["checks"].as_array().unwrap().iter().all(|check| check["passed"] == true));
    // A non-reference module must be refused before the CLI starts/configures
    // any host. The gate uses configured entrypoint, never provider display name.
    let mut non_reference: serde_json::Value = serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    non_reference[0]["configuration"]["modules"][0]["entrypoint"] = serde_json::json!("vendor-module");
    let gated_config = dir.path().join("live-hosts.json");
    std::fs::write(&gated_config, serde_json::to_vec(&non_reference).unwrap()).unwrap();
    let refused = tokio::process::Command::new(env!("CARGO_BIN_EXE_drydock"))
        .arg("--config")
        .arg(gated_config)
        .arg("--runtime-directory")
        .arg(dir.path().join("unused"))
        .args(["conformance", "--provider", "a", "--options"])
        .arg(&options_file)
        .output()
        .await
        .unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("requires --live"));
    assert!(!dir.path().join("unused").exists());
    run(vec!["destroy".into(), "rust".into(), "a".into(), environment.id]).await;
    assert!(client.list("a").await.unwrap().is_empty());
    server.abort();
}

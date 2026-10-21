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
                .arg(&config)
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
    let help = run(vec!["prepare".into(), "--help".into()]).await;
    for flag in ["--cpus", "--memory-bytes", "--disk-bytes"] {
        assert!(help.contains(flag));
    }
    // The reference host accepts byte-sized RAM and zero disk; Daytona does not.
    // Named size flags can be supplied in any order.
    let prepared: Prepared = serde_json::from_str(
        &run(vec![
            "prepare".into(),
            "rust".into(),
            "a".into(),
            "sha256:image".into(),
            "sha256:tools".into(),
            "--disk-bytes".into(),
            "0".into(),
            "--cpus".into(),
            "1".into(),
            "--memory-bytes".into(),
            "1024".into(),
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

// The CLI traverses real host and vendor sockets. This HTTP stand-in supplies
// validation/permission errors at the vendor boundary; no provider logic is faked.
#[tokio::test]
async fn cli_full_provider_errors() {
    use serde_json::json;
    use std::sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    };
    let status = Arc::new(AtomicU16::new(200));
    let current = status.clone();
    let router = axum::Router::new().fallback(move || {
        let current = current.clone();
        async move {
            let status = current.load(Ordering::SeqCst);
            let body = if status == 200 {
                json!({"items":[]})
            } else {
                json!({"message":"Cannot specify Sandbox resources when using a snapshot; credential test-secret-value"})
            };
            (axum::http::StatusCode::from_u16(status).unwrap(), axum::Json(body))
        }
    });

    for reference in [true, false] {
        for (upstream, class) in [(400, "internal"), (401, "credential_rejected"), (403, "refused"), (0, "unavailable")] {
            status.store(200, Ordering::SeqCst);
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let socket = dir.path().join("host.sock");
            let path = socket.clone();
            let vendor = rigging_replay_testkit::http_contract::StandIn::start("https://app.daytona.io", router.clone()).await;
            let host = drydock_host::Host::new(BTreeMap::from([
                ("reference".into(), Arc::new(drydock_host::reference::ReferenceModule) as Arc<dyn drydock_host::module::Module>),
                ("daytona".into(), Arc::new(CliDaytonaModule(vendor.http.clone())) as Arc<dyn drydock_host::module::Module>),
            ]));
            let server =
                tokio::spawn(async move { host.serve_unix(path, unsafe { libc::geteuid() }, std::future::pending()).await.unwrap() });
            let client = drydock::client::Client::unix(&socket).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while client.hello().await.is_err() {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            let credential = dir.path().join("credential");
            std::fs::write(&credential, "test-secret-value").unwrap();
            let kind = if reference { "reference" } else { "daytona" };
            let mut settings = json!({
                "organization_id":"org", "ssh_host_key":"ssh-ed25519 AAAA", "agent_command":"agent",
                "rate_limits":[]
            });
            if reference {
                settings = json!({"fixture":true,"fixture_push":true,"poll_interval_ms":3600000,"fault":{
                    "kind":class, "reason":format!("HTTP {upstream}: vendor validation test-secret-value"),
                    "provider_error":"vendor explanation test-secret-value", "retry_after":null
                }});
            }
            let configuration: HostConfiguration = serde_json::from_value(json!({
                "modules":[{"name":"module","entrypoint":kind}],
                "providers":[{"name":"provider-a","module":"module","settings":settings,
                    "credential":{"mode":"direct","credential_reference":"test"}}]
            }))
            .unwrap();
            // Configure before invoking the CLI so readiness/polling are exercised too.
            client.configure(&configuration).await.unwrap();
            client.credential("provider-a", Secret::new("test-secret-value")).await.unwrap();
            if !reference && upstream != 0 {
                // Let the immediate successful poll settle before injecting the route error.
                drydock::client::Observer::new(client.clone(), None).next().await.unwrap();
                status.store(upstream, Ordering::SeqCst);
            }
            if upstream == 0 {
                drop(vendor);
            }
            let spec = HostSpec {
                name: "rust".into(),
                connection: HostConnection::ExternalUnix { path: socket },
                configuration,
                credentials: BTreeMap::from([(
                    "test".into(),
                    drydock::credentials::CredentialReference::File { path: credential, json_field: None },
                )]),
            };
            let config = dir.path().join("hosts.json");
            std::fs::write(&config, serde_json::to_vec(&vec![spec]).unwrap()).unwrap();
            let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_drydock"))
                .arg("--config")
                .arg(&config)
                .arg("--runtime-directory")
                .arg(dir.path().join("run"))
                .args(["list", "rust", "provider-a"])
                .output()
                .await
                .unwrap();
            assert!(!output.status.success());
            let text = String::from_utf8(output.stderr).unwrap();
            for expected in [class, "provider-a", "list"] {
                assert!(text.contains(expected), "{text}");
            }
            assert!(!text.contains("test-secret-value"), "{text}");
            if upstream != 0 {
                assert!(text.contains(&upstream.to_string()), "{text}");
                assert!(text.contains(if reference { "vendor validation" } else { "Cannot specify Sandbox resources" }), "{text}");
                assert!(text.contains("<REDACTED>"), "{text}");
            } else {
                assert!(text.contains(if reference { "vendor validation" } else { "transport failed" }), "{text}");
            }
            if upstream == 400 {
                let request = dir.path().join("launch.json");
                std::fs::write(
                    &request,
                    serde_json::to_vec(&ProvisionRequest {
                        label: "bad-request".into(),
                        prepared: Prepared {
                            provider: "provider-a".into(),
                            id: "snapshot".into(),
                            image_digest: "image".into(),
                            tools_digest: "tools".into(),
                        },
                        size: Size { cpus: 2., memory_bytes: 4 << 30, disk_bytes: 10 << 30 },
                        egress: EgressRequest::default(),
                        ssh_public_key: None,
                    })
                    .unwrap(),
                )
                .unwrap();
                let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_drydock"))
                    .arg("--config")
                    .arg(&config)
                    .arg("--runtime-directory")
                    .arg(dir.path().join("run"))
                    .args(["launch", "rust", "provider-a"])
                    .arg(request)
                    .output()
                    .await
                    .unwrap();
                let text = String::from_utf8(output.stderr).unwrap();
                assert!(!output.status.success());
                for expected in [
                    "internal",
                    "provider-a",
                    "provision",
                    "400",
                    if reference { "vendor validation" } else { "Cannot specify Sandbox resources" },
                ] {
                    assert!(text.contains(expected), "{text}");
                }
                assert!(!text.contains("test-secret-value"), "{text}");
            }
            if upstream == 403 {
                assert_eq!(client.hello().await.unwrap().providers[0].readiness, Readiness::Ready);
            }
            server.abort();
        }
    }
}

// Substitute only the vendor network port; use the real Daytona module.
struct CliDaytonaModule(std::sync::Arc<dyn drydock_host::module::HttpClient>);
#[async_trait::async_trait]
impl drydock_host::module::Module for CliDaytonaModule {
    fn version(&self) -> &str {
        "test"
    }
    async fn configure(
        &self,
        config: &ProviderConfiguration,
        _: std::sync::Arc<dyn drydock_host::module::HttpClient>,
    ) -> drydock_host::module::Result<std::sync::Arc<dyn drydock_host::module::Provider>> {
        drydock_host::daytona::DaytonaModule.configure(config, self.0.clone()).await
    }
}

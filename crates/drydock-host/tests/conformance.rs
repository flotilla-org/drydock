use drydock::api::{ConfigUpdate, ProviderApi};
#[path = "support/public_server.rs"]
mod public_server;
use drydock::{
    HostConnection, HostSpec, Supervisor,
    conformance::{self, Options},
    credentials::*,
};
use drydock_protocol::*;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

// ADR 0070's same endpoint scenarios run against a standalone Rust binary;
// this harness imports no reference-module internals and owns configuration/auth.
#[tokio::test]
async fn reference_binary_passes_conformance() {
    let configuration = fixture_configuration();
    let (dir, mut binary, host) = start_binary(configuration.clone()).await;
    let client = public_server::client(host.client.clone(), dir.path().join("public.sock")).await;
    let prepared = host
        .client
        .prepare(
            "a",
            &PrepareRequest {
                size: drydock_protocol::Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
                platform: None,
                route: None,
                image_pull: None,
                image_digest: "image".into(),
                tools_digest: "tools".into(),
            },
        )
        .await
        .unwrap();
    // The reference module has no guest: exercise the reusable startup checks
    // with its explicit process model, through the real authenticated endpoint.
    let tools_environment = host
        .client
        .provision(
            "a",
            &ProvisionRequest {
                label: "tools-model".into(),
                prepared: prepared.clone(),
                size: Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
                egress: EgressRequest::Open,
                ssh_public_key: None,
            },
        )
        .await
        .unwrap()
        .into_inner();
    conformance::vessel_tools(
        &client,
        "a",
        &tools_environment.id,
        &ExecRequest { command: vec!["drydock-fixture".into(), "tools".into()] },
        "reference-model",
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    host.client.destroy("a", &tools_environment.id).await.unwrap();
    // Tiny sizes exercise the reference module; these are not Daytona resource requests.
    let options = Options {
        request: ProvisionRequest {
            label: "conformance".into(),
            prepared,
            size: Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
            egress: EgressRequest::default(),
            ssh_public_key: None,
        },
        // Policy scenarios run on the server-owned endpoint; TCP adapter
        // authentication is checked separately on the actual private listener.
        scenarios: conformance::Scenario::ALL.iter().copied().filter(|s| *s != conformance::Scenario::Authentication).collect(),
        fixture_configuration: Some(configuration),
        billing_sample_millis: 25,
        billing_settle_millis: 0,
        auth_audit: Some(vec![
            "python3".into(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../tools/auth-audit.py").into(),
            "--cargo-package".into(),
            "rigging-http-serve".into(),
        ]),
        timeouts: Default::default(),
        echo_relay: true,
        reach_probe: None,
        egress_probe: None,
    };
    let report = conformance::run(&client, "a", &options).await;
    assert!(report.passed(), "{}", serde_json::to_string_pretty(&report).unwrap());
    assert!(host.client.list("a").await.unwrap().is_empty());
    binary.kill().await.unwrap();
}

async fn start_binary(configuration: Configuration) -> (tempfile::TempDir, tokio::process::Child, drydock::HostHandle) {
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let token_file = dir.path().join("token");
    let binary = tokio::process::Command::new(env!("CARGO_BIN_EXE_drydock-host"))
        .args(["--tcp", &address.to_string(), "--token-file"])
        .arg(&token_file)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !token_file.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let bearer = Secret::new(tokio::fs::read_to_string(&token_file).await.unwrap().trim());
    let raw = drydock::client::Client::external(&format!("http://{address}"), bearer).unwrap();
    conformance::authentication(&raw, Duration::from_secs(5)).await.unwrap();
    let spec = HostSpec {
        name: "rust".into(),
        connection: HostConnection::External { url: format!("http://{address}"), token_file },
        credentials: configuration.providers.keys().map(|name| (name.clone(), CredentialReference::Env { name: "PATH".into() })).collect(),
        configuration,
    };
    let supervisor = Supervisor::new(dir.path().join("runtime"), Arc::new(BuiltinCredentials::default()));
    let mut host = supervisor.start(spec).await.unwrap();
    host.ready(Duration::from_secs(5)).await.unwrap();
    (dir, binary, host)
}
fn fixture_configuration() -> Configuration {
    serde_json::from_value(serde_json::json!({"providers":{"a":{"module":"reference","settings":{"fixture":true}},"b":{"module":"reference","settings":{"fixture":true}}}})).unwrap()
}
async fn python_report(fault: &str) -> conformance::Report {
    python_report_with(fault, conformance::Timeouts { record_seconds: 1, transition_seconds: 1, probe_seconds: 5, ..Default::default() })
        .await
}
async fn python_report_with(fault: &str, timeouts: conformance::Timeouts) -> conformance::Report {
    python_report_selection(fault, timeouts, conformance::Scenario::ALL.to_vec()).await
}
async fn python_report_selection(
    fault: &str,
    timeouts: conformance::Timeouts,
    scenarios: Vec<conformance::Scenario>,
) -> conformance::Report {
    let dir = tempfile::tempdir().unwrap();
    let address = dir.path().join("address");
    let mut process = tokio::process::Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/host.py"))
        .arg(&address)
        .arg(fault)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let url = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(url) = tokio::fs::read_to_string(&address).await
                && !url.is_empty()
            {
                break url;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let client = drydock::client::Client::external(&url, Secret::new("fixture-token")).unwrap();
    client.configure(ConfigUpdate::Replace(fixture_configuration())).await.unwrap();
    for provider in ["a", "b"] {
        client.credential(provider, Secret::new("fixture-token")).await.unwrap();
    }
    let mut options = Options {
        request: ProvisionRequest {
            label: "conformance".into(),
            prepared: Prepared {
                provider: "a".into(),
                id: "prepared".into(),
                platform: Platform::new("linux", "amd64"),
                image_digest: "image".into(),
                tools_digest: "tools".into(),
            },
            size: Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
            egress: EgressRequest::default(),
            ssh_public_key: None,
        },
        scenarios,
        fixture_configuration: Some(fixture_configuration()),
        billing_sample_millis: 25,
        billing_settle_millis: 0,
        auth_audit: Some(vec![
            "python3".into(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../tools/auth-audit.py").into(),
            "--python".into(),
            format!("{}.auth.py", address.display()),
        ]),
        timeouts,
        echo_relay: true,
        reach_probe: None,
        egress_probe: Some(ExecRequest { command: vec!["probe".into()] }),
    };
    if fault.starts_with("egress-") {
        options.request.egress = EgressRequest::DenyAll {
            direct: vec![Destination::HostPort { host: "127.0.0.1".parse().unwrap(), port: Port::new(443).unwrap() }],
        };
    }
    if fault == "neighbor" {
        let mut neighbor = options.request.clone();
        neighbor.label.push_str("-neighbor");
        client.provision("a", &neighbor).await.unwrap();
    }
    let report = conformance::run(&client, "a", &options).await;
    let remaining = client.list("a").await.unwrap();
    if fault == "cleanup-failure" || fault == "cleanup" {
        assert_eq!(remaining.len(), 1);
    } else if fault == "neighbor" {
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].label.as_deref(), Some("conformance-neighbor"));
    } else {
        assert!(remaining.is_empty(), "{fault} leaked resources");
    }
    process.kill().await.unwrap();
    report
}

// The scenario list is language independent. Every deliberate wire/lifecycle
// violation must fail its named check; a healthy independent host must pass.
#[tokio::test]
async fn independent_host_and_deliberate_violations() {
    let matrix: BTreeMap<String, String> = serde_json::from_str(include_str!("fixtures/broken-matrix.json")).unwrap();
    let healthy = python_report("egress-healthy").await;
    assert!(healthy.passed(), "{}", serde_json::to_string_pretty(&healthy).unwrap());
    let actual: std::collections::BTreeSet<_> = healthy.checks.iter().map(|check| check.name.as_str()).collect();
    let expected: std::collections::BTreeSet<_> = matrix.keys().map(String::as_str).collect();
    assert_eq!(actual, expected, "every reported check requires a matrix row; removing a check must fail too");
    for (check, fault) in matrix {
        eprintln!("MATRIX {check} <= {fault}");
        let report = python_report(&fault).await;
        assert!(
            report.checks.iter().any(|case| case.name == check && !case.passed),
            "{check} mutant {fault}: {}",
            serde_json::to_string_pretty(&report).unwrap()
        );
    }
}

// Partial creation failures and failed teardown still trigger an independently
// recorded cleanup sweep. Exact owned labels protect adjacent test runs.
#[tokio::test]
async fn cleanup_handles_partial_creation_transients_and_strays() {
    for fault in ["partial", "transient-destroy", "stray-cleanup"] {
        let report = python_report(fault).await;
        assert!(!report.passed(), "{fault} must report the original violation");
        let check = if fault == "partial" { "cleanup_after_failed_provision" } else { "cleanup" };
        assert!(report.checks.iter().any(|c| c.name == check && c.passed), "{fault}: {report:?}");
    }
    let failed = python_report("cleanup-failure").await;
    assert!(failed.checks.iter().any(|c| c.name == "cleanup" && !c.passed));
}

// Cold-start observation waits obey configured deadlines. The same delayed
// host fails a short deadline and passes when given sufficient time.
#[tokio::test]
async fn configurable_transition_deadlines() {
    let short = conformance::Timeouts { record_seconds: 1, transition_seconds: 1, ..Default::default() };
    let report = python_report_with("slow", short).await;
    assert!(report.checks.iter().any(|c| c.name == "running_event" && !c.passed && c.detail == "timeout"));
    let long = conformance::Timeouts { record_seconds: 3, transition_seconds: 3, ..Default::default() };
    let report = python_report_with("slow", long).await;
    assert!(report.passed(), "{report:?}");
}

// A temporary inspect failure is a state-check failure, not a missing event.
// The retained Running event still drives replay and subsequent cursor checks.
#[tokio::test]
async fn running_state_failure_preserves_replay_checks() {
    let report = python_report("inspect").await;
    assert!(report.checks.iter().any(|c| c.name == "running_state" && !c.passed && c.detail.starts_with("http 503 unavailable")));
    for name in ["running_event", "cursor_resume", "resume_stream", "stopped_event", "cleanup"] {
        assert!(report.checks.iter().any(|c| c.name == name && c.passed), "{name}: {report:?}");
    }
}

// CI executes the real guest script, including a denied UDP-connect regression.
#[test]
fn actual_guest_probe_contract() {
    let result = std::process::Command::new("python3")
        .args(["-m", "unittest", "discover", "-s", "tools", "-p", "test_egress_probe.py"])
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
        .status()
        .unwrap();
    assert!(result.success());
}

// Every recipe runs through the same endpoint runner and exchanges real bytes.
// Broken pins/tokens/relay data must fail that exact reach verdict in CI.
#[tokio::test]
async fn declared_reach_recipes_and_faults() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_path = dir.path().join("recipes.json");
    let mut servers = tokio::process::Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/recipe_servers.py"))
        .arg(&manifest_path)
        .stdin(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let manifest: serde_json::Value = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(bytes) = tokio::fs::read(&manifest_path).await
                && let Ok(value) = serde_json::from_slice(&bytes)
            {
                break value;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let mut configuration = fixture_configuration();
    configuration.providers.clear();
    for kind in ["relay", "tcp", "ws", "ssh"] {
        for broken in [false, true] {
            let name = format!("{kind}-{broken}");
            let mut recipe = if kind == "relay" { serde_json::json!({"kind":"relay","path":"unused"}) } else { manifest[kind].clone() };
            if broken && kind == "ssh" {
                recipe["host_key"] = manifest["wrong_key"].clone();
            }
            if broken && (kind == "tcp" || kind == "ws") {
                recipe["token"] = serde_json::json!("wrong-token");
            }
            let settings =
                serde_json::from_value(serde_json::json!({"fixture":true,"fixture_bad_relay":kind == "relay" && broken,"reach":recipe}))
                    .unwrap();
            configuration.providers.insert(name, ProviderConfiguration { module: "reference".into(), settings, credential: None });
        }
    }
    let (runtime, mut binary, host) = start_binary(configuration).await;
    let client = public_server::client(host.client.clone(), runtime.path().join("public.sock")).await;
    for kind in ["relay", "tcp", "ws", "ssh"] {
        for broken in [false, true] {
            let provider = format!("{kind}-{broken}");
            let options: Options = serde_json::from_value(serde_json::json!({
                "request":{"label":"recipes","prepared":{"provider":provider,"id":"prepare-in-run","image_digest":"image","tools_digest":"tools","platform":{"os":"linux","architecture":"amd64"}},"size":{"cpus":1.,"memory_bytes":1024,"disk_bytes":0}},
                "scenarios":["prepare","reach","destroy"],"echo_relay":kind=="relay",
                "reach_probe":if kind=="relay" {serde_json::Value::Null} else {serde_json::json!(["python3",concat!(env!("CARGO_MANIFEST_DIR"), "/../../tools/recipe-probe.py"),"--identity",manifest["identity"]])}
            })).unwrap();
            let report = conformance::run(&client, &provider, &options).await;
            let reach = report.checks.iter().find(|check| check.name == "reach_byte_stream").unwrap();
            assert_eq!(reach.passed, !broken, "{kind} broken={broken}: {report:?}");
            assert!(host.client.list(&provider).await.unwrap().is_empty());
        }
    }
    binary.kill().await.unwrap();
    drop(servers.stdin.take());
    assert!(tokio::time::timeout(Duration::from_secs(5), servers.wait()).await.unwrap().unwrap().success());
}

// Network execution port stand-in. Authentication must retain injection and
// cancel a stalled request at the configured deadline, without touching a socket.
struct AuthenticationPort {
    calls: std::sync::atomic::AtomicUsize,
    pending: bool,
    status: u16,
}
#[async_trait::async_trait]
impl drydock_host::module::HttpClient for AuthenticationPort {
    async fn execute(&self, _: reqwest::Request, _: &rigging_http_client::ChannelLabel) -> Result<http::Response<bytes::Bytes>, String> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.pending {
            std::future::pending::<()>().await;
        }
        Ok(http::Response::builder().status(self.status).body(bytes::Bytes::new()).unwrap())
    }
}
#[tokio::test(start_paused = true)]
async fn authentication_injection_timeout_and_bypass_matrix() {
    for (pending, status) in [(false, 401), (false, 200), (true, 401)] {
        let port = Arc::new(AuthenticationPort { calls: Default::default(), pending, status });
        let client = drydock::client::Client::external("http://127.0.0.1:9", Secret::new("token")).unwrap().with_http(port.clone());
        let result = conformance::authentication(&client, Duration::from_secs(2)).await;
        if pending {
            assert_eq!(result.unwrap_err(), "timeout");
        } else if status == 200 {
            assert!(result.unwrap_err().contains("authentication bypass"));
        } else {
            result.unwrap();
            assert_eq!(port.calls.load(std::sync::atomic::Ordering::SeqCst), 6);
        }
    }
}

#[test]
fn executable_authentication_audit_mutations() {
    let result = std::process::Command::new("python3")
        .args(["-m", "unittest", "discover", "-s", "tools", "-p", "test_auth_audit.py"])
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
        .status()
        .unwrap();
    assert!(result.success());
}

// Selecting a metadata-only scenario must not perform preparation, provisioning,
// teardown or optional host controls; a broken prepare implementation is irrelevant.
#[tokio::test]
async fn scenarios_are_individually_selectable() {
    let report = python_report_selection("prepare", Default::default(), vec![conformance::Scenario::Capabilities]).await;
    assert!(report.passed(), "{report:?}");
    assert_eq!(report.checks.iter().map(|check| check.name.as_str()).collect::<Vec<_>>(), ["hello", "capabilities"]);
}

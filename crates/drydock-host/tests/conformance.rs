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
    let dir = tempfile::tempdir().unwrap();
    let spec = HostSpec {
        name: "rust".into(),
        connection: HostConnection::Managed { command: vec![env!("CARGO_BIN_EXE_drydock-host").into()], runtime: None, proxy_environment: BTreeMap::new() },
        configuration: serde_json::from_value(serde_json::json!({"modules":[{"name":"memory","entrypoint":"reference"}],"providers":[{"name":"a","module":"memory","settings":{},"credential":{"mode":"direct","credential_reference":"test"}}]})).unwrap(),
        credentials: BTreeMap::from([("test".into(), CredentialReference::Env { name: "PATH".into() })]),
    };
    let supervisor = Supervisor::new(dir.path().join("runtime"), Arc::new(BuiltinCredentials::default()));
    let mut host = supervisor.start(spec).await.unwrap();
    host.ready(Duration::from_secs(5)).await.unwrap();
    let prepared = host.client.prepare("a", &PrepareRequest { image_digest: "image".into(), tools_digest: "tools".into() }).await.unwrap();
    let options = Options {
        request: ProvisionRequest {
            label: "conformance".into(),
            prepared,
            size: Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
            egress: EgressRequest::default(),
            ssh_public_key: None,
        },
        echo_relay: true,
        reach_probe: None,
        egress_probe: None,
    };
    let report = conformance::run(&host.client, "a", &options).await;
    assert!(report.passed(), "{}", serde_json::to_string_pretty(&report).unwrap());
    assert!(host.client.list("a").await.unwrap().is_empty());
}

async fn python_report(fault: &str) -> conformance::Report {
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
    let mut options = Options {
        request: ProvisionRequest {
            label: "conformance".into(),
            prepared: Prepared { provider: "a".into(), id: "prepared".into(), image_digest: "image".into(), tools_digest: "tools".into() },
            size: Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
            egress: EgressRequest::default(),
            ssh_public_key: None,
        },
        echo_relay: true,
        reach_probe: None,
        egress_probe: Some(ExecRequest { command: vec!["probe".into()] }),
    };
    if fault.starts_with("egress-") {
        options.request.egress = EgressRequest::DenyAll {
            direct: vec![Destination::HostPort { host: "127.0.0.1".parse().unwrap(), port: Port::new(443).unwrap() }],
        };
    }
    let report = conformance::run(&client, "a", &options).await;
    process.kill().await.unwrap();
    report
}

// The scenario list is language independent. Every deliberate wire/lifecycle
// violation must fail its named check; a healthy independent host must pass.
#[tokio::test]
async fn independent_host_and_deliberate_violations() {
    let healthy = python_report("none").await;
    assert!(healthy.passed(), "{}", serde_json::to_string_pretty(&healthy).unwrap());
    for fault in ["paused", "booting", "egress-healthy"] {
        let report = python_report(fault).await;
        assert!(report.passed(), "{fault}: {}", serde_json::to_string_pretty(&report).unwrap());
    }
    for (fault, check) in [
        ("auth", "authentication"),
        ("idempotent", "idempotent_label"),
        ("label", "list_readoption"),
        ("size", "running_event"),
        ("timestamp", "running_event"),
        ("gap", "running_event"),
        ("loss", "typed_loss"),
        ("destroy", "destroy_absent"),
        ("refusal", "typed_refusal"),
        ("reach", "reach_byte_stream"),
        ("null", "explicit_nulls"),
        ("usage", "usage"),
        ("semantic", "semantic_requests"),
        ("credits", "quota_before"),
        ("time-range", "running_event"),
        ("billing", "running_event"),
        ("egress-listed", "enforced_egress"),
        ("egress-canary", "enforced_egress"),
        ("egress-dns", "enforced_egress"),
        ("egress-root", "enforced_egress"),
    ] {
        let report = python_report(fault).await;
        assert!(!report.passed(), "fault {fault} passed");
        assert!(report.checks.iter().any(|c| c.name == check && !c.passed), "{fault}: {}", serde_json::to_string_pretty(&report).unwrap());
    }
}

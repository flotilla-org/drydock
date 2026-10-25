//! The language host uses the same endpoint checker as `drydock conformance`.
use drydock::{
    client::Client,
    conformance::{self, Options},
};
use drydock_protocol::*;
use std::{path::PathBuf, time::Duration};

// A real TCP process exercises the complete checker, including authentication and
// host configuration routes that the daemon intentionally does not forward.
#[tokio::test]
async fn typescript_reference_passes_full_conformance() {
    let Some(binary) = std::env::var_os("DRYDOCK_TYPESCRIPT_TEST_BIN") else { return };
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let token_file = dir.path().join("token");
    let mut child = tokio::process::Command::new("node")
        .arg(binary)
        .args(["--tcp", &address.to_string(), "--token-file"])
        .arg(&token_file)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let token = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(token) = tokio::fs::read_to_string(&token_file).await
                && !token.is_empty()
            {
                break token;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let client = Client::external(&format!("http://{address}"), Secret::new(token)).unwrap();
    let configuration: HostConfiguration = serde_json::from_value(serde_json::json!({"modules":[{"name":"memory","entrypoint":"reference"}],"providers":[{"name":"a","module":"memory","settings":{"fixture":true},"credential":{"mode":"direct","credential_reference":"test"}},{"name":"b","module":"memory","settings":{"fixture":true},"credential":{"mode":"direct","credential_reference":"test"}}]})).unwrap();
    client.configure(&configuration).await.unwrap();
    for name in ["a", "b"] {
        client.credential(name, Secret::new("test-only-token")).await.unwrap();
    }
    // The reference has no guest: exercise the shared startup contract using its
    // explicit tools process model over the same authenticated endpoint.
    let prepared = client
        .prepare(
            "a",
            &PrepareRequest {
                size: Size { cpus: 1.0, memory_bytes: 1024, disk_bytes: 0 },
                platform: None,
                image_digest: "image".into(),
                tools_digest: "tools".into(),
            },
        )
        .await
        .unwrap();
    let tools = client
        .provision(
            "a",
            &ProvisionRequest {
                label: "typescript-tools-model".into(),
                prepared,
                size: Size { cpus: 1.0, memory_bytes: 1024, disk_bytes: 0 },
                egress: EgressRequest::default(),
                ssh_public_key: None,
            },
        )
        .await
        .unwrap();
    conformance::vessel_tools(
        &client,
        "a",
        &tools.id,
        &ExecRequest { command: vec!["drydock-fixture".into(), "tools".into()] },
        "reference-model",
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    client.destroy("a", &tools.id).await.unwrap();
    let options: Options = serde_json::from_value(serde_json::json!({
        "request":{"label":"ts-full-conformance","prepared":{"provider":"a","id":"placeholder","image_digest":"image","tools_digest":"tools","platform":{"os":"linux","architecture":"amd64"}},"size":{"cpus":1,"memory_bytes":1024,"disk_bytes":0},"egress":{"mode":"deny_all","direct":[]}},
        "scenarios":conformance::Scenario::ALL,"fixture_configuration":configuration,"echo_relay":true,
        "auth_audit":["node",PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../hosts/typescript/scripts/audit-auth.mjs")],
        "timeouts":{"record_seconds":3,"transition_seconds":3,"probe_seconds":5}
    })).unwrap();
    let report = conformance::run(&client, "a", &options).await;
    child.kill().await.unwrap();
    assert!(report.passed(), "{}", serde_json::to_string_pretty(&report).unwrap());
}

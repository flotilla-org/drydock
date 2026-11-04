use drydock::api::{ConfigUpdate, ProviderApi};
use drydock_protocol::*;

fn configuration(value: serde_json::Value) -> Configuration {
    serde_json::from_value(value).unwrap()
}
fn preparation() -> PrepareRequest {
    PrepareRequest {
        size: Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
        platform: None,
        route: None,
        image_pull: None,
        image_digest: "image".into(),
        tools_digest: "tools".into(),
    }
}

// Destroy and inspect refuse what another instance made, the same way in every
// module, and leave it alone; what is ours, or already gone, is done.
#[tokio::test]
async fn destroy_refuses_a_foreign_environment_and_leaves_it() {
    let host = drydock_host::Host::new(drydock_host::reference::registry());
    host.configure(ConfigUpdate::Replace(configuration(
        serde_json::json!({"providers":{"a":{"module":"reference","settings":{"fixture":true}}}}),
    )))
    .await
    .unwrap();
    let prepared = host.prepare("a", &preparation()).await.unwrap();
    let request = |label: &str| ProvisionRequest {
        label: label.into(),
        prepared: prepared.clone(),
        size: Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
        egress: EgressRequest::Open,
        ssh_public_key: None,
    };
    let ours = host.provision("a", &request("ours")).await.unwrap().into_inner();
    let theirs = host.provision("a", &request("theirs")).await.unwrap().into_inner();
    let fixture = ExecRequest { command: vec!["drydock-fixture".into(), "foreign".into(), theirs.id.clone(), "".into()] };
    host.exec("a", &ours.id, &fixture).await.unwrap();

    for refused in [host.destroy("a", &theirs.id).await.map(drop), host.inspect("a", &theirs.id).await.map(drop)] {
        assert!(matches!(refused.unwrap_err(), drydock::client::Error::Protocol(ProtocolError::Refused { .. })));
    }
    assert_eq!(host.list("a").await.unwrap().iter().map(|e| e.id.clone()).collect::<Vec<_>>(), vec![ours.id.clone()]);

    host.destroy("a", &ours.id).await.unwrap();
    host.destroy("a", &ours.id).await.unwrap();
    assert!(host.inspect("a", &ours.id).await.is_err());
}

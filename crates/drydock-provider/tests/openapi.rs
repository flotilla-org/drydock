use drydock_provider::openapi;

// Like the public contract: a deterministic export must match the published file.
#[test]
fn checked_in_host_contract_does_not_drift() {
    assert_eq!(openapi::to_json(), include_str!("../../../host-openapi.json"));
}

// Every thin Rust-host route is published, including the private handle release.
// Source inventory comparison catches adding/removing a route without documenting it.
#[test]
fn document_covers_the_rust_router() {
    let value: serde_json::Value = serde_json::from_str(&openapi::to_json()).unwrap();
    let routes: std::collections::BTreeSet<_> = include_str!("../../drydock-host/src/lib.rs")
        .lines()
        .filter_map(|line| line.trim().strip_prefix(".route(\""))
        .map(|line| line.split('"').next().unwrap())
        .collect();
    assert_eq!(routes, value["paths"].as_object().unwrap().keys().map(String::as_str).collect());
    assert_eq!(
        value["paths"]["/private/providers/{provider}"]["delete"]["responses"]["204"]["description"],
        "Handle released; logical module binding remains loaded"
    );
}

// Utoipa's unit/tuple/generic fallbacks must not erase the actual Serde shapes.
#[test]
fn generic_arguments_keep_null_tuple_and_canonical_schema_rules() {
    use drydock_protocol::{CredentialMode, ExecRequest};
    use drydock_provider::{Call, Credentials};
    let value: serde_json::Value = serde_json::from_str(&openapi::to_json()).unwrap();
    let schemas = &value["components"]["schemas"];
    assert_eq!(schemas["Call_TupleUnit"]["properties"]["argument"]["type"], "null");
    let call = Call {
        credentials: Credentials::new(CredentialMode::Direct { credential_reference: "test-only".into() }),
        argument: ("opaque/id", ExecRequest { command: vec!["cat".into(), "".into()] }),
    };
    let serialized = serde_json::to_value(call).unwrap();
    assert_eq!(serialized["argument"], serde_json::json!(["opaque/id", {"command":["cat", ""]}]));
    for (name, payload) in [("ExecArgs", "ExecRequest"), ("ResumeArgs", "ResumeToken")] {
        assert_eq!(schemas[name]["prefixItems"][0]["type"], "string");
        assert_eq!(schemas[name]["prefixItems"][1]["$ref"], format!("#/components/schemas/{payload}"));
        assert_eq!(schemas[name]["items"], false);
        assert_eq!(schemas[name]["minItems"], 2);
        assert_eq!(schemas[name]["maxItems"], 2);
    }
    assert_eq!(schemas["Call_PrepareRequest"]["properties"]["argument"]["$ref"], "#/components/schemas/PrepareRequest");
    assert_eq!(schemas["ExecRequest"]["properties"]["command"]["prefixItems"][0]["minLength"], 1);
    assert!(schemas["ObservedEnvironment"]["properties"].get("egress_measured").is_some());
    assert!(schemas["SubscriptionRecord"].get("oneOf").is_some());
}

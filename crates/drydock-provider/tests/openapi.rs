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
    assert!(!routes.is_empty(), "Rust router inventory must not be empty");
    assert_eq!(routes, value["paths"].as_object().unwrap().keys().map(String::as_str).collect());
    assert_eq!(
        value["paths"]["/private/providers/{provider}"]["delete"]["responses"]["204"]["description"],
        "Handle released; logical module binding remains loaded"
    );
}

// Generic call arguments must reference the public generator's constrained
// schemas, rather than retaining Utoipa's unpatched inline copies.
#[test]
fn generic_calls_reuse_canonical_schema_rules() {
    let document = openapi::document();
    let schemas = &document["components"]["schemas"];
    assert_eq!(schemas["Call_PrepareRequest"]["properties"]["argument"]["$ref"], "#/components/schemas/PrepareRequest");
    assert_eq!(schemas["ExecRequest"]["properties"]["command"]["prefixItems"][0]["minLength"], 1);
}

// Validate real Serde samples at the cross-language seam, including rejection of
// swapped tuple elements, non-null unit, and a string duration (Utoipa defaults).
#[test]
fn serialized_provider_facts_validate_against_the_document() {
    use drydock_protocol::*;
    use drydock_provider::*;
    let document = drydock_provider::openapi::document();
    let credentials = || Credentials::new(CredentialMode::Direct { credential_reference: "test-only".into() });
    let samples = [
        (
            "Call_TupleUnit",
            serde_json::to_value(Call { credentials: credentials(), argument: () }).unwrap(),
            serde_json::json!({"credentials":credentials(),"argument":"not-null"}),
        ),
        (
            "Call_ExecArgs",
            serde_json::to_value(Call {
                credentials: credentials(),
                argument: ("opaque/id", ExecRequest { command: vec!["cat".into(), "".into()] }),
            })
            .unwrap(),
            serde_json::json!({"credentials":credentials(),"argument":[{"command":["cat"]},"opaque/id"]}),
        ),
        (
            "ObservationMode",
            serde_json::to_value(ObservationMode::Poll { interval: std::time::Duration::new(1, 2) }).unwrap(),
            serde_json::json!({"Poll":{"interval":"PT1S"}}),
        ),
    ];
    for (name, valid, invalid) in samples {
        let root = serde_json::json!({"$ref":format!("#/components/schemas/{name}"),"components":document["components"]});
        let validator = jsonschema::draft202012::new(&root).unwrap();
        assert!(validator.is_valid(&valid), "{name}: {valid}");
        assert!(!validator.is_valid(&invalid), "{name}: {invalid}");
    }
}

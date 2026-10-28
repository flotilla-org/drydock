use drydock_protocol::*;

// One published document derives from the same handlers used by host and server.
#[test]
fn checked_in_openapi_does_not_drift() {
    assert_eq!(drydock_client::api::openapi_json(), include_str!("../../../openapi.json"));
}

// Real Serde values cross the shared configuration, discovery and resource seam;
// counterexamples must fail without language-specific schema mirrors.
#[test]
fn serialized_values_match_the_document() {
    let document = drydock_client::api::openapi();
    let components = serde_json::to_value(document.components.unwrap()).unwrap();
    let config = Configuration {
        providers: [(
            "opaque /%".into(),
            ProviderConfiguration { module: "reference".into(), settings: Default::default(), credential: None },
        )]
        .into(),
    };
    let hello = Hello { protocol_version: PROTOCOL_VERSION.into(), host_version: "test".into(), loadable_modules: vec![] };
    let environment = Environment {
        id: "opaque /%".into(),
        label: None,
        provider: "opaque /%".into(),
        state: Observation::Running,
        granted_size: None,
        egress: Enforcement::Advisory,
        platform: None,
        egress_measured: true,
        egress_policy: Some("raw-policy".into()),
        timestamp: Some("2026-01-01T00:00:00Z".parse().unwrap()),
    };
    let samples = [
        ("Configuration", serde_json::to_value(config).unwrap(), serde_json::json!({"providers":{"p":{"module":false}}})),
        ("Hello", serde_json::to_value(hello).unwrap(), serde_json::json!({"protocol_version":false})),
        ("Environment", serde_json::to_value(environment).unwrap(), serde_json::json!({"id":5})),
        ("Reach", serde_json::to_value(Reach::Relay { path: "/opaque/path".into() }).unwrap(), serde_json::json!({"kind":"relay"})),
        ("ResumeToken", serde_json::to_value(ResumeToken { token: Secret::new("test-only") }).unwrap(), serde_json::json!({"token":5})),
    ];
    for (schema, valid, invalid) in samples {
        let root = serde_json::json!({"$ref":format!("#/components/schemas/{schema}"), "components":components});
        let validator = jsonschema::draft202012::new(&root).unwrap();
        assert!(validator.is_valid(&valid), "{schema}: {valid}");
        assert!(!validator.is_valid(&invalid), "{schema}: {invalid}");
    }
}

use drydock_protocol::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

fn fixture<T: Serialize + DeserializeOwned>(value: Value) {
    let decoded: T = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), value);
}

// Literal fixtures independently pin every variant of the externally tagged wire families.
// Empty strings/lists, null options and nested reasons exercise their boundary shapes.
#[test]
fn tagged_wire_fixtures() {
    for value in [
        json!({"state":"running"}),
        json!({"state":"stopped","cause":"paused_by_provider"}),
        json!({"state":"gone","cause":{"kind":"missing_on_list"}}),
        json!({"state":"unknown","reason":"provider_api_error"}),
        json!({"state":"unknown","reason":"provider_state_unknown"}),
    ] {
        fixture::<Observation>(value);
    }
    for value in [
        json!({"kind":"ssh","endpoint":"h:22","user":"u","host_key":"k"}),
        json!({"kind":"dial","url":"wss://h","token":"secret","expires_at":"2026-10-19T00:00:00Z"}),
        json!({"kind":"relay","path":"/relay"}),
    ] {
        fixture::<Reach>(value);
    }
    for value in [
        json!({"mode":"open"}),
        json!({"mode":"deny_all","direct":[]}),
        json!({"mode":"deny_all","direct":[{"kind":"host_port","host":"h","port":65535},{"kind":"cidr","cidr":"::/0"}]}),
    ] {
        fixture::<EgressRequest>(value);
    }
    for value in [
        json!({"mode":"direct","credential_reference":""}),
        json!({"mode":"proxied","placeholder_token":"secret","proxy_url":"http://localhost"}),
    ] {
        fixture::<CredentialMode>(value);
    }
    fixture::<ObserveRecord>(json!({"type":"snapshot","cursor":"","environments":[]}));
    // Partial snapshots explicitly mark unavailable providers; legacy complete snapshots omit the map.
    fixture::<ObserveRecord>(json!({"type":"snapshot","cursor":"c","environments":[],
        "unavailable_providers":{"a":{"kind":"unavailable","reason":"not ready","retry_after":null}}}));
    for event in [
        json!({"kind":"created"}),
        json!({"kind":"running","granted_size":{"cpus":1.0,"memory_bytes":0,"disk_bytes":0}}),
        json!({"kind":"stopped","cause":"guest_halted"}),
        json!({"kind":"paused","cause":"paused_by_provider"}),
        json!({"kind":"resumed"}),
        json!({"kind":"gone","cause":{"kind":"destroyed_by_request"}}),
    ] {
        fixture::<ObserveRecord>(json!({"type":"event","event":{"cursor":"c","id":"usage","provider":"p","label":null,
            "timestamp":"2026-10-19T00:00:00Z","timestamp_source":"provider","event":event}}));
    }
}

// Secret Debug must redact through enclosing types; JSON must retain the transport value.
#[test]
fn secret_debug_redacts_without_changing_wire() {
    let value = "sensitive-token";
    let secret = Secret::new(value);
    let refresh = CredentialRefresh { value: secret.clone() };
    let credential = CredentialMode::Proxied { placeholder_token: secret.clone(), proxy_url: "http://localhost".into() };
    let reach = Reach::Dial { url: "tcp://h".into(), token: secret.clone(), expires_at: "2026-10-19T00:00:00Z".parse().unwrap() };
    let resume = ResumeToken { token: secret };
    for debug in [format!("{refresh:?}"), format!("{credential:?}"), format!("{reach:?}"), format!("{resume:?}")] {
        assert!(!debug.contains(value));
        assert!(debug.contains("[REDACTED]"));
    }
    assert_eq!(serde_json::to_value(refresh).unwrap(), json!({"value":value}));
}

// Additive unknown fields are accepted, but unknown enum variants fail closed at version skew.
#[test]
fn compatibility_policy() {
    let value: Readiness = serde_json::from_value(json!({"status":"ready","future":true})).unwrap();
    assert_eq!(value, Readiness::Ready);
    assert!(serde_json::from_value::<Readiness>(json!({"status":"future"})).is_err());
    assert!(serde_json::from_value::<GoneCause>(json!({"kind":"future"})).is_err());
    assert_eq!(serde_json::from_value::<ResumeToken>(json!({"token":"a","future":true})).unwrap().token.expose(), "a");
}

// Owner ruling on issue #1: environments have one collection, no aliases; IDs stay opaque.
// Enumerating all paths/methods pins the complete routing surface independently of generation.
#[test]
fn route_and_version_contract() {
    let doc = serde_json::to_value(openapi::document()).unwrap();
    assert_eq!(doc["info"]["version"], PROTOCOL_VERSION);
    let expected = [
        ("/v1/hello", vec!["get"]),
        ("/v1/config", vec!["put"]),
        ("/v1/events", vec!["get"]),
        ("/v1/providers/{provider}/credential", vec!["put"]),
        ("/v1/providers/{provider}/prepare", vec!["post"]),
        ("/v1/providers/{provider}/usage", vec!["get"]),
        ("/v1/providers/{provider}/quota", vec!["get"]),
        ("/v1/providers/{provider}/environments", vec!["get", "post"]),
        ("/v1/providers/{provider}/environments/{id}", vec!["delete", "get"]),
        ("/v1/providers/{provider}/environments/{id}/reach", vec!["post"]),
        ("/v1/providers/{provider}/environments/{id}/relay", vec!["get"]),
        ("/v1/providers/{provider}/environments/{id}/suspend", vec!["post"]),
        ("/v1/providers/{provider}/environments/{id}/resume", vec!["post"]),
        ("/v1/providers/{provider}/environments/{id}/exec", vec!["post"]),
        ("/v1/providers/{provider}/environments/{id}/export", vec!["post"]),
    ];
    let paths = doc["paths"].as_object().unwrap();
    assert_eq!(paths.len(), expected.len());
    for (path, methods) in expected {
        let operations = paths[path].as_object().unwrap();
        assert_eq!(operations.len(), methods.len());
        for method in methods {
            assert!(operations.contains_key(method), "{method} {path}");
        }
    }
}

// Version negotiation must reject every mismatch, including empty and deceptively similar versions.
#[test]
fn hello_requires_exact_protocol_version() {
    // Version 1 assumes every snapshot is complete and must reject version 2 semantics.
    let old =
        Hello { protocol_version: "1".into(), host_version: "test".into(), modules: vec![], loadable_modules: vec![], providers: vec![] };
    assert!(!old.is_compatible());
    for version in [PROTOCOL_VERSION, "", "0", "1", "2", "3", "4", "5", "6.0.0", "6 "] {
        let hello = Hello {
            protocol_version: version.into(),
            host_version: "test".into(),
            modules: vec![],
            loadable_modules: vec![],
            providers: vec![],
        };
        assert_eq!(hello.is_compatible(), version == PROTOCOL_VERSION);
    }
}

// Approved protocol 4 uses explicit progress phases, UCUM units and exact
// decimal money. Resource additions are gated by the exact protocol version.
#[test]
fn progress_and_neutral_resource_wire() {
    for phase in ["preparing", "starting", "stopping", "reconfiguring", "destroying"] {
        fixture::<Observation>(json!({"state":"transitioning","phase":phase}));
    }
    fixture::<UsageMeasurements>(
        json!({"scope":{"kind":"organization","id":"opaque/eu"},"resources":{"cpu":{"amount":123.0,"unit":"{vCPU}.s"}},"cost":{"amount":"9007199254740993.000001","currency":"USD"}}),
    );
    fixture::<ResourceQuota>(json!({"key":{"region":"eu","class":"container","resource":"memory"},"unit":"By","in_use":0.0,"limit":null}));
    for amount in [json!(0.12), json!("NaN"), json!("-1"), json!("1e3"), json!(""), json!("1.")] {
        assert!(serde_json::from_value::<Cost>(json!({"amount":amount,"currency":"USD"})).is_err());
    }
    assert!(serde_json::from_value::<ResourceKind>(json!("vendor_magic")).is_err());
}

// Exact decimal strings roundtrip without arithmetic. The generator spans all
// u64 whole parts, including values beyond 2^53, plus nine fractional digits.
#[hegel::test]
fn exact_cost_roundtrips(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let whole = tc.draw(gs::integers::<u64>());
    let cost = Cost { amount: format!("{whole}.123456789"), currency: "EUR".into() };
    let encoded = serde_json::to_string(&cost).unwrap();
    assert_eq!(serde_json::from_str::<Cost>(&encoded).unwrap(), cost);
    assert!(!ResourceKind::Cpu.accepts_unit("By"));
    assert!(ResourceKind::Memory.accepts_unit("By.s"));
}

// Protocol 6 changes diagnostic field semantics and the permission-error mapping;
// protocol-5 peers must not pass the exact handshake after that contract change.
#[test]
fn diagnostic_contract_requires_protocol_six() {
    for (version, compatible) in [("5", false), ("6", true)] {
        let hello = Hello {
            protocol_version: version.into(),
            host_version: "test".into(),
            modules: vec![],
            loadable_modules: vec![],
            providers: vec![],
        };
        assert_eq!(hello.is_compatible(), compatible);
    }
}

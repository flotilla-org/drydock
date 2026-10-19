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
    fixture::<ObserveRecord>(json!({"type":"snapshot","cursor":"","sandboxes":[]}));
    for event in [
        json!({"kind":"created"}),
        json!({"kind":"running","granted_size":{"cpus":1.0,"memory_bytes":0,"disk_bytes":0}}),
        json!({"kind":"stopped","cause":"guest_halted"}),
        json!({"kind":"paused","cause":"paused_by_provider"}),
        json!({"kind":"resumed"}),
        json!({"kind":"gone","cause":{"kind":"destroyed_by_request"}}),
    ] {
        fixture::<ObserveRecord>(
            json!({"type":"event","event":{"cursor":"c","id":"usage","provider":"p","label":null,
            "timestamp":"2026-10-19T00:00:00Z","timestamp_source":"provider","event":event}}),
        );
    }
}

// Secret Debug must redact through enclosing types; JSON must retain the transport value.
#[test]
fn secret_debug_redacts_without_changing_wire() {
    let value = "sensitive-token";
    let secret = Secret(value.into());
    let refresh = CredentialRefresh {
        value: secret.clone(),
    };
    let credential = CredentialMode::Proxied {
        placeholder_token: secret.clone(),
        proxy_url: "http://localhost".into(),
    };
    let reach = Reach::Dial {
        url: "tcp://h".into(),
        token: secret.clone(),
        expires_at: "time".into(),
    };
    let resume = ResumeToken { token: secret };
    for debug in [
        format!("{refresh:?}"),
        format!("{credential:?}"),
        format!("{reach:?}"),
        format!("{resume:?}"),
    ] {
        assert!(!debug.contains(value));
        assert!(debug.contains("[REDACTED]"));
    }
    assert_eq!(
        serde_json::to_value(refresh).unwrap(),
        json!({"value":value})
    );
}

// Additive unknown fields are accepted, but unknown enum variants fail closed at version skew.
#[test]
fn compatibility_policy() {
    let value: Readiness = serde_json::from_value(json!({"status":"ready","future":true})).unwrap();
    assert_eq!(value, Readiness::Ready);
    assert!(serde_json::from_value::<Readiness>(json!({"status":"future"})).is_err());
    assert!(serde_json::from_value::<GoneCause>(json!({"kind":"future"})).is_err());
    assert_eq!(
        serde_json::from_value::<ResumeToken>(json!({"token":"a","future":true}))
            .unwrap()
            .token
            .0,
        "a"
    );
}

// Provider-wide operations must not shadow opaque sandbox IDs; wire versions share one source.
#[test]
fn route_and_version_contract() {
    let doc = serde_json::to_value(openapi::document()).unwrap();
    assert_eq!(doc["info"]["version"], PROTOCOL_VERSION);
    for operation in ["usage", "quota", "prepare", "credential"] {
        assert!(
            doc["paths"]
                .get(format!("/v1/{operation}/{{provider}}"))
                .is_some()
        );
        assert!(
            doc["paths"]
                .get(format!("/v1/providers/{{provider}}/{operation}"))
                .is_none()
        );
    }
}

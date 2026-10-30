use drydock_protocol::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

fn fixture<T: Serialize + DeserializeOwned>(value: Value) {
    let decoded: T = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), value);
}

// Literal fixtures independently pin every variant of the externally tagged wire families.
// Empty strings/lists, omitted options and nested reasons exercise their boundary shapes.
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
        json!({"kind":"ssh","endpoint":"h:22","user":"u","host_key":"k","reverse_forwards":true}),
        json!({"kind":"ssh","endpoint":"h:22","user":"u","host_key":"k","reverse_forwards":false}),
        json!({"kind":"dial","url":"wss://h","token":"secret","expires_at":"2026-10-19T00:00:00Z"}),
        json!({"kind":"relay","path":"/relay"}),
    ] {
        fixture::<Reach>(value);
    }
    // A host that says nothing about reverse forwards does not accept them.
    let reach: Reach = serde_json::from_value(json!({"kind":"ssh","endpoint":"h:22","user":"u","host_key":"k"})).unwrap();
    assert!(matches!(reach, Reach::Ssh { reverse_forwards: false, .. }));
    for value in [
        json!({"mode":"open"}),
        json!({"mode":"deny_all","direct":[]}),
        json!({"mode":"deny_all","direct":[{"kind":"host_port","host":"h","port":65535},{"kind":"cidr","cidr":"::/0"}]}),
    ] {
        fixture::<EgressRequest>(value);
    }
    fixture::<Configuration>(json!({"providers":{
        "a":{"module":"m","settings":{"nested":{"n":1}},"credential":{"env":"TOKEN"}},
        "b":{"module":"m","settings":{},"credential":{"file":"~/token","json_field":"token"}},
        "host":{"module":"m","settings":{}}
    }}));
    fixture::<ObserveRecord>(json!({"type":"snapshot","cursor":"","environments":[]}));
    // Partial snapshots explicitly mark unavailable providers; legacy complete snapshots omit the map.
    fixture::<ObserveRecord>(json!({"type":"snapshot","cursor":"c","environments":[],
        "unavailable_providers":{"a":{"kind":"unavailable","reason":"not ready"}}}));
    for event in [
        json!({"kind":"created"}),
        json!({"kind":"running","granted_size":{"cpus":1.0,"memory_bytes":0,"disk_bytes":0}}),
        json!({"kind":"stopped","cause":"guest_halted"}),
        json!({"kind":"paused","cause":"paused_by_provider"}),
        json!({"kind":"resumed"}),
        json!({"kind":"gone","cause":{"kind":"destroyed_by_request"}}),
    ] {
        fixture::<ObserveRecord>(json!({"type":"event","event":{"cursor":"c","id":"usage","provider":"p",
            "timestamp":"2026-10-19T00:00:00Z","timestamp_source":"provider","event":event}}));
    }
    // Exposures: the agreed request and response layouts (drydock#132), with
    // nothing that names SSH, keys, tokens or how the bytes travel.
    for event in [
        json!({"kind":"exposure","direction":"inward","name":"cleat","ready":false,
            "error":{"code":"vessel_unreachable","reason":"r"}}),
        json!({"kind":"exposure","direction":"outward","name":"lab","ready":false,"removed":true}),
        json!({"kind":"exposure","direction":"inward","name":"cleat","ready":true}),
    ] {
        fixture::<ObserveRecord>(json!({"type":"event","event":{"cursor":"c","id":"e","provider":"p","label":"l",
            "timestamp":"2026-10-19T00:00:00Z","timestamp_source":"adaptor","event":event}}));
    }
    fixture::<InwardRequest>(json!({"target":{"unix":"/run/cleat/cleat.sock"}}));
    fixture::<InwardRequest>(json!({"target":{"tcp":"127.0.0.1:8080"}}));
    fixture::<Inward>(json!({"name":"cleat","target":{"unix":"/run/cleat/cleat.sock"},
        "local":{"unix":"/run/drydock/exposures/e/cleat.sock"},"ready":true}));
    fixture::<OutwardRequest>(json!({"guest":{"unix":"/run/flotilla/crew.sock"},"destination":{"unix":"/srv/crew.sock"}}));
    fixture::<OutwardRequest>(json!({"guest":{"name":"forgejo.lab.flotilla.work","port":443},
        "destination":{"tcp":"forgejo.lab.flotilla.work:443"}}));
    fixture::<Outward>(json!({"name":"lab","guest":{"name":"forgejo.lab.flotilla.work","port":443},
        "destination":{"tcp":"forgejo.lab.flotilla.work:443"},"address":"127.77.0.1:443","resolved":"10.0.0.5:443",
        "ready":false,"error":{"code":"not_running","reason":"r"}}));
    for code in ["not_running", "vessel_unreachable", "refused", "unresolved"] {
        fixture::<ExposureError>(json!({"code":code,"reason":""}));
    }
}

// Secret Debug must redact through enclosing types; JSON must retain the transport value.
#[test]
fn secret_debug_redacts_without_changing_wire() {
    let value = "sensitive-token";
    let secret = Secret::new(value);
    let refresh = CredentialRefresh { value: secret.clone() };
    let reach = Reach::Dial { url: "tcp://h".into(), token: secret.clone(), expires_at: "2026-10-19T00:00:00Z".parse().unwrap() };
    let pull = RegistryCredential { username: "u".into(), secret: secret.clone() };
    let resume = ResumeToken { token: secret };
    for debug in [format!("{refresh:?}"), format!("{reach:?}"), format!("{resume:?}"), format!("{pull:?}")] {
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

// Version negotiation must reject every mismatch, including empty and deceptively similar versions.
#[test]
fn hello_requires_exact_protocol_version() {
    // Version 1 assumes every snapshot is complete and must reject version 2 semantics.
    let old = Hello { protocol_version: "1".into(), host_version: "test".into(), loadable_modules: vec![] };
    assert!(!old.is_compatible());
    for version in [PROTOCOL_VERSION, "", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9.0.0", "9 "] {
        let hello = Hello { protocol_version: version.into(), host_version: "test".into(), loadable_modules: vec![] };
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
    fixture::<ResourceQuota>(json!({"key":{"region":"eu","class":"container","resource":"memory"},"unit":"By","in_use":0.0}));
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

// Every image route and refusal variant has one pinned wire shape; a request
// may name a route and carry pull access, and omits both by default.
#[test]
fn image_route_wire_shapes() {
    for value in [
        json!({"route":"provider_push","protocol":"oci_distribution","credential_lifetime_seconds":3600,"tools_layer":"host"}),
        json!({"route":"provider_push","protocol":"oci_distribution","tools_layer":"host"}),
        json!({"route":"registry_pull","auth":"basic","registration":"provider_api","digest_references":true,"tools_layer":"provider"}),
        json!({"route":"registry_pull","auth":"anonymous","registration":"not_required","digest_references":false,"tools_layer":"provider"}),
        json!({"route":"registry_pull","auth":"basic","registration":"per_request","digest_references":true,"tools_layer":"host"}),
        json!({"route":"remote_build","input":"dockerfile","multi_stage":false,"tools_layer":"provider"}),
    ] {
        fixture::<ImageRoute>(value);
    }
    for value in [
        json!({"kind":"image_refused","reason":"r","refusal":{"cause":"unsupported_platform","platform":{"os":"linux","architecture":"arm64"}}}),
        json!({"kind":"image_refused","reason":"r","refusal":{"cause":"too_large","bytes":2,"limit_bytes":1}}),
        json!({"kind":"image_refused","reason":"r","refusal":{"cause":"push_credential_expired"}}),
    ] {
        fixture::<ProtocolError>(value);
    }
    let size = json!({"cpus": 1.0, "memory_bytes": 1024, "disk_bytes": 0});
    fixture::<PrepareRequest>(json!({"size": size, "route": "registry_pull", "image_pull": {"username": "u", "secret": "s"},
        "image_digest": "image", "tools_digest": "tools"}));
    for route in [ImageRouteKind::ProviderPush, ImageRouteKind::RegistryPull, ImageRouteKind::RemoteBuild] {
        assert_eq!(route.to_string().parse::<ImageRouteKind>().unwrap(), route);
        assert_eq!(serde_json::to_value(route).unwrap(), json!(route.to_string()));
    }
    assert!("push".parse::<ImageRouteKind>().is_err());
}

// The platform is recorded at prepare: prepared forms require it, requests and
// environments may omit it, and capabilities without platforms decode as none.
#[test]
fn platform_wire_shapes() {
    let amd64 = json!({"os": "linux", "architecture": "amd64"});
    let size = json!({"cpus": 1.0, "memory_bytes": 1024, "disk_bytes": 0});
    fixture::<Prepared>(json!({"provider": "p", "id": "i", "platform": amd64, "image_digest": "image", "tools_digest": "tools"}));
    assert!(
        serde_json::from_value::<Prepared>(json!({"provider": "p", "id": "i", "image_digest": "image", "tools_digest": "tools"})).is_err()
    );
    fixture::<PrepareRequest>(json!({"size": size, "platform": amd64, "image_digest": "image", "tools_digest": "tools"}));
    fixture::<PrepareRequest>(json!({"size": size, "image_digest": "image", "tools_digest": "tools"}));
    let environment = json!({"id": "e", "provider": "p", "state": {"state": "running"}, "egress": "advisory"});
    fixture::<Environment>(environment.clone());
    let mut recorded = environment;
    recorded["platform"] = amd64;
    fixture::<Environment>(recorded);
}

// Platform names become agent build file and variable names, so decoding
// accepts only plain lowercase OCI names; parsing takes os/architecture.
#[test]
fn platform_names_are_plain_oci_names() {
    let platform = |os: &str, architecture: &str| serde_json::from_value::<Platform>(json!({"os": os, "architecture": architecture}));
    assert_eq!(platform("linux", "arm64").unwrap(), Platform::new("linux", "arm64"));
    for (os, architecture) in [("", "amd64"), ("Linux", "amd64"), ("linux", "../x"), ("linux", "amd 64"), ("linux", &"a".repeat(33))] {
        assert!(platform(os, architecture).is_err(), "{os}/{architecture}");
    }
    assert_eq!("linux/amd64".parse::<Platform>().unwrap(), Platform::new("linux", "amd64"));
    assert_eq!(Platform::new("linux", "amd64").to_string(), "linux/amd64");
    for text in ["linux", "linux/", "/amd64", "Linux/amd64", "linux/amd64/v8"] {
        assert!(text.parse::<Platform>().is_err(), "{text}");
    }
}

// Absent optional fields are omitted on output, never written as `null`.
#[test]
fn absent_optional_fields_are_omitted() {
    let environment: Environment =
        serde_json::from_value(json!({"id": "e", "provider": "p", "state": {"state": "running"}, "egress": "advisory"})).unwrap();
    let written = serde_json::to_value(&environment).unwrap();
    for field in ["label", "granted_size", "platform", "timestamp", "egress_policy"] {
        assert!(written.get(field).is_none(), "{field} was written");
    }
    assert_eq!(serde_json::to_value(serde_json::from_value::<Quota>(json!({})).unwrap()).unwrap(), json!({}));
}

// Readers accept an omitted optional field and an explicit `null` alike.
#[test]
fn readers_accept_omitted_and_null_optional_fields() {
    let omitted = json!({"id": "e", "provider": "p", "state": {"state": "running"}, "egress": "advisory"});
    let nulled = json!({"id": "e", "label": null, "provider": "p", "state": {"state": "running"}, "granted_size": null, "platform": null,
        "timestamp": null, "egress_policy": null, "egress": "advisory"});
    let from_omitted: Environment = serde_json::from_value(omitted).unwrap();
    assert_eq!(from_omitted, serde_json::from_value(nulled).unwrap());
    assert_eq!(from_omitted.label, None);
    let quota: Quota = serde_json::from_value(json!({"credits_remaining": null, "credit_unit": null})).unwrap();
    assert_eq!(quota, serde_json::from_value(json!({})).unwrap());
}

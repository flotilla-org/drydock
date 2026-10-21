use drydock_protocol::*;
use serde_json::json;

// The shared wire decoder and emitted schema accept exactly the same host and CIDR
// syntax. Generator covers all IPv4 octets, IPv6 tails, zero/max ports and invalid masks.
#[hegel::test]
fn generated_destinations_share_schema_rules(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let octets: Vec<_> = (0..4).map(|_| tc.draw(gs::integers::<u8>().min_value(0).max_value(255))).collect();
    let ip = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
    let tail = tc.draw(gs::integers::<u16>().min_value(0).max_value(u16::MAX));
    let v6 = format!("2001:db8::{tail:x}");
    let port = tc.draw(gs::integers::<u16>().min_value(0).max_value(u16::MAX));
    let schema = serde_json::to_value(openapi::document()).unwrap();
    let host_schema = &schema["components"]["schemas"]["HostAddress"];
    let host_regex = regex::Regex::new(host_schema["pattern"].as_str().unwrap()).unwrap();
    for host in [
        ip.clone(),
        format!("::ffff:{ip}"),
        v6.clone(),
        format!("[{v6}]"),
        "host.example".into(),
        format!("{0}.{0}.{0}.{1}", "a".repeat(63), "a".repeat(61)),
        format!("{0}.{0}.{0}.{1}", "a".repeat(63), "a".repeat(62)),
        "-invalid".into(),
        "bad/path".into(),
    ] {
        let decoded = serde_json::from_value::<Destination>(json!({"kind":"host_port","host":host,"port":port}));
        assert_eq!(
            decoded.is_ok(),
            port > 0 && host.len() <= host_schema["maxLength"].as_u64().unwrap() as usize && host_regex.is_match(&host)
        );
    }
    let bits = tc.draw(gs::integers::<u8>().min_value(0).max_value(34));
    assert!(serde_json::from_value::<Destination>(json!({"kind":"cidr","cidr":format!("::ffff:{ip}/128")})).is_ok());
    assert_eq!(serde_json::from_value::<Destination>(json!({"kind":"cidr","cidr":format!("{ip}/{bits}")})).is_ok(), bits <= 32);
    for (cidr, valid) in [("::/0", true), ("2001:db8::/128", true), ("::/129", false), ("1.2.3.999/2", false)] {
        assert_eq!(serde_json::from_value::<Destination>(json!({"kind":"cidr","cidr":cidr})).is_ok(), valid);
    }
}

// Periods accept ordered RFC3339 instants (including empty intervals) and reject
// a reversed or malformed interval before any language host invokes a provider.
#[hegel::test]
fn generated_period_ordering(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let start = tc.draw(gs::integers::<i64>().min_value(-60).max_value(60));
    let delta = tc.draw(gs::integers::<i64>().min_value(-1).max_value(120));
    let timestamp = |seconds| chrono::DateTime::from_timestamp(1_700_000_000 + seconds, 0).unwrap().to_rfc3339();
    let value = json!({"start":timestamp(start),"end":timestamp(start+delta)});
    assert!(serde_json::from_value::<Period>(json!({"start":timestamp(start),"end":timestamp(start)})).is_ok());
    assert_eq!(serde_json::from_value::<Period>(value).is_ok(), delta >= 0);
    assert!(serde_json::from_value::<Period>(json!({"start":"bad","end":"2026-01-01T00:00:00Z"})).is_err());
}

// Every route documents the same error/status mapping as ProtocolError::status;
// clients can use the shared schema rather than reverse-engineering a language host.
#[test]
fn every_route_carries_typed_error_statuses() {
    let errors = [
        ProtocolError::NotFound { reason: "r".into() },
        ProtocolError::MethodNotAllowed { reason: "r".into() },
        ProtocolError::Refused { reason: "r".into() },
        ProtocolError::unavailable("r", None),
        ProtocolError::RateLimited { reason: "r".into(), retry_after: Some(2) },
        ProtocolError::QuotaExhausted { reason: "r".into() },
        ProtocolError::CredentialRejected { reason: "r".into() },
        ProtocolError::Internal { reason: "r".into(), provider_error: "sensitive".into() },
        ProtocolError::CommandFailed { reason: "r".into(), exit_code: 7, output: Secret::new("sensitive") },
    ];
    assert_eq!(errors.iter().map(ProtocolError::status).collect::<Vec<_>>(), [404, 405, 422, 503, 429, 402, 502, 500, 424]);
    let document = serde_json::to_value(openapi::document()).unwrap();
    for path in document["paths"].as_object().unwrap().values() {
        for operation in path.as_object().unwrap().values() {
            for error in &errors {
                let name = format!("Error{}", error.status());
                assert_eq!(operation["responses"][error.status().to_string()]["$ref"], format!("#/components/responses/{name}"));
                let body = &document["components"]["responses"][&name]["content"]["application/json"]["schema"];
                assert_eq!(body["properties"]["kind"]["enum"], json!([error.class()]));
                if error.retry_after().is_some() || error.status() == 503 {
                    assert!(document["components"]["responses"][&name]["headers"]["Retry-After"].is_object());
                }
            }
        }
    }
    assert_eq!(document["components"]["schemas"]["Timestamp"]["format"], "date-time");
    assert!(document["components"]["schemas"]["Period"]["description"].as_str().unwrap().contains("start must be <= end"));
}

// Typed instants compare by time, reject invalid wire dates, and never require
// modules to format strings. Schema constraints must survive generated renames.
#[test]
fn instants_and_shared_constraints() {
    assert_eq!("2026-01-01T00:00:00Z".parse::<Timestamp>().unwrap(), "2026-01-01T01:00:00+01:00".parse::<Timestamp>().unwrap());
    assert!(serde_json::from_value::<Reach>(json!({"kind":"dial","url":"x","token":"x","expires_at":"bad"})).is_err());
    let schemas = serde_json::to_value(openapi::document()).unwrap()["components"]["schemas"].clone();
    assert_eq!(schemas["Port"]["minimum"], 1);
    assert_eq!(schemas["Port"]["maximum"], 65535);
    assert_eq!(schemas["Cidr"]["pattern"], drydock_protocol::validation::cidr_pattern());
    assert_eq!(schemas["HostAddress"]["pattern"], drydock_protocol::validation::host_pattern());
    assert_eq!(schemas["HostAddress"]["maxLength"], 253);
    assert_eq!(schemas["Size"]["properties"]["cpus"]["exclusiveMinimum"], 0);
    assert_eq!(schemas["ProvisionRequest"]["properties"]["label"]["minLength"], 1);
    assert_eq!(schemas["CredentialRefresh"]["properties"]["value"]["minLength"], 1);
    assert_eq!(schemas["PrepareRequest"]["properties"]["image_digest"]["minLength"], 1);
    assert_eq!(schemas["ExecRequest"]["properties"]["command"]["prefixItems"][0]["minLength"], 1);
    assert_eq!(schemas["ExecRequest"]["properties"]["command"]["minItems"], 1);
    let error = ProtocolError::Internal { reason: "safe".into(), provider_error: "sensitive-value".into() };
    assert!(format!("{error:?}").contains("sensitive-value"));
    assert_eq!(serde_json::to_value(error).unwrap()["provider_error"], "sensitive-value");
}

// Generate across non-positive/positive CPUs and empty/nonempty strings. Decoding
// rejects invalid semantic requests before any module or language host runs them.
#[hegel::test]
fn generated_request_semantics(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let cpus = tc.draw(gs::integers::<i32>().min_value(-2).max_value(2));
    assert_eq!(serde_json::from_value::<Size>(json!({"cpus":cpus,"memory_bytes":0,"disk_bytes":0})).is_ok(), cpus > 0);
    let nonempty = tc.draw(gs::integers::<u8>().min_value(0).max_value(1)) != 0;
    let text = if nonempty { "ok" } else { "" };
    assert_eq!(
        serde_json::from_value::<PrepareRequest>(
            json!({"image_digest":text,"tools_digest":"tools","size":{"cpus":2.0,"memory_bytes":4294967296u64,"disk_bytes":10737418240u64}})
        )
        .is_ok(),
        nonempty
    );
    assert_eq!(serde_json::from_value::<CredentialRefresh>(json!({"value":text})).is_ok(), nonempty);
    assert_eq!(serde_json::from_value::<ExecRequest>(json!({"command":[text,""]})).is_ok(), nonempty);
    assert!(serde_json::from_value::<ExecRequest>(json!({"command":[]})).is_err());
}

// Proxy placeholder tokens have the same non-empty wire constraint as refreshed
// credentials. The generator spans empty, one-byte, and longer placeholder values.
#[hegel::test]
fn proxy_placeholder_requires_a_value(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let length = tc.draw(gs::integers::<usize>().min_value(0).max_value(64));
    let token = "x".repeat(length);
    let result = serde_json::from_value::<CredentialMode>(json!({
        "mode":"proxied", "placeholder_token":token, "proxy_url":"http://localhost:1234"
    }));
    assert_eq!(result.is_ok(), length > 0);
}

// Size is mandatory at prepare, and its existing CPU constraints apply there too.
#[test]
fn preparation_requires_valid_size() {
    for size in [json!(null), json!({"cpus":0,"memory_bytes":0,"disk_bytes":0})] {
        assert!(serde_json::from_value::<PrepareRequest>(json!({"image_digest":"image","tools_digest":"tools","size":size})).is_err());
    }
    assert!(serde_json::from_value::<PrepareRequest>(json!({"image_digest":"image","tools_digest":"tools"})).is_err());
}

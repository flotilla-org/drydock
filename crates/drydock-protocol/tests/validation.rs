use drydock_protocol::*;
use serde_json::json;

// The shared wire decoder and emitted schema accept exactly the same host and CIDR
// syntax. Generator covers all IPv4 octets, IPv6 tails, zero/max ports and invalid masks.
#[hegel::test]
fn generated_destinations_share_schema_rules(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let octets: Vec<_> = (0..4)
        .map(|_| tc.draw(gs::integers::<u8>().min_value(0).max_value(255)))
        .collect();
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
        let decoded = serde_json::from_value::<Destination>(
            json!({"kind":"host_port","host":host,"port":port}),
        );
        assert_eq!(
            decoded.is_ok(),
            port > 0
                && host.len() <= host_schema["maxLength"].as_u64().unwrap() as usize
                && host_regex.is_match(&host)
        );
    }
    let bits = tc.draw(gs::integers::<u8>().min_value(0).max_value(34));
    assert!(
        serde_json::from_value::<Destination>(
            json!({"kind":"cidr","cidr":format!("::ffff:{ip}/128")})
        )
        .is_ok()
    );
    assert_eq!(
        serde_json::from_value::<Destination>(json!({"kind":"cidr","cidr":format!("{ip}/{bits}")}))
            .is_ok(),
        bits <= 32
    );
    for (cidr, valid) in [
        ("::/0", true),
        ("2001:db8::/128", true),
        ("::/129", false),
        ("1.2.3.999/2", false),
    ] {
        assert_eq!(
            serde_json::from_value::<Destination>(json!({"kind":"cidr","cidr":cidr})).is_ok(),
            valid
        );
    }
}

// Periods accept ordered RFC3339 instants (including empty intervals) and reject
// a reversed or malformed interval before any language host invokes a provider.
#[hegel::test]
fn generated_period_ordering(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let start = tc.draw(gs::integers::<i64>().min_value(-60).max_value(60));
    let delta = tc.draw(gs::integers::<i64>().min_value(-1).max_value(120));
    let timestamp = |seconds| {
        chrono::DateTime::from_timestamp(1_700_000_000 + seconds, 0)
            .unwrap()
            .to_rfc3339()
    };
    let value = json!({"start":timestamp(start),"end":timestamp(start+delta)});
    assert!(
        serde_json::from_value::<Period>(json!({"start":timestamp(start),"end":timestamp(start)}))
            .is_ok()
    );
    assert_eq!(serde_json::from_value::<Period>(value).is_ok(), delta >= 0);
    assert!(
        serde_json::from_value::<Period>(json!({"start":"bad","end":"2026-01-01T00:00:00Z"}))
            .is_err()
    );
}

// Every route documents the same error/status mapping as ProtocolError::status;
// clients can use the shared schema rather than reverse-engineering a language host.
#[test]
fn every_route_carries_typed_error_statuses() {
    let errors = [
        ProtocolError::Refused { reason: "r".into() },
        ProtocolError::Unavailable {
            reason: "r".into(),
            retry_after: None,
        },
        ProtocolError::RateLimited {
            reason: "r".into(),
            retry_after: Some(2),
        },
        ProtocolError::QuotaExhausted { reason: "r".into() },
        ProtocolError::CredentialRejected { reason: "r".into() },
        ProtocolError::Internal {
            reason: "r".into(),
            provider_error: "sensitive".into(),
        },
    ];
    assert_eq!(
        errors.iter().map(ProtocolError::status).collect::<Vec<_>>(),
        [422, 503, 429, 402, 502, 500]
    );
    let document = serde_json::to_value(openapi::document()).unwrap();
    for path in document["paths"].as_object().unwrap().values() {
        for operation in path.as_object().unwrap().values() {
            for error in &errors {
                assert_eq!(
                    operation["responses"][error.status().to_string()]["content"]["application/json"]
                        ["schema"]["$ref"],
                    "#/components/schemas/ProtocolError"
                );
            }
        }
    }
    assert_eq!(
        document["components"]["schemas"]["Timestamp"]["format"],
        "date-time"
    );
    assert!(
        document["components"]["schemas"]["Period"]["description"]
            .as_str()
            .unwrap()
            .contains("start must be <= end")
    );
}

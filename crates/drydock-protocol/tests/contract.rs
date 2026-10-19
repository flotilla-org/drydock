use drydock_protocol::*;

// ADR 0070 requires the checked-in document to match the Rust source of truth.
// One exact comparison covers this deterministic generation boundary.
#[test]
fn checked_in_openapi_does_not_drift() {
    assert_eq!(openapi::to_json(), include_str!("../../../openapi.json"));
}

// Omitted egress must deny all; Open requires an explicit placement opt-in.
#[test]
fn omitted_egress_denies_all() {
    let request: ProvisionRequest = serde_json::from_value(serde_json::json!({
        "label": "env", "prepared": {"provider":"p", "id":"prepared",
        "image_digest":"sha256:image", "tools_digest":"sha256:tools"},
        "size":{"cpus":1.0,"memory_bytes":0,"disk_bytes":0}
    }))
    .unwrap();
    assert_eq!(request.egress, EgressRequest::DenyAll { direct: vec![] });
}

// Typed errors preserve reasons, retry hints and raw provider errors through JSON.
// Explicit generator spans every variant, empty text, and retry delay boundaries.
#[test]
fn errors_round_trip() {
    for reason in ["", "vendor failed: ü\n"] {
        let reason = reason.to_owned();
        let mut errors = vec![
            ProtocolError::Refused {
                reason: reason.clone(),
            },
            ProtocolError::QuotaExhausted {
                reason: reason.clone(),
            },
            ProtocolError::CredentialRejected {
                reason: reason.clone(),
            },
            ProtocolError::Internal {
                reason: reason.clone(),
                provider_error: reason.clone(),
            },
        ];
        for retry_after in [None, Some(0), Some(u64::MAX)] {
            errors.push(ProtocolError::Unavailable {
                reason: reason.clone(),
                retry_after,
            });
            errors.push(ProtocolError::RateLimited {
                reason: reason.clone(),
                retry_after,
            });
        }
        for error in errors {
            let json = serde_json::to_string(&error).unwrap();
            assert_eq!(serde_json::from_str::<ProtocolError>(&json).unwrap(), error);
        }
    }
}

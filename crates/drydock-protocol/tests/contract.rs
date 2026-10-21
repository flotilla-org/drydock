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
            ProtocolError::Refused { reason: reason.clone() },
            ProtocolError::QuotaExhausted { reason: reason.clone() },
            ProtocolError::CredentialRejected { reason: reason.clone() },
            ProtocolError::Internal { reason: reason.clone(), provider_error: reason.clone() },
            ProtocolError::CommandFailed { reason: reason.clone(), exit_code: 7, output: Secret::new(reason.clone()) },
        ];
        for retry_after in [None, Some(0), Some(u64::MAX)] {
            errors.push(ProtocolError::unavailable(reason.clone(), retry_after));
            errors.push(ProtocolError::RateLimited { reason: reason.clone(), retry_after });
        }
        for error in errors {
            let json = serde_json::to_string(&error).unwrap();
            assert_eq!(serde_json::from_str::<ProtocolError>(&json).unwrap(), error);
        }
    }
}

// Provider explanations survive content masking; credentials are removed from
// reason, raw detail and secret command output. Enumerate all error variants,
// empty/Unicode/repeated text, duplicate credentials and retry boundaries.
#[test]
fn diagnostic_masking_preserves_error_contract() {
    for secret in ["token-123", "秘密", "quoted\"token"] {
        for copies in [0, 1, 3] {
            let text = format!("vendor validation {}", secret.repeat(copies));
            let errors = [
                ProtocolError::NotFound { reason: text.clone() },
                ProtocolError::MethodNotAllowed { reason: text.clone() },
                ProtocolError::Refused { reason: text.clone() },
                ProtocolError::CredentialRejected { reason: text.clone() },
                ProtocolError::QuotaExhausted { reason: text.clone() },
                ProtocolError::RateLimited { reason: text.clone(), retry_after: Some(u64::MAX) },
                ProtocolError::Unavailable { reason: text.clone(), retry_after: Some(0), provider_error: Some(text.clone()) },
                ProtocolError::Internal { reason: text.clone(), provider_error: text.clone() },
                ProtocolError::CommandFailed { reason: text.clone(), exit_code: 1, output: Secret::new(&text) },
            ];
            for original in errors {
                let error = original.clone().diagnostic_context("provider", "provision", &["", secret, secret]);
                assert_eq!(error.class(), original.class());
                assert_eq!(error.status(), original.status());
                assert_eq!(error.retry_after(), original.retry_after());
                for view in [error.to_string(), format!("{error:?}"), serde_json::to_string(&error).unwrap()] {
                    assert!(!view.contains(secret), "{view}");
                    assert!(view.contains("vendor validation"), "{view}");
                }
                assert!(error.to_string().contains("provider provider operation provision"));
            }
        }
    }
}

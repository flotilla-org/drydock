use drydock_protocol::*;

// Omitted egress must deny all; Open requires an explicit placement opt-in.
#[test]
fn omitted_egress_denies_all() {
    let request: ProvisionRequest = serde_json::from_value(serde_json::json!({
        "label": "env", "prepared": {"provider":"p", "id":"prepared", "platform": {"os":"linux","architecture":"amd64"},
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

// Vendor JSON may escape credential bytes. Masking must happen before the
// diagnostic limit, and Display must not emit vendor-controlled log lines.
#[test]
fn escaped_and_long_diagnostics_are_safe() {
    let secret = "quoted\"token\\秘密";
    let encoded = serde_json::to_string(secret).unwrap();
    let detail = format!("validation {encoded}");
    let error = ProtocolError::Internal { reason: "vendor\nFORGED\u{1b}[31m".into(), provider_error: detail }.diagnostic_context(
        "p",
        "list",
        &[secret],
    );
    assert!(!error.to_string().contains(&encoded));
    assert!(!error.to_string().contains('\n'));
    assert!(!error.to_string().contains('\u{1b}'));
    let detail = format!("{}key-abcdef trailing", "x".repeat(16381));
    let error =
        ProtocolError::Internal { reason: "validation".into(), provider_error: detail }.diagnostic_context("p", "list", &["key-abcdef"]);
    let ProtocolError::Internal { provider_error, .. } = error else { unreachable!() };
    assert!(provider_error.len() <= 16384);
    assert!(!provider_error.contains("key-"));
}

// Credential echoes can be literal, JSON escaped (including UTF-16), percent
// encoded, or standard/URL-safe base64 with or without padding. Short values and
// overlapping patterns must not re-mask inserted markers.
#[test]
fn encoded_credential_echoes_and_short_values_are_masked() {
    for echo in [
        "quoted\\\"token\\\\\\u79d8\\u5bc6",
        "quoted%22token%5C%E7%A7%98%E5%AF%86",
        "quoted%22token%5c%e7%a7%98%e5%af%86",
        "cXVvdGVkInRva2VuXOenmOWvhg==",
        "cXVvdGVkInRva2VuXOenmOWvhg",
    ] {
        let error = ProtocolError::Internal { reason: "validation".into(), provider_error: echo.into() }.diagnostic_context(
            "p",
            "list",
            &["quoted\"token\\秘密"],
        );
        let ProtocolError::Internal { provider_error, .. } = error else { unreachable!() };
        assert_eq!(provider_error, "<REDACTED>", "{echo}");
    }
    let error =
        ProtocolError::Internal { reason: "AAA".into(), provider_error: "AAA".into() }.diagnostic_context("p", "list", &["", "A", "AA"]);
    let ProtocolError::Internal { provider_error, .. } = error else { unreachable!() };
    assert_eq!(provider_error, "<REDACTED><REDACTED>");
}

// A retained masker must preserve every earlier credential across insertions,
// repeated deliveries and insertion order; caching cannot drop old encodings.
#[test]
fn cached_masker_retains_all_delivered_credentials() {
    for sequence in [vec!["old-key", "new-key", "old-key"], vec!["new-key", "old-key", "new-key"], vec!["", "old-key", "new-key"]] {
        let mut masker = DiagnosticMasker::default();
        let mut delivered = Vec::new();
        for secret in sequence {
            masker.remember(secret);
            delivered.push(secret);
            let error = ProtocolError::Internal {
                reason: "validation old-key new-key".into(),
                provider_error: "vendor old-key new-key b2xkLWtleQ== bmV3LWtleQ==".into(),
            };
            let actual = masker.context(error.clone(), "p", "list");
            assert_eq!(actual, error.diagnostic_context("p", "list", &delivered));
            let ProtocolError::Internal { provider_error, .. } = actual else { unreachable!() };
            if delivered.contains(&"old-key") {
                assert!(!provider_error.contains("old-key"));
                assert!(!provider_error.contains("b2xkLWtleQ=="));
            }
            if delivered.contains(&"new-key") {
                assert!(!provider_error.contains("new-key"));
                assert!(!provider_error.contains("bmV3LWtleQ=="));
            }
        }
    }
}

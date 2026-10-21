//! Credential masking happens before diagnostic truncation or human rendering.
use crate::{ProtocolError, Secret};
use base64::{Engine, engine::general_purpose};

const LIMIT: usize = 16 * 1024;
const URL_RESERVED: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

fn patterns(secrets: &[&str]) -> Vec<String> {
    let mut patterns = Vec::new();
    for secret in secrets.iter().filter(|secret| !secret.is_empty()) {
        patterns.push((*secret).to_owned());
        let json = serde_json::to_string(secret).expect("string serialization");
        let json = &json[1..json.len() - 1];
        patterns.push(json.to_owned());
        // JSON serializers may escape non-ASCII text as UTF-16 code units.
        for upper in [false, true] {
            let mut ascii = String::new();
            for ch in json.chars() {
                if ch.is_ascii() {
                    ascii.push(ch);
                } else {
                    for unit in ch.encode_utf16(&mut [0; 2]) {
                        use std::fmt::Write;
                        if upper {
                            write!(ascii, "\\u{unit:04X}").unwrap();
                        } else {
                            write!(ascii, "\\u{unit:04x}").unwrap();
                        }
                    }
                }
            }
            patterns.push(ascii);
        }
        let percent = percent_encoding::utf8_percent_encode(secret, URL_RESERVED).to_string();
        patterns.push(percent.replace("%20", "+"));
        patterns.push(percent.clone());
        // Hex digits in percent encoding are case-insensitive.
        let mut lower = percent.into_bytes();
        let mut i = 0;
        while i + 2 < lower.len() {
            if lower[i] == b'%' {
                lower[i + 1].make_ascii_lowercase();
                lower[i + 2].make_ascii_lowercase();
                i += 3;
            } else {
                i += 1;
            }
        }
        patterns.push(String::from_utf8(lower).expect("UTF-8 percent encoding"));
        for engine in
            [general_purpose::STANDARD, general_purpose::STANDARD_NO_PAD, general_purpose::URL_SAFE, general_purpose::URL_SAFE_NO_PAD]
        {
            patterns.push(engine.encode(secret));
        }
    }
    patterns.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    patterns.dedup();
    patterns
}

fn mask(text: &str, patterns: &[String]) -> String {
    let mut masked = String::new();
    let mut rest = text;
    loop {
        // Leftmost match, longest on ties. Inserted markers are never scanned:
        // even a one-character credential cannot corrupt a redaction marker.
        let next = patterns
            .iter()
            .filter_map(|pattern| rest.find(pattern).map(|at| (at, pattern.len())))
            .min_by_key(|(at, len)| (*at, std::cmp::Reverse(*len)));
        let Some((at, len)) = next else {
            masked.push_str(rest);
            break;
        };
        masked.push_str(&rest[..at]);
        masked.push_str("<REDACTED>");
        rest = &rest[at + len..];
    }
    masked
}
fn bounded(text: String) -> String {
    if text.len() <= LIMIT {
        return text;
    }
    let end = text.floor_char_boundary(LIMIT - "...<truncated>".len());
    format!("{}...<truncated>", &text[..end])
}

/// Prevent provider-controlled newlines, terminal escapes or other controls from
/// forging log records. JSON and Debug already escape controls themselves.
pub(super) struct LogText<'a>(pub &'a str);
impl std::fmt::Display for LogText<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for ch in self.0.chars() {
            if ch.is_control() {
                write!(f, "{}", ch.escape_debug())?;
            } else {
                write!(f, "{ch}")?;
            }
        }
        Ok(())
    }
}
/// Cached credential patterns for repeated host diagnostics. This type deliberately
/// has no Debug/Display implementation because patterns include credential values.
#[derive(Default)]
pub struct DiagnosticMasker {
    patterns: Vec<String>,
}
impl DiagnosticMasker {
    /// Add a credential's common literal/encoded forms once, at delivery time.
    pub fn remember(&mut self, secret: &str) {
        self.patterns.extend(patterns(&[secret]));
        self.patterns.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        self.patterns.dedup();
    }
    /// Mask complete diagnostics before bounding text or rendering for operators.
    pub fn context(&self, mut error: ProtocolError, provider: &str, operation: &str) -> ProtocolError {
        let patterns = &self.patterns;
        let reason = match &mut error {
            ProtocolError::NotFound { reason }
            | ProtocolError::MethodNotAllowed { reason }
            | ProtocolError::Refused { reason }
            | ProtocolError::Unavailable { reason, .. }
            | ProtocolError::RateLimited { reason, .. }
            | ProtocolError::QuotaExhausted { reason }
            | ProtocolError::CredentialRejected { reason }
            | ProtocolError::CommandFailed { reason, .. }
            | ProtocolError::Internal { reason, .. } => reason,
        };
        *reason = bounded(mask(&format!("provider {provider} operation {operation}: {reason}"), patterns));
        match &mut error {
            ProtocolError::Internal { provider_error, .. } => *provider_error = bounded(mask(provider_error, patterns)),
            ProtocolError::Unavailable { provider_error: Some(detail), .. } => *detail = bounded(mask(detail, patterns)),
            ProtocolError::CommandFailed { output, .. } => *output = Secret::new(mask(output.expose(), patterns)),
            _ => {}
        }
        error
    }
}

impl ProtocolError {
    /// Convenience for a single diagnostic. Hosts with retained credential state
    /// should cache a DiagnosticMasker instead of deriving patterns on each error.
    pub fn diagnostic_context(self, provider: &str, operation: &str, secrets: &[&str]) -> Self {
        let mut masker = DiagnosticMasker::default();
        for secret in secrets {
            masker.remember(secret);
        }
        masker.context(self, provider, operation)
    }
}

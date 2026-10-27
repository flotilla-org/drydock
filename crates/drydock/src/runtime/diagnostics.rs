//! Credential-aware masking of public diagnostics.
use super::*;

// Keep active values plus a bounded recent history, shared across providers.
// Derive patterns at delivery; rebuild only when an old value is evicted.
pub(super) const RECENT_CREDENTIAL_LIMIT: usize = 32;
#[derive(Default)]
pub(super) struct DiagnosticSecrets {
    pub(super) current: BTreeMap<String, Secret>,
    pub(super) recent: VecDeque<Secret>,
    pub(super) masker: Arc<DiagnosticMasker>,
}
impl DiagnosticSecrets {
    pub(super) fn contains(&self, secret: &Secret) -> bool {
        self.current.values().any(|value| value == secret) || self.recent.contains(secret)
    }
    pub(super) fn remember(&mut self, provider: &str, secret: Secret) {
        if self.current.get(provider) == Some(&secret) {
            return;
        }
        let known = self.contains(&secret);
        if let Some(previous) = self.current.insert(provider.to_owned(), secret.clone()) {
            self.recent.retain(|value| value != &previous);
            if !self.current.values().any(|value| value == &previous) {
                self.recent.push_back(previous);
            }
        }
        self.recent.retain(|value| value != &secret);
        let evicted = self.recent.len() > RECENT_CREDENTIAL_LIMIT;
        if evicted {
            self.recent.pop_front();
            self.masker = Arc::default();
            for value in self.current.values().chain(self.recent.iter()) {
                Arc::make_mut(&mut self.masker).remember(value.expose());
            }
        } else if !known {
            Arc::make_mut(&mut self.masker).remember(secret.expose());
        }
        if !known && (1..4).contains(&secret.expose().len()) {
            tracing::debug!(
                credential_bytes = secret.expose().len(),
                "short credential registered; diagnostic masking may obscure unrelated text"
            );
        }
    }
}
pub(super) fn mask_readiness(readiness: Readiness, masker: &DiagnosticMasker) -> Readiness {
    match readiness {
        Readiness::MissingCredential { reason } => Readiness::MissingCredential { reason: masker.text(&reason) },
        Readiness::MissingTool { reason } => Readiness::MissingTool { reason: masker.text(&reason) },
        Readiness::VersionMismatch { reason } => Readiness::VersionMismatch { reason: masker.text(&reason) },
        Readiness::Unknown { reason } => Readiness::Unknown { reason: masker.text(&reason) },
        Readiness::Ready => Readiness::Ready,
    }
}
// Readiness transitions log only a static status label, never the reason.
// They are not serialized as events; hello masks reasons at its wire boundary.
pub(super) fn readiness_status(value: &Readiness) -> &'static str {
    match value {
        Readiness::Ready => "ready",
        Readiness::MissingTool { .. } => "missing_tool",
        Readiness::MissingCredential { .. } => "missing_credential",
        Readiness::VersionMismatch { .. } => "version_mismatch",
        Readiness::Unknown { .. } => "unknown",
    }
}

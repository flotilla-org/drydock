//! Credential ownership stays with the embedder. No resolver executes commands.
use async_trait::async_trait;
use drydock_protocol::Secret;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::SystemTime};
use tokio::sync::watch;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialReference {
    File { path: PathBuf, json_field: Option<String> },
    Env { name: String },
    Embedder { reference: String },
}
#[derive(Debug, Clone)]
pub struct Credential {
    pub value: Secret,
    pub expires_at: Option<SystemTime>,
}
#[derive(Debug, thiserror::Error)]
#[error("credential unavailable")]
pub struct CredentialError;

#[async_trait]
pub trait CredentialSource: Send + Sync {
    async fn resolve(&self, reference: &CredentialReference) -> Result<Credential, CredentialError>;
    /// Notifications are hints: the supervisor re-resolves all direct credentials.
    /// Send a new revision after changing the underlying credential store.
    fn changes(&self) -> watch::Receiver<u64>;
}
/// Built-ins are polled at the supervisor's refresh interval, so file replacement
/// and environment changes do not require an OS-specific notification watcher.
pub struct BuiltinCredentials {
    changes: watch::Sender<u64>,
}
impl Default for BuiltinCredentials {
    fn default() -> Self {
        let (changes, _) = watch::channel(0);
        Self { changes }
    }
}
#[async_trait]
impl CredentialSource for BuiltinCredentials {
    async fn resolve(&self, reference: &CredentialReference) -> Result<Credential, CredentialError> {
        let value = match reference {
            CredentialReference::Env { name } => std::env::var(name).map_err(|_| CredentialError)?,
            CredentialReference::File { path, json_field } => {
                let content = tokio::fs::read_to_string(path).await.map_err(|_| CredentialError)?;
                match json_field {
                    Some(field) => serde_json::from_str::<serde_json::Value>(&content)
                        .map_err(|_| CredentialError)?
                        .get(field)
                        .and_then(|v| v.as_str())
                        .ok_or(CredentialError)?
                        .to_owned(),
                    // A JSON object credential (Namespace's `{"bearer_token": …}`)
                    // travels in a header, so its formatting whitespace goes.
                    None => match serde_json::from_str::<serde_json::Value>(&content) {
                        Ok(object @ serde_json::Value::Object(_)) => object.to_string(),
                        _ => content.trim_end_matches(['\r', '\n']).to_owned(),
                    },
                }
            }
            CredentialReference::Embedder { .. } => return Err(CredentialError),
        };
        if value.is_empty() {
            return Err(CredentialError);
        }
        Ok(Credential { value: Secret::new(value), expires_at: None })
    }
    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

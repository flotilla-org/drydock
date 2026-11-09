//! A credential exchanged for a short-lived token, the token held until
//! shortly before it expires.
use super::digest;
use crate::module::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use drydock_protocol::Secret;
use std::{
    future::Future,
    sync::{Mutex, PoisonError},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// How long before an exchanged token expires a new one is asked for.
const RENEW_MARGIN: Duration = Duration::from_secs(60);

/// The token last exchanged, for the digest of the credential it came from,
/// and when to renew it. Only a JWT that says when it expires is held.
#[derive(Default)]
pub struct Exchanged(Mutex<Option<(String, Secret, SystemTime)>>);
impl Exchanged {
    /// The token held for `credential`, or the one `exchange` gives for it.
    pub async fn token(&self, credential: &Secret, exchange: impl Future<Output = Result<Secret>>) -> Result<Secret> {
        let digest = digest(credential.expose());
        let held = self.0.lock().unwrap_or_else(PoisonError::into_inner).clone();
        if let Some((_, token, _)) = held.filter(|(held, _, renew_at)| *held == digest && SystemTime::now() < *renew_at) {
            return Ok(token);
        }
        let token = exchange.await?;
        if let Some(expires) = expiry(token.expose()) {
            let renew_at = expires.checked_sub(RENEW_MARGIN).unwrap_or(UNIX_EPOCH);
            *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some((digest, token.clone(), renew_at));
        }
        Ok(token)
    }
}

/// When a JWT says it expires, if it does.
fn expiry(token: &str) -> Option<SystemTime> {
    let payload = URL_SAFE_NO_PAD.decode(token.split('.').nth(1)?).ok()?;
    let exp = serde_json::from_slice::<serde_json::Value>(&payload).ok()?.get("exp")?.as_u64()?;
    Some(UNIX_EPOCH + Duration::from_secs(exp))
}

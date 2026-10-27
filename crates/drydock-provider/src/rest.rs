//! HTTP adapters shared by the public router and the private bridge: typed
//! refusals, request decoding that names the failing field, and stream upgrades.
use axum::{
    Json,
    body::Bytes,
    extract::{FromRequest, FromRequestParts, Path, Query, Request},
    http::{StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use drydock_protocol::ProtocolError;
use serde::de::DeserializeOwned;
use tokio::sync::watch;

/// A protocol error as its HTTP response, with Retry-After when it carries one.
pub struct Refusal(pub ProtocolError);
impl From<ProtocolError> for Refusal {
    fn from(error: ProtocolError) -> Self {
        Self(error)
    }
}
impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        tracing::warn!(error_class = self.0.class(), "request failed");
        let mut response =
            (StatusCode::from_u16(self.0.status()).expect("protocol error status is valid HTTP"), Json(&self.0)).into_response();
        if let Some(seconds) = self.0.retry_after() {
            response.headers_mut().insert(header::RETRY_AFTER, seconds.into());
        }
        response
    }
}
/// Name the failing field and the decoder's reason, never the offending value.
fn invalid(path: impl std::fmt::Display, error: impl std::fmt::Display) -> Refusal {
    let error = error.to_string();
    let reason = match (error.split_once(':'), error.rsplit_once(", expected ")) {
        (Some((kind, _)), Some((_, expected))) => format!("{kind}, expected {expected}"),
        _ => error,
    };
    Refusal(ProtocolError::Refused { reason: format!("invalid request: {path}: {reason}") })
}
pub struct ApiJson<T>(pub T);
impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiJson<T> {
    type Rejection = Refusal;
    async fn from_request(request: Request, state: &S) -> Result<Self, Refusal> {
        let body = Bytes::from_request(request, state).await.map_err(|error| invalid("body", error.body_text()))?;
        serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_slice(&body))
            .map(Self)
            .map_err(|error| invalid(error.path(), error.inner()))
    }
}
pub struct ApiPath<T>(pub T);
impl<S: Send + Sync, T: DeserializeOwned + Send> FromRequestParts<S> for ApiPath<T> {
    type Rejection = Refusal;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Refusal> {
        let Path(value) = Path::<T>::from_request_parts(parts, state).await.map_err(|error| invalid("path", error.body_text()))?;
        Ok(Self(value))
    }
}
pub struct ApiQuery<T>(pub T);
impl<S: Send + Sync, T: DeserializeOwned> FromRequestParts<S> for ApiQuery<T> {
    type Rejection = Refusal;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Refusal> {
        let Query(value) = Query::<T>::from_request_parts(parts, state).await.map_err(|error| invalid("query", error.body_text()))?;
        Ok(Self(value))
    }
}

/// Check upgrade headers before the provider is called.
pub fn upgrade(request: &mut Request, protocol: &str) -> Result<hyper::upgrade::OnUpgrade, Refusal> {
    let headers = request.headers();
    let upgrade = headers.get(header::UPGRADE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case(protocol));
    let connection = headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|v| v.trim().eq_ignore_ascii_case("upgrade")));
    if !upgrade || !connection {
        return Err(Refusal(ProtocolError::Refused { reason: format!("missing {protocol} upgrade headers") }));
    }
    Ok(hyper::upgrade::on(request))
}
/// Switch protocols and bridge raw bytes until either side closes or `stopping` is set.
pub fn switch(
    upgrade: hyper::upgrade::OnUpgrade,
    protocol: &'static str,
    mut stream: rigging_stream::ByteStream,
    mut stopping: watch::Receiver<bool>,
) -> Response {
    tokio::spawn(async move {
        if *stopping.borrow() {
            return;
        }
        let upgraded = tokio::select! {
            result = upgrade => match result { Ok(upgraded) => upgraded, Err(_) => return },
            _ = stopping.wait_for(|stopped| *stopped) => return,
        };
        let mut io = hyper_util::rt::TokioIo::new(upgraded);
        tokio::select! {
            _ = tokio::io::copy_bidirectional(&mut io, &mut stream) => {},
            _ = stopping.wait_for(|stopped| *stopped) => {},
        }
    });
    (StatusCode::SWITCHING_PROTOCOLS, [(header::CONNECTION, "Upgrade"), (header::UPGRADE, protocol)]).into_response()
}

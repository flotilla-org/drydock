// Serve the main-server runtime through the production public router for the
// existing HTTP harnesses. Production supervision configures providers and
// delivers credentials by direct calls; only these tests expose them as routes.
#![allow(dead_code)]
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::put,
};
use drydock::runtime::Runtime;
use drydock_protocol::{CredentialRefresh, ProtocolError};

pub fn router(runtime: Runtime) -> Router {
    Router::new()
        .route("/v1/config", put(configure))
        .route("/v1/providers/{provider}/credential", put(credential))
        .with_state(runtime.clone())
        .fallback_service(drydock::api::router(std::sync::Arc::new(runtime.clone()), runtime.stopping()))
}
fn reply(result: Result<(), ProtocolError>) -> Response {
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => (StatusCode::from_u16(error.status()).unwrap(), Json(error)).into_response(),
    }
}
fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ProtocolError> {
    serde_json::from_slice(body).map_err(|_| ProtocolError::Refused { reason: "invalid JSON request".into() })
}
async fn configure(State(runtime): State<Runtime>, body: Bytes) -> Response {
    reply(async { runtime.configure(&decode(&body)?).await }.await)
}
async fn credential(State(runtime): State<Runtime>, Path(provider): Path<String>, body: Bytes) -> Response {
    reply(async { runtime.credential(&provider, decode::<CredentialRefresh>(&body)?.value).await }.await)
}
/// Shutdown stops the runtime first, ending its streams, then drains HTTP.
pub async fn serve_unix(
    runtime: Runtime,
    path: impl AsRef<std::path::Path>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let stop = runtime.shutdown(shutdown);
    rigging_http_serve::UnixServer::bind(path, 0o600).await?.serve(router(runtime), rigging_http_serve::Caller::<()>::Unix, stop).await
}
pub async fn client(runtime: Runtime, path: std::path::PathBuf) -> drydock::client::Client {
    use drydock::api::ProviderApi;
    let client = drydock::client::Client::unix(&path).unwrap();
    tokio::spawn(serve_unix(runtime, path, std::future::pending()));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while client.hello().await.is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    client
}

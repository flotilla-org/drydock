//! The public provider HTTP surface: thin axum adapters over [`ProviderApi`].
//! Each handler decodes its request, calls one trait method and encodes the result.
use crate::client::Error;
use axum::{
    Json, Router,
    body::Body,
    extract::{FromRequest, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
pub use drydock_client::api::*;
use drydock_protocol::*;
pub(crate) use drydock_provider::rest::{ApiJson, ApiPath, ApiQuery, Refusal, switch, upgrade};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::watch;

#[derive(Clone)]
struct Surface {
    api: Arc<dyn ProviderApi>,
    stopping: watch::Receiver<bool>,
}
/// Stream upgrades end when `stopping` becomes true.
pub fn router(api: Arc<dyn ProviderApi>, stopping: watch::Receiver<bool>) -> Router {
    Router::new()
        .route("/v1/hello", get(hello))
        .route("/v1/events", get(events))
        .route("/v1/providers/{provider}/prepare", post(prepare))
        .route("/v1/providers/{provider}/environments", get(list).post(provision))
        .route("/v1/providers/{provider}/environments/{id}", get(inspect).delete(destroy))
        .route("/v1/providers/{provider}/environments/{id}/reach", post(reach))
        .route("/v1/providers/{provider}/environments/{id}/relay", get(relay))
        .route("/v1/providers/{provider}/environments/{id}/exec", post(exec))
        .route("/v1/providers/{provider}/environments/{id}/suspend", post(suspend))
        .route("/v1/providers/{provider}/environments/{id}/resume", post(resume))
        .route("/v1/providers/{provider}/environments/{id}/export", post(export))
        .route("/v1/providers/{provider}/usage", get(usage))
        .route("/v1/providers/{provider}/quota", get(quota))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(Surface { api, stopping })
        .layer(middleware::from_fn(trace_request))
}
pub(crate) async fn not_found() -> ApiError {
    ApiError(ProtocolError::NotFound { reason: "unknown route".into() }.into())
}
pub(crate) async fn method_not_allowed() -> ApiError {
    ApiError(ProtocolError::MethodNotAllowed { reason: "unsupported method".into() }.into())
}

pub(crate) struct ApiError(pub(crate) Error);
impl<E: Into<Error>> From<E> for ApiError {
    fn from(error: E) -> Self {
        Self(error.into())
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        Refusal(match self.0 {
            Error::Protocol(error) => error,
            Error::InvalidRequest(reason) => ProtocolError::Refused { reason: format!("invalid request: {reason}") },
            Error::RateLimited => ProtocolError::RateLimited { reason: "status budget exhausted".into(), retry_after: None },
            Error::InvalidResponse(reason) => {
                ProtocolError::Internal { reason: format!("invalid host response: {reason}"), provider_error: String::new() }
            }
            other => ProtocolError::unavailable(other.to_string(), None),
        })
        .into_response()
    }
}
type ApiResult<T> = Result<T, ApiError>;

async fn hello(State(s): State<Surface>) -> ApiResult<Json<Hello>> {
    Ok(Json(s.api.hello().await?))
}
async fn prepare(State(s): State<Surface>, ApiPath(p): ApiPath<String>, ApiJson(r): ApiJson<PrepareRequest>) -> ApiResult<Json<Prepared>> {
    Ok(Json(s.api.prepare(&p, &r).await?))
}
async fn provision(State(s): State<Surface>, ApiPath(p): ApiPath<String>, ApiJson(r): ApiJson<ProvisionRequest>) -> ApiResult<Response> {
    Ok(match s.api.provision(&p, &r).await? {
        Provisioned::Created(environment) => (StatusCode::CREATED, Json(environment)).into_response(),
        Provisioned::Existing(environment) => Json(environment).into_response(),
    })
}
async fn list(State(s): State<Surface>, ApiPath(p): ApiPath<String>) -> ApiResult<Json<Vec<Environment>>> {
    Ok(Json(s.api.list(&p).await?))
}
async fn inspect(State(s): State<Surface>, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Environment>> {
    Ok(Json(s.api.inspect(&p, &id).await?))
}
async fn destroy(State(s): State<Surface>, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<StatusCode> {
    s.api.destroy(&p, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn reach(State(s): State<Surface>, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Reach>> {
    Ok(Json(s.api.reach(&p, &id).await?))
}
async fn suspend(State(s): State<Surface>, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<ResumeToken>> {
    Ok(Json(s.api.suspend(&p, &id).await?))
}
async fn resume(
    State(s): State<Surface>,
    ApiPath((p, id)): ApiPath<(String, String)>,
    ApiJson(token): ApiJson<ResumeToken>,
) -> ApiResult<StatusCode> {
    s.api.resume(&p, &id, &token).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn export(State(s): State<Surface>, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Export>> {
    Ok(Json(s.api.export(&p, &id).await?))
}
async fn usage(State(s): State<Surface>, ApiPath(p): ApiPath<String>, ApiQuery(period): ApiQuery<Period>) -> ApiResult<Json<Usage>> {
    Ok(Json(s.api.usage(&p, &period).await?))
}
async fn quota(State(s): State<Surface>, ApiPath(p): ApiPath<String>) -> ApiResult<Json<Quota>> {
    Ok(Json(s.api.quota(&p).await?))
}

async fn relay(State(s): State<Surface>, ApiPath((p, id)): ApiPath<(String, String)>, mut request: Request) -> ApiResult<Response> {
    let on = upgrade(&mut request, "drydock-relay").map_err(|refusal| refusal.0)?;
    let stream = s.api.relay(&p, &id).await?;
    Ok(switch(on, "drydock-relay", stream, s.stopping))
}
async fn exec(State(s): State<Surface>, ApiPath((p, id)): ApiPath<(String, String)>, mut request: Request) -> ApiResult<Response> {
    let on = upgrade(&mut request, "drydock-stream").map_err(|refusal| refusal.0)?;
    let ApiJson(command) = ApiJson::<ExecRequest>::from_request(request, &()).await.map_err(|refusal| refusal.0)?;
    let stream = s.api.exec(&p, &id, &command).await?;
    Ok(switch(on, "drydock-stream", stream, s.stopping))
}

#[derive(Deserialize)]
struct EventQuery {
    since: Option<String>,
}
async fn events(State(s): State<Surface>, ApiQuery(query): ApiQuery<EventQuery>) -> ApiResult<Response> {
    use futures::StreamExt;
    // A failed observation ends the body; readers resume from their last cursor.
    let lines = s.api.observe(query.since.as_deref()).await?.map(|record| {
        let mut line = serde_json::to_vec(&record.map_err(std::io::Error::other)?).expect("wire record serializes");
        line.push(b'\n');
        Ok::<_, std::io::Error>(line)
    });
    Ok(([(header::CONTENT_TYPE, "application/x-ndjson")], Body::from_stream(lines)).into_response())
}

async fn trace_request(request: Request, next: Next) -> Response {
    use tracing::Instrument;
    let route = request.extensions().get::<axum::extract::MatchedPath>().map(|p| p.as_str()).unwrap_or("unknown").to_owned();
    let parts: Vec<_> = request.uri().path().split('/').collect();
    let provider = if parts.get(2) == Some(&"providers") { parts.get(3).copied().unwrap_or("") } else { "" };
    let environment_id = if parts.get(4) == Some(&"environments") { parts.get(5).copied().unwrap_or("") } else { "" };
    let span = tracing::info_span!("request", route, provider, environment_id);
    async move {
        let response = next.run(request).await;
        tracing::info!(status = response.status().as_u16(), "request completed");
        response
    }
    .instrument(span)
    .await
}

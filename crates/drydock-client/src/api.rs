//! The one provider API, served by the drydock server and by language hosts.
//! [`ProviderApi`] is the seam; [`router`] is the one HTTP adapter over it, and
//! the socket [`Client`] implements it over HTTP for remote callers.
use crate::{Client, Error, Method};
use axum::{
    Json, Router,
    body::Body,
    extract::{FromRequest, FromRequestParts, Request, State},
    http::{StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use drydock_protocol::*;
pub use drydock_provider::Provisioned;
use drydock_provider::rest::{ApiJson, ApiPath, ApiQuery, Refusal, switch, upgrade};
use rigging_stream::ByteStream;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::watch;
pub type ObservationStream = futures::stream::BoxStream<'static, Result<ObserveRecord, Error>>;

/// A whole configuration document, or an RFC 7396 merge patch of the current one.
#[derive(Clone, Debug)]
pub enum ConfigUpdate {
    Replace(Configuration),
    MergePatch(serde_json::Value),
}
impl ConfigUpdate {
    /// The document this update makes of `current`.
    pub fn apply(self, current: &Configuration) -> Result<Configuration, ProtocolError> {
        match self {
            Self::Replace(document) => Ok(document),
            Self::MergePatch(patch) => {
                let mut document = serde_json::to_value(current).expect("configuration serializes");
                json_patch::merge(&mut document, &patch);
                serde_path_to_error::deserialize(document).map_err(|error| ProtocolError::Refused {
                    reason: format!("invalid configuration: {}: {}", error.path(), error.inner()),
                })
            }
        }
    }
}

/// Provider operations. Server-only extensions (credential delivery and the
/// event stream) default to NotFound, so hosts implement only the common API.
#[async_trait::async_trait]
pub trait ProviderApi: Send + Sync {
    /// Typed discovery with the same protocol compatibility checks as the socket client.
    async fn hello(&self) -> Result<Hello, Error>;
    async fn configure(&self, update: ConfigUpdate) -> Result<(), Error>;
    async fn providers(&self) -> Result<Vec<ProviderDeclaration>, Error>;
    async fn provider(&self, provider: &str) -> Result<ProviderDeclaration, Error>;
    async fn prepare(&self, provider: &str, request: &PrepareRequest) -> Result<Prepared, Error>;
    async fn provision(&self, provider: &str, request: &ProvisionRequest) -> Result<Provisioned<Environment>, Error>;
    async fn list(&self, provider: &str) -> Result<Vec<Environment>, Error>;
    async fn inspect(&self, provider: &str, id: &str) -> Result<Environment, Error>;
    async fn destroy(&self, provider: &str, id: &str) -> Result<(), Error>;
    async fn reach(&self, provider: &str, id: &str) -> Result<Reach, Error>;
    async fn suspend(&self, provider: &str, id: &str) -> Result<ResumeToken, Error>;
    async fn resume(&self, provider: &str, id: &str, token: &ResumeToken) -> Result<(), Error>;
    async fn export(&self, provider: &str, id: &str) -> Result<Export, Error>;
    async fn quota(&self, provider: &str) -> Result<Quota, Error>;
    async fn usage(&self, provider: &str, period: &Period) -> Result<Usage, Error>;
    async fn relay(&self, provider: &str, id: &str) -> Result<ByteStream, Error>;
    async fn exec(&self, provider: &str, id: &str, command: &ExecRequest) -> Result<ByteStream, Error>;
    /// The same API, using `credential` instead of any held one for each call.
    fn with_credential(&self, credential: Secret) -> Arc<dyn ProviderApi>;
    /// Server only: replace the held credential.
    async fn credential(&self, _provider: &str, _value: Secret) -> Result<(), Error> {
        Err(ProtocolError::NotFound { reason: "unknown route".into() }.into())
    }
    /// Server only: billing events and inventory snapshots.
    async fn observe(&self, _since: Option<&str>) -> Result<ObservationStream, Error> {
        Err(ProtocolError::NotFound { reason: "unknown route".into() }.into())
    }
}
#[async_trait::async_trait]
impl ProviderApi for Client {
    async fn hello(&self) -> Result<Hello, Error> {
        let hello: Hello = self.call::<_, ()>(Method::GET, &["v1", "hello"], None).await?;
        if !hello.is_compatible() {
            return Err(Error::VersionMismatch);
        }
        Ok(hello)
    }
    async fn configure(&self, update: ConfigUpdate) -> Result<(), Error> {
        match update {
            ConfigUpdate::Replace(document) => self.call(Method::PUT, &["v1", "config"], Some(&document)).await,
            ConfigUpdate::MergePatch(patch) => {
                let request = self
                    .request(Method::PATCH, &["v1", "config"])?
                    .header(header::CONTENT_TYPE, "application/merge-patch+json")
                    .body(patch.to_string());
                self.execute_response::<()>(request).await?;
                Ok(())
            }
        }
    }
    async fn providers(&self) -> Result<Vec<ProviderDeclaration>, Error> {
        self.call::<_, ()>(Method::GET, &["v1", "providers"], None).await
    }
    async fn provider(&self, provider: &str) -> Result<ProviderDeclaration, Error> {
        self.call::<_, ()>(Method::GET, &["v1", "providers", provider], None).await
    }
    async fn credential(&self, provider: &str, value: Secret) -> Result<(), Error> {
        self.call(Method::PUT, &["v1", "providers", provider, "credential"], Some(&CredentialRefresh { value })).await
    }
    async fn observe(&self, since: Option<&str>) -> Result<ObservationStream, Error> {
        let mut records = Client::observe(self, since).await?;
        Ok(Box::pin(async_stream::stream! {
            loop { match records.next().await {
                Ok(Some(record)) => yield Ok(record),
                Ok(None) => break,
                Err(error) => {yield Err(error);break;}
            }}
        }))
    }
    async fn prepare(&self, provider: &str, request: &PrepareRequest) -> Result<Prepared, Error> {
        self.call(Method::POST, &["v1", "providers", provider, "prepare"], Some(request)).await
    }
    async fn provision(&self, provider: &str, request: &ProvisionRequest) -> Result<Provisioned<Environment>, Error> {
        let request = self.request(Method::POST, &["v1", "providers", provider, "environments"])?.json(request);
        Ok(match self.execute_response(request).await? {
            (201, environment) => Provisioned::Created(environment),
            (_, environment) => Provisioned::Existing(environment),
        })
    }
    async fn list(&self, provider: &str) -> Result<Vec<Environment>, Error> {
        self.call::<_, ()>(Method::GET, &["v1", "providers", provider, "environments"], None).await
    }
    async fn inspect(&self, provider: &str, id: &str) -> Result<Environment, Error> {
        self.call::<_, ()>(Method::GET, &["v1", "providers", provider, "environments", id], None).await
    }
    async fn destroy(&self, provider: &str, id: &str) -> Result<(), Error> {
        self.call::<_, ()>(Method::DELETE, &["v1", "providers", provider, "environments", id], None).await
    }
    async fn reach(&self, provider: &str, id: &str) -> Result<Reach, Error> {
        self.call::<_, ()>(Method::POST, &["v1", "providers", provider, "environments", id, "reach"], None).await
    }
    async fn suspend(&self, provider: &str, id: &str) -> Result<ResumeToken, Error> {
        self.call::<_, ()>(Method::POST, &["v1", "providers", provider, "environments", id, "suspend"], None).await
    }
    async fn resume(&self, provider: &str, id: &str, token: &ResumeToken) -> Result<(), Error> {
        self.call(Method::POST, &["v1", "providers", provider, "environments", id, "resume"], Some(token)).await
    }
    async fn export(&self, provider: &str, id: &str) -> Result<Export, Error> {
        self.call::<_, ()>(Method::POST, &["v1", "providers", provider, "environments", id, "export"], None).await
    }
    async fn quota(&self, provider: &str) -> Result<Quota, Error> {
        self.call::<_, ()>(Method::GET, &["v1", "providers", provider, "quota"], None).await
    }
    async fn usage(&self, provider: &str, period: &Period) -> Result<Usage, Error> {
        Ok(self.execute_response(self.request(Method::GET, &["v1", "providers", provider, "usage"])?.query(period)).await?.1)
    }
    async fn relay(&self, provider: &str, id: &str) -> Result<ByteStream, Error> {
        self.upgrade::<()>(provider, id, "relay", "drydock-relay", None).await
    }
    async fn exec(&self, provider: &str, id: &str, command: &ExecRequest) -> Result<ByteStream, Error> {
        self.upgrade(provider, id, "exec", "drydock-stream", Some(command)).await
    }
    fn with_credential(&self, credential: Secret) -> Arc<dyn ProviderApi> {
        Arc::new(self.clone().credentialed(Some(credential)))
    }
}

#[derive(Clone)]
struct Surface {
    api: Arc<dyn ProviderApi>,
    stopping: watch::Receiver<bool>,
}
/// The API for one request: the served one, or one using its `Drydock-Credential`.
struct Api(Arc<dyn ProviderApi>);
impl FromRequestParts<Surface> for Api {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &Surface) -> Result<Self, ApiError> {
        let api = state.api.clone();
        Ok(Self(match parts.headers.get(CREDENTIAL_HEADER) {
            None => api,
            Some(value) => {
                let value = value.to_str().ok().filter(|value| !value.is_empty());
                let value = value.ok_or_else(|| Error::InvalidRequest("Drydock-Credential must be nonempty visible ASCII".into()))?;
                api.with_credential(Secret::new(value))
            }
        }))
    }
}
/// The routes common to the server and hosts. Stream upgrades end when `stopping` becomes true.
pub fn router(api: Arc<dyn ProviderApi>, stopping: watch::Receiver<bool>) -> Router {
    routes().with_state(Surface { api, stopping }).layer(middleware::from_fn(trace_request)).layer(sensitive())
}
/// The common routes plus the server-only extensions: credential delivery and events.
pub fn server_router(api: Arc<dyn ProviderApi>, stopping: watch::Receiver<bool>) -> Router {
    routes()
        .route("/v1/events", get(events))
        .route("/v1/providers/{provider}/credential", put(credential))
        .with_state(Surface { api, stopping })
        .layer(middleware::from_fn(trace_request))
        .layer(sensitive())
}
fn sensitive() -> tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer {
    tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer::new([
        header::HeaderName::from_static(CREDENTIAL_HEADER),
        header::AUTHORIZATION,
    ])
}
fn routes() -> Router<Surface> {
    Router::new()
        .route("/v1/hello", get(hello))
        .route("/v1/config", put(configure).patch(patch_configuration))
        .route("/v1/providers", get(providers))
        .route("/v1/providers/{provider}", get(provider))
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
}
pub async fn not_found() -> ApiError {
    ApiError(ProtocolError::NotFound { reason: "unknown route".into() }.into())
}
pub async fn method_not_allowed() -> ApiError {
    ApiError(ProtocolError::MethodNotAllowed { reason: "unsupported method".into() }.into())
}

pub struct ApiError(pub Error);
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

async fn hello(Api(api): Api) -> ApiResult<Json<Hello>> {
    Ok(Json(api.hello().await?))
}
async fn configure(Api(api): Api, ApiJson(document): ApiJson<Configuration>) -> ApiResult<StatusCode> {
    api.configure(ConfigUpdate::Replace(document)).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn patch_configuration(Api(api): Api, ApiJson(patch): ApiJson<serde_json::Value>) -> ApiResult<StatusCode> {
    api.configure(ConfigUpdate::MergePatch(patch)).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn providers(Api(api): Api) -> ApiResult<Json<Vec<ProviderDeclaration>>> {
    Ok(Json(api.providers().await?))
}
async fn provider(Api(api): Api, ApiPath(p): ApiPath<String>) -> ApiResult<Json<ProviderDeclaration>> {
    Ok(Json(api.provider(&p).await?))
}
async fn credential(Api(api): Api, ApiPath(p): ApiPath<String>, ApiJson(r): ApiJson<CredentialRefresh>) -> ApiResult<StatusCode> {
    api.credential(&p, r.value).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn prepare(Api(api): Api, ApiPath(p): ApiPath<String>, ApiJson(r): ApiJson<PrepareRequest>) -> ApiResult<Json<Prepared>> {
    Ok(Json(api.prepare(&p, &r).await?))
}
async fn provision(Api(api): Api, ApiPath(p): ApiPath<String>, ApiJson(r): ApiJson<ProvisionRequest>) -> ApiResult<Response> {
    Ok(match api.provision(&p, &r).await? {
        Provisioned::Created(environment) => (StatusCode::CREATED, Json(environment)).into_response(),
        Provisioned::Existing(environment) => Json(environment).into_response(),
    })
}
async fn list(Api(api): Api, ApiPath(p): ApiPath<String>) -> ApiResult<Json<Vec<Environment>>> {
    Ok(Json(api.list(&p).await?))
}
async fn inspect(Api(api): Api, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Environment>> {
    Ok(Json(api.inspect(&p, &id).await?))
}
async fn destroy(Api(api): Api, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<StatusCode> {
    api.destroy(&p, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn reach(Api(api): Api, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Reach>> {
    Ok(Json(api.reach(&p, &id).await?))
}
async fn suspend(Api(api): Api, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<ResumeToken>> {
    Ok(Json(api.suspend(&p, &id).await?))
}
async fn resume(Api(api): Api, ApiPath((p, id)): ApiPath<(String, String)>, ApiJson(token): ApiJson<ResumeToken>) -> ApiResult<StatusCode> {
    api.resume(&p, &id, &token).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn export(Api(api): Api, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Export>> {
    Ok(Json(api.export(&p, &id).await?))
}
async fn usage(Api(api): Api, ApiPath(p): ApiPath<String>, ApiQuery(period): ApiQuery<Period>) -> ApiResult<Json<Usage>> {
    Ok(Json(api.usage(&p, &period).await?))
}
async fn quota(Api(api): Api, ApiPath(p): ApiPath<String>) -> ApiResult<Json<Quota>> {
    Ok(Json(api.quota(&p).await?))
}

async fn relay(
    State(s): State<Surface>,
    Api(api): Api,
    ApiPath((p, id)): ApiPath<(String, String)>,
    mut request: Request,
) -> ApiResult<Response> {
    let on = upgrade(&mut request, "drydock-relay").map_err(|refusal| refusal.0)?;
    let stream = api.relay(&p, &id).await?;
    Ok(switch(on, "drydock-relay", stream, s.stopping))
}
async fn exec(
    State(s): State<Surface>,
    Api(api): Api,
    ApiPath((p, id)): ApiPath<(String, String)>,
    mut request: Request,
) -> ApiResult<Response> {
    let on = upgrade(&mut request, "drydock-stream").map_err(|refusal| refusal.0)?;
    let ApiJson(command) = ApiJson::<ExecRequest>::from_request(request, &()).await.map_err(|refusal| refusal.0)?;
    let stream = api.exec(&p, &id, &command).await?;
    Ok(switch(on, "drydock-stream", stream, s.stopping))
}

#[derive(Deserialize)]
struct EventQuery {
    since: Option<String>,
}
async fn events(Api(api): Api, ApiQuery(query): ApiQuery<EventQuery>) -> ApiResult<Response> {
    use futures::StreamExt;
    // A failed observation ends the body; readers resume from their last cursor.
    let lines = api.observe(query.since.as_deref()).await?.map(|record| {
        let record = record.inspect_err(|error| tracing::warn!(%error, "event stream ended by an error")).map_err(std::io::Error::other)?;
        let mut line = serde_json::to_vec(&record).expect("wire record serializes");
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    // A merge patch edits the document in place: nested settings merge, null
    // removes a provider, an absent key is untouched, and a result that is not a
    // configuration is refused, naming the field without echoing its value.
    #[test]
    fn merge_patch_edits_the_document() {
        let current: Configuration = serde_json::from_value(json!({"providers":{
            "a":{"module":"m","settings":{"keep":1,"change":1},"credential":{"env":"A"}},
            "b":{"module":"m"}
        }}))
        .unwrap();
        let patch = json!({"providers":{"a":{"settings":{"change":2,"new":3}},"b":null,"c":{"module":"n"}}});
        let patched = ConfigUpdate::MergePatch(patch).apply(&current).unwrap();
        assert_eq!(
            serde_json::to_value(patched).unwrap(),
            json!({"providers":{
                "a":{"module":"m","settings":{"keep":1,"change":2,"new":3},"credential":{"env":"A"}},
                "c":{"module":"n","settings":{}}
            }})
        );
        let refused = ConfigUpdate::MergePatch(json!({"providers":{"a":{"module":"secret-value-1"},"d":{"settings":{}}}}))
            .apply(&current)
            .unwrap_err();
        assert!(matches!(&refused, ProtocolError::Refused { reason } if reason.contains("providers.d") && !reason.contains("secret")));
    }
}

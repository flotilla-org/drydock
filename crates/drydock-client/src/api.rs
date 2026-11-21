//! The one provider API, served by the drydock server and by language hosts.
//! [`ProviderApi`] is the seam; [`router`] is the one HTTP adapter over it, and
//! the socket [`Client`] implements it over HTTP for remote callers.
use crate::{Client, Error, Method, ProvisionError};
use axum::{
    Json, Router,
    body::Body,
    extract::{FromRequest, FromRequestParts, Request, State},
    http::{StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use drydock_protocol::openapi::ErrorResponses;
use drydock_protocol::{
    service::{Service, ServiceInfo},
    *,
};
pub use drydock_provider::Provisioned;
use drydock_provider::rest::{ApiJson, ApiPath, ApiQuery, Refusal, switch, upgrade};
use rigging_stream::ByteStream;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::watch;
use utoipa_axum::{router::OpenApiRouter, routes};
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

/// The outcome of setting an exposure: a first `PUT` creates it (201), a later one replaces it (200).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exposed<T> {
    Created(T),
    Replaced(T),
}
impl<T> Exposed<T> {
    pub fn into_inner(self) -> T {
        match self {
            Self::Created(value) | Self::Replaced(value) => value,
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
    async fn provision(&self, provider: &str, request: &ProvisionRequest) -> Result<Provisioned<Environment>, ProvisionError>;
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
    /// Host only: a stream to an endpoint on the provider's machine, through
    /// its streams port. drydockd opens these for its children alone and does
    /// not serve this.
    async fn stream(&self, _provider: &str, _endpoint: &Carried) -> Result<ByteStream, Error> {
        Err(ProtocolError::not_found("unknown route").into())
    }
    /// Write one file into a guest, through the provider's files port.
    async fn put_file(&self, provider: &str, id: &str, file: &GuestFile, bytes: bytes::Bytes) -> Result<(), Error>;
    /// Mint push access to the provider's own registry.
    async fn push_access(&self, provider: &str) -> Result<PushAccess, Error>;
    /// Host only: what one of the vendor's event deliveries says, read by the
    /// provider's module. drydockd reads deliveries itself and does not serve this.
    async fn event(&self, _provider: &str, _delivery: &VendorDelivery) -> Result<Vec<VendorObservation>, Error> {
        Err(ProtocolError::not_found("unknown route").into())
    }
    /// The same API, using `credential` instead of any held one for each call.
    fn with_credential(&self, credential: Secret) -> Arc<dyn ProviderApi>;
    /// Server only: replace the held credential.
    async fn credential(&self, _provider: &str, _value: Secret) -> Result<(), Error> {
        Err(ProtocolError::not_found("unknown route").into())
    }
    /// Server only: billing events and inventory snapshots.
    async fn observe(&self, _since: Option<&str>) -> Result<ObservationStream, Error> {
        Err(ProtocolError::not_found("unknown route").into())
    }
    /// Server only: carry an instance into the parent environment `carry.parent` names.
    async fn put_provider(&self, _provider: &str, _carry: &Carry) -> Result<Provisioned<ProviderDeclaration>, ProvisionError> {
        Err(Error::from(ProtocolError::not_found("unknown route")).into())
    }
    /// Server only: remove a carried instance that holds no environments.
    async fn remove_provider(&self, _provider: &str) -> Result<(), Error> {
        Err(ProtocolError::not_found("unknown route").into())
    }
    /// Server only: start a service in a vessel, unless it runs from the same body.
    async fn put_service(&self, _provider: &str, _id: &str, _name: &str, _service: &Service) -> Result<Provisioned<ServiceInfo>, Error> {
        Err(ProtocolError::not_found("unknown route").into())
    }
    /// Server only.
    async fn service(&self, _provider: &str, _id: &str, _name: &str) -> Result<ServiceInfo, Error> {
        Err(ProtocolError::not_found("unknown route").into())
    }
    /// Server only.
    async fn services(&self, _provider: &str, _id: &str) -> Result<Vec<ServiceInfo>, Error> {
        Err(ProtocolError::not_found("unknown route").into())
    }
    /// Server only: stop a service and forget it.
    async fn remove_service(&self, _provider: &str, _id: &str, _name: &str, _grace_ms: Option<u64>) -> Result<ServiceInfo, Error> {
        Err(ProtocolError::not_found("unknown route").into())
    }
    /// Server only: set an inward exposure, reporting whether it replaced one.
    async fn put_inward(&self, _provider: &str, _id: &str, _name: &str, _request: &InwardRequest) -> Result<Exposed<Inward>, Error> {
        Err(ProtocolError::not_found("unknown route").into())
    }
    /// Server only.
    async fn inward(&self, _provider: &str, _id: &str, _name: &str) -> Result<Inward, Error> {
        Err(ProtocolError::not_found("unknown route").into())
    }
    /// Server only.
    async fn inwards(&self, _provider: &str, _id: &str) -> Result<Vec<Inward>, Error> {
        Err(ProtocolError::not_found("unknown route").into())
    }
    /// Server only: removing an absent exposure succeeds.
    async fn remove_inward(&self, _provider: &str, _id: &str, _name: &str) -> Result<(), Error> {
        Err(ProtocolError::not_found("unknown route").into())
    }
    /// Server only: set an outward exposure, reporting whether it replaced one.
    async fn put_outward(&self, _provider: &str, _id: &str, _name: &str, _request: &OutwardRequest) -> Result<Exposed<Outward>, Error> {
        Err(ProtocolError::not_found("unknown route").into())
    }
    /// Server only.
    async fn outward(&self, _provider: &str, _id: &str, _name: &str) -> Result<Outward, Error> {
        Err(ProtocolError::not_found("unknown route").into())
    }
    /// Server only.
    async fn outwards(&self, _provider: &str, _id: &str) -> Result<Vec<Outward>, Error> {
        Err(ProtocolError::not_found("unknown route").into())
    }
    /// Server only: removing an absent exposure succeeds.
    async fn remove_outward(&self, _provider: &str, _id: &str, _name: &str) -> Result<(), Error> {
        Err(ProtocolError::not_found("unknown route").into())
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
    async fn provision(&self, provider: &str, request: &ProvisionRequest) -> Result<Provisioned<Environment>, ProvisionError> {
        let request = self.request(Method::POST, &["v1", "providers", provider, "environments"])?.json(request);
        let (status, environment) = self.execute_provision(request).await?;
        Ok(Provisioned::new(status == 201, environment))
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
    async fn stream(&self, provider: &str, endpoint: &Carried) -> Result<ByteStream, Error> {
        self.open_stream(provider, endpoint).await
    }
    async fn put_file(&self, provider: &str, id: &str, file: &GuestFile, bytes: bytes::Bytes) -> Result<(), Error> {
        let request = self
            .request(Method::PUT, &["v1", "providers", provider, "environments", id, "files"])?
            .query(file)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(bytes);
        self.execute_response::<()>(request).await?;
        Ok(())
    }
    async fn push_access(&self, provider: &str) -> Result<PushAccess, Error> {
        self.call::<_, ()>(Method::POST, &["v1", "providers", provider, "push-access"], None).await
    }
    async fn event(&self, provider: &str, delivery: &VendorDelivery) -> Result<Vec<VendorObservation>, Error> {
        self.call(Method::POST, &["v1", "providers", provider, "event"], Some(delivery)).await
    }
    async fn put_provider(&self, provider: &str, carry: &Carry) -> Result<Provisioned<ProviderDeclaration>, ProvisionError> {
        let request = self.request(Method::PUT, &["v1", "providers", provider])?.json(carry);
        let (status, declaration) = self.execute_provision(request).await?;
        Ok(Provisioned::new(status == 201, declaration))
    }
    async fn put_service(&self, provider: &str, id: &str, name: &str, service: &Service) -> Result<Provisioned<ServiceInfo>, Error> {
        let request = self.request(Method::PUT, &["v1", "providers", provider, "environments", id, "services", name])?.json(service);
        let (status, info) = self.execute_response(request).await?;
        Ok(Provisioned::new(status == 201, info))
    }
    async fn service(&self, provider: &str, id: &str, name: &str) -> Result<ServiceInfo, Error> {
        self.call::<_, ()>(Method::GET, &["v1", "providers", provider, "environments", id, "services", name], None).await
    }
    async fn services(&self, provider: &str, id: &str) -> Result<Vec<ServiceInfo>, Error> {
        self.call::<_, ()>(Method::GET, &["v1", "providers", provider, "environments", id, "services"], None).await
    }
    async fn remove_service(&self, provider: &str, id: &str, name: &str, grace_ms: Option<u64>) -> Result<ServiceInfo, Error> {
        let request = self.request(Method::DELETE, &["v1", "providers", provider, "environments", id, "services", name])?;
        Ok(self.execute_response(request.query(&Grace { grace_ms })).await?.1)
    }
    async fn remove_provider(&self, provider: &str) -> Result<(), Error> {
        self.call::<_, ()>(Method::DELETE, &["v1", "providers", provider], None).await
    }
    async fn put_inward(&self, provider: &str, id: &str, name: &str, request: &InwardRequest) -> Result<Exposed<Inward>, Error> {
        let request =
            self.request(Method::PUT, &["v1", "providers", provider, "environments", id, "exposures", "inward", name])?.json(request);
        Ok(match self.execute_response(request).await? {
            (201, exposure) => Exposed::Created(exposure),
            (_, exposure) => Exposed::Replaced(exposure),
        })
    }
    async fn inward(&self, provider: &str, id: &str, name: &str) -> Result<Inward, Error> {
        self.call::<_, ()>(Method::GET, &["v1", "providers", provider, "environments", id, "exposures", "inward", name], None).await
    }
    async fn inwards(&self, provider: &str, id: &str) -> Result<Vec<Inward>, Error> {
        self.call::<_, ()>(Method::GET, &["v1", "providers", provider, "environments", id, "exposures", "inward"], None).await
    }
    async fn remove_inward(&self, provider: &str, id: &str, name: &str) -> Result<(), Error> {
        self.call::<_, ()>(Method::DELETE, &["v1", "providers", provider, "environments", id, "exposures", "inward", name], None).await
    }
    async fn put_outward(&self, provider: &str, id: &str, name: &str, request: &OutwardRequest) -> Result<Exposed<Outward>, Error> {
        let request =
            self.request(Method::PUT, &["v1", "providers", provider, "environments", id, "exposures", "outward", name])?.json(request);
        Ok(match self.execute_response(request).await? {
            (201, exposure) => Exposed::Created(exposure),
            (_, exposure) => Exposed::Replaced(exposure),
        })
    }
    async fn outward(&self, provider: &str, id: &str, name: &str) -> Result<Outward, Error> {
        self.call::<_, ()>(Method::GET, &["v1", "providers", provider, "environments", id, "exposures", "outward", name], None).await
    }
    async fn outwards(&self, provider: &str, id: &str) -> Result<Vec<Outward>, Error> {
        self.call::<_, ()>(Method::GET, &["v1", "providers", provider, "environments", id, "exposures", "outward"], None).await
    }
    async fn remove_outward(&self, provider: &str, id: &str, name: &str) -> Result<(), Error> {
        self.call::<_, ()>(Method::DELETE, &["v1", "providers", provider, "environments", id, "exposures", "outward", name], None).await
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
/// The routes hosts serve: the common routes, and `stream`, which the server
/// does not serve. Stream upgrades end when `stopping` becomes true.
pub fn router(api: Arc<dyn ProviderApi>, stopping: watch::Receiver<bool>) -> Router {
    routes()
        .routes(routes!(stream))
        .split_for_parts()
        .0
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(Surface { api, stopping })
        .layer(middleware::from_fn(trace_request))
        .layer(sensitive())
}
/// The common routes plus the server-only extensions: credential delivery and events.
pub fn server_router(api: Arc<dyn ProviderApi>, stopping: watch::Receiver<bool>) -> Router {
    server_routes()
        .split_for_parts()
        .0
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
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
fn routes() -> OpenApiRouter<Surface> {
    OpenApiRouter::new()
        .routes(routes!(hello))
        .routes(routes!(configure, patch_configuration))
        .routes(routes!(providers))
        .routes(routes!(provider))
        .routes(routes!(prepare))
        .routes(routes!(list, provision))
        .routes(routes!(inspect, destroy))
        .routes(routes!(reach))
        .routes(routes!(relay))
        .routes(routes!(exec))
        .routes(routes!(put_file))
        .routes(routes!(push_access))
        .routes(routes!(event))
        .routes(routes!(suspend))
        .routes(routes!(resume))
        .routes(routes!(export))
        .routes(routes!(usage))
        .routes(routes!(quota))
}
fn server_routes() -> OpenApiRouter<Surface> {
    routes()
        .routes(routes!(events))
        .routes(routes!(credential))
        .routes(routes!(put_provider, remove_provider))
        .routes(routes!(services))
        .routes(routes!(service, put_service, remove_service))
        .routes(routes!(inwards))
        .routes(routes!(inward, put_inward, remove_inward))
        .routes(routes!(outwards))
        .routes(routes!(outward, put_outward, remove_outward))
}
/// Canonical shared API, with only the credential/events extensions server-only.
pub fn openapi() -> utoipa::openapi::OpenApi {
    drydock_protocol::openapi::document(server_routes().split_for_parts().1)
}
pub fn openapi_json() -> String {
    format!("{}\n", openapi().to_pretty_json().expect("OpenAPI serializes"))
}

pub async fn not_found() -> ApiError {
    ApiError(ProtocolError::not_found("unknown route").into())
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
        Refusal(protocol(self.0)).into_response()
    }
}
/// An error as the protocol states it.
fn protocol(error: Error) -> ProtocolError {
    match error {
        Error::Protocol(error) => error,
        Error::InvalidRequest(reason) => ProtocolError::Refused { reason: format!("invalid request: {reason}") },
        Error::RateLimited => ProtocolError::RateLimited { reason: "status budget exhausted".into(), retry_after: None },
        Error::InvalidResponse(reason) => {
            ProtocolError::Internal { reason: format!("invalid host response: {reason}"), provider_error: String::new() }
        }
        other => ProtocolError::unavailable(other.to_string(), None),
    }
}
type ApiResult<T> = Result<T, ApiError>;

#[utoipa::path(get, tag = "host", path = "/v1/hello",
responses((status = 200, description = "Protocol and module discovery", body = Hello), ErrorResponses)
)]
async fn hello(Api(api): Api) -> ApiResult<Json<Hello>> {
    Ok(Json(api.hello().await?))
}
#[utoipa::path(put, tag = "host", path = "/v1/config",
request_body = Configuration,
responses((status = 204, description = "Success"), ErrorResponses)
)]
async fn configure(Api(api): Api, ApiJson(document): ApiJson<Configuration>) -> ApiResult<StatusCode> {
    api.configure(ConfigUpdate::Replace(document)).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(patch, tag = "host", path = "/v1/config",
request_body(content = Object, content_type = "application/merge-patch+json", description = "RFC 7396 JSON merge patch of the configuration document"),
responses((status = 204, description = "Success"), ErrorResponses)
)]
async fn patch_configuration(Api(api): Api, ApiJson(patch): ApiJson<serde_json::Value>) -> ApiResult<StatusCode> {
    api.configure(ConfigUpdate::MergePatch(patch)).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(get, tag = "host", path = "/v1/providers",
responses((status = 200, description = "Configured providers", body = Vec<ProviderDeclaration>), ErrorResponses)
)]
async fn providers(Api(api): Api) -> ApiResult<Json<Vec<ProviderDeclaration>>> {
    Ok(Json(api.providers().await?))
}
#[utoipa::path(get, tag = "host", path = "/v1/providers/{provider}",
params(("provider" = String, Path, description = "Opaque provider")),
responses((status = 200, description = "Provider declaration", body = ProviderDeclaration), ErrorResponses)
)]
async fn provider(Api(api): Api, ApiPath(p): ApiPath<String>) -> ApiResult<Json<ProviderDeclaration>> {
    Ok(Json(api.provider(&p).await?))
}
#[utoipa::path(put, tag = "server", path = "/v1/providers/{provider}",
params(("provider" = String, Path, description = "Carried instance name: 1 to 64 of A-Z, a-z, 0-9, _, . and -, starting with a letter or digit")),
request_body(content = Carry, description = "A failure partway also says what it left, as `left`, as a failed provision does"),
responses((status = 201, description = "Carried", body = ProviderDeclaration), (status = 200, description = "Already carried from the same body", body = ProviderDeclaration), ErrorResponses)
)]
async fn put_provider(
    api: Result<Api, ApiError>,
    p: Result<ApiPath<String>, Refusal>,
    body: Result<ApiJson<Carry>, Refusal>,
) -> Result<Response, ProvisionAnswer> {
    let (Api(api), ApiPath(p), ApiJson(body)) = (api.map_err(|e| e.0)?, p.map_err(|e| e.0)?, body.map_err(|e| e.0)?);
    Ok(answer(api.put_provider(&p, &body).await.map_err(ProvisionAnswer)?))
}
#[utoipa::path(get, tag = "server", path = "/v1/providers/{provider}/environments/{id}/services",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 200, description = "Every service the vessel's agent has a record of", body = Vec<ServiceInfo>), ErrorResponses)
)]
async fn services(Api(api): Api, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Vec<ServiceInfo>>> {
    Ok(Json(api.services(&p, &id).await?))
}
#[utoipa::path(get, tag = "server", path = "/v1/providers/{provider}/environments/{id}/services/{name}",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id"),("name" = String, Path, description = "Service name: 1 to 64 of A-Z, a-z, 0-9, _, . and -, starting with a letter or digit")),
responses((status = 200, description = "The service", body = ServiceInfo), ErrorResponses)
)]
async fn service(Api(api): Api, ApiPath((p, id, name)): ApiPath<(String, String, String)>) -> ApiResult<Json<ServiceInfo>> {
    Ok(Json(api.service(&p, &id, &name).await?))
}
#[utoipa::path(put, tag = "server", path = "/v1/providers/{provider}/environments/{id}/services/{name}",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id"),("name" = String, Path, description = "Service name: 1 to 64 of A-Z, a-z, 0-9, _, . and -, starting with a letter or digit")),
request_body = Service,
responses((status = 201, description = "Started", body = ServiceInfo), (status = 200, description = "Already running from the same body", body = ServiceInfo), ErrorResponses)
)]
async fn put_service(
    Api(api): Api,
    ApiPath((p, id, name)): ApiPath<(String, String, String)>,
    ApiJson(service): ApiJson<Service>,
) -> ApiResult<Response> {
    Ok(answer(api.put_service(&p, &id, &name, &service).await?))
}
#[derive(Serialize, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct Grace {
    /// How long after SIGTERM before SIGKILL: 10 seconds by default, at most 60.
    grace_ms: Option<u64>,
}
#[utoipa::path(delete, tag = "server", path = "/v1/providers/{provider}/environments/{id}/services/{name}",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id"),("name" = String, Path, description = "Service name"), Grace),
responses((status = 200, description = "Stopped and forgotten; its last state", body = ServiceInfo), ErrorResponses)
)]
async fn remove_service(
    Api(api): Api,
    ApiPath((p, id, name)): ApiPath<(String, String, String)>,
    ApiQuery(grace): ApiQuery<Grace>,
) -> ApiResult<Json<ServiceInfo>> {
    Ok(Json(api.remove_service(&p, &id, &name, grace.grace_ms).await?))
}
#[utoipa::path(delete, tag = "server", path = "/v1/providers/{provider}",
params(("provider" = String, Path, description = "Carried instance name")),
responses((status = 204, description = "Removed, or never carried"), ErrorResponses)
)]
async fn remove_provider(Api(api): Api, ApiPath(p): ApiPath<String>) -> ApiResult<StatusCode> {
    api.remove_provider(&p).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(put, tag = "server", path = "/v1/providers/{provider}/credential",
params(("provider" = String, Path, description = "Opaque provider")),
request_body = CredentialRefresh,
responses((status = 204, description = "Success"), ErrorResponses)
)]
async fn credential(Api(api): Api, ApiPath(p): ApiPath<String>, ApiJson(r): ApiJson<CredentialRefresh>) -> ApiResult<StatusCode> {
    api.credential(&p, r.value).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(post, tag = "host", path = "/v1/providers/{provider}/prepare",
params(("provider" = String, Path, description = "Opaque provider")),
request_body = PrepareRequest,
responses((status = 200, description = "Prepared provider form", body = Prepared), ErrorResponses)
)]
async fn prepare(Api(api): Api, ApiPath(p): ApiPath<String>, ApiJson(r): ApiJson<PrepareRequest>) -> ApiResult<Json<Prepared>> {
    Ok(Json(api.prepare(&p, &r).await?))
}
#[utoipa::path(post, tag = "host", path = "/v1/providers/{provider}/environments",
params(("provider" = String, Path, description = "Opaque provider")),
request_body = ProvisionRequest,
responses((status = 200, description = "Environment", body = Environment), (status = 201, description = "Created; repeats by label return 200", body = Environment), ErrorResponses)
)]
async fn provision(
    api: Result<Api, ApiError>,
    p: Result<ApiPath<String>, Refusal>,
    r: Result<ApiJson<ProvisionRequest>, Refusal>,
) -> Result<Response, ProvisionAnswer> {
    let (Api(api), ApiPath(p), ApiJson(r)) = (api.map_err(|e| e.0)?, p.map_err(|e| e.0)?, r.map_err(|e| e.0)?);
    Ok(answer(api.provision(&p, &r).await.map_err(ProvisionAnswer)?))
}
/// 201 for what this call made, 200 for what it found.
fn answer<T: Serialize>(provisioned: Provisioned<T>) -> Response {
    match provisioned {
        Provisioned::Created(row) => (StatusCode::CREATED, Json(row)).into_response(),
        Provisioned::Existing(row) => Json(row).into_response(),
    }
}
/// A provision's failure as its HTTP response: the error, and what it left.
pub struct ProvisionAnswer(pub ProvisionError);
impl<E: Into<ProvisionError>> From<E> for ProvisionAnswer {
    fn from(error: E) -> Self {
        Self(error.into())
    }
}
impl IntoResponse for ProvisionAnswer {
    fn into_response(self) -> Response {
        let failure = ProvisionFailure { error: protocol(self.0.error), left: self.0.left };
        // The error's own response gives the status and Retry-After; only the body differs.
        let (mut parts, _) = Refusal(failure.error.clone()).into_response().into_parts();
        parts.headers.remove(http::header::CONTENT_LENGTH);
        Response::from_parts(parts, Body::from(serde_json::to_vec(&failure).expect("a provision failure serializes")))
    }
}
#[utoipa::path(get, tag = "host", path = "/v1/providers/{provider}/environments",
params(("provider" = String, Path, description = "Opaque provider")),
responses((status = 200, description = "Environment inventory", body = Vec<Environment>), ErrorResponses)
)]
async fn list(Api(api): Api, ApiPath(p): ApiPath<String>) -> ApiResult<Json<Vec<Environment>>> {
    Ok(Json(api.list(&p).await?))
}
#[utoipa::path(get, tag = "host", path = "/v1/providers/{provider}/environments/{id}",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 200, description = "Environment", body = Environment), ErrorResponses)
)]
async fn inspect(Api(api): Api, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Environment>> {
    Ok(Json(api.inspect(&p, &id).await?))
}
#[utoipa::path(delete, tag = "host", path = "/v1/providers/{provider}/environments/{id}",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 204, description = "Success; destroying an already absent resource succeeds"), ErrorResponses)
)]
async fn destroy(Api(api): Api, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<StatusCode> {
    api.destroy(&p, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(post, tag = "host", path = "/v1/providers/{provider}/environments/{id}/reach",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 200, description = "Reach recipe", body = Reach), ErrorResponses)
)]
async fn reach(Api(api): Api, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Reach>> {
    Ok(Json(api.reach(&p, &id).await?))
}
#[utoipa::path(post, tag = "host", path = "/v1/providers/{provider}/environments/{id}/suspend",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 200, description = "Resume token", body = ResumeToken), ErrorResponses)
)]
async fn suspend(Api(api): Api, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<ResumeToken>> {
    Ok(Json(api.suspend(&p, &id).await?))
}
#[utoipa::path(post, tag = "host", path = "/v1/providers/{provider}/environments/{id}/resume",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
request_body = ResumeToken,
responses((status = 204, description = "Success"), ErrorResponses)
)]
async fn resume(Api(api): Api, ApiPath((p, id)): ApiPath<(String, String)>, ApiJson(token): ApiJson<ResumeToken>) -> ApiResult<StatusCode> {
    api.resume(&p, &id, &token).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(post, tag = "host", path = "/v1/providers/{provider}/environments/{id}/export",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 200, description = "Export reference", body = Export), ErrorResponses)
)]
async fn export(Api(api): Api, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Export>> {
    Ok(Json(api.export(&p, &id).await?))
}
#[utoipa::path(get, tag = "host", path = "/v1/providers/{provider}/usage",
params(("provider" = String, Path, description = "Opaque provider"),("start" = Timestamp, Query, description = "RFC 3339 period start"),("end" = Timestamp, Query, description = "RFC 3339 period end")),
responses((status = 200, description = "Usage for the requested period", body = Usage), ErrorResponses)
)]
async fn usage(Api(api): Api, ApiPath(p): ApiPath<String>, ApiQuery(period): ApiQuery<Period>) -> ApiResult<Json<Usage>> {
    Ok(Json(api.usage(&p, &period).await?))
}
#[utoipa::path(get, tag = "host", path = "/v1/providers/{provider}/quota",
params(("provider" = String, Path, description = "Opaque provider")),
responses((status = 200, description = "Quota", body = Quota), ErrorResponses)
)]
async fn quota(Api(api): Api, ApiPath(p): ApiPath<String>) -> ApiResult<Json<Quota>> {
    Ok(Json(api.quota(&p).await?))
}

#[utoipa::path(put, tag = "server", path = "/v1/providers/{provider}/environments/{id}/exposures/inward/{name}",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id"),("name" = String, Path, description = "Exposure name: 1 to 64 of A-Z, a-z, 0-9, _, . and -, starting with a letter or digit")),
request_body = InwardRequest,
responses((status = 201, description = "Set; the outcome is in ready and error", body = Inward), (status = 200, description = "Replaced; the outcome is in ready and error", body = Inward), ErrorResponses)
)]
async fn put_inward(
    Api(api): Api,
    ApiPath((p, id, name)): ApiPath<(String, String, String)>,
    ApiJson(r): ApiJson<InwardRequest>,
) -> ApiResult<Response> {
    Ok(match api.put_inward(&p, &id, &name, &r).await? {
        Exposed::Created(exposure) => (StatusCode::CREATED, Json(exposure)).into_response(),
        Exposed::Replaced(exposure) => Json(exposure).into_response(),
    })
}
#[utoipa::path(get, tag = "server", path = "/v1/providers/{provider}/environments/{id}/exposures/inward/{name}",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id"),("name" = String, Path, description = "Exposure name: 1 to 64 of A-Z, a-z, 0-9, _, . and -, starting with a letter or digit")),
responses((status = 200, description = "The exposure as it stands", body = Inward), ErrorResponses)
)]
async fn inward(Api(api): Api, ApiPath((p, id, name)): ApiPath<(String, String, String)>) -> ApiResult<Json<Inward>> {
    Ok(Json(api.inward(&p, &id, &name).await?))
}
#[utoipa::path(get, tag = "server", path = "/v1/providers/{provider}/environments/{id}/exposures/inward",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 200, description = "The environment's exposures", body = Vec<Inward>), ErrorResponses)
)]
async fn inwards(Api(api): Api, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Vec<Inward>>> {
    Ok(Json(api.inwards(&p, &id).await?))
}
#[utoipa::path(delete, tag = "server", path = "/v1/providers/{provider}/environments/{id}/exposures/inward/{name}",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id"),("name" = String, Path, description = "Exposure name: 1 to 64 of A-Z, a-z, 0-9, _, . and -, starting with a letter or digit")),
responses((status = 204, description = "Success; removing an absent exposure succeeds"), ErrorResponses)
)]
async fn remove_inward(Api(api): Api, ApiPath((p, id, name)): ApiPath<(String, String, String)>) -> ApiResult<StatusCode> {
    api.remove_inward(&p, &id, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(put, tag = "server", path = "/v1/providers/{provider}/environments/{id}/exposures/outward/{name}",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id"),("name" = String, Path, description = "Exposure name: 1 to 64 of A-Z, a-z, 0-9, _, . and -, starting with a letter or digit")),
request_body = OutwardRequest,
responses((status = 201, description = "Set; the outcome is in ready and error", body = Outward), (status = 200, description = "Replaced; the outcome is in ready and error", body = Outward), ErrorResponses)
)]
async fn put_outward(
    Api(api): Api,
    ApiPath((p, id, name)): ApiPath<(String, String, String)>,
    ApiJson(r): ApiJson<OutwardRequest>,
) -> ApiResult<Response> {
    Ok(match api.put_outward(&p, &id, &name, &r).await? {
        Exposed::Created(exposure) => (StatusCode::CREATED, Json(exposure)).into_response(),
        Exposed::Replaced(exposure) => Json(exposure).into_response(),
    })
}
#[utoipa::path(get, tag = "server", path = "/v1/providers/{provider}/environments/{id}/exposures/outward/{name}",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id"),("name" = String, Path, description = "Exposure name: 1 to 64 of A-Z, a-z, 0-9, _, . and -, starting with a letter or digit")),
responses((status = 200, description = "The exposure as it stands", body = Outward), ErrorResponses)
)]
async fn outward(Api(api): Api, ApiPath((p, id, name)): ApiPath<(String, String, String)>) -> ApiResult<Json<Outward>> {
    Ok(Json(api.outward(&p, &id, &name).await?))
}
#[utoipa::path(get, tag = "server", path = "/v1/providers/{provider}/environments/{id}/exposures/outward",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 200, description = "The environment's exposures", body = Vec<Outward>), ErrorResponses)
)]
async fn outwards(Api(api): Api, ApiPath((p, id)): ApiPath<(String, String)>) -> ApiResult<Json<Vec<Outward>>> {
    Ok(Json(api.outwards(&p, &id).await?))
}
#[utoipa::path(delete, tag = "server", path = "/v1/providers/{provider}/environments/{id}/exposures/outward/{name}",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id"),("name" = String, Path, description = "Exposure name: 1 to 64 of A-Z, a-z, 0-9, _, . and -, starting with a letter or digit")),
responses((status = 204, description = "Success; removing an absent exposure succeeds"), ErrorResponses)
)]
async fn remove_outward(Api(api): Api, ApiPath((p, id, name)): ApiPath<(String, String, String)>) -> ApiResult<StatusCode> {
    api.remove_outward(&p, &id, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(get, tag = "host", path = "/v1/providers/{provider}/environments/{id}/relay",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 101, description = "Raw byte-stream upgrade; request Connection: Upgrade and Upgrade: drydock-relay", headers(("Connection" = String, description = "Upgrade"), ("Upgrade" = String, description = "drydock-relay"))), ErrorResponses)
)]
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
#[utoipa::path(post, tag = "host", path = "/v1/providers/{provider}/environments/{id}/exec",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
request_body = ExecRequest,
responses((status = 101, description = "Raw byte-stream upgrade; request Connection: Upgrade and Upgrade: drydock-stream", headers(("Connection" = String, description = "Upgrade"), ("Upgrade" = String, description = "drydock-stream"))), ErrorResponses)
)]
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
#[utoipa::path(post, tag = "host", path = "/v1/providers/{provider}/streams",
params(("provider" = String, Path, description = "Opaque provider")),
request_body = Carried,
responses((status = 101, description = "Raw byte-stream upgrade to the endpoint; request Connection: Upgrade and Upgrade: drydock-stream", headers(("Connection" = String, description = "Upgrade"), ("Upgrade" = String, description = "drydock-stream"))), ErrorResponses)
)]
async fn stream(State(s): State<Surface>, Api(api): Api, ApiPath(p): ApiPath<String>, mut request: Request) -> ApiResult<Response> {
    let on = upgrade(&mut request, "drydock-stream").map_err(|refusal| refusal.0)?;
    let ApiJson(endpoint) = ApiJson::<Carried>::from_request(request, &()).await.map_err(|refusal| refusal.0)?;
    let stream = api.stream(&p, &endpoint).await?;
    Ok(switch(on, "drydock-stream", stream, s.stopping))
}
/// A file's raw bytes, as the files route takes them.
#[derive(utoipa::ToSchema)]
#[schema(value_type = String, format = Binary)]
#[allow(dead_code)]
struct FileBytes(Vec<u8>);
/// The largest file the files route takes, held whole while it is passed
/// on: an agent build (about 12 MB) with room to grow, and no more.
pub const GUEST_FILE_LIMIT: usize = 64 << 20;
#[utoipa::path(put, tag = "host", path = "/v1/providers/{provider}/environments/{id}/files",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id"),
("path" = String, Query, description = "Absolute guest path; parents are made and an existing file replaced"),
("mode" = u32, Query, description = "Read, write and execute bits, at most 0o777 (511)")),
request_body(content = FileBytes, content_type = "application/octet-stream", description = "The file's bytes"),
responses((status = 204, description = "The file is in place"), ErrorResponses)
)]
async fn put_file(
    Api(api): Api,
    ApiPath((p, id)): ApiPath<(String, String)>,
    ApiQuery(file): ApiQuery<GuestFile>,
    body: Body,
) -> ApiResult<StatusCode> {
    let bytes = axum::body::to_bytes(body, GUEST_FILE_LIMIT)
        .await
        .map_err(|_| Error::InvalidRequest(format!("file body unreadable or over {GUEST_FILE_LIMIT} bytes")))?;
    api.put_file(&p, &id, &file, bytes).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(post, tag = "host", path = "/v1/providers/{provider}/push-access",
params(("provider" = String, Path, description = "Opaque provider")),
responses((status = 200, description = "Push access to the provider's own registry", body = PushAccess), ErrorResponses)
)]
async fn push_access(Api(api): Api, ApiPath(p): ApiPath<String>) -> ApiResult<Json<PushAccess>> {
    Ok(Json(api.push_access(&p).await?))
}
#[utoipa::path(post, tag = "host", path = "/v1/providers/{provider}/event",
params(("provider" = String, Path, description = "Opaque provider")),
request_body = VendorDelivery,
responses((status = 200, description = "What the delivery says of each environment it is about", body = Vec<VendorObservation>), ErrorResponses)
)]
async fn event(
    Api(api): Api,
    ApiPath(p): ApiPath<String>,
    ApiJson(delivery): ApiJson<VendorDelivery>,
) -> ApiResult<Json<Vec<VendorObservation>>> {
    Ok(Json(api.event(&p, &delivery).await?))
}

#[derive(Deserialize)]
struct EventQuery {
    since: Option<String>,
}
#[utoipa::path(get, tag = "server", path = "/v1/events",
params(("since" = Option<String>, Query, description = "Exclusive last-seen cursor; absent starts with a snapshot")),
responses((status = 200, description = "NDJSON stream: one ObserveRecord JSON value per line", body = ObserveRecord, content_type = "application/x-ndjson"), ErrorResponses)
)]
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

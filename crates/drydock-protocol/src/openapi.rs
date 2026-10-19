//! OpenAPI route descriptions; these functions are documentation, not HTTP handlers.
#![allow(dead_code)]
use crate::*;
use utoipa::OpenApi;

#[derive(utoipa::IntoResponses)]
#[response(
    status = "default",
    description = "Typed adaptor error; no automatic retries. retry_after is seconds."
)]
struct ErrorResponses(ProtocolError);

#[utoipa::path(get, path = "/v1/hello",
responses((status = 200, description = "Success", body = Hello), ErrorResponses)
)]
fn hello() {}

#[utoipa::path(put, path = "/v1/config",
request_body = HostConfiguration,
responses((status = 204, description = "Success"), ErrorResponses)
)]
fn configure() {}

#[utoipa::path(put, path = "/v1/providers/{provider}/credential",
params(("provider" = String, Path, description = "Opaque provider")),
request_body = CredentialRefresh,
responses((status = 204, description = "Success"), ErrorResponses)
)]
fn refresh_credential() {}

#[utoipa::path(post, path = "/v1/providers/{provider}/prepare",
params(("provider" = String, Path, description = "Opaque provider")),
request_body = PrepareRequest,
responses((status = 200, description = "Success", body = Prepared), ErrorResponses)
)]
fn prepare() {}

#[utoipa::path(post, path = "/v1/providers/{provider}/environments",
params(("provider" = String, Path, description = "Opaque provider")),
request_body = ProvisionRequest,
responses((status = 200, description = "Success", body = Sandbox), (status = 201, description = "Created; repeats by label return 200", body = Sandbox), ErrorResponses)
)]
fn provision() {}

#[utoipa::path(get, path = "/v1/providers/{provider}/environments",
params(("provider" = String, Path, description = "Opaque provider")),
responses((status = 200, description = "Success", body = Vec<Sandbox>), ErrorResponses)
)]
fn list() {}

#[utoipa::path(get, path = "/v1/providers/{provider}/environments/{id}",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 200, description = "Success", body = Sandbox), ErrorResponses)
)]
fn inspect() {}

#[utoipa::path(delete, path = "/v1/providers/{provider}/environments/{id}",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 204, description = "Success; destroying an already absent resource succeeds"), ErrorResponses)
)]
fn destroy() {}

#[utoipa::path(post, path = "/v1/providers/{provider}/environments/{id}/reach",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 200, description = "Success", body = Reach), ErrorResponses)
)]
fn reach() {}

#[utoipa::path(get, path = "/v1/providers/{provider}/environments/{id}/relay",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 101, description = "Raw byte-stream upgrade; request Connection: Upgrade and Upgrade: drydock-relay", headers(("Connection" = String, description = "Upgrade"), ("Upgrade" = String, description = "drydock-relay"))), ErrorResponses)
)]
fn relay() {}

#[utoipa::path(post, path = "/v1/providers/{provider}/environments/{id}/exec",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
request_body = ExecRequest,
responses((status = 101, description = "Raw byte-stream upgrade; request Connection: Upgrade and Upgrade: drydock-stream", headers(("Connection" = String, description = "Upgrade"), ("Upgrade" = String, description = "drydock-stream"))), ErrorResponses)
)]
fn exec() {}

#[utoipa::path(post, path = "/v1/providers/{provider}/environments/{id}/suspend",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 200, description = "Success", body = ResumeToken), ErrorResponses)
)]
fn suspend() {}

#[utoipa::path(post, path = "/v1/providers/{provider}/environments/{id}/resume",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
request_body = ResumeToken,
responses((status = 204, description = "Success"), ErrorResponses)
)]
fn resume() {}

#[utoipa::path(post, path = "/v1/providers/{provider}/environments/{id}/export",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 200, description = "Success", body = Export), ErrorResponses)
)]
fn export() {}

#[utoipa::path(get, path = "/v1/events",
params(("since" = Option<String>, Query, description = "Exclusive last-seen cursor; absent starts with a snapshot")),
responses((status = 200, description = "Success", body = ObserveRecord, content_type = "application/x-ndjson"), ErrorResponses)
)]
fn observe() {}

#[utoipa::path(get, path = "/v1/providers/{provider}/usage",
params(("provider" = String, Path, description = "Opaque provider"),("start" = String, Query, description = "RFC 3339 period start"),("end" = String, Query, description = "RFC 3339 period end")),
responses((status = 200, description = "Success", body = Usage), ErrorResponses)
)]
fn usage() {}

#[utoipa::path(get, path = "/v1/providers/{provider}/quota",
params(("provider" = String, Path, description = "Opaque provider")),
responses((status = 200, description = "Success", body = Quota), ErrorResponses)
)]
fn quota() {}

#[derive(OpenApi)]
#[openapi(
    components(schemas(ProtocolError)),
    info(
        title = "Drydock adaptor protocol",
        version = "1.0.0",
        description = "ADR 0070. Managed Unix sockets authenticate peer credentials; external loopback hosts use bearer token files. Provider labels are idempotency keys; all subsequent operations use opaque IDs. Optional routes are declared by capabilities. Observe is NDJSON; relay and exec upgrade to raw streams."
    ),
    paths(
        hello,
        configure,
        refresh_credential,
        prepare,
        provision,
        list,
        inspect,
        destroy,
        reach,
        relay,
        exec,
        suspend,
        resume,
        export,
        observe,
        usage,
        quota
    )
)]
struct Document;

/// Generate the checked-in OpenAPI 3.1 document deterministically.
pub fn document() -> utoipa::openapi::OpenApi {
    let mut document = Document::openapi();
    document.info.version = PROTOCOL_VERSION.to_owned();
    document
}

/// Stable JSON presentation shared by the generator and drift test.
pub fn to_json() -> String {
    format!(
        "{}\n",
        document().to_pretty_json().expect("OpenAPI serializes")
    )
}

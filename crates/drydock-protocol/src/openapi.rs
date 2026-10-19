//! OpenAPI route descriptions; these functions are documentation, not HTTP handlers.
use crate::*;
use utoipa::OpenApi;

#[utoipa::path(get, path = "/v1/hello",
responses((status = 200, description = "Success", body = Hello), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn hello() {}

#[utoipa::path(put, path = "/v1/configuration",
request_body = HostConfiguration,
responses((status = 204, description = "Success"), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn configure() {}

#[utoipa::path(put, path = "/v1/providers/{provider}/credential",
params(("provider" = String, Path, description = "Opaque provider")),
request_body = CredentialRefresh,
responses((status = 204, description = "Success"), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn refresh_credential() {}

#[utoipa::path(post, path = "/v1/providers/{provider}/prepare",
params(("provider" = String, Path, description = "Opaque provider")),
request_body = PrepareRequest,
responses((status = 200, description = "Success", body = Prepared), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn prepare() {}

#[utoipa::path(post, path = "/v1/providers/{provider}",
params(("provider" = String, Path, description = "Opaque provider")),
request_body = ProvisionRequest,
responses((status = 200, description = "Success", body = Sandbox), (status = 201, description = "Created; repeats by label return 200", body = Sandbox), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn provision() {}

#[utoipa::path(get, path = "/v1/providers/{provider}",
params(("provider" = String, Path, description = "Opaque provider")),
responses((status = 200, description = "Success", body = Vec<Sandbox>), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn list() {}

#[utoipa::path(get, path = "/v1/providers/{provider}/{id}",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 200, description = "Success", body = Sandbox), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn inspect() {}

#[utoipa::path(delete, path = "/v1/providers/{provider}/{id}",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 204, description = "Success; destroying an already absent resource succeeds"), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn destroy() {}

#[utoipa::path(get, path = "/v1/providers/{provider}/{id}/reach",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 200, description = "Success", body = Reach), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn reach() {}

#[utoipa::path(get, path = "/v1/providers/{provider}/{id}/relay",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 101, description = "Raw byte-stream upgrade"), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn relay() {}

#[utoipa::path(post, path = "/v1/providers/{provider}/{id}/exec",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
request_body = ExecRequest,
responses((status = 101, description = "Raw byte-stream upgrade"), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn exec() {}

#[utoipa::path(post, path = "/v1/providers/{provider}/{id}/suspend",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 200, description = "Success", body = ResumeToken), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn suspend() {}

#[utoipa::path(post, path = "/v1/providers/{provider}/{id}/resume",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
request_body = ResumeToken,
responses((status = 204, description = "Success"), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn resume() {}

#[utoipa::path(post, path = "/v1/providers/{provider}/{id}/export",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 200, description = "Success", body = Export), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn export() {}

#[utoipa::path(get, path = "/v1/observe",
params(("since" = Option<String>, Query, description = "Exclusive last-seen cursor; absent starts with a snapshot")),
responses((status = 200, description = "Success", body = ObserveRecord, content_type = "application/x-ndjson"), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn observe() {}

#[utoipa::path(get, path = "/v1/providers/{provider}/usage",
params(("provider" = String, Path, description = "Opaque provider"),("start" = String, Query, description = "RFC 3339 period start"),("end" = String, Query, description = "RFC 3339 period end")),
responses((status = 200, description = "Success", body = Usage), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn usage() {}

#[utoipa::path(get, path = "/v1/providers/{provider}/quota",
params(("provider" = String, Path, description = "Opaque provider")),
responses((status = 200, description = "Success", body = Quota), (status = "default", description = "Typed adaptor error; no automatic retries. retry_after is seconds.", body = ProtocolError))
)]
#[allow(dead_code)]
fn quota() {}

#[derive(OpenApi)]
#[openapi(
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
    Document::openapi()
}

/// Stable JSON presentation shared by the generator and drift test.
pub fn to_json() -> String {
    format!(
        "{}\n",
        document().to_pretty_json().expect("OpenAPI serializes")
    )
}

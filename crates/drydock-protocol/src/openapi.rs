//! OpenAPI route descriptions; these functions are documentation, not HTTP handlers.
#![allow(dead_code)]
use crate::*;
use utoipa::OpenApi;

#[derive(utoipa::IntoResponses)]
enum ErrorResponses {
    #[response(status = 404, description = "NotFound: route, provider or environment does not exist")]
    NotFound(ProtocolError),
    #[response(status = 405, description = "MethodNotAllowed")]
    MethodNotAllowed(ProtocolError),
    #[response(status = 422, description = "Refused: request cannot be met")]
    Refused(ProtocolError),
    #[response(status = 503, description = "Unavailable: provider not ready or temporarily unavailable")]
    Unavailable(ProtocolError),
    #[response(status = 429, description = "RateLimited: retry_after is whole seconds")]
    RateLimited(ProtocolError),
    #[response(status = 402, description = "QuotaExhausted")]
    QuotaExhausted(ProtocolError),
    #[response(status = 502, description = "CredentialRejected: vendor rejected delivered credentials")]
    CredentialRejected(ProtocolError),
    #[response(status = 424, description = "CommandFailed: completed guest command failed; includes exit code and sensitive merged output")]
    CommandFailed(ProtocolError),
    #[response(status = 500, description = "Internal: sensitive provider error for supervisor diagnostics")]
    Internal(ProtocolError),
}

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
responses((status = 200, description = "Success", body = Environment), (status = 201, description = "Created; repeats by label return 200", body = Environment), ErrorResponses)
)]
fn provision() {}

#[utoipa::path(get, path = "/v1/providers/{provider}/environments",
params(("provider" = String, Path, description = "Opaque provider")),
responses((status = 200, description = "Success", body = Vec<Environment>), ErrorResponses)
)]
fn list() {}

#[utoipa::path(get, path = "/v1/providers/{provider}/environments/{id}",
params(("provider" = String, Path, description = "Opaque provider"),("id" = String, Path, description = "Opaque id")),
responses((status = 200, description = "Success", body = Environment), ErrorResponses)
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
params(("provider" = String, Path, description = "Opaque provider"),("start" = Timestamp, Query, description = "RFC 3339 period start"),("end" = Timestamp, Query, description = "RFC 3339 period end")),
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
    // Keep runtime and cross-language schema rules identical.
    use utoipa::openapi::{RefOr, schema::Schema};
    let schemas = &mut document.components.as_mut().expect("components").schemas;
    if let Some(RefOr::T(Schema::Object(port))) = schemas.get_mut("Port") {
        port.minimum = Some(1.into());
        port.maximum = Some(65535.into());
    }
    if let Some(RefOr::T(Schema::Object(host))) = schemas.get_mut("HostAddress") {
        host.pattern = Some(validation::host_pattern().into());
        host.max_length = Some(253);
    }
    if let Some(RefOr::T(Schema::Object(cidr))) = schemas.get_mut("Cidr") {
        cidr.pattern = Some(validation::cidr_pattern().into());
    }
    if let Some(RefOr::T(Schema::Object(period))) = schemas.get_mut("Period") {
        period.extensions = Some(
            utoipa::openapi::extensions::ExtensionsBuilder::new().add("x-drydock-invariants", serde_json::json!(["start <= end"])).build(),
        );
        period.description = Some("RFC 3339 endpoints; start must be <= end (equal endpoints are an empty interval).".into());
    }
    // A nonempty executable is required, but later arguments may be empty.
    let Some(RefOr::T(Schema::Object(exec))) = schemas.get_mut("ExecRequest") else { panic!("ExecRequest schema changed") };
    let Some(RefOr::T(Schema::Array(command))) = exec.properties.get_mut("command") else { panic!("command schema changed") };
    command.prefix_items = vec![
        utoipa::openapi::schema::ObjectBuilder::new().schema_type(utoipa::openapi::schema::Type::String).min_length(Some(1)).build().into(),
    ];

    // Deduplicate response declarations, narrowing each body to its status class.
    // Locate variants by their serialized discriminator rather than their order.
    let Some(RefOr::T(Schema::OneOf(errors))) = schemas.get("ProtocolError") else { panic!("ProtocolError schema changed") };
    let variants = errors.items.clone();
    let components = document.components.as_mut().expect("components");
    for path in document.paths.paths.values_mut() {
        for operation in [&mut path.get, &mut path.put, &mut path.post, &mut path.delete].into_iter().flatten() {
            for (status, class) in [
                ("404", "not_found"),
                ("405", "method_not_allowed"),
                ("422", "refused"),
                ("503", "unavailable"),
                ("429", "rate_limited"),
                ("402", "quota_exhausted"),
                ("502", "credential_rejected"),
                ("424", "command_failed"),
                ("500", "internal"),
            ] {
                let name = format!("Error{status}");
                let Some(RefOr::T(mut response)) = operation.responses.responses.get(status).cloned() else {
                    panic!("missing error response")
                };
                let variant = variants.iter().find(|variant| {
                    matches!(variant, RefOr::T(Schema::Object(object)) if matches!(object.properties.get("kind"), Some(RefOr::T(Schema::Object(kind))) if kind.enum_values.as_ref().is_some_and(|values| values.contains(&serde_json::Value::String(class.into())))))
                }).expect("error class schema exists").clone();
                response.content.get_mut("application/json").expect("JSON error").schema = Some(variant);
                if status == "429" || status == "503" {
                    response.headers.insert(
                        "Retry-After".into(),
                        utoipa::openapi::header::HeaderBuilder::new()
                            .description(Some("Optional whole seconds until retry; adaptors do not retry automatically"))
                            .schema(
                                utoipa::openapi::schema::ObjectBuilder::new()
                                    .schema_type(utoipa::openapi::schema::Type::Integer)
                                    .minimum(Some(0)),
                            )
                            .build(),
                    );
                }
                components.responses.insert(name.clone(), response.into());
                operation.responses.responses.insert(status.into(), utoipa::openapi::Ref::from_response_name(name).into());
            }
        }
    }
    document
}

/// Stable JSON presentation shared by the generator and drift test.
pub fn to_json() -> String {
    format!("{}\n", document().to_pretty_json().expect("OpenAPI serializes"))
}

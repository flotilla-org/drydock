//! Canonical API metadata and shared schema constraints; routes come from real handlers.
#![allow(dead_code)]
use crate::*;
use utoipa::OpenApi;

#[derive(utoipa::IntoResponses)]
pub enum ErrorResponses {
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

#[derive(OpenApi)]
#[openapi(
    components(schemas(ProtocolError)),
    info(
        title = "Drydock adaptor protocol",
        version = "1.0.0",
        description = "One API for the drydock server and language hosts. Hosts serve every route except those marked x-drydock-server-only. Managed Unix sockets use private directory/socket permissions; external loopback hosts use bearer token files. The optional Drydock-Credential header carries an opaque provider credential for that request only: the server sends it on every call to a host, and on the public API it overrides the held credential without storing or logging it. Provider labels are idempotency keys; all subsequent operations use opaque IDs. Optional routes are declared by ports. Observe is NDJSON; relay and exec upgrade to raw streams."
    )
)]
struct Document;

/// Generate the checked-in OpenAPI 3.1 document deterministically.
pub fn document(routes: utoipa::openapi::OpenApi) -> utoipa::openapi::OpenApi {
    let mut document = Document::openapi();
    document.merge(routes);
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

    use utoipa::openapi::{
        extensions::ExtensionsBuilder,
        path::{ParameterBuilder, ParameterIn},
    };
    for (route, path) in document.paths.paths.iter_mut() {
        let server_only = route == "/v1/events" || route.ends_with("/credential");
        for operation in [&mut path.get, &mut path.put, &mut path.patch, &mut path.post, &mut path.delete].into_iter().flatten() {
            if server_only {
                operation.extensions = Some(ExtensionsBuilder::new().add("x-drydock-server-only", true).build());
            } else if route.starts_with("/v1/providers/{provider}") {
                let header = ParameterBuilder::new()
                    .name("Drydock-Credential")
                    .parameter_in(ParameterIn::Header)
                    .description(Some("Opaque provider credential for this request only, passed as-is; never stored or logged"))
                    .schema(Some(utoipa::openapi::schema::ObjectBuilder::new().schema_type(utoipa::openapi::schema::Type::String)));
                operation.parameters.get_or_insert_with(Vec::new).push(header.build());
            }
        }
    }
    // Deduplicate response declarations, narrowing each body to its status class.
    // Locate variants by their serialized discriminator rather than their order.
    let Some(RefOr::T(Schema::OneOf(errors))) = schemas.get("ProtocolError") else { panic!("ProtocolError schema changed") };
    let variants = errors.items.clone();
    let components = document.components.as_mut().expect("components");
    for path in document.paths.paths.values_mut() {
        for operation in [&mut path.get, &mut path.put, &mut path.patch, &mut path.post, &mut path.delete].into_iter().flatten() {
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

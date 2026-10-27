//! Private host REST contract, generated with the public protocol's Utoipa exporter.
//! Declarations document the thin adapter, not main-server policy or public routes.
#![allow(dead_code)]
use crate::*;
use utoipa::OpenApi;
type Unit = ();
// Utoipa cannot name tuple generic arguments; these schema-only tuples have
// exactly the same Serde shape as the Rust adapter arguments.
#[derive(utoipa::ToSchema)]
struct ExecArgs(String, ExecRequest);
#[derive(utoipa::ToSchema)]
struct ResumeArgs(String, ResumeToken);

#[derive(utoipa::IntoResponses)]
enum Errors {
    #[response(status = 404, description = "Unknown provider handle")]
    NotFound(ProtocolError),
    #[response(status = 422, description = "Invalid input or absent operation port")]
    Refused(ProtocolError),
    #[response(status = 500, description = "Provider failure")]
    Internal(ProtocolError),
    #[response(status = 503, description = "Provider unavailable")]
    Unavailable(ProtocolError),
    #[response(status = 429, description = "Vendor rate limited; optional Retry-After seconds")]
    RateLimited(ProtocolError),
    #[response(status = 402, description = "Vendor quota exhausted")]
    Quota(ProtocolError),
    #[response(status = 502, description = "Vendor rejected credential")]
    Credential(ProtocolError),
    #[response(status = 424, description = "Guest command failed")]
    Command(ProtocolError),
}

#[utoipa::path(get, path = "/v1/hello", responses((status = 200, body = BridgeHello)))]
fn hello() {}
#[utoipa::path(post, path = "/private/modules/{module}/configure",
    params(("module" = String, Path)), request_body = ProviderConfiguration,
    responses((status = 200, body = ConfiguredProvider), Errors))]
fn configure() {}
#[utoipa::path(delete, path = "/private/providers/{provider}", params(("provider" = String, Path)),
    responses((status = 204, description = "Handle released; logical module binding remains loaded")))]
fn release() {}
#[utoipa::path(post, path = "/private/providers/{provider}/facts", params(("provider" = String, Path)),
    request_body = Call<Unit>, responses((status = 200, body = Facts), Errors))]
fn facts() {}
#[utoipa::path(post, path = "/private/providers/{provider}/prepare", params(("provider" = String, Path)),
    request_body = Call<PrepareRequest>, responses((status = 200, body = Prepared), Errors))]
fn prepare() {}
#[utoipa::path(post, path = "/private/providers/{provider}/provision", params(("provider" = String, Path)),
    request_body = Call<ProvisionRequest>, responses((status = 200, body = Provisioned), Errors))]
fn provision() {}
#[utoipa::path(post, path = "/private/providers/{provider}/list", params(("provider" = String, Path)),
    request_body = Call<Unit>, responses((status = 200, body = Vec<ObservedEnvironment>), Errors))]
fn list() {}
#[utoipa::path(post, path = "/private/providers/{provider}/inspect", params(("provider" = String, Path)),
    request_body = Call<String>, responses((status = 200, body = ObservedEnvironment), Errors))]
fn inspect() {}
#[utoipa::path(post, path = "/private/providers/{provider}/inspect-after-lifecycle", params(("provider" = String, Path)),
    request_body = Call<String>, responses((status = 200, body = ObservedEnvironment), Errors))]
fn inspect_after_lifecycle() {}
#[utoipa::path(post, path = "/private/providers/{provider}/destroy", params(("provider" = String, Path)),
    request_body = Call<String>, responses((status = 200, body = ()), Errors))]
fn destroy() {}
#[utoipa::path(post, path = "/private/providers/{provider}/reach", params(("provider" = String, Path)),
    request_body = Call<String>, responses((status = 200, body = Connection), Errors))]
fn reach() {}
#[utoipa::path(post, path = "/private/providers/{provider}/relay", params(("provider" = String, Path)),
    request_body = Call<String>,
    responses((status = 101, description = "Connection: Upgrade; Upgrade: drydock-relay; raw duplex bytes"), Errors))]
fn relay() {}
#[utoipa::path(post, path = "/private/providers/{provider}/subscribe", params(("provider" = String, Path)),
    request_body = Call<Unit>,
    responses((status = 200, description = "NDJSON records, not an array; immutable subscription credentials; disconnect cancels run",
    body = SubscriptionRecord, content_type = "application/x-ndjson"), Errors))]
fn subscribe() {}
#[utoipa::path(post, path = "/private/providers/{provider}/exec", params(("provider" = String, Path)),
    request_body = Call<ExecArgs>,
    responses((status = 101, description = "Connection: Upgrade; Upgrade: drydock-stream; raw duplex bytes"), Errors))]
fn exec() {}
#[utoipa::path(post, path = "/private/providers/{provider}/suspend", params(("provider" = String, Path)),
    request_body = Call<String>, responses((status = 200, body = ResumeToken), Errors))]
fn suspend() {}
#[utoipa::path(post, path = "/private/providers/{provider}/resume", params(("provider" = String, Path)),
    request_body = Call<ResumeArgs>, responses((status = 200, body = ()), Errors))]
fn resume() {}
#[utoipa::path(post, path = "/private/providers/{provider}/export", params(("provider" = String, Path)),
    request_body = Call<String>, responses((status = 200, body = Export), Errors))]
fn export() {}
#[utoipa::path(post, path = "/private/providers/{provider}/usage", params(("provider" = String, Path)),
    request_body = Call<Period>, responses((status = 200, body = Usage), Errors))]
fn usage() {}
#[utoipa::path(post, path = "/private/providers/{provider}/quota", params(("provider" = String, Path)),
    request_body = Call<Unit>, responses((status = 200, body = Quota), Errors))]
fn quota() {}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Drydock private provider host",
        description = "Generated from drydock-provider Rust declarations. Loader handles are opaque. Credentials are immutable per call/subscription. Hosts invoke providers without server policy or retries. Managed same-user UDS access uses directory 0700 and socket 0600; no peer UID checks."
    ),
    paths(
        hello,
        configure,
        release,
        facts,
        prepare,
        provision,
        list,
        inspect,
        inspect_after_lifecycle,
        destroy,
        reach,
        relay,
        subscribe,
        exec,
        suspend,
        resume,
        export,
        usage,
        quota
    )
)]
struct Document;

// std::time::Duration's Serde representation is an object, not an ISO duration.
// Utoipa's built-in Duration mapping is a string, so describe this standard type.
pub(crate) fn duration_schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    use utoipa::openapi::schema::{ObjectBuilder, Type};
    ObjectBuilder::new()
        .schema_type(Type::Object)
        .property("secs", ObjectBuilder::new().schema_type(Type::Integer).minimum(Some(0)))
        .property("nanos", ObjectBuilder::new().schema_type(Type::Integer).minimum(Some(0)).maximum(Some(u32::MAX)))
        .required("secs")
        .required("nanos")
        .into()
}

pub fn document() -> serde_json::Value {
    let mut document = Document::openapi();
    document.info.version = PROTOCOL_VERSION.into();
    // Reuse the public generator's integer/address/exec/period schema rules.
    // These are the SAME Rust payloads; no private copy of their validation policy.
    document
        .components
        .as_mut()
        .expect("components")
        .schemas
        .extend(drydock_protocol::openapi::document().components.expect("public components").schemas);
    // Utoipa 5 inlines generic arguments (losing the public schema patches),
    // leaves unit unconstrained and erases tuple item types. Correct those
    // exporter limitations without changing the Rust or Serde contract.
    let mut value = serde_json::to_value(document).expect("document JSON");
    let schemas = value["components"]["schemas"].as_object_mut().expect("schemas");
    for (call, argument) in
        [("Call_PrepareRequest", "PrepareRequest"), ("Call_ProvisionRequest", "ProvisionRequest"), ("Call_Period", "Period")]
    {
        schemas.get_mut(call).expect("call")["properties"]["argument"] =
            serde_json::json!({"$ref": format!("#/components/schemas/{argument}")});
    }
    schemas.get_mut("Call_TupleUnit").expect("unit call")["properties"]["argument"] = serde_json::json!({"type": "null"});
    for (call, tuple, payload) in [("Call_ExecArgs", "ExecArgs", "ExecRequest"), ("Call_ResumeArgs", "ResumeArgs", "ResumeToken")] {
        schemas.insert(
            tuple.into(),
            serde_json::json!({"type":"array", "minItems":2, "maxItems":2,
            "prefixItems":[{"type":"string"},{"$ref":format!("#/components/schemas/{payload}")}], "items":false}),
        );
        schemas.get_mut(call).expect("tuple call")["properties"]["argument"] =
            serde_json::json!({"$ref": format!("#/components/schemas/{tuple}")});
    }
    for operation in ["destroy", "resume"] {
        value["paths"][format!("/private/providers/{{provider}}/{operation}")]["post"]["responses"]["200"]["content"]["application/json"]
            ["schema"] = serde_json::json!({"type":"null"});
    }
    value
}
pub fn to_json() -> String {
    format!("{}\n", serde_json::to_string_pretty(&document()).expect("host OpenAPI serializes"))
}

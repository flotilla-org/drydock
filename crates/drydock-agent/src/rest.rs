//! Server-side HTTP plumbing: the one layer that turns every refusal the
//! framework makes (an unknown route, a wrong method, a body or path its
//! extractors reject) into the structured error. Handlers use axum's own
//! extractors; their rejections pass through here.
use crate::{AgentError, ErrorKind};
use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

fn rejected(operation: &str, subject: impl std::fmt::Display, status: StatusCode, text: String) -> AgentError {
    AgentError::new(operation, subject, ErrorKind::from_status(status.as_u16()), text).with_status(status.as_u16())
}

/// Percent-encode an ID as one route segment. Only unreserved bytes stay,
/// so an ID containing `/` still names one segment.
pub(crate) fn encode_segment(id: &str) -> String {
    const SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');
    percent_encoding::utf8_percent_encode(id, SET).to_string()
}
/// Whether an `If-Match` precondition holds for a resource whose current
/// tag is `current` (None when it does not exist). Any tag in the list may
/// match; `*` matches any existing resource. A header that is not `*` or a
/// list of entity tags is refused rather than ignored.
pub(crate) fn if_match(
    operation: &str,
    subject: impl std::fmt::Display,
    headers: &HeaderMap,
    current: Option<&str>,
) -> Result<bool, AgentError> {
    use headers::HeaderMapExt;
    let refuse = || AgentError::new(operation, &subject, ErrorKind::InvalidInput, "If-Match must be * or a list of entity tags");
    let values: Vec<&str> = headers.get_all(header::IF_MATCH).iter().map(|v| v.to_str()).collect::<Result<_, _>>().map_err(|_| refuse())?;
    if values.is_empty() {
        return Ok(true);
    }
    // headers decodes any value as an If-Match without complaint, so the
    // syntax is checked here first: that is what makes a malformed header a
    // 400 rather than a precondition nobody can meet.
    if !values.iter().all(|value| value.trim() == "*" || entity_tags(value)) {
        return Err(refuse());
    }
    let condition = headers.typed_try_get::<headers::IfMatch>().ok().flatten().ok_or_else(refuse)?;
    Ok(current.is_some_and(|tag| condition.is_any() || tag.parse::<headers::ETag>().is_ok_and(|tag| condition.precondition_passes(&tag))))
}
/// A comma-separated list of one or more entity tags (RFC 9110, 8.8.3).
fn entity_tags(value: &str) -> bool {
    let mut rest = value.trim();
    loop {
        let tag = rest.strip_prefix("W/").unwrap_or(rest);
        let Some(end) = tag.strip_prefix('"').and_then(|t| t.find('"')) else { return false };
        if !tag[1..=end].bytes().all(|b| b == 0x21 || (0x23..=0x7e).contains(&b) || b >= 0x80) {
            return false;
        }
        // end indexes the closing quote within tag[1..]; past it is tag[end + 2..].
        rest = tag[end + 2..].trim_start();
        match rest.strip_prefix(',') {
            Some(next) => rest = next.trim_start(),
            None => return rest.is_empty(),
        }
    }
}
/// A panicking handler is answered with the structured error, not a dropped
/// stream, and its message goes to the agent's log.
pub(crate) fn panicked(payload: Box<dyn std::any::Any + Send>) -> Response {
    let message = payload.downcast_ref::<&str>().copied().or_else(|| payload.downcast_ref::<String>().map(String::as_str));
    tracing::error!(panic = message.unwrap_or("(not a string)"), "request handler panicked");
    AgentError::new("request", "handler", ErrorKind::Other, "the agent failed while handling this request").into_response()
}

/// Any refusal that is not already an AgentError, from the framework or
/// from hyper, becomes one carrying the original status and text. Routing
/// refusals name the method and path; extractor refusals keep the reason the
/// extractor gave, such as serde's (one over 64 KiB gives way to the status's
/// canonical reason). Other headers, such as a 405's `Allow`, are kept.
pub(crate) async fn structured(request: Request, next: Next) -> Response {
    let (method, subject) = (request.method().clone(), request.uri().path().to_owned());
    let response = next.run(request).await;
    let status = response.status();
    // A JSON refusal is already an AgentError: every handler refusal is, and
    // no framework rejection the agent uses answers in JSON.
    let json = response.headers().get(header::CONTENT_TYPE).is_some_and(|v| v.as_bytes().starts_with(b"application/json"));
    if !(status.is_client_error() || status.is_server_error()) || json {
        return response;
    }
    let (parts, body) = response.into_parts();
    let text = match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(bytes) if !bytes.is_empty() => Some(String::from_utf8_lossy(&bytes).into_owned()),
        _ => None,
    };
    let (operation, text) = match (status, text) {
        (StatusCode::NOT_FOUND, None) => ("request.route", format!("no route {method} {subject}")),
        (StatusCode::METHOD_NOT_ALLOWED, None) => ("request.route", format!("{method} is not allowed on {subject}")),
        (_, text) => ("request", text.unwrap_or_else(|| status.canonical_reason().unwrap_or("refused").to_owned())),
    };
    let mut structured = rejected(operation, subject, status, text).into_response();
    for (name, value) in &parts.headers {
        if name != header::CONTENT_TYPE && name != header::CONTENT_LENGTH {
            structured.headers_mut().insert(name, value.clone());
        }
    }
    structured
}

/// A header value. Control characters, which a header cannot carry, are
/// percent-encoded, so no value can make a handler panic.
pub(crate) fn header_value(value: impl std::fmt::Display) -> HeaderValue {
    let text = value.to_string();
    HeaderValue::from_str(&text).unwrap_or_else(|_| {
        let encoded = percent_encoding::utf8_percent_encode(&text, percent_encoding::CONTROLS).to_string();
        HeaderValue::from_str(&encoded).unwrap_or_else(|_| HeaderValue::from_static("invalid"))
    })
}

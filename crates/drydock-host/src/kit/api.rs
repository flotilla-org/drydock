//! A vendor's HTTP control plane: authenticated requests, a 2xx answer as
//! JSON, any other status as the protocol's error (by a table the vendor
//! may override), transport failures as Unavailable, and cursor paging.
//! Nothing here retries: modules don't (ADR 0070).
use super::Vendor;
use crate::module::{Credentials, HttpClient, Result, refused};
use bytes::Bytes;
use drydock_protocol::ProtocolError;
use reqwest::{
    Method, Url,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue},
};
use serde_json::Value;
use std::{collections::BTreeSet, sync::Arc};

/// How the API key travels.
#[derive(Clone)]
pub enum Auth {
    /// `Authorization: Bearer <key>`.
    Bearer,
    /// The key alone in a header of the vendor's own (E2B's `X-API-Key`).
    Header(HeaderName),
}

/// One refused answer: what the status table and a vendor's overrides read.
pub struct Failure<'a> {
    pub vendor: Vendor,
    /// `METHOD /path`, as error reasons name it.
    pub operation: &'a str,
    pub status: u16,
    pub body: &'a [u8],
    /// From the answer's headers, as [`Api::retry_after`] reads them.
    pub retry_after: Option<u64>,
}
impl Failure<'_> {
    /// `"<Vendor> <operation> HTTP <status>: <explanation>"`.
    pub fn reason(&self, explanation: &str) -> String {
        format!("{} {} HTTP {}: {explanation}", self.vendor, self.operation, self.status)
    }
    /// The body's JSON `message`, else the body itself, cut to its start.
    pub fn message(&self) -> String {
        let text = serde_json::from_slice::<Value>(self.body)
            .ok()
            .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_owned))
            .unwrap_or_else(|| String::from_utf8_lossy(self.body).trim().to_owned());
        cut(&text, EXPLANATION_CHARS)
    }
    /// The table every vendor starts from, `reason` kept in each error:
    /// 401 rejects the credential, 402 is quota, 403 a refusal (permission),
    /// 404 not found, 429 rate limited, 408 and 5xx unavailable, the other
    /// 4xx refusals (the request cannot be met as asked) and anything else
    /// internal.
    pub fn standard(&self, reason: String) -> ProtocolError {
        let retry_after = self.retry_after;
        match self.status {
            401 => ProtocolError::CredentialRejected { reason },
            402 => ProtocolError::QuotaExhausted { reason },
            403 => ProtocolError::Refused { reason: format!("permission denied; {reason}") },
            404 => ProtocolError::NotFound { reason },
            429 => ProtocolError::RateLimited { reason, retry_after },
            408 | 500..=599 => ProtocolError::Unavailable { reason, retry_after, provider_error: None },
            400..=499 => ProtocolError::Refused { reason },
            status => ProtocolError::Internal {
                reason: format!("unexpected {} {} HTTP {status}", self.vendor, self.operation),
                provider_error: String::from_utf8_lossy(self.body).into_owned(),
            },
        }
    }
}

/// The most of a vendor's refusal text an error keeps.
pub const EXPLANATION_CHARS: usize = 500;
/// `text`'s first `chars` characters, marked when cut.
pub fn cut(text: &str, chars: usize) -> String {
    match text.char_indices().nth(chars) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text.to_owned(),
    }
}
/// The last `chars` characters of `text`.
pub fn tail(text: &str, chars: usize) -> String {
    text.chars().rev().take(chars).collect::<Vec<_>>().into_iter().rev().collect()
}

/// A request body.
pub enum Body {
    None,
    Json(Value),
    /// Bytes with their content type (none when empty).
    Bytes(Bytes, &'static str),
}
impl From<Option<Value>> for Body {
    fn from(body: Option<Value>) -> Self {
        body.map_or(Body::None, Body::Json)
    }
}

/// Where a page's rows and the next cursor are.
pub struct Paging {
    /// The rows' key in the page, or None when the page is the array.
    pub rows: Option<&'static str>,
    /// The query parameter the cursor goes back in.
    pub cursor: &'static str,
    /// Where the next cursor comes from: a body key, or a header.
    pub next: Next,
}
pub enum Next {
    Body(&'static [&'static str]),
    Header(&'static str),
}

/// One vendor API: its base URL, how its key travels, and how its refusals
/// map. Requests carry the credential of the call; no state is kept.
#[derive(Clone)]
pub struct Api {
    pub vendor: Vendor,
    base: Url,
    auth: Auth,
    http: Arc<dyn HttpClient>,
    classify: fn(&Failure) -> ProtocolError,
    retry_after: fn(&HeaderMap) -> Option<u64>,
}
impl Api {
    /// `base` must be an HTTPS URL without credentials or query.
    pub fn new(vendor: Vendor, base: &str, auth: Auth, http: Arc<dyn HttpClient>) -> Result<Self> {
        let base = https_base(vendor, base)?;
        Ok(Self { vendor, base, auth, http, classify: |f| f.standard(f.reason(&f.message())), retry_after: retry_after_header })
    }
    /// The vendor's status table, in place of [`Failure::standard`] on its message.
    pub fn classify(mut self, classify: fn(&Failure) -> ProtocolError) -> Self {
        self.classify = classify;
        self
    }
    /// How the vendor says when to retry, in place of `Retry-After` seconds.
    pub fn retry_after(mut self, retry_after: fn(&HeaderMap) -> Option<u64>) -> Self {
        self.retry_after = retry_after;
        self
    }
    pub fn http(&self) -> &Arc<dyn HttpClient> {
        &self.http
    }
    /// The base URL with `segments` appended, each percent-encoded.
    pub fn url(&self, segments: &[&str]) -> Result<Url> {
        join(&self.base, segments)
    }
    /// The API key as a sensitive header value.
    pub fn key(&self, c: &Credentials) -> Result<HeaderValue> {
        let key =
            c.token().ok_or_else(|| ProtocolError::CredentialRejected { reason: format!("{} API key not delivered", self.vendor) })?;
        let value = match self.auth {
            Auth::Bearer => format!("Bearer {}", key.expose()),
            Auth::Header(_) => key.expose().to_owned(),
        };
        sensitive(&value).map_err(|_| refused(format!("invalid {} API key header", self.vendor)))
    }
    /// One request, whatever its status. `authenticated` adds the key;
    /// `headers` are added as given (mark secrets sensitive).
    pub async fn send(
        &self,
        method: Method,
        url: Url,
        body: impl Into<Body>,
        c: &Credentials,
        authenticated: bool,
        headers: &[(HeaderName, HeaderValue)],
    ) -> Result<http::Response<Bytes>> {
        let operation = operation(&method, &url);
        let mut request = reqwest::Request::new(method, url);
        if authenticated {
            let name = match &self.auth {
                Auth::Bearer => AUTHORIZATION,
                Auth::Header(name) => name.clone(),
            };
            request.headers_mut().insert(name, self.key(c)?);
        }
        for (name, value) in headers {
            request.headers_mut().insert(name.clone(), value.clone());
        }
        match body.into() {
            Body::None => {}
            Body::Json(value) => {
                request.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                *request.body_mut() = Some(value.to_string().into());
            }
            Body::Bytes(bytes, content_type) => {
                if !content_type.is_empty() {
                    request.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
                }
                *request.body_mut() = Some(bytes.into());
            }
        }
        rigging_http_client::http_execute!(self.http, request).map_err(|error| ProtocolError::Unavailable {
            provider_error: Some(error),
            reason: format!("{} {operation} transport failed", self.vendor),
            retry_after: None,
        })
    }
    /// The error a non-2xx answer is, by this vendor's table.
    pub fn failure(&self, operation: &str, response: &http::Response<Bytes>) -> ProtocolError {
        let retry_after = (self.retry_after)(response.headers());
        (self.classify)(&Failure { vendor: self.vendor, operation, status: response.status().as_u16(), body: response.body(), retry_after })
    }
    /// The JSON of a 2xx answer (Null when empty); any other status as its error.
    pub fn answer(&self, operation: &str, response: &http::Response<Bytes>) -> Result<Value> {
        if !response.status().is_success() {
            return Err(self.failure(operation, response));
        }
        if response.body().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(response.body()).map_err(|_| self.vendor.bad_response())
    }
    /// An authenticated JSON call.
    pub async fn call(&self, method: Method, url: Url, body: Option<Value>, c: &Credentials) -> Result<Value> {
        self.call_with(method, url, body, c, &[]).await
    }
    pub async fn call_with(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
        c: &Credentials,
        headers: &[(HeaderName, HeaderValue)],
    ) -> Result<Value> {
        let operation = operation(&method, &url);
        let response = self.send(method, url, body, c, true, headers).await?;
        self.answer(&operation, &response)
    }
    /// A GET whose 404 means absent.
    pub async fn find(&self, url: Url, c: &Credentials) -> Result<Option<Value>> {
        absent_on_not_found(self.call(Method::GET, url, None, c).await)
    }
    /// Every row of a cursor-paged list, following each cursor once (a
    /// repeated cursor is a bad response, never a loop).
    pub async fn paged(&self, url: Url, paging: &Paging, c: &Credentials) -> Result<Vec<Value>> {
        let mut rows = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen = BTreeSet::new();
        loop {
            let mut page_url = url.clone();
            if let Some(cursor) = &cursor {
                page_url.query_pairs_mut().append_pair(paging.cursor, cursor);
            }
            let operation = operation(&Method::GET, &page_url);
            let response = self.send(Method::GET, page_url, None, c, true, &[]).await?;
            let page = self.answer(&operation, &response)?;
            let page_rows = match paging.rows {
                Some(key) => page.get(key),
                None => Some(&page),
            };
            rows.extend(page_rows.and_then(Value::as_array).ok_or_else(|| self.vendor.bad_response())?.iter().cloned());
            let next = match &paging.next {
                Next::Body(keys) => keys.iter().find_map(|key| page.get(*key).and_then(Value::as_str)).map(str::to_owned),
                Next::Header(name) => response.headers().get(*name).and_then(|v| v.to_str().ok()).map(str::to_owned),
            };
            match next.filter(|n| !n.is_empty()) {
                None => return Ok(rows),
                Some(next) if seen.insert(next.clone()) => cursor = Some(next),
                Some(_) => return Err(self.vendor.bad_response()),
            }
        }
    }
}

/// `METHOD /path`, as reasons name an operation.
pub fn operation(method: &Method, url: &Url) -> String {
    format!("{method} {}", url.path())
}
/// Ok(None) for a NotFound, the rest unchanged.
pub fn absent_on_not_found<T>(result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(ProtocolError::NotFound { .. }) => Ok(None),
        Err(error) => Err(error),
    }
}
/// A header value never shown in Debug output.
pub fn sensitive(value: &str) -> std::result::Result<HeaderValue, http::header::InvalidHeaderValue> {
    let mut value = HeaderValue::from_str(value)?;
    value.set_sensitive(true);
    Ok(value)
}
/// `Retry-After` in whole seconds.
pub fn retry_after_header(headers: &HeaderMap) -> Option<u64> {
    headers.get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse().ok())
}
/// An HTTPS endpoint setting: a host, no credentials, query or fragment.
pub fn https_base(vendor: Vendor, endpoint: &str) -> Result<Url> {
    Url::parse(endpoint)
        .ok()
        .filter(|u| {
            u.scheme() == "https"
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none()
        })
        .ok_or_else(|| refused(format!("{vendor} endpoints must be HTTPS URLs without credentials, query or fragment")))
}
/// `base` with `segments` appended (an empty last segment dropped first).
pub fn join(base: &Url, segments: &[&str]) -> Result<Url> {
    let mut url = base.clone();
    url.path_segments_mut().map_err(|_| refused("invalid base URL"))?.pop_if_empty().extend(segments);
    Ok(url)
}

//! A vendor's HTTP control plane: authenticated requests with typed bodies,
//! a 2xx answer decoded into the type the caller names (anything missing or
//! malformed is one error naming the operation), any other status as the
//! protocol's error (by a table the vendor may override), transport failures
//! as Unavailable, and cursor paging. The types are a module's own structs,
//! hand-written or generated from the vendor's OpenAPI document, keeping only
//! the fields it reads. Nothing here retries: modules don't (ADR 0070).
use super::Vendor;
use crate::module::{Credentials, HttpClient, Result, refused};
use bytes::Bytes;
use drydock_protocol::ProtocolError;
use reqwest::{
    Method, Url,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{collections::BTreeSet, fmt, ops::Deref, sync::Arc};

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
    /// From the answer, as [`Api::retry_after`] reads it.
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
/// A request body.
pub enum Body {
    None,
    /// Serialized JSON.
    Json(Bytes),
    /// Bytes with their content type; an empty one sets none, leaving any
    /// the caller's headers carry.
    Bytes(Bytes, &'static str),
}
impl Body {
    /// `value` as a JSON body.
    pub fn json(value: &impl Serialize) -> Result<Self> {
        let bytes = serde_json::to_vec(value)
            .map_err(|e| ProtocolError::Internal { reason: "request body did not serialize".into(), provider_error: e.to_string() })?;
        Ok(Body::Json(bytes.into()))
    }
}

/// A string field that must not be empty: ids, states, names.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "String")]
pub struct Text(String);
impl TryFrom<String> for Text {
    type Error = &'static str;
    fn try_from(text: String) -> std::result::Result<Self, Self::Error> {
        if text.is_empty() { Err("empty") } else { Ok(Self(text)) }
    }
}
impl Deref for Text {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl From<Text> for String {
    fn from(text: Text) -> Self {
        text.0
    }
}

/// A number field that must be finite and not negative: sizes, usage, quota.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Deserialize)]
#[serde(try_from = "f64")]
pub struct Amount(f64);
impl Amount {
    pub fn get(self) -> f64 {
        self.0
    }
}
impl TryFrom<f64> for Amount {
    type Error = &'static str;
    fn try_from(n: f64) -> std::result::Result<Self, Self::Error> {
        if n.is_finite() && n >= 0.0 { Ok(Self(n)) } else { Err("not a finite, non-negative number") }
    }
}

/// Where a page's rows and the next cursor are.
pub struct Paging {
    /// The rows' key in the page, or None when the page is the array (whose
    /// cursor then can only travel in a header). A page missing the key is
    /// incomplete, never empty: a vendor that omits an empty list needs its
    /// own read.
    pub rows: Option<&'static str>,
    /// The query parameter the cursor goes back in.
    pub cursor: &'static str,
    /// Where the next cursor comes from: a body key, or a header.
    pub next: Next,
}
pub enum Next {
    Body(&'static [&'static str]),
    Header(&'static str),
    /// An offset: the rows read so far, while a page comes back full at this size.
    Offset(usize),
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
    retry_after: fn(&HeaderMap, &[u8]) -> Option<u64>,
}
impl Api {
    /// `base` must be an HTTPS URL without credentials or query.
    pub fn new(vendor: Vendor, base: &str, auth: Auth, http: Arc<dyn HttpClient>) -> Result<Self> {
        let base = https_base(vendor, base)?;
        Ok(Self {
            vendor,
            base,
            auth,
            http,
            classify: |f| f.standard(f.reason(&f.message())),
            retry_after: |headers, _| retry_after_header(headers),
        })
    }
    /// The vendor's status table, in place of [`Failure::standard`] on its message.
    pub fn classify(mut self, classify: fn(&Failure) -> ProtocolError) -> Self {
        self.classify = classify;
        self
    }
    /// How the vendor says when to retry (whole seconds, from an answer's headers
    /// and body), in place of the `Retry-After` header.
    pub fn retry_after(mut self, retry_after: fn(&HeaderMap, &[u8]) -> Option<u64>) -> Self {
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
    /// One request, whatever its status. `headers` are added as given (mark
    /// secrets sensitive); `authenticated` then adds the key, and a body its
    /// content type, which no caller header replaces.
    pub async fn send(
        &self,
        method: Method,
        url: Url,
        body: impl Into<Body>,
        c: &Credentials,
        authenticated: bool,
        headers: &[(HeaderName, HeaderValue)],
    ) -> Result<http::Response<Bytes>> {
        self.send_within(method, url, body, c, authenticated, headers, None).await
    }
    /// [`Self::send`], ending at `deadline` instead of the client's own
    /// (30 s), for a request whose body takes longer to send.
    #[allow(clippy::too_many_arguments)]
    async fn send_within(
        &self,
        method: Method,
        url: Url,
        body: impl Into<Body>,
        c: &Credentials,
        authenticated: bool,
        headers: &[(HeaderName, HeaderValue)],
        deadline: Option<std::time::Duration>,
    ) -> Result<http::Response<Bytes>> {
        let operation = operation(&method, &url);
        let mut request = reqwest::Request::new(method, url);
        *request.timeout_mut() = deadline;
        for (name, value) in headers {
            request.headers_mut().insert(name.clone(), value.clone());
        }
        if authenticated {
            let name = match &self.auth {
                Auth::Bearer => AUTHORIZATION,
                Auth::Header(name) => name.clone(),
            };
            request.headers_mut().insert(name, self.key(c)?);
        }
        match body.into() {
            Body::None => {}
            Body::Json(bytes) => {
                request.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                *request.body_mut() = Some(bytes.into());
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
        let retry_after = (self.retry_after)(response.headers(), response.body());
        (self.classify)(&Failure { vendor: self.vendor, operation, status: response.status().as_u16(), body: response.body(), retry_after })
    }
    /// A 2xx answer decoded as `T`; any other status as its error.
    pub fn answer<T: DeserializeOwned>(&self, operation: &str, response: &http::Response<Bytes>) -> Result<T> {
        if !response.status().is_success() {
            return Err(self.failure(operation, response));
        }
        self.decode(operation, response.body())
    }
    /// `body` as `T`, an empty body read as JSON null. Serde's reason is
    /// never kept: it can quote the value, and answers hold secrets.
    pub fn decode<T: DeserializeOwned>(&self, operation: &str, body: &[u8]) -> Result<T> {
        serde_json::from_slice(if body.is_empty() { b"null" } else { body }).map_err(|_| self.vendor.incomplete(operation))
    }
    /// An authenticated call, its answer decoded as `T`.
    pub async fn call<T: DeserializeOwned>(&self, method: Method, url: Url, body: Body, c: &Credentials) -> Result<T> {
        self.call_with(method, url, body, c, &[]).await
    }
    pub async fn call_with<T: DeserializeOwned>(
        &self,
        method: Method,
        url: Url,
        body: Body,
        c: &Credentials,
        headers: &[(HeaderName, HeaderValue)],
    ) -> Result<T> {
        let operation = operation(&method, &url);
        let response = self.send(method, url, body, c, true, headers).await?;
        self.answer(&operation, &response)
    }
    /// An authenticated call whose request may take until `deadline`, as a
    /// large upload does; its answer decoded as `T`.
    pub async fn call_within<T: DeserializeOwned>(
        &self,
        method: Method,
        url: Url,
        body: Body,
        c: &Credentials,
        deadline: std::time::Duration,
    ) -> Result<T> {
        let operation = operation(&method, &url);
        let response = self.send_within(method, url, body, c, true, &[], Some(deadline)).await?;
        self.answer(&operation, &response)
    }
    /// An authenticated GET.
    pub async fn get<T: DeserializeOwned>(&self, url: Url, c: &Credentials) -> Result<T> {
        self.call(Method::GET, url, Body::None, c).await
    }
    /// A GET whose 404 means absent.
    pub async fn find<T: DeserializeOwned>(&self, url: Url, c: &Credentials) -> Result<Option<T>> {
        absent_on_not_found(self.get(url, c).await)
    }
    /// Every row of a paged list, following each cursor once: a repeated cursor,
    /// one that is not text, or more than [`MAX_PAGES`] pages is a bad response,
    /// never a loop or a silently short list.
    pub async fn paged<T: DeserializeOwned>(&self, url: Url, paging: &Paging, c: &Credentials) -> Result<Vec<T>> {
        let (rows, ended) = self.paged_until(url, paging, MAX_PAGES, c, |_| false).await?;
        if ended { Ok(rows) } else { Err(self.vendor.bad_response()) }
    }
    /// The rows of a paged list read until `done` says a page holds what the
    /// caller needs (a list newest first, read back to a date), the list ends, or
    /// `max_pages` have been read. True when the list ended or `done` said so:
    /// false is a list cut short at `max_pages`, for the caller to say what that means.
    pub async fn paged_until<T: DeserializeOwned>(
        &self,
        url: Url,
        paging: &Paging,
        max_pages: usize,
        c: &Credentials,
        mut done: impl FnMut(&[T]) -> bool,
    ) -> Result<(Vec<T>, bool)> {
        let mut rows = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen = BTreeSet::new();
        for _ in 0..max_pages.min(MAX_PAGES) {
            let mut page_url = url.clone();
            if let Some(cursor) = &cursor {
                page_url.query_pairs_mut().append_pair(paging.cursor, cursor);
            }
            let operation = operation(&Method::GET, &page_url);
            let response = self.send(Method::GET, page_url, Body::None, c, true, &[]).await?;
            let mut page: Value = self.answer(&operation, &response)?;
            let page_rows = match paging.rows {
                Some(key) => page.get_mut(key).map(Value::take),
                None => Some(page.take()),
            };
            let page_rows: Vec<T> =
                serde_json::from_value(page_rows.unwrap_or_default()).map_err(|_| self.vendor.incomplete(&operation))?;
            let (count, finished) = (page_rows.len(), done(&page_rows));
            rows.extend(page_rows);
            if finished {
                return Ok((rows, true));
            }
            let next = match &paging.next {
                Next::Body(keys) => match keys.iter().find_map(|key| page.get(*key).filter(|v| !v.is_null())) {
                    Some(value) => Some(value.as_str().ok_or_else(|| self.vendor.bad_response())?.to_owned()),
                    None => None,
                },
                Next::Header(name) => match response.headers().get(*name) {
                    Some(value) => Some(value.to_str().map_err(|_| self.vendor.bad_response())?.to_owned()),
                    None => None,
                },
                // A full page means there may be more, at the offset after the rows so far.
                Next::Offset(size) => (count >= *size).then(|| rows.len().to_string()),
            };
            match next.filter(|n| !n.is_empty()) {
                None => return Ok((rows, true)),
                Some(next) if seen.insert(next.clone()) => cursor = Some(next),
                Some(_) => return Err(self.vendor.bad_response()),
            }
        }
        Ok((rows, false))
    }
}

/// The most pages one list follows.
pub const MAX_PAGES: usize = 1000;

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
/// Whether a refusal's `text` has any of `wording`, ignoring case. For a vendor
/// that gives no code or status for a condition (a quota, say) and says it only
/// in words: the module names the wording it matches next to the vendor it is
/// from, so the match is one thing to read, check and replace.
pub fn says(text: &str, wording: &[&str]) -> bool {
    let text = text.to_ascii_lowercase();
    wording.iter().any(|w| text.contains(&w.to_ascii_lowercase()))
}
/// A header value never shown in Debug output.
pub fn sensitive(value: &str) -> std::result::Result<HeaderValue, http::header::InvalidHeaderValue> {
    let mut value = HeaderValue::from_str(value)?;
    value.set_sensitive(true);
    Ok(value)
}
/// `Retry-After` in whole seconds; an HTTP-date form reads as None.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::Credentials;
    use async_trait::async_trait;
    use drydock_protocol::Secret;
    use rigging_http_client::ChannelLabel;
    use std::sync::Mutex;

    /// A scripted answer: status, headers, body.
    type Answer = (u16, Vec<(&'static str, &'static str)>, &'static str);
    /// Answers each request with the next scripted answer, keeping what it
    /// was asked.
    #[derive(Default)]
    struct Script {
        answers: Mutex<Vec<Answer>>,
        /// Whole responses, answered before `answers`.
        raw: Mutex<Vec<http::Response<Bytes>>>,
        asked: Mutex<Vec<reqwest::Request>>,
    }
    #[async_trait]
    impl HttpClient for Script {
        async fn execute(&self, request: reqwest::Request, _: &ChannelLabel) -> std::result::Result<http::Response<Bytes>, String> {
            self.asked.lock().unwrap().push(request);
            if let Some(answer) = self.raw.lock().unwrap().pop() {
                return Ok(answer);
            }
            let (status, headers, body) = self.answers.lock().unwrap().remove(0);
            let mut response = http::Response::builder().status(status);
            for (name, value) in headers {
                response = response.header(name, value);
            }
            Ok(response.body(Bytes::from_static(body.as_bytes())).unwrap())
        }
    }
    fn api(auth: Auth, answers: Vec<Answer>) -> (Api, Arc<Script>) {
        let script = Arc::new(Script { answers: Mutex::new(answers), ..Script::default() });
        (Api::new(Vendor("Test"), "https://api.test/v1/", auth, script.clone()).unwrap(), script)
    }
    fn key() -> Credentials {
        Credentials::new(Some(Secret::new("k")))
    }

    // A key in the vendor's own header travels alone there, never as a
    // Bearer; a header cursor is followed until absent, and a repeated one
    // is a bad response rather than a loop.
    #[tokio::test]
    async fn header_keys_and_header_cursors() {
        let paging = Paging { rows: None, cursor: "next", next: Next::Header("x-next") };
        let (api, script) = api(
            Auth::Header(HeaderName::from_static("x-api-key")),
            vec![
                (200, vec![("x-next", "c1")], "[1]"),
                (200, vec![], "[2,3]"),
                (200, vec![("x-next", "c")], "[]"),
                (200, vec![("x-next", "c")], "[]"),
            ],
        );
        let url = api.url(&["rows"]).unwrap();
        assert_eq!(api.paged::<u8>(url.clone(), &paging, &key()).await.unwrap(), [1, 2, 3]);
        let asked: Vec<_> = script.asked.lock().unwrap().iter().map(|r| r.url().to_string()).collect();
        assert_eq!(asked, ["https://api.test/v1/rows", "https://api.test/v1/rows?next=c1"]);
        let headers = script.asked.lock().unwrap()[0].headers().clone();
        assert_eq!(headers["x-api-key"], "k");
        assert!(headers.get(AUTHORIZATION).is_none());
        assert_eq!(api.paged::<u8>(url.clone(), &paging, &key()).await.unwrap_err(), Vendor("Test").bad_response());
        // A cursor that is not text is never read as the last page.
        let mut answer = http::Response::new(Bytes::from_static(b"[]"));
        answer.headers_mut().insert("x-next", HeaderValue::from_bytes(b"\xff").unwrap());
        script.raw.lock().unwrap().push(answer);
        assert_eq!(api.paged::<u8>(url, &paging, &key()).await.unwrap_err(), Vendor("Test").bad_response());
    }

    // An offset cursor is the rows so far, followed while pages come back full;
    // a stop condition ends the read at the page that satisfies it, and a page
    // cap says so rather than returning a list that looks whole.
    #[tokio::test]
    async fn offset_paging_stops_when_told_or_capped() {
        let paging = Paging { rows: None, cursor: "offset", next: Next::Offset(2) };
        let fresh = || api(Auth::Bearer, vec![(200, vec![], "[1,2]"), (200, vec![], "[3,4]"), (200, vec![], "[5]")]);
        let (client, script) = fresh();
        let url = client.url(&["rows"]).unwrap();
        assert_eq!(client.paged_until::<u8>(url.clone(), &paging, 10, &key(), |_| false).await.unwrap(), (vec![1, 2, 3, 4, 5], true));
        let asked: Vec<_> = script.asked.lock().unwrap().iter().map(|r| r.url().to_string()).collect();
        assert_eq!(asked, ["https://api.test/v1/rows", "https://api.test/v1/rows?offset=2", "https://api.test/v1/rows?offset=4"]);
        let stop = |page: &[u8]| page.contains(&3);
        assert_eq!(fresh().0.paged_until::<u8>(url.clone(), &paging, 10, &key(), stop).await.unwrap(), (vec![1, 2, 3, 4], true));
        assert_eq!(fresh().0.paged_until::<u8>(url.clone(), &paging, 1, &key(), |_| false).await.unwrap(), (vec![1, 2], false));
        assert_eq!(fresh().0.paged::<u8>(url, &paging, &key()).await.unwrap(), [1, 2, 3, 4, 5]);
    }

    // A vendor that never stops handing out fresh cursors ends the list
    // with a bad response at the page limit.
    #[tokio::test]
    async fn endless_cursors_stop_at_the_page_limit() {
        let cursors: Vec<&'static str> = (0..MAX_PAGES).map(|n| &*Box::leak(n.to_string().into_boxed_str())).collect();
        let (api, script) = api(Auth::Bearer, cursors.iter().map(|c| (200, vec![("x-next", *c)], "[1]")).collect());
        let paging = Paging { rows: None, cursor: "next", next: Next::Header("x-next") };
        assert_eq!(api.paged::<u8>(api.url(&["rows"]).unwrap(), &paging, &key()).await.unwrap_err(), Vendor("Test").bad_response());
        assert_eq!(script.asked.lock().unwrap().len(), MAX_PAGES);
    }

    // A body cursor is followed from the page beside its rows; a page
    // without its rows key is incomplete; a caller's header never replaces
    // the key.
    #[tokio::test]
    async fn body_cursors_missing_rows_and_the_key_wins() {
        let paging = Paging { rows: Some("items"), cursor: "cursor", next: Next::Body(&["next"]) };
        let (api, script) = api(
            Auth::Bearer,
            vec![
                (200, vec![], r#"{"items":[1],"next":"c1"}"#),
                (200, vec![], r#"{"items":[2],"next":""}"#),
                (200, vec![], r#"{"next":"c2"}"#),
                (200, vec![], r#"{"items":[1],"next":7}"#),
                (200, vec![], "null"),
            ],
        );
        let url = api.url(&["rows"]).unwrap();
        assert_eq!(api.paged::<u8>(url.clone(), &paging, &key()).await.unwrap(), [1, 2]);
        assert_eq!(api.paged::<u8>(url.clone(), &paging, &key()).await.unwrap_err(), Vendor("Test").incomplete("GET /v1/rows"));
        // A cursor that is not text is never read as the last page.
        assert_eq!(api.paged::<u8>(url.clone(), &paging, &key()).await.unwrap_err(), Vendor("Test").bad_response());
        let forged = [(AUTHORIZATION, HeaderValue::from_static("Bearer forged"))];
        api.call_with::<Value>(Method::GET, url, Body::None, &key(), &forged).await.unwrap();
        let asked = script.asked.lock().unwrap();
        assert_eq!(asked[1].url().query(), Some("cursor=c1"));
        assert_eq!(asked[4].headers()[AUTHORIZATION], "Bearer k");
    }

    #[derive(Debug, PartialEq, Deserialize)]
    struct Row {
        id: Text,
        size: Amount,
    }

    // Typed answers: a body that is not JSON, a missing field, an empty
    // string or a negative amount is one error naming the operation and
    // quoting nothing; 404 is absent to `find`. A typed body goes as JSON.
    #[tokio::test]
    async fn typed_answers_and_bodies() {
        let (api, script) = api(
            Auth::Bearer,
            vec![
                (404, vec![], ""),
                (200, vec![], r#"{"id":"a","size":1.5}"#),
                (200, vec![], "secret not json"),
                (200, vec![], r#"{"id":"secret"}"#),
                (200, vec![], r#"{"id":"","size":1}"#),
                (200, vec![], r#"{"id":"secret","size":-1}"#),
            ],
        );
        let url = api.url(&["a b"]).unwrap();
        assert_eq!(url.path(), "/v1/a%20b");
        assert_eq!(api.find::<Row>(url.clone(), &key()).await.unwrap(), None);
        let body = Body::json(&serde_json::json!({"x": 1})).unwrap();
        let row: Row = api.call(Method::POST, url.clone(), body, &key()).await.unwrap();
        assert_eq!(row, Row { id: Text("a".into()), size: Amount(1.5) });
        {
            let asked = script.asked.lock().unwrap();
            assert_eq!(asked[0].headers()[AUTHORIZATION], "Bearer k");
            assert_eq!(asked[1].headers()[CONTENT_TYPE], "application/json");
            assert_eq!(asked[1].body().unwrap().as_bytes(), Some(&br#"{"x":1}"#[..]));
        }
        for _ in 0..4 {
            let error = api.get::<Row>(url.clone(), &key()).await.unwrap_err();
            assert_eq!(error, Vendor("Test").incomplete("GET /v1/a%20b"));
            assert!(!format!("{error:?}").contains("secret"), "{error:?}");
        }
    }

    // A vendor's hint is read from the answer's headers and body; its wording is matched without case.
    #[tokio::test]
    async fn retry_hints_and_wording() {
        let (api, _) = api(Auth::Bearer, vec![(503, vec![], r#"{"wait":4}"#)]);
        let api = api.retry_after(|_, body| serde_json::from_slice::<Value>(body).ok()?.get("wait")?.as_u64());
        let down = api.get::<Value>(api.url(&["a"]).unwrap(), &key()).await.unwrap_err();
        assert!(matches!(down, ProtocolError::Unavailable { retry_after: Some(4), .. }), "{down:?}");
        assert!(says("Concurrent sandbox LIMIT reached", &["concurrent"]));
        assert!(!says("slow down", &["concurrent", "quota"]));
    }

    // The standard table on the body's message, cut.
    #[tokio::test]
    async fn the_standard_table() {
        let long: &'static str = Box::leak(format!("{{\"message\":\"{}\"}}", "x".repeat(EXPLANATION_CHARS + 1)).into_boxed_str());
        let (api, script) = api(
            Auth::Bearer,
            vec![(403, vec![], long), (503, vec![("retry-after", "7")], "down"), (418, vec![], "teapot"), (302, vec![], "moved")],
        );
        let url = api.url(&["a"]).unwrap();
        let ProtocolError::Refused { reason } = api.get::<Value>(url.clone(), &key()).await.unwrap_err() else { panic!() };
        assert_eq!(reason, format!("permission denied; Test GET /v1/a HTTP 403: {}…", "x".repeat(EXPLANATION_CHARS)));
        let down = api.get::<Value>(url.clone(), &key()).await.unwrap_err();
        assert!(matches!(down, ProtocolError::Unavailable { retry_after: Some(7), .. }), "{down:?}");
        assert!(matches!(api.get::<Value>(url.clone(), &key()).await.unwrap_err(), ProtocolError::Refused { .. }));
        // The whole body: the host masks credential echoes before it limits.
        let ProtocolError::Internal { reason, provider_error } = api.get::<Value>(url, &key()).await.unwrap_err() else { panic!() };
        assert_eq!((reason.as_str(), provider_error.as_str()), ("unexpected Test GET /v1/a HTTP 302", "moved"));
        assert!(Api::new(Vendor("Test"), "http://api.test/", Auth::Bearer, script).is_err());
    }
}

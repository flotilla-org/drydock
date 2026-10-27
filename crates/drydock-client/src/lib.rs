//! Typed, single-attempt host calls. Observation reconnect policy is explicit and
//! separate from calls. Neither API stores desired state or reconciles resources.
pub mod api;
use drydock_protocol::*;
use futures::{StreamExt, stream::BoxStream};
pub use reqwest::Method;
use reqwest::Url;
use rigging_http_client::{HttpClient, http_execute};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, VecDeque},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{sync::Mutex, time::Instant};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Connection refused, missing socket, reset or failed upgrade, with its cause chain.
    #[error("host transport failed: {0}")]
    Transport(String),
    #[error("host request timed out after {0:?}")]
    Timeout(Duration),
    /// A body that is not the declared JSON shape: the decoder's reason, never the body.
    #[error("invalid host response: {0}")]
    InvalidResponse(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("host protocol error: {0}")]
    Protocol(ProtocolError),
    #[error("host protocol version mismatch")]
    VersionMismatch,
    #[error("local status request budget exhausted")]
    RateLimited,
    #[error("host is not ready: {0}")]
    NotReady(Readiness),
    #[error("host readiness timed out: {0}")]
    ReadinessTimeout(Readiness),
}
impl From<ProtocolError> for Error {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}
impl Error {
    pub fn transport(error: &(dyn std::error::Error + 'static)) -> Self {
        Self::Transport(chain(error))
    }
    fn response(error: impl std::fmt::Display) -> Self {
        Self::InvalidResponse(error.to_string())
    }
}
/// An error and its sources, outermost first: "error sending request: ...: Connection refused".
pub fn chain(error: &(dyn std::error::Error + 'static)) -> String {
    std::iter::successors(Some(error), |error| error.source()).map(ToString::to_string).collect::<Vec<_>>().join(": ")
}
pub type Result<T> = std::result::Result<T, Error>;

// Socket transport adapter for rigging's injectable HTTP execution port. The
// reqwest client is also retained for streaming, which the buffered port cannot do.
struct SocketHttp(reqwest::Client);
#[async_trait::async_trait]
impl HttpClient for SocketHttp {
    async fn execute(
        &self,
        request: reqwest::Request,
        _: &rigging_http_client::ChannelLabel,
    ) -> std::result::Result<http::Response<bytes::Bytes>, String> {
        let response = self.0.execute(request).await.map_err(|error| chain(&error))?;
        let mut result = http::Response::builder().status(response.status());
        *result.headers_mut().expect("response builder") = response.headers().clone();
        result.body(response.bytes().await.map_err(|error| chain(&error))?).map_err(|error| chain(&error))
    }
}

pub struct WireResponse {
    pub status: u16,
    pub headers: http::HeaderMap,
    pub body: serde_json::Value,
}
#[derive(Clone)]
pub struct Client {
    base: Url,
    bearer: Option<Secret>,
    transport: reqwest::Client,
    http: Arc<dyn HttpClient>,
    request_timeout: Duration,
}
impl Client {
    pub fn unix(path: impl AsRef<Path>) -> Result<Self> {
        let transport = Self::builder().unix_socket(path.as_ref().to_path_buf()).build().map_err(|e| Error::transport(&e))?;
        Ok(Self {
            base: Url::parse("http://localhost/").expect("constant URL"),
            bearer: None,
            request_timeout: Duration::from_secs(30),
            http: Arc::new(SocketHttp(transport.clone())),
            transport,
        })
    }
    /// External TCP hosts are loopback-only and require an explicitly supplied token.
    pub fn external(url: &str, bearer: Secret) -> Result<Self> {
        let base = Url::parse(url).map_err(|e| Error::InvalidRequest(format!("host URL: {e}")))?;
        let loopback = base
            .host_str()
            .and_then(|host| host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if base.scheme() != "http"
            || !loopback
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
        {
            return Err(Error::InvalidRequest("host URL must be a plain http:// loopback origin".into()));
        }
        let transport = Self::builder().build().map_err(|e| Error::transport(&e))?;
        let http = rigging_http_client::ReqwestHttpClient::restricted(None, None).map_err(|e| Error::Transport(e.to_string()))?;
        Ok(Self { base, bearer: Some(bearer), transport, http: Arc::new(http), request_timeout: Duration::from_secs(30) })
    }
    /// Bound buffered calls and upgrade setup independently of stream lifetimes.
    /// The 30-second default is shorter than the server's 600-second deadline
    /// for prepare, provision, reach, suspend, resume and export. Callers of
    /// those raise it, as the CLI does, or treat a `Timeout` as an unknown outcome.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }
    /// Replace the buffered execution port for recording or deterministic tests.
    pub fn with_http(mut self, http: Arc<dyn HttpClient>) -> Self {
        self.http = http;
        self
    }
    fn builder() -> reqwest::ClientBuilder {
        rigging_tls::client_builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(5))
    }
    fn request(&self, method: Method, segments: &[&str]) -> Result<reqwest::RequestBuilder> {
        let mut url = self.base.clone();
        url.path_segments_mut().map_err(|_| Error::InvalidRequest("host URL cannot carry a path".into()))?.clear().extend(segments);
        let mut request = self.transport.request(method, url);
        if let Some(token) = &self.bearer {
            request = request.bearer_auth(token.expose());
        }
        Ok(request)
    }
    /// The one caller deadline for buffered calls and stream upgrades.
    async fn bounded<T>(&self, call: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::time::timeout(self.request_timeout, call).await.map_err(|_| Error::Timeout(self.request_timeout))?
    }
    async fn execute_buffered(&self, request: reqwest::RequestBuilder) -> Result<http::Response<bytes::Bytes>> {
        let request = request.build().map_err(|e| Error::InvalidRequest(chain(&e)))?;
        http_execute!(self.http, request).map_err(Error::Transport)
    }
    async fn call<T: DeserializeOwned, B: Serialize + ?Sized>(&self, method: Method, segments: &[&str], body: Option<&B>) -> Result<T> {
        let mut request = self.request(method, segments)?;
        if let Some(body) = body {
            request = request.json(body);
        }
        Ok(self.execute_response(request).await?.1)
    }
    async fn execute_response<T: DeserializeOwned>(&self, request: reqwest::RequestBuilder) -> Result<(u16, T)> {
        decode(self.bounded(self.execute_buffered(request)).await?)
    }
    /// Replace the bearer credential while preserving the endpoint and HTTP port.
    pub fn with_bearer(mut self, bearer: Option<Secret>) -> Self {
        self.bearer = bearer;
        self
    }
    /// The configured credential, for refresh and credential-aware callers.
    pub fn bearer(&self) -> Option<&Secret> {
        self.bearer.as_ref()
    }
    /// Inspect the JSON wire contract, including status and explicit null fields.
    /// Uses the same endpoint, authentication and injectable HTTP port as typed calls.
    pub async fn wire(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<&serde_json::Value>,
    ) -> Result<(u16, serde_json::Value)> {
        let response = self.wire_response(method, segments, query, body).await?;
        Ok((response.status, response.body))
    }
    /// Raw JSON response metadata for protocol/status/header validation.
    pub async fn wire_response(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<&serde_json::Value>,
    ) -> Result<WireResponse> {
        let mut request = self.request(method, segments)?.query(query);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = self.bounded(self.execute_buffered(request)).await?;
        let value = if response.body().is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(response.body()).map_err(Error::response)?
        };
        Ok(WireResponse { status: response.status().as_u16(), headers: response.headers().clone(), body: value })
    }
    pub async fn provider_hello(&self) -> Result<drydock_provider::BridgeHello> {
        let hello: drydock_provider::BridgeHello = self.call::<_, ()>(Method::GET, &["v1", "hello"], None).await?;
        if !hello.hello.is_compatible() {
            return Err(Error::VersionMismatch);
        }
        Ok(hello)
    }
    pub async fn configure_provider(
        &self,
        module: &str,
        configuration: &ProviderConfiguration,
    ) -> Result<drydock_provider::ConfiguredProvider> {
        self.call(Method::POST, &["private", "modules", module, "configure"], Some(configuration)).await
    }
    pub async fn release_provider(&self, instance: &str) -> Result<()> {
        self.call::<_, ()>(Method::DELETE, &["private", "providers", instance], None).await
    }
    /// Private trait adapter. Each request carries its own credential snapshot.
    pub async fn provider_call<T: DeserializeOwned, A: Serialize>(
        &self,
        provider: &str,
        operation: &str,
        argument: A,
        credentials: &drydock_provider::Credentials,
    ) -> Result<T> {
        let request = self
            .request(Method::POST, &["private", "providers", provider, operation])?
            .json(&drydock_provider::Call { credentials: credentials.clone(), argument });
        // The server's policy owns this operation's deadline. Do not add a
        // second, shorter private-transport deadline for long mutating calls.
        Ok(decode(self.execute_buffered(request).await?)?.1)
    }
    pub async fn provider_stream<A: Serialize>(
        &self,
        provider: &str,
        operation: &str,
        argument: A,
        credentials: &drydock_provider::Credentials,
        protocol: &str,
    ) -> Result<rigging_stream::ByteStream> {
        let request = self
            .request(Method::POST, &["private", "providers", provider, operation])?
            .json(&drydock_provider::Call { credentials: credentials.clone(), argument });
        upgraded(request, protocol).await
    }
    pub async fn provider_updates(
        &self,
        provider: &str,
        credentials: &drydock_provider::Credentials,
        sink: drydock_provider::EventSink,
    ) -> Result<()> {
        let response = self
            .request(Method::POST, &["private", "providers", provider, "subscribe"])?
            .json(&drydock_provider::Call { credentials: credentials.clone(), argument: () })
            .send()
            .await
            .map_err(|e| Error::transport(&e))?;
        let mut records = Records::new(success(response).await?);
        while let Some(record) = records.next_line::<drydock_provider::SubscriptionRecord>().await? {
            match record {
                drydock_provider::SubscriptionRecord::Update(update) => sink.publish(update)?,
                drydock_provider::SubscriptionRecord::Failed(error) => return Err(Error::Protocol(error)),
            }
        }
        Ok(())
    }
    pub async fn configure(&self, configuration: &HostConfiguration) -> Result<()> {
        self.call(Method::PUT, &["v1", "config"], Some(configuration)).await
    }
    pub async fn credential(&self, provider: &str, value: Secret) -> Result<()> {
        self.call(Method::PUT, &["v1", "providers", provider, "credential"], Some(&CredentialRefresh { value })).await
    }
    async fn upgrade<B: Serialize + ?Sized>(
        &self,
        provider: &str,
        id: &str,
        route: &str,
        protocol: &str,
        body: Option<&B>,
    ) -> Result<rigging_stream::ByteStream> {
        let mut request = self
            .request(if body.is_some() { Method::POST } else { Method::GET }, &["v1", "providers", provider, "environments", id, route])?;
        if let Some(body) = body {
            request = request.json(body);
        }
        self.bounded(upgraded(request, protocol)).await
    }
    pub async fn observe(&self, since: Option<&str>) -> Result<Records> {
        let mut request = self.request(Method::GET, &["v1", "events"])?;
        if let Some(since) = since {
            request = request.query(&[("since", since)]);
        }
        let response = request.send().await.map_err(|e| Error::transport(&e))?;
        Ok(Records::new(success(response).await?))
    }
}
/// A refusal must be the protocol error its status declares.
fn protocol_error(status: http::StatusCode, body: &[u8]) -> Error {
    match serde_json::from_slice::<ProtocolError>(body) {
        Ok(error) if error.status() == status.as_u16() => Error::Protocol(error),
        Ok(error) => Error::InvalidResponse(format!("HTTP {status} carried a {} error", error.class())),
        Err(error) => Error::InvalidResponse(format!("HTTP {status} without a protocol error body: {error}")),
    }
}
fn decode<T: DeserializeOwned>(response: http::Response<bytes::Bytes>) -> Result<(u16, T)> {
    let status = response.status();
    if !status.is_success() {
        return Err(protocol_error(status, response.body()));
    }
    let body = if status == http::StatusCode::NO_CONTENT { b"null".as_slice() } else { response.body().as_ref() };
    Ok((status.as_u16(), serde_json::from_slice(body).map_err(Error::response)?))
}
async fn success(response: reqwest::Response) -> Result<reqwest::Response> {
    let status = response.status();
    if status.is_success() || status == http::StatusCode::SWITCHING_PROTOCOLS {
        return Ok(response);
    }
    Err(protocol_error(status, &response.bytes().await.map_err(|e| Error::transport(&e))?))
}
async fn upgraded(request: reqwest::RequestBuilder, protocol: &str) -> Result<rigging_stream::ByteStream> {
    let response = request.header("connection", "upgrade").header("upgrade", protocol).send().await.map_err(|e| Error::transport(&e))?;
    let response = success(response).await?;
    if response.status() != http::StatusCode::SWITCHING_PROTOCOLS
        || response.headers().get("upgrade").and_then(|h| h.to_str().ok()) != Some(protocol)
        || !response
            .headers()
            .get("connection")
            .and_then(|h| h.to_str().ok())
            .is_some_and(|value| value.split(',').any(|token| token.trim().eq_ignore_ascii_case("upgrade")))
    {
        return Err(Error::InvalidResponse(format!("HTTP {} did not switch to {protocol}", response.status())));
    }
    Ok(Box::new(response.upgrade().await.map_err(|e| Error::transport(&e))?))
}

pub struct Records {
    stream: BoxStream<'static, std::result::Result<bytes::Bytes, reqwest::Error>>,
    buffer: Vec<u8>,
    pending: bytes::Bytes,
}
impl Records {
    fn new(response: reqwest::Response) -> Self {
        Self { stream: response.bytes_stream().boxed(), buffer: Vec::new(), pending: bytes::Bytes::new() }
    }
    pub async fn next(&mut self) -> Result<Option<ObserveRecord>> {
        self.next_line().await
    }
    /// A partial final record is a protocol failure, never silently discarded.
    async fn next_line<T: DeserializeOwned>(&mut self) -> Result<Option<T>> {
        const MAX_RECORD: usize = 8 * 1024 * 1024;
        loop {
            if self.pending.is_empty() {
                match self.stream.next().await {
                    Some(Ok(bytes)) => self.pending = bytes,
                    Some(Err(error)) => return Err(Error::transport(&error)),
                    None if self.buffer.is_empty() => return Ok(None),
                    None => return Err(Error::InvalidResponse("stream ended inside a record".into())),
                }
                continue;
            }
            // Copy one newline-delimited segment at a time: a chunk of many bounded
            // records is accepted, and an oversized record is refused before copying.
            let end = self.pending.iter().position(|b| *b == b'\n').map_or(self.pending.len(), |n| n + 1);
            if self.buffer.len().saturating_add(end) > MAX_RECORD + 1 {
                return Err(Error::InvalidResponse("record exceeds 8 MiB".into()));
            }
            self.buffer.extend_from_slice(&self.pending.split_to(end));
            if self.buffer.last() == Some(&b'\n') {
                let record = serde_json::from_slice(&self.buffer[..self.buffer.len() - 1]).map_err(Error::response);
                self.buffer.clear();
                return record.map(Some);
            }
        }
    }
}
/// Cursor survives reconnects. A snapshot is surfaced intact: it explicitly marks
/// a metering gap, rather than synthesizing transitions across missing history.
pub struct Observer<C = Client> {
    client: C,
    cursor: Option<String>,
    records: Option<api::ObservationStream>,
    reconnect_delay: Duration,
    retry_at: Option<Instant>,
}
impl<C: api::ProviderApi> Observer<C> {
    pub fn new(client: C, since: Option<String>) -> Self {
        Self { client, cursor: since, records: None, reconnect_delay: Duration::from_millis(100), retry_at: None }
    }
    fn disconnected(&mut self) {
        self.records = None;
        self.retry_at = Some(Instant::now() + self.reconnect_delay);
        self.reconnect_delay = (self.reconnect_delay * 2).min(Duration::from_secs(5));
    }
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
    pub async fn next(&mut self) -> Result<ObserveRecord> {
        if let Some(at) = self.retry_at {
            tokio::time::sleep_until(at).await;
            self.retry_at = None;
        }
        if self.records.is_none() {
            match self.client.observe(self.cursor.as_deref()).await {
                Ok(records) => self.records = Some(records),
                Err(error) => {
                    self.disconnected();
                    return Err(error);
                }
            }
        }
        match self.records.as_mut().expect("connected stream").next().await {
            Some(Ok(record)) => {
                self.reconnect_delay = Duration::from_millis(100);
                self.cursor = Some(
                    match &record {
                        ObserveRecord::Event { event } => &event.cursor,
                        ObserveRecord::Snapshot { cursor, .. } => cursor,
                    }
                    .clone(),
                );
                Ok(record)
            }
            result => {
                self.disconnected();
                Err(result.and_then(std::result::Result::err).unwrap_or_else(|| Error::Transport("observation stream ended".into())))
            }
        }
    }
}

/// Cache + per-provider rolling budgets. Each provider's mutex coalesces reads,
/// including reads for different IDs sharing an inspect rate limit.
/// No limits means no caching. Zero requests is a refusal, never a division panic.
pub struct StatusCache<C = Client> {
    client: C,
    states: BTreeMap<String, Mutex<CacheState>>,
}
struct CacheState {
    limits: Vec<RateLimit>,
    values: BTreeMap<Vec<String>, (Instant, serde_json::Value)>,
    calls: BTreeMap<(String, String), VecDeque<Instant>>,
}
impl<C: api::ProviderApi> StatusCache<C> {
    pub fn new(client: C, declarations: &[ProviderDeclaration]) -> Self {
        Self {
            client,
            states: declarations
                .iter()
                .map(|declaration| {
                    (
                        declaration.provider.clone(),
                        Mutex::new(CacheState { limits: declaration.rate_limits.clone(), values: BTreeMap::new(), calls: BTreeMap::new() }),
                    )
                })
                .collect(),
        }
    }
    async fn read<T: DeserializeOwned + Serialize>(&self, provider: &str, id: Option<&str>) -> Result<T> {
        let operation = if id.is_some() { "inspect" } else { "list" };
        let key = vec![provider.to_owned(), operation.to_owned(), id.unwrap_or_default().to_owned()];
        let Some(state) = self.states.get(provider) else {
            // Undeclared providers have no local budget or cache policy.
            let value = match id {
                Some(id) => serde_json::to_value(self.client.inspect(provider, id).await?),
                None => serde_json::to_value(self.client.list(provider).await?),
            }
            .map_err(Error::response)?;
            return serde_json::from_value(value).map_err(Error::response);
        };
        let mut state = state.lock().await;
        let now = Instant::now();
        let limits: Vec<_> = state.limits.iter().filter(|l| l.operation == operation || l.operation == "*").cloned().collect();
        if limits.iter().any(|l| l.requests == 0) {
            return Err(Error::RateLimited);
        }
        let ttl = limits.iter().map(|l| Duration::from_secs(l.period_seconds) / l.requests).max().unwrap_or_default();
        if let Some((at, value)) = state.values.get(&key)
            && now.duration_since(*at) < ttl
        {
            return serde_json::from_value(value.clone()).map_err(Error::response);
        }
        // Wildcard budgets are shared by list and inspect, not independently spent.
        for limit in &limits {
            let budget = (provider.to_owned(), limit.operation.clone());
            let window = Duration::from_secs(limit.period_seconds);
            if state.calls.get(&budget).into_iter().flatten().filter(|at| now.duration_since(**at) < window).count()
                >= limit.requests as usize
            {
                return Err(Error::RateLimited);
            }
        }
        // Reserve before I/O: failed or cancelled attempts still spend budget.
        for operation in limits.iter().map(|l| l.operation.clone()).collect::<std::collections::BTreeSet<_>>() {
            let calls = state.calls.entry((provider.to_owned(), operation.clone())).or_default();
            let longest =
                limits.iter().filter(|l| l.operation == operation).map(|l| Duration::from_secs(l.period_seconds)).max().unwrap_or_default();
            while calls.front().is_some_and(|at| now.duration_since(*at) >= longest) {
                calls.pop_front();
            }
            calls.push_back(now);
        }
        let value = match id {
            Some(id) => serde_json::to_value(self.client.inspect(provider, id).await?),
            None => serde_json::to_value(self.client.list(provider).await?),
        }
        .map_err(Error::response)?;
        // Bound memory per declared provider independently of caller-supplied IDs.
        if state.values.len() >= 1024 {
            state.values.clear();
        }
        state.values.insert(key, (now, value.clone()));
        serde_json::from_value(value).map_err(Error::response)
    }
    /// Mutations discard cached observations but retain their spent budget.
    pub async fn invalidate(&self, provider: &str) {
        if let Some(state) = self.states.get(provider) {
            state.lock().await.values.clear();
        }
    }
    pub async fn list(&self, provider: &str) -> Result<Vec<Environment>> {
        self.read(provider, None).await
    }
    pub async fn inspect(&self, provider: &str, id: &str) -> Result<Environment> {
        self.read(provider, Some(id)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Network body boundary stand-in. Exhaust every split position in a pair
    // of valid records, including empty chunks and multiple records per chunk.
    #[tokio::test]
    async fn framing_preserves_records_at_every_chunk_boundary() {
        let record = b"{\"type\":\"snapshot\",\"cursor\":\"c\",\"environments\":[]}\n";
        let body = record.repeat(2);
        for split in 0..=body.len() {
            let chunks = vec![Ok(bytes::Bytes::copy_from_slice(&body[..split])), Ok(bytes::Bytes::copy_from_slice(&body[split..]))];
            let mut records = Records { stream: futures::stream::iter(chunks).boxed(), buffer: vec![], pending: bytes::Bytes::new() };
            for _ in 0..2 {
                assert!(matches!(records.next().await.unwrap(), Some(ObserveRecord::Snapshot { cursor, .. }) if cursor == "c"));
            }
            assert!(records.next().await.unwrap().is_none());
        }
    }
    // A missing socket names its cause, and a host that never answers is a
    // timeout rather than a transport failure.
    #[tokio::test]
    async fn errors_keep_their_causes() {
        use api::ProviderApi;
        let dir = tempfile::tempdir().unwrap();
        let missing = Client::unix(dir.path().join("missing.sock")).unwrap().hello().await.unwrap_err();
        assert!(matches!(&missing, Error::Transport(cause) if cause.contains("No such file or directory")), "{missing}");
        let path = dir.path().join("silent.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let _held = tokio::spawn(async move {
            let _connection = listener.accept().await;
            std::future::pending::<()>().await
        });
        let silent = Client::unix(&path).unwrap().with_request_timeout(Duration::from_millis(50)).hello().await.unwrap_err();
        assert!(matches!(silent, Error::Timeout(_)), "{silent}");
    }
    // Malformed streams cannot retain more than the framing bound, and a
    // truncated final record is an error rather than a silent disconnect.
    #[tokio::test]
    async fn framing_rejects_oversized_and_partial_input() {
        for body in [b"{\"type\":\"snapshot\"".to_vec(), vec![b'x'; 8 * 1024 * 1024 + 2]] {
            let mut records = Records {
                stream: futures::stream::iter(vec![Ok(bytes::Bytes::from(body))]).boxed(),
                buffer: vec![],
                pending: bytes::Bytes::new(),
            };
            assert!(matches!(records.next().await, Err(Error::InvalidResponse(_))));
            assert!(records.buffer.len() <= 8 * 1024 * 1024 + 1);
        }
    }
}

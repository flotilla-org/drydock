//! Typed, single-attempt host calls. Observation reconnect policy is explicit and
//! separate from calls. Neither API stores desired state or reconciles resources.
use drydock_protocol::*;
use futures::{StreamExt, stream::BoxStream};
use reqwest::{Method, Url};
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
    #[error("host transport failed")]
    Transport,
    #[error("invalid host response")]
    InvalidResponse,
    #[error("invalid host endpoint or request")]
    InvalidRequest,
    #[error("host protocol error: {}", .0.class())]
    Protocol(ProtocolError),
    #[error("host protocol version mismatch")]
    VersionMismatch,
    #[error("local status request budget exhausted")]
    RateLimited,
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
        let response = self.0.execute(request).await.map_err(|_| "host transport".to_owned())?;
        let mut result = http::Response::builder().status(response.status());
        *result.headers_mut().expect("response builder") = response.headers().clone();
        result.body(response.bytes().await.map_err(|_| "host body".to_owned())?).map_err(|_| "host response".to_owned())
    }
}

#[derive(Clone)]
pub struct Client {
    base: Url,
    bearer: Option<Secret>,
    transport: reqwest::Client,
    http: Arc<dyn HttpClient>,
}
impl Client {
    pub fn unix(path: impl AsRef<Path>) -> Result<Self> {
        let transport = Self::builder().unix_socket(path.as_ref().to_path_buf()).build().map_err(|_| Error::InvalidRequest)?;
        Ok(Self {
            base: Url::parse("http://localhost/").expect("constant URL"),
            bearer: None,
            http: Arc::new(SocketHttp(transport.clone())),
            transport,
        })
    }
    /// External TCP hosts are loopback-only and require an explicitly supplied token.
    pub fn external(url: &str, bearer: Secret) -> Result<Self> {
        let base = Url::parse(url).map_err(|_| Error::InvalidRequest)?;
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
            return Err(Error::InvalidRequest);
        }
        let transport = Self::builder().build().map_err(|_| Error::InvalidRequest)?;
        let http = rigging_http_client::ReqwestHttpClient::restricted(None, None).map_err(|_| Error::InvalidRequest)?;
        Ok(Self { base, bearer: Some(bearer), transport, http: Arc::new(http) })
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
        url.path_segments_mut().map_err(|_| Error::InvalidRequest)?.clear().extend(segments);
        let mut request = self.transport.request(method, url);
        if let Some(token) = &self.bearer {
            request = request.bearer_auth(token.expose());
        }
        Ok(request)
    }
    async fn call<T: DeserializeOwned, B: Serialize + ?Sized>(&self, method: Method, segments: &[&str], body: Option<&B>) -> Result<T> {
        let mut request = self.request(method, segments)?.timeout(Duration::from_secs(30));
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = http_execute!(self.http, request.build().map_err(|_| Error::InvalidRequest)?).map_err(|_| Error::Transport)?;
        if !response.status().is_success() {
            return Err(Error::Protocol(serde_json::from_slice(response.body()).map_err(|_| Error::InvalidResponse)?));
        }
        let body = if response.status() == http::StatusCode::NO_CONTENT { b"null".as_slice() } else { response.body().as_ref() };
        serde_json::from_slice(body).map_err(|_| Error::InvalidResponse)
    }
    async fn get<T: DeserializeOwned>(&self, segments: &[&str]) -> Result<T> {
        self.call::<T, ()>(Method::GET, segments, None).await
    }
    pub async fn hello(&self) -> Result<Hello> {
        let hello: Hello = self.get(&["v1", "hello"]).await?;
        if !hello.is_compatible() {
            return Err(Error::VersionMismatch);
        }
        Ok(hello)
    }
    pub async fn configure(&self, configuration: &HostConfiguration) -> Result<()> {
        self.call(Method::PUT, &["v1", "config"], Some(configuration)).await
    }
    pub async fn credential(&self, provider: &str, value: Secret) -> Result<()> {
        self.call(Method::PUT, &["v1", "providers", provider, "credential"], Some(&CredentialRefresh { value })).await
    }
    pub async fn prepare(&self, provider: &str, request: &PrepareRequest) -> Result<Prepared> {
        self.call(Method::POST, &["v1", "providers", provider, "prepare"], Some(request)).await
    }
    pub async fn list(&self, provider: &str) -> Result<Vec<Environment>> {
        self.get(&["v1", "providers", provider, "environments"]).await
    }
    pub async fn inspect(&self, provider: &str, id: &str) -> Result<Environment> {
        self.get(&["v1", "providers", provider, "environments", id]).await
    }
    pub async fn provision(&self, provider: &str, request: &ProvisionRequest) -> Result<Environment> {
        self.call(Method::POST, &["v1", "providers", provider, "environments"], Some(request)).await
    }
    pub async fn destroy(&self, provider: &str, id: &str) -> Result<()> {
        self.call::<_, ()>(Method::DELETE, &["v1", "providers", provider, "environments", id], None).await
    }
    pub async fn reach(&self, provider: &str, id: &str) -> Result<Reach> {
        self.call::<_, ()>(Method::POST, &["v1", "providers", provider, "environments", id, "reach"], None).await
    }
    pub async fn suspend(&self, provider: &str, id: &str) -> Result<ResumeToken> {
        self.call::<_, ()>(Method::POST, &["v1", "providers", provider, "environments", id, "suspend"], None).await
    }
    pub async fn resume(&self, provider: &str, id: &str, token: &ResumeToken) -> Result<()> {
        self.call(Method::POST, &["v1", "providers", provider, "environments", id, "resume"], Some(token)).await
    }
    pub async fn export(&self, provider: &str, id: &str) -> Result<Export> {
        self.call::<_, ()>(Method::POST, &["v1", "providers", provider, "environments", id, "export"], None).await
    }
    pub async fn quota(&self, provider: &str) -> Result<Quota> {
        self.get(&["v1", "providers", provider, "quota"]).await
    }
    pub async fn usage(&self, provider: &str, period: &Period) -> Result<Usage> {
        let request = self
            .request(Method::GET, &["v1", "providers", provider, "usage"])?
            .query(period)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| Error::InvalidRequest)?;
        let response = http_execute!(self.http, request).map_err(|_| Error::Transport)?;
        if !response.status().is_success() {
            return Err(Error::Protocol(serde_json::from_slice(response.body()).map_err(|_| Error::InvalidResponse)?));
        }
        serde_json::from_slice(response.body()).map_err(|_| Error::InvalidResponse)
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
            .request(if body.is_some() { Method::POST } else { Method::GET }, &["v1", "providers", provider, "environments", id, route])?
            .header("connection", "upgrade")
            .header("upgrade", protocol)
            .timeout(Duration::from_secs(30));
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(|_| Error::Transport)?;
        if response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
            return Err(Error::Protocol(response.json().await.map_err(|_| Error::InvalidResponse)?));
        }
        if response.headers().get("upgrade").and_then(|h| h.to_str().ok()) != Some(protocol) {
            return Err(Error::InvalidResponse);
        }
        Ok(Box::new(response.upgrade().await.map_err(|_| Error::Transport)?))
    }
    pub async fn relay(&self, provider: &str, id: &str) -> Result<rigging_stream::ByteStream> {
        self.upgrade::<()>(provider, id, "relay", "drydock-relay", None).await
    }
    pub async fn exec(&self, provider: &str, id: &str, command: &ExecRequest) -> Result<rigging_stream::ByteStream> {
        self.upgrade(provider, id, "exec", "drydock-stream", Some(command)).await
    }
    pub async fn observe(&self, since: Option<&str>) -> Result<Records> {
        let mut request = self.request(Method::GET, &["v1", "events"])?;
        if let Some(since) = since {
            request = request.query(&[("since", since)]);
        }
        let response = request.send().await.map_err(|_| Error::Transport)?;
        if !response.status().is_success() {
            return Err(Error::Protocol(response.json().await.map_err(|_| Error::InvalidResponse)?));
        }
        Ok(Records { stream: response.bytes_stream().boxed(), buffer: Vec::new() })
    }
}

pub struct Records {
    stream: BoxStream<'static, std::result::Result<bytes::Bytes, reqwest::Error>>,
    buffer: Vec<u8>,
}
impl Records {
    /// A partial final record is a protocol failure, never silently discarded.
    pub async fn next(&mut self) -> Result<Option<ObserveRecord>> {
        const MAX_RECORD: usize = 8 * 1024 * 1024;
        loop {
            if let Some(end) = self.buffer.iter().position(|b| *b == b'\n') {
                if end > MAX_RECORD {
                    return Err(Error::InvalidResponse);
                }
                let record = serde_json::from_slice(&self.buffer[..end]).map_err(|_| Error::InvalidResponse)?;
                self.buffer.drain(..=end);
                return Ok(Some(record));
            }
            if self.buffer.len() > MAX_RECORD {
                return Err(Error::InvalidResponse);
            }
            match self.stream.next().await {
                Some(Ok(bytes)) => self.buffer.extend(bytes),
                Some(Err(_)) => return Err(Error::Transport),
                None if self.buffer.is_empty() => return Ok(None),
                None => return Err(Error::InvalidResponse),
            }
        }
    }
}
/// Cursor survives reconnects. A snapshot is surfaced intact: it explicitly marks
/// a metering gap, rather than synthesizing transitions across missing history.
pub struct Observer {
    client: Client,
    cursor: Option<String>,
    records: Option<Records>,
    reconnect_delay: Duration,
}
impl Observer {
    pub fn new(client: Client, since: Option<String>) -> Self {
        Self { client, cursor: since, records: None, reconnect_delay: Duration::from_millis(100) }
    }
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
    pub async fn next(&mut self) -> Result<ObserveRecord> {
        if self.records.is_none() {
            self.records = Some(self.client.observe(self.cursor.as_deref()).await?);
        }
        match self.records.as_mut().expect("connected stream").next().await {
            Ok(Some(record)) => {
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
                self.records = None;
                tokio::time::sleep(self.reconnect_delay).await;
                Err(result.err().unwrap_or(Error::Transport))
            }
        }
    }
}

/// Cache + per-provider rolling budgets. A single mutex coalesces concurrent
/// reads, including reads for different IDs sharing an inspect rate limit.
/// No limits means no caching. Zero requests is a refusal, never a division panic.
pub struct StatusCache {
    client: Client,
    state: Mutex<CacheState>,
}
struct CacheState {
    declarations: BTreeMap<String, Vec<RateLimit>>,
    values: BTreeMap<Vec<String>, (Instant, serde_json::Value)>,
    calls: BTreeMap<(String, String), VecDeque<Instant>>,
}
impl StatusCache {
    pub fn new(client: Client, declarations: &[ProviderDeclaration]) -> Self {
        Self {
            client,
            state: Mutex::new(CacheState {
                declarations: declarations.iter().map(|d| (d.provider.clone(), d.rate_limits.clone())).collect(),
                values: BTreeMap::new(),
                calls: BTreeMap::new(),
            }),
        }
    }
    async fn read<T: DeserializeOwned + Serialize>(&self, provider: &str, id: Option<&str>) -> Result<T> {
        let operation = if id.is_some() { "inspect" } else { "list" };
        let key = vec![provider.to_owned(), operation.to_owned(), id.unwrap_or_default().to_owned()];
        let mut state = self.state.lock().await;
        let now = Instant::now();
        let limits: Vec<_> = state
            .declarations
            .get(provider)
            .into_iter()
            .flatten()
            .filter(|l| l.operation == operation || l.operation == "*")
            .cloned()
            .collect();
        if limits.iter().any(|l| l.requests == 0) {
            return Err(Error::RateLimited);
        }
        let ttl = limits.iter().map(|l| Duration::from_secs(l.period_seconds) / l.requests).max().unwrap_or_default();
        if let Some((at, value)) = state.values.get(&key)
            && now.duration_since(*at) < ttl
        {
            return serde_json::from_value(value.clone()).map_err(|_| Error::InvalidResponse);
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
        .map_err(|_| Error::InvalidResponse)?;
        // Bound memory independently of IDs supplied by callers.
        if state.values.len() >= 1024 {
            state.values.clear();
        }
        state.values.insert(key, (now, value.clone()));
        serde_json::from_value(value).map_err(|_| Error::InvalidResponse)
    }
    pub async fn list(&self, provider: &str) -> Result<Vec<Environment>> {
        self.read(provider, None).await
    }
    pub async fn inspect(&self, provider: &str, id: &str) -> Result<Environment> {
        self.read(provider, Some(id)).await
    }
}

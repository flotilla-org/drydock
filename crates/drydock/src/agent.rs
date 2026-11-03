//! The one way a client reaches a vessel's agent: provider, vessel and identity
//! in, a connected agent out. The provider's declaration decides whether its
//! vessels run an agent, and its reach decides how to get there; a client never
//! interprets either. The daemon's launch and embedding clients both use this.
use crate::{api::ProviderApi, client::Error};
use async_trait::async_trait;
use drydock_protocol::{DiagnosticMasker, Platform, ProtocolError, Reach};
use drydock_transport::{ByteStream, ssh::SshConfig, websocket::StreamDialer};
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

pub mod stand_in;

/// The agent's control socket inside every vessel.
pub const AGENT_SOCKET: &str = "/run/drydock/agent.sock";

/// Opens the SSH link a reach recipe describes: one connection to the agent's
/// socket through a local forward, which every SSH server allows (Daytona's
/// gateway included). OpenSSH in production; tests stand in a gateway. A relay
/// reach needs no dialer: the provider's host relays the connection.
#[async_trait]
pub trait SshDialer: Send + Sync {
    async fn dial(&self, config: SshConfig) -> io::Result<ByteStream>;
}

/// The production dialer for a dial reach, made on first use: building its
/// TLS configuration reads the platform's trust store.
struct Tls(std::sync::OnceLock<drydock_transport::websocket::TlsDialer>);

#[async_trait]
impl StreamDialer for Tls {
    async fn connect(&self, url: &str) -> io::Result<ByteStream> {
        let dialer = match self.0.get() {
            Some(dialer) => dialer,
            None => {
                // Two first uses at once may both build one; the loser is
                // dropped (`get_or_try_init` is unstable).
                let dialer = drydock_transport::websocket::TlsDialer::new()?;
                self.0.get_or_init(|| dialer)
            }
        };
        dialer.connect(url).await
    }
}

/// Drydock's OpenSSH transport.
pub struct OpenSsh;

#[async_trait]
impl SshDialer for OpenSsh {
    async fn dial(&self, config: SshConfig) -> io::Result<ByteStream> {
        drydock_transport::ssh::connect(config).await
    }
}

/// One vessel's agent, as a client asks for it.
pub struct Vessel<'a> {
    pub provider: &'a str,
    /// The provider's environment ID.
    pub environment: &'a str,
    /// The private key whose public half was provisioned into the vessel.
    pub identity: &'a Path,
    /// The prepared platform, which the agent must report.
    pub platform: &'a Platform,
    /// The agent build for `platform`, pushed to an older agent.
    pub build: &'a [u8],
}

/// What drydock chose for one vessel's agent connection, reported to clients
/// as information: they show it and never decide on it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentReport {
    /// The provider instance.
    pub provider: String,
    /// The provider's module, such as `daytona`.
    pub module: String,
    /// The provider's environment ID for the vessel.
    pub environment: String,
    /// The SSH endpoint the agent is reached through, without credentials;
    /// [`RELAY`] when the provider's host carries the connection; or a dial
    /// reach's URL without its query.
    pub endpoint: String,
}

/// The reported endpoint of an agent reached through its provider's relay route.
pub const RELAY: &str = "relay";

impl std::fmt::Display for AgentReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.endpoint.as_str() {
            RELAY => write!(f, "relay"),
            endpoint if endpoint.contains("://") => write!(f, "dial {endpoint}"),
            endpoint => write!(f, "ssh {endpoint}"),
        }?;
        write!(f, " to {} vessel {} (provider {})", self.module, self.environment, self.provider)
    }
}

/// A connected agent and what drydock chose to reach it.
pub struct ConnectedAgent {
    pub client: drydock_agent::Client,
    pub report: AgentReport,
}

/// Connects to vessel agents.
#[derive(Clone)]
pub struct AgentReach {
    dialer: Arc<dyn SshDialer>,
    streams: Arc<dyn StreamDialer>,
    timeout: Duration,
}

impl Default for AgentReach {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentReach {
    pub fn new() -> Self {
        Self { dialer: Arc::new(OpenSsh), streams: Arc::new(Tls(Default::default())), timeout: Duration::from_secs(60) }
    }

    pub fn with_dialer(mut self, dialer: Arc<dyn SshDialer>) -> Self {
        self.dialer = dialer;
        self
    }

    /// The dialer a dial reach's connections are opened with.
    pub fn with_streams(mut self, streams: Arc<dyn StreamDialer>) -> Self {
        self.streams = streams;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Wait for the vessel agent's current hello. A provider that declares no
    /// agent, or a reach this client cannot follow, is refused at once; other
    /// failures retry until the timeout and report the last one, with the
    /// reach's minted gateway username masked. Each distinct retry reason is
    /// written once to stderr (the daemon's `drydock.log`), masked the same way;
    /// an embedding client sees those lines on its own stderr.
    pub async fn connect(&self, api: &dyn ProviderApi, vessel: &Vessel<'_>) -> Result<ConnectedAgent, Error> {
        self.connect_at(api, vessel, Path::new(AGENT_SOCKET)).await
    }

    /// [`Self::connect`] to an agent listening at `socket` rather than the
    /// fixed [`AGENT_SOCKET`], for tests whose vessel is the test host.
    pub(crate) async fn connect_at(&self, api: &dyn ProviderApi, vessel: &Vessel<'_>, socket: &Path) -> Result<ConnectedAgent, Error> {
        let refused = |reason: String| Error::Protocol(ProtocolError::Refused { reason });
        let declaration = api.provider(vessel.provider).await?;
        if !declaration.capabilities.agent {
            return Err(refused(format!("provider {} declares no vessel agent", vessel.provider)));
        }
        // Each reach mints a fresh gateway username, which is an access token.
        let masker = Mutex::new(DiagnosticMasker::default());
        let choice = Mutex::new(None);
        let open = || async {
            let reach = api.reach(vessel.provider, vessel.environment).await.map_err(|e| io::Error::other(format!("agent reach: {e}")))?;
            // Whether the server accepts remote forwards does not matter: the
            // agent never opens a connection towards drydock.
            let (endpoint, user, host_key) = match reach {
                Reach::Ssh { endpoint, user, host_key, .. } => (endpoint, user, host_key),
                // The provider's host carries the connection to the agent's
                // socket itself, as Namespace's does over an SSH exec channel.
                Reach::Relay { .. } => {
                    let stream =
                        api.relay(vessel.provider, vessel.environment).await.map_err(|e| io::Error::other(format!("agent relay: {e}")))?;
                    *choice.lock().unwrap() = Some(RELAY.to_owned());
                    return Ok(Box::new(stream) as ByteStream);
                }
                // The agent's TCP listener behind the provider's edge, which
                // takes its own credential from the URL's query or a header.
                Reach::Dial { url, token, headers, .. } => {
                    let stream = self.dial(&url, &token, &headers, &masker).await?;
                    *choice.lock().unwrap() = Some(url.split(['?', '#']).next().unwrap_or_default().to_owned());
                    return Ok(stream);
                }
            };
            masker.lock().unwrap().remember(user.expose());
            let mut config = ssh_config(&endpoint, user.expose(), host_key, vessel.identity.into())?;
            // The endpoint dialled, which is the one reported: host and port only.
            let reached = format!("{}:{}", config.host, config.port);
            config.agent_socket = socket.into();
            let stream = self.dialer.dial(config).await?;
            // The endpoint of the last dial that succeeded, which carries the agent returned.
            *choice.lock().unwrap() = Some(reached);
            Ok(stream)
        };
        let client = wait_for_agent(open, vessel.platform, vessel.build, self.timeout, |text| masker.lock().unwrap().text(text))
            .await
            .map_err(|error| {
                let reason = format!("vessel agent did not complete its hello handshake: {error}");
                Error::Protocol(match error.kind() {
                    io::ErrorKind::Unsupported => ProtocolError::Refused { reason },
                    _ => ProtocolError::unavailable(reason, None),
                })
            })?;
        let endpoint = choice.lock().unwrap().take().expect("a connected agent was reached");
        let report = AgentReport {
            provider: declaration.provider.clone(),
            module: declaration.module.clone(),
            environment: vessel.environment.into(),
            endpoint,
        };
        Ok(ConnectedAgent { client, report })
    }
}

/// The shortest query value a dial reach's errors mask on its own; shorter
/// ones are masked only as `name=value`.
const MASKED_QUERY_VALUE: usize = 8;

impl AgentReach {
    /// One connection to the agent through a dial reach's edge. Everything
    /// the edge is given is masked first, since it may echo it: each query
    /// value (raw and decoded), each header value and the agent's token. What
    /// no fresh reach could make followable (userinfo in `url`, a header that
    /// is not one, a token that cannot be an agent's) is `Unsupported`, so it
    /// is refused at once rather than retried. The edge's refusal (a
    /// [`drydock_transport::tcp::Refusal`]) is reported with its status,
    /// naming the URL without its query.
    async fn dial(
        &self,
        url: &str,
        token: &drydock_protocol::Secret,
        headers: &std::collections::BTreeMap<String, drydock_protocol::Secret>,
        masker: &Mutex<DiagnosticMasker>,
    ) -> io::Result<ByteStream> {
        use http::header::{HeaderName, HeaderValue};
        let unsupported = |reason: String| io::Error::new(io::ErrorKind::Unsupported, reason);
        let base = url.split(['?', '#']).next().unwrap_or_default();
        {
            let mut masker = masker.lock().unwrap();
            // An edge may echo its credential, raw or decoded, alone or with
            // its name. A value too short to be a credential (`v=1`) is
            // masked only with its name, or it would mask every `1` in a
            // status such as 401.
            if let Some((_, query)) = url.split_once('?') {
                let query = query.split('#').next().unwrap_or_default();
                masker.remember(query);
                for pair in query.split('&') {
                    masker.remember(pair);
                    let Some((_, value)) = pair.split_once('=') else { continue };
                    let decoded = percent_encoding::percent_decode_str(&value.replace('+', " ")).decode_utf8_lossy().into_owned();
                    for value in [value, &decoded] {
                        if value.len() >= MASKED_QUERY_VALUE {
                            masker.remember(value);
                        }
                    }
                }
            }
            for value in headers.values() {
                masker.remember(value.expose());
            }
            // The edge sees the agent's token in transit too.
            masker.remember(token.expose());
        }
        // Userinfo would go out in `Host`; it is never shown, so neither is the URL.
        if url.split_once("://").is_some_and(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default().contains('@')) {
            return Err(unsupported("dial reach URL must not carry userinfo".into()));
        }
        let token = drydock_transport::tcp::Token::parse(token.expose()).map_err(|e| unsupported(format!("dial reach token: {e}")))?;
        let mut sent = http::HeaderMap::new();
        for (name, value) in headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| unsupported(format!("dial reach header {name:?} is not a header name")))?;
            // Names are case-insensitive: two spellings of one would leave one unsent.
            if sent.contains_key(&name) {
                return Err(unsupported(format!("dial reach header {name} is given twice")));
            }
            let mut value = HeaderValue::from_str(value.expose())
                .map_err(|_| unsupported(format!("dial reach header {name}'s value is not a header value")))?;
            value.set_sensitive(true);
            sent.insert(name, value);
        }
        // A refusal before anything is sent cannot change with a fresh reach.
        let invalid = |error: io::Error| match error.kind() {
            io::ErrorKind::InvalidInput => unsupported(format!("dial reach {base}: {error}")),
            _ => error,
        };
        let stream = self.streams.connect(url).await.map_err(invalid)?;
        drydock_transport::tcp::connect_at_with(stream, url, &token, sent).await.map_err(|error| {
            match drydock_transport::tcp::Refusal::of(&error) {
                // The edge's answer, or the agent's through it: which one shows in the status.
                Some(refusal) => io::Error::new(error.kind(), format!("the edge at {base} {refusal}")),
                None => invalid(error),
            }
        })
    }
}

/// The SSH link for one reach recipe. Any userinfo a provider puts in the
/// endpoint is dropped: the user is the reach's own.
pub(crate) fn ssh_config(endpoint: &str, user: &str, host_key: String, identity: PathBuf) -> io::Result<SshConfig> {
    let endpoint = endpoint.rsplit_once('@').map_or(endpoint, |(_, host)| host);
    let (host, port) = endpoint.rsplit_once(':').ok_or_else(|| io::Error::other("invalid SSH endpoint"))?;
    Ok(SshConfig {
        connect_timeout: Duration::from_secs(10),
        host: host.into(),
        port: port.parse().map_err(|e| io::Error::other(format!("invalid SSH endpoint port: {e}")))?,
        user: user.into(),
        host_key,
        identity_file: identity,
        agent_socket: AGENT_SOCKET.into(),
    })
}

// Provider startup can precede the socket listener. connect_current itself owns
// upgrade/re-exec reconnects and only returns a compatible hello. Unsupported
// errors (including an agent reporting another platform than the prepared one)
// return at once; others retry until the deadline. `mask` removes credentials
// from each attempt's error before it is logged or returned.
pub(crate) async fn wait_for_agent<F, Fut>(
    mut open: F,
    platform: &Platform,
    executable: &[u8],
    timeout: Duration,
    mask: impl Fn(&str) -> String,
) -> io::Result<drydock_agent::Client>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = io::Result<ByteStream>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last = None;
    for attempt in 1.. {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, drydock_agent::Client::connect_current(&mut open, platform, executable, remaining)).await {
            Ok(Ok(client)) => return Ok(client),
            // Retrying cannot change an unsupported arrangement.
            Ok(Err(error)) if error.kind() == io::ErrorKind::Unsupported => return Err(error),
            Ok(Err(error)) => {
                let interrupted = error.kind() == io::ErrorKind::TimedOut && tokio::time::Instant::now() >= deadline;
                let error = mask(&error.to_string());
                // Log a reason once, not on every 250ms retry.
                if last.as_deref() != Some(error.as_str()) {
                    // The daemon logs through stderr into drydock.log.
                    eprintln!("agent hello attempt {attempt} failed: {error}");
                }
                // An attempt cut short by the deadline says less than the one before it.
                if !interrupted || last.is_none() {
                    last = Some(error);
                }
            }
            Err(_) => break,
        }
        tokio::time::sleep(Duration::from_millis(250).min(remaining)).await;
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("agent hello timed out after {timeout:?}; last error: {}", last.as_deref().unwrap_or("no attempt finished")),
    ))
}

#[cfg(test)]
mod tests;

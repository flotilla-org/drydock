//! The one way a client reaches a vessel's agent: provider, vessel and identity
//! in, a connected agent out. The provider's declaration decides whether its
//! vessels run an agent, and its reach decides how to get there; a client never
//! interprets either. The daemon's launch and embedding clients both use this.
use crate::{api::ProviderApi, client::Error};
use async_trait::async_trait;
use drydock_protocol::{DiagnosticMasker, Platform, ProtocolError, Reach};
use drydock_transport::{
    Limits, Transport,
    ssh::{GuestStreams, SshConfig},
};
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
/// The guest path a reverse forward serves the agent's guest-to-host streams on.
pub const HOST_SOCKET: &str = "/run/drydock/host.sock";

/// How guest-to-host streams travel on the agent's SSH link.
///
/// As a provider setting (`agent_link` in drydock's configuration) it is the
/// preferred link, used where the provider's SSH server allows it; reverse
/// forward is the default. As a [`ConnectedAgent`]'s link it is the one in use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLink {
    /// Each guest-to-host stream gets its own SSH channel through a remote
    /// forward. Only servers that accept remote Unix-socket forwards allow it.
    #[default]
    ReverseForward,
    /// Streams in both directions share one yamux link through the local
    /// forward. Every SSH server allows it, Daytona's gateway included.
    LocalForward,
}

impl AgentLink {
    /// The link to use under this preference, given whether the provider's
    /// server accepts remote forwards.
    pub fn under(self, reverse_forwards: bool) -> Self {
        match self {
            Self::ReverseForward if reverse_forwards => Self::ReverseForward,
            _ => Self::LocalForward,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReverseForward => "reverse_forward",
            Self::LocalForward => "local_forward",
        }
    }
}

impl std::fmt::Display for AgentLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Opens the SSH link a reach recipe describes. OpenSSH in production; tests
/// stand in a gateway with the same forwarding rules.
#[async_trait]
pub trait SshDialer: Send + Sync {
    async fn dial(&self, config: SshConfig) -> io::Result<Transport>;
}

/// Drydock's OpenSSH transport.
pub struct OpenSsh;

#[async_trait]
impl SshDialer for OpenSsh {
    async fn dial(&self, config: SshConfig) -> io::Result<Transport> {
        drydock_transport::ssh::connect(config, Limits::default()).await
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

/// A connected agent and the link it uses.
pub struct ConnectedAgent {
    pub client: drydock_agent::Client,
    pub link: AgentLink,
}

/// Connects to vessel agents under one provider's link preference.
#[derive(Clone)]
pub struct AgentReach {
    preferred: AgentLink,
    dialer: Arc<dyn SshDialer>,
    timeout: Duration,
}

impl AgentReach {
    pub fn new(preferred: AgentLink) -> Self {
        Self { preferred, dialer: Arc::new(OpenSsh), timeout: Duration::from_secs(60) }
    }

    pub fn with_dialer(mut self, dialer: Arc<dyn SshDialer>) -> Self {
        self.dialer = dialer;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Wait for the vessel agent's current hello. A provider that declares no
    /// agent, or a reach this client cannot follow, is refused at once; other
    /// failures retry until the timeout and report the last one, with the
    /// reach's minted gateway username masked.
    pub async fn connect(&self, api: &dyn ProviderApi, vessel: &Vessel<'_>) -> Result<ConnectedAgent, Error> {
        self.connect_at(api, vessel, Path::new(AGENT_SOCKET)).await
    }

    /// [`Self::connect`] to an agent listening at `socket` rather than the
    /// fixed [`AGENT_SOCKET`], for tests whose vessel is the test host.
    pub(crate) async fn connect_at(&self, api: &dyn ProviderApi, vessel: &Vessel<'_>, socket: &Path) -> Result<ConnectedAgent, Error> {
        let refused = |reason: String| Error::Protocol(ProtocolError::Refused { reason });
        let hello = api.hello().await?;
        let declaration = hello
            .providers
            .iter()
            .find(|declaration| declaration.provider == vessel.provider)
            .ok_or_else(|| refused(format!("provider {} is not declared", vessel.provider)))?;
        if !declaration.capabilities.agent {
            return Err(refused(format!("provider {} declares no vessel agent", vessel.provider)));
        }
        // Each reach mints a fresh gateway username, which is an access token.
        let masker = Mutex::new(DiagnosticMasker::default());
        let link = Mutex::new(None);
        let open = || async {
            let reach = api.reach(vessel.provider, vessel.environment).await.map_err(|e| io::Error::other(format!("agent reach: {e}")))?;
            let Reach::Ssh { endpoint, user, host_key, reverse_forwards } = reach else {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "agent hello requires an SSH reach"));
            };
            masker.lock().unwrap().remember(user.expose());
            let chosen = self.preferred.under(reverse_forwards);
            let mut config = ssh_config(&endpoint, user.expose(), host_key, vessel.identity.into(), chosen)?;
            config.agent_socket = socket.into();
            let transport = self.dialer.dial(config).await?;
            // The link of the last dial that succeeded, which carries the agent returned.
            *link.lock().unwrap() = Some(chosen);
            Ok(transport)
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
        let link = link.lock().unwrap().expect("a connected agent was reached");
        Ok(ConnectedAgent { client, link })
    }
}

/// The SSH link for one reach recipe and the chosen agent link.
pub(crate) fn ssh_config(endpoint: &str, user: &str, host_key: String, identity: PathBuf, link: AgentLink) -> io::Result<SshConfig> {
    let (host, port) = endpoint.rsplit_once(':').ok_or_else(|| io::Error::other("invalid SSH endpoint"))?;
    Ok(SshConfig {
        connect_timeout: Duration::from_secs(10),
        host: host.into(),
        port: port.parse().map_err(|e| io::Error::other(format!("invalid SSH endpoint port: {e}")))?,
        user: user.into(),
        host_key,
        identity_file: identity,
        agent_socket: AGENT_SOCKET.into(),
        guest_streams: match link {
            AgentLink::ReverseForward => GuestStreams::ReverseForward(HOST_SOCKET.into()),
            AgentLink::LocalForward => GuestStreams::OverLocalForward,
        },
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
    Fut: std::future::Future<Output = io::Result<Transport>>,
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

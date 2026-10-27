//! An in-process SSH gateway and vessel for clients' tests of agent reach. It
//! serves a real agent, and dials it under an SSH server's forwarding rules: a
//! gateway that refuses remote forwards fails a reverse-forward link the way
//! OpenSSH does (`ExitOnForwardFailure`), as Daytona's gateway does. Guest paths
//! in the agent's requests are this host's own paths. It is test support for
//! drydock and its embedding clients, never a production dialer.
use super::{AgentLink, SshDialer};
use async_trait::async_trait;
use drydock_transport::{
    Limits, Transport,
    native::UnixConnections,
    ssh::{GuestStreams, SshConfig},
};
use sha2::{Digest, Sha256};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::{
    net::{UnixListener, UnixStream},
    task::JoinHandle,
};

pub struct Gateway {
    agent_socket: PathBuf,
    host_socket: PathBuf,
    executable: PathBuf,
    fingerprint: String,
    reverse_forwards: bool,
    links: Mutex<Vec<AgentLink>>,
    agent: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Gateway {
    /// Serve an agent whose fingerprint is `build`'s, with its sockets in
    /// `directory`. `reverse_forwards` is whether this gateway accepts them.
    pub fn start(directory: &Path, reverse_forwards: bool, build: &[u8]) -> io::Result<Arc<Self>> {
        let gateway = Arc::new(Self {
            agent_socket: directory.join("agent.sock"),
            host_socket: directory.join("host.sock"),
            executable: directory.join("drydock-agent"),
            fingerprint: format!("{:x}", Sha256::digest(build)),
            reverse_forwards,
            links: Mutex::default(),
            agent: Mutex::default(),
        });
        gateway.restart()?;
        Ok(gateway)
    }

    /// The agent dies, closing every link; its socket refuses connections.
    pub fn stop(&self) {
        if let Some(agent) = self.agent.lock().unwrap().take() {
            agent.abort();
        }
    }

    /// A new agent serves the vessel, as its supervisor restarts it: it has
    /// none of the configuration or forwards the previous one was given.
    pub fn restart(&self) -> io::Result<()> {
        self.stop();
        match std::fs::remove_file(&self.agent_socket) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        let listener = UnixListener::bind(&self.agent_socket)?;
        let transport = Transport::native(Arc::new(UnixConnections::new(listener, self.host_socket.clone())), Limits::default())?;
        let agent = drydock_agent::Agent::new(transport, self.fingerprint.clone(), self.executable.clone());
        *self.agent.lock().unwrap() = Some(tokio::spawn(async move {
            let _ = agent.run().await;
        }));
        Ok(())
    }

    /// Every link a client dialled, in order, refused ones included.
    pub fn links(&self) -> Vec<AgentLink> {
        self.links.lock().unwrap().clone()
    }
}

#[async_trait]
impl SshDialer for Gateway {
    async fn dial(&self, config: SshConfig) -> io::Result<Transport> {
        match config.guest_streams {
            GuestStreams::ReverseForward(_) => {
                self.links.lock().unwrap().push(AgentLink::ReverseForward);
                if !self.reverse_forwards {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "SSH forwarding rejected: remote port forwarding failed for listen path /run/drydock/host.sock",
                    ));
                }
                // Each session forwards the guest path afresh.
                match std::fs::remove_file(&self.host_socket) {
                    Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
                    _ => {}
                }
                let listener = UnixListener::bind(&self.host_socket)?;
                Transport::native(Arc::new(UnixConnections::new(listener, self.agent_socket.clone())), Limits::default())
            }
            GuestStreams::OverLocalForward => {
                self.links.lock().unwrap().push(AgentLink::LocalForward);
                Transport::yamux(Box::new(UnixStream::connect(&self.agent_socket).await?), true, Limits::default()).await
            }
        }
    }
}

//! An in-process SSH gateway and vessel for clients' tests of agent reach. It
//! serves a real agent, and dials it as an SSH local forward does: one
//! connection to the agent's socket, cut when the agent dies. Guest paths in
//! the agent's requests are this host's own paths. It is test support for
//! drydock and its embedding clients, never a production dialer.
use super::SshDialer;
use async_trait::async_trait;
use drydock_protocol::Platform;
use drydock_transport::{ByteStream, ssh::SshConfig};
use sha2::{Digest, Sha256};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    net::{UnixListener, UnixStream},
    task::JoinHandle,
};

pub struct Gateway {
    agent_socket: PathBuf,
    executable: PathBuf,
    fingerprint: String,
    platform: Platform,
    dials: AtomicUsize,
    agent: Mutex<Option<JoinHandle<()>>>,
    /// Bumped when the agent dies, cutting every connection it served.
    cut: tokio::sync::watch::Sender<u64>,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Gateway {
    /// Serve an agent whose fingerprint is `build`'s, with its socket in `directory`.
    pub fn start(directory: &Path, build: &[u8]) -> io::Result<Arc<Self>> {
        Self::start_as(directory, build, Platform::current())
    }

    /// As [`Gateway::start`], with the agent reporting `platform`: the vessel
    /// stands in for a guest of the platform it was prepared for, whatever
    /// host the test runs on.
    pub fn start_as(directory: &Path, build: &[u8], platform: Platform) -> io::Result<Arc<Self>> {
        let gateway = Arc::new(Self {
            agent_socket: directory.join("agent.sock"),
            executable: directory.join("drydock-agent"),
            fingerprint: format!("{:x}", Sha256::digest(build)),
            platform,
            dials: AtomicUsize::new(0),
            agent: Mutex::default(),
            cut: tokio::sync::watch::channel(0).0,
        });
        gateway.restart()?;
        Ok(gateway)
    }

    /// The agent dies, closing every connection; its socket refuses new ones.
    pub fn stop(&self) {
        if let Some(agent) = self.agent.lock().unwrap().take() {
            agent.abort();
        }
        self.cut.send_modify(|generation| *generation += 1);
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
        let agent =
            drydock_agent::Agent::new(listener, self.fingerprint.clone(), self.executable.clone()).with_platform(self.platform.clone());
        *self.agent.lock().unwrap() = Some(tokio::spawn(async move {
            let _ = agent.run().await;
        }));
        Ok(())
    }

    /// How many times a client dialled, refused dials included.
    pub fn dials(&self) -> usize {
        self.dials.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl SshDialer for Gateway {
    async fn dial(&self, _: SshConfig) -> io::Result<ByteStream> {
        self.dials.fetch_add(1, Ordering::Relaxed);
        // The connection runs through a pair this gateway can cut, as a dying
        // agent process closes its end of every connection.
        let agent = UnixStream::connect(&self.agent_socket).await?;
        let (near, far) = UnixStream::pair()?;
        let mut cut = self.cut.subscribe();
        tokio::spawn(async move {
            let (mut far, mut agent) = (far, agent);
            tokio::select! {
                _ = tokio::io::copy_bidirectional(&mut far, &mut agent) => {}
                _ = cut.changed() => {}
            }
        });
        Ok(Box::new(near))
    }
}

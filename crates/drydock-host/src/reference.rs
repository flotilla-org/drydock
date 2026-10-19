//! In-memory conformance module. Relay echoes; exec supports cat/echo without a subprocess.
use crate::{EventSink, module::*};
use async_trait::async_trait;
use drydock_protocol::*;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::AsyncWriteExt;
pub fn registry() -> Registry {
    BTreeMap::from([(
        "reference".into(),
        Arc::new(ReferenceModule) as Arc<dyn Module>,
    )])
}
pub struct ReferenceModule;
#[async_trait]
impl Module for ReferenceModule {
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    async fn configure(
        &self,
        c: &ProviderConfiguration,
        _events: EventSink,
        _http: Arc<dyn HttpClient>,
    ) -> Result<Arc<dyn Provider>> {
        let settings: ReferenceSettings =
            serde_json::from_value(serde_json::to_value(&c.settings).expect("settings map"))
                .map_err(|_| refused("invalid reference settings"))?;
        if settings.poll_interval_ms == 0 {
            return Err(refused("poll interval must be positive"));
        }
        Ok(Arc::new(Reference {
            name: c.name.clone(),
            state: Mutex::new(Memory::default()),
            settings,
        }))
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceSettings {
    #[serde(default)]
    fault: Option<ProtocolError>,
    #[serde(default = "default_poll_interval")]
    poll_interval_ms: u64,
}
fn default_poll_interval() -> u64 {
    10
}
struct Reference {
    name: String,
    state: Mutex<Memory>,
    settings: ReferenceSettings,
}
#[derive(Default)]
struct Memory {
    prepared: BTreeMap<(String, String), Prepared>,
    sandboxes: BTreeMap<String, Sandbox>,
    tokens: BTreeMap<String, ResumeToken>,
    next: u64,
}

impl Reference {
    fn find(&self, id: &str) -> Result<Sandbox> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sandboxes
            .get(id)
            .cloned()
            .ok_or_else(|| refused("unknown environment"))
    }
    fn check(&self) -> Result<()> {
        if let Some(e) = &self.settings.fault {
            Err(e.clone())
        } else {
            Ok(())
        }
    }
}
#[async_trait]
impl Provider for Reference {
    fn observation(&self) -> ObservationMode {
        ObservationMode::Poll {
            interval: Duration::from_millis(self.settings.poll_interval_ms),
        }
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            material_modes: vec![
                MaterialMode::Frozen,
                MaterialMode::Pushed,
                MaterialMode::Shared,
            ],
            checkout_strategies: vec![
                CheckoutStrategy::HostWorktree,
                CheckoutStrategy::HostClone,
                CheckoutStrategy::CloneInVessel,
            ],
            workspace_root: "/workspace".into(),
            suspend_resume: true,
            export: true,
            egress: EgressCapability {
                routes: vec![EgressRoute::None, EgressRoute::Open],
                enforcement: Enforcement::Advisory,
            },
            fallback_runner: true,
            bootstrap: BootstrapRoute::Bake,
            usage: true,
            quota: true,
        }
    }
    async fn prepare(&self, r: PrepareRequest, _: &Credentials) -> Result<Prepared> {
        self.check()?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let n = state.prepared.len() + 1;
        Ok(state
            .prepared
            .entry((r.image_digest.clone(), r.tools_digest.clone()))
            .or_insert_with(|| Prepared {
                provider: self.name.clone(),
                id: format!("prepared-{n}"),
                image_digest: r.image_digest,
                tools_digest: r.tools_digest,
            })
            .clone())
    }
    async fn provision(&self, r: ProvisionRequest, _: &Credentials) -> Result<Provisioned> {
        self.check()?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(s) = state
            .sandboxes
            .values()
            .find(|s| s.label.as_deref() == Some(&r.label))
        {
            return Ok(Provisioned::Existing(s.clone()));
        }
        if !state.prepared.values().any(|p| p == &r.prepared) {
            return Err(refused("unknown prepared form"));
        }
        if matches!(&r.egress,EgressRequest::DenyAll {direct} if !direct.is_empty()) {
            return Err(refused("reference cannot implement direct destinations"));
        }
        state.next += 1;
        let s = Sandbox {
            id: format!("sandbox-{}", state.next),
            label: Some(r.label),
            provider: self.name.clone(),
            state: Observation::Running,
            granted_size: Some(r.size.clone()),
            egress: Enforcement::Advisory,
        };
        state.sandboxes.insert(s.id.clone(), s.clone());
        Ok(Provisioned::Created(s))
    }
    async fn list(&self, _: &Credentials) -> Result<Vec<ObservedSandbox>> {
        self.check()?;
        Ok(self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sandboxes
            .values()
            .cloned()
            .map(Into::into)
            .collect())
    }
    async fn inspect(&self, id: &str, _: &Credentials) -> Result<ObservedSandbox> {
        self.check()?;
        Ok(self.find(id)?.into())
    }
    async fn destroy(&self, id: &str, _: &Credentials) -> Result<()> {
        self.check()?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.sandboxes.remove(id);
        state.tokens.remove(id);
        Ok(())
    }
    async fn reach(&self, id: &str, _: &Credentials) -> Result<Connection> {
        self.check()?;
        self.find(id)?;
        Ok(Connection::Relay)
    }
    async fn relay(&self, id: &str, _: &Credentials) -> Result<ByteStream> {
        self.check()?;
        self.find(id)?;
        let (client, mut server) = tokio::io::duplex(65536);
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(&mut server);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        Ok(Box::new(client))
    }
    async fn exec(&self, id: &str, r: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        if r.command == ["cat"] {
            return self.relay(id, c).await;
        }
        self.check()?;
        self.find(id)?;
        if r.command.first().map(String::as_str) != Some("echo") {
            return Err(refused("reference exec supports cat and echo"));
        }
        let bytes = format!("{}\n", r.command[1..].join(" ")).into_bytes();
        let (client, mut server) = tokio::io::duplex(65536);
        tokio::spawn(async move {
            let _ = server.write_all(&bytes).await;
            let _ = server.shutdown().await;
        });
        Ok(Box::new(client))
    }
    async fn suspend(&self, id: &str, _: &Credentials) -> Result<ResumeToken> {
        self.check()?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut s = state
            .sandboxes
            .get(id)
            .cloned()
            .ok_or_else(|| refused("unknown environment"))?;
        if matches!(s.state, Observation::Stopped { .. }) {
            return state
                .tokens
                .get(id)
                .cloned()
                .ok_or_else(|| refused("missing resume token"));
        }
        s.state = Observation::Stopped {
            cause: StopCause::SuspendedByRequest,
        };
        let token = ResumeToken {
            token: Secret::new(format!("{}:{id}", self.name)),
        };
        state.tokens.insert(id.into(), token.clone());
        state.sandboxes.insert(id.into(), s);
        Ok(token)
    }
    async fn resume(&self, id: &str, token: ResumeToken, _: &Credentials) -> Result<()> {
        self.check()?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.tokens.get(id) != Some(&token) {
            return Err(refused(
                "invalid resume token for this provider/environment",
            ));
        }
        state
            .sandboxes
            .get_mut(id)
            .ok_or_else(|| refused("unknown environment"))?
            .state = Observation::Running;
        Ok(())
    }
    async fn export(&self, id: &str, _: &Credentials) -> Result<Export> {
        self.check()?;
        self.find(id)?;
        Ok(Export {
            reference: format!("memory://{}/{id}", self.name),
        })
    }
    async fn usage(&self, period: Period, _: &Credentials) -> Result<Usage> {
        self.check()?;
        Ok(Usage {
            period,
            sandbox_hours: vec![],
        })
    }
    async fn quota(&self, _: &Credentials) -> Result<Quota> {
        self.check()?;
        Ok(Quota {
            credits_remaining: None,
            credit_unit: None,
            concurrency_in_use: Some(
                self.state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .sandboxes
                    .values()
                    .filter(|s| matches!(s.state, Observation::Running))
                    .count() as u64,
            ),
            concurrency_limit: None,
        })
    }
}

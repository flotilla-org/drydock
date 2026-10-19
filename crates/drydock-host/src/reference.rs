//! In-memory conformance module. Relay echoes; exec supports cat/echo without a subprocess.
use crate::{EventSink, module::*};
use async_trait::async_trait;
use drydock_protocol::*;
use std::{collections::BTreeMap, sync::Arc};
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
        events: EventSink,
    ) -> Result<Box<dyn Provider>> {
        let fault = c
            .settings
            .get("fault")
            .map(|v| {
                serde_json::from_value::<ProtocolError>(v.clone())
                    .map_err(|_| refused("invalid reference fault"))
            })
            .transpose()?;
        Ok(Box::new(Reference {
            name: c.name.clone(),
            events,
            prepared: BTreeMap::new(),
            sandboxes: BTreeMap::new(),
            tokens: BTreeMap::new(),
            next: 0,
            fault,
        }))
    }
}
struct Reference {
    name: String,
    events: EventSink,
    prepared: BTreeMap<(String, String), Prepared>,
    sandboxes: BTreeMap<String, Sandbox>,
    tokens: BTreeMap<String, ResumeToken>,
    next: u64,
    fault: Option<ProtocolError>,
}
impl Reference {
    fn find(&self, id: &str) -> Result<Sandbox> {
        self.sandboxes
            .get(id)
            .cloned()
            .ok_or_else(|| refused("unknown environment"))
    }
    fn emit(&self, s: &Sandbox, event: EventKind) {
        self.events.publish(
            s.id.clone(),
            s.label.clone(),
            chrono::Utc::now().to_rfc3339(),
            TimestampSource::Adaptor,
            event,
        );
    }
    fn check(&self) -> Result<()> {
        if let Some(e) = &self.fault {
            Err(e.clone())
        } else {
            Ok(())
        }
    }
}
#[async_trait]
impl Provider for Reference {
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
    async fn prepare(&mut self, r: PrepareRequest, _: &Credentials) -> Result<Prepared> {
        self.check()?;
        let n = self.prepared.len() + 1;
        Ok(self
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
    async fn provision(&mut self, r: ProvisionRequest, _: &Credentials) -> Result<(Sandbox, bool)> {
        self.check()?;
        if let Some(s) = self
            .sandboxes
            .values()
            .find(|s| s.label.as_deref() == Some(&r.label))
        {
            return Ok((s.clone(), false));
        }
        if !self.prepared.values().any(|p| p == &r.prepared) {
            return Err(refused("unknown prepared form"));
        }
        if matches!(&r.egress,EgressRequest::DenyAll {direct} if !direct.is_empty()) {
            return Err(refused("reference cannot implement direct destinations"));
        }
        self.next += 1;
        let s = Sandbox {
            id: format!("sandbox-{}", self.next),
            label: Some(r.label),
            provider: self.name.clone(),
            state: Observation::Running,
            granted_size: Some(r.size.clone()),
            egress: Enforcement::Advisory,
        };
        self.sandboxes.insert(s.id.clone(), s.clone());
        self.emit(&s, EventKind::Created);
        self.emit(
            &s,
            EventKind::Running {
                granted_size: r.size,
            },
        );
        Ok((s, true))
    }
    async fn list(&mut self, _: &Credentials) -> Result<Vec<Sandbox>> {
        self.check()?;
        Ok(self.sandboxes.values().cloned().collect())
    }
    async fn inspect(&mut self, id: &str, _: &Credentials) -> Result<Sandbox> {
        self.check()?;
        self.find(id)
    }
    async fn destroy(&mut self, id: &str, _: &Credentials) -> Result<()> {
        self.check()?;
        if let Some(s) = self.sandboxes.remove(id) {
            self.tokens.remove(id);
            self.emit(
                &s,
                EventKind::Gone {
                    cause: GoneCause::DestroyedByRequest,
                },
            );
        }
        Ok(())
    }
    async fn reach(&mut self, id: &str, _: &Credentials) -> Result<Reach> {
        self.check()?;
        self.find(id)?;
        let mut url = reqwest::Url::parse("http://localhost").expect("static URL");
        url.path_segments_mut().expect("base URL").extend([
            "v1",
            "providers",
            &self.name,
            "environments",
            id,
            "relay",
        ]);
        Ok(Reach::Relay {
            path: url.path().into(),
        })
    }
    async fn relay(&mut self, id: &str, _: &Credentials) -> Result<ByteStream> {
        self.check()?;
        self.find(id)?;
        let (client, mut server) = tokio::io::duplex(65536);
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(&mut server);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        Ok(Box::new(client))
    }
    async fn exec(&mut self, id: &str, r: ExecRequest, c: &Credentials) -> Result<ByteStream> {
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
    async fn suspend(&mut self, id: &str, _: &Credentials) -> Result<ResumeToken> {
        self.check()?;
        let mut s = self.find(id)?;
        if matches!(s.state, Observation::Stopped { .. }) {
            return Ok(self.tokens[id].clone());
        }
        s.state = Observation::Stopped {
            cause: StopCause::SuspendedByRequest,
        };
        let token = ResumeToken {
            token: Secret::new(format!("{}:{id}", self.name)),
        };
        self.tokens.insert(id.into(), token.clone());
        self.sandboxes.insert(id.into(), s.clone());
        self.emit(
            &s,
            EventKind::Stopped {
                cause: StopCause::SuspendedByRequest,
            },
        );
        Ok(token)
    }
    async fn resume(&mut self, id: &str, token: ResumeToken, _: &Credentials) -> Result<()> {
        self.check()?;
        let mut s = self.find(id)?;
        if self.tokens.get(id) != Some(&token) {
            return Err(refused(
                "invalid resume token for this provider/environment",
            ));
        }
        if !matches!(s.state, Observation::Running) {
            s.state = Observation::Running;
            self.sandboxes.insert(id.into(), s.clone());
            self.emit(&s, EventKind::Resumed);
        }
        Ok(())
    }
    async fn export(&mut self, id: &str, _: &Credentials) -> Result<Export> {
        self.check()?;
        self.find(id)?;
        Ok(Export {
            reference: format!("memory://{}/{id}", self.name),
        })
    }
    async fn usage(&mut self, period: Period, _: &Credentials) -> Result<Usage> {
        self.check()?;
        Ok(Usage {
            period,
            sandbox_hours: vec![],
        })
    }
    async fn quota(&mut self, _: &Credentials) -> Result<Quota> {
        self.check()?;
        Ok(Quota {
            credits_remaining: None,
            credit_unit: None,
            concurrency_in_use: Some(
                self.sandboxes
                    .values()
                    .filter(|s| matches!(s.state, Observation::Running))
                    .count() as u64,
            ),
            concurrency_limit: None,
        })
    }
}

//! In-memory conformance module. Relay echoes; exec supports cat/echo without a subprocess.
use crate::{RecoverLock, module::*};
use async_trait::async_trait;
use drydock_protocol::*;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::AsyncWriteExt;
pub fn registry() -> Registry {
    BTreeMap::from([("reference".into(), Arc::new(ReferenceModule) as Arc<dyn Module>)])
}
pub struct ReferenceModule;
#[async_trait]
impl Module for ReferenceModule {
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    async fn configure(&self, c: &ProviderConfiguration, _http: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
        let settings: ReferenceSettings = serde_json::from_value(serde_json::to_value(&c.settings).expect("settings map"))
            .map_err(|_| refused("invalid reference settings"))?;
        Ok(Arc::new(Reference { name: c.name.clone(), state: Mutex::new(Memory::default()), settings }))
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceSettings {
    #[serde(default)]
    fault: Option<ProtocolError>,
    #[serde(default)]
    fixture: bool,
    #[serde(default)]
    fixture_push: bool,
    #[serde(default)]
    fixture_bad_relay: bool,
    #[serde(default)]
    reach: Option<Reach>,
    #[serde(default)]
    rate_limits: Vec<RateLimit>,
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
    environments: BTreeMap<String, Environment>,
    tokens: BTreeMap<String, ResumeToken>,
    next: u64,
    provider_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    inventory_error: bool,
    running_since: BTreeMap<String, chrono::DateTime<chrono::Utc>>,
    usage: Vec<(Size, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
}

impl Memory {
    fn stop_billing(&mut self, id: &str) {
        if let Some(start) = self.running_since.remove(id)
            && let Some(size) = self.environments.get(id).and_then(|row| row.granted_size.clone())
        {
            self.usage.push((size, start, chrono::Utc::now()));
        }
    }
}
impl Reference {
    fn find(&self, id: &str) -> Result<Environment> {
        self.state.recover().environments.get(id).cloned().ok_or_else(|| ProtocolError::NotFound { reason: "unknown environment".into() })
    }
    fn check(&self) -> Result<()> {
        if let Some(e) = &self.settings.fault { Err(e.clone()) } else { Ok(()) }
    }
}
#[async_trait]
impl Provider for Reference {
    fn rate_limits(&self) -> Vec<RateLimit> {
        self.settings.rate_limits.clone()
    }
    fn observation(&self) -> ObservationMode {
        if self.settings.fixture && self.settings.fixture_push {
            return ObservationMode::Push;
        }
        ObservationMode::Poll { interval: Duration::from_millis(self.settings.poll_interval_ms) }
    }
    fn operations(&self) -> Operations<'_> {
        Operations { exec: Some(self), suspend_resume: Some(self), export: Some(self), usage: Some(self), quota: Some(self) }
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            material_modes: vec![MaterialMode::Frozen, MaterialMode::Pushed, MaterialMode::Shared],
            checkout_strategies: vec![CheckoutStrategy::HostWorktree, CheckoutStrategy::HostClone, CheckoutStrategy::CloneInVessel],
            workspace_root: "/workspace".into(),
            suspend_resume: true,
            suspend_preserves_memory: Some(true),
            export: true,
            egress: EgressCapability { routes: vec![EgressRoute::None, EgressRoute::Open], enforcement: Enforcement::Advisory },
            fallback_runner: true,
            bootstrap: BootstrapRoute::Bake,
            usage: true,
            quota: true,
        }
    }
    async fn prepare(&self, r: PrepareRequest, _: &Credentials) -> Result<Prepared> {
        self.check()?;
        let mut state = self.state.recover();
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
        let mut state = self.state.recover();
        if let Some(s) = state.environments.values().find(|s| s.label.as_deref() == Some(&r.label)) {
            return Ok(Provisioned::Existing(s.clone().into()));
        }
        if !state.prepared.values().any(|p| p == &r.prepared) {
            return Err(refused("unknown prepared form"));
        }
        if matches!(&r.egress,EgressRequest::DenyAll {direct} if !direct.is_empty()) {
            return Err(refused("reference cannot implement direct destinations"));
        }
        state.next += 1;
        let s = Environment {
            id: format!("environment-{}", state.next),
            label: Some(r.label),
            provider: self.name.clone(),
            state: Observation::Running,
            granted_size: Some(r.size.clone()),
            egress: Enforcement::Advisory,
        };
        state.running_since.insert(s.id.clone(), chrono::Utc::now());
        state.environments.insert(s.id.clone(), s.clone());
        Ok(Provisioned::Created(s.into()))
    }
    async fn list(&self, _: &Credentials) -> Result<Vec<ObservedEnvironment>> {
        self.check()?;
        let state = self.state.recover();
        if state.inventory_error {
            return Err(ProtocolError::unavailable("fixture inventory unavailable", None));
        }
        Ok(state
            .environments
            .values()
            .cloned()
            .map(|environment| ObservedEnvironment {
                egress_policy: None,
                egress_measured: true,
                environment,
                timestamp: state.provider_timestamp,
            })
            .collect())
    }
    async fn inspect(&self, id: &str, _: &Credentials) -> Result<ObservedEnvironment> {
        self.check()?;
        let environment = self.find(id)?;
        let timestamp = self.state.recover().provider_timestamp;
        Ok(ObservedEnvironment { egress_policy: None, egress_measured: true, environment, timestamp })
    }
    async fn destroy(&self, id: &str, _: &Credentials) -> Result<()> {
        self.check()?;
        let mut state = self.state.recover();
        state.stop_billing(id);
        state.environments.remove(id);
        state.tokens.remove(id);
        Ok(())
    }
    async fn reach(&self, id: &str, _: &Credentials) -> Result<Connection> {
        self.check()?;
        self.find(id)?;
        Ok(match &self.settings.reach {
            Some(Reach::Ssh { endpoint, user, host_key }) => {
                Connection::Ssh { endpoint: endpoint.clone(), user: user.clone(), host_key: host_key.clone() }
            }
            Some(Reach::Dial { url, token, expires_at }) => {
                Connection::Dial { url: url.clone(), token: token.clone(), expires_at: expires_at.clone() }
            }
            _ => Connection::Relay,
        })
    }
    async fn relay(&self, id: &str, _: &Credentials) -> Result<ByteStream> {
        self.check()?;
        self.find(id)?;
        let (client, mut server) = tokio::io::duplex(65536);
        let corrupt = self.settings.fixture && self.settings.fixture_bad_relay;
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut r, mut w) = tokio::io::split(&mut server);
            let mut bytes = [0; 4096];
            while let Ok(count) = r.read(&mut bytes).await {
                if count == 0 {
                    break;
                }
                if corrupt {
                    bytes[0] ^= 1;
                }
                if w.write_all(&bytes[..count]).await.is_err() {
                    break;
                }
            }
        });
        Ok(Box::new(client))
    }
}

#[async_trait::async_trait]
impl Exec for Reference {
    async fn exec(&self, id: &str, r: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        if self.settings.fixture && r.command.first().map(String::as_str) == Some("drydock-fixture") {
            self.find(id)?;
            let mut state = self.state.recover();
            let action = r.command.get(1).map(String::as_str).unwrap_or("");
            let target = r.command.get(2).map(String::as_str).unwrap_or(id);
            let value = match action {
                "null_environment" => {
                    let row = Environment {
                        id: format!("null-{id}"),
                        label: None,
                        provider: self.name.clone(),
                        state: Observation::Unknown { reason: UnknownReason::ProviderApiError },
                        granted_size: None,
                        egress: Enforcement::Advisory,
                    };
                    state.environments.insert(row.id.clone(), row.clone());
                    serde_json::to_value(row).expect("environment")
                }
                "forget" => {
                    state.stop_billing(target);
                    state.environments.remove(target);
                    serde_json::Value::Null
                }
                "timestamp" => {
                    state.provider_timestamp =
                        if target.is_empty() { None } else { Some(target.parse().map_err(|_| refused("invalid timestamp"))?) };
                    serde_json::Value::Null
                }
                "inventory_error" => {
                    state.inventory_error = target == "true";
                    serde_json::Value::Null
                }
                "state" => {
                    let observation: Observation = serde_json::from_str(r.command.get(3).ok_or_else(|| refused("missing fixture state"))?)
                        .map_err(|_| refused("invalid fixture state"))?;
                    state.stop_billing(target);
                    if matches!(observation, Observation::Running) {
                        state.running_since.insert(target.into(), chrono::Utc::now());
                    }
                    state.environments.get_mut(target).ok_or_else(|| refused("unknown fixture target"))?.state = observation;
                    serde_json::Value::Null
                }
                "pause" => {
                    state.stop_billing(target);
                    state.environments.get_mut(target).ok_or_else(|| refused("unknown fixture target"))?.state =
                        Observation::Stopped { cause: StopCause::PausedByProvider };
                    serde_json::Value::Null
                }
                _ => return Err(refused("unknown fixture action")),
            };
            let bytes = serde_json::to_vec(&value).expect("fixture value");
            let (client, mut server) = tokio::io::duplex(65536);
            tokio::spawn(async move {
                let _ = server.write_all(&bytes).await;
            });
            return Ok(Box::new(client));
        }
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
}

#[async_trait::async_trait]
impl SuspendResume for Reference {
    async fn suspend(&self, id: &str, _: &Credentials) -> Result<ResumeToken> {
        self.check()?;
        let mut state = self.state.recover();
        let mut s = state.environments.get(id).cloned().ok_or_else(|| ProtocolError::NotFound { reason: "unknown environment".into() })?;
        if matches!(s.state, Observation::Stopped { .. }) {
            return state.tokens.get(id).cloned().ok_or_else(|| refused("missing resume token"));
        }
        state.stop_billing(id);
        s.state = Observation::Stopped { cause: StopCause::SuspendedByRequest };
        let token = ResumeToken { token: Secret::new(format!("{}:{id}", self.name)) };
        state.tokens.insert(id.into(), token.clone());
        state.environments.insert(id.into(), s);
        Ok(token)
    }
    async fn resume(&self, id: &str, token: ResumeToken, _: &Credentials) -> Result<()> {
        self.check()?;
        let mut state = self.state.recover();
        if !state.environments.contains_key(id) {
            return Err(ProtocolError::NotFound { reason: "unknown environment".into() });
        }
        if state.tokens.get(id) != Some(&token) {
            return Err(refused("invalid resume token for this provider/environment"));
        }
        state.running_since.entry(id.into()).or_insert_with(chrono::Utc::now);
        state.environments.get_mut(id).ok_or_else(|| ProtocolError::NotFound { reason: "unknown environment".into() })?.state =
            Observation::Running;
        Ok(())
    }
}

#[async_trait::async_trait]
impl ExportOperation for Reference {
    async fn export(&self, id: &str, _: &Credentials) -> Result<Export> {
        self.check()?;
        self.find(id)?;
        Ok(Export { reference: format!("memory://{}/{id}", self.name) })
    }
}

#[async_trait::async_trait]
impl UsageOperation for Reference {
    async fn usage(&self, period: Period, _: &Credentials) -> Result<Usage> {
        self.check()?;
        let state = self.state.recover();
        let now = chrono::Utc::now();
        let mut segments = state.usage.clone();
        for (id, start) in &state.running_since {
            if let Some(size) = state.environments.get(id).and_then(|row| row.granted_size.clone()) {
                segments.push((size, *start, now));
            }
        }
        let mut environment_hours: Vec<SizeUsage> = vec![];
        for (size, start, end) in segments {
            let start = start.max(period.start().instant());
            let end = end.min(period.end().instant());
            if end > start {
                let hours = (end - start).num_microseconds().unwrap_or(i64::MAX) as f64 / 3_600_000_000.0;
                if let Some(row) = environment_hours.iter_mut().find(|row| row.size == size) {
                    row.hours += hours;
                } else {
                    environment_hours.push(SizeUsage { size, hours });
                }
            }
        }
        Ok(Usage { period, environment_hours, measurements: None })
    }
}

#[async_trait::async_trait]
impl QuotaOperation for Reference {
    async fn quota(&self, _: &Credentials) -> Result<Quota> {
        self.check()?;
        Ok(Quota {
            resources: vec![],
            credits_remaining: None,
            credit_unit: None,
            concurrency_in_use: Some(
                self.state.recover().environments.values().filter(|s| matches!(s.state, Observation::Running)).count() as u64,
            ),
            concurrency_limit: None,
        })
    }
}

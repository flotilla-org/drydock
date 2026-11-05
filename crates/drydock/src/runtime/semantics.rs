//! What drydockd adds to a module's operations, in one place: waiting for a
//! state, idempotent lifecycle calls, adoption by label and the ownership of
//! a shared account. A module declares what its vendor already guarantees
//! ([`Semantics`]); an instance's [`SemanticOptions`] and [`Ownership`] ask
//! for the rest. A module that declares the default gets nothing added.
use super::*;
use module::{ByteStream, Operations, Provisioned, SuspendResume};
use std::time::Duration;
use tokio::time::Instant;

/// `provider`, with what `config` asks for and its module does not declare.
pub(super) fn apply(name: &str, config: &ProviderConfiguration, provider: Arc<dyn Provider>) -> Result<Arc<dyn Provider>> {
    let declared = provider.capabilities().semantics;
    let shared = config.ownership == Ownership::SharedAccount;
    if !shared && !declared.reports_tags {
        return Err(refused("an owned account needs a module that leaves ownership to drydockd; this one checks its own"));
    }
    let o = &config.semantics;
    if o.poll_millis == 0 {
        return Err(refused("semantics.poll_millis must be positive"));
    }
    let added = Added {
        owner: (shared && declared.reports_tags).then(|| name.to_owned()),
        settle: o.settle && !declared.settles,
        idempotent: o.idempotent && !declared.idempotent,
        adopt: o.adopt_label && !declared.adopts_label,
        token_is_id: !declared.resume_token,
        wait: Duration::from_secs(o.wait_seconds),
        prepare_wait: Duration::from_secs(o.prepare_wait_seconds),
        poll: Duration::from_millis(o.poll_millis),
        labels: Mutex::default(),
        provisions: Mutex::default(),
        inner: provider,
    };
    if added.owner.is_none() && !added.settle && !added.idempotent && !added.adopt {
        return Ok(added.inner);
    }
    Ok(Arc::new(added))
}

struct Added {
    inner: Arc<dyn Provider>,
    /// The instance whose tag marks what it may list and destroy, on a shared account.
    owner: Option<String>,
    settle: bool,
    idempotent: bool,
    adopt: bool,
    /// The module's resume ignores its token, which is the environment id.
    token_is_id: bool,
    wait: Duration,
    prepare_wait: Duration,
    poll: Duration,
    /// The environment each label names, as this drydockd made or adopted
    /// it: a vendor's list can lag a creation by seconds.
    labels: Mutex<BTreeMap<String, String>>,
    /// One provision of a label at a time.
    provisions: Mutex<BTreeMap<String, std::sync::Weak<AsyncMutex<()>>>>,
}

fn described(e: &Environment) -> String {
    let state = serde_json::to_string(&e.state).unwrap_or_default();
    match &e.vendor {
        Some(v) => format!("{state} (the vendor says {:?})", v.state),
        None => state,
    }
}

impl Added {
    /// The live environment `label` names: the one this drydockd knows, else
    /// the first the list shows.
    async fn named(&self, label: &str, c: &Credentials) -> Result<Option<Environment>> {
        let known = self.labels.recover().get(label).cloned();
        if let Some(id) = known {
            match self.inner.inspect(&id, c).await {
                Ok(e) if e.live() => return Ok(Some(e)),
                Ok(_) | Err(ProtocolError::NotFound { .. }) => drop(self.labels.recover().remove(label)),
                Err(error) => return Err(error),
            }
        }
        Ok(self.list(c).await?.into_iter().find(|e| e.live() && e.label.as_deref() == Some(label)))
    }
    fn ours(&self, e: &Environment) -> bool {
        self.owner.as_ref().is_none_or(|owner| e.vendor.as_ref().and_then(|v| v.tags.get(OWNER_TAG)) == Some(owner))
    }
    /// Reads the environment until `done` holds. A wait ends early when it
    /// is gone or its state is unknown, and as unavailable at the deadline.
    async fn until(&self, id: &str, what: &str, done: fn(&Observation) -> bool, c: &Credentials) -> Result<Environment> {
        let deadline = Instant::now() + self.wait;
        loop {
            let e = self.inner.inspect(id, c).await?;
            if done(&e.state) {
                return Ok(e);
            }
            if matches!(e.state, Observation::Gone { .. } | Observation::Unknown { .. }) {
                return Err(refused(format!("environment {id} is {} while waiting for it to be {what}", described(&e))));
            }
            if Instant::now() + self.poll > deadline {
                let reason = format!("environment {id} is still {} after {}s waiting to be {what}", described(&e), self.wait.as_secs());
                return Err(ProtocolError::unavailable(reason, Some(self.poll.as_secs().max(1))));
            }
            tokio::time::sleep(self.poll).await;
        }
    }
    async fn running(&self, id: &str, c: &Credentials) -> Result<Environment> {
        self.until(id, "running", |s| matches!(s, Observation::Running), c).await
    }
}

#[async_trait::async_trait]
impl Provider for Added {
    fn operations(&self) -> Operations<'_> {
        let mut ops = self.inner.operations();
        if ops.suspend_resume.is_some() {
            ops.suspend_resume = Some(self);
        }
        ops
    }
    /// With adoption, drydockd makes one environment per label for the
    /// provisions it serves, and declares so.
    fn capabilities(&self) -> Capabilities {
        let capabilities = self.inner.capabilities();
        Capabilities { exclusive_label: capabilities.exclusive_label || self.adopt, ..capabilities }
    }
    fn observation(&self) -> ObservationMode {
        self.inner.observation()
    }
    fn readiness(&self, c: &Credentials) -> Readiness {
        self.inner.readiness(c)
    }
    async fn refresh_readiness(&self, c: &Credentials) {
        self.inner.refresh_readiness(c).await
    }
    fn rate_limits(&self) -> Vec<RateLimit> {
        self.inner.rate_limits()
    }
    /// Asks again while the module answers unavailable: the form is still
    /// being built.
    async fn prepare(&self, r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
        let deadline = Instant::now() + self.prepare_wait;
        loop {
            match self.inner.prepare(r.clone(), c).await {
                Err(ProtocolError::Unavailable { retry_after, .. }) if self.settle && Instant::now() + self.poll < deadline => {
                    tokio::time::sleep(self.poll.max(Duration::from_secs(retry_after.unwrap_or(0)))).await
                }
                result => return result,
            }
        }
    }
    /// With adoption, one provision of a label at a time, so concurrent
    /// provisions through this drydockd return one environment.
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        let lock = self.adopt.then(|| {
            let mut locks = self.provisions.recover();
            locks.retain(|_, lock| lock.strong_count() > 0);
            let lock = locks.get(&r.label).and_then(std::sync::Weak::upgrade).unwrap_or_default();
            locks.insert(r.label.clone(), Arc::downgrade(&lock));
            lock
        });
        let _one = match &lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        if self.adopt
            && let Some(e) = self.named(&r.label, c).await?
        {
            self.labels.recover().insert(r.label.clone(), e.id.clone());
            // An adopted environment is returned as it is, unless it is on its
            // way to running: provision never resumes a stopped one.
            let starting = matches!(e.state, Observation::Transitioning { phase: TransitionPhase::Preparing | TransitionPhase::Starting });
            return Ok(Provisioned::Existing(if self.settle && starting { self.running(&e.id, c).await? } else { e }));
        }
        let label = r.label.clone();
        let provisioned = self.inner.provision(r, c).await?;
        if self.adopt {
            let (Provisioned::Created(e) | Provisioned::Existing(e)) = &provisioned;
            self.labels.recover().insert(label, e.id.clone());
        }
        if !self.settle {
            return Ok(provisioned);
        }
        Ok(match provisioned {
            Provisioned::Created(e) => Provisioned::Created(self.running(&e.id, c).await?),
            Provisioned::Existing(e) => Provisioned::Existing(e),
        })
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        Ok(self.inner.list(c).await?.into_iter().filter(|e| self.ours(e)).collect())
    }
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        self.inner.inspect(id, c).await
    }
    /// On a shared account, refuses an environment another instance or tool
    /// made. Idempotent: absent, or already being destroyed, is destroyed;
    /// a vendor busy with another change is asked again within the wait.
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        if self.owner.is_some() {
            match self.inner.inspect(id, c).await {
                Ok(e) if !self.ours(&e) => {
                    return Err(refused(format!("environment {id} does not carry this instance's {OWNER_TAG} tag")));
                }
                Err(ProtocolError::NotFound { .. }) if self.idempotent => return Ok(()),
                _ => {}
            }
        }
        let deadline = Instant::now() + self.wait;
        loop {
            match self.inner.destroy(id, c).await {
                Err(ProtocolError::NotFound { .. }) if self.idempotent => return Ok(()),
                Err(busy @ ProtocolError::Unavailable { .. }) if self.idempotent => match self.inner.inspect(id, c).await {
                    Err(ProtocolError::NotFound { .. }) => return Ok(()),
                    Ok(e) if !e.live() => return Ok(()),
                    _ if self.settle && Instant::now() + self.poll < deadline => tokio::time::sleep(self.poll).await,
                    _ => return Err(busy),
                },
                result => return result,
            }
        }
    }
    async fn reach(&self, id: &str, c: &Credentials) -> Result<Reach> {
        self.inner.reach(id, c).await
    }
    async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream> {
        self.inner.relay(id, c).await
    }
}

#[async_trait::async_trait]
impl SuspendResume for Added {
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        let port = self.inner.operations().suspend_resume.ok_or_else(|| refused("suspend is not supported"))?;
        let skip = self.idempotent
            && self.token_is_id
            && matches!(
                self.inner.inspect(id, c).await?.state,
                Observation::Stopped { .. } | Observation::Transitioning { phase: TransitionPhase::Stopping }
            );
        let token = if skip { ResumeToken { token: Secret::new(id) } } else { port.suspend(id, c).await? };
        if self.settle {
            self.until(id, "stopped", |s| matches!(s, Observation::Stopped { .. }), c).await?;
        }
        Ok(token)
    }
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()> {
        let port = self.inner.operations().suspend_resume.ok_or_else(|| refused("resume is not supported"))?;
        let skip = self.idempotent
            && matches!(
                self.inner.inspect(id, c).await?.state,
                Observation::Running | Observation::Transitioning { phase: TransitionPhase::Starting }
            );
        if !skip {
            port.resume(id, token, c).await?;
        }
        if self.settle {
            self.running(id, c).await?;
        }
        Ok(())
    }
}

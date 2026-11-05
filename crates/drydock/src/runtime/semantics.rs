//! What drydockd adds to a module's operations, in one place: waiting for a
//! state, idempotent lifecycle calls and the ownership of a shared account. A
//! module declares what its own operations guarantee ([`Semantics`]); an
//! instance's [`SemanticOptions`] and [`Ownership`] ask for the rest.
//!
//! A wait reads what drydockd's observer already sees of the provider: it
//! asks the observer to poll once, then follows its polls. It makes no vendor
//! calls of its own.
use super::*;
use module::{ByteStream, Operations, Provisioned, SuspendResume};
use std::time::Duration;
use tokio::{sync::Notify, time::Instant};

/// The observer's view of one provider, as waits read it.
pub(super) struct Observed {
    log: Arc<Mutex<Log>>,
    provider: String,
    /// The outcome of the observer's latest poll: `None` once it committed
    /// what the vendor listed, or the error the vendor answered.
    pub(super) polls: watch::Sender<Option<ProtocolError>>,
    /// Asks the observer to poll now rather than at its next interval.
    pub(super) poll_now: Notify,
}
impl Observed {
    pub(super) fn new(log: &EventLog, provider: &str) -> Arc<Self> {
        Arc::new(Self { log: log.log.clone(), provider: provider.to_owned(), polls: watch::channel(None).0, poll_now: Notify::new() })
    }
    fn row(&self, id: &str) -> Option<Environment> {
        self.log.recover().inventories.get(&self.provider)?.iter().find(|row| row.id == id).cloned()
    }
}

/// `provider`, with what `config` asks for and its module does not declare.
pub(super) fn apply(config: &ProviderConfiguration, observed: Arc<Observed>, provider: Arc<dyn Provider>) -> Result<Arc<dyn Provider>> {
    let declared = provider.capabilities().semantics;
    let shared = config.ownership == Ownership::SharedAccount;
    if !shared && declared.owner_scoped {
        return Err(refused(format!(
            "provider {}: an owned account needs a module that leaves ownership to drydockd; this one checks its own",
            observed.provider
        )));
    }
    let o = &config.semantics;
    let added = Added {
        owner: (shared && !declared.owner_scoped).then(|| observed.provider.clone()),
        settle: o.settle && !declared.settles,
        idempotent: o.idempotent && !declared.idempotent,
        token_is_id: declared.token_is_id,
        wait: Duration::from_secs(o.wait_seconds),
        observed,
        inner: provider,
    };
    if added.owner.is_none() && !added.settle && !added.idempotent {
        return Ok(added.inner);
    }
    Ok(Arc::new(added))
}

struct Added {
    inner: Arc<dyn Provider>,
    /// The instance whose tag marks what it may list, destroy, suspend and
    /// resume, on a shared account.
    owner: Option<String>,
    settle: bool,
    idempotent: bool,
    token_is_id: bool,
    wait: Duration,
    observed: Arc<Observed>,
}

fn described(e: &Environment) -> String {
    let state = serde_json::to_string(&e.state).unwrap_or_default();
    match &e.vendor {
        Some(v) => format!("{state} (the vendor says {:?})", v.state),
        None => state,
    }
}

impl Added {
    fn ours(&self, e: &Environment) -> bool {
        self.owner.as_ref().is_none_or(|owner| e.vendor.as_ref().and_then(|v| v.tags.get(OWNER_TAG)) == Some(owner))
    }
    /// The environment once the observer sees it `what`. A wait ends early
    /// when the observer sees it gone or in an unknown state, and as
    /// unavailable at the deadline, naming the last poll's error if the
    /// observer's polls were failing.
    async fn until(&self, id: &str, what: &str, done: fn(&Observation) -> bool) -> Result<Environment> {
        let mut polls = self.observed.polls.subscribe();
        polls.mark_unchanged();
        // When the observer is mid-poll this stores a permit, so it polls
        // again straight after: the poll in flight may predate the change.
        self.observed.poll_now.notify_one();
        let deadline = Instant::now() + self.wait;
        let mut last = None;
        let mut failed = None;
        loop {
            tokio::select! {
                changed = polls.changed() => if changed.is_err() {
                    return Err(ProtocolError::unavailable("provider observation stopped", None));
                },
                _ = tokio::time::sleep_until(deadline) => {
                    let seen = last.as_ref().map_or_else(|| "not yet observed".to_owned(), |e| format!("still {}", described(e)));
                    let polling = failed.map_or_else(String::new, |e: ProtocolError| format!("; the last poll failed: {e}"));
                    return Err(ProtocolError::unavailable(
                        format!("environment {id} is {seen} after {}s waiting to be {what}{polling}", self.wait.as_secs()),
                        None,
                    ));
                },
            }
            failed = polls.borrow_and_update().clone();
            if failed.is_some() {
                continue;
            }
            if let Some(e) = self.observed.row(id) {
                if done(&e.state) {
                    return Ok(e);
                }
                if matches!(e.state, Observation::Gone { .. } | Observation::Unknown { .. }) {
                    return Err(refused(format!("environment {id} is {} while waiting for it to be {what}", described(&e))));
                }
                last = Some(e);
            }
        }
    }
    /// On a shared account, the environment as the vendor reports it, refused
    /// unless it carries this instance's tag. Fails closed: any inspect error
    /// is returned rather than acting on what cannot be verified. `None` on an
    /// owned account, where nothing is checked. The check and the operation
    /// that follows are two vendor calls, not one atomic step; drydockd does
    /// not lock through the vendor to close that gap.
    async fn guard(&self, id: &str, c: &Credentials) -> Result<Option<Environment>> {
        if self.owner.is_none() {
            return Ok(None);
        }
        let e = self.inner.inspect(id, c).await?;
        if !self.ours(&e) {
            return Err(refused(format!("environment {id} does not carry this instance's {OWNER_TAG} tag")));
        }
        Ok(Some(e))
    }
    /// The vendor's state of `id`, reusing what [`Self::guard`] read.
    async fn state(&self, id: &str, guarded: Option<Environment>, c: &Credentials) -> Result<Observation> {
        Ok(match guarded {
            Some(e) => e.state,
            None => self.inner.inspect(id, c).await?.state,
        })
    }
    async fn running(&self, id: &str) -> Result<Environment> {
        self.until(id, "running", |s| matches!(s, Observation::Running)).await
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
    /// What the operations guarantee with drydockd's additions.
    fn capabilities(&self) -> Capabilities {
        let mut capabilities = self.inner.capabilities();
        let s = &mut capabilities.semantics;
        s.settles |= self.settle;
        s.idempotent |= self.idempotent;
        s.owner_scoped |= self.owner.is_some();
        capabilities
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
    async fn prepare(&self, r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
        self.inner.prepare(r, c).await
    }
    async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
        match self.inner.provision(r, c).await? {
            Provisioned::Created(e) if self.settle => Ok(Provisioned::Created(self.running(&e.id).await?)),
            provisioned => Ok(provisioned),
        }
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        Ok(self.inner.list(c).await?.into_iter().filter(|e| self.ours(e)).collect())
    }
    // Inspect, reach and relay are not owner-checked: they change nothing at
    // the vendor, and the observer inspects whatever a client asks about. The
    // guard covers the operations that change vendor state. Reach and relay
    // do open the guest to the client; whether they take the guard too is
    // flotilla-org/drydock#276.
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        self.inner.inspect(id, c).await
    }
    /// On a shared account, refuses an environment another instance or tool
    /// made, or one the vendor cannot say is ours. Idempotent: absent, or
    /// already being destroyed, is destroyed.
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        match self.guard(id, c).await {
            Err(ProtocolError::NotFound { .. }) if self.idempotent => return Ok(()),
            guarded => guarded?,
        };
        match self.inner.destroy(id, c).await {
            Err(ProtocolError::NotFound { .. }) if self.idempotent => Ok(()),
            Err(busy @ ProtocolError::Unavailable { .. }) if self.idempotent => match self.inner.inspect(id, c).await {
                Err(ProtocolError::NotFound { .. }) => Ok(()),
                Ok(e) if !e.live() => Ok(()),
                _ => Err(busy),
            },
            result => result,
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
        let guarded = self.guard(id, c).await?;
        let skip = self.idempotent
            && self.token_is_id
            && matches!(
                self.state(id, guarded, c).await?,
                Observation::Stopped { .. } | Observation::Transitioning { phase: TransitionPhase::Stopping }
            );
        let token = if skip { ResumeToken { token: Secret::new(id) } } else { port.suspend(id, c).await? };
        if self.settle {
            self.until(id, "stopped", |s| matches!(s, Observation::Stopped { .. })).await?;
        }
        Ok(token)
    }
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()> {
        let port = self.inner.operations().suspend_resume.ok_or_else(|| refused("resume is not supported"))?;
        let guarded = self.guard(id, c).await?;
        let skip = self.idempotent
            && matches!(
                self.state(id, guarded, c).await?,
                Observation::Running | Observation::Transitioning { phase: TransitionPhase::Starting }
            );
        if !skip {
            port.resume(id, token, c).await?;
        }
        if self.settle {
            self.running(id).await?;
        }
        Ok(())
    }
}

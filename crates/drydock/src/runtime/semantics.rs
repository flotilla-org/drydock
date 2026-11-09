//! What drydockd adds to a module's operations, in one place: waiting for a
//! state, idempotent lifecycle calls and the ownership of a shared account. A
//! module declares what its own operations guarantee ([`Semantics`]); an
//! instance's [`SemanticOptions`] and [`Ownership`] ask for the rest.
//!
//! A wait reads what drydockd's observer already sees of the provider: it
//! wakes on each change to the event log. On an instance that hears of
//! changes only by listing, it asks the observer to poll once. It makes no
//! vendor calls of its own.
use super::*;
use module::{ByteStream, Exec, ExportOperation, GuestFiles, Operations, Provisioned, SuspendResume};
use std::time::Duration;
use tokio::{sync::Notify, time::Instant};

/// The observer's view of one provider, as waits read it.
pub(super) struct Observed {
    log: EventLog,
    provider: String,
    /// Whether the vendor's events reach the observer as they happen.
    pushed: bool,
    /// The outcome of the observer's latest poll: `None` once it committed
    /// what the vendor listed, or the error the vendor answered.
    pub(super) polls: watch::Sender<Option<ProtocolError>>,
    /// Asks the observer to poll now rather than at its next interval.
    pub(super) poll_now: Notify,
    /// Tells the observer this instance's provision returned an id.
    pub(super) claimed_now: Notify,
    /// What this instance provisioned and no list has shown yet: its first
    /// vendor event starts from this row, and it is this instance's own.
    pub(super) claimed: Mutex<BTreeMap<String, Environment>>,
    /// What this instance asked to suspend. Held in memory only: after a
    /// restart, a stop states only the cause the vendor gives.
    pub(super) suspended: Mutex<BTreeMap<String, Suspend>>,
    /// The credential drydockd holds for the provider, which the observer
    /// lists with.
    auth: Arc<Mutex<Authentication>>,
}
impl Observed {
    pub(super) fn new(log: &EventLog, provider: &str, pushed: bool, auth: Arc<Mutex<Authentication>>) -> Arc<Self> {
        Arc::new(Self {
            log: log.clone(),
            provider: provider.to_owned(),
            pushed,
            polls: watch::channel(None).0,
            poll_now: Notify::new(),
            claimed_now: Notify::new(),
            claimed: Mutex::default(),
            suspended: Mutex::default(),
            auth,
        })
    }
    pub(super) fn row(&self, id: &str) -> Option<Environment> {
        self.log.log.recover().inventories.get(&self.provider)?.iter().find(|row| row.id == id).cloned()
    }
    /// What the observer holds of `id`: its row, or what this instance's
    /// provision returned of it before any list showed it.
    fn held(&self, id: &str) -> Option<Environment> {
        self.row(id).or_else(|| self.claimed.recover().get(id).cloned())
    }
}

/// How far the observer has seen a suspend this instance asked for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Suspend {
    Asked,
    Stopped,
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
    // Applied even when it adds nothing: its provision tells the observer what
    // this instance made, so the environment's first delivery starts a row.
    Ok(Arc::new(added))
}

struct Added {
    inner: Arc<dyn Provider>,
    /// The instance whose tag marks what it may list and act on by id, on a
    /// shared account.
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
        self.owner.as_ref().is_none_or(|owner| e.vendor.as_ref().and_then(|v| v.tags.as_ref()?.get(OWNER_TAG)) == Some(owner))
    }
    /// The environment once the observer sees it `what`. A wait ends early
    /// when the observer sees it gone or in an unknown state, and as
    /// unavailable at the deadline, naming the last poll's error if the
    /// observer's polls were failing. It answers at once, unavailable, when
    /// the observer cannot see the provider.
    async fn until(&self, id: &str, what: &str, done: fn(&Observation) -> bool) -> Result<Environment> {
        if let Some(readiness) = self.blind() {
            return Err(ProtocolError::unavailable(
                format!(
                    "drydockd cannot confirm environment {id} is {what}: it hears of no vendor events for provider {}, and cannot list it with the credential it holds ({readiness})",
                    self.observed.provider
                ),
                None,
            ));
        }
        let mut changes = self.observed.log.changed.subscribe();
        if !self.observed.pushed {
            // When the observer is mid-poll this stores a permit, so it polls
            // again straight after: the poll in flight may predate the change.
            self.observed.poll_now.notify_one();
        }
        let deadline = Instant::now() + self.wait;
        let mut last = None;
        loop {
            if let Some(e) = self.observed.row(id) {
                if done(&e.state) {
                    return Ok(e);
                }
                if matches!(e.state, Observation::Gone { .. } | Observation::Unknown { .. }) {
                    return Err(refused(format!("environment {id} is {} while waiting for it to be {what}", described(&e))));
                }
                last = Some(e);
            }
            tokio::select! {
                changed = changes.changed() => if changed.is_err() {
                    return Err(ProtocolError::unavailable("provider observation stopped", None));
                },
                _ = tokio::time::sleep_until(deadline) => {
                    let seen = last.as_ref().map_or_else(|| "not yet observed".to_owned(), |e| format!("still {}", described(e)));
                    let failed = self.observed.polls.borrow().clone();
                    let polling = failed.map_or_else(String::new, |e: ProtocolError| format!("; the last poll failed: {e}"));
                    return Err(ProtocolError::unavailable(
                        format!("environment {id} is {seen} after {}s waiting to be {what}{polling}", self.wait.as_secs()),
                        None,
                    ));
                },
            }
        }
    }
    /// On a shared account, refuses `id` unless the observer holds it as this
    /// instance's: provisioned here, or held with this instance's tag. An id
    /// the observer holds nothing of is refused, never assumed to be ours.
    fn guard(&self, id: &str) -> Result<()> {
        if self.owner.is_none() || self.observed.claimed.recover().contains_key(id) {
            return Ok(());
        }
        match self.observed.row(id) {
            Some(e) if self.ours(&e) => Ok(()),
            Some(_) => Err(refused(format!("environment {id} does not carry this instance's {OWNER_TAG} tag"))),
            None => Err(refused(format!("environment {id} is unknown to this instance"))),
        }
    }
    /// Why the observer cannot see the provider now, when it cannot: no
    /// vendor events reach it, and it may not list with the credential
    /// drydockd holds.
    fn blind(&self) -> Option<Readiness> {
        if self.observed.pushed {
            return None;
        }
        let availability = availability(&*self.inner, &self.observed.auth.recover());
        (!availability.may_call).then_some(availability.readiness)
    }
    /// Whether the observer last saw `id` in a state `skip` accepts.
    fn already(&self, id: &str, skip: fn(&Observation) -> bool) -> bool {
        self.idempotent && self.observed.held(id).is_some_and(|e| skip(&e.state))
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
        if ops.exec.is_some() {
            ops.exec = Some(self);
        }
        if ops.files.is_some() {
            ops.files = Some(self);
        }
        if ops.export.is_some() {
            ops.export = Some(self);
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
    fn ways_in(&self) -> Vec<WayIn> {
        self.inner.ways_in()
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
            Provisioned::Created(e) => {
                self.observed.claimed.recover().insert(e.id.clone(), e.clone());
                self.observed.claimed_now.notify_one();
                Ok(Provisioned::Created(if self.settle { self.running(&e.id).await? } else { e }))
            }
            provisioned => Ok(provisioned),
        }
    }
    async fn list(&self, c: &Credentials) -> Result<Vec<Environment>> {
        Ok(self.inner.list(c).await?.into_iter().filter(|e| self.ours(e)).collect())
    }
    // Inspect is not owner-checked: it changes nothing, and the observer
    // inspects whatever a client asks about.
    async fn inspect(&self, id: &str, c: &Credentials) -> Result<Environment> {
        self.inner.inspect(id, c).await
    }
    /// Idempotent: absent at the vendor, or already being destroyed, is
    /// destroyed. An id the observer does not hold is still refused on a
    /// shared account.
    async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
        self.guard(id)?;
        match self.inner.destroy(id, c).await {
            Err(ProtocolError::NotFound { .. }) if self.idempotent => Ok(()),
            Err(busy @ ProtocolError::Unavailable { .. }) if self.idempotent => match self.inner.inspect(id, c).await {
                Err(ProtocolError::NotFound { .. }) => Ok(()),
                Ok(e) if !e.live() => Ok(()),
                // Still live, or unreadable: the vendor's busy answer is the
                // one the client can act on.
                _ => Err(busy),
            },
            result => result,
        }
    }
    async fn reach(&self, id: &str, c: &Credentials) -> Result<Reach> {
        self.guard(id)?;
        self.inner.reach(id, c).await
    }
    async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream> {
        self.guard(id)?;
        self.inner.relay(id, c).await
    }
}

#[async_trait::async_trait]
impl Exec for Added {
    async fn exec(&self, id: &str, request: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        let port = self.inner.operations().exec.ok_or_else(|| refused("exec is not supported"))?;
        self.guard(id)?;
        port.exec(id, request, c).await
    }
}

#[async_trait::async_trait]
impl GuestFiles for Added {
    async fn put(&self, id: &str, file: GuestFile, bytes: bytes::Bytes, c: &Credentials) -> Result<()> {
        let port = self.inner.operations().files.ok_or_else(|| refused("file upload is not supported"))?;
        self.guard(id)?;
        port.put(id, file, bytes, c).await
    }
}

#[async_trait::async_trait]
impl ExportOperation for Added {
    async fn export(&self, id: &str, c: &Credentials) -> Result<Export> {
        let port = self.inner.operations().export.ok_or_else(|| refused("export is not supported"))?;
        self.guard(id)?;
        port.export(id, c).await
    }
}

#[async_trait::async_trait]
impl SuspendResume for Added {
    async fn suspend(&self, id: &str, c: &Credentials) -> Result<ResumeToken> {
        let port = self.inner.operations().suspend_resume.ok_or_else(|| refused("suspend is not supported"))?;
        self.guard(id)?;
        let skip = self.token_is_id
            && self.already(id, |s| {
                matches!(s, Observation::Stopped { .. } | Observation::Transitioning { phase: TransitionPhase::Stopping })
            });
        let token = if skip {
            ResumeToken { token: Secret::new(id) }
        } else {
            // Marked before the call: the vendor's event can arrive before its answer.
            self.observed.suspended.recover().entry(id.to_owned()).or_insert(Suspend::Asked);
            port.suspend(id, c).await.inspect_err(|_| {
                let mut suspended = self.observed.suspended.recover();
                if suspended.get(id) == Some(&Suspend::Asked) {
                    suspended.remove(id);
                }
            })?
        };
        if self.settle {
            self.until(id, "stopped", |s| matches!(s, Observation::Stopped { .. })).await?;
        }
        Ok(token)
    }
    async fn resume(&self, id: &str, token: ResumeToken, c: &Credentials) -> Result<()> {
        let port = self.inner.operations().suspend_resume.ok_or_else(|| refused("resume is not supported"))?;
        self.guard(id)?;
        if !self.already(id, |s| matches!(s, Observation::Running | Observation::Transitioning { phase: TransitionPhase::Starting })) {
            port.resume(id, token, c).await?;
        }
        self.observed.suspended.recover().remove(id);
        if self.settle {
            self.running(id).await?;
        }
        Ok(())
    }
}

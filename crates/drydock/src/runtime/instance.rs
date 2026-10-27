//! One configured provider: readiness, admission, credential rejection and budgets.
use super::*;

const LONG_CALL: std::time::Duration = std::time::Duration::from_secs(600);

pub(super) struct Authentication {
    pub(super) credentials: Credentials,
    pub(super) generation: u64,
    pub(super) rejected: bool,
    pub(super) rejection_error: Option<ProtocolError>,
}
pub(super) struct Instance {
    pub(super) diagnostic_secrets: Arc<Mutex<DiagnosticSecrets>>,
    pub(super) config: ProviderConfiguration,
    pub(super) provider: Arc<dyn Provider>,
    // Synchronous metadata access only; never hold this guard across await.
    pub(super) auth: Mutex<Authentication>,
    pub(super) capabilities: Capabilities,
    pub(super) rate_limits: Vec<RateLimit>,
    pub(super) poll_waiting: Mutex<BTreeSet<String>>,
    pub(super) budget: Mutex<BTreeMap<String, VecDeque<tokio::time::Instant>>>,
    pub(super) events: EventSink,
    pub(super) observation: ObservationMode,
    pub(super) poll_interval: Option<std::time::Duration>,
    pub(super) poll_error: Mutex<Option<ProtocolError>>,
    pub(super) credential_changes: watch::Sender<Credentials>,
    pub(super) destroyed: Mutex<BTreeMap<String, DestroyState>>,
    pub(super) lifecycle_changes: watch::Sender<u64>,
    pub(super) inspected: Mutex<BTreeMap<String, ObservedEnvironment>>,
    pub(super) observation_generation: Mutex<u64>,
    pub(super) egress_measured_at: Mutex<BTreeMap<String, tokio::time::Instant>>,
    pub(super) request_timeout: std::time::Duration,
}
#[derive(Default)]
pub(super) struct DestroyState {
    pub(super) pending: usize,
    pub(super) confirmed: bool,
}
pub(super) struct DestroyAttempt {
    pub(super) instance: Arc<Instance>,
    pub(super) id: String,
    pub(super) active: bool,
}
impl DestroyAttempt {
    pub(super) fn begin(instance: Arc<Instance>, id: String) -> Self {
        instance.destroyed.recover().entry(id.clone()).or_default().pending += 1;
        Self { instance, id, active: true }
    }
    pub(super) fn finish(&mut self, confirmed: bool) {
        if !self.active {
            return;
        }
        let mut states = self.instance.destroyed.recover();
        if let Some(state) = states.get_mut(&self.id) {
            state.pending -= 1;
            state.confirmed |= confirmed;
            if state.pending == 0 && !state.confirmed {
                states.remove(&self.id);
            }
        }
        self.active = false;
        drop(states);
        self.instance.lifecycle_changes.send_modify(|generation| *generation += 1);
    }
}
impl Drop for DestroyAttempt {
    fn drop(&mut self) {
        self.finish(false);
    }
}
#[derive(Clone, Copy)]
pub(super) enum Gate {
    Prepare,
    Provision,
    List,
    Inspect,
    Destroy,
    Reach,
    Relay,
    Suspend,
    Resume,
    Export,
    Exec,
    Usage,
    Quota,
}
impl Gate {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Provision => "provision",
            Self::List => "list",
            Self::Inspect => "inspect",
            Self::Destroy => "destroy",
            Self::Reach => "reach",
            Self::Relay => "relay",
            Self::Suspend => "suspend",
            Self::Resume => "resume",
            Self::Export => "export",
            Self::Exec => "exec",
            Self::Usage => "usage",
            Self::Quota => "quota",
        }
    }
    /// Long mutations keep the deadline the Daemon gave its POST routes.
    fn deadline(self, ordinary: std::time::Duration) -> std::time::Duration {
        match self {
            Self::Prepare | Self::Provision | Self::Reach | Self::Suspend | Self::Resume | Self::Export => LONG_CALL.max(ordinary),
            _ => ordinary,
        }
    }
    /// Calls whose interruption can leave vendor side effects.
    fn mutates(self) -> bool {
        matches!(self, Self::Prepare | Self::Provision | Self::Destroy | Self::Suspend | Self::Resume | Self::Export | Self::Exec)
    }
    fn supported(self, c: &Capabilities) -> bool {
        match self {
            Self::Prepare | Self::Provision | Self::List | Self::Inspect | Self::Destroy | Self::Reach | Self::Relay => true,
            Self::Suspend | Self::Resume => c.suspend_resume,
            Self::Export => c.export,
            Self::Exec => c.fallback_runner,
            Self::Usage => c.usage,
            Self::Quota => c.quota,
        }
    }
}
pub(super) struct Availability {
    pub(super) readiness: Readiness,
    pub(super) may_call: bool,
}
impl Instance {
    // All callers, hello and refresh use this single derivation. Direct rejection
    // is sticky until a new credential generation. Proxy credentials are repaired
    // out of band, so rejection does not disable subsequent probes or route calls.
    pub(super) fn availability(&self, auth: &Authentication) -> Availability {
        let module = self.provider.readiness(&auth.credentials);
        let module_ready = matches!(module, Readiness::Ready);
        if auth.rejected {
            match auth.credentials.mode {
                CredentialMode::Direct { .. } => Availability {
                    readiness: Readiness::MissingCredential {
                        reason: auth.rejection_error.as_ref().map(ToString::to_string).unwrap_or_else(|| "credential rejected".into()),
                    },
                    may_call: false,
                },
                CredentialMode::Proxied { .. } if module_ready => Availability {
                    readiness: Readiness::Unknown { reason: "proxy credential rejected; awaiting successful probe".into() },
                    may_call: true,
                },
                CredentialMode::Proxied { .. } => Availability { readiness: module, may_call: false },
            }
        } else {
            Availability { readiness: module, may_call: module_ready }
        }
    }
    pub(super) fn readiness(&self, auth: &Authentication) -> Readiness {
        self.availability(auth).readiness
    }
    pub(super) fn ready(&self) -> Result<()> {
        let auth = self.auth.recover();
        if matches!(self.readiness(&auth), Readiness::Ready) {
            Ok(())
        } else {
            if auth.rejected
                && let Some(error @ ProtocolError::CredentialRejected { .. }) = self.poll_error.recover().clone()
            {
                return Err(error);
            }
            Err(ProtocolError::unavailable("provider is not ready; inspect hello", None))
        }
    }

    // Instance owns the deadlines of the calls it makes. A readiness probe
    // that overruns keeps the last reported readiness.
    pub(super) async fn refresh_readiness(&self) {
        let credentials = self.auth.recover().credentials.clone();
        let _ = tokio::time::timeout(self.request_timeout, self.provider.refresh_readiness(&credentials)).await;
    }
    /// An ordinary call ends at its deadline; the provider outcome is then unknown.
    /// Calls are never retried here: an `Unavailable` mutation may have happened.
    pub(super) async fn call<T, F, Fut>(&self, gate: Gate, f: F) -> Result<T>
    where
        T: Send,
        F: FnOnce(Arc<dyn Provider>, Credentials) -> Fut + Send,
        Fut: std::future::Future<Output = Result<T>> + Send,
    {
        use tracing::Instrument;
        let deadline = gate.deadline(self.request_timeout);
        tokio::time::timeout(deadline, self.call_with_budget(gate, false, f))
            .instrument(tracing::info_span!("provider_route", provider = %self.config.name, route = gate.name()))
            .await
            .unwrap_or_else(|_| {
                let unknown = if gate.mutates() { "; the provider outcome is unknown" } else { "" };
                let reason = format!("{} timed out after {}s{unknown}", gate.name(), deadline.as_secs());
                Err(ProtocolError::unavailable(reason, None))
            })
    }
    /// Resolve readiness, gate cached capabilities, enforce declared budgets, invoke,
    /// and update credential rejection state once for every route and host poll.
    pub(super) async fn call_with_budget<T, F, Fut>(&self, gate: Gate, poll: bool, f: F) -> Result<T>
    where
        T: Send,
        F: FnOnce(Arc<dyn Provider>, Credentials) -> Fut + Send,
        Fut: std::future::Future<Output = Result<T>> + Send,
    {
        self.refresh_readiness().await;
        let (credentials, generation) = {
            let auth = self.auth.recover();
            // Routes and polls use exactly the same admission gate. Direct
            // rejection blocks both; proxied rejection permits both to probe.
            // A pending observation reservation can safely survive unready time:
            // no route can resume while polling remains disabled by readiness.
            let availability = self.availability(&auth);
            if !availability.may_call {
                if auth.rejected
                    && matches!(auth.credentials.mode, CredentialMode::Direct { .. })
                    && let Some(error) = &auth.rejection_error
                {
                    // Already masked and contextualized at the original failure.
                    return Err(error.clone());
                }
                let reason = format!("provider is not ready: {}", availability.readiness);
                return Err(self.diagnostic_error(ProtocolError::unavailable(reason, None), gate.name()));
            }
            (auth.credentials.clone(), auth.generation)
        };
        if !gate.supported(&self.capabilities) {
            return Err(refused("operation capability not declared"));
        }
        self.reserve(gate.name(), poll)?;
        let call_token = credentials.token().cloned();
        // Nothing awaits between the provider's result and `finish_call`, so an
        // outer deadline drops only a call with no result yet; one that returned
        // (including CredentialRejected) is always recorded in the same poll.
        let result = f(self.provider.clone(), credentials)
            .await
            .map_err(|error| self.diagnostic_error_for_token(error, gate.name(), call_token.as_ref()));
        if let Err(error) = &result {
            tracing::warn!(provider = %self.config.name, route = gate.name(), error_class = error.class(), error = %error, "provider call failed");
        }
        self.finish_call(generation, poll, gate.name(), &result);
        result
    }
    pub(super) fn finish_call<T>(&self, generation: u64, poll: bool, operation: &str, result: &Result<T>) {
        let mut auth = self.auth.recover();
        let before = self.readiness(&auth);
        if auth.generation == generation {
            if poll {
                *self.poll_error.recover() = result.as_ref().err().cloned();
            }
            if matches!(result, Err(ProtocolError::CredentialRejected { .. })) {
                auth.rejection_error = result.as_ref().err().cloned();
                auth.rejected = true;
                auth.generation += 1; // invalidate every call started before this rejection
            } else if result.is_ok() && auth.rejected && matches!(auth.credentials.mode, CredentialMode::Proxied { .. }) {
                auth.rejected = false;
                auth.rejection_error = None;
                auth.generation += 1; // only a probe started after rejection can repair it
            }
        }
        let after = self.readiness(&auth);
        if before != after {
            tracing::info!(provider = %self.config.name, route = operation, readiness = readiness_status(&after), "provider readiness changed");
        }
    }
    pub(super) fn diagnostic_error(&self, error: ProtocolError, operation: &str) -> ProtocolError {
        self.diagnostic_error_for_token(error, operation, None)
    }
    pub(super) fn diagnostic_error_for_token(&self, error: ProtocolError, operation: &str, token: Option<&Secret>) -> ProtocolError {
        let (mut masker, missing_token) = {
            let secrets = self.diagnostic_secrets.recover();
            (secrets.masker.clone(), token.filter(|token| !secrets.contains(token)))
        };
        if let Some(token) = missing_token {
            // A long-running call may outlive the recent-generation window.
            Arc::make_mut(&mut masker).remember(token.expose());
        }
        masker.context(error, &self.config.name, operation)
    }

    fn longest_window(&self, operation: &str) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.rate_limits.iter().filter(|r| r.operation == operation).map(|r| r.period_seconds).max().unwrap_or(0),
        )
    }
    pub(super) fn reserve(&self, operation: &'static str, poll: bool) -> Result<()> {
        let mut budget = self.budget.recover();
        let mut waiting = self.poll_waiting.recover();
        let now = tokio::time::Instant::now();
        let limits: Vec<_> = self.rate_limits.iter().filter(|r| r.operation == operation || r.operation == "*").collect();
        for limit in &limits {
            let longest = self.longest_window(&limit.operation);
            if !poll && limit.requests == 1 && waiting.contains(&limit.operation) {
                return Err(ProtocolError::RateLimited {
                    reason: "slot reserved for pending observation".into(),
                    retry_after: Some(limit.period_seconds),
                });
            }
            if poll {
                let window = std::time::Duration::from_secs(limit.period_seconds);
                let times = budget.entry(format!("poll:{}", limit.operation)).or_default();
                times.retain(|at| now.duration_since(*at) < longest);
                if times.iter().filter(|at| now.duration_since(**at) < window).count() >= (limit.requests / 2).max(1) as usize {
                    return Err(ProtocolError::RateLimited {
                        reason: "observation share exhausted".into(),
                        retry_after: Some(limit.period_seconds),
                    });
                }
            }
            let times = budget.entry(limit.operation.clone()).or_default();
            while times.front().is_some_and(|at| now.duration_since(*at) >= longest) {
                times.pop_front();
            }
            let window = std::time::Duration::from_secs(limit.period_seconds);
            let active: Vec<_> = times.iter().filter(|at| now.duration_since(**at) < window).collect();
            if active.len() >= limit.requests as usize {
                if poll && limit.requests == 1 {
                    waiting.insert(limit.operation.clone());
                }
                let remaining = window.saturating_sub(now.duration_since(*active[0]));
                return Err(ProtocolError::RateLimited {
                    reason: "declared provider rate limit".into(),
                    retry_after: Some(remaining.as_secs().saturating_add(1)),
                });
            }
        }
        let scopes: BTreeSet<_> = limits.iter().map(|limit| limit.operation.clone()).collect();
        for scope in scopes {
            if poll {
                waiting.remove(&scope);
                budget.entry(format!("poll:{scope}")).or_default().push_back(now);
            }
            budget.entry(scope).or_default().push_back(now);
        }
        Ok(())
    }
}

// A module violating stable port declarations must produce a typed request
// refusal rather than panic after the cached capability gate has admitted it.
pub(super) fn operation_port<T: ?Sized>(port: Option<&T>) -> Result<&T> {
    port.ok_or_else(|| refused("operation port unavailable"))
}

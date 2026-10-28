//! Endpoint-driven ADR 0070 scenarios. No reference-host implementation is used.
//! The caller configures/authenticates the client and owns the host's lifetime.
use drydock_client::{
    Client, Error, Method, Records,
    api::{ConfigUpdate, ProviderApi, Provisioned},
};
use drydock_protocol::*;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn default_sample_millis() -> u64 {
    25
}

type Result<T> = std::result::Result<T, String>;
#[derive(Clone, Deserialize, Serialize)]
pub struct Options {
    pub request: ProvisionRequest,
    /// Empty means the provider suite. Fixture scenarios must be explicitly selected.
    #[serde(default)]
    pub scenarios: Vec<Scenario>,
    /// Full non-secret fixture configuration, only used by the host-contract suite.
    pub fixture_configuration: Option<Configuration>,
    pub null_environment_id: Option<String>,
    pub auth_audit: Option<Vec<String>>,
    #[serde(default = "default_sample_millis")]
    pub billing_sample_millis: u64,
    /// Wait 0..=86400000 ms after recording the sample before reading vendor usage.
    #[serde(default)]
    pub billing_settle_millis: u64,
    #[serde(default)]
    pub timeouts: Timeouts,
    /// Only hermetic echo fixtures may enable this. Real agents speak their own protocol.
    #[serde(default)]
    pub echo_relay: bool,
    /// Command must exercise the returned reach recipe and exit only after a byte round trip.
    /// Receives the full recipe verbatim on stdin, including any credentials, never argv or logs.
    /// For SSH it owns the matching key.
    pub reach_probe: Option<Vec<String>>,
    /// Root guest probe: emit exactly the documented JSON and close the stream.
    /// The exec byte-stream protocol has no process exit-status channel.
    pub egress_probe: Option<ExecRequest>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scenario {
    Capabilities,
    Authentication,
    Prepare,
    Lifecycle,
    Observation,
    Semantics,
    Nulls,
    Reach,
    Refusal,
    Egress,
    Destroy,
    Metering,
    HostFixtures,
}
impl Scenario {
    pub const ALL: &'static [Self] = &[
        Self::Capabilities,
        Self::Authentication,
        Self::Prepare,
        Self::Lifecycle,
        Self::Observation,
        Self::Semantics,
        Self::Nulls,
        Self::Reach,
        Self::Refusal,
        Self::Egress,
        Self::Destroy,
        Self::Metering,
        Self::HostFixtures,
    ];
}
impl Options {
    fn selected(&self, scenario: Scenario) -> bool {
        if self.scenarios.is_empty() { scenario != Scenario::HostFixtures } else { self.scenarios.contains(&scenario) }
    }
}
/// Independently tunable deadlines for cold provider starts and guest probes.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct Timeouts {
    pub startup_seconds: u64,
    pub request_seconds: u64,
    pub headers_seconds: u64,
    pub record_seconds: u64,
    pub transition_seconds: u64,
    pub probe_seconds: u64,
}
impl Default for Timeouts {
    fn default() -> Self {
        Self {
            startup_seconds: 15,
            request_seconds: 30,
            headers_seconds: 20,
            record_seconds: 20,
            transition_seconds: 30,
            probe_seconds: 30,
        }
    }
}
impl Timeouts {
    pub fn validate(&self) -> Result<()> {
        require(
            [
                self.startup_seconds,
                self.request_seconds,
                self.headers_seconds,
                self.record_seconds,
                self.transition_seconds,
                self.probe_seconds,
            ]
            .into_iter()
            .all(|seconds| (1..=86400).contains(&seconds)),
            "timeouts must be between 1 and 86400 seconds",
        )
    }
}
#[derive(Debug, Serialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}
#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub checks: Vec<Check>,
    pub usage: Option<Usage>,
    pub quota_before: Option<Quota>,
    pub quota_after: Option<Quota>,
    /// Wall-clock exposure, not a guessed monetary amount.
    pub elapsed_seconds: f64,
    /// Account credit delta; None means unavailable, never zero spend.
    pub credits_spent: Option<f64>,
}
impl Report {
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }
    fn capture<T>(&mut self, name: &str, result: Result<T>) -> Option<T> {
        match result {
            Ok(value) => {
                self.record(name, Ok(()));
                Some(value)
            }
            Err(error) => {
                self.record(name, Err(error));
                None
            }
        }
    }
    fn record(&mut self, name: &str, result: Result<()>) {
        let (passed, detail) = match result {
            Ok(()) => (true, "ok".into()),
            Err(message) => (false, message),
        };
        self.checks.push(Check { name: name.into(), passed, detail });
    }
}
fn require(value: bool, message: &str) -> Result<()> {
    if value { Ok(()) } else { Err(message.into()) }
}
trait SafeError {
    fn category(self) -> String;
}
impl SafeError for Error {
    fn category(self) -> String {
        match self {
            Error::Protocol(error) => format!("http {} {}", error.status(), error),
            Error::InvalidResponse(_) => "decode".into(),
            Error::Transport(_) => "transport".into(),
            Error::Timeout(_) => "timeout".into(),
            Error::InvalidRequest(_) => "invalid request".into(),
            Error::VersionMismatch => "version mismatch".into(),
            Error::RateLimited => "rate limited".into(),
            Error::NotReady(readiness) => format!("not ready: {readiness}"),
            Error::ReadinessTimeout(readiness) => format!("startup timeout: {readiness}"),
        }
    }
}
impl SafeError for std::io::Error {
    fn category(self) -> String {
        if self.kind() == std::io::ErrorKind::TimedOut { "timeout" } else { "io" }.into()
    }
}
impl SafeError for serde_json::Error {
    fn category(self) -> String {
        "decode".into()
    }
}
impl SafeError for tokio::time::error::Elapsed {
    fn category(self) -> String {
        "timeout".into()
    }
}
pub async fn authentication(client: &Client, timeout: Duration) -> Result<()> {
    let token = client.bearer().ok_or("bearer authentication requires a TCP target; Unix peer admission is a separate scenario")?;
    let mut candidates = vec![None];
    for index in 0..token.expose().len() {
        let mut bytes = token.expose().as_bytes().to_vec();
        bytes[index] = if bytes[index] == b'a' { b'b' } else { b'a' };
        if let Ok(value) = String::from_utf8(bytes) {
            candidates.push(Some(Secret::new(value)));
        }
    }
    for candidate in candidates {
        let probe = client.clone().with_request_timeout(timeout).with_bearer(candidate);
        let (status, _) = tokio::time::timeout(timeout, probe.wire(Method::GET, &["v1", "hello"], &[], None))
            .await
            .map_err(SafeError::category)?
            .map_err(SafeError::category)?;
        require(status == 401, "authentication bypass: absent or invalid token accepted")?;
    }
    Ok(())
}
/// The caller supplies an endpoint whose allowed peer UID differs from its process.
pub async fn unix_peer_admission(unauthorized: &Client) -> Result<()> {
    let (status, _) = unauthorized.wire(Method::GET, &["v1", "hello"], &[], None).await.map_err(SafeError::category)?;
    require(status == 403, "Unix peer authentication bypass")
}
async fn auth_audit(options: &Options) -> Result<()> {
    let command = options.auth_audit.as_ref().ok_or("constant-time authentication requires executable comparator evidence")?;
    let (program, args) = command.split_first().ok_or("empty authentication audit")?;
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(SafeError::category)?;
    let status = tokio::time::timeout(Duration::from_secs(options.timeouts.probe_seconds), child.wait())
        .await
        .map_err(SafeError::category)?
        .map_err(SafeError::category)?;
    require(status.success(), "constant-time comparator audit failed")
}
async fn observe(client: &Client, since: Option<&str>, timeouts: &Timeouts) -> Result<Records> {
    tokio::time::timeout(Duration::from_secs(timeouts.headers_seconds), client.observe(since))
        .await
        .map_err(SafeError::category)?
        .map_err(SafeError::category)
}
async fn next(records: &mut Records, timeouts: &Timeouts) -> Result<ObserveRecord> {
    tokio::time::timeout(Duration::from_secs(timeouts.record_seconds), records.next())
        .await
        .map_err(SafeError::category)?
        .map_err(SafeError::category)?
        .ok_or_else(|| "event stream ended".into())
}
async fn transition(
    records: &mut Records,
    provider: &str,
    id: &str,
    predicate: impl Fn(&EventKind) -> bool,
    timeouts: &Timeouts,
) -> Result<Event> {
    tokio::time::timeout(Duration::from_secs(timeouts.transition_seconds), async {
        loop {
            if let ObserveRecord::Event { event } = next(records, timeouts).await?
                && event.provider == provider
                && event.id == id
                && predicate(&event.event)
            {
                require(!event.cursor.is_empty(), "empty event cursor")?;
                return Ok(event);
            }
        }
    })
    .await
    .map_err(SafeError::category)?
}
fn valid_usage(usage: &Usage, period: &Period) -> Result<()> {
    require(&usage.period == period, "usage period differs from request")?;
    require(
        usage.environment_hours.iter().all(|row| row.hours.is_finite() && row.hours >= 0.0 && valid_size(&row.size))
            && usage.measurements.as_ref().is_none_or(|m| {
                m.resources.iter().all(|(kind, q)| q.amount.is_finite() && q.amount >= 0.0 && kind.accepts_unit(&q.unit))
                    && m.cost.as_ref().is_none_or(|c| valid_decimal(&c.amount) && !c.currency.is_empty())
            }),
        "invalid usage size or hours",
    )
}
fn valid_size(size: &Size) -> bool {
    size.cpus.is_finite() && size.cpus > 0.0
}
fn valid_quota(quota: &Quota) -> Result<()> {
    require(quota.credits_remaining.is_none_or(f64::is_finite), "nonfinite credits")?;
    require(
        quota.resources.iter().all(|r| {
            r.key.resource.accepts_unit(&r.unit)
                && r.in_use.is_finite()
                && r.in_use >= 0.0
                && r.limit.is_none_or(|limit| limit.is_finite() && limit >= 0.0)
        }),
        "invalid resource quota",
    )
}
/// Each scenario records its own verdict. Cleanup is attempted even after failures.
/// Use a unique label and an otherwise idle provider to avoid metering interference.
pub async fn run(client: &Client, provider: &str, options: &Options) -> Report {
    let start = std::time::Instant::now();
    let period_start = chrono::Utc::now();
    let mut report = Report::default();
    if let Err(error) = options.timeouts.validate() {
        report.record("timeouts", Err(error));
        return report;
    }
    if let Err(error) = validate_billing_settle(options.billing_settle_millis) {
        report.record("billing_settle", Err(error));
        return report;
    }
    let client = &client.clone().with_request_timeout(Duration::from_secs(options.timeouts.request_seconds));
    let hello = match client.hello().await {
        Ok(hello) => hello,
        Err(error) => {
            report.record("hello", Err(error.category()));
            return report;
        }
    };
    report.record("hello", Ok(()));
    let declaration = match client.provider(provider).await {
        Ok(declaration) => declaration,
        Err(error) => {
            report.record("provider", Err(error.category()));
            return report;
        }
    };
    let caps = &declaration.capabilities;
    if options.selected(Scenario::Capabilities) {
        report.record("capabilities", capabilities(&hello, &declaration));
    }
    if options.selected(Scenario::Authentication) {
        report.record("authentication", authentication(client, Duration::from_secs(options.timeouts.request_seconds)).await);
        report.record("authentication_constant_time", auth_audit(options).await);
    }
    if options.selected(Scenario::Metering) && caps.quota {
        match client.quota(provider).await {
            Ok(quota) => {
                report.record("quota_before", valid_quota(&quota));
                report.quota_before = Some(quota);
            }
            Err(error) => report.record("quota_before", Err(error.category())),
        }
    }
    let needs_environment = [
        Scenario::Lifecycle,
        Scenario::Observation,
        Scenario::Nulls,
        Scenario::Reach,
        Scenario::Refusal,
        Scenario::Egress,
        Scenario::Destroy,
        Scenario::HostFixtures,
    ]
    .into_iter()
    .any(|scenario| options.selected(scenario));
    let mut options = options.clone();
    if options.selected(Scenario::Prepare) || needs_environment || options.selected(Scenario::Semantics) {
        if let Some(prepared) = report.capture("prepare", prepare(client, provider, &options.request).await) {
            options.request.prepared = prepared;
        } else {
            return report;
        }
    }
    let target = Target { client, provider, options: &options, caps };
    let mut owned_ids = Resources::new(&options.request.label);
    let mut records = if needs_environment && (options.selected(Scenario::Observation) || options.selected(Scenario::Destroy)) {
        target.initial_observation(&mut report).await
    } else {
        None
    };
    let environment = if needs_environment { target.create(&mut report, &mut owned_ids).await } else { None };
    if let Some(environment) = &environment {
        if options.selected(Scenario::Lifecycle) {
            target.lifecycle(environment, &mut report, &mut owned_ids).await;
        }
        let mut resumed =
            if options.selected(Scenario::Observation) { target.observation(environment, &mut report, &mut records).await } else { None };
        if options.selected(Scenario::Nulls) {
            target.explicit_nulls(environment, &mut report, &mut owned_ids).await;
        }
        if options.selected(Scenario::Reach) {
            report.record("reach_byte_stream", reach(client, provider, &environment.id, &options).await);
        }
        if options.selected(Scenario::Refusal) {
            target.refusal(&mut report, &mut owned_ids).await;
        }
        if options.selected(Scenario::Egress)
            && (caps.egress.enforcement == Enforcement::Enforced || environment.egress == Enforcement::Enforced)
        {
            report.record("enforced_egress", egress(client, provider, environment, &options).await);
        }
        if options.selected(Scenario::HostFixtures) {
            host_fixtures(client, provider, &options, environment, &mut report, &mut owned_ids).await;
        }
        if options.selected(Scenario::Semantics) {
            semantic_requests(client, provider, &options, &mut owned_ids, &mut report).await;
        }
        if options.selected(Scenario::Destroy) {
            target.destruction(environment, &mut report, &mut records, &mut resumed, &owned_ids).await;
        }
    } else if options.selected(Scenario::Semantics) {
        semantic_requests(client, provider, &options, &mut owned_ids, &mut report).await;
    }
    if (!options.selected(Scenario::Destroy) || environment.is_none()) && (needs_environment || !owned_ids.is_empty()) {
        report.record("cleanup", cleanup(client, provider, &owned_ids).await);
    }
    if options.selected(Scenario::Metering) {
        finish_report(client, provider, caps, &mut report, start, period_start).await;
    }
    report.elapsed_seconds = start.elapsed().as_secs_f64();
    report
}
fn validate_billing_settle(millis: u64) -> Result<()> {
    require(millis <= 86_400_000, "billing settle delay must be 0..86400000 milliseconds")
}
async fn billing_window(
    client: &Client,
    provider: &str,
    size: &Size,
    id: &str,
    millis: u64,
    settle_millis: u64,
    running: bool,
) -> Result<()> {
    validate_billing_settle(settle_millis)?;
    require((1..=60000).contains(&millis), "billing sample must be 1..60000 milliseconds")?;
    let start = chrono::Utc::now();
    tokio::time::sleep(Duration::from_millis(millis)).await;
    let period = Period::new(start.into(), chrono::Utc::now().into()).map_err(str::to_owned)?;
    tokio::time::sleep(Duration::from_millis(settle_millis)).await;
    let usage = client.usage(provider, &period).await.map_err(SafeError::category)?;
    valid_usage(&usage, &period)?;
    if let Some(m) = &usage.measurements
        && matches!(&m.scope, UsageScope::Environment { .. })
    {
        // Aggregate organization usage cannot establish one sandbox's billing.
        require(
            matches!(&m.scope, UsageScope::Environment { id: measured } if measured == id),
            "billing sample is organization/provider scoped or for another environment; isolated usage unavailable",
        )?;
        let cpu = m.resources.get(&ResourceKind::Cpu).filter(|q| q.unit == "{vCPU}.s").ok_or("isolated CPU seconds unavailable")?;
        return require(if running { cpu.amount > 0.0 } else { cpu.amount == 0.0 }, "isolated CPU usage disagrees with billing transition");
    }
    let hours: f64 = usage.environment_hours.iter().filter(|row| &row.size == size).map(|row| row.hours).sum();
    require(if running { hours > 0.0 } else { hours == 0.0 }, "vendor usage disagrees with billing transition")
}
async fn prepare(client: &Client, provider: &str, provision: &ProvisionRequest) -> Result<Prepared> {
    let prepared = &provision.prepared;
    let request = PrepareRequest {
        size: provision.size.clone(),
        platform: Some(prepared.platform.clone()),
        route: None,
        image_pull: None,
        image_digest: prepared.image_digest.clone(),
        tools_digest: prepared.tools_digest.clone(),
    };
    let first = client.prepare(provider, &request).await.map_err(SafeError::category)?;
    let second = client.prepare(provider, &request).await.map_err(SafeError::category)?;
    require(
        first == second
            && first.provider == provider
            && !first.id.is_empty()
            && first.image_digest == request.image_digest
            && first.tools_digest == request.tools_digest
            && request.platform.as_ref() == Some(&first.platform),
        "prepare must be idempotent and preserve provider/digest/platform identity",
    )?;
    Ok(first)
}
fn capabilities(hello: &Hello, declaration: &ProviderDeclaration) -> Result<()> {
    let c = &declaration.capabilities;
    require(
        matches!(declaration.readiness, Readiness::Ready)
            && hello.loadable_modules.iter().any(|m| m.name == declaration.module && !m.version.is_empty()),
        "provider readiness or loadable module declaration invalid",
    )?;
    require(
        !c.material_modes.is_empty()
            && !c.checkout_strategies.is_empty()
            && c.workspace_root.starts_with('/')
            && !c.egress.routes.is_empty()
            && !c.platforms.is_empty(),
        "incomplete capability declaration",
    )?;
    require(
        declaration.rate_limits.iter().all(|limit| limit.requests > 0 && limit.period_seconds > 0 && !limit.operation.is_empty()),
        "invalid rate-limit declaration",
    )
}
struct Target<'a> {
    client: &'a Client,
    provider: &'a str,
    options: &'a Options,
    caps: &'a Capabilities,
}
impl Target<'_> {
    async fn initial_observation(&self, report: &mut Report) -> Option<Records> {
        let client = self.client;
        let provider = self.provider;
        let options = self.options;

        let timeouts = &options.timeouts;
        let mut records = match observe(client, None, timeouts).await {
            Ok(records) => Some(records),
            Err(error) => {
                report.record("initial_snapshot", Err(error));
                None
            }
        };
        if let Some(records) = records.as_mut() {
            report.record(
                "initial_snapshot",
                match next(records, timeouts).await {
                    Ok(ObserveRecord::Snapshot { unavailable_providers, .. }) => {
                        require(!unavailable_providers.contains_key(provider), "provider inventory unavailable")
                    }
                    Ok(_) => Err("initial observation must mark a snapshot".into()),
                    Err(error) => Err(error),
                },
            );
        }
        records
    }
}

impl Target<'_> {
    async fn create(&self, report: &mut Report, owned_ids: &mut Resources) -> Option<Environment> {
        let client = self.client;
        let provider = self.provider;
        let options = self.options;

        owned_ids.register(&options.request);
        let (first, second) = tokio::join!(client.provision(provider, &options.request), client.provision(provider, &options.request));
        let first_created = first.as_ref().ok().map(|row| matches!(row, Provisioned::Created(_)));
        let environment = match first {
            Ok(row) => row.into_inner(),
            Err(error) => {
                report.record("provision", Err(error.category()));
                report.record("cleanup_after_failed_provision", cleanup(client, provider, owned_ids).await);
                return None;
            }
        };
        owned_ids.insert(environment.id.clone());
        report.record(
            "concurrent_label",
            async {
                let second = second.map_err(SafeError::category)?;
                let created = matches!(second, Provisioned::Created(_));
                let other = second.into_inner();
                let same = other.id == environment.id;
                owned_ids.insert(other.id.clone());
                require(first_created == Some(!created) && same, "concurrent retries must return one creation and one existing resource")
            }
            .await,
        );
        report.record(
            "provision",
            require(
                environment.label.as_deref() == Some(options.request.label.as_str())
                    && environment.provider == provider
                    && !environment.id.is_empty(),
                "wrong environment identity",
            ),
        );
        Some(environment)
    }
}

impl Target<'_> {
    async fn lifecycle(&self, environment: &Environment, report: &mut Report, owned_ids: &mut Resources) -> () {
        let client = self.client;
        let provider = self.provider;
        let options = self.options;

        report.record(
            "idempotent_label",
            async {
                let again = client.provision(provider, &options.request).await.map(Provisioned::into_inner).map_err(SafeError::category)?;
                let same = again.id == environment.id && again.label == environment.label;
                owned_ids.insert(again.id.clone());
                require(same, "duplicate label created another environment")
            }
            .await,
        );
        report.record(
            "list_readoption",
            async {
                let rows = client.list(provider).await.map_err(SafeError::category)?;
                let matches: Vec<_> = rows.iter().filter(|e| e.label == environment.label).collect();
                require(matches.len() == 1 && matches[0].id == environment.id, "list did not uniquely re-adopt label")
            }
            .await,
        );
    }
}

impl Target<'_> {
    async fn observation(&self, environment: &Environment, report: &mut Report, records: &mut Option<Records>) -> Option<Records> {
        let client = self.client;
        let provider = self.provider;
        let options = self.options;
        let caps = self.caps;

        let timeouts = &options.timeouts;
        let created = report.capture(
            "created_event",
            async {
                transition(
                    records.as_mut().ok_or("cannot observe")?,
                    provider,
                    &environment.id,
                    |e| matches!(e, EventKind::Created),
                    timeouts,
                )
                .await
            }
            .await,
        );
        let running = report.capture(
            "running_event",
            async {
                transition(
                    records.as_mut().ok_or("cannot observe")?,
                    provider,
                    &environment.id,
                    |e| matches!(e, EventKind::Running { .. }),
                    timeouts,
                )
                .await
            }
            .await,
        );
        if let Some(event) = &running {
            report.record(
                "running_state",
                async {
                    let EventKind::Running { granted_size } = &event.event else { unreachable!() };
                    let current = client.inspect(provider, &environment.id).await.map_err(SafeError::category)?;
                    require(
                        valid_size(granted_size)
                            && current.granted_size.as_ref() == Some(granted_size)
                            && matches!(current.state, Observation::Running),
                        "running event has wrong granted size or billing state",
                    )
                }
                .await,
            );
        }
        // Replay a known predecessor to check exclusive resume without depending on
        // optional suspend support. Snapshot fallback explicitly marks a metering gap.
        if let (Some(created), Some(running)) = (&created, &running) {
            report.record(
                "cursor_resume",
                async {
                    let mut replay = observe(client, Some(&created.cursor), timeouts).await?;
                    match next(&mut replay, timeouts).await? {
                        ObserveRecord::Event { event } => require(event == *running, "resume did not return the next event exclusively"),
                        ObserveRecord::Snapshot { unavailable_providers, .. } => {
                            require(!unavailable_providers.contains_key(provider), "resume inventory unavailable")
                        }
                    }
                }
                .await,
            );
        }
        report.record(
            "gap_snapshot",
            async {
                let mut gap = observe(client, Some("conformance-unknown-cursor"), timeouts).await?;
                require(matches!(next(&mut gap, timeouts).await?, ObserveRecord::Snapshot { .. }), "unknown cursor did not mark snapshot")
            }
            .await,
        );
        // Keep the resumed stream as soon as it opens, even if a later scenario fails.
        let mut resumed_records = if let Some(event) = &running {
            report.capture("resume_stream", observe(client, Some(&event.cursor), timeouts).await)
        } else {
            None
        };
        if caps.usage
            && let Some(size) = &environment.granted_size
        {
            report.record(
                "billing_running",
                billing_window(client, provider, size, &environment.id, options.billing_sample_millis, options.billing_settle_millis, true)
                    .await,
            );
        }
        if caps.suspend_resume
            && let Some(token) = report.capture(
                "suspend",
                async {
                    let token = client.suspend(provider, &environment.id).await.map_err(SafeError::category)?;
                    require(
                        !token.token.expose().is_empty()
                            && client.suspend(provider, &environment.id).await.map_err(SafeError::category)? == token,
                        "suspend returned an empty or unstable token",
                    )?;
                    Ok(token)
                }
                .await,
            )
        {
            report.record(
                "stopped_event",
                async {
                    let stream = resumed_records.as_mut().or(records.as_mut()).ok_or("cannot observe")?;
                    let stopped = transition(
                        stream,
                        provider,
                        &environment.id,
                        |e| matches!(e, EventKind::Stopped { .. } | EventKind::Paused { .. }),
                        timeouts,
                    )
                    .await?;
                    require(
                        running.as_ref().is_none_or(|event| stopped.cursor != event.cursor)
                            && matches!(
                                stopped.event,
                                EventKind::Stopped { cause: StopCause::SuspendedByRequest }
                                    | EventKind::Paused { cause: StopCause::SuspendedByRequest }
                            ),
                        "stopped event has wrong cursor or cause",
                    )
                }
                .await,
            );
            report.record(
                "stopped_billing",
                async {
                    require(
                        matches!(
                            client.inspect(provider, &environment.id).await.map_err(SafeError::category)?.state,
                            Observation::Stopped { cause: StopCause::SuspendedByRequest }
                        ),
                        "suspended environment has wrong state or cause",
                    )
                }
                .await,
            );
            if caps.usage
                && let Some(size) = &environment.granted_size
            {
                report.record(
                    "billing_suspended",
                    billing_window(
                        client,
                        provider,
                        size,
                        &environment.id,
                        options.billing_sample_millis,
                        options.billing_settle_millis,
                        false,
                    )
                    .await,
                );
            }
            if report
                .capture(
                    "resume",
                    async {
                        client.resume(provider, &environment.id, &token).await.map_err(SafeError::category)?;
                        require(
                            matches!(
                                client.inspect(provider, &environment.id).await.map_err(SafeError::category)?.state,
                                Observation::Running
                            ),
                            "resume did not restore running state",
                        )
                    }
                    .await,
                )
                .is_some()
            {
                report.record(
                    "resumed_event",
                    async {
                        transition(
                            resumed_records.as_mut().or(records.as_mut()).ok_or("cannot observe")?,
                            provider,
                            &environment.id,
                            |e| matches!(e, EventKind::Resumed | EventKind::Running { .. }),
                            timeouts,
                        )
                        .await?;
                        Ok(())
                    }
                    .await,
                );
            }
        }
        resumed_records
    }
}

impl Target<'_> {
    async fn explicit_nulls(&self, environment: &Environment, report: &mut Report, owned_ids: &mut Resources) -> () {
        let client = self.client;
        let provider = self.provider;
        let caps = self.caps;

        report.record(
            "environment_nulls",
            async {
                let null_id = if self.options.fixture_configuration.is_some() {
                    let value = fixture(client, provider, &environment.id, &["null_environment".into()]).await?;
                    let id = value["id"].as_str().ok_or("fixture omitted null environment id")?.to_owned();
                    owned_ids.insert(id.clone());
                    id
                } else {
                    self.options
                        .null_environment_id
                        .clone()
                        .ok_or("null-field check requires an unlabelled, unknown-size environment or fixture controls")?
                };
                let (status, value) = client
                    .wire(Method::GET, &["v1", "providers", provider, "environments", &null_id], &[], None)
                    .await
                    .map_err(SafeError::category)?;
                require(
                    status == 200
                        && value.get("label").is_some_and(serde_json::Value::is_null)
                        && value.get("granted_size").is_some_and(serde_json::Value::is_null),
                    "environment must emit explicit null label and granted_size",
                )?;
                Ok(())
            }
            .await,
        );
        if caps.quota {
            report.record(
                "quota_nulls",
                async {
                    let (status, value) =
                        client.wire(Method::GET, &["v1", "providers", provider, "quota"], &[], None).await.map_err(SafeError::category)?;
                    require(status == 200, "quota refused")?;
                    for field in ["credits_remaining", "credit_unit", "concurrency_in_use", "concurrency_limit"] {
                        require(value.get(field).is_some(), "optional quota field omitted instead of null")?;
                    }
                    Ok(())
                }
                .await,
            );
        }
    }
}

impl Target<'_> {
    async fn refusal(&self, report: &mut Report, owned_ids: &mut Resources) -> () {
        let client = self.client;
        let provider = self.provider;
        let options = self.options;

        report.record(
            "typed_refusal",
            async {
                let mut invalid = options.request.clone();
                invalid.prepared.provider = format!("{provider}-other");
                invalid.label = owned_ids.label(ProbeLabel::Refused);
                match client.provision(provider, &invalid).await.map(Provisioned::into_inner) {
                    Err(Error::Protocol(ProtocolError::Refused { .. })) => Ok(()),
                    Ok(unexpected) => {
                        owned_ids.insert(unexpected.id);
                        Err("cross-provider prepared form accepted".into())
                    }
                    _ => Err("refusal was not typed Refused".into()),
                }
            }
            .await,
        );
    }
}

impl Target<'_> {
    async fn destruction(
        &self,
        environment: &Environment,
        report: &mut Report,
        records: &mut Option<Records>,
        resumed_records: &mut Option<Records>,
        owned_ids: &Resources,
    ) -> () {
        let client = self.client;
        let provider = self.provider;
        let options = self.options;

        let timeouts = &options.timeouts;
        report.record(
            "destroy_absent",
            async {
                if !options.selected(Scenario::Observation) {
                    transition(
                        records.as_mut().ok_or("missing observation dependency")?,
                        provider,
                        &environment.id,
                        |kind| matches!(kind, EventKind::Running { .. }),
                        timeouts,
                    )
                    .await?;
                }
                client.destroy(provider, &environment.id).await.map_err(SafeError::category)?;
                client.destroy(provider, &environment.id).await.map_err(SafeError::category)?;
                require(
                    !client.list(provider).await.map_err(SafeError::category)?.iter().any(|row| row.id == environment.id),
                    "destroyed environment still listed",
                )
            }
            .await,
        );
        report.record("cleanup", cleanup(client, provider, owned_ids).await);
        report.record(
            "typed_loss",
            async {
                let event = transition(
                    resumed_records.as_mut().or(records.as_mut()).ok_or("cannot observe")?,
                    provider,
                    &environment.id,
                    |e| matches!(e, EventKind::Gone { .. }),
                    timeouts,
                )
                .await?;
                require(
                    matches!(event.event, EventKind::Gone { cause: GoneCause::DestroyedByRequest }),
                    "confirmed destroy has wrong loss cause",
                )
            }
            .await,
        );
    }
}

fn probe_label(base: &str, probe: ProbeLabel) -> String {
    match probe {
        ProbeLabel::Refused => format!("{base}-refused"),
        ProbeLabel::Invalid(field) => format!("{base}-invalid-{field}"),
        ProbeLabel::Auxiliary(suffix) => format!("{base}-{suffix}"),
    }
}
#[derive(Clone)]
enum ProbeLabel {
    Refused,
    Invalid(&'static str),
    Auxiliary(String),
}
#[derive(Default)]
struct Resources {
    base: String,
    ids: std::collections::BTreeSet<String>,
    labels: std::collections::BTreeSet<String>,
}
impl Resources {
    fn new(base: &str) -> Self {
        Self { base: base.into(), ..Default::default() }
    }
    fn label(&mut self, probe: ProbeLabel) -> String {
        let label = probe_label(&self.base, probe);
        self.labels.insert(label.clone());
        label
    }
    fn register(&mut self, request: &ProvisionRequest) {
        self.labels.insert(request.label.clone());
    }
    fn insert(&mut self, id: String) {
        self.ids.insert(id);
    }
    fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
    }
    fn is_empty(&self) -> bool {
        self.ids.is_empty() && self.labels.is_empty()
    }
}
async fn cleanup(client: &Client, provider: &str, known: &Resources) -> Result<()> {
    let labels = &known.labels;
    let owns = |row: &Environment| known.contains(&row.id) || row.label.as_ref().is_some_and(|label| labels.contains(label));
    let mut ids = known.ids.clone();
    let inventory = match client.list(provider).await {
        Ok(rows) => Ok(rows),
        Err(_) => client.list(provider).await,
    };
    if let Ok(rows) = &inventory {
        ids = rows.iter().filter(|row| owns(row)).map(|row| row.id.clone()).collect();
    }
    let mut failure = None;
    for id in ids {
        if client.destroy(provider, &id).await.is_err() {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Err(error) = client.destroy(provider, &id).await {
                failure = Some(error.category());
            }
        }
    }
    if let Some(error) = failure {
        return Err(format!("cleanup: {error}"));
    }
    let rows = match client.list(provider).await {
        Ok(rows) => rows,
        Err(_) => client.list(provider).await.map_err(SafeError::category)?,
    };
    require(!rows.iter().any(owns), "cleanup left test resources running")
}
async fn finish_report(
    client: &Client,
    provider: &str,
    caps: &Capabilities,
    report: &mut Report,
    start: std::time::Instant,
    period_start: chrono::DateTime<chrono::Utc>,
) {
    if caps.quota {
        match client.quota(provider).await {
            Ok(quota) => {
                report.record("quota_after", valid_quota(&quota));
                report.quota_after = Some(quota);
            }
            Err(e) => report.record("quota_after", Err(e.category())),
        }
    }
    if caps.usage {
        let usage = async {
            let period = Period::new(period_start.into(), chrono::Utc::now().max(period_start).into()).map_err(str::to_owned)?;
            let usage = client.usage(provider, &period).await.map_err(SafeError::category)?;
            valid_usage(&usage, &period)?;
            Ok(usage)
        }
        .await;
        match usage {
            Ok(usage) => {
                report.record("usage", Ok(()));
                report.usage = Some(usage);
            }
            Err(e) => report.record("usage", Err(e)),
        }
    }
    report.credits_spent = report
        .quota_before
        .as_ref()
        .zip(report.quota_after.as_ref())
        .filter(|(before, after)| before.credit_unit == after.credit_unit)
        .and_then(|(before, after)| Some(before.credits_remaining? - after.credits_remaining?))
        .filter(|value| value.is_finite());
    report.elapsed_seconds = start.elapsed().as_secs_f64();
}

async fn reach(client: &Client, provider: &str, id: &str, options: &Options) -> Result<()> {
    let recipe = client.reach(provider, id).await.map_err(SafeError::category)?;
    if let Some(command) = &options.reach_probe {
        let (program, args) = command.split_first().ok_or("empty reach probe")?;
        let mut child = tokio::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(SafeError::category)?;
        let status = tokio::time::timeout(Duration::from_secs(options.timeouts.probe_seconds), async {
            let mut input = child.stdin.take().ok_or("probe stdin unavailable")?;
            input.write_all(&serde_json::to_vec(&recipe).map_err(SafeError::category)?).await.map_err(SafeError::category)?;
            drop(input);
            child.wait().await.map_err(SafeError::category)
        })
        .await
        .map_err(SafeError::category)??;
        return require(status.success(), "reach round trip probe failed");
    }
    if options.echo_relay && matches!(recipe, Reach::Relay { .. }) {
        let mut stream = client.relay(provider, id).await.map_err(SafeError::category)?;
        let bytes = b"drydock-conformance\0\xff\n";
        return tokio::time::timeout(Duration::from_secs(options.timeouts.probe_seconds), async {
            stream.write_all(bytes).await.map_err(SafeError::category)?;
            let mut actual = vec![0; bytes.len()];
            stream.read_exact(&mut actual).await.map_err(SafeError::category)?;
            require(actual == bytes, "reach corrupted bytes")
        })
        .await
        .map_err(SafeError::category)?;
    }
    Err("reach requires a recipe round-trip probe (or hermetic echo relay)".into())
}
async fn egress(client: &Client, provider: &str, environment: &Environment, options: &Options) -> Result<()> {
    require(environment.egress == Enforcement::Enforced, "Enforced declaration downgraded")?;
    let EgressRequest::DenyAll { direct } = &options.request.egress else { return Err("Enforced check requires DenyAll".into()) };
    let deny_all = direct.is_empty();
    let mut command = options.egress_probe.clone().ok_or("Enforced check requires root guest probe")?;
    if deny_all {
        command.command.splice(0..0, ["env".into(), "DRYDOCK_PROBE_DENY_ALL=1".into()]);
    }
    let mut stream = client.exec(provider, &environment.id, &command).await.map_err(SafeError::category)?;
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(options.timeouts.probe_seconds), (&mut stream).take(4097).read_to_end(&mut bytes))
        .await
        .map_err(SafeError::category)?
        .map_err(SafeError::category)?;
    require(bytes.len() <= 4096, "oversized guest probe output")?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(SafeError::category)?;
    require(
        value["uid"] == 0 && value["unlisted_canary"] == false && value["raw_dns"] == false && (deny_all || value["listed_direct"] == true),
        "root egress probe violated isolation",
    )
}

async fn semantic_requests(client: &Client, provider: &str, options: &Options, owned_ids: &mut Resources, report: &mut Report) {
    let original = match serde_json::to_value(&options.request) {
        Ok(value) => value,
        Err(error) => {
            report.record("semantic_requests", Err(error.category()));
            return;
        }
    };
    // Boundary generator: negative, zero, overflow and wrong-type values cross
    // the CPU and unsigned byte-size domains, including JSON exponent overflow.
    for (field, values) in [
        ("cpus", vec![serde_json::json!(-1), serde_json::json!(0), serde_json::Value::Null, serde_json::json!("NaN")]),
        ("memory_bytes", vec![serde_json::json!(-1), serde_json::json!(1.5), serde_json::json!(1e20)]),
        ("disk_bytes", vec![serde_json::json!(-1), serde_json::json!(1.5)]),
    ] {
        for (index, value) in values.into_iter().enumerate() {
            report.record(
                &format!("semantic_{field}_{index}"),
                async {
                    let mut invalid = original.clone();
                    invalid["size"][field] = value;
                    invalid["label"] = serde_json::json!(owned_ids.label(ProbeLabel::Invalid(field)));
                    let (status, body) = client
                        .wire(drydock_client::Method::POST, &["v1", "providers", provider, "environments"], &[], Some(&invalid))
                        .await
                        .map_err(SafeError::category)?;
                    if status < 300
                        && let Some(id) = body["id"].as_str()
                    {
                        owned_ids.insert(id.to_owned());
                    }
                    require(
                        status == 422 && matches!(serde_json::from_value::<ProtocolError>(body), Ok(ProtocolError::Refused { .. })),
                        "invalid size was not refused before provisioning",
                    )
                }
                .await,
            );
        }
    }
    for (index, destination) in [
        serde_json::json!({"kind":"cidr","cidr":"1.2.3.4/33"}),
        serde_json::json!({"kind":"host_port","host":"bad host","port":1}),
        serde_json::json!({"kind":"host_port","host":"valid.example","port":0}),
    ]
    .into_iter()
    .enumerate()
    {
        report.record(
            &format!("semantic_destination_{index}"),
            async {
                let mut invalid = original.clone();
                invalid["label"] = serde_json::json!(owned_ids.label(ProbeLabel::Auxiliary(format!("invalid-destination-{index}"))));
                invalid["egress"] = serde_json::json!({"mode":"deny_all","direct":[destination]});
                let (status, value) = client
                    .wire(Method::POST, &["v1", "providers", provider, "environments"], &[], Some(&invalid))
                    .await
                    .map_err(SafeError::category)?;
                if status < 300
                    && let Some(id) = value["id"].as_str()
                {
                    owned_ids.insert(id.into());
                }
                require(
                    status == 422 && matches!(serde_json::from_value::<ProtocolError>(value), Ok(ProtocolError::Refused { .. })),
                    "invalid destination was accepted",
                )
            }
            .await,
        );
    }
    for (index, (start, end)) in [("bad", "2026-01-01T00:00:00Z"), ("2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z")].into_iter().enumerate()
    {
        report.record(
            &format!("semantic_period_{index}"),
            async {
                let (status, body) = client
                    .wire(drydock_client::Method::GET, &["v1", "providers", provider, "usage"], &[("start", start), ("end", end)], None)
                    .await
                    .map_err(SafeError::category)?;
                require(
                    status == 422 && matches!(serde_json::from_value::<ProtocolError>(body), Ok(ProtocolError::Refused { .. })),
                    "invalid period or timestamp accepted",
                )
            }
            .await,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Conformance reports preserve the host-masked provider reasons and details;
    // low-level decode/IO failures retain their stable categories.
    #[test]
    fn diagnostic_categories_and_provider_messages() {
        let secret = "vendor explanation";
        let errors = [
            (Error::InvalidResponse("expected value".into()), "decode"),
            (Error::Transport("connection refused".into()), "transport"),
            (Error::Protocol(ProtocolError::Refused { reason: secret.into() }), "http 422 refused: vendor explanation"),
            (
                Error::Protocol(ProtocolError::Internal { reason: secret.into(), provider_error: secret.into() }),
                "http 500 internal: vendor explanation; vendor explanation",
            ),
            (Error::NotReady(Readiness::Unknown { reason: secret.into() }), "not ready: unknown: vendor explanation"),
        ];
        for (error, expected) in errors {
            assert_eq!(error.category(), expected);
        }
        assert_eq!(std::io::Error::new(std::io::ErrorKind::TimedOut, secret).category(), "timeout");
    }
    // Conformance retains the host's readiness reason for both initial refusal
    // and readiness timeout, rather than collapsing either to a bare category.
    #[test]
    fn readiness_diagnostics_retain_reasons() {
        for readiness in [
            Readiness::Unknown { reason: "provider validation".into() },
            Readiness::MissingCredential { reason: "provider validation".into() },
            Readiness::MissingTool { reason: "provider validation".into() },
        ] {
            assert!(Error::NotReady(readiness.clone()).category().contains("provider validation"));
            assert!(Error::ReadinessTimeout(readiness).category().contains("provider validation"));
        }
    }
    // Billing settle accepts zero through one day and refuses typos/overflow
    // before any endpoint calls; it is independent of request/event timeouts.
    #[test]
    fn billing_settle_boundaries() {
        for (millis, valid) in [(0, true), (1, true), (86_400_000, true), (86_400_001, false), (u64::MAX, false)] {
            assert_eq!(validate_billing_settle(millis).is_ok(), valid);
        }
    }
    // Deserializing partial options keeps the established defaults, rejects
    // zero/overflowing timer values, and permits bounded live-provider deadlines.
    #[test]
    fn timeout_options_defaults_and_boundaries() {
        let timeouts: Timeouts = serde_json::from_str(r#"{"startup_seconds":120,"transition_seconds":600}"#).unwrap();
        assert_eq!(timeouts.startup_seconds, 120);
        assert_eq!(timeouts.transition_seconds, 600);
        assert_eq!(timeouts.record_seconds, 20);
        assert_eq!(timeouts.request_seconds, 30);
        assert!(timeouts.validate().is_ok());
        for value in [0, 1, 86400, 86401, u64::MAX] {
            let timeouts = Timeouts { request_seconds: value, ..Default::default() };
            assert_eq!(timeouts.validate().is_ok(), (1..=86400).contains(&value));
        }
    }
    // Exhaust the interesting floating-point classes: infinities, NaN, negative,
    // both signed zeroes, smallest positive and largest finite representable values.
    // Hours are finite/nonnegative, CPUs finite/positive, credits finite (debt is legal).
    #[test]
    fn numeric_output_boundaries() {
        let period = Period::new("2026-01-01T00:00:00Z".parse().unwrap(), "2026-01-01T00:00:00Z".parse().unwrap()).unwrap();
        for value in [f64::NEG_INFINITY, -1., -0., 0., f64::MIN_POSITIVE, 1., f64::MAX, f64::INFINITY, f64::NAN] {
            let size = Size { cpus: 1., memory_bytes: 0, disk_bytes: 0 };
            let usage = Usage { measurements: None, period: period.clone(), environment_hours: vec![SizeUsage { size, hours: value }] };
            assert_eq!(valid_usage(&usage, &period).is_ok(), value.is_finite() && value >= 0.);
            let quota = Quota {
                resources: vec![],
                credits_remaining: Some(value),
                credit_unit: None,
                concurrency_in_use: None,
                concurrency_limit: None,
            };
            assert_eq!(valid_quota(&quota).is_ok(), value.is_finite());
            // Aggregated cost and resource quota figures must be finite and
            // nonnegative; unknown credit balances may still be negative.
            let aggregate = Usage {
                period: period.clone(),
                environment_hours: vec![],
                measurements: Some(UsageMeasurements {
                    scope: UsageScope::Provider,
                    resources: [(ResourceKind::Cpu, Quantity { amount: value, unit: "{vCPU}.s".into() })].into(),
                    cost: None,
                }),
            };
            assert_eq!(valid_usage(&aggregate, &period).is_ok(), value.is_finite() && value >= 0.0);
            let resources = Quota {
                resources: vec![ResourceQuota {
                    key: QuotaKey { region: None, class: None, resource: ResourceKind::Cpu },
                    unit: "{vCPU}".into(),
                    in_use: value,
                    limit: Some(10.0),
                }],
                credits_remaining: None,
                ..quota
            };
            assert_eq!(valid_quota(&resources).is_ok(), value.is_finite() && value >= 0.0);
            assert_eq!(valid_size(&Size { cpus: value, memory_bytes: 0, disk_bytes: 0 }), value.is_finite() && value > 0.);
        }
        assert!(valid_usage(&Usage { measurements: None, period: period.clone(), environment_hours: vec![] }, &period).is_ok());
        let other = Period::new("2025-01-01T00:00:00Z".parse().unwrap(), "2026-01-01T00:00:00Z".parse().unwrap()).unwrap();
        assert!(valid_usage(&Usage { measurements: None, period: other, environment_hours: vec![] }, &period).is_err());
    }
}

mod host;
pub use host::{configuration_contract, error_contract, lifecycle_sequence, optional_contract, poll_contract, stream_contract};
use host::{fixture, host_fixtures};

mod tools;
pub use tools::{ToolsEvidence, vessel_tools};

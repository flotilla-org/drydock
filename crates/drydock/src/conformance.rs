//! Endpoint-driven ADR 0070 scenarios. No reference-host implementation is used.
//! The caller configures/authenticates the client and owns the host's lifetime.
use drydock_client::{Client, Error, Records};
use drydock_protocol::*;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Result<T> = std::result::Result<T, String>;
#[derive(Clone, Deserialize, Serialize)]
pub struct Options {
    pub request: ProvisionRequest,
    #[serde(default)]
    pub timeouts: Timeouts,
    /// Only hermetic echo fixtures may enable this. Real agents speak their own protocol.
    #[serde(default)]
    pub echo_relay: bool,
    /// Command must exercise the returned reach recipe and exit only after a byte round trip.
    /// Receives the recipe on stdin, never argv or logs. For SSH it owns the matching key.
    pub reach_probe: Option<Vec<String>>,
    /// Root guest probe: emit exactly the documented JSON and close the stream.
    /// The exec byte-stream protocol has no process exit-status channel.
    pub egress_probe: Option<ExecRequest>,
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
    fn category(&self) -> String;
}
impl SafeError for Error {
    fn category(&self) -> String {
        match self {
            Error::Protocol(error) => format!("http {} {}", error.status(), error.class()),
            Error::InvalidResponse => "decode".into(),
            Error::Transport => "transport".into(),
            Error::InvalidRequest => "invalid request".into(),
            Error::VersionMismatch => "version mismatch".into(),
            Error::RateLimited => "rate limited".into(),
            Error::NotReady(_) => "not ready".into(),
            Error::ReadinessTimeout(_) => "startup timeout".into(),
        }
    }
}
impl SafeError for std::io::Error {
    fn category(&self) -> String {
        if self.kind() == std::io::ErrorKind::TimedOut { "timeout" } else { "io" }.into()
    }
}
impl SafeError for serde_json::Error {
    fn category(&self) -> String {
        "decode".into()
    }
}
impl SafeError for tokio::time::error::Elapsed {
    fn category(&self) -> String {
        "timeout".into()
    }
}
fn transport(error: impl SafeError) -> String {
    // Only static categories and numeric status: no vendor text or probe output.
    error.category()
}
async fn observe(client: &Client, since: Option<&str>, timeouts: &Timeouts) -> Result<Records> {
    tokio::time::timeout(Duration::from_secs(timeouts.headers_seconds), client.observe(since)).await.map_err(transport)?.map_err(transport)
}
async fn next(records: &mut Records, timeouts: &Timeouts) -> Result<ObserveRecord> {
    tokio::time::timeout(Duration::from_secs(timeouts.record_seconds), records.next())
        .await
        .map_err(transport)?
        .map_err(transport)?
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
    .map_err(transport)?
}
fn valid_usage(usage: &Usage, period: &Period) -> Result<()> {
    require(&usage.period == period, "usage period differs from request")?;
    require(
        usage.environment_hours.iter().all(|row| row.hours.is_finite() && row.hours >= 0.0 && valid_size(&row.size)),
        "invalid usage size or hours",
    )
}
fn valid_size(size: &Size) -> bool {
    size.cpus.is_finite() && size.cpus > 0.0
}
fn valid_quota(quota: &Quota) -> Result<()> {
    require(quota.credits_remaining.is_none_or(f64::is_finite), "nonfinite credits")
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
    let timeouts = &options.timeouts;
    let client = &client.clone().with_request_timeout(Duration::from_secs(timeouts.request_seconds));
    let mut owned_ids = std::collections::BTreeSet::new();
    let hello = match client.hello().await {
        Ok(hello) => hello,
        Err(error) => {
            report.record("hello", Err(transport(error)));
            return report;
        }
    };
    let Some(declaration) = hello.providers.iter().find(|d| d.provider == provider) else {
        report.record("hello", Err("provider absent".into()));
        return report;
    };
    let caps = &declaration.capabilities;
    report.record("authentication", client.authentication_check().await.map_err(transport));
    report.record("readiness", require(matches!(declaration.readiness, Readiness::Ready), "provider not ready"));
    if caps.quota {
        match client.quota(provider).await {
            Ok(quota) => {
                report.record("quota_before", valid_quota(&quota));
                report.quota_before = Some(quota);
            }
            Err(e) => report.record("quota_before", Err(transport(e))),
        }
    }
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
    let body = serde_json::to_value(&options.request).expect("serializable provision request");
    let path = ["v1", "providers", provider, "environments"];
    let (first, second) = tokio::join!(client.wire("POST", &path, &[], Some(&body)), client.wire("POST", &path, &[], Some(&body)));
    let first_status = first.as_ref().ok().map(|(status, _)| *status);
    let provisioned = match first {
        Ok((status, value)) if status == 200 || status == 201 => {
            serde_json::from_value::<Environment>(value).map_err(|_| Error::InvalidResponse)
        }
        Ok((_, value)) => Err(serde_json::from_value::<ProtocolError>(value).map(Error::Protocol).unwrap_or(Error::InvalidResponse)),
        Err(error) => Err(error),
    };
    let environment = match provisioned {
        Ok(environment) => environment,
        Err(e) => {
            report.record("provision", Err(transport(e)));
            report.record("cleanup_after_failed_provision", cleanup(client, provider, &options.request.label, &owned_ids).await);
            finish_report(client, provider, caps, &mut report, start, period_start).await;
            return report;
        }
    };
    owned_ids.insert(environment.id.clone());
    report.record(
        "concurrent_label",
        async {
            let (status, value) = second.map_err(transport)?;
            let other: Environment = serde_json::from_value(value).map_err(transport)?;
            let same = other.id == environment.id;
            owned_ids.insert(other.id.clone());
            require(
                matches!((first_status, status), (Some(200), 201) | (Some(201), 200)) && same,
                "concurrent retries must return one creation and one existing resource",
            )
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
    report.record(
        "idempotent_label",
        async {
            let again = client.provision(provider, &options.request).await.map_err(transport)?;
            let same = again.id == environment.id && again.label == environment.label;
            owned_ids.insert(again.id.clone());
            require(same, "duplicate label created another environment")
        }
        .await,
    );
    report.record(
        "list_readoption",
        async {
            let rows = client.list(provider).await.map_err(transport)?;
            let matches: Vec<_> = rows.iter().filter(|e| e.label == environment.label).collect();
            require(matches.len() == 1 && matches[0].id == environment.id, "list did not uniquely re-adopt label")
        }
        .await,
    );
    let created = report.capture(
        "created_event",
        async {
            transition(records.as_mut().ok_or("cannot observe")?, provider, &environment.id, |e| matches!(e, EventKind::Created), timeouts)
                .await
        }
        .await,
    );
    let running = report.capture(
        "running_event",
        async {
            let event = transition(
                records.as_mut().ok_or("cannot observe")?,
                provider,
                &environment.id,
                |e| matches!(e, EventKind::Running { .. }),
                timeouts,
            )
            .await?;
            let EventKind::Running { granted_size } = &event.event else { unreachable!() };
            let current = client.inspect(provider, &environment.id).await.map_err(transport)?;
            require(
                valid_size(granted_size)
                    && current.granted_size.as_ref() == Some(granted_size)
                    && matches!(current.state, Observation::Running),
                "running event has wrong granted size or billing state",
            )?;
            Ok(event)
        }
        .await,
    );
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
    if caps.suspend_resume
        && let Some(token) = report.capture("suspend", client.suspend(provider, &environment.id).await.map_err(transport))
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
                require(running.as_ref().is_none_or(|event| stopped.cursor != event.cursor), "resume replayed old cursor")
            }
            .await,
        );
        report.record(
            "stopped_billing",
            async {
                require(
                    matches!(client.inspect(provider, &environment.id).await.map_err(transport)?.state, Observation::Stopped { .. }),
                    "suspended environment still bills as running",
                )
            }
            .await,
        );
        if report.capture("resume", client.resume(provider, &environment.id, &token).await.map_err(transport)).is_some() {
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
    report.record("semantic_requests", semantic_requests(client, provider, options, &mut owned_ids).await);
    report.record(
        "explicit_nulls",
        async {
            let (status, value) =
                client.wire("GET", &["v1", "providers", provider, "environments", &environment.id], &[], None).await.map_err(transport)?;
            require(
                status == 200 && value.get("label").is_some() && value.get("granted_size").is_some(),
                "optional environment field omitted",
            )?;
            if caps.quota {
                let (status, value) = client.wire("GET", &["v1", "providers", provider, "quota"], &[], None).await.map_err(transport)?;
                require(status == 200, "quota refused")?;
                for field in ["credits_remaining", "credit_unit", "concurrency_in_use", "concurrency_limit"] {
                    require(value.get(field).is_some(), "optional quota field omitted instead of null")?;
                }
            }
            Ok(())
        }
        .await,
    );
    report.record("reach_byte_stream", reach(client, provider, &environment.id, options).await);
    report.record(
        "typed_refusal",
        async {
            let mut invalid = options.request.clone();
            invalid.prepared.provider = format!("{provider}-other");
            invalid.label.push_str("-refused");
            match client.provision(provider, &invalid).await {
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
    if caps.egress.enforcement == Enforcement::Enforced {
        report.record("enforced_egress", egress(client, provider, &environment, options).await);
    }
    report.record(
        "destroy_absent",
        async {
            client.destroy(provider, &environment.id).await.map_err(transport)?;
            client.destroy(provider, &environment.id).await.map_err(transport)?;
            require(
                !client.list(provider).await.map_err(transport)?.iter().any(|row| row.id == environment.id),
                "destroyed environment still listed",
            )
        }
        .await,
    );
    report.record("cleanup", cleanup(client, provider, &options.request.label, &owned_ids).await);
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
    finish_report(client, provider, caps, &mut report, start, period_start).await;
    report
}
async fn cleanup(client: &Client, provider: &str, label: &str, known: &std::collections::BTreeSet<String>) -> Result<()> {
    let labels = [
        label.to_owned(),
        format!("{label}-refused"),
        format!("{label}-invalid-cpus"),
        format!("{label}-invalid-memory_bytes"),
        format!("{label}-invalid-disk_bytes"),
    ];
    let owns = |row: &Environment| known.contains(&row.id) || row.label.as_ref().is_some_and(|label| labels.contains(label));
    let mut ids = known.clone();
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
                failure = Some(transport(error));
            }
        }
    }
    if let Some(error) = failure {
        return Err(format!("cleanup: {error}"));
    }
    let rows = match client.list(provider).await {
        Ok(rows) => rows,
        Err(_) => client.list(provider).await.map_err(transport)?,
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
            Err(e) => report.record("quota_after", Err(transport(e))),
        }
    }
    if caps.usage {
        let period = Period::new(period_start.into(), chrono::Utc::now().max(period_start).into()).expect("ordered run timestamps");
        match client.usage(provider, &period).await {
            Ok(usage) => {
                report.record("usage", valid_usage(&usage, &period));
                report.usage = Some(usage);
            }
            Err(e) => report.record("usage", Err(transport(e))),
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
    let recipe = client.reach(provider, id).await.map_err(transport)?;
    if let Some(command) = &options.reach_probe {
        let (program, args) = command.split_first().ok_or("empty reach probe")?;
        let mut child = tokio::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(transport)?;
        let status = tokio::time::timeout(Duration::from_secs(options.timeouts.probe_seconds), async {
            let mut input = child.stdin.take().ok_or("probe stdin unavailable")?;
            input.write_all(&serde_json::to_vec(&recipe).map_err(transport)?).await.map_err(transport)?;
            drop(input);
            child.wait().await.map_err(transport)
        })
        .await
        .map_err(transport)??;
        return require(status.success(), "reach round trip probe failed");
    }
    if options.echo_relay && matches!(recipe, Reach::Relay { .. }) {
        let mut stream = client.relay(provider, id).await.map_err(transport)?;
        let bytes = b"drydock-conformance\0\xff\n";
        return tokio::time::timeout(Duration::from_secs(options.timeouts.probe_seconds), async {
            stream.write_all(bytes).await.map_err(transport)?;
            let mut actual = vec![0; bytes.len()];
            stream.read_exact(&mut actual).await.map_err(transport)?;
            require(actual == bytes, "reach corrupted bytes")
        })
        .await
        .map_err(transport)?;
    }
    Err("reach requires a recipe round-trip probe (or hermetic echo relay)".into())
}
async fn egress(client: &Client, provider: &str, environment: &Environment, options: &Options) -> Result<()> {
    require(environment.egress == Enforcement::Enforced, "Enforced declaration downgraded")?;
    require(
        matches!(&options.request.egress, EgressRequest::DenyAll { direct } if direct.len() == 1),
        "Enforced check requires DenyAll with exactly one destination",
    )?;
    let command = options.egress_probe.as_ref().ok_or("Enforced check requires root guest probe")?;
    let mut stream = client.exec(provider, &environment.id, command).await.map_err(transport)?;
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(options.timeouts.probe_seconds), (&mut stream).take(4097).read_to_end(&mut bytes))
        .await
        .map_err(transport)?
        .map_err(transport)?;
    require(bytes.len() <= 4096, "oversized guest probe output")?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(transport)?;
    require(
        value == serde_json::json!({"uid":0,"listed_direct":true,"unlisted_canary":false,"raw_dns":false}),
        "root egress probe violated isolation",
    )
}

async fn semantic_requests(
    client: &Client,
    provider: &str,
    options: &Options,
    owned_ids: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    let original = serde_json::to_value(&options.request).map_err(transport)?;
    // Boundary generator: negative, zero, overflow and wrong-type values cross
    // the CPU and unsigned byte-size domains, including JSON exponent overflow.
    for (field, values) in [
        ("cpus", vec![serde_json::json!(-1), serde_json::json!(0), serde_json::Value::Null, serde_json::json!("NaN")]),
        ("memory_bytes", vec![serde_json::json!(-1), serde_json::json!(1.5), serde_json::json!(1e20)]),
        ("disk_bytes", vec![serde_json::json!(-1), serde_json::json!(1.5)]),
    ] {
        for value in values {
            let mut invalid = original.clone();
            invalid["size"][field] = value;
            invalid["label"] = serde_json::json!(format!("{}-invalid-{field}", options.request.label));
            let (status, body) =
                client.wire("POST", &["v1", "providers", provider, "environments"], &[], Some(&invalid)).await.map_err(transport)?;
            if status < 300
                && let Some(id) = body["id"].as_str()
            {
                owned_ids.insert(id.to_owned());
            }
            require(
                status == 422 && matches!(serde_json::from_value::<ProtocolError>(body), Ok(ProtocolError::Refused { .. })),
                "invalid size was not refused before provisioning",
            )?;
        }
    }
    for (start, end) in [("bad", "2026-01-01T00:00:00Z"), ("2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z")] {
        let (status, body) = client
            .wire("GET", &["v1", "providers", provider, "usage"], &[("start", start), ("end", end)], None)
            .await
            .map_err(transport)?;
        require(
            status == 422 && matches!(serde_json::from_value::<ProtocolError>(body), Ok(ProtocolError::Refused { .. })),
            "invalid period or timestamp accepted",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Operator diagnostics identify failure classes but never include vendor
    // reasons, raw errors or readiness text, which may contain credentials.
    #[test]
    fn safe_diagnostic_categories() {
        let secret = "must-never-appear";
        let errors = [
            (Error::InvalidResponse, "decode"),
            (Error::Transport, "transport"),
            (Error::Protocol(ProtocolError::Refused { reason: secret.into() }), "http 422 refused"),
            (Error::Protocol(ProtocolError::Internal { reason: secret.into(), provider_error: Secret::new(secret) }), "http 500 internal"),
            (Error::NotReady(Readiness::Unknown { reason: secret.into() }), "not ready"),
        ];
        for (error, expected) in errors {
            assert_eq!(transport(error), expected);
        }
        assert_eq!(transport(std::io::Error::new(std::io::ErrorKind::TimedOut, secret)), "timeout");
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
            let usage = Usage { period: period.clone(), environment_hours: vec![SizeUsage { size, hours: value }] };
            assert_eq!(valid_usage(&usage, &period).is_ok(), value.is_finite() && value >= 0.);
            let quota = Quota { credits_remaining: Some(value), credit_unit: None, concurrency_in_use: None, concurrency_limit: None };
            assert_eq!(valid_quota(&quota).is_ok(), value.is_finite());
            assert_eq!(valid_size(&Size { cpus: value, memory_bytes: 0, disk_bytes: 0 }), value.is_finite() && value > 0.);
        }
        assert!(valid_usage(&Usage { period: period.clone(), environment_hours: vec![] }, &period).is_ok());
        let other = Period::new("2025-01-01T00:00:00Z".parse().unwrap(), "2026-01-01T00:00:00Z".parse().unwrap()).unwrap();
        assert!(valid_usage(&Usage { period: other, environment_hours: vec![] }, &period).is_err());
    }
}

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
    /// Only hermetic echo fixtures may enable this. Real agents speak their own protocol.
    #[serde(default)]
    pub echo_relay: bool,
    /// Command must exercise the returned reach recipe and exit only after a byte round trip.
    /// Receives the recipe on stdin, never argv or logs. For SSH it owns the matching key.
    pub reach_probe: Option<Vec<String>>,
    /// Root guest probe: exit zero and emit exactly the JSON contract documented in README.
    pub egress_probe: Option<ExecRequest>,
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
fn transport(_: impl std::fmt::Display) -> String {
    // Neither vendor errors nor probe output are safe diagnostics.
    "request, stream or probe failed".into()
}
async fn observe(client: &Client, since: Option<&str>) -> Result<Records> {
    tokio::time::timeout(Duration::from_secs(20), client.observe(since)).await.map_err(transport)?.map_err(transport)
}
async fn next(records: &mut Records) -> Result<ObserveRecord> {
    tokio::time::timeout(Duration::from_secs(20), records.next())
        .await
        .map_err(transport)?
        .map_err(transport)?
        .ok_or_else(|| "event stream ended".into())
}
fn cursor(record: &ObserveRecord) -> &str {
    match record {
        ObserveRecord::Event { event } => &event.cursor,
        ObserveRecord::Snapshot { cursor, .. } => cursor,
    }
}
async fn transition(records: &mut Records, provider: &str, id: &str, predicate: impl Fn(&EventKind) -> bool) -> Result<Event> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let ObserveRecord::Event { event } = next(records).await?
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
    let mut records = observe(client, None).await.ok();
    if let Some(records) = records.as_mut() {
        report.record(
            "initial_snapshot",
            match next(records).await {
                Ok(ObserveRecord::Snapshot { unavailable_providers, .. }) => {
                    require(!unavailable_providers.contains_key(provider), "provider inventory unavailable")
                }
                _ => Err("initial observation must mark a snapshot".into()),
            },
        );
    } else {
        report.record("initial_snapshot", Err("cannot observe".into()));
    }
    let body = serde_json::to_value(&options.request).expect("serializable provision request");
    let path = ["v1", "providers", provider, "environments"];
    let (first, second) = tokio::join!(client.wire("POST", &path, &[], Some(&body)), client.wire("POST", &path, &[], Some(&body)));
    let first_status = first.as_ref().ok().map(|(status, _)| *status);
    let provisioned = match first {
        Ok((status, value)) if status == 200 || status == 201 => {
            serde_json::from_value::<Environment>(value).map_err(|_| Error::InvalidResponse)
        }
        _ => Err(Error::InvalidResponse),
    };
    let environment = match provisioned {
        Ok(environment) => environment,
        Err(e) => {
            report.record("provision", Err(transport(e)));
            // A lost or malformed response may still have created a resource.
            // Discover only this run's unique label, and report cleanup failure.
            report.record(
                "cleanup_after_failed_provision",
                async {
                    let rows = client.list(provider).await.map_err(transport)?;
                    for row in rows.into_iter().filter(|row| row.label.as_deref() == Some(options.request.label.as_str())) {
                        client.destroy(provider, &row.id).await.map_err(transport)?;
                    }
                    Ok(())
                }
                .await,
            );
            finish_report(client, provider, caps, &mut report, start, period_start).await;
            return report;
        }
    };
    report.record(
        "concurrent_label",
        async {
            let (status, value) = second.map_err(transport)?;
            let other: Environment = serde_json::from_value(value).map_err(transport)?;
            let same = other.id == environment.id;
            if !same {
                let _ = client.destroy(provider, &other.id).await;
            }
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
            if again.id != environment.id {
                let _ = client.destroy(provider, &again.id).await;
            }
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
    let mut resumed_records = None;
    report.record(
        "running_event",
        async {
            let records = records.as_mut().ok_or("cannot observe")?;
            let event = transition(records, provider, &environment.id, |e| matches!(e, EventKind::Running { .. })).await?;
            let EventKind::Running { granted_size } = &event.event else { unreachable!() };
            // Provision may return an environment still booting. Compare granted
            // size against current inventory after Running, not the creation reply.
            let running = client.inspect(provider, &environment.id).await.map_err(transport)?;
            require(
                valid_size(granted_size)
                    && running.granted_size.as_ref() == Some(granted_size)
                    && matches!(running.state, Observation::Running),
                "running event has wrong granted size or billing state",
            )?;
            // Typed decoding requires timestamp and its source; reconnect is exclusive or a marked snapshot.
            let mut resumed = observe(client, Some(&event.cursor)).await?;
            let mut gap = observe(client, Some("conformance-unknown-cursor")).await?;
            require(matches!(next(&mut gap).await?, ObserveRecord::Snapshot { .. }), "unknown cursor did not mark snapshot")?;
            // A subsequent lifecycle transition below validates the resumed cursor too.
            if caps.suspend_resume {
                let token = client.suspend(provider, &environment.id).await.map_err(transport)?;
                let stopped = transition(&mut resumed, provider, &environment.id, |e| {
                    matches!(e, EventKind::Stopped { .. } | EventKind::Paused { .. })
                })
                .await?;
                require(cursor(&ObserveRecord::Event { event: stopped.clone() }) != event.cursor, "resume replayed old cursor")?;
                require(
                    matches!(client.inspect(provider, &environment.id).await.map_err(transport)?.state, Observation::Stopped { .. }),
                    "suspended environment still bills as running",
                )?;
                client.resume(provider, &environment.id, &token).await.map_err(transport)?;
                transition(&mut resumed, provider, &environment.id, |e| matches!(e, EventKind::Resumed | EventKind::Running { .. }))
                    .await?;
            }
            resumed_records = Some(resumed);
            Ok(())
        }
        .await,
    );
    report.record("semantic_requests", semantic_requests(client, provider, options).await);
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
                    let _ = client.destroy(provider, &unexpected.id).await;
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
    report.record(
        "typed_loss",
        async {
            let event =
                transition(resumed_records.as_mut().or(records.as_mut()).ok_or("cannot observe")?, provider, &environment.id, |e| {
                    matches!(e, EventKind::Gone { .. })
                })
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
        let mut input = child.stdin.take().ok_or("probe stdin unavailable")?;
        input.write_all(&serde_json::to_vec(&recipe).map_err(transport)?).await.map_err(transport)?;
        drop(input);
        return require(
            tokio::time::timeout(Duration::from_secs(30), child.wait()).await.map_err(transport)?.map_err(transport)?.success(),
            "reach round trip probe failed",
        );
    }
    if options.echo_relay && matches!(recipe, Reach::Relay { .. }) {
        let mut stream = client.relay(provider, id).await.map_err(transport)?;
        let bytes = b"drydock-conformance\0\xff\n";
        return tokio::time::timeout(Duration::from_secs(10), async {
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
    tokio::time::timeout(Duration::from_secs(30), (&mut stream).take(4097).read_to_end(&mut bytes))
        .await
        .map_err(transport)?
        .map_err(transport)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(transport)?;
    require(
        value == serde_json::json!({"uid":0,"listed_direct":true,"unlisted_canary":false,"raw_dns":false}),
        "root egress probe violated isolation",
    )
}

async fn semantic_requests(client: &Client, provider: &str, options: &Options) -> Result<()> {
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
                let _ = client.destroy(provider, id).await;
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

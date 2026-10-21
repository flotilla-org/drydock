//! Deterministic host contract scenarios. Only the public endpoint and fixture
//! exec commands cross this seam; no Rust module or Host construction lives here.
use super::*;
use serde_json::{Value, json};

pub(super) async fn fixture(client: &Client, provider: &str, id: &str, args: &[String]) -> Result<Value> {
    let mut command = vec!["drydock-fixture".into()];
    command.extend_from_slice(args);
    let mut stream = client.exec(provider, id, &ExecRequest { command }).await.map_err(SafeError::category)?;
    let mut bytes = vec![];
    tokio::time::timeout(Duration::from_secs(5), (&mut stream).take(65537).read_to_end(&mut bytes))
        .await
        .map_err(SafeError::category)?
        .map_err(SafeError::category)?;
    require(bytes.len() <= 65536, "fixture control response too large")?;
    serde_json::from_slice(&bytes).map_err(SafeError::category)
}
pub(super) async fn host_fixtures(
    client: &Client,
    provider: &str,
    options: &Options,
    environment: &Environment,
    report: &mut Report,
    ids: &mut Resources,
) {
    let Some(configuration) = &options.fixture_configuration else {
        report.record("host_fixture_configuration", Err("host fixture scenarios require explicit configuration".into()));
        return;
    };
    report.record(
        "configuration_atomic",
        async {
            let before = client.hello().await.map_err(SafeError::category)?;
            let mut invalid = configuration.clone();
            invalid.modules.push(ModuleConfiguration { name: "invalid".into(), entrypoint: "unknown".into() });
            let (status, _) = client
                .wire(Method::PUT, &["v1", "config"], &[], Some(&serde_json::to_value(invalid).map_err(SafeError::category)?))
                .await
                .map_err(SafeError::category)?;
            let after = client.hello().await.map_err(SafeError::category)?;
            require(status == 422 && before == after, "configuration rejection was not atomic")
        }
        .await,
    );
    report.record("credential_preserves_inventory", configuration_contract(client, configuration, provider, environment).await);
    error_contract(client, configuration, report).await;
    let peer = configuration
        .providers
        .iter()
        .find(|candidate| candidate.name != provider && !candidate.settings.contains_key("fault"))
        .map(|candidate| candidate.name.as_str())
        .unwrap_or("missing-peer");
    report.record("host_optional_operations", optional_contract(client, provider, peer, &options.request, &options.timeouts).await);
    report.record(
        "host_lifecycle_sequence",
        lifecycle_sequence(
            client,
            [provider, peer],
            &options.request.label,
            &[(false, 0, false), (true, 0, false), (false, 0, false), (false, 1, true), (false, 0, true), (true, 0, true)],
        )
        .await,
    );
    report.record("host_provider_isolation", provider_isolation(client, [provider, peer], environment, options).await);

    report.record("host_stream_upgrades", stream_contract(client, provider, &environment.id, &options.timeouts).await);
    poll_cases(client, provider, options, environment, report, ids).await;
    for (name, cause) in loss_cases() {
        report.record(
            &format!("loss_{name}"),
            async {
                let mut request = options.request.clone();
                request.label = ids.label(ProbeLabel::Auxiliary(format!("loss-{name}")));
                let row = client.provision(provider, &request).await.map_err(SafeError::category)?;
                ids.insert(row.id.clone());
                let mut records = observe(client, None, &options.timeouts).await?;
                next(&mut records, &options.timeouts).await?;
                fixture(
                    client,
                    provider,
                    &environment.id,
                    &[
                        "state".into(),
                        row.id.clone(),
                        serde_json::to_string(&Observation::Gone { cause: cause.clone() }).map_err(SafeError::category)?,
                    ],
                )
                .await?;
                let event =
                    transition(&mut records, provider, &row.id, |kind| matches!(kind, EventKind::Gone { .. }), &options.timeouts).await?;
                require(matches!(event.event, EventKind::Gone { cause: actual } if actual == cause), "loss cause changed or was untyped")
            }
            .await,
        );
    }
}
fn loss_cases() -> Vec<(&'static str, GoneCause)> {
    vec![
        ("lifetime_cap_reached", GoneCause::LifetimeCapReached),
        ("evicted_by_provider", GoneCause::EvictedByProvider),
        ("host_out_of_memory", GoneCause::HostOutOfMemory),
        ("vmm_exited", GoneCause::VmmExited { code: 17 }),
        ("guest_powered_off", GoneCause::GuestPoweredOff),
    ]
}
fn error_cases() -> Vec<ProtocolError> {
    vec![
        ProtocolError::Refused { reason: "fixture".into() },
        ProtocolError::unavailable("fixture", Some(3)),
        ProtocolError::RateLimited { reason: "fixture".into(), retry_after: Some(7) },
        ProtocolError::QuotaExhausted { reason: "fixture".into() },
        ProtocolError::CredentialRejected { reason: "fixture".into() },
        ProtocolError::Internal { reason: "fixture".into(), provider_error: "vendor raw".into() },
        ProtocolError::NotFound { reason: "fixture".into() },
        ProtocolError::MethodNotAllowed { reason: "fixture".into() },
    ]
}
/// Extracted from the host socket error scenarios. Every class/status/retry
/// header, plus credential rejection/readiness recovery, crosses the endpoint.
pub async fn error_contract(client: &Client, base: &HostConfiguration, report: &mut Report) {
    let Some(module) = base.modules.first() else {
        report.record("host_configuration", Err("no fixture module".into()));
        return;
    };
    let mut configuration = base.clone();
    for error in error_cases() {
        let settings = match serde_json::from_value(json!({"fault":error,"fixture":true,"fixture_push":true,"poll_interval_ms":100000})) {
            Ok(value) => value,
            Err(error) => {
                report.record("host_configuration", Err(error.category()));
                return;
            }
        };
        configuration.providers.push(ProviderConfiguration {
            name: format!("error-{}", error.class()),
            module: module.name.clone(),
            settings,
            credential: CredentialMode::Direct { credential_reference: "fixture".into() },
        });
    }
    let configured = client.configure(&configuration).await.map_err(SafeError::category);
    if report.capture("host_configuration", configured).is_none() {
        return;
    }
    for error in error_cases() {
        let provider = format!("error-{}", error.class());
        report.record(
            &format!("error_{}", error.class()),
            async {
                client.credential(&provider, Secret::new("fixture-token")).await.map_err(SafeError::category)?;
                let response = client
                    .wire_response(Method::GET, &["v1", "providers", &provider, "environments"], &[], None)
                    .await
                    .map_err(SafeError::category)?;
                require(response.status == error.status(), "wrong typed error HTTP status")?;
                let actual: ProtocolError = serde_json::from_value(response.body).map_err(SafeError::category)?;
                let mut actual_fields = serde_json::to_value(&actual).map_err(SafeError::category)?;
                let expected_fields = serde_json::to_value(&error).map_err(SafeError::category)?;
                let reason = actual_fields["reason"].as_str().unwrap_or_default();
                require(reason.ends_with(expected_fields["reason"].as_str().unwrap_or_default()), "typed error reason lost")?;
                actual_fields["reason"] = expected_fields["reason"].clone();
                require(actual_fields == expected_fields, "typed error fields lost")?;
                if let Some(retry) = error.retry_after() {
                    require(
                        response.headers.get("retry-after").and_then(|value| value.to_str().ok()) == Some(retry.to_string().as_str()),
                        "retry header differs from typed error",
                    )?;
                }
                if matches!(error, ProtocolError::CredentialRejected { .. }) {
                    let hello = client.hello().await.map_err(SafeError::category)?;
                    require(
                        hello
                            .providers
                            .iter()
                            .any(|p| p.provider == provider && matches!(p.readiness, Readiness::MissingCredential { .. })),
                        "credential rejection did not change readiness",
                    )?;
                    client.credential(&provider, Secret::new("refreshed")).await.map_err(SafeError::category)?;
                    require(
                        client
                            .hello()
                            .await
                            .map_err(SafeError::category)?
                            .providers
                            .iter()
                            .any(|p| p.provider == provider && matches!(p.readiness, Readiness::Ready)),
                        "credential refresh did not restore readiness",
                    )?;
                }
                Ok(())
            }
            .await,
        );
    }
}
/// Real relay and POST exec upgrades, including half close and payloads larger
/// than the reference stream buffer. Taken from the existing socket scenario.
pub async fn stream_contract(client: &Client, provider: &str, id: &str, timeouts: &Timeouts) -> Result<()> {
    for exec in [false, true] {
        let mut stream = if exec {
            client.exec(provider, id, &ExecRequest { command: vec!["cat".into()] }).await
        } else {
            client.relay(provider, id).await
        }
        .map_err(SafeError::category)?;
        let data: Vec<u8> = (0..200_000).map(|n| (n % 256) as u8).collect();
        let (mut read, mut write) = tokio::io::split(&mut stream);
        let result = tokio::time::timeout(Duration::from_secs(timeouts.probe_seconds), async {
            let (sent, received) = tokio::join!(
                async {
                    write.write_all(&data).await?;
                    write.shutdown().await
                },
                async {
                    let mut bytes = vec![];
                    read.read_to_end(&mut bytes).await?;
                    Ok::<_, std::io::Error>(bytes)
                }
            );
            sent.map_err(SafeError::category)?;
            require(received.map_err(SafeError::category)? == data, "upgrade corrupted bytes or half close")
        })
        .await
        .map_err(SafeError::category)?;
        result?;
    }
    let mut stream =
        client.exec(provider, id, &ExecRequest { command: vec!["echo".into(), "hello".into()] }).await.map_err(SafeError::category)?;
    let mut bytes = vec![];
    tokio::time::timeout(Duration::from_secs(timeouts.probe_seconds), (&mut stream).take(100).read_to_end(&mut bytes))
        .await
        .map_err(SafeError::category)?
        .map_err(SafeError::category)?;
    require(bytes == b"hello\n", "exec output differs")
}
pub async fn optional_contract(
    client: &Client,
    provider: &str,
    peer: &str,
    request: &ProvisionRequest,
    _timeouts: &Timeouts,
) -> Result<()> {
    let prepared = client
        .prepare(
            provider,
            &PrepareRequest {
                size: request.size.clone(),
                image_digest: request.prepared.image_digest.clone(),
                tools_digest: request.prepared.tools_digest.clone(),
            },
        )
        .await
        .map_err(SafeError::category)?;
    require(
        prepared
            == client
                .prepare(
                    provider,
                    &PrepareRequest {
                        size: request.size.clone(),
                        image_digest: prepared.image_digest.clone(),
                        tools_digest: prepared.tools_digest.clone(),
                    },
                )
                .await
                .map_err(SafeError::category)?,
        "prepare changed identity",
    )?;
    let mut cross = request.clone();
    cross.prepared = prepared;
    let refused = matches!(client.provision(peer, &cross).await, Err(Error::Protocol(ProtocolError::Refused { .. })));
    let mut peer_resources = Resources::new(&cross.label);
    peer_resources.register(&cross);
    cleanup(client, peer, &peer_resources).await?;
    require(refused, "cross-provider prepared form was accepted")?;
    let row = client.provision(provider, request).await.map_err(SafeError::category)?;
    let token = client.suspend(provider, &row.id).await.map_err(SafeError::category)?;
    require(client.suspend(provider, &row.id).await.map_err(SafeError::category)? == token, "repeated suspend changed token")?;
    require(
        matches!(
            client.inspect(provider, &row.id).await.map_err(SafeError::category)?.state,
            Observation::Stopped { cause: StopCause::SuspendedByRequest }
        ),
        "suspend observation cause changed",
    )?;
    for _ in 0..2 {
        client.resume(provider, &row.id, &token).await.map_err(SafeError::category)?;
    }
    require(
        matches!(client.inspect(provider, &row.id).await.map_err(SafeError::category)?.state, Observation::Running),
        "repeated resume did not run",
    )?;
    require(!client.export(provider, &row.id).await.map_err(SafeError::category)?.reference.is_empty(), "empty export reference")?;
    for path in [vec!["v1", "providers", provider, "environments", "usage"], vec!["v1", "providers", provider]] {
        let (status, value) = client.wire(Method::GET, &path, &[], None).await.map_err(SafeError::category)?;
        require(
            status == 404 && matches!(serde_json::from_value::<ProtocolError>(value), Ok(ProtocolError::NotFound { .. })),
            "opaque id or unknown route did not return typed NotFound",
        )?;
    }
    let (status, value) = client
        .wire(Method::GET, &["v1", "providers", provider, "environments", &row.id, "relay"], &[], None)
        .await
        .map_err(SafeError::category)?;
    require(
        status == 422 && matches!(serde_json::from_value::<ProtocolError>(value), Ok(ProtocolError::Refused { .. })),
        "relay accepted missing upgrade headers",
    )
}
/// Polling scenario port. Fixture commands alter vendor-visible inventory, not
/// host observer internals. Both independent hosts execute this same scenario.
async fn poll_cases(client: &Client, provider: &str, options: &Options, main: &Environment, report: &mut Report, ids: &mut Resources) {
    let timestamp = "2026-01-01T00:00:00Z";
    let mut request = options.request.clone();
    request.label = ids.label(ProbeLabel::Auxiliary("poll".into()));
    let Some(row) = report.capture("poll_provision", client.provision(provider, &request).await.map_err(SafeError::category)) else {
        return;
    };
    ids.insert(row.id.clone());
    let mut records = match observe(client, None, &options.timeouts).await {
        Ok(mut records) => {
            let _ = next(&mut records, &options.timeouts).await;
            records
        }
        Err(error) => {
            report.record("poll_timestamp", Err(error));
            return;
        }
    };
    report.record(
        "poll_timestamp",
        async {
            fixture(client, provider, &main.id, &["timestamp".into(), timestamp.into()]).await?;
            fixture(
                client,
                provider,
                &main.id,
                &[
                    "state".into(),
                    row.id.clone(),
                    serde_json::to_string(&Observation::Stopped { cause: StopCause::PausedByProvider }).map_err(SafeError::category)?,
                ],
            )
            .await?;
            let event =
                transition(&mut records, provider, &row.id, |kind| matches!(kind, EventKind::Paused { .. }), &options.timeouts).await?;
            require(
                event.timestamp == timestamp.parse::<Timestamp>().map_err(|_| "invalid fixture timestamp".to_owned())?
                    && event.timestamp_source == TimestampSource::Provider,
                "poll did not preserve provider timestamp/source",
            )
        }
        .await,
    );
    report.record(
        "poll_failed_list",
        async {
            fixture(client, provider, &main.id, &["inventory_error".into(), "true".into()]).await?;
            require(
                matches!(client.list(provider).await, Err(Error::Protocol(ProtocolError::Unavailable { .. }))),
                "fixture did not reject inventory",
            )?;
            let premature = tokio::time::timeout(Duration::from_millis(50), async {
                loop {
                    if let ObserveRecord::Event { event } = next(&mut records, &options.timeouts).await?
                        && event.id == row.id
                        && matches!(event.event, EventKind::Gone { .. })
                    {
                        return Ok::<_, String>(());
                    }
                }
            })
            .await;
            require(premature.is_err(), "failed list fabricated loss")
        }
        .await,
    );
    // Recovery is unconditional, including after a failed assertion.
    let _ = fixture(client, provider, &main.id, &["inventory_error".into(), "false".into()]).await;
    let _ = fixture(client, provider, &main.id, &["timestamp".into(), "".into()]).await;
    report.record(
        "loss_missing_on_list",
        async {
            fixture(client, provider, &main.id, &["forget".into(), row.id.clone()]).await?;
            let event =
                transition(&mut records, provider, &row.id, |kind| matches!(kind, EventKind::Gone { .. }), &options.timeouts).await?;
            require(
                matches!(event.event, EventKind::Gone { cause: GoneCause::MissingOnList })
                    && event.timestamp_source == TimestampSource::Adaptor,
                "authoritative disappearance has wrong cause or provenance",
            )
        }
        .await,
    );
    for (name, cause, cpus) in [("paused_by_provider", StopCause::PausedByProvider, 2.0), ("guest_halted", StopCause::GuestHalted, 3.0)] {
        report.record(
            &format!("billing_{name}"),
            async {
                let mut request = options.request.clone();
                request.label = ids.label(ProbeLabel::Auxiliary(format!("billing-{name}")));
                request.size.cpus = cpus;
                let row = client.provision(provider, &request).await.map_err(SafeError::category)?;
                ids.insert(row.id.clone());
                let mut events = observe(client, None, &options.timeouts).await?;
                next(&mut events, &options.timeouts).await?;
                fixture(
                    client,
                    provider,
                    &main.id,
                    &[
                        "state".into(),
                        row.id.clone(),
                        serde_json::to_string(&Observation::Stopped { cause: cause.clone() }).map_err(SafeError::category)?,
                    ],
                )
                .await?;
                let event = transition(
                    &mut events,
                    provider,
                    &row.id,
                    |kind| matches!(kind, EventKind::Stopped { .. } | EventKind::Paused { .. }),
                    &options.timeouts,
                )
                .await?;
                require(
                    matches!(event.event, EventKind::Stopped { cause: actual } | EventKind::Paused { cause: actual } if actual == cause),
                    "provider stop cause changed",
                )?;
                require(
                    client.inspect(provider, &row.id).await.map_err(SafeError::category)?.state == Observation::Stopped { cause },
                    "stopped inventory disagrees",
                )?;
                billing_window(
                    client,
                    provider,
                    &client.inspect(provider, &row.id).await.map_err(SafeError::category)?.granted_size.ok_or("missing granted size")?,
                    &row.id,
                    options.billing_sample_millis,
                    options.billing_settle_millis,
                    false,
                )
                .await
            }
            .await,
        );
    }
}

/// Run deterministic polling assertions against an already configured fixture host.
pub async fn poll_contract(client: &Client, provider: &str, options: &Options, main: &Environment, report: &mut Report) {
    let mut ids = Resources::new(&options.request.label);
    poll_cases(client, provider, options, main, report, &mut ids).await;
    // The supplied main environment belongs to the caller; only this scenario's
    // probe labels are in its resource set.
    ids.labels.remove(&options.request.label);
    report.record("poll_cleanup", cleanup(client, provider, &ids).await);
}

/// Generated lifecycle state-machine, extracted from the Rust socket property.
/// Callers supply operations; both providers are checked after every step.
pub async fn lifecycle_sequence(client: &Client, providers: [&str; 2], base: &str, steps: &[(bool, usize, bool)]) -> Result<()> {
    let mut resources = [Resources::new(base), Resources::new(base)];
    let result = async {
        // Reference-host scenarios accept tiny sizes; vendor conformance uses options.request.size.
        let preparation = PrepareRequest {
            size: Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
            image_digest: "sequence-image".into(),
            tools_digest: "sequence-tools".into(),
        };
        let prepared = [
            client.prepare(providers[0], &preparation).await.map_err(SafeError::category)?,
            client.prepare(providers[1], &preparation).await.map_err(SafeError::category)?,
        ];
        let mut model: std::collections::BTreeMap<(usize, usize), Environment> = Default::default();
        for (provider, label, delete) in steps {
            let index = usize::from(*provider);
            let name = providers[index];
            let key = (index, *label);
            if *delete {
                let id = model.remove(&key).map(|row| row.id).unwrap_or_else(|| "absent-sequence-id".into());
                client.destroy(name, &id).await.map_err(SafeError::category)?;
                client.destroy(name, &id).await.map_err(SafeError::category)?;
            } else {
                let label = resources[index].label(ProbeLabel::Auxiliary(format!("sequence-{label}")));
                let request = ProvisionRequest {
                    label,
                    prepared: prepared[index].clone(),
                    size: Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 },
                    egress: EgressRequest::default(),
                    ssh_public_key: None,
                };
                let (status, row) = client.provision_with_status(name, &request).await.map_err(SafeError::category)?;
                resources[index].insert(row.id.clone());
                require(status == if model.contains_key(&key) { 200 } else { 201 }, "sequence creation/retry status changed")?;
                if let Some(old) = model.get(&key) {
                    require(old == &row, "sequence retry created another environment")?;
                }
                model.insert(key, row);
            }
            for (index, provider) in providers.iter().enumerate() {
                let actual: Vec<_> = client
                    .list(provider)
                    .await
                    .map_err(SafeError::category)?
                    .into_iter()
                    .filter(|row| row.label.as_ref().is_some_and(|label| resources[index].labels.contains(label)))
                    .collect();
                let expected: Vec<_> = model.values().filter(|row| row.provider == *provider).collect();
                require(actual.len() == expected.len(), "sequence inventory count changed")?;
                for row in expected {
                    require(
                        actual.contains(row) && client.inspect(provider, &row.id).await.map_err(SafeError::category)? == *row,
                        "sequence inventory differs from model",
                    )?;
                }
            }
        }
        Ok(())
    }
    .await;
    let a = cleanup(client, providers[0], &resources[0]).await;
    let b = cleanup(client, providers[1], &resources[1]).await;
    result.and(a).and(b)
}

async fn provider_isolation(client: &Client, providers: [&str; 2], main: &Environment, options: &Options) -> Result<()> {
    let mut resources = Resources::new(&options.request.label);
    let result = async {
        let prepared = client
            .prepare(
                providers[1],
                &PrepareRequest {
                    size: options.request.size.clone(),
                    image_digest: "isolation-image".into(),
                    tools_digest: "isolation-tools".into(),
                },
            )
            .await
            .map_err(SafeError::category)?;
        let mut request = options.request.clone();
        request.prepared = prepared;
        request.label = resources.label(ProbeLabel::Auxiliary("isolation".into()));
        let mut live = observe(client, None, &options.timeouts).await?;
        next(&mut live, &options.timeouts).await?;
        let other = client.provision(providers[1], &request).await.map_err(SafeError::category)?;
        transition(&mut live, providers[1], &other.id, |kind| matches!(kind, EventKind::Running { .. }), &options.timeouts).await?;
        resources.insert(other.id.clone());
        let mut gap = observe(client, Some("isolation-unknown-cursor"), &options.timeouts).await?;
        let ObserveRecord::Snapshot { environments, unavailable_providers, .. } = next(&mut gap, &options.timeouts).await? else {
            return Err("host-wide gap was not a snapshot".into());
        };
        require(
            !unavailable_providers.contains_key(providers[0])
                && !unavailable_providers.contains_key(providers[1])
                && environments.iter().any(|row| row.id == main.id && row.provider == providers[0])
                && environments.iter().any(|row| row.id == other.id && row.provider == providers[1]),
            "host-wide snapshot omitted or crossed providers",
        )
    }
    .await;
    result.and(cleanup(client, providers[1], &resources).await)
}

/// Configuration/credential socket scenario, shared by host implementations.
/// Invalid credentials and configuration preserve readiness and live inventory;
/// credential rotation and repeating configuration preserve environment identity.
pub async fn configuration_contract(
    client: &Client,
    configuration: &HostConfiguration,
    provider: &str,
    environment: &Environment,
) -> Result<()> {
    let before = client.hello().await.map_err(SafeError::category)?;
    for credential in [json!({"value":""}), json!({"value":{"TOP_SECRET":123}})] {
        let (status, value) = client
            .wire(Method::PUT, &["v1", "providers", provider, "credential"], &[], Some(&credential))
            .await
            .map_err(SafeError::category)?;
        require(status == 422 && !value.to_string().contains("TOP_SECRET"), "invalid credential accepted or exposed")?;
    }
    require(client.hello().await.map_err(SafeError::category)? == before, "invalid credential changed readiness")?;
    client.credential(provider, Secret::new("refreshed")).await.map_err(SafeError::category)?;
    client.configure(configuration).await.map_err(SafeError::category)?;
    require(
        client.inspect(provider, &environment.id).await.map_err(SafeError::category)? == *environment,
        "credential/config refresh discarded inventory",
    )?;
    let mut changed = configuration.clone();
    let entry = changed.providers.iter_mut().find(|entry| entry.name == provider).ok_or("missing provider")?;
    entry.settings.insert("changed".into(), json!(true));
    let (status, _) = client
        .wire(Method::PUT, &["v1", "config"], &[], Some(&serde_json::to_value(changed).map_err(SafeError::category)?))
        .await
        .map_err(SafeError::category)?;
    require(status == 422 && client.hello().await.map_err(SafeError::category)? == before, "incompatible configuration was not atomic")
}

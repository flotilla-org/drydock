//! Executable wire examples for the unapproved PR #34 proposal. These tests do
//! not add the candidates to active routes or implement host/provider behaviour.
use drydock_protocol::{Destination, proposal as p};
use serde_json::json;
use std::collections::BTreeMap;

// The proposed union distinguishes known progress from an API failure and
// round-trips every phase, without guessing a stable billing state in the module.
#[test]
fn transitional_wire_examples_cover_every_phase() {
    for (phase, name) in [
        (p::TransitionPhase::Preparing, "preparing"),
        (p::TransitionPhase::Starting, "starting"),
        (p::TransitionPhase::Stopping, "stopping"),
        (p::TransitionPhase::Reconfiguring, "reconfiguring"),
        (p::TransitionPhase::Destroying, "destroying"),
    ] {
        let observation = p::Observation::Transitioning { phase };
        let wire = json!({"state":"transitioning","phase":name});
        assert_eq!(serde_json::to_value(&observation).unwrap(), wire);
        assert_eq!(serde_json::from_value::<p::Observation>(wire).unwrap(), observation);
    }
}

// Resource keys, units and scope are wire data. The generator crosses empty and
// nonempty maps, resource variants, currencies, absent/zero costs and quota limits.
#[hegel::test]
fn generic_resource_wire_round_trips(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let kinds = [
        p::ResourceKind::Cpu,
        p::ResourceKind::Memory,
        p::ResourceKind::Disk,
        p::ResourceKind::Gpu,
        p::ResourceKind::SnapshotStorage,
        p::ResourceKind::VolumeStorage,
        p::ResourceKind::Environments,
    ];
    let index = tc.draw(gs::integers::<usize>().min_value(0).max_value(kinds.len() - 1));
    let amount = tc.draw(gs::integers::<u32>().min_value(0).max_value(1_000_000)) as f64 / 4.0;
    let kind = kinds[index];
    let unit = match kind {
        p::ResourceKind::Cpu => p::ResourceUnit::VcpuSecond,
        p::ResourceKind::Gpu => p::ResourceUnit::DeviceSecond,
        p::ResourceKind::Environments => {
            if tc.draw(gs::booleans()) {
                p::ResourceUnit::Count
            } else {
                p::ResourceUnit::CountSecond
            }
        }
        _ => p::ResourceUnit::ByteSecond,
    };
    let resources = if tc.draw(gs::booleans()) { BTreeMap::from([(kind, p::Quantity { amount, unit })]) } else { BTreeMap::new() };
    let scope = match tc.draw(gs::integers::<u8>().min_value(0).max_value(2)) {
        0 => p::UsageScope::Provider,
        1 => p::UsageScope::Organization { id: "account-a".into() },
        _ => p::UsageScope::Environment { id: "sandbox-a".into() },
    };
    let currency = if tc.draw(gs::booleans()) { "USD" } else { "EUR" };
    let cost = tc.draw(gs::booleans()).then(|| p::Cost { amount, currency: currency.into() });
    let measurements = p::UsageMeasurements { scope, resources, cost };
    let wire = serde_json::to_value(&measurements).unwrap();
    assert_eq!(serde_json::from_value::<p::UsageMeasurements>(wire).unwrap(), measurements);
    let period = drydock_protocol::Period::new("2026-10-20T00:00:00Z".parse().unwrap(), "2026-10-21T00:00:00Z".parse().unwrap()).unwrap();
    let usage = p::Usage { period, environment_hours: vec![], measurements: tc.draw(gs::booleans()).then_some(measurements) };
    let wire = serde_json::to_value(&usage).unwrap();
    assert_eq!(serde_json::from_value::<p::Usage>(wire).unwrap(), usage);

    let row = p::ResourceQuota {
        key: p::QuotaKey {
            region: tc.draw(gs::booleans()).then(|| "eu".into()),
            class: tc.draw(gs::booleans()).then(|| "container".into()),
            resource: kind,
        },
        unit: match kind {
            p::ResourceKind::Cpu => p::ResourceUnit::Vcpu,
            p::ResourceKind::Gpu | p::ResourceKind::Environments => p::ResourceUnit::Count,
            _ => p::ResourceUnit::Byte,
        },
        in_use: amount,
        limit: tc.draw(gs::booleans()).then_some(amount),
    };
    let wire = serde_json::to_value(&row).unwrap();
    assert_eq!(serde_json::from_value::<p::ResourceQuota>(wire).unwrap(), row);
}

// Exact encoding is the proposed contract: costs name their currency and quota
// keys keep region/class separate from resource identifiers. This is serde glue.
#[test]
fn neutral_cost_and_structured_quota_example() {
    let row = p::ResourceQuota {
        key: p::QuotaKey { region: Some("eu".into()), class: Some("container".into()), resource: p::ResourceKind::Cpu },
        unit: p::ResourceUnit::Vcpu,
        in_use: 2.0,
        limit: Some(10.0),
    };
    assert_eq!(
        serde_json::to_value(row).unwrap(),
        json!({"key":{"region":"eu","class":"container","resource":"cpu"},"unit":"vcpu","in_use":2.0,"limit":10.0})
    );
    assert_eq!(serde_json::to_value(p::Cost { amount: 0.0, currency: "EUR".into() }).unwrap(), json!({"amount":0.0,"currency":"EUR"}));
    let host = Destination::Host { host: "forge.example".parse().unwrap() };
    assert_eq!(serde_json::to_value(host).unwrap(), json!({"kind":"host","host":"forge.example"}));
}

//! Provider-side evidence for ADR 0070's tools and startup outcome. A probe must
//! read a real hello, inspect the process and compare prepared/base image config.
//! The reference module supplies explicitly simulated evidence (it has no guest).
use super::*;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ToolsEvidence {
    pub files: Vec<String>,
    pub base_entrypoint: Option<Vec<String>>,
    pub prepared_entrypoint: Option<Vec<String>>,
    pub base_command: Option<Vec<String>>,
    pub prepared_command: Option<Vec<String>>,
    pub command: Vec<String>,
    pub pid: u32,
    /// Process incarnation (e.g. PID plus procfs start time), not the fingerprint.
    pub incarnation: String,
    /// Must be read from the agent's hello, not a hash of the installed file.
    pub fingerprint: String,
    /// Echo the per-invocation challenge only after reading a fresh hello.
    /// Reusing a cached ToolsEvidence response must fail conformance.
    pub challenge: String,
}
fn valid_evidence(e: &ToolsEvidence, fingerprint: &str, challenge: &str) -> Result<()> {
    require(e.challenge == challenge, "cached tools evidence: probe challenge differs")?;
    require(!e.files.is_empty() && e.files.iter().any(|s| s == "/opt/drydock/drydock-agent"), "agent missing from tools layer")?;
    require(
        e.files.iter().all(|s| s.starts_with("/opt/drydock/") && !s.split('/').any(|p| p == ".." || p.starts_with(".wh."))),
        "tools layer writes outside /opt/drydock",
    )?;
    require(e.base_entrypoint == e.prepared_entrypoint && e.base_command == e.prepared_command, "base entrypoint or command changed")?;
    require(e.command == ["/opt/drydock/drydock-agent"] && e.pid > 1, "agent fixed command or PID 1 contract violated")?;
    require(
        !fingerprint.is_empty() && e.fingerprint == fingerprint && !e.incarnation.is_empty(),
        "agent hello fingerprint or incarnation missing",
    )
}
/// Runs a module-supplied guest probe through exec. Appends `initial`, `crash`
/// or `resumed`, followed by a fresh challenge, to its argv. Echo the challenge
/// only after a new hello exchange; cached evidence must not satisfy the probe.
/// `crash` must SIGKILL the agent, then wait for its
/// provider supervisor and read a fresh hello. Other phases wait for hello.
/// The JSON result is ToolsEvidence. Failures and unsupported probes fail closed.
/// The caller owns preparation, provisioning and destruction of this environment.
pub async fn vessel_tools(
    client: &Client,
    provider: &str,
    id: &str,
    probe: &ExecRequest,
    fingerprint: &str,
    timeout: Duration,
) -> Result<()> {
    let sample = |phase: &'static str| {
        let mut command = probe.clone();
        let challenge = uuid::Uuid::new_v4().to_string();
        command.command.extend([phase.into(), challenge.clone()]);
        async move {
            let mut stream = client.exec(provider, id, &command).await.map_err(SafeError::category)?;
            let mut bytes = Vec::new();
            (&mut stream).take(16385).read_to_end(&mut bytes).await.map_err(SafeError::category)?;
            require(bytes.len() <= 16384, "oversized tools probe result")?;
            let evidence: ToolsEvidence = serde_json::from_slice(&bytes).map_err(SafeError::category)?;
            valid_evidence(&evidence, fingerprint, &challenge)?;
            Ok::<_, String>(evidence)
        }
    };
    tokio::time::timeout(timeout, async {
        let initial = sample("initial").await?;
        let crashed = sample("crash").await?;
        require(crashed.incarnation != initial.incarnation, "agent did not restart after crash")?;
        let token = client.suspend(provider, id).await.map_err(SafeError::category)?;
        client.resume(provider, id, &token).await.map_err(SafeError::category)?;
        // A memory-preserving resume may keep the same incarnation. Its probe
        // must still return fresh, challenge-bound hello evidence.
        sample("resumed").await?;
        Ok(())
    })
    .await
    .map_err(SafeError::category)?
}

#[cfg(test)]
mod tests {
    use super::*;
    // Contract boundaries: each independent malformed evidence field must fail;
    // the reference endpoint scenario covers the valid lifecycle sequence.
    #[hegel::test]
    fn tools_evidence_refuses_contract_violations(tc: hegel::TestCase) {
        use hegel::generators as gs;
        // Span every valid non-init PID and every fingerprint byte; invalid
        // cases below cross the PID 1, empty, traversal, flag and config bounds.
        let pid = tc.draw(gs::integers::<u32>().min_value(2));
        let fingerprint: String = (0..32).map(|_| format!("{:02x}", tc.draw(gs::integers::<u8>()))).collect();
        let good = ToolsEvidence {
            files: vec!["/opt/drydock/drydock-agent".into()],
            base_entrypoint: Some(vec!["init".into()]),
            prepared_entrypoint: Some(vec!["init".into()]),
            base_command: Some(vec!["bash".into()]),
            prepared_command: Some(vec!["bash".into()]),
            command: vec!["/opt/drydock/drydock-agent".into()],
            pid,
            incarnation: "2:100".into(),
            fingerprint: fingerprint.clone(),
            challenge: "this-invocation".into(),
        };
        assert!(valid_evidence(&good, &fingerprint, "this-invocation").is_ok());
        for case in 0..10 {
            let mut bad = good.clone();
            match case {
                0 => bad.files.clear(),
                1 => bad.files.push("/sbin/init".into()),
                2 => bad.files.push("/opt/drydock/../../etc/init".into()),
                3 => bad.prepared_entrypoint = None,
                4 => bad.prepared_command = Some(vec!["agent".into()]),
                5 => bad.command.push("--extra".into()),
                6 => bad.pid = 1,
                7 => bad.incarnation.clear(),
                8 => bad.fingerprint = "wrong".into(),
                _ => bad.challenge = "cached-invocation".into(),
            }
            assert!(valid_evidence(&bad, &fingerprint, "this-invocation").is_err(), "case {case}");
        }
    }
}

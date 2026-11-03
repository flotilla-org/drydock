//! Starting and reaching the agent in a guest, through whatever runs a
//! command there (a vendor's exec API). The bootstrap script, the token file
//! and its cache, guest output and its errors, the egress probe and the
//! relay's one stale-token retry are the same for every provider that runs
//! the agent's TCP listener; a module supplies only [`Guest::run`].
use super::{Vendor, api::tail, shell_command};
use crate::module::{ByteStream, Credentials, Result};
use async_trait::async_trait;
use drydock_protocol::*;
use drydock_transport::tcp::Token;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Mutex,
};

pub const TOKEN_FILE: &str = "/run/drydock/tcp.token";
/// Prefixes the token where the bootstrap prints it back; such lines never
/// reach an error.
pub const TOKEN_LINE: &str = "drydock-tcp-token ";
pub const AGENT: &str = "/opt/drydock/drydock-agent";
pub const SOCKET: &str = "/run/drydock/agent.sock";
/// The agent's supervisor without a TCP listener (reach by SSH). The baked
/// executable owns detachment, singleton locking and crash recovery.
pub const SUPERVISE: &str = "/opt/drydock/drydock-agent --supervise --socket /run/drydock/agent.sock";
/// How much of a failed command's output an Internal error keeps.
pub const OUTPUT_CAUSE_CHARS: usize = 800;

/// How the agent starts in this provider's guests.
pub struct Bootstrap {
    /// The TCP listener's address in the guest: the interface a vendor's
    /// proxy reaches (`0.0.0.0:PORT`) or loopback for a tunnel.
    pub listen: String,
    /// Shell run first, which may print a marker line and exit non-zero.
    pub precheck: Option<String>,
    /// Environment the agent must not inherit, beyond the token itself.
    pub unset: &'static [&'static str],
    /// Make /workspace too.
    pub workspace: bool,
}
impl Bootstrap {
    /// Starts the agent as root, supervised, with a token only root can
    /// read. The token arrives in `DRYDOCK_TCP_TOKEN` (never on an argv) and
    /// the agent's environment loses it. A token file already there is kept
    /// when it holds a token, so a running agent (after resume, or another
    /// host's bootstrap) keeps answering to it; one holding no token is
    /// replaced. The write is exclusive (`set -C`): of two concurrent
    /// bootstraps one token wins and both read it back. The file must then
    /// hold a token, or the bootstrap stops saying so. `--supervise` returns
    /// at once; the supervisor's lock makes a rerun idempotent. Its argv ends
    /// with `--socket`, as the supervisor requires.
    pub fn script(&self) -> String {
        let token = "'[A-Za-z0-9_-]{43,}={0,2}'";
        let precheck = self.precheck.as_deref().map(|p| format!("{p} && ")).unwrap_or_default();
        let dirs = if self.workspace { "/run/drydock /workspace" } else { "/run/drydock" };
        let unset: String = self.unset.iter().map(|name| format!(" -u {name}")).collect();
        let listen = &self.listen;
        format!(
            "{precheck}mkdir -p {dirs} && chmod 0700 /run/drydock && \
             if [ -e {TOKEN_FILE} ] && ! grep -Eqx {token} {TOKEN_FILE}; then rm -f {TOKEN_FILE}; fi && \
             {{ (umask 077; set -C; printf %s \"$DRYDOCK_TCP_TOKEN\" > {TOKEN_FILE}) 2>/dev/null || true; }} && \
             {{ grep -Eqx {token} {TOKEN_FILE} || {{ echo 'drydock: {TOKEN_FILE} holds no token after writing it' >&2; exit 1; }}; }} && \
             echo \"{TOKEN_LINE}$(cat {TOKEN_FILE})\" && \
             exec env -u DRYDOCK_TCP_TOKEN{unset} {AGENT} --supervise \
             --tcp {listen} --tcp-token-file {TOKEN_FILE} --socket {SOCKET}"
        )
    }
}
/// Prints the token file back, as the bootstrap does.
pub fn token_read_script() -> String {
    format!("echo \"{TOKEN_LINE}$(cat {TOKEN_FILE})\"")
}

/// What one guest command printed and how it ended.
#[derive(Default, Debug)]
pub struct GuestOutput {
    /// (stderr, bytes), in arrival order.
    pub chunks: Vec<(bool, Vec<u8>)>,
    /// The exit status; None when the command never reported one.
    pub exit: Option<i32>,
    pub timed_out: bool,
    /// The vendor's own word on a command that did not run to its end,
    /// appended to the output of a failure.
    pub note: Option<String>,
}
impl GuestOutput {
    pub fn from_text(stdout: &str, stderr: &str, exit: Option<i64>) -> Self {
        let chunks = [(false, stdout), (true, stderr)].into_iter().filter(|(_, s)| !s.is_empty()).map(|(e, s)| (e, s.into())).collect();
        Self { chunks, exit: exit.map(|c| i32::try_from(c).unwrap_or(-1)), ..Self::default() }
    }
    pub fn bytes(&self, stderr: Option<bool>) -> Vec<u8> {
        self.chunks.iter().filter(|(e, _)| stderr.is_none_or(|s| s == *e)).flat_map(|(_, b)| b.iter().copied()).collect()
    }
    pub fn stdout(&self) -> Vec<u8> {
        self.bytes(Some(false))
    }
    /// -1 when the command timed out or ended without a status.
    pub fn exit_code(&self) -> i32 {
        if self.timed_out { -1 } else { self.exit.unwrap_or(-1) }
    }
    fn merged(&self) -> String {
        let mut output = String::from_utf8_lossy(&self.bytes(None)).into_owned();
        if let Some(note) = &self.note {
            output.push_str(&format!("\n{note}"));
        }
        output
    }
    /// Exit 0, or CommandFailed with the merged output (a user's command).
    pub fn success(self, vendor: Vendor) -> Result<Self> {
        if self.exit_code() == 0 {
            return Ok(self);
        }
        let ended = if self.timed_out { "timed out" } else { "failed" };
        Err(ProtocolError::CommandFailed {
            reason: format!("{vendor} guest command {ended}"),
            exit_code: self.exit_code(),
            output: Secret::new(self.merged()),
        })
    }
    /// Exit 0, or for the module's own commands an Internal error whose
    /// cause is the output's tail, so drydockd's log shows why. Token lines
    /// are left out.
    pub fn started(self, vendor: Vendor, what: &str) -> Result<Self> {
        if self.exit_code() == 0 {
            return Ok(self);
        }
        let merged = self.merged();
        let output: Vec<&str> = merged.lines().filter(|line| !line.contains(TOKEN_LINE.trim_end())).collect();
        let tail = tail(&output.join("\n"), OUTPUT_CAUSE_CHARS);
        let ended = if self.timed_out { "timed out".to_owned() } else { format!("exited {}", self.exit_code()) };
        Err(ProtocolError::Internal {
            reason: format!("{vendor} guest {what} {ended}"),
            provider_error: if tail.is_empty() { "no output".into() } else { tail },
        })
    }
    /// The token the bootstrap or a token read printed.
    pub fn token(&self) -> Result<Token> {
        let stdout = String::from_utf8_lossy(&self.stdout()).into_owned();
        let line = stdout.lines().find_map(|line| line.strip_prefix(TOKEN_LINE));
        line.and_then(|line| Token::parse(line).ok()).ok_or_else(|| ProtocolError::Internal {
            reason: "the agent's TCP token was not read back".into(),
            provider_error: String::new(),
        })
    }
    /// The output as an exec's byte stream.
    pub fn into_stream(self) -> ByteStream {
        Box::new(std::io::Cursor::new(self.bytes(None)))
    }
}

/// Runs `sh -c script` in a guest as root, `env` in its environment (never
/// on an argv), stdin closed.
#[async_trait]
pub trait Guest: Send + Sync {
    fn vendor(&self) -> Vendor;
    async fn run(&self, id: &str, script: &str, env: BTreeMap<&str, String>, c: &Credentials) -> Result<GuestOutput>;
    /// A user's command, as the exec port runs it.
    async fn exec(&self, id: &str, request: ExecRequest, c: &Credentials) -> Result<ByteStream> {
        Ok(self.run(id, &shell_command(&request.command), BTreeMap::new(), c).await?.success(self.vendor())?.into_stream())
    }
}

/// The agent in each of a provider's guests: how it starts, and each guest's
/// token as last read back. The cache holds only this host's memory; a
/// missing or stale entry is read from the guest again.
pub struct Agent {
    pub bootstrap: Bootstrap,
    tokens: Mutex<HashMap<String, Token>>,
}
impl Agent {
    pub fn new(bootstrap: Bootstrap) -> Self {
        Self { bootstrap, tokens: Mutex::default() }
    }
    fn remember(&self, id: &str, token: &Token) {
        self.tokens.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(id.to_owned(), token.clone());
    }
    pub fn forget(&self, id: &str) {
        self.tokens.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(id);
    }
    /// Runs the bootstrap; `check` sees its output first, to refuse what
    /// only this provider knows to look for.
    pub async fn start_checked(
        &self,
        guest: &dyn Guest,
        id: &str,
        c: &Credentials,
        check: impl FnOnce(&GuestOutput) -> Result<()>,
    ) -> Result<Token> {
        let fresh = Token::generate().map_err(|e| ProtocolError::Internal { reason: "TCP token".into(), provider_error: e.to_string() })?;
        let output = guest.run(id, &self.bootstrap.script(), BTreeMap::from([("DRYDOCK_TCP_TOKEN", fresh.secret().to_owned())]), c).await?;
        check(&output)?;
        let token = output.started(guest.vendor(), "bootstrap")?.token()?;
        self.remember(id, &token);
        Ok(token)
    }
    pub async fn start(&self, guest: &dyn Guest, id: &str, c: &Credentials) -> Result<Token> {
        self.start_checked(guest, id, c, |_| Ok(())).await
    }
    /// The guest's token: cached, or read back from its file.
    pub async fn token(&self, guest: &dyn Guest, id: &str, refresh: bool, c: &Credentials) -> Result<Token> {
        if !refresh && let Some(token) = self.tokens.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(id) {
            return Ok(token.clone());
        }
        let token = guest.run(id, &token_read_script(), BTreeMap::new(), c).await?.started(guest.vendor(), "token read")?.token()?;
        self.remember(id, &token);
        Ok(token)
    }
    /// `connect` with the guest's token; when the agent refuses it (another
    /// bootstrap replaced the file), once more with the token read again.
    /// The outer error is the way to the agent failing; the inner one the
    /// agent's handshake.
    pub async fn connect<S>(
        &self,
        guest: &dyn Guest,
        id: &str,
        c: &Credentials,
        connect: impl AsyncFn(Token) -> Result<std::io::Result<S>>,
    ) -> Result<std::io::Result<S>> {
        let connected = connect(self.token(guest, id, false, c).await?).await?;
        if connected.as_ref().is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied) {
            return connect(self.token(guest, id, true, c).await?).await;
        }
        Ok(connected)
    }
}

/// The agent's handshake failure, as the relay's error.
pub fn unaccepted(vendor: Vendor, via: &str, error: std::io::Error) -> ProtocolError {
    ProtocolError::Unavailable {
        reason: format!("the agent's TCP listener did not accept the connection through {vendor}'s {via}"),
        retry_after: None,
        provider_error: Some(error.to_string()),
    }
}

/// The operator's egress probe as root, told whether the policy denies all.
pub fn probe_script(probe: &ExecRequest, deny_all: bool) -> String {
    format!("test \"$(id -u)\" = 0 && DRYDOCK_PROBE_DENY_ALL={} {}", u8::from(deny_all), shell_command(&probe.command))
}
/// The probe's JSON proof: Some(confined) when complete, None otherwise.
pub fn egress_proof(stdout: &[u8], deny_all: bool) -> Option<bool> {
    let proof: serde_json::Value = serde_json::from_slice(stdout).ok()?;
    let complete = proof["uid"].as_u64().is_some()
        && proof["unlisted_canary"].as_bool().is_some()
        && proof["raw_dns"].as_bool().is_some()
        && (deny_all || proof["listed_direct"].as_bool().is_some());
    complete.then(|| {
        proof["uid"] == 0 && proof["unlisted_canary"] == false && proof["raw_dns"] == false && (deny_all || proof["listed_direct"] == true)
    })
}
/// Measures `row`'s egress claim with the probe, as root in the guest: a
/// complete proof of confinement is Enforced, anything else Advisory. A
/// probe that could not run leaves the row as it was (logged by class only:
/// the error bypasses the host's masking); the result says whether it ran.
pub async fn measure_egress(guest: &dyn Guest, row: &mut Environment, probe: &ExecRequest, deny_all: bool, c: &Credentials) -> bool {
    match guest.run(&row.id, &probe_script(probe, deny_all), BTreeMap::new(), c).await.and_then(|o| o.success(guest.vendor())) {
        Ok(output) => {
            let confined = egress_proof(&output.stdout(), deny_all) == Some(true);
            row.egress = if confined { Enforcement::Enforced } else { Enforcement::Advisory };
            row.egress_measured = true;
            true
        }
        Err(error) => {
            tracing::warn!(provider = %row.provider, environment = %row.id, error_class = error.class(), "egress measurement failed");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bootstrap(listen: &str) -> Bootstrap {
        Bootstrap { listen: listen.into(), precheck: None, unset: &["EXTRA"], workspace: true }
    }

    // The bootstrap's shell code, run for real over a temporary directory: it
    // writes a fresh token only root can read, keeps a token already there,
    // replaces a file holding none, and stops with a clear message when the
    // write leaves no token.
    #[test]
    fn bootstrap_writes_keeps_or_refuses_the_token() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        let script = bootstrap("0.0.0.0:7811").script();
        let (prefix, exec) = script.split_once(" && exec ").unwrap();
        assert!(exec.contains("-u DRYDOCK_TCP_TOKEN -u EXTRA") && exec.ends_with("--socket /run/drydock/agent.sock"), "{exec}");
        let prefix = prefix.replace("/run/drydock", run.to_str().unwrap()).replace("/workspace", dir.path().join("w").to_str().unwrap());
        let bootstrap =
            |token: &str| std::process::Command::new("sh").args(["-c", &prefix]).env("DRYDOCK_TCP_TOKEN", token).output().unwrap();
        let file = run.join("tcp.token");
        let missing = bootstrap("");
        assert!(!missing.status.success());
        assert!(String::from_utf8_lossy(&missing.stderr).contains("tcp.token holds no token after writing it"), "{missing:?}");
        let (first, second) = (Token::generate().unwrap(), Token::generate().unwrap());
        let _ = std::fs::remove_file(&file);
        let written = bootstrap(first.secret());
        assert!(written.status.success(), "{written:?}");
        assert_eq!(String::from_utf8_lossy(&written.stdout), format!("{TOKEN_LINE}{}\n", first.secret()));
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(bootstrap(second.secret()).status.success());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), first.secret());
        std::fs::write(&file, "garbage").unwrap();
        assert!(bootstrap(second.secret()).status.success());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), second.secret());
    }

    // Failures carry the output's tail without token lines; a timeout says so.
    #[test]
    fn guest_output_errors() {
        let v = Vendor("Test");
        let output = GuestOutput::from_text(&format!("{TOKEN_LINE}secret\nwhy it failed\n"), "", Some(3));
        let ProtocolError::Internal { reason, provider_error } = output.started(v, "bootstrap").unwrap_err() else { panic!() };
        assert_eq!(reason, "Test guest bootstrap exited 3");
        assert!(provider_error.contains("why it failed") && !provider_error.contains("secret"), "{provider_error}");
        let timed_out = GuestOutput { timed_out: true, exit: Some(0), ..GuestOutput::default() };
        assert!(
            matches!(timed_out.success(v), Err(ProtocolError::CommandFailed { exit_code: -1, reason, .. }) if reason.contains("timed out"))
        );
    }

    #[test]
    fn egress_proofs() {
        assert_eq!(egress_proof(br#"{"uid":0,"unlisted_canary":false,"raw_dns":false}"#, true), Some(true));
        assert_eq!(egress_proof(br#"{"uid":0,"unlisted_canary":false,"raw_dns":false}"#, false), None);
        assert_eq!(egress_proof(br#"{"uid":0,"unlisted_canary":true,"raw_dns":false,"listed_direct":true}"#, false), Some(false));
        assert_eq!(egress_proof(b"not json", true), None);
    }
}

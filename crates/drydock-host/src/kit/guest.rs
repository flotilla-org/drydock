//! Running commands in a guest through whatever runs them there (a
//! vendor's exec API): what a command printed and how it ended, the errors
//! that makes, and a user's exec on top. A module supplies only
//! [`Guest::run`].
use super::{Recover, Vendor, shell_command};
use crate::module::{ByteStream, Credentials, Result};
use async_trait::async_trait;
use drydock_protocol::*;
use drydock_transport::tcp::Token;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Mutex,
};

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
    /// An exit status outside i32 reads as -1, as an unreported one does.
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

/// The drydock agent's path in a guest and the file its TCP listener's token is in.
const AGENT: &str = "/opt/drydock/drydock-agent";
const TOKEN_FILE: &str = "/run/drydock/tcp-token";
const TOKEN_LINE: &str = "drydock-tcp-token ";
/// The agent prints this line for `--print-token`.
fn print_token() -> String {
    format!("{AGENT} --print-token --tcp-token-file {TOKEN_FILE}")
}
/// The token of the TCP agent in a guest, read once and kept until the module
/// drops it. A module drops it when the guest could have a new agent (suspend,
/// resume, destroy) or the agent refused it; the next [`AgentTokens::get`] reads it again.
#[derive(Default)]
pub struct AgentTokens(Mutex<HashMap<String, Token>>);
impl AgentTokens {
    /// The token the agent in `id` prints. A guest that cannot print one yet
    /// (the agent is not up, or the file is not written) is Unavailable: try again.
    pub async fn get(&self, guest: &(impl Guest + ?Sized), id: &str, c: &Credentials) -> Result<Token> {
        if let Some(token) = self.0.recover().get(id) {
            return Ok(token.clone());
        }
        let output = guest.run(id, &print_token(), BTreeMap::new(), c).await?;
        let stdout = String::from_utf8_lossy(&output.stdout()).into_owned();
        let token = (output.exit_code() == 0)
            .then(|| stdout.lines().find_map(|line| line.strip_prefix(TOKEN_LINE)).and_then(|line| Token::parse(line).ok()))
            .flatten()
            .ok_or_else(|| ProtocolError::unavailable(format!("{} sandbox {id}'s agent has no TCP token yet", guest.vendor()), Some(2)))?;
        self.0.recover().insert(id.to_owned(), token.clone());
        Ok(token)
    }
    pub fn forget(&self, id: &str) {
        self.0.recover().remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Printer(std::sync::atomic::AtomicUsize, &'static str, i64);
    #[async_trait]
    impl Guest for Printer {
        fn vendor(&self) -> Vendor {
            Vendor("Test")
        }
        async fn run(&self, _: &str, script: &str, _: BTreeMap<&str, String>, _: &Credentials) -> Result<GuestOutput> {
            assert!(script.contains("--print-token"));
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(GuestOutput::from_text(self.1, "", Some(self.2)))
        }
    }

    // The token is read once and kept until dropped; a guest that prints none,
    // or exits nonzero, is Unavailable and caches nothing.
    #[tokio::test]
    async fn agent_tokens_are_read_once_and_forgotten() {
        let token = "A".repeat(43);
        let c = Credentials::default();
        let tokens = AgentTokens::default();
        let guest = Printer(0.into(), Box::leak(format!("noise\ndrydock-tcp-token {token}\n").into_boxed_str()), 0);
        for _ in 0..2 {
            assert_eq!(tokens.get(&guest, "a", &c).await.unwrap().secret(), token);
        }
        assert_eq!(guest.0.load(std::sync::atomic::Ordering::Relaxed), 1);
        tokens.forget("a");
        tokens.get(&guest, "a", &c).await.unwrap();
        assert_eq!(guest.0.load(std::sync::atomic::Ordering::Relaxed), 2);
        for bad in [
            Printer(0.into(), "", 0),
            Printer(0.into(), "drydock-tcp-token short\n", 0),
            Printer(0.into(), "drydock-tcp-token AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n", 1),
        ] {
            let error = AgentTokens::default().get(&bad, "a", &c).await.unwrap_err();
            assert!(matches!(error, ProtocolError::Unavailable { retry_after: Some(2), .. }), "{error:?}");
        }
    }

    // A failure carries the merged output and the vendor's note; a timeout
    // says so and has no exit status, whatever the vendor reported.
    #[test]
    fn guest_output_errors() {
        let v = Vendor("Test");
        let mut output = GuestOutput::from_text("out\n", "err\n", Some(3));
        output.note = Some("killed".into());
        let ProtocolError::CommandFailed { reason, exit_code, output } = output.success(v).unwrap_err() else { panic!() };
        assert_eq!((reason.as_str(), exit_code, output.expose()), ("Test guest command failed", 3, "out\nerr\n\nkilled"));
        let timed_out = GuestOutput { timed_out: true, exit: Some(0), ..GuestOutput::default() };
        assert!(
            matches!(timed_out.success(v), Err(ProtocolError::CommandFailed { exit_code: -1, reason, .. }) if reason.contains("timed out"))
        );
        assert!(GuestOutput::from_text("", "", Some(0)).success(v).is_ok());
    }
}

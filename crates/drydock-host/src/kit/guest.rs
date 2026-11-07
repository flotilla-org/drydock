//! Running commands in a guest through whatever runs them there (a
//! vendor's exec API): what a command printed and how it ended, the errors
//! that makes, and a user's exec and the agent's TCP token on top. A module
//! supplies only [`Guest::run`].
use super::{Vendor, shell_command};
use crate::module::{ByteStream, Credentials, Result};
use async_trait::async_trait;
use drydock_protocol::*;
use std::collections::BTreeMap;

const AGENT: &str = "/opt/drydock/drydock-agent";
const TOKEN_FILE: &str = "/run/drydock/tcp-token";
const TOKEN_LINE: &str = "drydock-tcp-token ";

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
    /// The token the guest's agent serves its TCP listener with.
    async fn agent_token(&self, id: &str, c: &Credentials) -> Result<Secret> {
        let output = self.run(id, &format!("{AGENT} --print-token --tcp-token-file {TOKEN_FILE}"), BTreeMap::new(), c).await?;
        let token = String::from_utf8_lossy(&output.stdout())
            .lines()
            .find_map(|line| line.strip_prefix(TOKEN_LINE))
            .filter(|t| !t.is_empty())
            .map(str::to_owned);
        match token {
            Some(token) if output.exit_code() == 0 => Ok(Secret::new(token)),
            _ => Err(ProtocolError::unavailable(format!("{} sandbox {id}'s agent has no TCP token yet", self.vendor()), Some(2))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

//! The guest half of every agent-running provider's stand-in, specified once:
//! the module's bootstrap run for real by `sh` (the token file's handling,
//! the environment the agent inherits), its argv judged by the supervisor's
//! own parser, and a real agent on a token-gated listener. A vendor's
//! stand-in keeps only its wire: how the script arrives and how output
//! returns.
#![allow(dead_code)]
use drydock_agent::{Agent, tcp::TokenListener};
use drydock_transport::tcp::Token;
use std::{collections::BTreeMap, net::SocketAddr, os::unix::fs::PermissionsExt};

pub const AGENT: &str = "/opt/drydock/drydock-agent";
pub const TOKEN_READ: &str = "echo \"drydock-tcp-token $(cat /run/drydock/tcp.token)\"";
pub const PROBE: &str = "test \"$(id -u)\" = 0";

/// A guest's drydock agent, really listening on loopback in place of the
/// guest's interface.
pub struct Guest {
    pub address: SocketAddr,
    pub token: Token,
    task: tokio::task::JoinHandle<std::io::Result<std::path::PathBuf>>,
    _dir: tempfile::TempDir,
    _keep: drydock_transport::MemoryDialer,
}
impl Drop for Guest {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub async fn start_guest(token: Token) -> Guest {
    let dir = tempfile::tempdir().unwrap();
    let (keep, control) = drydock_transport::memory();
    let listener = TokenListener::bind("127.0.0.1:0".parse().unwrap(), token.clone()).await.unwrap();
    let address = listener.local_addr();
    let mut agent = Agent::new(control, "test-build".into(), dir.path().join("agent"));
    agent.add_listener(listener);
    Guest { address, token, task: tokio::spawn(agent.run()), _dir: dir, _keep: keep }
}

/// What the guest's `drydock-agent --supervise` makes of the bootstrap's
/// argv, through the supervisor's own parser.
pub fn supervise(script: &str) -> Result<Vec<String>, String> {
    let Some((_, argv)) = script.split_once(&format!("{AGENT} --supervise ")) else {
        return Err(format!("sh: unexpected bootstrap {script}"));
    };
    let argv: Vec<std::ffi::OsString> = argv.split_whitespace().map(Into::into).collect();
    drydock_agent::socket::supervised(&argv).map_err(|e| e.to_string())?;
    Ok(argv.iter().map(|a| a.to_string_lossy().into_owned()).collect())
}
/// The address the agent's `--tcp` listener binds.
pub fn listen(argv: &[String]) -> Option<String> {
    argv.windows(2).find(|w| w[0] == "--tcp").map(|w| w[1].clone())
}

/// One bootstrap run by `sh`.
pub struct BootstrapRun {
    /// The token file afterwards.
    pub token_file: Option<String>,
    /// The environment the agent was started with.
    pub env: BTreeMap<String, String>,
    /// stdout and the exit status, when the script failed.
    pub failed: Option<(String, i64)>,
}
/// The bootstrap run for real by `sh`, with /run/drydock and /workspace moved
/// to a temporary directory, a stub in the agent's place recording the
/// environment it gets, `env` as the guest's own environment, and a PATH of
/// the tools the script may use (with a python3 stub when `python3`).
/// `existing` is the token file before; `token` the module's fresh one.
pub fn run_bootstrap(script: &str, existing: Option<&str>, token: Option<&str>, env: &[(&str, &str)], python3: bool) -> BootstrapRun {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let path = std::env::var_os("PATH").unwrap_or_default();
    for tool in ["mkdir", "chmod", "grep", "rm", "cat", "env"] {
        let found = std::env::split_paths(&path).map(|d| d.join(tool)).find(|p| p.is_file()).unwrap();
        std::os::unix::fs::symlink(found, bin.join(tool)).unwrap();
    }
    if python3 {
        std::fs::write(bin.join("python3"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(bin.join("python3"), PermissionsExt::from_mode(0o755)).unwrap();
    }
    let run = dir.path().join("run");
    let stub = dir.path().join("agent");
    let recorded = dir.path().join("env");
    std::fs::write(&stub, format!("#!/bin/sh\nenv > {}\n", recorded.display())).unwrap();
    std::fs::set_permissions(&stub, PermissionsExt::from_mode(0o755)).unwrap();
    let script = script
        .replace("/run/drydock", run.to_str().unwrap())
        .replace("/workspace", dir.path().join("workspace").to_str().unwrap())
        .replace(AGENT, stub.to_str().unwrap());
    if let Some(existing) = existing {
        std::fs::create_dir(&run).unwrap();
        std::fs::write(run.join("tcp.token"), existing).unwrap();
    }
    let mut command = std::process::Command::new("/bin/sh");
    command.args(["-c", &script]).env_clear().env("PATH", &bin).env("DRYDOCK_TCP_TOKEN", token.unwrap_or_default());
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().unwrap();
    let failed = (!output.status.success())
        .then(|| (String::from_utf8_lossy(&output.stdout).into_owned(), i64::from(output.status.code().unwrap_or(-1))));
    let env = std::fs::read_to_string(&recorded)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
        .collect();
    BootstrapRun { token_file: std::fs::read_to_string(run.join("tcp.token")).ok(), env, failed }
}

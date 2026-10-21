//! SSH terminal sessions with a recipe-pinned host key and a per-vessel identity.
use drydock_protocol::{Reach, Secret};
use serde::{Deserialize, Serialize};
use std::{io::Write, path::PathBuf, process::Stdio};

#[derive(Serialize, Deserialize)]
pub struct Session {
    pub reach: Reach,
    pub identity_file: PathBuf,
}
pub struct SshCommand {
    pub program: &'static str,
    pub args: Vec<String>,
    known_hosts: tempfile::NamedTempFile,
}
impl SshCommand {
    pub fn new(session: Session) -> Result<Self, String> {
        let (endpoint, user, host_key) = match session.reach {
            Reach::Ssh { endpoint, user, host_key } => (endpoint, user, host_key),
            Reach::Dial { .. } => return Err("shell over Dial needs the vessel agent; only SSH is available yet".into()),
            Reach::Relay { .. } => return Err("shell over Relay needs the vessel agent; only SSH is available yet".into()),
        };
        let (host, port) = endpoint.rsplit_once(':').ok_or("SSH endpoint must contain host:port")?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.parse::<drydock_protocol::HostAddress>().map_err(|_| "invalid SSH endpoint")?;
        if host.is_empty()
            || host.starts_with('-')
            || host.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || matches!(b, b'/' | b'[' | b']'))
            || port.parse::<u16>().ok().filter(|p| *p > 0).is_none()
        {
            return Err("invalid SSH endpoint".into());
        }
        let parts: Vec<_> = host_key.split_whitespace().collect();
        if parts.len() < 2
            || host_key.contains(['\n', '\r'])
            || !matches!(parts[0], "ssh-ed25519" | "ssh-rsa" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521")
        {
            return Err("invalid pinned SSH host key".into());
        }
        let mut known_hosts = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
        writeln!(known_hosts, "[{host}]:{port} {} {}", parts[0], parts[1]).map_err(|e| e.to_string())?;
        // Port 22 can use the unadorned lookup name depending on OpenSSH's version.
        writeln!(known_hosts, "{host} {} {}", parts[0], parts[1]).map_err(|e| e.to_string())?;
        let user: Secret = user;
        let args = vec![
            "-F".into(),
            "/dev/null".into(),
            "-tt".into(),
            "-o".into(),
            "StrictHostKeyChecking=yes".into(),
            "-o".into(),
            format!("UserKnownHostsFile={}", known_hosts.path().display()),
            "-o".into(),
            "GlobalKnownHostsFile=/dev/null".into(),
            "-o".into(),
            "IdentitiesOnly=yes".into(),
            "-o".into(),
            "IdentityAgent=none".into(),
            "-i".into(),
            session.identity_file.to_string_lossy().into_owned(),
            "-p".into(),
            port.into(),
            "-l".into(),
            user.expose().into(),
            "--".into(),
            host.into(),
        ];
        Ok(Self { program: "ssh", args, known_hosts })
    }
    pub async fn run(&self) -> Result<std::process::ExitStatus, String> {
        let _keep_pin_alive = &self.known_hosts;
        tokio::process::Command::new(self.program)
            .args(&self.args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .map_err(|_| "could not run ssh".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // SSH glue: both endpoint forms use the recipe's user/port, a private
    // known_hosts pin, and the vessel identity. Ambient SSH configuration is off.
    #[test]
    fn ssh_recipe_is_pinned_and_arguments_are_separate() {
        for endpoint in ["gateway.example:2222", "[::1]:22"] {
            let command = SshCommand::new(Session {
                reach: Reach::Ssh { endpoint: endpoint.into(), user: Secret::new("gateway-user"), host_key: "ssh-ed25519 AAAAtest".into() },
                identity_file: "/private/key".into(),
            })
            .unwrap();
            assert_eq!(&command.args[..2], ["-F", "/dev/null"]);
            assert!(command.args.iter().any(|s| s == "StrictHostKeyChecking=yes"));
            assert!(command.args.windows(2).any(|s| s == ["-i", "/private/key"]));
            assert!(command.args.windows(2).any(|s| s == ["-l", "gateway-user"]));
            let pin = std::fs::read_to_string(command.known_hosts.path()).unwrap();
            assert!(pin.contains("ssh-ed25519 AAAAtest"));
        }
        for endpoint in ["-oProxyCommand=bad:22", "host\nother:22", "host:0", "host:70000", "host"] {
            assert!(
                SshCommand::new(Session {
                    reach: Reach::Ssh { endpoint: endpoint.into(), user: Secret::new("u"), host_key: "ssh-ed25519 key".into() },
                    identity_file: "key".into()
                })
                .is_err()
            );
        }
    }
}

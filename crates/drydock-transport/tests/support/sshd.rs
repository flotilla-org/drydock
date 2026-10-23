//! Real OpenSSH test server at the provider boundary, with disposable host and
//! user keys. It runs as the current user and never reads ambient SSH config.
//! Shared by the transport, agent and daemon tests through `#[path]`.
use drydock_transport::ssh::{GuestStreams, SshConfig};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::process::{Child, Command};

/// Which Unix-socket forwards the server grants.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum Forwarding {
    /// Local and remote forwards, like a vessel's own sshd.
    Both,
    /// Local forwards only. Daytona's gateway refuses remote Unix-socket
    /// forwards ("remote port forwarding failed for listen path ...").
    Gateway,
}

pub async fn start(dir: &Path, agent_socket: &Path, guest_streams: GuestStreams, forwarding: Forwarding) -> (SshConfig, Child) {
    for name in ["host_key", "user_key"] {
        let result = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(dir.join(name))
            .status()
            .await
            .expect("install openssh-client: ssh-keygen is required by the SSH tests");
        assert!(result.success());
    }
    let user = Command::new("id").arg("-un").output().await.unwrap();
    let user = String::from_utf8(user.stdout).unwrap().trim().to_owned();
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let allow = match forwarding {
        Forwarding::Both => "yes",
        Forwarding::Gateway => "local",
    };
    let config_path = dir.join("sshd_config");
    std::fs::write(&config_path, format!("Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\nPidFile {}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin yes\nAllowUsers {user}\nAllowStreamLocalForwarding {allow}\nStreamLocalBindUnlink yes\n", dir.join("host_key").display(), dir.join("user_key.pub").display(), dir.join("sshd.pid").display())).unwrap();
    let sshd = std::env::var("DRYDOCK_TEST_SSHD").unwrap_or_else(|_| "/usr/sbin/sshd".into());
    let log = std::fs::File::create(dir.join("sshd.log")).unwrap();
    let mut child = Command::new(sshd)
        .args(["-D", "-e", "-f"])
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .kill_on_drop(true)
        .spawn()
        .expect("install openssh-server or set DRYDOCK_TEST_SSHD");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(child.try_wait().unwrap().is_none(), "sshd exited: {}", std::fs::read_to_string(dir.join("sshd.log")).unwrap());
            if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (
        SshConfig {
            connect_timeout: Duration::from_secs(5),
            host: "127.0.0.1".into(),
            port,
            user,
            host_key: std::fs::read_to_string(dir.join("host_key.pub")).unwrap().trim().into(),
            identity_file: dir.join("user_key"),
            agent_socket: agent_socket.into(),
            guest_streams,
        },
        child,
    )
}

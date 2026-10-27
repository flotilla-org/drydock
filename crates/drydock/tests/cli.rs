//! Real process/socket acceptance scenarios. Only the daemon executable boundary
//! is wrapped to point its external-host option at our real reference host.
use drydock::{
    HostConnection,
    client::{Client, Method},
    config::Config,
    daemon::{Daemon, HostOption, ProviderApi},
};
use drydock_protocol::*;
use std::{os::unix::fs::PermissionsExt, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn config_text(socket_credential: &std::path::Path) -> String {
    format!(
        r#"
[provider.demo]
module = "reference"
credential = {{ file = {:?} }}
image = "image@sha256:{}"
settings = {{
  fixture = true,
  poll_interval_ms = 10,
}}
[provider.other]
module = "reference"
credential = {{ env = "PATH" }}
image = "image@sha256:{}"
settings = {{}}
"#,
        socket_credential.to_str().unwrap(),
        "a".repeat(64),
        "a".repeat(64)
    )
}
async fn reference(dir: &std::path::Path) -> (std::path::PathBuf, tokio::task::JoinHandle<()>) {
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.join("reference.sock");
    let socket = path.clone();
    let task = tokio::spawn(async move {
        drydock_host::Host::new(drydock_host::reference::registry())
            .serve_unix(socket, unsafe { libc::geteuid() }, std::future::pending())
            .await
            .unwrap();
    });
    for _ in 0..200 {
        if Client::unix(&path).unwrap().hello().await.is_ok() {
            return (path, task);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("reference did not start");
}
struct KillDaemon {
    socket: std::path::PathBuf,
    pid: u32,
}
impl Drop for KillDaemon {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.pid as i32, libc::SIGTERM);
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}
async fn cli(config: &std::path::Path, socket: &std::path::Path, shim: &std::path::Path, args: &[&str]) -> std::process::Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_drydock"))
        .arg("--config")
        .arg(config)
        .arg("--socket")
        .arg(socket)
        // Runtime environment cannot override the build-owned image selection.
        .env("DRYDOCK_TOOLS_IMAGE", "runtime.invalid/override@sha256:".to_owned() + &"b".repeat(64))
        .env("DRYDOCK_DAEMON_BIN", shim)
        .env("DRYDOCK_HOST_BIN", "/not-installed/drydock-host")
        .args(args)
        .output()
        .await
        .unwrap()
}
async fn cli_xdg(xdg: &std::path::Path, shim: &std::path::Path, args: &[&str]) -> std::process::Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_drydock"))
        .env("XDG_CONFIG_HOME", xdg)
        .env_remove("DRYDOCK_ROOT")
        // Runtime environment cannot override the build-owned image selection.
        .env("DRYDOCK_TOOLS_IMAGE", "runtime.invalid/override@sha256:".to_owned() + &"b".repeat(64))
        .env("DRYDOCK_DAEMON_BIN", shim)
        .args(args)
        .output()
        .await
        .unwrap()
}
fn json(output: std::process::Output) -> serde_json::Value {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).unwrap()
}
// Contract: provider-only TOML, client starts a missing daemon once, concurrent
// clients reuse it, and the real host continues polling after the CLI exits.
#[tokio::test]
async fn cli_starts_reuses_and_observes_between_calls() {
    let dir = tempfile::tempdir().unwrap();
    let (host, task) = reference(dir.path()).await;
    let token = dir.path().join("token");
    std::fs::write(&token, "test-token").unwrap();
    let xdg = dir.path().join("xdg");
    let config_dir = xdg.join("drydock");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config = config_dir.join("drydock.toml");
    std::fs::write(&config, config_text(&token)).unwrap();
    let run = config_dir.join("run");
    drydock::local::private_dir(&run).unwrap();
    let socket = run.join("drydock.sock");
    let pid = dir.path().join("daemon.pid");
    let shim = dir.path().join("daemon");
    std::fs::write(
        &shim,
        format!(
            "#!/bin/sh\necho $$ >> '{}'\nexec '{}' --external-host '{}' \"$@\"\n",
            pid.display(),
            env!("CARGO_BIN_EXE_drydockd"),
            host.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (a, b) = tokio::join!(cli_xdg(&xdg, &shim, &["providers"]), cli(&config, &socket, &shim, &["list", "demo"]));
    let providers = json(a);
    assert_eq!(providers[0]["provider"], "demo");
    assert_eq!(providers[0]["readiness"]["status"], "ready");
    assert_eq!(json(b), serde_json::json!([]));
    let pids = std::fs::read_to_string(&pid).unwrap();
    assert_eq!(pids.lines().count(), 1);
    let _cleanup = KillDaemon { socket: socket.clone(), pid: pids.trim().parse().unwrap() };
    let client = Client::unix(&socket).unwrap();
    let mut records = client.observe(None).await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(2), records.next()).await.unwrap().unwrap().unwrap();
    assert!(matches!(first, ObserveRecord::Snapshot { .. }));
    // Before the first publish, builds must refuse to invent an image pin. The
    // published branch below uses a checked-in pin or a build-time override.
    if drydock::launch::build_tools_digest().is_err() {
        let output = cli_xdg(&xdg, &shim, &["launch", "demo"]).await;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("the tools image has not been published yet"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("publish workflow and merge its pin PR"));
        let output = cli_xdg(&xdg, &shim, &["prepare", "demo"]).await;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("the tools image has not been published yet"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("publish workflow and merge its pin PR"));
        assert!(client.list("demo").await.unwrap().is_empty());
        task.abort();
        return;
    }
    let environment: Environment = serde_json::from_value(json(cli_xdg(&xdg, &shim, &["launch", "demo"]).await)).unwrap();
    assert_eq!(environment.granted_size, Some(Size { cpus: 1., memory_bytes: 1 << 30, disk_bytes: 1 << 30 }));
    assert_eq!(environment.egress, Enforcement::Advisory);
    let label = environment.label.as_ref().unwrap();
    let request: ProvisionRequest =
        serde_json::from_slice(&std::fs::read(run.join("keys").join(label).join("request.json")).unwrap()).unwrap();
    assert_eq!(request.prepared.tools_digest, drydock::launch::build_tools_digest().unwrap());
    assert!(request.ssh_public_key.unwrap().starts_with("ssh-ed25519 "));
    assert_eq!(request.egress, EgressRequest::Open);
    // Change provider state directly while no CLI process is running. The host
    // poller, rather than a CLI read, must emit the stopped transition.
    let upstream = Client::unix(host).unwrap();
    let resume = upstream.suspend("demo", &environment.id).await.unwrap();
    let event = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(ObserveRecord::Event { event }) = records.next().await.unwrap()
                && event.id == environment.id
                && matches!(event.event, EventKind::Paused { .. } | EventKind::Stopped { .. })
            {
                break event;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(event.provider, "demo");
    upstream.resume("demo", &environment.id, &resume).await.unwrap();
    let inspected = json(cli(&config, &socket, &shim, &["inspect", "demo", &environment.id]).await);
    assert_eq!(inspected["id"], environment.id);
    let shell = cli(&config, &socket, &shim, &["shell", "demo", &environment.id]).await;
    assert!(!shell.status.success());
    assert!(String::from_utf8_lossy(&shell.stderr).contains("vessel agent"));
    let override_image = format!("image@sha256:{}", "b".repeat(64));
    let override_env: Environment = serde_json::from_value(json(
        cli(
            &config,
            &socket,
            &shim,
            &["launch", "other", "--image", &override_image, "--cpus", "2", "--memory", "2GiB", "--disk", "3GiB", "--egress", "deny-all"],
        )
        .await,
    ))
    .unwrap();
    assert_eq!(override_env.granted_size, Some(Size { cpus: 2., memory_bytes: 2 << 30, disk_bytes: 3 << 30 }));
    let override_request: ProvisionRequest =
        serde_json::from_slice(&std::fs::read(run.join("keys").join(override_env.label.as_ref().unwrap()).join("request.json")).unwrap())
            .unwrap();
    assert_eq!(override_request.prepared.image_digest, override_image);
    let warmed: Prepared = serde_json::from_value(json(cli(&config, &socket, &shim, &["prepare", "demo"]).await)).unwrap();
    assert_eq!(warmed, request.prepared);

    assert!(cli(&config, &socket, &shim, &["destroy", "demo", &environment.id]).await.status.success());
    assert_eq!(json(cli(&config, &socket, &shim, &["list", "demo"]).await), serde_json::json!([]));
    // Existing daemon remains authoritative even after config disappears.
    std::fs::remove_file(config.clone()).unwrap();
    assert_eq!(json(cli(&config, &socket, &shim, &["list", "other"]).await).as_array().unwrap().len(), 1);
    assert_eq!(std::fs::read_to_string(&pid).unwrap().lines().count(), 1);
    task.abort();
}

// Routing tests use the host's explicit reference prepared form when the CLI
// was built before the first pin is published; the separate CLI test checks that refusal.
async fn routing_environment(daemon: &Daemon, socket: &std::path::Path) -> Environment {
    if drydock::launch::build_tools_digest().is_ok() {
        return daemon.launch("demo", &drydock::launch::LaunchOptions::default()).await.unwrap();
    }
    let host = Client::unix(socket).unwrap();
    let size = Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 };
    let prepared = host
        .prepare(
            "demo",
            &PrepareRequest {
                platform: None,
                route: None,
                image_pull: None,
                size: size.clone(),
                image_digest: "routing-image".into(),
                tools_digest: "routing-tools".into(),
            },
        )
        .await
        .unwrap();
    host.provision(
        "demo",
        &ProvisionRequest { label: "routing-fixture".into(), prepared, size, egress: EgressRequest::Open, ssh_public_key: None },
    )
    .await
    .unwrap()
}

// Contract: the embedded and socket forms route the same provider API, isolate
// provider IDs, expose streaming upgrades, refuse host-control routes, and keep
// unknown modules visible. External hosts remain alive after daemon drop.
#[tokio::test]
async fn daemon_routes_provider_api_and_streams() {
    let dir = tempfile::tempdir().unwrap();
    let (socket, task) = reference(dir.path()).await;
    let token = dir.path().join("token");
    std::fs::write(&token, "token").unwrap();
    let config = Config::parse(&(config_text(&token) + "\n[provider.missing]\nmodule='absent'\ncredential={env='PATH'}\n")).unwrap();
    let run = dir.path().join("run");
    let daemon = Daemon::start(
        config,
        &run,
        run.join("keys"),
        vec![HostOption { optional: false, name: "external".into(), connection: HostConnection::ExternalUnix { path: socket.clone() } }],
    )
    .await
    .unwrap();
    assert_eq!(daemon.providers()[2]["readiness"]["status"], "ready");
    let missing = daemon.providers().as_array().unwrap().iter().find(|p| p["provider"] == "missing").unwrap().clone();
    assert_eq!(missing["readiness"]["status"], "missing_tool");
    let path = run.join("api.sock");
    let api = daemon.clone();
    let bind = path.clone();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        api.serve(&bind, async {
            let _ = stopped.await;
        })
        .await
        .unwrap();
    });
    let client = Client::unix(path).unwrap();
    for _ in 0..200 {
        if client.hello().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let env = routing_environment(&daemon, &socket).await;
    assert_eq!(client.inspect("demo", &env.id).await.unwrap(), env);
    let response =
        ProviderApi::request(daemon.as_ref(), Method::GET, &["v1", "providers", "demo", "environments"], &[], None).await.unwrap();
    assert_eq!(response.body, serde_json::to_value(client.list("demo").await.unwrap()).unwrap());
    assert!(client.inspect("other", &env.id).await.is_err());
    assert!(
        matches!(client.list("missing").await,Err(drydock::client::Error::Protocol(ProtocolError::Unavailable {reason,..})) if reason.contains("MissingTool"))
    );
    assert!(client.credential("demo", Secret::new("bad")).await.is_err());
    let command: ExecRequest = serde_json::from_value(serde_json::json!({"command":["echo","hello"],"env":{},"cwd":null})).unwrap();
    for api in [daemon.clone() as std::sync::Arc<dyn ProviderApi>, std::sync::Arc::new(client.clone())] {
        assert_eq!(api.inspect("demo", &env.id).await.unwrap(), env);
        let mut relay = api.relay("demo", &env.id).await.unwrap();
        relay.write_all(b"hello").await.unwrap();
        let mut echo = [0; 5];
        relay.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"hello");
        drop(relay);
        let mut exec = api.exec("demo", &env.id, &command).await.unwrap();
        let mut output = Vec::new();
        exec.read_to_end(&mut output).await.unwrap();
        assert!(!output.is_empty());
        use futures::StreamExt;
        let mut events = api.observe(None).await.unwrap();
        assert!(events.next().await.unwrap().is_ok());
    }
    client.destroy("demo", &env.id).await.unwrap();
    client.destroy("demo", &env.id).await.unwrap();
    assert!(client.list("demo").await.unwrap().is_empty());
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), server).await.unwrap().unwrap();
    drop(daemon);
    assert!(Client::unix(socket).unwrap().hello().await.is_ok());
    task.abort();
}

// Generated operation sequences exercise provider routing and repeat creation
// labels through the real in-memory reference module. The model checks inventory
// after every operation, including empty state, duplicates and missing IDs.
#[hegel::test]
fn generated_provider_lifecycle(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let count = tc.draw(gs::integers::<usize>().min_value(0).max_value(9));
    let steps: Vec<_> = (0..count)
        .map(|_| {
            (
                tc.draw(gs::integers::<usize>().min_value(0).max_value(2)),
                tc.draw(gs::integers::<usize>().min_value(0).max_value(1)),
                tc.draw(gs::integers::<usize>().min_value(0).max_value(2)),
            )
        })
        .collect();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let (socket, task) = reference(dir.path()).await;
        let token = dir.path().join("token");
        std::fs::write(&token, "token").unwrap();
        let run = dir.path().join("run");
        let daemon = Daemon::start(
            Config::parse(&config_text(&token)).unwrap(),
            &run,
            run.join("keys"),
            vec![HostOption { optional: false, name: "rust".into(), connection: HostConnection::ExternalUnix { path: socket } }],
        )
        .await
        .unwrap();
        let api: &dyn ProviderApi = daemon.as_ref();
        let mut model = std::collections::BTreeMap::<(usize, usize), Environment>::new();
        for (operation, p, label) in steps {
            let provider = ["demo", "other"][p];
            match operation {
                0 => {
                    let size = Size { cpus: 1., memory_bytes: 1024, disk_bytes: 0 };
                    let prepared = api
                        .prepare(
                            provider,
                            &PrepareRequest {
                                platform: None,
                                route: None,
                                image_pull: None,
                                size: size.clone(),
                                image_digest: "image".into(),
                                tools_digest: "tools".into(),
                            },
                        )
                        .await
                        .unwrap();
                    let request = ProvisionRequest {
                        label: format!("label-{label}"),
                        prepared,
                        size,
                        egress: EgressRequest::default(),
                        ssh_public_key: None,
                    };
                    let env = api.provision(provider, &request).await.unwrap();
                    if let Some(previous) = model.insert((p, label), env.clone()) {
                        assert_eq!(previous, env);
                    }
                }
                1 => {
                    let id = model.remove(&(p, label)).map(|e| e.id).unwrap_or_else(|| "absent".into());
                    api.destroy(provider, &id).await.unwrap();
                    api.destroy(provider, &id).await.unwrap();
                }
                _ => {
                    if let Some(env) = model.get(&(p, label)) {
                        assert_eq!(&api.inspect(provider, &env.id).await.unwrap(), env);
                    } else {
                        assert!(api.inspect(provider, "absent").await.is_err());
                    }
                }
            }
            for (p, provider) in ["demo", "other"].into_iter().enumerate() {
                let mut actual = api.list(provider).await.unwrap();
                actual.sort_by(|a, b| a.id.cmp(&b.id));
                let mut expected: Vec<_> = model.iter().filter(|((owner, _), _)| *owner == p).map(|(_, e)| e.clone()).collect();
                expected.sort_by(|a, b| a.id.cmp(&b.id));
                assert_eq!(actual, expected);
            }
        }
        drop(daemon);
        task.abort();
    });
}

// Provider diagnostics survive the extra daemon hop and CLI formatting, while
// credential values echoed by a module stay masked. No vendor API is involved.
#[tokio::test]
async fn cli_preserves_masked_provider_diagnostics() {
    let dir = tempfile::tempdir().unwrap();
    let (host, task) = reference(dir.path()).await;
    let token = dir.path().join("token");
    std::fs::write(&token, "test-secret-value").unwrap();
    let text = format!(
        r#"[provider.broken]
module="reference"
credential={{file={:?}}}
settings={{fault={{kind="internal",reason="HTTP 400 vendor validation",provider_error="test-secret-value rejected"}}}}
"#,
        token.to_str().unwrap()
    );
    let run = dir.path().join("run");
    let daemon = Daemon::start(
        Config::parse(&text).unwrap(),
        &run,
        run.join("keys"),
        vec![HostOption { optional: false, name: "rust".into(), connection: HostConnection::ExternalUnix { path: host } }],
    )
    .await
    .unwrap();
    let socket = run.join("api.sock");
    let path = socket.clone();
    let server = tokio::spawn(async move {
        daemon.serve(&path, std::future::pending()).await.unwrap();
    });
    let client = Client::unix(&socket).unwrap();
    for _ in 0..200 {
        if client.hello().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let output = cli(&dir.path().join("unused.toml"), &socket, std::path::Path::new("/not-needed"), &["list", "broken"]).await;
    assert!(!output.status.success());
    let text = String::from_utf8(output.stderr).unwrap();
    for expected in ["internal", "broken", "list", "400", "vendor validation", "<REDACTED>"] {
        assert!(text.contains(expected), "{text}");
    }
    assert!(!text.contains("test-secret-value"));
    server.abort();
    task.abort();
}

// Optional language companions can fail without taking down a healthy Rust
// provider. Failed/unloadable modules stay visible and unusable with a reason.
// The resolver double stands only at the registry/network boundary.
#[tokio::test]
async fn optional_discovery_failure_is_isolated_and_required_failure_is_reported() {
    struct Resolver;
    #[async_trait::async_trait]
    impl drydock::launch::ImageResolver for Resolver {
        async fn resolve(&self, image: &str) -> Result<String, drydock::client::Error> {
            Ok(image.into())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let (socket, task) = reference(dir.path()).await;
    let token = dir.path().join("token");
    std::fs::write(&token, "token").unwrap();
    let config = Config::parse(&(config_text(&token) + "\n[provider.python]\nmodule='python-only'\ncredential={env='PATH'}\n")).unwrap();
    let broken = |optional| HostOption {
        name: "python".into(),
        optional,
        connection: HostConnection::Managed { command: vec!["/bin/false".into()], runtime: None, proxy_environment: Default::default() },
    };
    let run = dir.path().join("run");
    let daemon = Daemon::start_with_resolver(
        config.clone(),
        &run,
        run.join("keys"),
        vec![
            HostOption { name: "rust".into(), optional: false, connection: HostConnection::ExternalUnix { path: socket.clone() } },
            broken(true),
        ],
        std::sync::Arc::new(Resolver),
    )
    .await
    .unwrap();
    assert_eq!(daemon.providers()[0]["readiness"]["status"], "ready");
    let row = daemon.providers().as_array().unwrap().iter().find(|p| p["provider"] == "python").unwrap().clone();
    assert_eq!(row["readiness"]["status"], "missing_tool");
    assert!(row["readiness"]["reason"].as_str().unwrap().contains("optional host unavailable"));
    assert!(matches!(
        ProviderApi::list(daemon.as_ref(), "python").await,
        Err(drydock::client::Error::NotReady(Readiness::MissingTool { .. }))
    ));
    let environment = routing_environment(&daemon, &socket).await;
    assert_eq!(ProviderApi::list(daemon.as_ref(), "demo").await.unwrap(), vec![environment]);
    let required_run = dir.path().join("required");
    let error = Daemon::start(config, &required_run, required_run.join("keys"), vec![broken(false)]).await.err().unwrap();
    assert!(error.contains("host exited during discovery"));
    drop(daemon);
    task.abort();
}

// Launch waits for the agent hello because the provider declares that its
// vessels run the agent, whatever its module. The reference module has no
// guest, so a declaring provider must fail launch naming the agent, while an
// identical provider that does not declare it launches as before.
#[tokio::test]
async fn launch_waits_for_agent_hello_only_when_declared() {
    if drydock::launch::build_tools_digest().is_err() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (socket, task) = reference(dir.path()).await;
    let image = format!("image@sha256:{}", "a".repeat(64));
    let text = format!(
        "[provider.plain]\nmodule='reference'\ncredential={{env='PATH'}}\nimage='{image}'\nsettings={{}}\n\
         [provider.agent]\nmodule='reference'\ncredential={{env='PATH'}}\nimage='{image}'\nsettings={{agent=true}}\n\
         [provider.foreign]\nmodule='reference'\ncredential={{env='PATH'}}\nimage='{image}'\n\
         settings={{agent=true, platforms=[{{os='linux', architecture='riscv64'}}]}}\n"
    );
    let run = dir.path().join("run");
    let daemon = Daemon::start(
        Config::parse(&text).unwrap(),
        &run,
        run.join("keys"),
        vec![HostOption { optional: false, name: "external".into(), connection: HostConnection::ExternalUnix { path: socket.clone() } }],
    )
    .await
    .unwrap();
    let host = Client::unix(&socket).unwrap();
    let hello = host.hello().await.unwrap();
    let declares = |name: &str| hello.providers.iter().find(|p| p.provider == name).unwrap().capabilities.agent;
    assert_eq!((declares("plain"), declares("agent")), (false, true));
    daemon.launch("plain", &drydock::launch::LaunchOptions::default()).await.unwrap();
    let error = tokio::time::timeout(Duration::from_secs(10), daemon.launch("agent", &drydock::launch::LaunchOptions::default()))
        .await
        .expect("a reach without SSH is refused at once, not retried")
        .err()
        .unwrap();
    let message = error.to_string();
    assert!(message.contains("drydock-agent") || message.contains("agent hello requires an SSH reach"), "{message}");
    // No build for the prepared platform: refused before anything is created.
    let error = daemon.launch("foreign", &drydock::launch::LaunchOptions::default()).await.err().unwrap().to_string();
    assert!(error.contains("no vessel agent build for linux/riscv64: install drydock-agent-linux-riscv64"), "{error}");
    assert!(host.list("foreign").await.unwrap().is_empty());
    task.abort();
}
// The prepared platform defaults to the provider's first declared one, can be
// chosen among the declared ones, is recorded on the environment, and a
// platform the provider doesn't declare is refused naming what it offers.
#[tokio::test]
async fn launch_records_the_prepared_platform() {
    if drydock::launch::build_tools_digest().is_err() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (socket, task) = reference(dir.path()).await;
    let image = format!("image@sha256:{}", "a".repeat(64));
    let text = format!("[provider.plain]\nmodule='reference'\ncredential={{env='PATH'}}\nimage='{image}'\nsettings={{}}\n");
    let run = dir.path().join("run");
    let daemon = Daemon::start(
        Config::parse(&text).unwrap(),
        &run,
        run.join("keys"),
        vec![HostOption { optional: false, name: "external".into(), connection: HostConnection::ExternalUnix { path: socket.clone() } }],
    )
    .await
    .unwrap();
    let launch = |platform: Option<&str>| {
        let options = drydock::launch::LaunchOptions { platform: platform.map(|p| p.parse().unwrap()), ..Default::default() };
        let daemon = &daemon;
        async move { daemon.launch("plain", &options).await }
    };
    assert_eq!(launch(None).await.unwrap().platform, Some(Platform::new("linux", "amd64")));
    assert_eq!(launch(Some("linux/arm64")).await.unwrap().platform, Some(Platform::new("linux", "arm64")));
    let error = launch(Some("linux/s390x")).await.err().unwrap().to_string();
    assert!(error.contains("provider cannot run linux/s390x; it offers linux/amd64, linux/arm64"), "{error}");
    task.abort();
}

// A language-host boundary double alters advertisements while retaining the
// real reference host's configuration, credentials, provider calls and streams.
async fn advertised_host(
    dir: &std::path::Path,
    version: &'static str,
    incompatible: bool,
) -> (std::path::PathBuf, tokio::task::JoinHandle<()>, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use axum::{
        body::{Body, to_bytes},
        extract::Request,
        middleware::{self, Next},
    };
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let host = drydock_host::Host::new(drydock_host::reference::registry());
    let state = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let current = state.clone();
    let router = host.router().layer(middleware::from_fn(move |req: Request, next: Next| {
        let current = current.clone();
        async move {
            let hello = req.uri().path() == "/v1/hello";
            let response = next.run(req).await;
            if !hello {
                return response;
            }
            let (parts, body) = response.into_parts();
            let mut hello: Hello = serde_json::from_slice(&to_bytes(body, usize::MAX).await.unwrap()).unwrap();
            let phase = current.load(std::sync::atomic::Ordering::SeqCst);
            let version = if phase > 0 { "upgraded" } else { version };
            if phase == 2 {
                for p in &mut hello.providers {
                    p.readiness =
                        Readiness::Unknown { reason: format!("host diagnostic test-identity nested-setting {}", "界".repeat(20000)) };
                }
            }
            for m in &mut hello.modules {
                m.version = version.into();
            }
            for m in &mut hello.loadable_modules {
                m.version = version.into();
            }
            hello.loadable_modules.push(LoadableModule {
                name: format!("unused-{version}"),
                version: version.into(),
                smallest_size: Size { cpus: 1., memory_bytes: 1, disk_bytes: 1 },
            });
            if incompatible {
                hello.protocol_version = "incompatible".into();
            }
            axum::response::Response::from_parts(parts, Body::from(serde_json::to_vec(&hello).unwrap()))
        }
    }));
    let socket = dir.join(format!("{version}.sock"));
    let server = rigging_http_serve::UnixServer::bind(&socket, 0o600).await.unwrap();
    let task = tokio::spawn(async move {
        server.serve(router, rigging_http_serve::Caller::<()>::Unix, std::future::pending()).await.unwrap();
    });
    (socket, task, state)
}

async fn discovery_contract(api: std::sync::Arc<dyn ProviderApi>, recovered: bool) -> Hello {
    let hello = api.hello().await.unwrap();
    assert!(hello.is_compatible());
    assert_eq!(hello.providers.iter().map(|p| p.provider.as_str()).collect::<Vec<_>>(), ["demo", "missing", "other", "recover"]);
    assert_eq!(hello.modules.iter().map(|m| (m.name.as_str(), m.version.as_str())).collect::<Vec<_>>(), [("reference", "first")]);
    assert_eq!(
        hello.loadable_modules.iter().map(|m| (m.name.as_str(), m.version.as_str())).collect::<Vec<_>>(),
        [("reference", "first"), ("unused-first", "first"), ("unused-second", "second")]
    );
    let missing = &hello.providers[1];
    assert!(
        matches!(&missing.readiness, Readiness::MissingTool { reason } if reason.len() <= 16384 && reason.contains("optional host protocol version mismatch"))
    );
    assert!(missing.capabilities.platforms.is_empty());
    assert!(missing.capabilities.material_modes.is_empty());
    assert!(!missing.capabilities.agent && !missing.capabilities.quota && !missing.capabilities.usage);
    assert!(matches!(hello.providers[0].readiness, Readiness::Ready));
    if recovered {
        assert!(matches!(hello.providers[3].readiness, Readiness::Ready));
    } else {
        assert!(matches!(hello.providers[3].readiness, Readiness::MissingCredential { .. }));
    }
    hello
}

// Discovery is identical through an object-safe embedded API (before any daemon
// listener exists) and its real Unix socket, including duplicate module choice,
// optional protocol failure, missing modules and credential readiness recovery.
#[tokio::test]
async fn typed_discovery_parity_and_recovery() {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let (first, first_task, phase) = advertised_host(dir.path(), "first", false).await;
    let (second, second_task, _) = advertised_host(dir.path(), "second", false).await;
    let (bad, bad_task, _) = advertised_host(dir.path(), "bad", true).await;
    let incompatible: Arc<dyn ProviderApi> = Arc::new(Client::unix(&bad).unwrap());
    assert!(matches!(incompatible.hello().await, Err(drydock::client::Error::VersionMismatch)));
    let token = dir.path().join("token");
    let recovery = dir.path().join("recover");
    std::fs::write(&token, "test-identity").unwrap();
    let config = Config::parse(&(config_text(&token).replace("fixture = true,", "fixture = true, reach = {kind = 'relay', path = 'nested-setting'},") + &format!("\n[provider.missing]\nmodule='absent'\ncredential={{file={:?}}}\n[provider.recover]\nmodule='reference'\ncredential={{file={:?}}}\nsettings={{fixture=true}}\n", token, recovery))).unwrap();
    let run = dir.path().join("run");
    let options = [("first", first), ("second", second), ("bad", bad)]
        .into_iter()
        .map(|(name, path)| HostOption { name: name.into(), optional: true, connection: HostConnection::ExternalUnix { path } })
        .collect();
    let daemon = Daemon::start(config, &run, run.join("keys"), options).await.unwrap();
    let embedded: Arc<dyn ProviderApi> = daemon.clone();
    let expected = discovery_contract(embedded.clone(), false).await;
    let socket = run.join("api.sock");
    assert!(!socket.exists());
    let d = daemon.clone();
    let bind = socket.clone();
    let server = tokio::spawn(async move {
        d.serve(&bind, std::future::pending()).await.unwrap();
    });
    let client = Client::unix(&socket).unwrap();
    for _ in 0..200 {
        if client.hello().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let remote: Arc<dyn ProviderApi> = Arc::new(client);
    assert_eq!(discovery_contract(remote.clone(), false).await, expected);
    std::fs::write(&recovery, "recovered-test-identity").unwrap();
    for _ in 0..400 {
        if matches!(embedded.hello().await.unwrap().providers[3].readiness, Readiness::Ready) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(discovery_contract(embedded.clone(), true).await, discovery_contract(remote.clone(), true).await);
    phase.store(1, std::sync::atomic::Ordering::SeqCst);
    for _ in 0..400 {
        if embedded.hello().await.unwrap().modules[0].version == "upgraded" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let upgraded = embedded.hello().await.unwrap();
    assert_eq!(upgraded.modules[0].version, "upgraded");
    assert_eq!(upgraded.loadable_modules[0].version, "upgraded");
    assert!(!upgraded.loadable_modules.iter().any(|m| m.name == "unused-first"));
    assert_eq!(upgraded, remote.hello().await.unwrap());
    phase.store(2, std::sync::atomic::Ordering::SeqCst);
    for _ in 0..400 {
        if matches!(embedded.hello().await.unwrap().providers[0].readiness, Readiness::Unknown { .. }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let diagnostic = embedded.hello().await.unwrap();
    let Readiness::Unknown { reason } = &diagnostic.providers[0].readiness else {
        panic!("expected host diagnostic");
    };
    assert!(reason.len() <= 16384 && reason.contains("host diagnostic") && reason.contains("<REDACTED>"));
    assert!(!reason.contains("test-identity") && !reason.contains("nested-setting"));
    assert_eq!(diagnostic, remote.hello().await.unwrap());
    server.abort();
    first_task.abort();
    second_task.abort();
    bad_task.abort();
}

// With no hosts or configured instances, embedded discovery is a compatible
// empty document; adding an unserved instance preserves its identity honestly.
#[tokio::test]
async fn discovery_without_hosts_or_listener() {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    for text in ["", "[provider.unavailable]\nmodule='absent'\ncredential={env='DRYDOCK_TEST_MISSING_CREDENTIAL'}\n"] {
        let run = dir.path().join(if text.is_empty() { "empty" } else { "configured" });
        let api: Arc<dyn ProviderApi> = Daemon::start(Config::parse(text).unwrap(), &run, run.join("keys"), vec![]).await.unwrap();
        let hello = api.hello().await.unwrap();
        assert!(hello.is_compatible());
        assert!(hello.modules.is_empty() && hello.loadable_modules.is_empty());
        if text.is_empty() {
            assert!(hello.providers.is_empty());
        } else {
            assert_eq!(hello.providers.len(), 1);
            assert_eq!(hello.providers[0].provider, "unavailable");
            assert!(matches!(hello.providers[0].readiness, Readiness::MissingTool { .. }));
        }
        assert!(!run.join("api.sock").exists());
    }
}

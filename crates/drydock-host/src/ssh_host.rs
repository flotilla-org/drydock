//! Host-direct vessels on a machine drydock reaches over SSH, one instance per
//! machine. Each vessel is a directory on the machine and a process tree its
//! agent starts there, as `local`'s are (see [`kit::vessels`]): the machine's
//! processes and filesystem are visible to it, and its egress is open.
//!
//! Control is the SSH session alone, pinned to the machine's host key and the
//! private key file its settings name; drydock reads no ssh_config or ssh-agent. Commands
//! run through exec, files go in on exec's stdin, and the relay is a stream to
//! the agent's socket over the session. Each agent runs as a transient service
//! of the user's systemd manager, so stopping the unit ends everything the
//! vessel started. Where the manager has the memory and cpu controllers
//! delegated, the unit carries the vessel's limits; where it does not, the
//! machine takes one vessel at a time, granted the whole machine.
use crate::{
    kit::{
        self,
        vessels::{self, AGENT, Found, Grant, LOG, Machine, RECORD, Record, SOCKET, SUSPENDED, Vessels, unavailable},
    },
    module::*,
};
use async_trait::async_trait;
use drydock_protocol::*;
use futures::FutureExt;
use rigging_ssh::{OpenSsh, SshSession, Target};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};
use tokio::io::AsyncRead;

const PREFIX: &str = "ssh";
const CONNECT: Duration = Duration::from_secs(10);
/// How long one command may take; the agent's upload has its own budget.
const COMMAND: Duration = Duration::from_secs(60);
const UPLOAD: Duration = Duration::from_secs(300);
const POLL: Duration = Duration::from_secs(5);

pub struct SshHostModule;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    address: String,
    port: u16,
    user: String,
    /// The machine's host public key, as `ssh-ed25519 AAAA…`.
    host_key: String,
    /// The private key drydock authenticates with: an absolute path on drydock's machine.
    identity_file: PathBuf,
    /// Where vessel directories live. Defaults to `drydock` under the user's XDG_RUNTIME_DIR.
    directory: Option<String>,
}

#[async_trait]
impl Module for SshHostModule {
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn smallest_size(&self) -> Size {
        Size { cpus: 1.0, memory_bytes: kit::GIB, disk_bytes: 0 }
    }
    async fn configure(&self, name: &str, c: &ProviderConfiguration, _: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
        let settings: Settings = serde_json::from_value(serde_json::to_value(&c.settings).expect("settings map")).map_err(|e| {
            refused(format!("invalid ssh_host settings (address, port, user, host_key and identity_file, and an optional directory): {e}"))
        })?;
        if !settings.identity_file.is_absolute() {
            return Err(refused(format!("the identity_file {:?} must be an absolute path", settings.identity_file)));
        }
        if let Some(directory) = &settings.directory {
            check_directory(directory).map_err(refused)?;
        }
        Ok(Arc::new(Vessels::new(name, SshHost { settings, connection: tokio::sync::Mutex::new(None), stated: Mutex::default() })))
    }
}

/// A path the commands, the agent's unit and the session's forwards all take:
/// absolute, and nothing a shell, systemd or a forward specification reads specially.
fn check_directory(path: &str) -> std::result::Result<(), String> {
    if path.starts_with('/')
        && !path.contains(|c: char| c.is_whitespace() || c.is_control() || matches!(c, ':' | '\'' | '"' | '\\' | '`' | '$' | '%'))
    {
        Ok(())
    } else {
        Err(format!(
            "the vessels' directory {path:?} must be an absolute path without whitespace, colons, quotes, backslashes, backticks, `$` or `%`"
        ))
    }
}

/// What the machine says of itself.
#[derive(Clone)]
struct Facts {
    platform: Option<Platform>,
    root: Option<PathBuf>,
    cpus: f64,
    memory_bytes: u64,
    /// The user's systemd manager answers, and keeps running without a login.
    manager: bool,
    lingering: bool,
    /// The manager has the memory and cpu controllers, so a unit's limits hold.
    enforced: bool,
}

struct SshHost {
    settings: Settings,
    connection: tokio::sync::Mutex<Option<Arc<OpenSsh>>>,
    /// Readiness and what the machine last said, from the last refresh.
    stated: Mutex<(Option<Readiness>, Option<Facts>)>,
}

/// A failed command, its stderr as the provider's words.
fn failed(doing: &str, output: &std::process::Output) -> ProtocolError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    ProtocolError::Unavailable {
        reason: format!("{doing} failed on the machine ({})", output.status),
        retry_after: None,
        provider_error: Some(stderr.char_indices().rev().nth(2047).map_or(&stderr[..], |(at, _)| &stderr[at..]).to_owned()),
    }
}

impl SshHost {
    fn machine(&self) -> String {
        format!("{}@{}:{}", self.settings.user, self.settings.address, self.settings.port)
    }
    fn facts(&self) -> Option<Facts> {
        self.stated.lock().unwrap_or_else(PoisonError::into_inner).1.clone()
    }
    /// The live session, or a new one.
    async fn session(&self) -> Result<Arc<OpenSsh>> {
        let mut connection = self.connection.lock().await;
        if let Some(live) = connection.as_ref().filter(|live| live.closed().now_or_never().is_none()) {
            return Ok(live.clone());
        }
        *connection = None;
        let target = Target::Pinned {
            host: self.settings.address.clone(),
            port: self.settings.port,
            user: self.settings.user.clone(),
            host_key: self.settings.host_key.clone(),
            identity_file: self.settings.identity_file.clone(),
        };
        let session = OpenSsh::connect(target, CONNECT).await.map_err(|e| ProtocolError::Unavailable {
            reason: format!("SSH connection to {} failed", self.machine()),
            retry_after: None,
            provider_error: Some(e.to_string()),
        })?;
        let session = Arc::new(session);
        *connection = Some(session.clone());
        Ok(session)
    }
    /// `script` run by `sh` on the machine with `args` as its positional
    /// parameters, and `input`, if any, on its stdin.
    async fn run(&self, script: &str, args: &[&str], input: Option<&mut (dyn AsyncRead + Send + Unpin)>) -> Result<std::process::Output> {
        let session = self.session().await?;
        let argv: Vec<String> = ["sh", "-c", script, "sh"].iter().chain(args).map(|s| s.to_string()).collect();
        let command = kit::shell_command(&argv);
        let (ran, budget) = match input {
            Some(input) => (tokio::time::timeout(UPLOAD, session.exec_with_input(&command, input)).await, UPLOAD),
            None => (tokio::time::timeout(COMMAND, session.exec(&command)).await, COMMAND),
        };
        let lost = |error: String| ProtocolError::Unavailable {
            reason: format!("command on {} did not complete", self.machine()),
            retry_after: None,
            provider_error: Some(error),
        };
        ran.map_err(|_| lost(format!("no answer within {budget:?}")))?.map_err(|e| lost(e.to_string()))
    }
    /// `run`, its stdout when it succeeds.
    async fn ok(&self, doing: &str, script: &str, args: &[&str]) -> Result<String> {
        let output = self.run(script, args, None).await?;
        if !output.status.success() {
            return Err(failed(doing, &output));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
    async fn probe(&self) -> Result<Facts> {
        const SCRIPT: &str = r#"
printf 'os=%s\narch=%s\nruntime=%s\ncpus=%s\n' "$(uname -s)" "$(uname -m)" "${XDG_RUNTIME_DIR-}" "$(nproc)"
awk '/^MemTotal:/ { print "memory_kib=" $2 }' /proc/meminfo
cg=$(systemctl --user show --value -p ControlGroup 2>/dev/null) || cg=
printf 'manager=%s\n' "$cg"
if [ -n "$cg" ] && [ -r "/sys/fs/cgroup$cg/cgroup.controllers" ]; then
  printf 'controllers=%s\n' "$(cat "/sys/fs/cgroup$cg/cgroup.controllers")"
fi
printf 'linger=%s\n' "$(loginctl show-user "$(id -u)" --value -p Linger 2>/dev/null)"
"#;
        let text = self.ok("reading the machine's facts", SCRIPT, &[]).await?;
        let value = |key: &str| text.lines().find_map(|line| line.strip_prefix(key)?.strip_prefix('=')).unwrap_or("").trim();
        let platform = (value("os") == "Linux").then(|| {
            let architecture = match value("arch") {
                "x86_64" => "amd64",
                "aarch64" => "arm64",
                other => other,
            };
            Platform::new("linux", architecture)
        });
        let root = match &self.settings.directory {
            Some(directory) => Some(PathBuf::from(directory)),
            None => Some(value("runtime")).filter(|r| check_directory(r).is_ok()).map(|r| Path::new(r).join("drydock")),
        };
        let controllers: Vec<&str> = value("controllers").split_whitespace().collect();
        let facts = Facts {
            platform,
            root,
            cpus: value("cpus").parse().unwrap_or(0.0),
            memory_bytes: value("memory_kib").parse::<u64>().unwrap_or(0).saturating_mul(1024),
            manager: !value("manager").is_empty(),
            lingering: value("linger") == "yes",
            enforced: controllers.contains(&"memory") && controllers.contains(&"cpu"),
        };
        self.stated.lock().unwrap_or_else(PoisonError::into_inner).1 = Some(facts.clone());
        Ok(facts)
    }
    /// What the machine said last, or says now.
    async fn known(&self) -> Result<Facts> {
        match self.facts() {
            Some(facts) => Ok(facts),
            None => self.probe().await,
        }
    }
    async fn root(&self) -> Result<PathBuf> {
        self.known().await?.root.ok_or_else(|| {
            refused(format!("{} has no XDG_RUNTIME_DIR for its vessels; set `directory` in the instance's settings", self.machine()))
        })
    }
    async fn dir(&self, id: &str) -> Result<String> {
        Ok(self.root().await?.join(id).to_string_lossy().into_owned())
    }
    /// Each vessel under the root (or only `id`), with the CPU and memory limits
    /// its unit's cgroup holds it to while it runs.
    async fn survey(&self, only: Option<&str>) -> Result<Vec<(Found, Option<(f64, u64)>)>> {
        const SCRIPT: &str = r#"
cd "$1" 2>/dev/null || exit 0
for d in $2; do
  [ -f "$d/environment.json" ] || continue
  u="drydock-$d.service"
  state=$(systemctl --user show --value -p ActiveState "$u" 2>/dev/null)
  cg=$(systemctl --user show --value -p ControlGroup "$u" 2>/dev/null)
  cpu=-; memory=-
  if [ "$state" = active ] && [ -n "$cg" ]; then
    cpu=$(tr ' ' / < "/sys/fs/cgroup$cg/cpu.max" 2>/dev/null) || cpu=-
    memory=$(cat "/sys/fs/cgroup$cg/memory.max" 2>/dev/null) || memory=-
  fi
  if [ -e "$d/suspended" ]; then mark=suspended; else mark=kept; fi
  record=$(tr -d '\n' < "$d/environment.json") || continue
  printf '%s %s %s %s %s %s\n' "$d" "${state:-unknown}" "$mark" "${cpu:--}" "${memory:--}" "$record"
done
"#;
        let root = self.root().await?;
        let pattern = only.map_or_else(|| format!("{PREFIX}-*"), str::to_owned);
        let text = self.ok("listing vessels", SCRIPT, &[&root.to_string_lossy(), &pattern]).await?;
        let machine = self.facts();
        let mut found = vec![];
        for line in text.lines() {
            let fields: Vec<&str> = line.splitn(6, ' ').collect();
            let [id, state, mark, cpu, memory, record] = fields[..] else { continue };
            if !vessels::valid_id(PREFIX, id) {
                continue;
            }
            let record: Record = match serde_json::from_str(record) {
                Ok(record) => record,
                Err(error) if only.is_some() => return Err(vessels::internal(format!("environment record: {error}"))),
                Err(error) => {
                    tracing::warn!(%id, %error, "skipping an ssh_host vessel whose record cannot be read");
                    continue;
                }
            };
            // An unlimited cgroup has the whole machine.
            let limits = (state == "active").then(|| {
                let cpus = match cpu.split_once('/') {
                    Some((quota, period)) => quota.parse::<f64>().ok().zip(period.parse::<f64>().ok()).map(|(q, p)| q / p),
                    None => None,
                };
                let whole = machine.as_ref().map_or((0.0, 0), |m| (m.cpus, m.memory_bytes));
                (cpus.unwrap_or(whole.0), memory.parse().unwrap_or(whole.1))
            });
            let reason = (record.grant == Some(Grant::WholeMachine))
                .then(|| "granted the whole machine, shared with whatever runs on it outside drydock".to_owned());
            let vendor = Some(VendorState { state: state.to_owned(), reason, tags: None });
            found.push((Found { id: id.to_owned(), record, running: state == "active", suspended: mark == "suspended", vendor }, limits));
        }
        Ok(found)
    }
}

#[async_trait]
impl Machine for SshHost {
    fn prefix(&self) -> &'static str {
        PREFIX
    }
    fn capabilities(&self) -> Capabilities {
        let facts = self.facts();
        let platforms = facts.as_ref().and_then(|f| f.platform.clone()).into_iter().collect();
        let root = facts.and_then(|f| f.root).map(|r| r.to_string_lossy().into_owned()).unwrap_or_default();
        Capabilities { quota: true, ..vessels::capabilities(platforms, root) }
    }
    fn ways_in(&self) -> Vec<WayIn> {
        vec![WayIn::Poll { interval_ms: POLL.as_millis() as u64 }]
    }
    fn readiness(&self, _: &Credentials) -> Readiness {
        if let Err(e) = std::fs::File::open(&self.settings.identity_file) {
            return Readiness::MissingCredential {
                reason: format!("the identity_file {} cannot be read: {e}", self.settings.identity_file.display()),
            };
        }
        let stated = self.stated.lock().unwrap_or_else(PoisonError::into_inner).0.clone();
        stated.unwrap_or_else(|| Readiness::Unknown { reason: format!("{} has not been asked yet", self.machine()) })
    }
    /// Connects, and reads what the machine says of itself.
    async fn refresh_readiness(&self, _: &Credentials) {
        let missing = |reason: String| Readiness::MissingTool { reason };
        let readiness = match self.probe().await {
            Err(error) => Readiness::Unknown { reason: error.to_string() },
            Ok(Facts { platform: None, .. }) => missing(format!("{} is not Linux", self.machine())),
            Ok(Facts { manager: false, .. }) => {
                missing(format!("{} runs no systemd user manager for {}", self.machine(), self.settings.user))
            }
            Ok(Facts { lingering: false, .. }) => missing(format!(
                "vessels outlive drydock's connection only where the user lingers: loginctl enable-linger {}",
                self.settings.user
            )),
            Ok(Facts { root: None, .. }) => missing(format!("{} has no XDG_RUNTIME_DIR; set `directory`", self.machine())),
            Ok(Facts { platform: Some(platform), .. }) => match drydock_provider::agent_build::agent_build(&platform) {
                Ok(_) => Readiness::Ready,
                Err(reason) => missing(reason),
            },
        };
        self.stated.lock().unwrap_or_else(PoisonError::into_inner).0 = Some(readiness);
    }
    fn platform(&self) -> Option<Platform> {
        self.facts()?.platform
    }
    /// Limits where the machine enforces them; otherwise the whole machine, to one vessel at a time.
    async fn grant(&self, size: &Size, _: &Credentials) -> Result<(Size, Option<Grant>)> {
        if size.disk_bytes != 0 {
            return Err(refused("ssh_host sets no per-vessel disk size: ask for a disk of 0"));
        }
        let facts = self.probe().await?;
        if facts.enforced {
            if size.memory_bytes == 0 {
                return Err(refused("ssh_host takes a positive memory size"));
            }
            return Ok((size.clone(), Some(Grant::Limits)));
        }
        if let Some((held, _)) = self.survey(None).await?.first() {
            return Err(ProtocolError::QuotaExhausted {
                reason: format!(
                    "{} cannot enforce per-vessel limits (its systemd user manager has no memory and cpu controllers delegated), so it takes one vessel at a time, and holds {}: destroy that vessel, suspended or not, to free the machine",
                    self.machine(),
                    held.id
                ),
            });
        }
        Ok((Size { cpus: facts.cpus, memory_bytes: facts.memory_bytes, disk_bytes: 0 }, Some(Grant::WholeMachine)))
    }
    async fn vessels(&self, only: Option<&str>, _: &Credentials) -> Result<Vec<Found>> {
        Ok(self.survey(only).await?.into_iter().map(|(found, _)| found).collect())
    }
    async fn create(&self, id: &str, record: &Record, c: &Credentials) -> Result<()> {
        let dir = self.dir(id).await?;
        vessels::check_socket(Path::new(&dir), "directory")?;
        let platform = record.platform.as_ref().ok_or_else(|| refused("a vessel needs its platform"))?;
        let build = drydock_provider::agent_build::agent_build(platform)
            .map_err(|reason| unavailable(format!("no agent build for {platform}: {reason}")))?;
        let build_error = |e: std::io::Error| unavailable(format!("agent build {}: {e}", build.display()));
        let mut file = tokio::fs::File::open(&build).await.map_err(build_error)?;
        let length = file.metadata().await.map_err(build_error)?.len().to_string();
        const UPLOAD_AGENT: &str = r#"umask 077 && mkdir -p "$1/opt/drydock" "$1/run/drydock" && cat > "$1/$2" && [ "$(wc -c < "$1/$2")" -eq "$3" ] && chmod 700 "$1/$2""#;
        const WRITE_RECORD: &str = r#"umask 077 && cat > "$1/$2.new" && mv "$1/$2.new" "$1/$2""#;
        let record = serde_json::to_vec(record).expect("record serializes");
        let made = async {
            let output = self.run(UPLOAD_AGENT, &[&dir, AGENT, &length], Some(&mut file)).await?;
            if !output.status.success() {
                return Err(failed("uploading the agent", &output));
            }
            let output = self.run(WRITE_RECORD, &[&dir, RECORD], Some(&mut &record[..])).await?;
            if !output.status.success() {
                return Err(failed("writing the vessel's record", &output));
            }
            Ok(())
        }
        .await;
        if made.is_err() {
            let _ = self.remove(id, c).await;
        }
        made
    }
    /// A transient service of the user's manager, holding everything the agent starts.
    async fn launch(&self, id: &str, record: &Record, _: &Credentials) -> Result<()> {
        const SCRIPT: &str = r#"
d="$1/$2"; u="drydock-$2.service"; agent="$d/$3"; socket="$d/$4"; log="$d/$5"; shift 5
systemctl --user reset-failed "$u" 2>/dev/null
rm -f "$socket"
exec systemd-run --user --quiet --collect --unit="$u" --service-type=exec --working-directory="$d" \
  -p KillMode=control-group -p TimeoutStopSec=2 -p StandardOutput="append:$log" -p StandardError="append:$log" \
  "$@" -- "$agent" --socket "$socket"
"#;
        let root = self.root().await?.to_string_lossy().into_owned();
        let mut args: Vec<String> = [&root, id, AGENT, SOCKET, LOG].map(str::to_owned).into();
        if let (Some(Grant::Limits), Some(size)) = (record.grant, &record.size) {
            let cpu = format!("CPUQuota={}%", (size.cpus * 100.0).round().max(1.0));
            args.extend(["-p".into(), format!("MemoryMax={}", size.memory_bytes), "-p".into(), "MemorySwapMax=0".into(), "-p".into(), cpu]);
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        self.ok("starting the agent", SCRIPT, &args).await.map(drop)
    }
    async fn running(&self, id: &str, _: &Credentials) -> Result<bool> {
        let script = r#"systemctl --user is-active --quiet "drydock-$1.service""#;
        Ok(self.run(script, &[id], None).await?.status.success())
    }
    /// Each look is a stream and a command over the session.
    fn startup_poll(&self) -> Duration {
        Duration::from_millis(250)
    }
    async fn stop(&self, id: &str, _: &Credentials) -> Result<()> {
        const SCRIPT: &str = r#"
u="drydock-$1.service"
systemctl --user stop "$u" 2>/dev/null
systemctl --user reset-failed "$u" 2>/dev/null
! systemctl --user is-active --quiet "$u"
"#;
        self.ok("stopping the vessel", SCRIPT, &[id]).await.map(drop)
    }
    async fn remove(&self, id: &str, _: &Credentials) -> Result<()> {
        // The agent's artifact store keeps its unpacked trees read-only; chmod -R follows no link.
        const SCRIPT: &str = r#"[ ! -e "$1" ] || { chmod -R u+w "$1" 2>/dev/null; rm -rf "$1"; }"#;
        let dir = self.dir(id).await?;
        self.ok("removing the vessel's directory", SCRIPT, &[&dir]).await.map(drop)
    }
    async fn mark_suspended(&self, id: &str, suspended: bool, _: &Credentials) -> Result<()> {
        let marker = Path::new(&self.dir(id).await?).join(SUSPENDED).to_string_lossy().into_owned();
        let script = if suspended { r#": > "$1""# } else { r#"rm -f "$1""# };
        self.ok("marking the vessel's suspension", script, &[&marker]).await.map(drop)
    }
    async fn connect(&self, id: &str, _: &Credentials) -> Result<ByteStream> {
        let socket = self.root().await?.join(id).join(SOCKET);
        let session = self.session().await?;
        session.open_unix(&socket).await.map_err(|e| unavailable(format!("agent socket over SSH: {e}")))
    }
    fn states_capacity(&self) -> bool {
        true
    }
    /// The machine's CPUs and memory, with the limits its running vessels are
    /// held to summed as in use. A vessel with the whole machine holds it all.
    async fn quota(&self, _: &Credentials) -> Option<Result<Quota>> {
        let quota = async {
            let facts = self.probe().await?;
            let held: Vec<(f64, u64)> = self.survey(None).await?.into_iter().filter_map(|(_, limits)| limits).collect();
            let row = |resource, unit: &str, in_use: f64, limit: f64| ResourceQuota {
                key: QuotaKey { region: None, class: None, resource },
                unit: unit.into(),
                in_use,
                limit: Some(limit),
            };
            Ok(Quota {
                resources: vec![
                    row(ResourceKind::Cpu, "{vCPU}", held.iter().map(|(cpus, _)| cpus).sum(), facts.cpus),
                    row(ResourceKind::Memory, "By", held.iter().map(|(_, memory)| *memory as f64).sum(), facts.memory_bytes as f64),
                ],
                concurrency_in_use: Some(held.len() as u64),
                concurrency_limit: (!facts.enforced).then_some(1),
                ..Quota::default()
            })
        };
        Some(quota.await)
    }
}

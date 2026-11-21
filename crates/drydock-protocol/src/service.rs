//! A vessel agent's long-lived services, as the agent and drydockd's
//! passthrough both serve them.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};
use utoipa::ToSchema;

/// How a process ended. A process killed by a signal has no code; one killed
/// for exceeding its timeout also reports `timed_out`.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct ExitStatus {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    #[serde(default)]
    pub timed_out: bool,
}
impl ExitStatus {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}
/// A long-lived service to keep running under a name the client chooses.
/// Unlike a process, its output never passes through the agent, and it
/// outlives agent restarts and re-execs.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[schema(value_type = Option<String>)]
    pub cwd: Option<PathBuf>,
    /// Added to the configured environment, overriding it per variable.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub output: ServiceOutput,
}
/// Where a service's stdout and stderr go. Its stdin is always `/dev/null`.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceOutput {
    /// Both streams, in the order written, to the file [`ServiceInfo::log`]
    /// names. Each start, and each pass of 64 MiB, keeps the previous content
    /// as `<log>.1`.
    #[default]
    File,
    Discard,
}
/// A service's status.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct ServiceInfo {
    pub name: String,
    /// The PID the service last had; once it has exited, it may name
    /// another process.
    pub pid: u32,
    pub service: Service,
    #[serde(flatten)]
    pub state: ServiceState,
    /// Readable through `GET /files/{path}`; absent when output is discarded.
    #[schema(value_type = Option<String>)]
    pub log: Option<PathBuf>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ServiceState {
    Running,
    /// `status` is known only to the agent process that started the service
    /// and saw it end; after a restart or re-exec it is absent.
    Exited {
        status: Option<ExitStatus>,
    },
}

//! Provider-only user configuration. Module settings are passed through unchanged.
use crate::credentials::CredentialReference;
use drydock_protocol::{EgressRequest, Size};
use rigging_process::EnvVars;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub provider: BTreeMap<String, Provider>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub module: String,
    pub credential: Credential,
    #[serde(default)]
    pub settings: BTreeMap<String, serde_json::Value>,
    pub image: Option<String>,
    #[serde(default)]
    pub size: SizeDefaults,
    pub egress: Option<Egress>,
    /// The preferred link to this provider's vessel agents, used where its SSH
    /// server allows it. Defaults to reverse forwards.
    #[serde(default)]
    pub agent_link: crate::agent::AgentLink,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SizeDefaults {
    pub cpus: Option<f64>,
    /// Bytes, or a quantity such as "2GiB".
    pub memory: Option<Quantity>,
    pub disk: Option<Quantity>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Quantity {
    Bytes(u64),
    Text(String),
}
impl Quantity {
    pub fn bytes(&self) -> Result<u64, String> {
        match self {
            Self::Bytes(n) => Ok(*n),
            Self::Text(s) => parse_bytes(s),
        }
    }
}
/// Integer bytes (including numeric strings), or case-sensitive SI/IEC suffixes.
/// Whitespace between the integer and suffix is accepted, e.g. "5 GiB".
pub fn parse_bytes(s: &str) -> Result<u64, String> {
    for (suffix, multiplier) in
        [("GiB", 1u64 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10), ("GB", 1_000_000_000), ("MB", 1_000_000), ("KB", 1000), ("B", 1)]
    {
        if let Some(n) = s.strip_suffix(suffix) {
            return n.trim().parse::<u64>().ok().and_then(|n| n.checked_mul(multiplier)).ok_or_else(|| "invalid byte quantity".into());
        }
    }
    s.parse().map_err(|_| "invalid byte quantity".into())
}
impl SizeDefaults {
    pub fn resolve(&self, minimum: &Size) -> Result<Size, String> {
        let size = Size {
            cpus: self.cpus.unwrap_or(minimum.cpus),
            memory_bytes: self.memory.as_ref().map(Quantity::bytes).transpose()?.unwrap_or(minimum.memory_bytes),
            disk_bytes: self.disk.as_ref().map(Quantity::bytes).transpose()?.unwrap_or(minimum.disk_bytes),
        };
        if !size.cpus.is_finite() || size.cpus <= 0. {
            return Err("cpus must be positive".into());
        }
        Ok(size)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Egress {
    Open,
    DenyAll,
}
impl Egress {
    pub fn request(self) -> EgressRequest {
        match self {
            Self::Open => EgressRequest::Open,
            Self::DenyAll => EgressRequest::DenyAll { direct: vec![] },
        }
    }
}
#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub enum Credential {
    File(FileCredential),
    Env(EnvCredential),
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileCredential {
    pub file: PathBuf,
    pub json_field: Option<String>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvCredential {
    pub env: String,
}
impl Credential {
    pub fn reference(&self, env: &dyn EnvVars) -> Result<CredentialReference, String> {
        Ok(match self {
            Self::File(c) => {
                let path = if let Ok(rest) = c.file.strip_prefix("~") {
                    PathBuf::from(env.get_os("HOME").filter(|v| !v.is_empty()).ok_or("HOME required for credential path")?).join(rest)
                } else {
                    c.file.clone()
                };
                CredentialReference::File { path, json_field: c.json_field.clone() }
            }
            Self::Env(c) => CredentialReference::Env { name: c.env.clone() },
        })
    }
}
impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        // Do not echo malformed configuration: it can contain sensitive values.
        let config: Self = toml::from_str(text).map_err(|_| "invalid provider TOML configuration")?;
        for (name, p) in &config.provider {
            if name.is_empty() || p.module.is_empty() {
                return Err("provider and module names must not be empty".into());
            }
            p.size.resolve(&Size { cpus: 1., memory_bytes: 1, disk_bytes: 1 })?;
        }
        Ok(config)
    }
    pub async fn load(path: &Path) -> Result<Self, String> {
        Self::parse(&tokio::fs::read_to_string(path).await.map_err(|e| format!("read config {}: {e}", path.display()))?)
    }
}
/// Socket paths intentionally live under config/run, matching flotillad.
pub fn default_paths(env: &dyn EnvVars) -> Result<(PathBuf, PathBuf), String> {
    let paths = rigging_paths::PathPolicy::from_env("drydock", env)?;
    Ok((paths.config_dir.join("drydock.toml"), paths.config_dir.join("run/drydock.sock")))
}

/// Explicit config/socket overrides need no HOME/XDG discovery.
pub fn resolve_paths(config: Option<PathBuf>, socket: Option<PathBuf>, env: &dyn EnvVars) -> Result<(PathBuf, PathBuf), String> {
    match (config, socket) {
        (Some(config), Some(socket)) => Ok((config, socket)),
        (config, socket) => {
            let (default_config, default_socket) = default_paths(env)?;
            Ok((config.unwrap_or(default_config), socket.unwrap_or(default_socket)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::generators as gs;
    struct Env(BTreeMap<String, String>);
    impl EnvVars for Env {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }
    // Shared XDG policy: root wins, absolute XDG bases override HOME, relative
    // XDG bases fall back, and socket stays below config/run for every case.
    #[hegel::test]
    fn xdg_precedence(tc: hegel::TestCase) {
        let root = tc.draw(gs::booleans());
        let xdg = tc.draw(gs::booleans());
        let relative = tc.draw(gs::booleans());
        let mut env = Env(BTreeMap::from([("HOME".into(), "/home/test".into())]));
        if root {
            env.0.insert("DRYDOCK_ROOT".into(), "/override".into());
        }
        if xdg {
            env.0.insert("XDG_CONFIG_HOME".into(), if relative { "relative" } else { "/xdg" }.into());
        }
        let (config, socket) = default_paths(&env).unwrap();
        let base = if root {
            "/override/config"
        } else if xdg && !relative {
            "/xdg/drydock"
        } else {
            "/home/test/.config/drydock"
        };
        assert_eq!(config, PathBuf::from(base).join("drydock.toml"));
        assert_eq!(socket, PathBuf::from(base).join("run/drydock.sock"));
    }
    // Opaque settings, including nested module-owned data and arrays, survive
    // TOML 1.1 multiline inline tables. Drydock defaults and credentials stay out.
    #[hegel::test]
    fn settings_are_opaque_and_defaults_are_separate(tc: hegel::TestCase) {
        let n = tc.draw(gs::integers::<u16>().min_value(0).max_value(u16::MAX));
        let enabled = tc.draw(gs::booleans());
        let text = format!(
            r#"[provider.demo]
module = "unknown-language-module"
credential = {{env="PATH"}}
image = "image:tag"
size = {{cpus=2, memory="2GiB"}}
egress = "deny-all"
settings = {{
    organization_id = "org",
    nested = {{value={n}, enabled={enabled}}},
    array = ["a", "b"],
}}
"#
        );
        let config = Config::parse(&text).unwrap();
        let p = &config.provider["demo"];
        assert_eq!(
            serde_json::to_value(&p.settings).unwrap(),
            serde_json::json!({"organization_id":"org","nested":{"value":n,"enabled":enabled},"array":["a","b"]})
        );
        assert_eq!(
            p.size.resolve(&Size { cpus: 1., memory_bytes: 1, disk_bytes: 9 }).unwrap(),
            Size { cpus: 2., memory_bytes: 2 << 30, disk_bytes: 9 }
        );
    }
    // A provider's agent link preference defaults to reverse forwards, names
    // either link, and refuses anything else.
    #[test]
    fn agent_link_parses_with_a_default() {
        let parse = |line: &str| Config::parse(&format!("[provider.demo]\nmodule = \"m\"\ncredential = {{env=\"PATH\"}}\n{line}\n"));
        assert_eq!(parse("").unwrap().provider["demo"].agent_link, crate::agent::AgentLink::ReverseForward);
        assert_eq!(parse("agent_link = \"reverse_forward\"").unwrap().provider["demo"].agent_link, crate::agent::AgentLink::ReverseForward);
        assert_eq!(parse("agent_link = \"local_forward\"").unwrap().provider["demo"].agent_link, crate::agent::AgentLink::LocalForward);
        assert!(parse("agent_link = \"over_the_rainbow\"").is_err());
        // The names a report shows are the configured ones.
        for link in [crate::agent::AgentLink::ReverseForward, crate::agent::AgentLink::LocalForward] {
            assert_eq!(serde_json::to_value(link).unwrap(), link.as_str());
        }
    }
    // Generated quantities cover zero, ordinary values and overflow near u64::MAX.
    #[hegel::test]
    fn quantities_preserve_bytes_and_reject_overflow(tc: hegel::TestCase) {
        let n = tc.draw(gs::integers::<u64>());
        assert_eq!(parse_bytes(&format!("{n}B")).unwrap(), n);
        assert_eq!(parse_bytes(&format!("{n}GiB")).ok(), n.checked_mul(1 << 30));
        assert_eq!(Quantity::Bytes(n).bytes().unwrap(), n);
    }
    // Boundary and malformed cases have no useful generation dimension; parser
    // refusals must never echo settings or credential contents.
    #[test]
    fn invalid_config_and_credential_paths() {
        for text in [
            "",
            "[provider.demo]\nmodule='x'\ncredential={env='PATH',file='secret'}",
            "[hosts]\nsecret='secret'",
            "[provider.demo]\nmodule='x'\ncredential={env='PATH'}\nsize={cpus=0}",
            "secret is not TOML",
        ] {
            if text.is_empty() {
                assert!(Config::parse(text).unwrap().provider.is_empty());
            } else {
                assert!(!Config::parse(text).err().unwrap().contains("secret"));
            }
        }
        let env = Env(BTreeMap::from([("HOME".into(), "/home/test".into())]));
        let credential = Credential::File(FileCredential { file: "~/.config/key".into(), json_field: Some("token".into()) });
        assert_eq!(
            credential.reference(&env).unwrap(),
            CredentialReference::File { path: "/home/test/.config/key".into(), json_field: Some("token".into()) }
        );
        for bad in ["-1GiB", "1.5GiB", "infinite", "18446744073709551616B"] {
            assert!(parse_bytes(bad).is_err());
        }
    }
    // Parsing provider TOML is environment-independent. Only resolving a tilde
    // credential path requires HOME, supplied through the injected environment.
    #[test]
    fn tilde_credential_resolution_is_deferred_until_environment_is_supplied() {
        // The real process-environment boundary needs a child: never mutate
        // HOME globally while other tests run in this test binary.
        if std::env::var_os("DRYDOCK_TEST_PARSE_WITHOUT_HOME").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "config::tests::tilde_credential_resolution_is_deferred_until_environment_is_supplied"])
                .env_remove("HOME")
                .env("DRYDOCK_TEST_PARSE_WITHOUT_HOME", "1")
                .output()
                .unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
            return;
        }
        let config = Config::parse(
            r#"[provider.demo]
module="reference"
credential={file="~/token"}
settings={}
"#,
        )
        .unwrap();
        let credential = &config.provider["demo"].credential;
        assert!(credential.reference(&Env(BTreeMap::new())).is_err());
        assert_eq!(
            credential.reference(&Env(BTreeMap::from([("HOME".into(), "/injected".into())]))).unwrap(),
            CredentialReference::File { path: "/injected/token".into(), json_field: None }
        );
        for text in ["5GiB", "5 GiB"] {
            assert_eq!(parse_bytes(text).unwrap(), 5 << 30);
        }
        assert_eq!(parse_bytes("12").unwrap(), 12);
        assert!(parse_bytes("5gib").is_err());
    }
}

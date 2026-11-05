//! Provider-only user configuration. Module settings are passed through unchanged.
use crate::credentials::CredentialReference;
use drydock_agent::Target;
use drydock_protocol::{
    Configuration, CredentialLocation, EgressRequest, EventsConfiguration, Ownership, ProviderConfiguration, SemanticOptions, Size,
};
use rigging_process::EnvVars;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// The configuration document in TOML, plus the CLI's launch defaults, which
/// are not part of that document.
#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub providers: BTreeMap<String, Provider>,
    /// Registries images are staged in, declared once and shared by every
    /// provider instance that lists them in `pull_from`.
    #[serde(default)]
    pub registries: BTreeMap<String, Registry>,
    /// The default targets for "try these destinations". Parsed and validated here; drydockd does not consume them yet.
    #[serde(default)]
    pub destinations: DefaultDestinations,
}
/// The shipped targets for the cases no provider lists, once per installation.
/// Each list given in `[destinations]` replaces the shipped one whole.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultDestinations {
    /// Egress to an endpoint nobody listed: stable public hosts on 443.
    #[serde(default = "unlisted")]
    pub unlisted: Vec<Target>,
    /// Raw DNS: a lookup through each public resolver on 53.
    #[serde(default = "raw_dns")]
    pub raw_dns: Vec<Target>,
}
impl Default for DefaultDestinations {
    fn default() -> Self {
        Self { unlisted: unlisted(), raw_dns: raw_dns() }
    }
}
fn unlisted() -> Vec<Target> {
    ["one.one.one.one", "dns.google"].map(|host| Target::Tcp { host: host.into(), port: 443 }).into()
}
fn raw_dns() -> Vec<Target> {
    ["1.1.1.1:53", "8.8.8.8:53"]
        .map(|resolver| Target::Dns { name: "example.com".into(), resolver: Some(resolver.parse().expect("literal address")) })
        .into()
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub module: String,
    #[serde(default)]
    pub settings: BTreeMap<String, serde_json::Value>,
    pub credential: Option<CredentialLocation>,
    pub image: Option<String>,
    #[serde(default)]
    pub size: SizeDefaults,
    pub egress: Option<Egress>,
    /// Registries this instance can pull from. On the registry-pull route an
    /// image in none of them is first staged in the first one listed.
    #[serde(default)]
    pub pull_from: Vec<String>,
    #[serde(default)]
    pub ownership: Ownership,
    #[serde(default)]
    pub semantics: SemanticOptions,
    /// How drydockd hears about this instance's environments.
    pub events: Option<EventsConfiguration>,
}
/// A registry drydock can copy images into and providers can pull them from.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    /// `host/path`. Images are staged under it by digest, and an image whose
    /// reference names it, or a path below it, is already in this registry.
    pub repository: String,
    pub push: RegistryAccess,
    /// Absent: providers pull anonymously.
    pub pull: Option<RegistryAccess>,
    /// The most bytes one upload request to this registry carries, for a
    /// registry whose limit differs from the default (4 MiB, GHCR's).
    pub chunk_bytes: Option<u64>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryAccess {
    pub username: String,
    pub credential: CredentialLocation,
}
impl Registry {
    /// The repository's host and path, provided it names both and no tag.
    pub fn location(&self) -> Result<(String, String), String> {
        let invalid = || format!("registry repository {:?} must be host/path", self.repository);
        let image = drydock_oci::ImageRef::parse(&format!("{}@sha256:{}", self.repository, "0".repeat(64))).map_err(|_| invalid())?;
        if format!("{}/{}", image.registry, image.repository) != self.repository {
            return Err(invalid());
        }
        Ok((image.registry, image.repository))
    }
}
impl Config {
    /// The configuration document, without the launch defaults.
    pub fn document(&self) -> Configuration {
        let providers = self.providers.iter().map(|(name, p)| (name.clone(), p.configuration())).collect();
        Configuration { providers }
    }
}
impl Provider {
    pub fn configuration(&self) -> ProviderConfiguration {
        ProviderConfiguration {
            module: self.module.clone(),
            settings: self.settings.clone(),
            credential: self.credential.clone(),
            ownership: self.ownership,
            semantics: self.semantics.clone(),
            events: self.events.clone(),
        }
    }
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
/// Where the server reads a configured credential.
pub fn credential_reference(source: &CredentialLocation, env: &dyn EnvVars) -> Result<CredentialReference, String> {
    Ok(match source {
        CredentialLocation::File { file, json_field } => {
            let file = Path::new(file);
            let path = if let Ok(rest) = file.strip_prefix("~") {
                PathBuf::from(env.get_os("HOME").filter(|v| !v.is_empty()).ok_or("HOME required for credential path")?).join(rest)
            } else {
                file.to_owned()
            };
            CredentialReference::File { path, json_field: json_field.clone() }
        }
        CredentialLocation::Env { env } => CredentialReference::Env { name: env.clone() },
    })
}
impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        // Do not echo malformed configuration: it can contain sensitive values.
        let config: Self = toml::from_str(text).map_err(|_| "invalid provider TOML configuration")?;
        for (name, p) in &config.providers {
            if name.is_empty() || p.module.is_empty() {
                return Err("provider and module names must not be empty".into());
            }
            p.size.resolve(&Size { cpus: 1., memory_bytes: 1, disk_bytes: 1 })?;
            if let Some(events) = &p.events {
                crate::runtime::relay::stream(events).map_err(|e| format!("provider {name}: {e}"))?;
            }
            if let Some(unknown) = p.pull_from.iter().find(|r| !config.registries.contains_key(*r)) {
                return Err(format!("provider {name} pulls from unknown registry {unknown:?}"));
            }
        }
        for (name, registry) in &config.registries {
            registry.location().map_err(|e| format!("registry {name}: {e}"))?;
            if registry.chunk_bytes == Some(0) {
                return Err(format!("registry {name}: chunk_bytes must be positive"));
            }
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
            r#"[providers.demo]
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
        let p = &config.providers["demo"];
        assert_eq!(
            serde_json::to_value(&p.settings).unwrap(),
            serde_json::json!({"organization_id":"org","nested":{"value":n,"enabled":enabled},"array":["a","b"]})
        );
        assert_eq!(
            p.size.resolve(&Size { cpus: 1., memory_bytes: 1, disk_bytes: 9 }).unwrap(),
            Size { cpus: 2., memory_bytes: 2 << 30, disk_bytes: 9 }
        );
    }
    // Every `pull_from` name is a declared registry, every registry's
    // repository names a host and a path, and an upload chunk carries at
    // least one byte: anything else fails at load.
    #[test]
    fn staging_registries_are_checked_at_load() {
        let registry = |repository: &str| {
            format!("[registries.ghcr]\nrepository='{repository}'\npush={{username='bot', credential={{env='PUSH'}}}}\n")
        };
        let provider = |pull_from: &str| format!("[providers.e2b]\nmodule='e2b'\npull_from=[{pull_from}]\n");
        let config = Config::parse(&(registry("ghcr.io/org/staging") + &provider("'ghcr'"))).unwrap();
        assert_eq!(config.providers["e2b"].pull_from, ["ghcr"]);
        assert!(Config::parse(&(registry("ghcr.io/org/staging") + &provider("'ghcr', 'quay'"))).is_err());
        assert!(Config::parse(&provider("'ghcr'")).is_err());
        for repository in ["org/staging", "ghcr.io", "ghcr.io/org/staging:tag", "ghcr.io/Org/staging"] {
            assert!(Config::parse(&(registry(repository) + &provider("'ghcr'"))).is_err(), "{repository}");
        }
        assert!(Config::parse(&(registry("ghcr.io/org/staging") + "chunk_bytes=0\n" + &provider("'ghcr'"))).is_err());
    }
    // The shipped targets apply until drydock.toml names its own, list by list.
    #[test]
    fn default_destinations_are_shipped_and_overridable() {
        let shipped = Config::parse("").unwrap().destinations;
        assert_eq!(shipped.unlisted.len(), 2);
        assert!(shipped.unlisted.iter().all(|t| matches!(t, Target::Tcp { port: 443, .. })));
        assert!(shipped.raw_dns.iter().all(|t| matches!(t, Target::Dns { resolver: Some(r), .. } if r.port() == 53)));
        let config = Config::parse("[destinations]\nunlisted=[{tcp={host='example.net', port=8443}}]\n").unwrap().destinations;
        assert_eq!(config.unlisted, [Target::Tcp { host: "example.net".into(), port: 8443 }]);
        assert_eq!(config.raw_dns, shipped.raw_dns);
        assert!(Config::parse("[destinations]\nother=[]\n").is_err());
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
            "[providers.demo]\nmodule='x'\ncredential={env='PATH',file='secret'}",
            "[hosts]\nsecret='secret'",
            "[providers.demo]\nmodule='x'\ncredential={env='PATH'}\nsize={cpus=0}",
            "secret is not TOML",
        ] {
            if text.is_empty() {
                assert!(Config::parse(text).unwrap().providers.is_empty());
            } else {
                assert!(!Config::parse(text).err().unwrap().contains("secret"));
            }
        }
        let env = Env(BTreeMap::from([("HOME".into(), "/home/test".into())]));
        let credential = CredentialLocation::File { file: "~/.config/key".into(), json_field: Some("token".into()) };
        assert_eq!(
            credential_reference(&credential, &env).unwrap(),
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
            r#"[providers.demo]
module="reference"
credential={file="~/token"}
settings={}
"#,
        )
        .unwrap();
        let credential = config.providers["demo"].credential.as_ref().unwrap();
        assert!(credential_reference(credential, &Env(BTreeMap::new())).is_err());
        assert_eq!(
            credential_reference(credential, &Env(BTreeMap::from([("HOME".into(), "/injected".into())]))).unwrap(),
            CredentialReference::File { path: "/injected/token".into(), json_field: None }
        );
        for text in ["5GiB", "5 GiB"] {
            assert_eq!(parse_bytes(text).unwrap(), 5 << 30);
        }
        assert_eq!(parse_bytes("12").unwrap(), 12);
        assert!(parse_bytes("5gib").is_err());
    }
}

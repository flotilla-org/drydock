//! Where the drydock-agent build for a vessel's platform is installed, for
//! drydockd's upgrades and for modules that start their vessels' agents.
use drydock_protocol::Platform;
use rigging_process::EnvVars;
use std::path::{Path, PathBuf};

/// The host's drydock-agent build for a vessel's prepared platform, which an
/// older vessel agent is upgraded to. Overrides win over installed files. The plain sibling
/// `drydock-agent` is the host's own build, so it is a candidate only when the
/// guest shares the host's platform; no build for another platform is chosen.
pub fn agent_build(guest: &Platform) -> Result<PathBuf, String> {
    agent_build_from(guest, &Platform::current(), &rigging_process::ProcessEnvVars, std::env::current_exe, |p| p.is_file())
}
fn agent_build_from(
    guest: &Platform,
    host: &Platform,
    env: &dyn EnvVars,
    current_exe: impl Fn() -> std::io::Result<PathBuf>,
    is_file: impl Fn(&Path) -> bool,
) -> Result<PathBuf, String> {
    // Platform names become a file name and a variable name.
    if !guest.is_plain() {
        return Err(format!("guest platform {guest:?} is not a lowercase OCI os/architecture pair"));
    }
    let binary = format!("drydock-agent-{}-{}", guest.os, guest.architecture);
    let variable = format!("DRYDOCK_AGENT_BIN_{}_{}", guest.os.to_ascii_uppercase(), guest.architecture.to_ascii_uppercase());
    let native = guest == host;
    let overridden = |name: &str| env.get_os(name).filter(|value| !value.is_empty()).map(PathBuf::from);
    if let Some(path) = overridden(&variable) {
        return Ok(path);
    }
    if native && let Some(path) = overridden("DRYDOCK_AGENT_BIN") {
        return Ok(path);
    }
    struct Installed;
    impl EnvVars for Installed {
        fn get(&self, _: &str) -> Option<String> {
            None
        }
    }
    if let Ok(path) = rigging_process::resolve_sibling_binary(&binary, &variable, &Installed, &current_exe, &is_file) {
        return Ok(path);
    }
    if native
        && let Ok(path) = rigging_process::resolve_sibling_binary("drydock-agent", "DRYDOCK_AGENT_BIN", &Installed, &current_exe, &is_file)
    {
        return Ok(path);
    }
    let directory = current_exe().ok().and_then(|path| path.parent().map(Path::to_path_buf)).unwrap_or_default();
    Err(format!("install {binary} beside {} or set {variable}", directory.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Env(std::collections::HashMap<&'static str, &'static str>);
    impl EnvVars for Env {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).map(|value| (*value).to_owned())
        }
    }
    // Every combination of guest platform, overrides and installed files (a
    // small finite space, so exhaustive): the platform's override, then (same
    // platform only) DRYDOCK_AGENT_BIN, then the platform's installed build,
    // then (same platform only) the sibling. A build for another platform is
    // never chosen; finding nothing is an error naming the file and variable.
    #[test]
    fn agent_build_lookup_follows_guest_platform() {
        let host = Platform::new("linux", "amd64");
        let names = ["drydock-agent-linux-amd64", "drydock-agent-linux-arm64", "drydock-agent"];
        for case in 0..1 << 6 {
            let bit = |n: u32| case & (1 << n) != 0;
            let guest = Platform::new("linux", if bit(0) { "amd64" } else { "arm64" });
            let native = guest == host;
            let (platform_override, plain_override) = (bit(1), bit(2));
            let installed: Vec<&str> = names.iter().enumerate().filter(|(n, _)| bit(3 + *n as u32)).map(|(_, name)| *name).collect();
            let dir = tempfile::tempdir().unwrap();
            for name in &installed {
                std::fs::write(dir.path().join(name), "").unwrap();
            }
            let variable = if native { "DRYDOCK_AGENT_BIN_LINUX_AMD64" } else { "DRYDOCK_AGENT_BIN_LINUX_ARM64" };
            let mut env = std::collections::HashMap::new();
            if platform_override {
                env.insert(variable, "/custom/platform-agent");
            }
            if plain_override {
                env.insert("DRYDOCK_AGENT_BIN", "/custom/agent");
            }
            let result = agent_build_from(&guest, &host, &Env(env), || Ok(dir.path().join("drydockd")), |p| p.is_file());
            let own = format!("drydock-agent-{}-{}", guest.os, guest.architecture);
            let expected = if platform_override {
                Some(PathBuf::from("/custom/platform-agent"))
            } else if native && plain_override {
                Some(PathBuf::from("/custom/agent"))
            } else if installed.contains(&own.as_str()) {
                Some(dir.path().join(&own))
            } else if native && installed.contains(&"drydock-agent") {
                Some(dir.path().join("drydock-agent"))
            } else {
                None
            };
            match expected {
                Some(path) => assert_eq!(result.unwrap(), path, "case {case:06b}"),
                None => {
                    let error = result.unwrap_err();
                    assert!(error.contains(&own) && error.contains(variable), "case {case:06b}: {error}");
                    assert!(error.contains(&dir.path().display().to_string()), "case {case:06b}: {error}");
                }
            }
        }
    }
    // Guest-reported names become a file name and a variable name, so a hello
    // cannot steer the lookup outside the install directory.
    #[test]
    fn agent_build_rejects_unsafe_platform_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("drydock-agent"), "").unwrap();
        for (os, architecture) in [("linux", "../../drydock"), ("Linux", "amd64"), ("", "amd64"), ("linux", "amd64/x"), ("linux", "AMD64")]
        {
            let error = agent_build_from(
                &Platform::new(os, architecture),
                &Platform::new(os, architecture),
                &Env(Default::default()),
                || Ok(dir.path().join("drydockd")),
                |p| p.is_file(),
            )
            .unwrap_err();
            assert!(error.contains("not a lowercase OCI"), "{error}");
        }
    }
}

// The real `drydock-agent` build the local module runs.
#![allow(dead_code)]
use std::{path::PathBuf, sync::OnceLock};

/// The workspace's `drydock-agent` beside the test binaries, built first if the
/// test run did not already (`cargo test -p drydock-host` builds only its own).
pub fn agent_binary() -> PathBuf {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY
        .get_or_init(|| {
            let profile = std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().to_path_buf();
            let binary = profile.join("drydock-agent");
            let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
            let mut build = std::process::Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
            build.args(["build", "--quiet", "-p", "drydock-agent"]).current_dir(workspace);
            if profile.file_name().is_some_and(|name| name == "release") {
                build.arg("--release");
            }
            assert!(build.status().unwrap().success(), "build drydock-agent");
            assert!(binary.is_file(), "{} was not built", binary.display());
            binary
        })
        .clone()
}

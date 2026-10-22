//! Shared build-time selection, independent of the consuming workspace's cwd.
pub fn select<'a>(pin: &'a str, override_reference: Option<&'a str>) -> Result<Option<&'a str>, &'static str> {
    let reference = match override_reference {
        Some(reference) => reference,
        None => {
            let pin = pin.trim();
            if pin == "unpublished" {
                return Ok(None);
            }
            pin
        }
    };
    let (name, digest) = reference.split_once("@sha256:").ok_or("tools image must be registry/name@sha256:<64 lowercase hex digits>")?;
    if name.is_empty()
        || !name.contains('/')
        || name.contains("://")
        || name.contains('@')
        || name.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err("tools image must name a registry/repository, without a URL scheme, whitespace or control characters");
    }
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("tools image digest must contain exactly 64 lowercase hexadecimal digits");
    }
    Ok(Some(reference))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::generators as gs;

    // Every digest byte and registry port varies. An override wins over any pin,
    // including the pre-publication sentinel or an invalid checked-in value.
    #[hegel::test]
    fn published_pin_and_override_selection(tc: hegel::TestCase) {
        let digest: String = (0..32).map(|_| format!("{:02x}", tc.draw(gs::integers::<u8>()))).collect();
        let port = tc.draw(gs::integers::<u16>().min_value(1));
        let reference = format!("registry.example:{port}/team/drydock-tools@sha256:{digest}");
        let file = format!("{reference}\n");
        assert_eq!(select(&file, None).unwrap(), Some(reference.as_str()));
        for pin in ["unpublished\n", "malformed", file.as_str()] {
            assert_eq!(select(pin, Some(&reference)).unwrap(), Some(reference.as_str()));
        }
    }

    // Only the checked-in sentinel means not published. Empty/malformed pins and
    // explicit empty/sentinel overrides are configuration errors, never fallbacks.
    #[test]
    fn unpublished_and_invalid_metadata() {
        assert_eq!(select("unpublished\n", None).unwrap(), None);
        let valid = format!("registry.example/tools@sha256:{}", "a".repeat(64));
        for invalid in ["", "bad", "registry/tools@sha256:short", "https://registry/tools@sha256:short"] {
            assert!(select(invalid, None).is_err());
            assert!(select(&valid, Some(invalid)).is_err());
        }
        assert!(select(&valid, Some("unpublished")).is_err());
        assert!(select(&valid, Some(&(valid.clone() + "\n"))).is_err());
    }

    // Cargo runs build scripts for Git dependencies from a different workspace.
    // Exercise the real build-script process with a foreign cwd and crate-local
    // pin, then verify both file changes and override precedence are observed.
    #[test]
    fn build_script_reads_the_crate_pin_from_a_foreign_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("build-script");
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("build.rs");
        let compiled = std::process::Command::new("rustc").arg("--edition=2024").arg(source).arg("-o").arg(&binary).output().unwrap();
        assert!(compiled.status.success(), "{}", String::from_utf8_lossy(&compiled.stderr));
        let package = dir.path().join("dependency");
        let consumer = dir.path().join("consumer");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::create_dir_all(&consumer).unwrap();
        let pin = package.join("tools-image.txt");
        let run = |override_reference: Option<&str>| {
            let mut command = std::process::Command::new(&binary);
            command.current_dir(&consumer).env("CARGO_MANIFEST_DIR", &package).env_remove("DRYDOCK_TOOLS_IMAGE");
            if let Some(reference) = override_reference {
                command.env("DRYDOCK_TOOLS_IMAGE", reference);
            }
            let output = command.output().unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
            String::from_utf8(output.stdout).unwrap()
        };
        for digit in ["a", "b"] {
            let reference = format!("registry.example/tools@sha256:{}", digit.repeat(64));
            std::fs::write(&pin, format!("{reference}\n")).unwrap();
            let output = run(None);
            assert!(output.contains(&format!("cargo:rustc-env=DRYDOCK_TOOLS_IMAGE={reference}\n")));
            assert!(output.contains(&format!("cargo:rerun-if-changed={}\n", pin.display())));
        }
        std::fs::write(&pin, "unpublished\n").unwrap();
        assert!(run(None).contains("cargo:rustc-env=DRYDOCK_TOOLS_IMAGE=unpublished\n"));
        let override_reference = format!("other.example/tools@sha256:{}", "c".repeat(64));
        assert!(run(Some(&override_reference)).contains(&format!("cargo:rustc-env=DRYDOCK_TOOLS_IMAGE={override_reference}\n")));
    }
}

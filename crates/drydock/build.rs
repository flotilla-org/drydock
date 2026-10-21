fn main() {
    println!("cargo:rerun-if-env-changed=DRYDOCK_TOOLS_IMAGE");
    if let Ok(reference) = std::env::var("DRYDOCK_TOOLS_IMAGE") {
        let (name, digest) =
            reference.split_once("@sha256:").expect("DRYDOCK_TOOLS_IMAGE must be registry/name@sha256:<64 lowercase hex digits>");
        assert!(
            !name.is_empty()
                && name.contains('/')
                && !name.contains("://")
                && !name.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control()),
            "DRYDOCK_TOOLS_IMAGE must name a registry/repository, without a URL scheme, whitespace or control characters"
        );
        assert!(
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "DRYDOCK_TOOLS_IMAGE digest must contain exactly 64 lowercase hexadecimal digits"
        );
        println!("cargo:rustc-env=DRYDOCK_TOOLS_IMAGE={reference}");
    }
}

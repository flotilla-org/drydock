mod tools_image_pin;

fn main() {
    println!("cargo:rerun-if-env-changed=DRYDOCK_TOOLS_IMAGE");
    let manifest = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest directory"));
    let path = manifest.join("tools-image.txt");
    println!("cargo:rerun-if-changed={}", path.display());
    let pin = std::fs::read_to_string(&path).expect("read checked-in tools-image.txt");
    let override_reference = match std::env::var("DRYDOCK_TOOLS_IMAGE") {
        Ok(reference) => Some(reference),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => panic!("DRYDOCK_TOOLS_IMAGE must be UTF-8: {error}"),
    };
    let reference = tools_image_pin::select(&pin, override_reference.as_deref())
        .unwrap_or_else(|reason| panic!("invalid tools-image.txt or DRYDOCK_TOOLS_IMAGE: {reason}"))
        .unwrap_or("unpublished");
    println!("cargo:rustc-env=DRYDOCK_TOOLS_IMAGE={reference}");
}

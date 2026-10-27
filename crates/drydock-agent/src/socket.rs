use std::{
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::Path,
};
/// A dedicated run directory belongs to the agent's effective user. Refuse
/// symlinks and sticky/shared directories rather than changing their protection.
pub fn private_directory(path: &Path) -> io::Result<()> {
    let result = (|| {
        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o1000 != 0 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "run directory must be an owned, non-sticky directory"));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    })();
    result.map_err(|e| crate::error::context("socket.directory", path.display(), e))
}
pub fn protect(path: &Path) -> io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| crate::error::context("socket.permissions", path.display(), e))
}

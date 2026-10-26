//! Durable filesystem steps shared by every writer: replace a small file
//! atomically, make a directory's entries durable, and the atomic renames
//! rename(2) alone cannot express.
use std::{io, path::Path};

/// Replace a small file atomically and durably: write a sibling, set its
/// mode, fsync it, rename it over `path`, then fsync the parent.
pub(crate) fn replace(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::{io::Write, os::unix::fs::PermissionsExt};
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().set_permissions(std::fs::Permissions::from_mode(mode))?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|e| e.error)?;
    sync_directory(parent)
}
/// Make the entries of `path` durable: a rename, link or removal inside it
/// survives a crash once this returns.
pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}
/// rename(2) that refuses an existing target with AlreadyExists.
pub(crate) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    Ok(renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE)?)
}

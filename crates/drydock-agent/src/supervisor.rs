//! Optional provider-side supervision, packaged in the tools executable.
use std::{
    ffi::OsString,
    io,
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

fn socket(args: &[OsString]) -> io::Result<PathBuf> {
    match args {
        [flag, path] if flag == "--socket" => Ok(path.into()),
        _ => Err(io::Error::other("usage: drydock-agent --supervise --socket PATH")),
    }
}

pub fn start(args: &[OsString]) -> io::Result<()> {
    let path = socket(args)?;
    let parent = path.parent().ok_or_else(|| io::Error::other("socket needs a directory"))?;
    drydock_agent::socket::private_directory(parent)?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(parent.join("supervisor.log"))?;
    let mut command = Command::new(std::env::current_exe()?);
    command.arg("--supervisor").args(args).stdin(Stdio::null()).stdout(log.try_clone()?).stderr(log);
    // SAFETY: setsid is async-signal-safe and takes no pointers. Detach from
    // the toolbox exec session without depending on nohup or an image init.
    unsafe {
        command.pre_exec(|| if libc::setsid() == -1 { Err(io::Error::last_os_error()) } else { Ok(()) });
    }
    command.spawn()?;
    Ok(())
}

pub async fn run(args: &[OsString]) -> io::Result<()> {
    let socket = socket(args)?;
    let parent = socket.parent().ok_or_else(|| io::Error::other("socket needs a directory"))?;
    drydock_agent::socket::private_directory(parent)?;
    // Keep this inode forever: unlinking a locked file would allow two owners.
    // Rust opens CLOEXEC, so neither children nor agent re-execs retain the lock.
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(parent.join("supervisor.lock"))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    let executable = std::env::current_exe()?;
    loop {
        // Resolve the installed pathname on each restart, including after an
        // upgrade. The agent itself removes a stale socket after a crash.
        match tokio::process::Command::new(&executable).args(args).stdin(Stdio::null()).spawn() {
            Ok(mut child) => {
                let _ = child.wait().await?;
            }
            Err(error) => eprintln!("start agent: {error}"),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

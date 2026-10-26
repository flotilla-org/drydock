//! Optional provider-side supervision, packaged in the tools executable.
use std::{
    ffi::OsString,
    io,
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
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
    // Its own process group, outside the toolbox exec session's foreground
    // group, without depending on nohup or an image init.
    command.process_group(0);
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
    // Capture the installed pathname once. Each spawn resolves that pathname
    // again, including after upgrade replaces its inode; current_exe() on this
    // supervisor would instead report the old inode as deleted after upgrade.
    let executable = std::env::current_exe()?;
    let mut delay = Duration::from_millis(250);
    loop {
        let started = Instant::now();
        // The agent itself removes a stale socket after a crash.
        match tokio::process::Command::new(&executable).args(args).stdin(Stdio::null()).spawn() {
            Ok(mut child) => {
                if let Err(error) = child.wait().await {
                    eprintln!("wait for agent: {error}");
                }
            }
            Err(error) => eprintln!("start agent: {error}"),
        }
        tokio::time::sleep(restart_delay(&mut delay, started.elapsed())).await;
    }
}

// Repeated startup failures back off from 250 ms to four seconds. A child that
// ran for at least 30 seconds resets the failure streak before its next restart.
fn restart_delay(next: &mut Duration, runtime: Duration) -> Duration {
    if runtime >= Duration::from_secs(30) {
        *next = Duration::from_millis(250);
    }
    let delay = *next;
    *next = (delay * 2).min(Duration::from_secs(4));
    delay
}

#[cfg(test)]
mod tests {
    use super::*;
    // Short runs increase backoff to a cap; a stable run resets it, including
    // exactly at the 30-second boundary. Generate sequences spanning immediate
    // exits, either side of that boundary, and duplicate failures at the cap.
    #[hegel::test]
    fn restart_backoff_is_bounded_and_resets_after_stable_runs(tc: hegel::TestCase) {
        use hegel::generators as gs;
        let mut next = Duration::from_millis(250);
        let mut failures = 0u32;
        for _ in 0..40 {
            let milliseconds = tc.draw(gs::integers::<u64>().min_value(0).max_value(30001));
            let runtime = Duration::from_millis(milliseconds);
            if milliseconds >= 30000 {
                failures = 0;
            }
            let actual = restart_delay(&mut next, runtime);
            assert_eq!(actual.as_millis(), 250u128 << failures.min(4));
            assert!((Duration::from_millis(250)..=Duration::from_secs(4)).contains(&actual));
            failures += 1;
        }
        // Always exercise both the threshold and the cap, independent of draws.
        for runtime in [29999, 30000, 30001] {
            for _ in 0..10 {
                restart_delay(&mut next, Duration::ZERO);
            }
            let actual = restart_delay(&mut next, Duration::from_millis(runtime));
            assert_eq!(actual, if runtime < 30000 { Duration::from_secs(4) } else { Duration::from_millis(250) });
        }
    }
}

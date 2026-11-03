//! Optional provider-side supervision, packaged in the tools executable.
use std::{
    ffi::OsString,
    io,
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// The supervised socket, which comes last: every process of a vessel's
/// agent ends its argv with `--socket PATH`, so a host can find them all by
/// it. Options before it (`--store DIR`, `--tcp ADDR:PORT`,
/// `--tcp-token-file PATH`) are the agent's, passed on to every agent the
/// supervisor starts.
fn socket(args: &[OsString]) -> io::Result<PathBuf> {
    const OPTIONS: &[&str] = &["--store", "--tcp", "--tcp-token-file"];
    let usage = || io::Error::other("usage: drydock-agent --supervise [--store DIR] [--tcp ADDR:PORT --tcp-token-file PATH] --socket PATH");
    let [options @ .., flag, path] = args else { return Err(usage()) };
    let names: Vec<_> = options.chunks(2).map(|pair| &pair[0]).collect();
    if flag != "--socket"
        || options.len() % 2 != 0
        || !names.iter().all(|name| OPTIONS.iter().any(|option| name == option))
        || (1..names.len()).any(|i| names[..i].contains(&names[i]))
    {
        return Err(usage());
    }
    if let Some(pair) = args.chunks(2).find(|pair| pair[1].as_encoded_bytes().starts_with(b"--")) {
        return Err(io::Error::other(format!(
            "{} takes a value, not {:?}; name a path beginning with -- as ./--…",
            pair[0].display(),
            pair[1]
        )));
    }
    Ok(path.into())
}

/// Refuses a TCP listener the agent would refuse, before detaching, so the
/// provider's bootstrap hears of it rather than a supervisor that restarts
/// a failing agent for ever. The token file's own state is [`provision`]'s.
fn check_tcp(args: &[OsString]) -> io::Result<()> {
    let value = |name: &str| args.chunks(2).find(|pair| pair[0] == name).and_then(|pair| pair.get(1));
    match (value("--tcp"), value("--tcp-token-file")) {
        (Some(address), Some(path)) => {
            address
                .to_str()
                .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
                .ok_or_else(|| io::Error::other("--tcp requires ADDR:PORT"))?;
            // Every agent the supervisor restarts reads it again, so it must
            // not depend on the directory bootstrap ran in.
            let path = std::path::Path::new(path);
            if !path.is_absolute() {
                return Err(io::Error::other("--supervise requires an absolute --tcp-token-file"));
            }
            Ok(())
        }
        (None, None) => Ok(()),
        (Some(_), None) => Err(io::Error::other("--tcp requires --tcp-token-file")),
        (None, Some(_)) => Err(io::Error::other("--tcp-token-file requires --tcp")),
    }
}

/// `--token-from-env VAR` and `--print-token` are bootstrap's, not the
/// agent's: `args` without them, and what they asked for.
fn bootstrap(args: &[OsString]) -> io::Result<(Vec<OsString>, Option<String>, bool)> {
    let (mut rest, mut variable, mut print) = (Vec::new(), None, false);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--print-token" {
            print = true;
        } else if arg == "--token-from-env" {
            let name = args.next().and_then(|v| v.to_str()).filter(|v| !v.is_empty() && !v.starts_with("--"));
            variable = Some(name.ok_or_else(|| io::Error::other("--token-from-env requires a variable name"))?.to_owned());
        } else {
            // Every other option takes a value, which is kept whole.
            rest.push(arg.clone());
            rest.extend(args.next().cloned());
        }
    }
    Ok((rest, variable, print))
}

/// Writes or keeps the token file `--tcp-token-file` names, then prints the
/// token if asked, before detaching, so a bootstrap hears of a bad file or
/// variable rather than a supervisor that restarts a failing agent for ever.
fn provision(args: &[OsString], variable: Option<&str>, print: bool) -> io::Result<()> {
    let Some(path) = args.chunks(2).find(|pair| pair[0] == "--tcp-token-file").and_then(|pair| pair.get(1)) else {
        return match (variable, print) {
            (None, false) => Ok(()),
            _ => Err(io::Error::other("--token-from-env and --print-token require --tcp-token-file")),
        };
    };
    let path = std::path::Path::new(path);
    let supplied = match variable {
        Some(name) => {
            let text = std::env::var(name).map_err(|_| io::Error::other(format!("--token-from-env: {name} is not set to text")))?;
            Some(drydock_agent::tcp::Token::parse(&text).map_err(|e| io::Error::new(e.kind(), format!("--token-from-env {name}: {e}")))?)
        }
        None => None,
    };
    let token = drydock_agent::tcp::provision_token(path, supplied)?;
    if print {
        println!("{}", drydock_agent::tcp::token_line(&token));
    }
    Ok(())
}

pub fn start(args: &[OsString]) -> io::Result<()> {
    let (args, variable, print) = bootstrap(args)?;
    let args = &args[..];
    let path = socket(args)?;
    check_tcp(args)?;
    provision(args, variable.as_deref(), print)?;
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
    // Only the file keeps the token: the agent's environment is readable through /proc.
    if let Some(name) = &variable {
        command.env_remove(name);
    }
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

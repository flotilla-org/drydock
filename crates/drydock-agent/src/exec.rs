use crate::{Exec, ExecEvent};
use std::{collections::BTreeMap, io, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command, sync::mpsc};

pub(crate) fn launch(request: Exec, environment: BTreeMap<String, String>) -> io::Result<mpsc::Receiver<ExecEvent>> {
    // Separate file descriptions: readers and child writers must not share offsets.
    // Anonymous files remain writable after an agent exit, with no broken pipe.
    let out = tempfile::NamedTempFile::new()?;
    let err = tempfile::NamedTempFile::new()?;
    let mut stdout = tokio::fs::File::from_std(out.reopen()?);
    let mut stderr = tokio::fs::File::from_std(err.reopen()?);
    let mut command = Command::new(&request.program);
    command.args(request.args).stdin(Stdio::null()).stdout(out.reopen()?).stderr(err.reopen()?);
    command.envs(environment);
    // Fixed pipeline defaults win over accidental interactive settings.
    command.envs([
        ("CI", "1"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("NO_COLOR", "1"),
        ("TERM", "dumb"),
        ("PAGER", "cat"),
        ("GIT_PAGER", "cat"),
        ("DEBIAN_FRONTEND", "noninteractive"),
    ]);
    if let Some(cwd) = request.cwd {
        command.current_dir(cwd);
    }
    // SAFETY: setsid is async-signal-safe; no allocation or locking after fork.
    unsafe {
        command.pre_exec(|| if libc::setsid() == -1 { Err(io::Error::last_os_error()) } else { Ok(()) });
    }
    let mut child = command.kill_on_drop(false).spawn()?;
    drop((out, err));
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        let mut status = None;
        let mut buffer = [0; 8192];
        let mut idle = Duration::from_millis(10);
        loop {
            if tx.is_closed() {
                let _ = child.wait().await;
                break;
            }
            let mut emitted = false;
            for (file, is_out) in [(&mut stdout, true), (&mut stderr, false)] {
                match file.read(&mut buffer).await {
                    Ok(0) => {}
                    Ok(n) => {
                        emitted = true;
                        let bytes = buffer[..n].to_vec();
                        let event = if is_out { ExecEvent::Stdout(bytes) } else { ExecEvent::Stderr(bytes) };
                        // On disconnect continue reaping; never kill the detached child.
                        let _ = tx.send(event).await;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "exec output spool read failed");
                        drop(tx);
                        let _ = child.wait().await;
                        return;
                    }
                }
            }
            if status.is_some() && !emitted {
                let _ = tx.send(ExecEvent::Exit { code: status.flatten() }).await;
                break;
            }
            if status.is_none() {
                match child.try_wait() {
                    Ok(Some(exit)) => status = Some(exit.code()),
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
            if !emitted {
                tokio::time::sleep(idle).await;
                idle = (idle * 2).min(Duration::from_millis(250));
            } else {
                idle = Duration::from_millis(10);
            }
        }
    });
    Ok(rx)
}

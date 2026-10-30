//! Processes as handles. Output is read from pipes into a bounded per-process
//! buffer; when nobody drains it the reader stops and the child blocks on
//! its pipe, so a process whose client went away never spools without limit.
//! A reader attaches to the handle, can be replaced by a later attach, and
//! sees each byte's offset. Sent bytes stay held while the buffer has room, so
//! a reader that reattaches at the offsets it received also gets what was in
//! flight when it went away; only bytes evicted for new output are lost, and
//! the offsets show that.
use crate::{
    AgentError, ErrorKind, Exec, ExitStatus, ProcessInfo, ProcessState,
    frames::{Frame, MAX_PAYLOAD},
};
use bytes::Bytes;
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    io,
    process::Stdio,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::unix::pipe,
    process::{ChildStdin, Command},
    sync::watch,
};

/// After the process exits, output still in its pipes is read until EOF. A
/// descendant holding a pipe open is waited for this long without new bytes.
const DRAIN_GRACE: Duration = Duration::from_millis(250);
/// Exited handles kept for status queries beyond this count are dropped,
/// oldest first.
const MAX_EXITED: usize = 256;

#[derive(Default)]
struct Output {
    /// Held frames in production order; the first `sent` went to the reader
    /// and are kept only for a reattach.
    frames: VecDeque<Frame>,
    sent: usize,
    /// Bytes in all held frames, never more than the limit.
    held: usize,
    /// Bytes in held frames not yet sent.
    buffered: usize,
    /// Offset of the next byte each stream will produce.
    produced: [u64; 2],
    /// Offset of the next byte each stream will deliver.
    delivered: [u64; 2],
    open_pipes: u8,
    exit: Option<ExitStatus>,
    exit_delivered: bool,
    /// Bumped by each attach; an older reader sees it and ends.
    reader: u64,
    /// The handle was removed or evicted: pumps stop, readers end.
    closed: bool,
}
impl Output {
    fn finished(&self) -> bool {
        self.exit.is_some() && self.open_pipes == 0
    }
    /// How many of `want` more bytes fit once sent frames, which are held
    /// only for a reattach, give way.
    fn room(&self, limit: usize, want: usize) -> usize {
        limit.saturating_sub(self.buffered).min(want)
    }
    /// Evict sent frames, oldest first, until `n` more bytes fit. Called
    /// only once they have been read, so history is never given up for a
    /// read that returned less, or nothing.
    fn make_room(&mut self, limit: usize, n: usize) {
        while self.held + n > limit && self.sent > 0 {
            let Some(Frame::Output { bytes, .. }) = self.frames.pop_front() else { unreachable!("exit frames are never held") };
            self.held -= bytes.len();
            self.sent -= 1;
        }
    }
}
pub(crate) struct Handle {
    id: String,
    pid: u32,
    program: String,
    limit: usize,
    output: Mutex<Output>,
    changed: watch::Sender<u64>,
    stdin: tokio::sync::Mutex<Option<ChildStdin>>,
    has_stdin: bool,
    sequence: u64,
}
impl Handle {
    fn bump(&self) {
        self.changed.send_modify(|v| *v = v.wrapping_add(1));
    }
    pub(crate) fn info(&self) -> ProcessInfo {
        let output = self.output.lock().unwrap();
        ProcessInfo {
            id: self.id.clone(),
            pid: self.pid,
            program: self.program.clone(),
            state: match output.exit {
                Some(status) => ProcessState::Exited(status),
                None => ProcessState::Running,
            },
            buffered: output.buffered as u64,
            stdout: output.delivered[0],
            stderr: output.delivered[1],
        }
    }
    fn running(&self) -> bool {
        self.output.lock().unwrap().exit.is_none()
    }
    /// Forget the output: the pumps stop reading (dropping the pipes) and
    /// any reader ends, so a removed handle holds nothing. Without this a
    /// pump blocked on a full buffer would keep the handle alive forever.
    fn close(&self) {
        let mut output = self.output.lock().unwrap();
        output.closed = true;
        output.frames.clear();
        (output.held, output.buffered, output.sent) = (0, 0, 0);
        drop(output);
        self.bump();
    }
    /// Signal the whole process group, which the process leads. The waiter
    /// reaps the process only while holding the output lock, after which
    /// `exit` is set; so while the lock is held here and `exit` is unset, the
    /// PID still names this process group and cannot have been reused.
    pub(crate) fn signal(&self, signal: i32) -> Result<(), AgentError> {
        let invalid =
            || AgentError::new("process.signal", &self.id, ErrorKind::InvalidInput, format!("{signal} is not a signal the agent sends"));
        let signal = rustix::process::Signal::from_named_raw(signal).ok_or_else(invalid)?;
        let output = self.output.lock().unwrap();
        if output.exit.is_some() {
            return Err(AgentError::new("process.signal", &self.id, ErrorKind::Conflict, "process has exited"));
        }
        let group = rustix::process::Pid::from_raw(self.pid as i32).ok_or_else(invalid)?;
        rustix::process::kill_process_group(group, signal).map_err(|e| AgentError::io("process.signal", &self.id, e.into()))
    }
    /// Stream request bytes to the process's stdin, then close it.
    pub(crate) async fn write_stdin(&self, body: axum::body::Body) -> Result<u64, AgentError> {
        const OP: &str = "process.stdin";
        if !self.has_stdin {
            return Err(AgentError::new(OP, &self.id, ErrorKind::Conflict, "process was started without a stdin pipe"));
        }
        let Some(mut stdin) = self.stdin.lock().await.take() else {
            return Err(AgentError::new(OP, &self.id, ErrorKind::Conflict, "stdin was already written and closed"));
        };
        let body = futures_util::TryStreamExt::map_err(body.into_data_stream(), |e| io::Error::new(io::ErrorKind::ConnectionAborted, e));
        let written =
            tokio::io::copy(&mut tokio_util::io::StreamReader::new(body), &mut stdin).await.map_err(|e| AgentError::io(OP, &self.id, e))?;
        stdin.shutdown().await.map_err(|e| AgentError::io(OP, &self.id, e))?;
        Ok(written)
    }
    /// Become the handle's reader. Bytes before the given offsets, which the
    /// caller already has, are discarded first.
    pub(crate) fn attach(
        self: &Arc<Self>,
        from: [u64; 2],
    ) -> Result<impl futures_util::Stream<Item = io::Result<Bytes>> + use<>, AgentError> {
        let generation = {
            let mut output = self.output.lock().unwrap();
            for (stream, offset) in from.iter().enumerate() {
                if *offset > output.produced[stream] {
                    return Err(AgentError::new(
                        "process.attach",
                        &self.id,
                        ErrorKind::InvalidInput,
                        format!("offset {offset} is beyond the {} bytes produced on {}", output.produced[stream], name(stream)),
                    ));
                }
            }
            // Everything held from the caller's offsets on is sent again,
            // including frames the previous reader was sent but never got.
            let (mut kept, mut held) = (VecDeque::new(), 0);
            for frame in std::mem::take(&mut output.frames) {
                let Frame::Output { stderr, offset, bytes } = frame else { unreachable!("exit frames are never held") };
                let skip = from[stderr as usize].saturating_sub(offset).min(bytes.len() as u64) as usize;
                if skip < bytes.len() {
                    held += bytes.len() - skip;
                    kept.push_back(Frame::Output { stderr, offset: offset + skip as u64, bytes: bytes.slice(skip..) });
                }
            }
            output.held = held;
            output.buffered = held;
            output.frames = kept;
            output.sent = 0;
            output.delivered = from;
            output.reader += 1;
            output.exit_delivered = false;
            output.reader
        };
        self.bump();
        let handle = self.clone();
        let changes = self.changed.subscribe();
        Ok(futures_util::stream::unfold((handle, changes, false), move |(handle, mut changes, done)| async move {
            if done {
                return None;
            }
            loop {
                changes.borrow_and_update();
                let next = {
                    let mut output = handle.output.lock().unwrap();
                    if output.reader != generation || output.closed {
                        return None;
                    }
                    if let Some(frame) = output.frames.get(output.sent).cloned() {
                        if let Frame::Output { stderr, offset, bytes } = &frame {
                            output.buffered -= bytes.len();
                            output.delivered[*stderr as usize] = offset + bytes.len() as u64;
                        }
                        output.sent += 1;
                        Some((frame, false))
                    } else if output.finished() && !output.exit_delivered {
                        output.exit_delivered = true;
                        Some((Frame::Exit(output.exit.unwrap()), true))
                    } else if output.exit_delivered {
                        return None;
                    } else {
                        None
                    }
                };
                if let Some((frame, last)) = next {
                    handle.bump();
                    return Some((Ok(frame.encode()), (handle, changes, last)));
                }
                if changes.changed().await.is_err() {
                    return None;
                }
            }
        }))
    }
}
fn name(stream: usize) -> &'static str {
    if stream == 0 { "stdout" } else { "stderr" }
}

pub(crate) struct Processes {
    table: Mutex<HashMap<String, Arc<Handle>>>,
    next: AtomicU64,
    limit: usize,
    events: Arc<crate::events::Events>,
    /// Set once an upgrade drains the agent. Every spawn holds the read side
    /// until its handle is in the table, so a drain that has set it sees
    /// every process that will ever start under this agent.
    draining: RwLock<bool>,
}
impl Processes {
    pub(crate) fn new(limit: usize, events: Arc<crate::events::Events>) -> Self {
        Self { table: Mutex::default(), next: AtomicU64::new(1), limit: limit.max(1), events, draining: RwLock::new(false) }
    }
    /// Stop accepting processes, then wait up to `limit` for the running ones
    /// to exit. Returns those still running at the limit. There is no way
    /// back: a drain is always followed by the re-exec, and if both the
    /// candidate's and the rollback's exec fail the agent exits, so no agent
    /// process ever serves on after draining.
    pub(crate) async fn drain(&self, limit: Duration) -> Vec<ProcessInfo> {
        *self.draining.write().unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            let running: Vec<_> = self.list().into_iter().filter(|p| p.state == ProcessState::Running).collect();
            if running.is_empty() || tokio::time::Instant::now() >= deadline {
                return running;
            }
            tokio::time::sleep_until(deadline.min(tokio::time::Instant::now() + Duration::from_millis(20))).await;
        }
    }
    pub(crate) fn get(&self, id: &str) -> Result<Arc<Handle>, AgentError> {
        self.table
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| AgentError::new("process.find", id, ErrorKind::NotFound, "no process with this ID"))
    }
    pub(crate) fn list(&self) -> Vec<ProcessInfo> {
        let mut handles: Vec<_> = self.table.lock().unwrap().values().cloned().collect();
        handles.sort_by_key(|h| h.sequence);
        handles.iter().map(|h| h.info()).collect()
    }
    /// Kill a running process's group and forget the handle.
    pub(crate) fn remove(&self, id: &str) -> Result<(), AgentError> {
        let handle = self.get(id)?;
        if handle.running() {
            // The waiter still reaps it; a race with its exit is harmless.
            let _ = handle.signal(libc::SIGKILL);
        }
        self.table.lock().unwrap().remove(id);
        handle.close();
        Ok(())
    }
    pub(crate) fn spawn(&self, request: Exec, environment: BTreeMap<String, String>) -> Result<Arc<Handle>, AgentError> {
        let draining = self.draining.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        if *draining {
            return Err(AgentError::new(
                "process.spawn",
                &request.program,
                ErrorKind::Conflict,
                "the agent is draining for an upgrade and starts no more processes",
            ));
        }
        let mut command = Command::new(&request.program);
        command
            .args(&request.args)
            .stdin(if request.stdin { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.envs(environment);
        // Fixed pipeline defaults win over accidental interactive settings in
        // the configuration; the request's own environment wins over both.
        command.envs([
            ("CI", "1"),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("NO_COLOR", "1"),
            ("TERM", "dumb"),
            ("PAGER", "cat"),
            ("GIT_PAGER", "cat"),
            ("DEBIAN_FRONTEND", "noninteractive"),
        ]);
        command.envs(&request.environment);
        if request.environment.iter().any(|(k, v)| k.is_empty() || k.contains(['=', '\0']) || v.contains('\0')) {
            return Err(AgentError::new("process.environment", &request.program, ErrorKind::InvalidInput, "invalid process environment"));
        }
        if let Some(cwd) = &request.cwd {
            let metadata = std::fs::metadata(cwd).map_err(|e| AgentError::io("process.cwd", cwd.display(), e))?;
            if !metadata.is_dir() {
                return Err(AgentError::new(
                    "process.cwd",
                    cwd.display(),
                    ErrorKind::NotADirectory,
                    "working directory is not a directory",
                ));
            }
            command.current_dir(cwd);
        }
        // Its own process group, which it leads, so signals reach its children.
        command.process_group(0);
        let mut child = command.kill_on_drop(false).spawn().map_err(|e| AgentError::io("process.spawn", &request.program, e))?;
        // Pipes the pumps can read without blocking, sized under the lock.
        let pipes = (|| {
            let stdout = pipe::Receiver::from_owned_fd(child.stdout.take().unwrap().into_owned_fd()?)?;
            Ok::<_, io::Error>((stdout, pipe::Receiver::from_owned_fd(child.stderr.take().unwrap().into_owned_fd()?)?))
        })();
        let (stdout, stderr) = match pipes {
            Ok(pipes) => pipes,
            Err(error) => {
                // Tokio reaps a dropped child in the background.
                let _ = child.start_kill();
                return Err(AgentError::io("process.spawn", &request.program, error));
            }
        };
        let pid = child.id().unwrap_or_default();
        let sequence = self.next.fetch_add(1, Ordering::Relaxed);
        let id = format!("{sequence}-{pid}");
        let (changed, _) = watch::channel(0);
        let handle = Arc::new(Handle {
            id: id.clone(),
            pid,
            program: request.program.clone(),
            limit: self.limit,
            output: Mutex::new(Output { open_pipes: 2, ..Output::default() }),
            changed,
            stdin: tokio::sync::Mutex::new(child.stdin.take()),
            has_stdin: request.stdin,
            sequence,
        });
        let (exited_tx, exited) = watch::channel(false);
        tokio::spawn(pump(handle.clone(), stdout, false, exited.clone()));
        tokio::spawn(pump(handle.clone(), stderr, true, exited));
        let waiter = handle.clone();
        let events = self.events.clone();
        let timeout = request.timeout_ms.map(Duration::from_millis);
        let unreaped = rustix::process::Pid::from_raw(pid as i32).expect("a spawned child has a PID");
        tokio::spawn(async move {
            // Wait for the exit without reaping, so the PID keeps naming this
            // process group until it is reaped below, under the output lock.
            let exit = exited_unreaped(unreaped);
            tokio::pin!(exit);
            let mut timed_out = false;
            let exited = match timeout {
                Some(limit) => match tokio::time::timeout(limit, &mut exit).await {
                    Ok(exited) => exited,
                    Err(_) => {
                        timed_out = true;
                        let _ = waiter.signal(libc::SIGKILL);
                        exit.await
                    }
                },
                None => exit.await,
            };
            if let Err(error) = exited {
                tracing::warn!(%error, process = %waiter.id, "process wait failed");
            }
            let status = {
                let mut output = waiter.output.lock().unwrap();
                *output.exit.insert(match child.try_wait() {
                    Ok(Some(status)) => {
                        use std::os::unix::process::ExitStatusExt;
                        ExitStatus { code: status.code(), signal: status.signal(), timed_out }
                    }
                    other => {
                        tracing::warn!(?other, process = %waiter.id, "process reaping failed");
                        ExitStatus { code: None, signal: None, timed_out }
                    }
                })
            };
            let _ = exited_tx.send(true);
            waiter.bump();
            events.push(crate::events::Event::ProcessExited { id: waiter.id.clone(), status });
        });
        let mut table = self.table.lock().unwrap();
        let mut exited: Vec<_> = table.values().filter(|h| !h.running()).map(|h| (h.sequence, h.id.clone())).collect();
        if exited.len() >= MAX_EXITED {
            exited.sort();
            for (_, id) in &exited[..=exited.len() - MAX_EXITED] {
                if let Some(evicted) = table.remove(id) {
                    evicted.close();
                }
            }
        }
        table.insert(id, handle.clone());
        drop(draining);
        Ok(handle)
    }
}
/// Wait until `pid` has exited, leaving it unreaped. On Linux a pidfd turns
/// readable at the exit, so no thread waits; elsewhere, or on a kernel
/// without pidfds, a blocking `waitid(WNOWAIT)` does.
async fn exited_unreaped(pid: rustix::process::Pid) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    match rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) {
        Ok(pidfd) => {
            // Deprecated in tokio 1.54 for descriptors a caller might close
            // early; the AsyncFd owns this OwnedFd, so that cannot happen. Its
            // replacement is missing from the tokio versions consumers lock.
            // TODO: use register_with_interest once the tokio floor is 1.54.
            #[allow(deprecated)]
            let pidfd = tokio::io::unix::AsyncFd::with_interest(pidfd, tokio::io::Interest::READABLE)?;
            let _ = pidfd.readable().await?;
            return Ok(());
        }
        Err(error) => tracing::debug!(%error, "no pidfd for this process; a blocking thread waits for its exit"),
    }
    tokio::task::spawn_blocking(move || {
        use rustix::process::{WaitId, WaitIdOptions, waitid};
        loop {
            match waitid(WaitId::Pid(pid), WaitIdOptions::EXITED | WaitIdOptions::NOWAIT) {
                Err(rustix::io::Errno::INTR) => continue,
                result => return result.map(drop).map_err(Into::into),
            }
        }
    })
    .await?
}
/// Move one pipe's bytes into the handle's buffer while it has room. The
/// read happens under the output lock, sized to the room left, so the two
/// pipes together never hold more than the limit.
async fn pump(handle: Arc<Handle>, pipe: pipe::Receiver, stderr: bool, mut exited: watch::Receiver<bool>) {
    let stream = stderr as usize;
    let mut changes = handle.changed.subscribe();
    let mut buffer = vec![0; MAX_PAYLOAD.min(64 * 1024)];
    loop {
        loop {
            changes.borrow_and_update();
            let (closed, room) = {
                let output = handle.output.lock().unwrap();
                (output.closed, output.buffered < handle.limit)
            };
            if closed {
                return;
            }
            if room {
                break;
            }
            if changes.changed().await.is_err() {
                return;
            }
        }
        let ready = if *exited.borrow() {
            match tokio::time::timeout(DRAIN_GRACE, pipe.readable()).await {
                Ok(ready) => ready.map(|()| true),
                // A descendant holds the pipe open; stop waiting for it.
                Err(_) => Ok(false),
            }
        } else {
            tokio::select! {
                ready = pipe.readable() => ready.map(|()| true),
                _ = exited.wait_for(|exited| *exited) => continue,
            }
        };
        let mut output = handle.output.lock().unwrap();
        if output.closed {
            return;
        }
        let read = match ready {
            Ok(false) => Ok(0),
            Ok(true) => match output.room(handle.limit, buffer.len()) {
                // The other pipe filled the buffer meanwhile.
                0 => continue,
                room => pipe.try_read(&mut buffer[..room]),
            },
            Err(error) => Err(error),
        };
        let n = match read {
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => {
                tracing::warn!(%error, process = %handle.id, stream = name(stream), "process pipe read failed");
                0
            }
        };
        if n == 0 {
            output.open_pipes -= 1;
            drop(output);
            handle.bump();
            return;
        }
        let offset = output.produced[stream];
        output.produced[stream] += n as u64;
        output.make_room(handle.limit, n);
        output.buffered += n;
        output.held += n;
        debug_assert!(output.held <= handle.limit);
        output.frames.push_back(Frame::Output { stderr, offset, bytes: Bytes::copy_from_slice(&buffer[..n]) });
        drop(output);
        handle.bump();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // A removed handle whose buffer filled with nobody reading is let go
    // entirely: its pumps stop, so nothing keeps it, its buffer or its pipes
    // alive after the process is gone.
    #[tokio::test]
    async fn removed_handles_are_released() {
        let processes = Processes::new(4096, Arc::new(crate::events::Events::new("test".into())));
        let script = "head -c 1000000 /dev/zero; sleep 30";
        let handle = processes.spawn(Exec::new("/bin/sh", ["-c", script]), BTreeMap::new()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while handle.info().buffered < 4096 {
            assert!(std::time::Instant::now() < deadline, "the buffer never filled");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        processes.remove(&handle.id).unwrap();
        let released = Arc::downgrade(&handle);
        drop(handle);
        while released.upgrade().is_some() {
            assert!(std::time::Instant::now() < deadline, "a removed handle is still held");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

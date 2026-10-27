//! The process API end to end: real `/bin/sh` children behind a real agent and
//! transport, driven through the typed client. How refusals are encoded
//! belongs to the error layer (`contract.rs`).
mod support;
use drydock_agent::{Agent, Configuration, ErrorKind, Exec, ExecEvent, ExecOutput, ExitStatus, ProcessState};
use std::{
    io,
    path::Path,
    time::{Duration, Instant},
};
use support::*;

const WAIT: Duration = Duration::from_secs(20);

/// An agent holding at most `limit` output bytes per process.
async fn bounded(limit: usize) -> Harness {
    harness_with(false, "test-build", move |guest, dir| Agent::with_process_buffer(guest, "test-build".into(), dir.join("agent"), limit))
        .await
}
async fn next(output: &mut ExecOutput) -> ExecEvent {
    tokio::time::timeout(WAIT, output.next()).await.expect("process output stalled").unwrap().expect("output ended before its exit")
}
/// Read events until `stdout` and `stderr` hold at least the given lengths.
async fn read_at_least(output: &mut ExecOutput, stdout: usize, stderr: usize) -> (Vec<u8>, Vec<u8>) {
    let (mut out, mut err) = (vec![], vec![]);
    while out.len() < stdout || err.len() < stderr {
        match next(output).await {
            ExecEvent::Stdout(bytes) => out.extend_from_slice(&bytes),
            ExecEvent::Stderr(bytes) => err.extend_from_slice(&bytes),
            ExecEvent::Exit(status) => panic!("exited with {status:?} after {} and {} bytes", out.len(), err.len()),
        }
    }
    (out, err)
}
/// Poll until `probe` yields a value, failing after a generous deadline.
async fn eventually<T>(what: &str, mut probe: impl AsyncFnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(value) = probe().await {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn exited(process: &drydock_agent::Process) -> ExitStatus {
    eventually("the process to exit", async || match process.info().await.unwrap().state {
        ProcessState::Exited(status) => Some(status),
        ProcessState::Running => None,
    })
    .await
}
/// A PID that no longer names a live process: gone, or a zombie whose reaper
/// is not the agent.
fn dead(pid: &str) -> bool {
    match std::fs::read_to_string(format!("/proc/{}/stat", pid.trim())) {
        Err(_) => true,
        Ok(stat) => stat.rsplit_once(')').is_some_and(|(_, rest)| rest.trim_start().starts_with('Z')),
    }
}
fn gated(gate: &Path, before: &str, after: &str) -> Exec {
    shell(&format!("{before}; while test ! -f '{}'; do sleep 0.01; done; {after}", gate.display()))
}
/// The refusal behind a failed call, which must be of `expected` kind.
fn refusal(error: io::Error, expected: ErrorKind) -> drydock_agent::AgentError {
    assert_eq!(kind(&error), expected, "{error}");
    agent_error(&error).clone()
}
fn status(code: Option<i32>, signal: Option<i32>, timed_out: bool) -> ExitStatus {
    ExitStatus { code, signal, timed_out }
}

// Stdin is a stream: every byte value and a few hundred KiB, written while the
// output is read, comes back through `cat` unchanged. The write must overlap
// the read, since `cat` stops reading stdin once its output buffer is full.
// Without a stdin pipe the process reads EOF from /dev/null.
#[tokio::test]
async fn stdin_is_streamed_and_absent_stdin_is_null() {
    let h = harness(false, "test-build").await;
    let input: Vec<u8> = (0..=255u8).cycle().take(300 * 1024 + 17).collect();
    let process = h.client.spawn(Exec { stdin: true, ..Exec::new("cat", Vec::<String>::new()) }).await.unwrap();
    let reader = process.output().await.unwrap();
    let (written, (stdout, stderr, exit)) = tokio::join!(process.write_stdin_bytes(input.clone()), output(reader));
    written.unwrap();
    assert!(stdout == input, "{} bytes back for {}", stdout.len(), input.len());
    assert_eq!((stderr, exit), (vec![], status(Some(0), None, false)));

    let (stdout, _, exit) = output(h.client.exec(shell("cat; echo eof $?")).await.unwrap()).await;
    assert_eq!((stdout, exit), (b"eof 0\n".to_vec(), status(Some(0), None, false)));
}

// Stdout and stderr stay separate: interleaved writes land on their own
// stream in order. Output streams while the process runs: the first bytes
// arrive while it still waits on a gate the test opens afterwards.
#[tokio::test]
async fn stdout_and_stderr_are_separate_and_incremental() {
    let h = harness(false, "test-build").await;
    let gate = h.dir.path().join("gate");
    let process = h
        .client
        .spawn(gated(&gate, "i=0; while [ $i -lt 40 ]; do printf o$i,; printf e$i, >&2; i=$((i+1)); done", "printf late; printf tail >&2"))
        .await
        .unwrap();
    let mut reader = process.output().await.unwrap();
    let (mut stdout, mut stderr) = read_at_least(&mut reader, 1, 1).await;
    assert_eq!(process.info().await.unwrap().state, ProcessState::Running);
    std::fs::write(&gate, []).unwrap();
    let (out, err, exit) = output(reader).await;
    stdout.extend(out);
    stderr.extend(err);
    let expected = |prefix: &str, last: &str| (0..40).map(|i| format!("{prefix}{i},")).collect::<String>() + last;
    assert_eq!(String::from_utf8(stdout).unwrap(), expected("o", "late"));
    assert_eq!(String::from_utf8(stderr).unwrap(), expected("e", "tail"));
    assert!(exit.success());
}

// A non-zero exit code is reported as a code, not a signal or a timeout, both
// in the output's exit frame and in the handle's state.
#[tokio::test]
async fn exit_code_is_reported() {
    let h = harness(false, "test-build").await;
    let process = h.client.spawn(shell("printf done; exit 7")).await.unwrap();
    let (stdout, _, exit) = output(process.output().await.unwrap()).await;
    assert_eq!((stdout, exit), (b"done".to_vec(), status(Some(7), None, false)));
    assert!(!exit.success());
    assert_eq!(exited(&process).await, exit);
    let info = process.info().await.unwrap();
    assert_eq!((info.stdout, info.stderr, info.buffered), (4, 0, 0));
}

// Kill reaches the whole process group the process leads: the shell dies by
// SIGKILL, reported as a signal with no exit code, and so does a background
// grandchild that would otherwise outlive it.
#[tokio::test]
async fn kill_ends_the_process_group() {
    let h = harness(false, "test-build").await;
    let process = h.client.spawn(shell("sleep 1000 & echo $!; wait")).await.unwrap();
    let mut reader = process.output().await.unwrap();
    let mut line = vec![];
    while !line.ends_with(b"\n") {
        line.extend(read_at_least(&mut reader, 1, 0).await.0);
    }
    let grandchild = String::from_utf8(line).unwrap();
    assert!(!dead(&grandchild));
    process.kill().await.unwrap();
    let (_, _, exit) = output(reader).await;
    assert_eq!(exit, status(None, Some(libc::SIGKILL), false));
    eventually("the grandchild to die", async || dead(&grandchild).then_some(())).await;
    assert!(dead(&process.pid().to_string()), "the agent reaps its own child");
}

// Signals are delivered, not just used to kill: a shell trapping SIGTERM runs
// its handler and exits with the code it chooses. Once the process has
// exited, its PID may be reused, so signalling it is a conflict.
#[tokio::test]
async fn signal_is_delivered_and_refused_after_exit() {
    let h = harness(false, "test-build").await;
    let process = h.client.spawn(shell("trap 'printf term; exit 3' TERM; printf ready; while :; do sleep 0.02; done")).await.unwrap();
    let mut reader = process.output().await.unwrap();
    assert_eq!(read_at_least(&mut reader, 5, 0).await.0, b"ready");
    process.signal(libc::SIGTERM).await.unwrap();
    let (stdout, _, exit) = output(reader).await;
    assert_eq!((stdout, exit), (b"term".to_vec(), status(Some(3), None, false)));
    let detail = refusal(process.signal(libc::SIGTERM).await.unwrap_err(), ErrorKind::Conflict);
    assert!(detail.message.contains("exited"), "{detail}");
    refusal(process.kill().await.unwrap_err(), ErrorKind::Conflict);
}

// A timeout kills the process group and says so; a process that finishes in
// time is not marked as timed out.
#[tokio::test]
async fn timeout_kills_and_is_reported() {
    let h = harness(false, "test-build").await;
    let started = Instant::now();
    let slow = Exec { timeout_ms: Some(300), ..shell("sleep 1000 & sleep 1000") };
    let (_, _, exit) = output(h.client.exec(slow).await.unwrap()).await;
    assert_eq!(exit, status(None, Some(libc::SIGKILL), true));
    assert!(started.elapsed() >= Duration::from_millis(300));
    let quick = Exec { timeout_ms: Some(10_000), ..shell("exit 4") };
    assert_eq!(output(h.client.exec(quick).await.unwrap()).await.2, status(Some(4), None, false));
}

// Each attach takes over: the previous reader ends with UnexpectedEof rather
// than competing for bytes, and the new one continues from its offsets. An
// offset beyond what the process produced is refused.
#[tokio::test]
async fn attach_takes_over_and_refuses_future_offsets() {
    let h = harness(false, "test-build").await;
    let gate = h.dir.path().join("gate");
    let process = h.client.spawn(gated(&gate, "printf first", "printf second")).await.unwrap();
    let mut old = process.output().await.unwrap();
    assert_eq!(read_at_least(&mut old, 5, 0).await.0, b"first");
    let (out, err) = old.offsets();
    let new = process.attach(out, err).await.unwrap();
    let ended = tokio::time::timeout(WAIT, old.next()).await.unwrap().unwrap_err();
    assert_eq!(ended.kind(), io::ErrorKind::UnexpectedEof, "{ended}");
    std::fs::write(&gate, []).unwrap();
    assert_eq!(output(new).await.0, b"second");
    let detail = refusal(process.attach(12, 0).await.err().unwrap(), ErrorKind::InvalidInput);
    assert!(detail.message.contains("beyond"), "{detail}");
    refusal(process.attach(0, 1).await.err().unwrap(), ErrorKind::InvalidInput);
}

// However often a reader disconnects, and wherever, every byte it receives
// sits at the offset it claims, nothing repeats and nothing held is lost: the
// sessions together reassemble both streams exactly.
#[hegel::test]
fn reattaching_anywhere_loses_and_repeats_nothing(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let chunks: Vec<(bool, usize)> =
        tc.draw(gs::vecs(gs::tuples!(gs::booleans(), gs::integers::<usize>().min_value(1).max_value(40_000))).min_size(1).max_size(8));
    let sessions: Vec<usize> = tc.draw(gs::vecs(gs::integers::<usize>().min_value(0).max_value(3)).max_size(12));
    runtime().block_on(async {
        let h = harness(false, "test-build").await;
        let mut expected = [vec![], vec![]];
        let mut script = String::new();
        for (index, (stderr, size)) in chunks.iter().enumerate() {
            let bytes: Vec<u8> = (0..*size).map(|i| (i * 7 + index * 31) as u8).collect();
            let path = h.dir.path().join(format!("chunk{index}"));
            std::fs::write(&path, &bytes).unwrap();
            expected[*stderr as usize].extend(bytes);
            script += &format!("cat '{}'{};", path.display(), if *stderr { " >&2" } else { "" });
        }
        let process = h.client.spawn(shell(&script)).await.unwrap();
        exited(&process).await;
        let mut received = [vec![], vec![]];
        let mut accept = |reader: &ExecOutput, event: ExecEvent| {
            let (stream, bytes) = match event {
                ExecEvent::Stdout(bytes) => (0, bytes),
                ExecEvent::Stderr(bytes) => (1, bytes),
                ExecEvent::Exit(_) => return true,
            };
            let end = [reader.offsets().0, reader.offsets().1][stream] as usize;
            assert_eq!(end - bytes.len(), received[stream].len(), "a gap or a repeat on stream {stream}");
            assert_eq!(&bytes[..], &expected[stream][end - bytes.len()..end]);
            received[stream].extend_from_slice(&bytes);
            false
        };
        let mut offsets = (0, 0);
        for events in sessions {
            let mut reader = process.attach(offsets.0, offsets.1).await.unwrap();
            for _ in 0..events {
                let event = next(&mut reader).await;
                if accept(&reader, event) {
                    break;
                }
            }
            offsets = reader.offsets();
        }
        let mut reader = process.attach(offsets.0, offsets.1).await.unwrap();
        loop {
            let event = next(&mut reader).await;
            if accept(&reader, event) {
                break;
            }
        }
        assert!(received == expected, "received {} and {} bytes", received[0].len(), received[1].len());
    });
}

// Nobody reading means the agent holds at most its buffer: with both streams
// producing without end and no reader, or a reader that left, the held bytes
// stay within the limit and the process stays blocked on its pipes instead of
// running ahead. A later reader drains the rest and the exit; any bytes lost
// in flight to the reader that left show as a jump in the offsets, and from
// there each stream is contiguous.
#[tokio::test]
async fn disconnected_output_is_bounded() {
    const LIMIT: usize = 64 * 1024;
    const SIZE: u64 = 4 * 1024 * 1024;
    let h = bounded(LIMIT).await;
    let process = h.client.spawn(shell(&format!("head -c {SIZE} /dev/zero >&2 & head -c {SIZE} /dev/zero; wait"))).await.unwrap();
    let held_back = async || {
        for _ in 0..50 {
            let info = process.info().await.unwrap();
            assert!(info.buffered as usize <= LIMIT, "{} bytes held beyond the {LIMIT} byte limit", info.buffered);
            assert_eq!(info.state, ProcessState::Running, "the process ran ahead of its reader");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    eventually("the buffer to fill", async || (process.info().await.unwrap().buffered as usize == LIMIT).then_some(())).await;
    held_back().await;
    let mut reader = process.output().await.unwrap();
    next(&mut reader).await;
    let (out, err) = reader.offsets();
    drop(reader);
    held_back().await;
    let mut reader = process.attach(out, err).await.unwrap();
    let mut end: [Option<u64>; 2] = [None, None];
    let exit = loop {
        let (stream, bytes) = match next(&mut reader).await {
            ExecEvent::Stdout(bytes) => (0, bytes),
            ExecEvent::Stderr(bytes) => (1, bytes),
            ExecEvent::Exit(status) => break status,
        };
        let now = [reader.offsets().0, reader.offsets().1][stream];
        let start = now - bytes.len() as u64;
        match end[stream] {
            Some(previous) => assert_eq!(start, previous, "stream {stream} skipped within one reader"),
            None => assert!(start >= [out, err][stream], "stream {stream} repeated bytes"),
        }
        end[stream] = Some(now);
    };
    assert_eq!(exit, status(Some(0), None, false));
    assert_eq!((end, reader.offsets()), ([Some(SIZE), Some(SIZE)], (SIZE, SIZE)));
}

// A detached process whose output fits in the buffer runs to completion with
// nobody reading, and the agent still reaps it, so no zombie is left. Its
// output waits for a reader that attaches afterwards.
#[tokio::test]
async fn detached_process_finishes_and_is_reaped() {
    let h = harness(false, "test-build").await;
    let done = h.dir.path().join("done");
    let process = h.client.spawn(shell(&format!("head -c 131072 /dev/zero; printf complete > '{}'", done.display()))).await.unwrap();
    let pid = process.pid().to_string();
    eventually("the detached process to finish and be reaped", async || {
        (std::fs::read(&done).ok().as_deref() == Some(b"complete") && !Path::new(&format!("/proc/{pid}")).exists()).then_some(())
    })
    .await;
    assert_eq!(exited(&process).await, status(Some(0), None, false));
    assert_eq!(process.info().await.unwrap().buffered, 131072);
    let (stdout, _, _) = output(process.output().await.unwrap()).await;
    assert!(stdout.len() == 131072 && stdout.iter().all(|b| *b == 0));
}

// The environment layers: the configured environment, then fixed defaults
// that keep tools non-interactive, then the request's own variables. Stdin is
// null and there is no terminal.
#[tokio::test]
async fn environment_layers_and_no_terminal() {
    let h = harness(false, "test-build").await;
    let environment = [("TOKEN", "configured"), ("OVERRIDE", "configured"), ("PAGER", "less")];
    let config = Configuration { environment: environment.map(|(k, v)| (k.into(), v.into())).into(), ..Configuration::default() };
    h.client.configure(config).await.unwrap();
    let mut request = shell(
        "test ! -t 0 && test ! -t 1 && test ! -t 2 || exit 9; if read line; then exit 8; fi; \
         printf '%s|%s|%s|%s|%s|%s' \"$TOKEN\" \"$OVERRIDE\" \"$PAGER\" \"$CI\" \"$TERM\" \"$OWN\"",
    );
    request.environment = [("OVERRIDE", "request"), ("TERM", "xterm"), ("OWN", "x y")].map(|(k, v)| (k.into(), v.into())).into();
    let (stdout, stderr, exit) = output(h.client.exec(request).await.unwrap()).await;
    assert_eq!(
        (String::from_utf8(stdout).unwrap(), stderr, exit),
        ("configured|request|cat|1|xterm|x y".into(), vec![], status(Some(0), None, false))
    );
    let (stdout, _, _) = output(h.client.exec(shell("printf '%s|%s|%s' \"$CI\" \"$PAGER\" \"$TERM\"")).await.unwrap()).await;
    assert_eq!(stdout, b"1|cat|dumb");
}

// Spawn refusals say which input was wrong: a missing program or working
// directory is NotFound, a working directory that is a file NotADirectory,
// and an environment the kernel could not carry InvalidInput. None of them
// leaves a handle.
#[tokio::test]
async fn spawn_refusals() {
    let h = harness(false, "test-build").await;
    let missing = h.dir.path().join("absent");
    let detail = refusal(h.client.spawn(Exec::new("/no/such/program", ["x"])).await.err().unwrap(), ErrorKind::NotFound);
    assert_eq!((detail.operation.as_str(), detail.subject.as_str()), ("process.spawn", "/no/such/program"));
    let cwd = |path: &Path| Exec { cwd: Some(path.into()), ..Exec::new("/bin/true", Vec::<String>::new()) };
    assert_eq!(refusal(h.client.spawn(cwd(&missing)).await.err().unwrap(), ErrorKind::NotFound).operation, "process.cwd");
    let file = h.dir.path().join("file");
    std::fs::write(&file, "x").unwrap();
    refusal(h.client.spawn(cwd(&file)).await.err().unwrap(), ErrorKind::NotADirectory);
    for (key, value) in [("", "x"), ("A=B", "x"), ("A\0", "x"), ("A", "x\0")] {
        let request = Exec { environment: [(key.into(), value.into())].into(), ..Exec::new("/bin/true", Vec::<String>::new()) };
        let detail = refusal(h.client.spawn(request).await.err().unwrap(), ErrorKind::InvalidInput);
        assert!(detail.message.contains("environment"), "{detail}");
    }
    assert_eq!(h.client.processes().await.unwrap(), vec![]);
}

// Stdin refusals: a process started without a pipe has no stdin to write,
// and a pipe is written once, then closed. A signal number outside the
// kernel's range is invalid input.
#[tokio::test]
async fn stdin_and_signal_refusals() {
    let h = harness(false, "test-build").await;
    let without = h.client.spawn(Exec::new("sleep", ["1000"])).await.unwrap();
    let detail = refusal(without.write_stdin_bytes("x").await.unwrap_err(), ErrorKind::Conflict);
    assert!(detail.message.contains("without a stdin pipe"), "{detail}");
    for signal in [0, -1, 65, 1000] {
        refusal(without.signal(signal).await.unwrap_err(), ErrorKind::InvalidInput);
    }
    assert_eq!(without.info().await.unwrap().state, ProcessState::Running);

    let with = h.client.spawn(Exec { stdin: true, ..Exec::new("cat", Vec::<String>::new()) }).await.unwrap();
    with.write_stdin_bytes("once").await.unwrap();
    let detail = refusal(with.write_stdin_bytes("twice").await.unwrap_err(), ErrorKind::Conflict);
    assert!(detail.message.contains("already"), "{detail}");
    assert_eq!(output(with.output().await.unwrap()).await, (b"once".to_vec(), vec![], status(Some(0), None, false)));
    without.remove().await.unwrap();
}

// The agent lists its processes in spawn order with their state. Removing a
// running process kills its group and forgets it; removing an exited one just
// forgets it.
#[tokio::test]
async fn processes_are_listed_and_removed() {
    let h = harness(false, "test-build").await;
    let running = h.client.spawn(Exec::new("sleep", ["1000"])).await.unwrap();
    let finished = h.client.spawn(shell("exit 2")).await.unwrap();
    exited(&finished).await;
    let listed = h.client.processes().await.unwrap();
    let summary: Vec<_> = listed.iter().map(|p| (p.id.as_str(), p.pid, p.program.as_str(), p.state.clone())).collect();
    assert_eq!(
        summary,
        vec![
            (running.id(), running.pid(), "sleep", ProcessState::Running),
            (finished.id(), finished.pid(), "/bin/sh", ProcessState::Exited(status(Some(2), None, false))),
        ]
    );
    let (id, pid) = (running.id().to_owned(), running.pid().to_string());
    running.remove().await.unwrap();
    refusal(h.client.process(&id).await.err().unwrap(), ErrorKind::NotFound);
    eventually("the removed process to be killed and reaped", async || (!Path::new(&format!("/proc/{pid}")).exists()).then_some(())).await;
    finished.remove().await.unwrap();
    assert_eq!(h.client.processes().await.unwrap(), vec![]);
}

// Running a process to completion leaves no handle behind, so an agent whose
// callers only collect whole outputs holds no output for them afterwards. A
// collection over its limit is refused and the still-running process is killed.
#[tokio::test]
async fn run_collects_and_forgets_the_handle() {
    let h = harness(false, "test-build").await;
    let (stdout, stderr, status) = h.client.run(shell("printf out; printf err >&2; exit 4"), 1024).await.unwrap();
    assert_eq!((stdout.as_slice(), stderr.as_slice(), status.code), (&b"out"[..], &b"err"[..], Some(4)));
    assert!(h.client.processes().await.unwrap().is_empty());
    let error = h.client.run(shell("head -c 100000 /dev/zero; sleep 30"), 1024).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::FileTooLarge, "{error}");
    assert!(h.client.processes().await.unwrap().is_empty());
}

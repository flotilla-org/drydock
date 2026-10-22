# drydock-agent

Drydock's vessel binary and Rust host client, without a dependency on flotilla.
Implements ADR 0070's control API, forwards, and agent versioning. Egress capture
is separate (#52); configuration accepts its table and CA without installing
redirects or enforcing policy.

## Runtime and trust

A provider starts `drydock-agent [--socket /run/drydock/agent.sock]
[--vsock-port PORT]` alongside the image's own processes. It must not be PID 1.
The agent creates its dedicated run directory with mode 0700 and protects its
Unix sockets with mode 0600, correcting existing owned directory permissions.
Symlink, foreign-owned and sticky run directories are refused. The provider
protects vsock access where used. There is no token or per-vessel startup configuration.
The Unix listener accepts native connections or a host-initiated yamux session;
the latter also carries reverse streams without a second guest socket. vsock is
Linux-only. Both listeners share one control state. Native Unix reverse connections use
the fixed host socket `/run/drydock/host.sock` (`HOST_SOCKET` in the binary);
host-initiated yamux requires no reverse socket. Live provider isolation and
startup/supervision are verified in the provider integration work (#54).

The host normally calls `Client::connect_current(open_transport, executable,
timeout)`. The tools image pin is a bootstrap reference and may contain an older
agent. This handshake hashes the host's desired executable, reads hello, and
pushes the binary plus re-execs when fingerprints differ. It reconnects through
the supplied provider transport factory and returns only after verifying the
current fingerprint. A matching hello avoids an unnecessary upgrade. Supply the
binary for the vessel's architecture; push configuration after this handshake.

Low-level `Client::connect(transport, expected_fingerprint)` remains available
for explicit hello/upgrade tooling. Until fingerprints match, its client refuses
every operation except hello and upgrade: generation-specific routes have no
cross-generation compatibility promise. A mismatch is an upgrade trigger for the
normal handshake, not a reason to refuse an older tools pin.

## Control contract

The host-facing `Purpose::Control` stream carries HTTP/2 through
`drydock_transport::http2`. These routes are private to that link:

| Method | Route | Body / result |
| --- | --- | --- |
| GET | `/hello` | `Hello { fingerprint, features }` |
| PUT / GET | `/configure` | Replace / read `Configuration` |
| POST | `/exec` | `Exec { program, args, cwd }`; NDJSON `ExecEvent` stream |
| POST | `/files/write` | `{ path, bytes, executable }`; atomic sibling write, fsync, rename, parent fsync |
| POST | `/files/read` | `{ path }`; raw bytes |
| POST | `/files/flush` | `{ path }`; fsync file or directory |
| PUT / DELETE | `/forwards/guest` | `GuestForward` / JSON ID |
| PUT / DELETE | `/forwards/host` | `{ id, endpoint }` / JSON ID |
| PUT | `/upgrade` | Raw executable bytes; stage beside the installed binary |
| POST | `/upgrade` | Activate staged binary and re-exec with the original flags |

I/O failures return JSON `AgentError { operation, subject, kind, message }`,
with missing paths (404), permissions (403), conflicts (409), malformed input
(400) and internal errors (500). The client preserves the error kind and retains
the structured body as its `io::Error` source.

JSON byte fields are deliberately arrays of integers for this push-focused API;
exec events use the same representation, with roughly 2–4 encoded bytes per
output byte. Streaming general file transfer remains part of #50. Requests and read-back are limited to
128 MiB (oversized reads return 413 before buffering). For JSON writes this is
the encoded body limit: three-digit byte arrays fit slightly less than 32 MiB
of file data, and single-digit arrays fit slightly less than 64 MiB, after path
and JSON metadata. The near-limit test covers accepted 31 MiB and rejected
32 MiB worst-case binary writes. Upgrade uploads and read-back use raw bytes;
large general file operations, archives, directory traversal and diffs belong
to #50. Empty writes and arbitrary binary read-back are supported. File writes
replace the entire file atomically; new non-executable files use mode 644,
replacements preserve the existing mode and preserve ownership when permitted.
The optional executable flag sets mode 755. An unprivileged agent tolerates ownership EPERM when directory
permissions allow replacement; root and other I/O failures remain strict.
A destination symlink is replaced rather than followed.
`flush` can also sync a parent directory. File routes require absolute paths within the vessel.

Configuration replaces egress, CA, enabled features, process environment and
guest forwards together. Invalid configuration leaves the previous state intact;
unchanged listeners and their streams survive replacement. The first Control
connection binds the reverse opener; later Control connections cannot replace
it. The transport may reconnect its own native carrier. Every configured guest
forward must have a host endpoint registered in that client. TCP-only changes reuse the Unix binding. Transient accept errors
back off; finished listener tasks are rebuilt on the next configuration push.
An address held by a different forward ID is not transferred in one push.
Port swaps/transfers require removing the old owners first, then adding the new
configuration; a refused swap preserves the previous configuration and listeners.
Refused preparations await cleanup of newly created listeners before returning,
so retrying immediately cannot race deferred socket removal.
In this slice the feature list and egress/CA values are stored configuration for consumers, not
switches that claim to activate capture. The host pushes CA files via the files
API and names their paths through the process environment.

Exec uses null stdin, no tty, a detached session, and fixed pipeline defaults
(`CI=1`, `TERM=dumb`, pagers set to `cat`, no Git terminal prompt). Every process
inherits the pushed environment, including proxy, CA variables and placeholder
tokens. Output is streamed incrementally and ordered independently per stdout
and stderr; `Exit` follows their drained output, with `None` for a signal exit.
EOF without a complete `Exit` is an `UnexpectedEof` error in the host client.
Output spools into unlinked temporary files so agent exit/re-exec cannot deliver
SIGPIPE to the child. Idle polling backs off, reuses a buffer, and stops tailing
when the client disconnects (the child is still reaped). The provider may set
the agent’s standard `TMPDIR` to place spools on disk instead of tmpfs. Disk use
grows with a command's output until it exits, including after disconnection.
This unbounded spool is an accepted tradeoff in this slice; callers must manage
long-running service logs. Dropping a stream does not kill
the process. On Linux, startup reaps children inherited across re-exec after they
exit. Discovery is best effort when procfs child lists are unavailable; exited
but unreaped children remain in those lists and are included in the startup scan.
The provider's init reaps children orphaned by an agent crash.

Upgrade uses only `/hello` and `/upgrade`: stage with PUT, activate with POST,
reconnect with a fresh provider transport, then verify the new fingerprint.
A failed activation retains its staged image and existing rollback until a new
backup is ready. `stage_upgrade` and `activate_upgrade` allow activation retries
without uploading again. The activation acknowledgement is advisory: a lost
response requires reconnecting and checking hello. A short acknowledgement grace period precedes shutdown;
the binary path remains stable across repeated upgrades. The previous executable
is retained as `.prev`. A durable `.probation` marker records the candidate
image, which runs from `.upgrade` while the installed entry point remains
runnable. The candidate promotes itself to that entry point on its first hello,
then clears the marker. If exec fails immediately, rollback happens in-process.
If the candidate dies before hello (including a loader failure after successful
exec), the next ordinary provider start restores `.prev` and clears probation.
Crashes after hello belong to provider supervision (#54).
Re-exec drops control and forward streams, removes owned guest sockets, and resets configuration.
Stale socket inodes from a crash are reclaimed only when they refuse a connection;
live listeners and ordinary files are preserved.
The host pushes it again after hello. Children continue running with their
original environment. Embedders update their own files using `/files/write`
without agent re-exec.

## Byte forwards and endpoint ownership

`Purpose::Forward { id }` begins with an opening result: a big-endian u32
JSON length and `Result<(), AgentError>`. The client waits for success before
returning the stream; unknown IDs and dead targets retain their kind and reason.
After that acknowledgement it carries raw bytes. The agent performs no HTTP parsing,
header rewriting, token checking, terminal handling or destination policy.
Cleat attach is an ordinary host-to-guest forward to a Unix socket.

Guest forwards grant vessel-level reach, not per-UID authorization. Unix sockets
use mode 0600 within an agent-owned 0700 directory; the optional
loopback TCP listener is reachable by every guest UID. Providers that need guest
UID separation must omit loopback TCP.
Host endpoints apply their own policy (for example per-terminal hook tokens);
the agent inspects no forwarded bytes and holds no token.

* Guest to host: `add_guest_forward` reserves a host endpoint in this client's
  registry, then creates a guest Unix listener and optional loopback TCP listener.
  `register_host_endpoint` reserves endpoints for forwards installed through a
  configuration push. The guest receives only IDs; it never receives a host
  target. An arriving ID resolves only in the client for that vessel.
* Host to guest: `add_host_forward` configures a guest Unix/TCP target;
  `forward(id)` opens a raw stream. TCP port zero is rejected. Unix endpoints
  connect lazily, allowing the host to register services before their sockets exist. `remove_*_forward` removes a route at runtime.
  Removal closes the route’s live streams in both directions and guest listeners;
  unknown IDs return NotFound. Unrelated forwards continue.
* Host Unix endpoints are claimed by stable path and device/inode, including symlink/hardlink
  aliases. Host TCP endpoints require dedicated loopback ports; claims reserve
  the port across loopback addresses, preventing wildcard-listener aliasing.
  Claims are shared across clients in one controller process and retained by
  active streams. Different controller processes must allocate separate host
  endpoints. Shared endpoints and direct multi-controller connections are not
  part of the current contract.
* Native forwards are arranged by the provider/controller, outside this agent's
  data path. The same rule applies there: one host endpoint serves one vessel.

## Verification

`cargo test -p drydock-agent` covers the control contract over in-memory yamux
and Unix connections, generated configuration/refusal sequences, atomic file
visibility, streamed exec, byte-transparent HTTP/1.1, WebSocket upgrade frames,
chunked bodies, dynamic forward changes, TCP and Unix endpoints, and isolation.
A subprocess test pushes a distinct ELF and verifies real re-exec, the new hello,
forward socket cleanup, fingerprint gating and survival/reaping of a child.
No cloud provider or cleat installation is required.

The first host-facing Control link supplies the reverse opener for the agent
lifetime. Later connections cannot retarget it.
Forward and transport failures emit `tracing` warnings, without logging process
environment or request bodies. Embedders supply their subscriber. The standalone
binary logs warnings to stderr by default and honors standard `RUST_LOG`.

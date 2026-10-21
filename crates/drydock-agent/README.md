# drydock-agent

Drydock's vessel binary and Rust host client, without a dependency on flotilla.
Implements ADR 0070's control API, forwards, and agent versioning. Egress capture
is separate (#52); configuration accepts its table and CA without installing
redirects or enforcing policy.

## Runtime and trust

A provider starts `drydock-agent [--socket /run/drydock/agent.sock]
[--vsock-port PORT]` alongside the image's own processes. It must not be PID 1.
The provider supplies a protected, host-facing socket directory, and protects
vsock access where used. There is no token or per-vessel startup configuration.
The Unix listener accepts native connections or a host-initiated yamux session;
the latter also carries reverse streams without a second guest socket. vsock is
Linux-only. Both listeners share one control state. Live provider isolation and
startup/supervision are verified in the provider integration work (#54).

The host constructs `Client::connect(transport, expected_fingerprint)`. The
client fetches `/hello` before returning: its build fingerprint and features
constitute readiness. The expected fingerprint is the SHA-256 of the delivered
agent executable, independent of the embedder's version. Until fingerprints
match, the client refuses every operation except hello and upgrade. Routes
other than those two have no cross-generation compatibility promise.

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

JSON byte fields are arrays of integers. Requests are limited to 128 MiB;
large general file operations, archives, directory traversal and diffs belong
to #50. Empty writes and arbitrary binary read-back are supported. File writes
replace the entire file atomically; the optional executable flag sets mode 755.
`flush` can also sync a parent directory. Routes use paths directly within the
vessel, which is already controlled by the trusted caller.

Configuration replaces egress, CA, enabled features, process environment and
guest forwards together. Invalid configuration leaves the previous state intact;
unchanged listeners and their streams survive replacement. In this slice the
feature list and egress/CA values are stored configuration for consumers, not
switches that claim to activate capture. The host pushes CA files via the files
API and names their paths through the process environment.

Exec uses null stdin, no tty, a detached session, and fixed pipeline defaults
(`CI=1`, `TERM=dumb`, pagers set to `cat`, no Git terminal prompt). Every process
inherits the pushed environment, including proxy, CA variables and placeholder
tokens. Output is streamed incrementally and ordered independently per stdout
and stderr; `Exit` follows their drained output, with `None` for a signal exit.
Output spools into unlinked temporary files so agent exit/re-exec cannot deliver
SIGPIPE to the child. Disk use grows with a command's output until it exits;
callers should manage long-running service logs. Dropping a stream does not kill
the process. On Linux, startup reaps children inherited across re-exec after they
exit. The provider's init reaps children orphaned by an agent crash.

Upgrade uses only `/hello` and `/upgrade`: stage with PUT, activate with POST,
reconnect with a fresh provider transport, then verify the new fingerprint. The
activation acknowledgement is advisory: a lost response requires reconnecting
and checking hello. A short acknowledgement grace period precedes shutdown;
the binary path remains stable across repeated upgrades. Re-exec drops control
and forward streams, removes owned guest sockets, and resets configuration.
Stale socket inodes from a crash are reclaimed only when they refuse a connection; live listeners and ordinary files are preserved.
The host pushes it again after hello. Children continue running with their
original environment. Embedders update their own files using `/files/write`
without agent re-exec.

## Byte forwards and endpoint ownership

`Purpose::Forward { id }` carries raw bytes. The agent performs no HTTP parsing,
header rewriting, token checking, terminal handling or destination policy.
Legacy transport purpose tags remain decodable but the agent does not serve
them. Cleat attach is an ordinary host-to-guest forward to a Unix socket.

* Guest to host: `add_guest_forward` reserves a host endpoint in this client's
  registry, then creates a guest Unix listener and optional loopback TCP listener.
  `register_host_endpoint` reserves endpoints for forwards installed through a
  configuration push. The guest receives only IDs; it never receives a host
  target. An arriving ID resolves only in the client for that vessel.
* Host to guest: `add_host_forward` configures a guest Unix/TCP target;
  `forward(id)` opens a raw stream. `remove_*_forward` removes a route at runtime.
  Removal closes guest listeners and their streams; unrelated forwards continue.
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

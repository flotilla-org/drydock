# drydock-agent

Drydock's vessel binary and Rust host client, without a dependency on flotilla.
Implements ADR 0070's control API, forwards, agent versioning, and guest egress
capture. The agent forwards traffic; the kind and upstream enforce policy.

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
The feature list remains descriptive configuration. `egress: null` disables
capture; `egress: {"upstream": "proxy-forward-id"}` activates it. The client must
first register that forward ID against this vessel's dedicated host endpoint.
The agent opens the forward directly; it needs no additional `GuestForward` for
the upstream. Capture configuration and guest TCP forward changes use a full
configuration push. Dynamic Unix-only forward changes remain available.

## Egress and guest requirements

The agent binds dual-stack TCP capture on port 15001, fake DNS over UDP/TCP on
1053, and an explicit HTTP proxy listener on `127.0.0.1:15002`. These ports are
reserved while capture is enabled. Set `HTTPS_PROXY=http://127.0.0.1:15002` in
`Configuration.environment`; explicit proxy bytes pass through unchanged.
Other TCP connections recover the conntrack original destination and become
ordinary `CONNECT hostname:port` requests on the registered upstream forward.
The agent waits for a successful CONNECT response before relaying application
bytes. Numeric destinations stay numeric. It carries no other UDP or ICMP.

The fake DNS allocator uses 198.18.0.0/15 and advertises a 30-second TTL.
Mappings live for 60 seconds after the last lookup, adding a setup grace period
for connections that start near DNS TTL expiry. Names are normalized and renewed
on repeated queries; an ordered expiry index reuses expired addresses without
scanning the pool under the shared DNS mutex. Allocation, renewal and exhaustion
use the O(log pool size) ordered index. The index holds one
entry per mapping, including after repeated renewals.

Unknown/expired fake destinations fail. A client caching an answer beyond the
lease must resolve again before reconnecting; connection pools, pinned
`/etc/hosts` entries and resolvers ignoring TTLs can otherwise fail. An address
can be reassigned after its lease expires, so callers must not pin fake addresses.
A/AAAA queries never yield real DNS answers: A gets a fake IPv4 address, AAAA and
other types get NODATA. DNS-over-TCP is also captured. Existing TCP sessions
survive lease expiry.

On an enabled configuration, the controller-supplied `ca` is atomically written
as `/opt/drydock/ca.pem` (`CA_PATH`), readable by guest processes. Supply the
**complete combined PEM trust bundle**, including any public roots needed by
the vessel. Name this path in the CA environment variables appropriate to each
tool (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, etc.). The
agent never depends on these variables for capture. Without proxy/CA variables,
a process still reaches the upstream and fails TLS if it lacks the required CA.
Disabling capture leaves the bundle on disk so existing processes can read it.

The guest/provider must supply:

- Linux with nftables inet NAT/redirect, conntrack original-destination support
  for IPv4 and IPv6, IPv6 sockets, and loopback up.
- An nft executable with its runtime libraries at `/opt/drydock/bin/nft`. Any
  drydock-supplied binary/libraries belong under `/opt/drydock` in the tools
  layer; tools-image packaging is #53. The agent does not install packages.
- `CAP_NET_ADMIN` for the agent to install its vessel-local nft table and mark
  its own outbound TCP sockets. This is not a UID exemption: launched processes
  with the same UID are still redirected. Native host-facing transports use
  Unix/vsock; yamux multiplexes these existing streams. All TCP sockets dialed by
  agent host-to-guest forwards use `SO_MARK` while capture is enabled. The shipped
  binary has no TCP host-link connector. A future agent-side TCP carrier must
  apply the same marking before connect to avoid capture recursion.
- A writable `/opt/drydock` for the pushed trust bundle, and a resolver entry in
  `/etc/resolv.conf`. UDP/TCP port 53 goes to fake DNS regardless of the named
  resolver. DNS libraries must have a nameserver to contact in the first place.
- Routes sufficient for an initial TCP SYN/DNS packet to reach the output hook,
  even under `--network none`. The provider owns any dummy default route (the
  Firecracker route is separate work); the agent does not configure interfaces.
- Provider-side isolation/enforcement. The nft table only captures; guest root
  with network-administration privileges can alter it. The kind still prevents
  external bypasses, as required by ADR 0044 P4a.

The agent only replaces its `inet drydock_egress` table, in one nft transaction.
Agent-marked sockets, the local explicit proxy, and configured loopback forward
listeners are exempt to avoid recursion. Forward TCP bind addresses must be
concrete loopback addresses; unspecified (`0.0.0.0`/`::`) and non-loopback binds
are rejected before their configuration is published. All other TCP is captured, including
loopback, RFC1918 destinations and guest-local services such as PostgreSQL.
A local service needing direct access must be arranged as a configured loopback
forward; there is no blanket loopback/private-network exemption. Direct access
to capture/DNS service ports is also captured; use port 53 for fake DNS.
Other guest TCP is captured regardless of environment. Refused configuration cleans up prepared listeners; unchanged
egress listeners, DNS leases and active streams survive configuration pushes.
Disabling capture removes redirects before stopping listeners. An agent crash
leaves redirects installed (connections fail until configuration is restored).
Agent re-exec loses DNS leases; callers must resolve names again.

Capture, explicit-proxy and DNS-TCP connections share a 128-stream budget.
Overflow connections are accepted and immediately closed, preserving descriptor
headroom for the control path. Saturation increments a shared rejection counter
and warns on the first rejection and powers of two, avoiding a log per rejected
connection. Closing a connection releases its slot. Opening an upstream forward,
including its acknowledgment, has a 30-second deadline. Established tunnels have
no idle/lifetime timeout so long-lived SSH/WebSocket/service streams can remain
open; the bounded budget still applies. DNS query frames are capped at 4 KiB
before allocating their payload, matching the UDP receive buffer. DNS TCP
uses a 30-second per-query timeout, renewed after each completed exchange, rather
than a total connection deadline. CONNECT upstreams must send a final 2xx reply
directly; interim 1xx replies are rejected. Fake DNS names must consist of ASCII
letters/digits, hyphens, underscores and dots (including punycode names); URL
delimiters and DNS label escapes cannot become CONNECT authorities.

`cargo test -p drydock-agent` covers DNS allocation/expiry and wire replies,
real UDP/TCP DNS listeners, CONNECT forwarding through a vessel-scoped transport,
explicit proxy transparency, refused/truncated CONNECT responses and half-closes.
`tools/test-agent-egress.sh` additionally exercises nftables and SO_ORIGINAL_DST,
a launched process without proxy variables, the same-UID capture invariant, CA
installation and the agent socket exemption. It requires `sudo`, `nft`, `ip`,
Python 3 and mount/network namespace support, and changes only disposable
namespaces. The live Docker `--network none` operator check remains #3487.

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

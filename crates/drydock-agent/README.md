# drydock-agent

Drydock's vessel binary and Rust host client, without a dependency on flotilla.
Implements ADR 0070's control API, forwards, agent versioning, and guest egress
capture. The agent forwards traffic; the kind and upstream enforce policy.

## Runtime and trust

A provider starts `drydock-agent [--socket /run/drydock/agent.sock]
[--vsock-port PORT] [--store DIR]` alongside the image's own processes. It must not be PID 1.
Daytona starts the same binary with `--supervise --socket /run/drydock/agent.sock`.
This detaches a singleton supervisor alongside the provider's init; the supervisor
holds an OS file lock and restarts the agent after a crash, without guest Python
or util-linux. Repeated startup failures back off from 250 ms to four seconds;
a run of at least 30 seconds resets the delay. Providers must invoke bootstrap
again after stop/start or resume, since the supervisor dies with the sandbox.
If the supervisor itself is killed (including by OOM), agent crash recovery is
unavailable until the next bootstrap; the provider's init does not restart it.
The agent creates its dedicated run directory with mode 0700 and protects its
Unix sockets with mode 0600, correcting existing owned directory permissions.
Symlink, foreign-owned and sticky run directories are refused. The provider
protects vsock access where used. There is no token or per-vessel startup configuration.
Every connection to the socket (and to vsock, Linux-only) is plain HTTP/1.1 or
HTTP/2 without TLS, from its first byte, so `curl --unix-socket
/run/drydock/agent.sock http://agent/hello` works as well as drydock's client.
All listeners share one state. The agent never opens a connection towards the
host: it tells drydockd what happens through `/events`, and drydockd claims
the vessel's outward connections from there. Agents from before plain HTTP
(the `DDT` framing) cannot be reached; such a vessel is reported unreachable
and its operator restarts it. Live provider isolation and startup/supervision
are verified in the provider integration work (#54).

The host normally calls `Client::connect_current(open, platform, executable,
timeout)`, where `open` returns a fresh connection to the agent's socket, passing the platform recorded in the vessel's prepared
form and the agent build for it. The tools image pin is a bootstrap reference
and may contain an older agent. This handshake reads hello, hashes the build,
and pushes the binary plus re-execs when fingerprints differ. It reconnects through the supplied
factory and returns only after verifying the current fingerprint. A matching
hello avoids an unnecessary upgrade. It confirms a candidate on probation once
its fingerprint matches. Push configuration after this handshake.

Hello's `platform` uses OCI names (`{"os": "linux", "architecture": "arm64"}`).
The agent reports the platform its running executable was built for, not the
kernel's `uname`: the guest is demonstrably running that build, so a replacement
for the same platform runs the same way, natively or under emulation. The hello
platform is only a check: when it differs from the prepared platform,
`connect_current` fails with `Unsupported` naming both and pushes nothing. A
hello with no `platform` comes from an agent older than platform reporting; the
check is skipped and the prepared platform's build is pushed. An empty build is
also `Unsupported`. These failures are final: retrying cannot help until the
vessel or the host's builds change.
The first connection/hello failure returns immediately: provider startup readiness
is the caller's responsibility. Only reconnects after an accepted upgrade are
retried until the deadline. A timeout includes the last observed fingerprint or
connection/hello error to distinguish rollback from reconnect failures.

Low-level `Client::connect(stream, expected_fingerprint)` remains available
for explicit hello/upgrade tooling. Until fingerprints match, its client refuses
every operation except hello and upgrade: generation-specific routes have no
cross-generation compatibility promise. A mismatch is an upgrade trigger for the
normal handshake, not a reason to refuse an older tools pin.

## Control contract

Every route is served on every connection, over HTTP/1.1 or HTTP/2, through
`drydock_transport::http`; the client keeps one HTTP/2 connection per vessel.
File paths in a route are absolute vessel paths, percent-encoded byte by byte,
so any Unix path can be named; relative paths and `.`/`..` components are
refused. Forward IDs are one percent-encoded route segment.

| Method | Route | Body / result |
| --- | --- | --- |
| GET | `/hello` | `Hello { fingerprint, features, platform, boot_id, probation }`; changes nothing |
| GET | `/events?since=<cursor>` | NDJSON `{ cursor, event }` lines from after `since`, held open for new ones |
| GET / PUT | `/configuration` | Read / replace `Configuration`, with an `ETag`; PUT honours `If-Match` |
| GET / PUT / DELETE | `/forwards/inward/{id}` | Read / upsert / remove one `InwardForward { id, endpoint }`; GET `/forwards/inward` lists them |
| CONNECT | `/forwards/inward/{id}/stream` | One byte stream to the forward's target; 200 once it is reached |
| GET / PUT / DELETE | `/forwards/outward/{id}` | Read / upsert / remove one `OutwardForward { id, unix, tcp }`; GET `/forwards/outward` lists them |
| CONNECT | `/forwards/outward/{id}/connections/{n}` | Claim connection `n`, announced on `/events`, as a byte stream |
| POST / GET | `/processes` | Start an `Exec` (201, `ProcessInfo`) / list processes |
| GET / DELETE | `/processes/{id}` | `ProcessInfo` / kill the group if running and forget the handle |
| GET | `/processes/{id}/output?stdout=N&stderr=M` | Become the reader; framed output from those offsets, then the exit |
| PUT | `/processes/{id}/stdin` | Stream the body to stdin, then close it |
| POST | `/processes/{id}/signals` | `{ "signal": N }` to the process group |
| GET / HEAD / PUT | `/files/{path}` | Stream a file (Range, `ETag`, `If-Match`) / its size / an atomic streamed write |
| GET / PATCH / DELETE | `/entries/{path}` | Stat without following links / change mode and owner / remove (`?recursive=true`) |
| GET / PUT | `/dirs/{path}` | List a directory / create one |
| PUT | `/links/{path}` | `{ "target": ... }`; create or atomically replace a symlink |
| PUT | `/trees/{path}?sha256=...` | Unpack a streamed tar (optionally gzip) into a new directory |
| POST | `/renames` | `Rename { from, to, exclusive, parents }` |
| HEAD / PATCH / DELETE | `/uploads/{sha256}` | Resumable upload: offset retrieval / append / cancellation |
| HEAD / PUT / DELETE | `/blobs/{sha256}` | A blob's size / upload creation / remove it |
| GET | `/artifacts` | Complete store entries, with the links that use them |
| GET / PUT / DELETE | `/artifacts/{sha256}` | One entry / fetch it by digest (`Fetch`) / remove it unless in use |
| PUT | `/artifacts/{sha256}/links/{path}` | `{ "member": ... }`; place a symlink to the entry atomically |
| POST | `/upgrade?sha256=...` | Activate the completed upload of that digest and re-exec with the original flags |
| POST | `/upgrade/confirm` | Confirm the running candidate |

### One error layer

Every refusal is a JSON `AgentError { operation, subject, kind, status,
message, causes }` with a fitting status: missing paths and IDs 404,
permissions 403, malformed input 400, well-formed input of the wrong shape or
a digest mismatch 422, duplicates and wrong-state calls 409, a failed
`If-Match` 412, an unsatisfiable range 416, a wrong content type 415, and a
deliberate size limit 413. `causes` keeps the chain behind the message, such
as the OS error. The framework's own refusals (unknown routes, wrong methods,
JSON bodies, queries and paths it cannot decode, oversized JSON) are the same
structured error; a last-resort layer converts anything else that is not,
and a handler that panics is answered with a structured 500. The client
rebuilds the `AgentError` as the source of its `io::Error`
(`AgentError::of(&error)`), keeping the I/O kind for kinds that have one. HEAD
replies have no body, so a HEAD refusal carries only its status.

### Files

File bytes travel as `application/octet-stream` bodies, streamed to and from
disk; neither side holds a file whole. There is no global body limit: JSON
control bodies are capped at 16 MiB, and nothing else is.

- `PUT /files/{path}` writes a sibling temporary, hashes it while writing,
  fsyncs, renames atomically and fsyncs the parent. Readers see the complete
  old file or the complete new one. The query takes `FileOptions`: `sha256`
  (refuse with 422 and leave nothing behind on a mismatch), `mode`, `uid`,
  `gid`, `parents` (create missing parents, mode 0755, the given owner) and
  `exclusive` (409 if the file exists). New files default to mode 0600, so a
  credential written through the agent is never world-readable. A replaced
  file keeps its mode, and its owner when permitted (an unprivileged agent
  tolerates EPERM there; root and other failures stay strict). A destination
  symlink is replaced, not followed. setuid and setgid bits are never set
  through the agent: they are cleared from requested and preserved modes
  alike. With `If-Match`, the write replaces only a file that still has one
  of the listed tags (412 otherwise, also for an absent file). The reply is
  `Written { sha256, size }` with the new `ETag`; 201 for a new file, 200
  for a replacement.
- `GET /files/{path}` streams the file with `Content-Length`, `ETag` and
  `Accept-Ranges`. A single `Range: bytes=` range returns 206 with
  `Content-Range`; multiple ranges and ranges past the end are 416, as is any
  range of an empty file (a plain GET returns it).
  A `Range` header that is not a byte range is ignored, as RFC 9110 asks.
  `If-Match` refuses (412) a file that changed since its tag was read, so a
  ranged resume never splices two versions; any listed tag may match, and an
  `If-Match` that is not a list of tags is refused (400). The tag is a strong validator of
  inode, size and modification time; writes replace the inode.
- Stat, list, remove, rename, symlink, mkdir and chmod/chown have their own
  routes, so callers need no shell commands for them. A mode or owner change
  acts on a descriptor opened without following a symlink, so it always
  concerns the entry that was checked; on Linux it is an `O_PATH` descriptor,
  so an owner can change an entry nobody can read. Rename replaces by
  default (`rename(2)`); `exclusive` refuses an existing target atomically.
- `PUT /trees/{path}` unpacks a tar stream (`compression=gzip` for tar.gz)
  into a staging directory beside the target, hashing every archive byte.
  Only if the digest matches, and once its bytes are durable, does the tree
  appear, by rename, or with
  `replace` by an atomic exchange with the existing directory. On a mismatch
  or a malformed archive the target is unchanged. Entries keep their modes,
  masked of setuid and setgid, but not their archived owners; `uid`/`gid` set
  the owner of every entry.

### Resumable uploads and the digest store

Uploads follow [draft-ietf-httpbis-resumable-upload-12][resumable]
(interop version 9). The blob resource is the upload's target and the
upload resource is named after the digest the finished bytes must have:

- **Creation:** `PUT /blobs/{sha256}` with `Upload-Complete`, and
  `Upload-Length` when known. With `?1` the body is the whole blob. With
  `?0` the reply is 201 with `Location: /uploads/{sha256}`, the offset
  reached and `Upload-Limit`. Without `Upload-Complete` it is a conventional,
  still digest-checked upload. A second creation for an existing upload is a
  409: resume it instead.
- **Offset retrieval:** `HEAD /uploads/{sha256}` returns 204 with
  `Upload-Offset`, `Upload-Complete`, `Upload-Length` once declared,
  `Upload-Limit` (`max-age`, the time left before an untouched upload is
  removed) and `Cache-Control: no-store`; 404 for an unknown upload.
- **Append:** `PATCH /uploads/{sha256}` with `Content-Type:
  application/partial-upload`, `Upload-Offset` and `Upload-Complete`
  continues from exactly that offset. Another offset is a 409 carrying the
  right `Upload-Offset`.
- **Cancellation:** `DELETE /uploads/{sha256}`.

Bytes received before a disconnect stay. A request that arrives while another
is still using the upload ends that one first (draft section 4.6), so the
offset a retrieval reports is the one the next append needs. When the client
completes the upload the agent checks the digest once: a match moves it to
`blobs/<sha256>`, and the reply is the blob's (201 with `Written`); a
mismatch discards it (422 with `Upload-Complete: ?1`). There are no per-piece
hashes. Completing short of the declared length is refused (400); a body that
runs past it discards the upload (413). A declared length beyond the store's
free space is refused up front (507), and partial uploads untouched for seven
days are removed at agent startup. Completed blobs are kept until
`DELETE /blobs/{sha256}`: they are content-addressed, so a later install of
the same digest needs no new upload. The agent sends no 104 interim
responses.

[resumable]: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-resumable-upload-12

`PUT /files/{path}?blob=<sha256>` and `PUT /trees/{path}?blob=<sha256>`
install from a completed blob.

The store lives beside the executable (`<executable>.store`) unless
`--store DIR` names another. Agents may share one store, as vessels on one
host do: each digest also has a lock file under `locks/`, so their uploads,
fetches and entries never interleave, and what one agent fetched is a
lookup for the next.

### Artifacts: fetch by digest

`PUT /artifacts/{sha256}` with a JSON `Fetch { sources, unpack }` makes the
artifact with that digest a store entry, fetching it if need be. Sources are
tried in the caller's order, which is its policy:

- `{"kind": "upstream", "url": ...}`: an `http` or `https` URL, such as a
  release download, following redirects, including from `https` to `http`.
  Integrity comes from the sha256, not from transport security; TLS only
  keeps the transfer private.
- `{"kind": "oci", "registry": ..., "repository": ..., "credential": ...}`:
  the blob `sha256:<digest>` through the OCI distribution API. `registry` is
  a host (HTTPS) or a base URL. A 401 challenge is answered once: a Bearer
  challenge with a token from its realm (anonymous, or with a `basic`
  credential), a Basic one with the `basic` credential. A `bearer`
  credential is sent as is. Credentials go only to HTTPS, never to a host a
  redirect names, and are never stored or logged. As Docker's client does,
  a `basic` credential goes to the token realm the registry's challenge
  names, which may be another HTTPS host (Docker Hub's realm is
  `auth.docker.io`).
- `{"kind": "push"}`: the caller pushes the bytes with the resumable upload
  protocol above. Reaching it without a completed upload is refused as
  `artifact.push` (404), naming how many bytes are staged; the caller
  uploads to `/blobs/{sha256}`, continuing from them, and asks again.
  `Client::fetch_artifact_or_push` does both.

Every source meets the same final check: the bytes stream into the upload
staging (`partial/<sha256>`), hashed as they arrive, and only bytes that
hash to the digest are kept; otherwise nothing is stored. Nothing is held
whole in memory. A body that breaks off or stalls for 60 seconds leaves its
bytes staged: the agent asks again with `Range: bytes=N-`, and restarts from
nothing when the source ignores it, up to five requests per source. Staged
bytes also survive a failed fetch, so the next fetch or push continues
them. A completed upload of the digest is used without asking any source.

`unpack` makes the entry `artifacts/<sha256>`: `{"kind": "file", "mode":
...}` the file itself (default 0555), or `{"kind": "tar"}` / `{"kind":
"tar.gz"}` a directory unpacked from the archive (OCI `tar+gzip` layers are
`tar.gz`). An archive entry whose path is absolute or has `..`, a symlink
resolving outside the tree (as the kernel resolves it, through the tree's
other symlinks), an entry under a symlink the archive made, a hard link to
outside it, a device file or a FIFO is refused (422) before the entry
appears; the verified bytes are then
kept, so asking again reads them instead of downloading. Entries are
read-only: every write, setuid and setgid bit is cleared. A file entry is
the verified blob itself; an archive's blob goes once it is unpacked.
`artifacts/` is readable and searchable by every user, and the store root
gains search permission for group and others (nothing more), so guest
processes can follow links into entries; the rest of the store stays
private. An archive is unpacked without a size limit of its own: it stops
at the filesystem's limit (507), so a pinned archive that expands beyond
the free space fails without an entry, and its partial unpack is removed.

Once an entry is complete, a record in `index/<sha256>` makes a repeat fetch
a lookup that reads and hashes nothing (200, `origin: "index"`); a stored
fetch is 201 with `origin` `blob` or `{"source": N}`. A fetch asking for an
entry already stored another way is a 409. Concurrent fetches of one digest
wait for each other rather than downloading twice. The fetch runs to the
end even if its caller goes away.

Fetches leave through the agent's configured egress like any other guest
traffic. With egress configured, every connection is a `CONNECT host:port`
on a fresh stream of the upstream forward, by name, and TLS is verified
against the configured `ca` bundle; without it, the agent connects directly
and trusts the system's roots (or bundled Mozilla roots when the guest has
none). A destination the upstream refuses fails at the `egress` step (403),
quoting the refusal and its `Proxy-Status` (RFC 9209) when given.

A failure names the digest and, for each source, its position, kind and
URL (without user information or query), the step that failed (`request`,
`egress`, `connect`, `tls`, `http`, `auth`, `download`, `verify`, `unpack`,
`disk`, `push`) and why. With several sources the message says all failed
and `causes` holds one line per source; the last failure gives the kind and
status. A full disk (507) or an unpack refusal stops the fetch, since no
other source can help.

`PUT /artifacts/{sha256}/links/{path}` with `{"member": "bin/codex"}` (empty
for the entry itself) and the link query of `/links` places a symlink to
the entry, or to a member inside it, by renaming a new link over the path,
so the path never goes missing. The link is recorded as a use of the entry.
`DELETE /artifacts/{sha256}` refuses an entry while any recorded link still
points into it (409, naming the links); links since removed or pointed
elsewhere no longer count. `GET /artifacts` lists complete entries with
their live links. Links made through plain `/links` are not recorded.

### Processes

A process is a handle. `POST /processes` starts it leading its own process
group, with no terminal; stdin is `/dev/null` unless `stdin: true` gives it a pipe for
`PUT /processes/{id}/stdin`, written once and then closed (a second write, or
a retry after the body broke off, is a 409). `timeout_ms` kills the process
group when it
expires. Every process inherits the configured environment, then fixed
pipeline defaults (`CI=1`, `TERM=dumb`, pagers set to `cat`, no Git terminal
prompt), then the request's own `environment`.

Output is read from pipes into a bounded buffer per process (1 MiB by
default). When it is full the agent stops reading, so the process blocks on
its pipe: a process whose client went away never spools output without
limit. `GET /processes/{id}/output` streams frames
(`application/vnd.drydock.process-frames`): a kind byte, a big-endian u32
length and the payload. Stdout and stderr frames carry raw bytes after a u64
offset into their stream; the exit frame carries JSON `ExitStatus { code,
signal, timed_out }` after all drained output. A later attach takes over from
an earlier reader, and the offsets in the query skip bytes the caller already
has. Sent bytes stay in the buffer for a reattach until new output needs the
room, so only bytes pushed out that way are lost, and the offsets show it.
After the process exits, its pipes are drained until EOF, waiting at most
250 ms without new bytes for a descendant still holding one. Signals go to the
process group; only named signals are sent, so a realtime signal number is
refused (400). A process is reaped only after its exit is recorded, so a
signal never reaches a reused PID. Exited handles are kept for their status until removed, at
most 256 of them; running handles are not capped, since the host that starts
them is trusted with the vessel. Where pidfds are unavailable (before Linux
5.3, or off Linux), each running process holds a blocking thread. EOF without an exit frame is `UnexpectedEof` in the client.
`Client::run` starts a process, collects its output and removes the handle,
so callers that only need whole outputs leave nothing held on the agent.

An agent restart or re-exec ends its process handles. A child that survives
it has lost its output reader: it can keep running and is reaped after it
exits, but writing to stdout or stderr then raises SIGPIPE. On Linux, startup
reaps children inherited across re-exec after they exit. Discovery is best
effort when procfs child lists are unavailable. The provider's init reaps
children orphaned by an agent crash.

### Configuration, forwards and restarts

`Configuration` replaces egress, CA, enabled features and process environment
together. Invalid configuration leaves the previous state intact. The reply's
`ETag` names the configuration's content and the agent's boot, so it changes
whenever either does. `Hello.boot_id` is fresh for each agent process: a host
that sees a new boot ID, or a configuration tag it did not set, knows the
agent restarted with empty configuration, no forwards and no processes, and
pushes its state again. `PUT` with `If-Match` replaces only the expected
configuration (412 otherwise); any tag in the list may match, and an
`If-Match` that is not `*` or a list of entity tags is refused (400).

Each forward is its own resource. Its ID is one route segment, percent-encoded
by the client, so an ID may contain `/`. `PUT` is an idempotent upsert: an unchanged
forward with a live listener is left alone, streams and all. A changed outward
forward is rebound before the old listener stops; a TCP-only change reuses the
Unix binding, and its live connections survive the rebind. A changed inward
target ends the old target's streams. `DELETE` has no body and ends the
forward's streams. Every forward, inward and outward, can be read back and
listed. The body's `id` must equal the route's. An address held by a
different forward is not transferred (409); move it by removing the old owner
first. Transient accept errors back off; a finished listener is rebuilt by
the next upsert. Refused upserts release anything they bound before
returning, so an immediate retry cannot race socket removal.

Every outward forward needs a host endpoint registered in the client that sets
it, and the client follows `/events` from then on to claim its connections.
The feature list remains descriptive configuration. `egress: null` disables
capture; `egress: {"upstream": "proxy-forward-id"}` activates it. The client
must first register that forward ID against this vessel's dedicated host
endpoint (`register_host_endpoint`); the agent announces each egress
connection on that ID like any outward connection, and needs no
`OutwardForward` for it. While capture is enabled, adding, changing or
removing an outward TCP forward reinstalls the capture table with the new
exemptions in the same call.

### Events

`GET /events` answers `application/x-ndjson`: one `{"cursor": ..., "event":
...}` per line, held open, each new event written as it happens, as drydock's
own `/v1/events` does. Events are tagged by `kind`:

```text
{"cursor":"<boot>:17","event":{"kind":"outward_connection","forward":"crew","connection":4}}
{"cursor":"<boot>:18","event":{"kind":"process_exited","id":"3-812","status":{"code":0,"signal":null,"timed_out":false}}}
{"cursor":"<boot>:19","event":{"kind":"forward_failed","forward":"crew","reason":"connection 5 was not claimed within 30s"}}
```

A cursor is `<boot_id>:<serial>`. `?since=` resumes after that event while
the agent still retains it (the last 1024). A cursor from another agent
process, one older than what is retained, or none, reads everything retained,
so a reader that reconnects after a restart sees what the new agent has said.
`forward_failed` reports an outward listener that stopped, or a connection
closed because nobody claimed it.

### Upgrade

The upgrade image travels as a blob: the host uploads it with the
resumable upload protocol above, so it is digest-checked and an interrupted
push resumes, and the completed upload survives an agent restart.
`POST /upgrade?sha256=` activates the completed upload of that digest (404
without one), copying it out of the store beside the
installed binary and hashing it again as it goes, so a blob changed on disk
is refused (422) and discarded rather than executed. It then re-execs with
the original flags; the host reconnects with a fresh connection and
verifies the new fingerprint. `/hello`, `/upgrade` and the upload routes are
the routes every generation keeps. Agents from before the blob store (their
hello lacks `uploads`, as in published tools images) still take the image
whole through `PUT /upgrade`, and ignore the digest query on activation, so
the same client upgrades them.

The candidate runs on probation: a durable `.probation` marker records it,
and it runs from `.upgrade` while the installed entry point stays the previous
executable. `GET /hello` reports `probation: true` and changes nothing, so a
health probe can never promote a candidate. The host confirms with
`POST /upgrade/confirm`, which moves the candidate to the entry point and
clears the marker; `connect_current` does this once the fingerprint matches.
An unconfirmed candidate can be replaced by activating another; only a
confirmed one ever becomes the entry point. If exec fails immediately,
rollback happens in-process. If the candidate dies unconfirmed (including a
loader failure after a successful exec), the next ordinary provider start
restores `.prev` and clears probation. The previous executable is kept as
`.prev`, and the binary path stays stable across upgrades. A failed
activation keeps its upload and the existing rollback until a new backup is
ready. The activation acknowledgement is advisory: a lost response means
reconnecting and checking hello.

Re-exec drops connections and byte streams, removes owned outward sockets,
clears the capture table and resets configuration. Stale socket inodes from a
crash are reclaimed only when they refuse a connection; live listeners and
ordinary files are preserved.

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
  with the same UID are still redirected. Host-facing connections use
  Unix/vsock. All TCP sockets dialed by inward forwards use `SO_MARK` while
  capture is enabled. The agent never dials the host: drydock connects in,
  over Unix or vsock. A future agent-side TCP connection must apply the same
  marking before connect to avoid capture recursion.
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
Disabling capture removes redirects before stopping listeners. Redirects never
outlive the configuration that installed them: the agent removes its table at
startup, so a crashed agent's redirects go when it restarts with empty
configuration, and before a re-exec. Agent re-exec loses DNS leases; callers
must resolve names again.

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
real UDP/TCP DNS listeners, CONNECT forwarding through claimed outward connections,
explicit proxy transparency, refused/truncated CONNECT responses and half-closes.
`tools/test-agent-egress.sh` additionally exercises nftables and SO_ORIGINAL_DST,
a launched process without proxy variables, the same-UID capture invariant, CA
installation and the agent socket exemption. It requires `sudo`, `nft`, `ip`,
Python 3 and mount/network namespace support, and changes only disposable
namespaces. The live Docker `--network none` operator check remains #3487.

## Byte forwards and endpoint ownership

A byte stream is an upgraded request: an extended CONNECT (RFC 8441) with
`:protocol drydock-forward` on HTTP/2, or on HTTP/1.1 a `GET` with `Connection:
upgrade` and `Upgrade: drydock-forward`, answered 101. Anything else on a
stream route is refused (400). After the 200 or 101 the stream carries raw
bytes, half-close included. The agent performs no HTTP parsing of them, no
header rewriting, token checking, terminal handling or destination policy.
Cleat attach is an ordinary inward forward to a Unix socket.

* Inward (host to vessel): `put_inward_forward` configures a target in the
  vessel, Unix or TCP; TCP port zero is rejected. drydockd opens one
  `CONNECT /forwards/inward/{id}/stream` per client connection
  (`Client::open_inward`). The agent replies 200 only after reaching the
  target; otherwise the reply is the structured error of that attempt, its
  kind kept (an unknown ID or a missing socket is 404, a refused connection
  `ConnectionRefused`). Unix targets connect lazily, so the host can register
  a service before its socket exists.
* Outward (vessel to host): `put_outward_forward` reserves a host endpoint in
  this client's registry, then creates a vessel Unix listener and an optional
  loopback TCP listener. The agent accepts each connection, announces it on
  `/events` as `outward_connection` with a number, and holds it, bytes the
  vessel already sent included, until drydockd claims it with `CONNECT
  /forwards/outward/{id}/connections/{n}`. The claim's stream is then that
  connection. A connection is claimed once, under its own forward ID; one not
  claimed within 30 seconds (`CLAIM_DEADLINE`, `Agent::with_claim_deadline`)
  is closed and reported as `forward_failed`. The client claims a connection
  only when the forward ID is in its registry, then dials the endpoint; an
  endpoint it cannot reach closes the connection at once. The vessel sends
  only IDs; it never names a host target.
* `register_host_endpoint` reserves an endpoint without a vessel listener, as
  for the egress upstream. `remove_*_forward` removes a route at runtime,
  closing its live streams in both directions and its vessel listeners;
  unknown IDs return NotFound. Unrelated forwards continue.
* Host Unix endpoints are claimed by stable path and device/inode, including symlink/hardlink
  aliases. Host TCP endpoints require dedicated loopback ports; claims reserve
  the port across loopback addresses, preventing wildcard-listener aliasing.
  Claims are shared across clients in one controller process and retained by
  active streams. Different controller processes must allocate separate host
  endpoints. Shared endpoints and direct multi-controller connections are not
  part of the current contract: every client following `/events` with a
  forward ID registered may claim its connections.

Outward forwards grant vessel-level reach, not per-UID authorization. Unix sockets
use mode 0600 within an agent-owned 0700 directory; the optional
loopback TCP listener is reachable by every guest UID. Providers that need guest
UID separation must omit loopback TCP.
Host endpoints apply their own policy (for example per-terminal hook tokens);
the agent inspects no forwarded bytes and holds no token.

## Verification

`cargo test -p drydock-agent` covers the control contract over in-memory and
Unix-socket connections: tagged configuration, forward resources and generated
upsert/removal sequences, byte-transparent HTTP/1.1, WebSocket upgrade frames,
chunked bodies, TCP and Unix endpoints, isolation, an outward connection held
until its HTTP/1.1 claim, an unclaimed one closed at its deadline, and `curl`
reaching `/hello` and following `/events` on the socket (`tests/contract.rs`);
processes with stdin, separate streams, exit codes, signals, kill, timeout,
reattach and bounded output (`tests/processes.rs`); file operations, ranges,
modes, digests, resumable uploads and tree unpacks (`tests/files.rs`);
fetches by digest from upstream, OCI and push sources against in-process
stand-ins, with resume, fall-through, unpack refusals and links
(`tests/artifacts.rs`); a streamed transfer and a fetch larger than 512 MiB
in bounded memory (`tests/large_files.rs`, `tests/large_fetch.rs`);
and every refusal as a structured error. Subprocess tests push a distinct ELF
and verify real re-exec, the new hello and boot ID, explicit confirmation,
rollback of an unconfirmed candidate, a durable upgrade upload, forward socket cleanup,
fingerprint gating and survival/reaping of a child. No cloud provider or cleat
installation is required; `curl` is. `examples/link_throughput.rs` measures
transfers over a shaped high-latency link; the HTTP/2 windows in
`drydock-transport` were sized with it.

Forward and connection failures emit `tracing` warnings, without logging process
environment or request bodies. Embedders supply their subscriber. The standalone
binary logs warnings to stderr by default and honors standard `RUST_LOG`.

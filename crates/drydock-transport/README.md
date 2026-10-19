# Vessel stream transport

Implements ADR 0070's API-review amendment and ADR 0069. This crate has no dependency on flotilla or any provider. Both drydock and the vessel agent can use it.

```text
Transport.open(purpose) -> AsyncRead + AsyncWrite
Transport.accept()      -> (purpose, AsyncRead + AsyncWrite)
  Unix / vsock: independent native connections
  SSH:         local and remote Unix-socket forwards, independent channels
  Dial / Relay: yamux over the supplied byte stream
```

The host knows the vessel identity from its reach recipe. There is no vessel ID, authentication token, or per-vessel agent configuration on this wire. Native listeners must be isolated to the owning vessel by the provider. Dial/Relay callers authenticate their outer connection before handing it to this crate. A port-forward header names a requested destination; the receiver still enforces policy before opening it.

## API and lifetime

Create `native::UnixConnections` with a bound Tokio listener and the peer's socket path; wrap it with `Transport::native(Arc::new(connections), Limits::default())` on each end. Linux also has `native::VsockConnections`, taking a bound listener and the peer CID/port. Socket directories, permissions, and removal belong to the caller. Socket permissions and per-vessel isolation are the access control: a permitted local peer can occupy every unfinished-header slot until the configured timeout (10 seconds by default).

`ssh::connect` starts an owned OpenSSH process with a local forward to the agent's socket and a remote forward to a private local listener. Supply the endpoint, user, private-key file, exact raw host public key, agent socket, and unique guest reverse socket. Host-key input must start with a supported raw `ssh-ed25519`, `ssh-rsa`, or `ecdsa-sha2-nistp*` type and a base64 key blob; known-hosts markers, options, and host certificates are refused. It uses no ambient SSH configuration or agent, pins the host key, and fails if authentication or forwarding setup fails. OpenSSH must support Unix-socket forwarding. Paths must be absolute, with no colon or whitespace. Setup first authenticates a private OpenSSH master, then requests both forwards over its control socket and waits for the remote-forward acknowledgement before returning. A rejected forward fails setup. The guest sshd must set `StreamLocalBindUnlink yes` to replace stale reverse sockets after an unclean disconnect; the adapter deliberately does not run a remote shell to remove paths. The provider must allow both forwarding directions. OpenSSH is intentional: a stalled receive queue in russh 0.54's session driver held up other channels in the isolation contract.

For Dial, Relay, or a native fallback, pass the established stream to `Transport::yamux(stream, initiator, limits)` on both ends, with opposite `initiator` values. The initiator writes the preface; the acceptor validates it. A native listener also recognizes a yamux connection and uses that session for reverse opens while it remains live. A later accepted yamux session supersedes the earlier session for new reverse opens; existing streams retain their session.

Clone `transport.opener` for concurrent opens; `accept(&mut self)` has one consumer. An accepted stream already has its header consumed, so its first readable byte is application data. Raw streams support half-close and can be spliced into Tender using `tokio::io::copy_bidirectional`. The Tokio `AsyncRead + AsyncWrite + Unpin + Send` shape matches Tender; no shared named type or Tender dependency is introduced. Move named stream/opener types to rigging when Tender adopts them (ADR 0068).

Keep the `Transport` alive while using its streams. Dropping it ends its accept driver and nested yamux sessions; SSH signals its monitor to kill and reap the owned process before removing its private local directory. Failed or cancelled setup uses the same reap-before-remove cleanup. This cleanup is asynchronous; keep the Tokio runtime alive during teardown. Dropping a raw stream affects only that stream. A cancelled open drops its pending stream; a cancelled accept leaves queued streams intact. `AcceptError::scope` distinguishes `Connection` (discard one malformed/failed stream and continue), `Retrying` (transient listener failure; resource errors back off exponentially from 100 ms to 1 second, while aborted/reset connections and interruptions yield without sleeping), and `Terminal` (the transport driver stops; drain queued streams until `None`). Interrupted/aborted/reset accepts, resource exhaustion, and would-block errors retry. Retry notices are best-effort and may be dropped when the incoming queue is full; terminal errors remain observable. Successful accepts reset the resource backoff. A fatal error inside one fallback session is scoped to that connection, not to the enclosing native listener. Reconnect policy for terminal failures belongs to the caller.

Queues and unfinished handshakes are bounded by `Limits`. Each native handshake runs separately, with a deadline. Yamux is polled independently of application readers; excess unfinished yamux headers are reset. Full incoming queues backpressure new admissions, not already established streams. Established fallback sessions run in a separate task set and never consume unfinished-header slots. The defaults permit 64 queued streams, 64 unfinished headers, and 64 fallback sessions, with a 10-second opening/header deadline.

## Links

`Purpose::Control` and `Purpose::Router` each carry one long-lived HTTP/2 connection. `http2::connect` returns a clonable hyper sender and its driver task. `http2::serve` runs an axum router for the accepted link's lifetime. `http2::connect_with_body` also accepts streaming hyper body types; the buffered `connect` helper remains convenient for small calls. Both ends send HTTP/2 keepalive pings every 15 seconds with a 30-second acknowledgement deadline (including idle client links). The caller owns these tasks, chooses the router, and applies request deadlines. Multiple calls share the same link; raw traffic uses separate streams, outside HTTP framing. Raw-stream idle/liveness deadlines belong to the consuming protocol; HTTP/2 keepalive covers both agent links.

## Wire format (version 1)

All integers are unsigned, big-endian. Readers consume exact header lengths without buffering payload bytes.

Every outer connection starts with `44 44 54 01` (`DDT`, version 1), followed by one byte:

| Mode | Meaning |
| --- | --- |
| 0 | One purpose header followed by raw application bytes |
| 1 | Yamux frames; every yamux substream starts with a purpose header |

Purpose headers:

| Tag | Purpose | Following fields |
| --- | --- | --- |
| 0 | Host-to-agent control link | none |
| 1 | Agent-to-host router link | none |
| 2 | Cleat attach | u16 byte length, UTF-8 session name |
| 3 | Port forward | u16 byte length, UTF-8 host, u16 port |

Targets are 1–1024 UTF-8 bytes without control characters. Host fields are requested destination strings, not parsed socket addresses: the receiver must validate DNS/IP syntax, resolve the name under its policy, and authorize the destination before connecting. Port zero is rejected. Unknown versions, modes, purposes, malformed UTF-8, oversized targets, and truncated headers are errors. Headers describe purpose, not authorization; the caller decides which purposes to serve on each side.

## Validation

On Linux install `openssh-client` and `openssh-server`, then run `./ci/check.sh` at the repository root. Tests run their own loopback-only sshd with disposable keys as the current user; they do not use the machine's SSH configuration or authorized keys. Set `DRYDOCK_TEST_SSHD` to an absolute executable path if sshd is elsewhere. Root test environments may need `/run/sshd` created for OpenSSH privilege separation.

The same routing, half-close, concurrent-open, and slow-stream HTTP/2 scenarios run over Unix sockets, an OpenSSH test server, and yamux over an in-memory duplex. Generated operation sequences assert routing and byte conservation after each operation across all three transports. Wire properties span all purposes, UTF-8, empty and oversized names, and the u16 port range. Named cases cover malformed and partial headers, fallback in both directions, cancelled accepts, rejected host/identity keys, and SSH process cleanup.

Vsock compiles on Linux but requires a VM/vsock device for a live test; the default suite does not claim hardware coverage. Live vsock contract coverage is tracked in [drydock#16](https://github.com/flotilla-org/drydock/issues/16). Hosted CI runs the workspace formatting, Clippy, test, and OpenAPI validation gates. `ci/check.sh` is the reproducible local Rust gate; OpenAPI validation is documented in the repository README.

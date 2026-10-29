# Vessel connections

Implements ADR 0070's API-review amendment and ADR 0069. This crate has no dependency on flotilla or any provider. Both drydock and the vessel agent use it.

```text
Every connection to the agent's socket: plain HTTP/1.1 or HTTP/2 (h2c), from its first byte.
  Requests:     ordinary HTTP
  Byte streams: extended CONNECT (RFC 8441, :protocol drydock-forward) on HTTP/2,
                GET with Upgrade: drydock-forward on HTTP/1.1
  SSH:          one connection through a local Unix-socket forward
  Unix / vsock: the same HTTP, straight to the socket
```

There is no framing of drydock's own, no multiplexer beneath HTTP, and no vessel ID, authentication token or per-vessel agent configuration on the wire. The host knows the vessel from its reach recipe. Socket permissions and per-vessel isolation are the access control; the provider isolates native listeners to the owning vessel. Destination policy belongs to the receiver.

## HTTP

`http::serve(stream, router)` serves an axum router for one connection's lifetime. It reads HTTP/1.1 or HTTP/2 as the peer's first bytes say (HTTP/2 by prior knowledge, as `curl --http2-prior-knowledge` sends it), with upgrades and extended CONNECT enabled. `http::connect(stream)` makes an HTTP/2 client on a connection and returns a clonable hyper sender and its driver task, which the caller owns and aborts on shutdown. Many requests and byte streams share that one connection. `http::upgraded(on_upgrade)` turns an upgraded request or response into a `ByteStream`; `http::BYTE_STREAM` is the `drydock-forward` protocol token. Both ends send HTTP/2 keepalive pings every 15 seconds with a 30-second acknowledgement deadline, idle links included. Callers choose the router and apply request deadlines. Byte-stream idle and liveness deadlines belong to the consuming protocol.

Flow-control windows are 16 MiB per stream and 32 MiB per connection, sized for large transfers over slow links with the agent's `link_throughput` example. A window bounds what a peer may send before the reader drains it, so it also bounds per-stream receive buffering; two stalled readers can hold the whole connection window until they drain or are dropped.

## Listeners

A `Listener` yields independent incoming connections. Tokio's `UnixListener` and, on Linux, `tokio_vsock::VsockListener` are listeners; so is `Box<dyn Listener>`. `memory()` returns an in-memory dialer and listener pair for tests and in-process vessels: each `MemoryDialer::connect` makes a fresh duplex. Once every dialer is gone, its listener's `accept` fails with `NotConnected`. Socket directories, permissions and removal belong to the caller.

## SSH

`ssh::connect(config)` starts an owned OpenSSH process with a local forward to the agent's socket and returns one connection through it. That connection owns the session: dropping it ends the session. Every SSH server allows a local forward, Daytona's gateway included, so no remote forward is ever requested. Supply the endpoint, user, private-key file, exact raw host public key and agent socket. Host-key input must start with a supported raw `ssh-ed25519`, `ssh-rsa`, or `ecdsa-sha2-nistp*` type and a base64 key blob; known-hosts markers, options, and host certificates are refused. It uses no ambient SSH configuration or agent, pins the host key, and fails if authentication or forwarding setup fails. OpenSSH must support Unix-socket forwarding. Paths must be absolute, with no colon or whitespace. Set `SshConfig::connect_timeout` for the TCP/authentication/forwarding budget (for example 60 seconds); the adapter also passes its rounded-up seconds to OpenSSH `ConnectTimeout`. SSH stderr is continuously drained into an 8 KiB in-memory tail with `LogLevel=ERROR`; no diagnostics file can grow on disk. Setup first authenticates a private OpenSSH master, then requests the forward over its control socket. A rejected forward fails setup with OpenSSH's reason; the SSH user is redacted from errors because some providers mint it as an access token. If the agent's socket is absent, OpenSSH closes the connection, so callers see the failure on their first request. Dropping the connection signals the monitor to kill and reap the owned process before removing its private local directory; failed or cancelled setup uses the same reap-before-remove cleanup. This cleanup is asynchronous: keep the Tokio runtime alive during teardown. The SSH adapter targets Unix hosts and is validated on Linux; its short `/tmp` paths preserve Unix socket length limits. Windows hosts are not supported. OpenSSH is intentional: a stalled receive queue in russh 0.54's session driver held up other channels in the isolation contract.

## Validation

On Linux install `openssh-client` and `openssh-server`, then run `./ci/check.sh` at the repository root. SSH tests run their own loopback-only sshd with disposable keys as the current user, granting local Unix-socket forwards only, as Daytona's gateway does; they do not use the machine's SSH configuration or authorized keys. Set `DRYDOCK_TEST_SSHD` to an absolute executable path if sshd is elsewhere. Root test environments may need `/run/sshd` created for OpenSSH privilege separation.

`tests/contract.rs` covers one socket serving both HTTP versions and their byte streams (extended CONNECT and HTTP/1.1 Upgrade, with half-close), streamed request bodies, keepalive failure against a silent peer, and through a real OpenSSH server: reaching the agent socket with half-close in both directions, the session ending when the connection drops, rejected host and identity keys, refused host-key markers, and the connect budget.

Vsock compiles on Linux but requires a VM/vsock device for a live test; the default suite does not claim hardware coverage. Live vsock contract coverage is tracked in [drydock#16](https://github.com/flotilla-org/drydock/issues/16). Hosted CI runs the workspace formatting, Clippy, test, and OpenAPI validation gates. `ci/check.sh` is the reproducible local Rust gate; OpenAPI validation is documented in the repository README.

# Host supervision and CLI

`drydock` embeds `drydock-client` and owns host lifetime and credential resolution.
It has no desired-state database. Dropping a `HostHandle` cancels supervision and
terminates its managed process through rigging's command runner. External hosts
remain running. Managed commands receive `--unix SOCKET`; commands that use a
different flag convention can provide a wrapper.

`Supervisor` injects a `CommandRunner`, `ToolDetector` and `CredentialSource`.
`runtime: "node"` or `"uv"` requests detection; Rust hosts need no runtime.
A missing tool or incompatible hello remains visible for every configured instance
through `HostHandle::instances()`. `status` is a watch receiver with the handshake,
declarations and generation. `ready()` waits for host initialization; inspect
individual instance readiness before placement. `ready()` waits through missing
runtimes and retains the last readiness cause in a distinct timeout error;
terminal credential errors also retain their readiness cause. Restart delay defaults to 100 ms.
The runtime directory must be private and owned by the current user. A per-name
OS lock prevents two supervisors from taking the same socket.

## Credentials

Each Direct wire configuration's opaque `credential_reference` indexes
`HostSpec.credentials`. References are File (`path`, optional top-level
`json_field`), Env (`name`), or Embedder (`reference`). Built-ins implement File
and Env; an embedder supplies `CredentialSource` for its own store. Resolution
returns a redacting `Secret` and optional `SystemTime` expiry. Errors deliberately
omit input values and parser diagnostics. Do not log serialized configuration,
credential documents or request bodies.

The source exposes a watch receiver of change revisions. A notification triggers
re-resolution; periodic resolution (one second by default) also notices file
replacement and expiry. Unchanged values are not resent. Missing, empty, rejected
or expired credentials make that instance not ready without affecting its peers.
Recovery refreshes the credential without replacing the live provider. Restarted
hosts always receive configuration and fresh credentials again.

Proxied instances do not resolve Direct credentials. The embedder supplies the
per-host `proxy_environment` (for example `HTTP_PROXY`, `HTTPS_PROXY` and
`DRYDOCK_PROXY_CA`) and the wire configuration's proxy URL and placeholder token.
The proxy must already exist; the CLI does not create one. Proxy environment
values must not contain secrets: they are passed through `env` as command
arguments. Direct secrets are sent only over the authenticated connection.

## Daemon and CLI

See the [standalone guide](../../README.md#standalone-daemon-and-cli) for the
provider-only TOML format, XDG paths, commands and the checked-in tools pin.
The [tools pin guide](../../ci/tools-image/README.md#checked-in-pin-and-first-publication)
explains the unpublished sentinel, build-time override and post-hello agent upgrade.
`drydock` connects to or starts `drydockd`; it does not own host lifetimes.
`drydockd` is a thin binary around `Daemon`, which embeds the existing
`Supervisor`, resolves credentials, discovers modules, assigns providers and
serves their API through rigging's Unix server with peer-UID admission.

`ProviderApi` is the object-safe provider seam implemented by the embedded
`Daemon` and the socket `Client`. It exposes typed buffered calls and the relay
and exec byte streams. `Daemon::router()` can be mounted by an embedding daemon;
`Daemon::serve()` installs local peer authentication. Authentication must be
installed by the embedder when mounting the router itself.

The daemon retains status caches across calls and discards stale cache values
after mutations or a supervised host generation change. Host pollers remain the
owners of observations; the daemon's `/v1/events` merges their NDJSON records
with a vector cursor. A snapshot from one host explicitly omits the other
providers, preserving the protocol's no-false-deletion rule.

`Daemon::start_with_resolver` injects the image resolver at construction, before
sharing the daemon. There is no runtime unique-Arc requirement.

`HostOption` chooses the available processes; it is daemon/embedder input, never
provider config. Installed language companions are optional: discovery errors
are logged and leave unaffected providers available. Explicit external hosts and
the bundled Rust host are required. CLI discovery uses installed companions; the explicit daemon
`--external-host` option instead uses externally managed Unix hosts. Embedders
can also supply existing `HostConnection::External` connections. Their tokens
remain private regular files owned by the current user; TCP is loopback-only.

Launch metadata and per-vessel SSH keys live under the private socket directory's
`keys/UUID` directory. This evidence records the immutable prepared image and
tools selection; it is not desired state and is never reconciled. Keep these
keys while their environments need SSH. Config edits take effect on daemon
restart, and distinct configs should use distinct socket overrides. Stop the
foreground daemon or send SIGTERM to its owning process, then the next CLI call
starts it with the new configuration. Startup rotates `drydock.log` to
`drydock.log.1` rather than appending across runs;
[#62](https://github.com/flotilla-org/drydock/issues/62) tracks within-run log caps. Keys/evidence currently remain
after errors and destruction; [#61](https://github.com/flotilla-org/drydock/issues/61)
tracks safe retention and garbage collection.

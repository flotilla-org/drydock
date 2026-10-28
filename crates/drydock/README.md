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

`HostSpec.credentials` maps each provider name to where its credential comes
from. References are File (`path`, optional top-level
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
hosts receive configuration again; the server sends each call's credential to the
host in its `Drydock-Credential` header, and hosts hold none. Drydock knows
nothing of credential proxies: hosts it spawns inherit its environment.

## Daemon and CLI

See the [standalone guide](../../README.md#standalone-daemon-and-cli) for the
provider-only TOML format, XDG paths, commands and the checked-in tools pin.
The [tools pin guide](../../ci/tools-image/README.md#checked-in-pin-and-first-publication)
explains the unpublished sentinel, build-time override and post-hello agent upgrade.
`drydock` connects to or starts `drydockd`; it does not own host lifetimes.
`drydockd` is a thin binary around `Daemon`, which embeds the existing
`Supervisor`, resolves credentials, discovers modules, assigns providers and
serves their API through rigging's Unix server with peer-UID admission.

`ProviderApi` is the object-safe provider seam: typed buffered calls plus the
relay and exec byte streams. The server `Runtime` implements it once; that is the
only implementation of provider policy. `api::router` is the one HTTP router,
shared with hosts: its handlers decode a request, call one `ProviderApi` method
and encode the result, using the request's `Drydock-Credential` instead of any
held credential (`ProviderApi::with_credential`). `api::server_router` adds the
server-only credential and event routes. The socket `Client` implements the same
trait over HTTP for remote callers, the Rust host implements it over its modules,
and `Daemon` implements it by routing each call to its provider's host runtime.
`Daemon::router()` adds the daemon's launch, prepare-defaults and shell routes in
front of the server router and can be mounted by an embedding daemon; `Daemon::serve()` installs local peer authentication. Authentication must
be installed by the embedder when mounting the router itself.

The daemon retains status caches across calls and discards stale cache values
after mutations or a supervised host generation change. The server Runtime owns polling, rate budgets, inventory reconciliation, credential
rejection and generation state, lifecycle causes, egress evidence, billing, public
snapshots, diagnostic masking and event history. `HostHandle.client` holds
this server-owned runtime directly; every public request reaches it through the same typed methods. The remote provider adapter implements the shared `drydock-provider`
traits over a host's public API. The daemon's `/v1/events` merges server runtime NDJSON records
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

Both `Daemon::router()` and embedded `ProviderApi` calls reach the same runtime
in process. Supervision creates no policy socket or server-to-itself HTTP hop.
Only the remote provider adapter crosses to a host, through the routes a client
would use against the server. Supervision configures each host with `PUT
/v1/config` (its providers, without credentials) before configuring the runtime;
a host that no longer lists its providers, for example after a restart, is
configured again before a fresh generation is published. No ordinary provider
operation is automatically replayed. External host processes and their
configured providers remain independently owned across server disconnects.

The runtime observes every provider by polling its list. It owns provider call deadlines: ordinary calls end at the
supervisor's request timeout (30 seconds by default), and prepare, provision,
reach, suspend, resume and export at 600 seconds, the deadline the daemon gave
its POST routes. An expired call reports Unavailable with an unknown outcome.
Remote adapter calls add no retry or second deadline. Cancelling a mutation
releases its future without asserting that vendor side effects rolled back.

Errors keep their causes. Client errors carry the transport's source chain, a
timeout is its own `Timeout` error, and an invalid response carries the decoder's
reason. A malformed request names the failing field and the reason without
echoing its value. A stored credential rejection stays `CredentialRejected`
(502) until a new credential arrives; it is never reported as a retryable 503.
See the [Rust host](../drydock-host/README.md) for its side of the API.

### Existing policy limitations retained

This separation does not redesign policy. If credential resolution becomes
unavailable or expires, supervision marks public readiness missing but retains the
last delivered runtime snapshot until a replacement arrives; background polls can
therefore still use that snapshot. These are existing behaviours to evaluate separately.
Diagnostic masking retains active credentials and 32 recent replaced values;
older values remain covered only by the in-flight call that used them. This is
bounded diagnostic retention, not proof that arbitrary vendor errors contain no
other secrets. No new retry or configurable deadline policy is introduced here.

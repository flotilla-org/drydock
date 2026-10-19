# Rust reference host

`drydock-host` serves protocol v1 directly from `drydock-protocol`. Its binary
registers the `reference` module. The crate and binary require Unix (tested on
Linux): they use Unix sockets, kernel peer credentials, and Unix shutdown signals. Embedders register additional Rust factories in
`module::Registry` and use the same `Host` router and listeners. The configuration's
`entrypoint` selects a registered factory, not a shared-library path: Rust's ABI
is not a plugin ABI. One factory can configure several independent providers.

```sh
mkdir -m 700 /tmp/drydock-example
cargo run -p drydock-host -- --unix /tmp/drydock-example/host.sock
# Or: --tcp 127.0.0.1:9280 --token-file /tmp/drydock-example/token
```

The runtime directory must already exist, be owned by the host user and have
mode 0700. Rigging creates the 0600 socket or bearer token file. Unix callers must
have the host's effective UID; an embedder can explicitly select another UID.
TCP accepts loopback addresses only, requires bearer authorization, and compares
token hashes in constant time. TCP clients send the numeric bound address in
`Host`, for example `127.0.0.1:9280`. A restart rotates the token. Ctrl-C and SIGTERM both drain event/upgrade streams
and remove the owned Unix socket.

Configure over the authenticated connection:

```json
{
  "modules": [{"name": "memory", "entrypoint": "reference"}],
  "providers": [{
    "name": "test",
    "module": "memory",
    "settings": {},
    "credential": {"mode": "direct", "credential_reference": "example"}
  }]
}
```

Send this document to `PUT /v1/config`, then send `{"value":"example-secret"}`
to `PUT /v1/providers/test/credential`. Direct values live only in memory;
configuration holds a reference, never the resolved value. Send the credential
route again to rotate it. A module's CredentialRejected error marks the provider
not ready until refresh. The host does not resolve references itself. `Credentials::new` initializes Direct
mode with no value, never an empty secret; the refresh route is its only delivery
path and refuses empty strings. Refresh repairs missing-credential readiness.
Missing-tool, version-mismatch and unknown states remain unchanged; restart those
modules after correcting their external prerequisites.

Exact repeated configuration preserves provider state and credentials. New providers
can be added atomically; replacing or removing a configured provider requires a
restart and is refused with a typed error. This protects live reference resources
from accidental loss. Restarting the reference module clears all its state.
Factories must not publish events or start observations until their provider is
used, because a later factory can reject the configuration transaction.

In Proxied mode, the provider's `Credentials` holds the supervisor's placeholder
and an HTTP client configured to use its proxy. `DRYDOCK_PROXY_CA` names the PEM
CA file for the binary; embedders use `Host::with_proxy_ca`. Modules use
`credentials.http` and `credentials.token()` for vendor calls. The client has no
automatic retries, no redirects, a 30-second timeout, no ambient proxy settings,
and Rigging's TLS provider. Proxied providers reject Direct refreshes. Modules
must not build a bypass client, persist credentials, or log serialized requests
or raw vendor errors. The host does not log request bodies or credentials.

All routes in `openapi.json` are implemented, including optional export, exec,
usage and quota. Capability declarations gate optional operations. Malformed JSON
is refused without returning deserialization diagnostics that could contain a
secret. Errors retain the protocol class and agreed HTTP status; retry hints also
appear in `Retry-After`. Modules own vendor bounds, granted resources, and vendor
idempotency. The host checks request sizes, prepared-provider ownership, destination
syntax, usage periods, and finite reported metering values. It never retries.

`Provider` is an asynchronous trait. The host serializes calls within each provider. A short-lived map lock protects
configuration commits; provider A cannot hold up hello, credential refresh, or
provider B. Requests use a credential snapshot and generation, so a stale
rejection cannot undo a newer refresh. Hello reads cached declarations, refreshed
after provider outcomes and credential changes.
`EventSink` assigns host-wide cursors and provider identity. Modules publish all
billing transitions, with RFC 3339 times and their provenance. Background
observations can publish through a cloned sink. A snapshot records its cursor
before listing so concurrent observations are replayed rather than lost. This is
not an atomic vendor snapshot: a background change can appear in both its rows
and an event replayed after its cursor. Consumers reconcile snapshot rows by
provider/ID, then apply events in cursor order. A snapshot marks a metering gap;
its rows do not create extra billing transitions. Event cursors still resume
exclusively. ADR 0070 does not prescribe an atomic cut between list and events;
this host chooses overlap over dropping a concurrent observation.

The host retains the latest 1024 events in memory. `GET /v1/events` starts with a
complete snapshot. `?since=` resumes exclusively at a retained cursor, including
the boundary immediately before the oldest retained event. Unknown, expired or
previous-process cursors produce a complete snapshot that marks a metering gap.
Slow readers also recover through snapshots. Streams stay open for new events;
an unready provider is never called for a snapshot. A complete snapshot cannot
omit providers, so an initial snapshot failure returns its typed error. One
unready provider therefore blocks initial/recovery snapshots for all providers;
replay from a retained cursor continues without listing providers. Recovery lists
providers sequentially and waits for their operation locks, so its latency can
include in-flight vendor calls plus each list round trip. Configure request timeouts
accordingly; the supplied HTTP client bounds each vendor request at 30 seconds.
Modules must bound any other vendor I/O they perform. A later
recovery failure fails the HTTP body (rather than clean EOF), allowing the client
to reconnect. Protocol v1 defines no terminal error record. History is deliberately not persisted.

Relay clients use `Connection: Upgrade` and `Upgrade: drydock-relay`; exec uses
POST with a JSON `ExecRequest` and `Upgrade: drydock-stream`. Responses echo both
headers with 101, then bridge raw bytes with half-close propagation. Modules must
return a connected stream only after checking the environment and command. Exec
request bodies are limited to 1 MiB and must arrive within five seconds; timeout
is a typed Refused error before any provider operation starts.

The reference module implements preparation, concurrent label idempotency,
list/inspect/destroy, reach/relay, suspend/resume, export, exec, usage and quota.
Repeated provision with a valid but changed body returns the original sandbox: a
label identifies creation, not an update. Zero-byte memory/disk and empty usage
intervals are valid; unsigned wire fields reject negative sizes. Both bare and
bracketed IPv6 direct host syntax are accepted by the host.

Its relay and `exec ["cat"]` echo raw bytes; `exec ["echo", ...]` writes one line.
It spawns no OS processes. Usage returns an empty measurement set and quota counts
running sandboxes; it has no vendor billing account. It reports advisory egress
and refuses direct destinations, because an in-memory sandbox cannot enforce a
firewall. Settings may contain `fault: <ProtocolError>` to exercise every error
class in conformance tests; this mode is intended only for testing.

```sh
cargo test -p drydock-host --locked
```

The integration suite drives real Unix sockets and loopback TCP. A generated
stateful scenario checks label idempotency and isolation after each operation;
named scenarios cover event replay/gaps, concurrent retries, credential rotation,
all error classes, peer/bearer auth, semantic refusals and raw stream upgrades.

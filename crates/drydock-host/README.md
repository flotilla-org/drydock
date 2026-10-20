# Rust reference host

`drydock-host` serves protocol version 2 directly from `drydock-protocol`. Its binary
registers the in-memory `reference` module. Embedders register additional compiled
Rust factories in `module::Registry` and use the same router/listeners. The crate
requires Unix and is tested on Linux.

```sh
mkdir -m 700 /tmp/drydock-example
cargo run -p drydock-host -- --unix /tmp/drydock-example/host.sock
# Or: --tcp 127.0.0.1:9280 --token-file /tmp/drydock-example/token
```

The runtime directory must exist, belong to the host user, and have mode 0700.
Rigging owns socket binding, peer credentials, token-file creation, constant-time
comparison, and Host/Origin enforcement. TCP is loopback only and uses the numeric
bound authority in Host. The host selects bearer-only TCP and the supervisor UID
through small caller-policy layers pending shared Rigging policy options (#20).
Ctrl-C and SIGTERM signal and await observers, close event bodies and upgraded streams, and unlink the
owned Unix socket. Restart rotates the TCP token.

## Configuration and module interface

Send this to `PUT /v1/config` over the authenticated connection:

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

`entrypoint` selects a compiled factory, not a shared-library path. Each factory
creates an `Arc<dyn Provider>`. **Every provider method takes `&self`; the host
holds no provider operation lock.** Concurrent prepare, inspect, list, snapshot
and credential refresh calls remain independent. Stateful modules synchronize
only their own data; the reference uses a short internal Mutex with no await.

`Provider` contains the core lifecycle and inventory operations. Optional operations
are borrowed ports returned by `operations()`: `Exec`, `SuspendResume`,
`ExportOperation`, `UsageOperation`, and `QuotaOperation`. The default is an empty
`Operations`, so a basic provider implements no optional methods. Implement only
the supported traits, returning `Some(self)` (or a separate adapter) for those ports.
Registration refuses a mismatch between ports and capability flags. Both declarations
must stay stable for the configured lifetime. If a module violates this contract by
withdrawing a port, the request returns a typed Refused error instead of panicking.
The host remains the single capability
gate; ports contain no unsupported defaults. All ports are object-safe, `Send + Sync`,
and use `&self`. Push providers retain the post-commit `run(PushContext)` hook.

Factories validate settings before commit and must not publish or start detached
work while configuring. The reference parses a typed settings struct, accepts an
optional `poll_interval_ms` (positive, default 10) and `fault: <ProtocolError>` for
error-class conformance, and rejects unknown settings. Exact repeated documents
preserve providers and credentials; additions commit atomically. Replacement or
removal currently requires restart, protecting in-memory resources. Stateless
settings replacement is tracked in #22.

One shared call helper resolves a provider, checks readiness and cached capability,
reserves the declared operation/global rate budget, invokes it and records the
outcome. Optional methods have no duplicate unsupported defaults. A missing
credential means Unavailable (503), without a vendor call. CredentialRejected
(502) means a vendor actually rejected a delivered value; readiness then becomes
MissingCredential until refresh. A stale rejection cannot undo a newer credential
generation. Hello reads cached declarations without waiting on vendor I/O.

Provision returns a typed Created/Existing result; the host chooses 201/200.
The same label with a valid changed body returns the existing environment, not an
update. Reach returns a module connection recipe; Relay is a marker and the host
builds its escaped route. Streams reuse `rigging_stream::ByteStream`.

## Credentials and HTTP transport

Send `{"value":"example-secret"}` to
`PUT /v1/providers/test/credential`, again whenever it rotates. Direct values
exist only in memory. `Credentials::new` has no initial secret; empty refreshes
are refused. The host does not resolve credential references. Tool/version/unknown
readiness is separate from credential refresh.

Factories receive `Arc<dyn rigging_http_client::HttpClient>` separately from
credential mode and values. Modules build requests, add the current credential,
and execute through that port, allowing Rigging stand-in/replay clients in tests.
The production client comes from Rigging's `ReqwestHttpClient::restricted`:
no ambient proxy, retries or redirects, a 30-second timeout, an explicit proxy
when configured and additional supervisor CA roots. No client construction is
copied into Drydock. `DRYDOCK_PROXY_CA` names a PEM file for the binary;
embedders use `Host::with_proxy_ca`. The file is PEM with one or more
`-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----` CA blocks, not a private
key or PKCS#12 file. Never log serialized credentials, request
bodies, or raw vendor errors. Proxied providers refuse Direct refreshes.

## Host-owned observation

A provider declares `ObservationMode::Poll { interval }` or Push. For Poll the
host owns one list loop, last-seen state and diffing. It stretches the interval
within declared list/global limits and skips missed ticks. Observation gets at
most half the long-run list/global rate and max(1, requests/2) slots per window;
route calls share the total budget and can use the remaining slots. An indivisible
one-request window is polled at most every two windows: a route immediately after
that single poll can still receive 429 until the shared window expires. If route
traffic consumes a single-slot window before a due poll, the host reserves the next
free slot for that pending observation. Routes may receive 429 until the next poll
attempt takes the slot; this prevents steady route traffic from starving observation.
The first
poll is eligible immediately; Direct credential delivery wakes observation, so a
large steady-state interval does not delay the first snapshot. Failed or unready lists preserve prior state and never report
resources gone. Successful complete lists emit Created/Running, Stopped/Paused,
Resumed/Running, size changes, and Gone transitions. Confirmed requested deletions
use DestroyedByRequest; unexplained absence uses MissingOnList. If a list observes
absence while destroy is pending, the host defers the billing cause until the call
confirms or fails. Failure/cancellation is never promoted to confirmed deletion.

Modules return `ObservedEnvironment` from list/inspect: the environment plus an optional
typed provider timestamp. Polling uses that time, including matching inspect
metadata when list has none; otherwise the host stamps first observation with
TimestampSource::Adaptor. Push modules publish through EventSink with an optional
typed timestamp. Some means Provider provenance; None asks the host to stamp
Adaptor time. Modules never format event times. The reference declares Poll and
publishes no events itself, so its lifecycle tests exercise the host poller.

The host retains `EVENT_HISTORY_CAPACITY` host-wide events in memory (1024).
`GET /v1/events` starts with a snapshot; `?since=` resumes exclusively at
retained cursors. Unknown, expired and previous-process cursors produce a
gap snapshot. Poll snapshots use the last successful host-owned inventory, never
another vendor list request. A poll commits its inventory and transition events
under the same log lock, so a poll-only snapshot cursor identifies that exact cut.
Before a provider's first successful poll, a snapshot waits for observation or
marks that provider's typed failure. With neither cache nor a failure, it waits for
an observation, an error, or host shutdown. Later transient poll failures retain the inventory.
Push snapshot cursors precede provider listing to replay overlapping events.
Independent push lists run concurrently under one shared five-second deadline
(`PUSH_SNAPSHOT_TIMEOUT`), once per snapshot. This is a fixed host policy rather than
provider configuration. A timed-out list is cancelled and its provider is marked
Unavailable; healthy providers still publish inventory. Lists return complete vectors:
no captured or unfinished response is published as authoritative. Host shutdown
cancels the whole batch immediately. Waiting for an initial poll inventory does not
restart the push lists or their deadline. If enough events arrive during that wait
to evict the pre-list cursor from the 1024-event history, the next stream iteration
emits a fresh gap snapshot instead of replaying the lost events. Clients apply that
replacement snapshot normally, preserving inventory for unavailable providers;
individual evicted billing transitions cannot be recovered from this in-memory log.
Snapshot rows mark a metering gap and do not create extra billing transitions.

Snapshots omit inventory for unready providers and failed push lists, reporting
those providers in an optional `unavailable_providers` map of name to typed error.
Cached poll rows are also withheld when that provider is unready; a ready provider's
cached inventory remains available through transient polling failures.
The map is absent for a complete snapshot. Consumers must preserve previous inventory
for marked providers: missing rows are not evidence of deletion or a billing transition.
Healthy providers continue streaming. Events from a marked provider can still follow
the snapshot cursor. Each such event is authoritative only for its own environment
row; it does not make that provider's omitted inventory complete or remove its marker.
Push lists use the normal call gate, so a
successful list repairs a proxied rejection without requiring a separate route call.
Direct credentials still require refresh. Poll providers repair through normal polling.
Retained-cursor replay does not list. Host stopping still returns an initial typed
HTTP error or ends an existing stream. The protocol defines no terminal NDJSON error record.
Polling cannot report transitions hidden entirely between samples; modules with
event streams declare Push.

Push observers receive `Provider::run(PushContext)` only after configuration commits.
The context carries a provider-scoped sink, a credential watch, and a stop watch.
On shutdown the host signals and cancels pending configuration, then awaits observer
cleanup against one shared five-second deadline. It aborts remaining observers without
awaiting cooperative cancellation and releases instances. Once the shared deadline
expires, remaining observers receive no additional grace; already-completed tasks
are still collected. Module factories must be
cancellation safe; configuration remains transactional until commit. Poll factories
receive no sink and do not start background work. Upgraded streams close on shutdown; they
are not drained to completion.

## Diagnostics and readiness

The library emits structured tracing events with route/provider/environment identity,
static error classes and readiness statuses; it never installs a subscriber or logs
request bodies, credentials or vendor error text. The binary installs a plain-text
stderr subscriber using `RUST_LOG`, defaulting to `info`. Embedders choose a subscriber.

One policy derives readiness and call admission from module readiness plus host
credential state. Direct rejection is sticky until a new refresh. A rejection also
invalidates older calls, so a stale success cannot repair it. Proxied rejection
reports Unknown while allowing subsequent probes; a successful post-rejection
probe restores readiness after the supervisor repairs the proxy. Direct credential
refresh is still refused for Proxied providers.

## Routes and validation

All routes in `openapi.json` are implemented. Typed JSON/path extraction returns
sanitized Refused errors without echoing diagnostics; no status-rewriting layer
is used. `ProtocolError::status` and every OpenAPI route carry the shared status
contract. Destination host/IP/CIDR parsing and ordered RFC3339 periods are validated
by protocol deserialization, and their patterns/formats/invariants appear in the
schema for other language hosts. Positive CPU counts, nonempty labels/digests/credential values and executable
commands are also protocol/schema constraints. Times are typed instants throughout
module and wire types. Unknown routes/providers/environments use NotFound (404);
wrong HTTP methods use MethodNotAllowed (405). Other statuses have shared,
status-specific OpenAPI responses, including Retry-After. Host checks retain
prepared-provider ownership and capability gates.

Relay requests send `Connection: Upgrade` and `Upgrade: drydock-relay`. Exec uses
POST, typed JSON `ExecRequest`, and `Upgrade: drydock-stream`; its upgrade extractor
preserves metadata while using the same JSON body path as other routes. Successful
101 responses echo the headers and bridge raw streams with half-close propagation.
Shared all-route body deadlines and auth policy options are tracked in #20 and
Rigging #18. Generic provider call lifetime/cancellation policy is tracked in #19.

The reference echoes relay and `exec ["cat"]`; `exec ["echo", ...]` writes a line
without OS processes. It reports advisory egress, refuses direct destinations,
returns no vendor usage measurements and counts running resources for quota.
Usage/quota numeric output assertions belong in conformance (#21), not routing.

```sh
cargo test -p drydock-host -p drydock-protocol --locked
```

Tests drive real Unix/TCP endpoints, a generated label lifecycle, host polling,
provider/inspect timestamp provenance, replay/eviction, concurrent same-provider
calls, credential rotation, Rigging replay injection, raw upgrades, rate limits,
auth and shutdown. Shared protocol properties compare decoding with schema rules.
Endpoint-driven reuse across language hosts and remaining forwarding/fixture-helper
consolidation are tracked in #21.

Unix UID admission failures return a bare 403 before protocol handling, just as
Rigging's TCP authentication failures return transport-level statuses. These are
not module or `/v1` ProtocolError outcomes.

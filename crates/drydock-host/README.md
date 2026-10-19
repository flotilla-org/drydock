# Rust reference host

`drydock-host` serves protocol v1 directly from `drydock-protocol`. Its binary
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
Ctrl-C and SIGTERM stop observers, drain event/upgrade streams and unlink the
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
The same label with a valid changed body returns the existing sandbox, not an
update. Reach returns a module connection recipe; Relay is a marker and the host
builds its escaped route. Streams reuse `drydock-transport::ByteStream`.

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
embedders use `Host::with_proxy_ca`. Never log serialized credentials, request
bodies, or raw vendor errors. Proxied providers refuse Direct refreshes.

## Host-owned observation

A provider declares `ObservationMode::Poll { interval }` or Push. For Poll the
host owns one list loop, last-seen state and diffing. It stretches the interval
within declared list/global limits, shares the budget with route calls, and
skips missed ticks. Failed or unready lists preserve prior state and never report
resources gone. Successful complete lists emit Created/Running, Stopped/Paused,
Resumed/Running, size changes, and Gone transitions. Confirmed requested deletions
use DestroyedByRequest; unexplained absence uses MissingOnList.

Modules return `ObservedSandbox` from list/inspect: the sandbox plus an optional
typed provider timestamp. Polling uses that time, including matching inspect
metadata when list has none; otherwise the host stamps first observation with
TimestampSource::Adaptor. Push modules publish through EventSink with an optional
typed timestamp. Some means Provider provenance; None asks the host to stamp
Adaptor time. Modules never format event times. The reference declares Poll and
publishes no events itself, so its lifecycle tests exercise the host poller.

The host retains 1024 host-wide events in memory. `GET /v1/events` starts with a
complete snapshot; `?since=` resumes exclusively at retained cursors. Unknown,
expired and previous-process cursors produce a new complete gap snapshot. Snapshot
cursors precede listing: background observations may appear in both rows and later
events. Reconcile rows by provider/ID, then apply events in cursor order; snapshot
rows mark a metering gap and are not extra billing transitions. ADR 0070 leaves
this concurrent cut unspecified; the host chooses overlap over losing a change.

An unready provider blocks a complete snapshot rather than silently omitting its
resources. Retained-cursor replay does not list. Recovery lists sequentially and
may wait for vendor calls themselves, but not for an unrelated prepare on the
same provider. Initial failures are typed HTTP errors; later recovery failures
fail the HTTP body instead of clean EOF. V1 defines no terminal NDJSON error
record. Polling naturally cannot report transitions that occur entirely between
samples; modules with event streams declare Push.

## Routes and validation

All routes in `openapi.json` are implemented. Typed JSON/path extraction returns
sanitized Refused errors without echoing diagnostics; no status-rewriting layer
is used. `ProtocolError::status` and every OpenAPI route carry the shared status
contract. Destination host/IP/CIDR parsing and ordered RFC3339 periods are validated
by protocol deserialization, and their patterns/formats/invariants appear in the
schema for other language hosts. Host-specific checks retain provider ownership,
label semantics and module capability gates.

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
Endpoint-driven reuse across language hosts is tracked in #21.

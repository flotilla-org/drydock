# drydock

The substrate for just launching vessels: isolated environments for AI coding agents, on any provider.

Drydock hosts out-of-process provider adaptors behind one HTTP protocol, reaches an agent inside each vessel over a bidirectional stream transport, and carries the vessel's egress. [Flotilla](https://github.com/flotilla-org/flotilla) embeds it; it is also usable on its own.

Status: design decided ([flotilla-org/flotilla#3503](https://github.com/flotilla-org/flotilla/issues/3503)); protocol workspace, [`drydock-transport`](crates/drydock-transport), and the [Rust reference host](crates/drydock-host) implemented; vendor modules and the agent are next.

See the [transport guide](crates/drydock-transport/README.md) for the API, wire format, lifecycle, and transport test instructions.

Project contents and roadmap:

- the protocol crate: Rust types, the generated OpenAPI document and a drift test;
- the Rust reference host and in-memory module; TypeScript and Python hosts follow, each with its own provider interface;
- provider modules, Daytona first in Rust, and Namespace through the TypeScript SDK;
- a conformance suite runnable against any language host or built-in provider.

Licensed under either of Apache License 2.0 or MIT, at your option.

## Protocol workspace

`drydock-protocol` contains the JSON types and OpenAPI route descriptions for
ADR 0070, including its API-review amendment. It has no flotilla dependency and
no HTTP server or client implementation. Language hosts should generate their
models from [`openapi.json`](openapi.json).

```sh
cargo run -p drydock-protocol --bin generate-openapi > openapi.json
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
uvx --from openapi-spec-validator==0.7.2 openapi-spec-validator openapi.json
```

The drift test compares deterministic generation with the checked-in document.
Regenerate it whenever wire types or route descriptions change. CI separately
validates the document against OpenAPI 3.1.

Protocol version 2 changes snapshot reconciliation semantics. Clients must check
`hello.protocol_version` for an exact match before using any provider or event
route (ADR 0070). Version 1 clients must not consume version 2 snapshots: ignoring
`unavailable_providers` could turn unavailable inventory into false deletions or
billing transitions. Upgrade snapshot reconciliation before accepting version 2.
The HTTP route namespace remains `/v1`; the hello version is the compatibility gate.
Snapshot errors retain the same typed details as route errors, including vendor
reasons and raw `Internal` error text. They are visible to authenticated host clients;
modules must exclude credentials from error text. The host does not sanitize it.

Wire conventions chosen for this first protocol version:

- Names follow the ADR amendment: configured `providers` load `modules`;
  environment `id` is opaque and `label` is the client's environment ID. Provision
  repeats by label return 200; new creations return 201. Inspect and destroy
  use IDs even when a environment has no label. Destroying an absent ID succeeds.
- Configuration contains non-secret settings and credential references or proxy
  placeholders. Direct credential values are sent separately through the
  authenticated credential refresh route, including initial delivery.
- Prepare is look-up-or-build by image/tools digest pair; a prepared form belongs
  to its named provider. Hosts must refuse cross-provider use. Baking and upload
  start the agent with fixed flags, without per-vessel configuration.
- Missing egress means deny-all with no direct destinations. `open` is explicit;
  unsupported destinations are refused, never widened. The result records
  enforced versus advisory protection.
- `/v1/events` is one host-wide NDJSON stream. Each line is an `ObserveRecord`.
  `since` is an opaque exclusive cursor. A host unable to replay emits a
  list snapshot with a new cursor, marking a metering gap. An optional
  `unavailable_providers` map names providers whose inventory is omitted, with
  typed errors; consumers preserve their previous rows rather than infer deletion.
  Event times are RFC 3339 with explicit provider/adaptor provenance; running
  events carry granted size.
- Retry hints are whole seconds. Modules do not retry. Capability flags govern
  optional suspend/resume, export, exec, usage and quota operations. A resume
  token is valid only at the same provider. Usage periods are RFC 3339 start/end;
  quota credit units are provider-defined.
- Relay and exec responses upgrade to raw streams. Dial uses TCP or WebSocket
  URLs and an expiring token; SSH carries endpoint, user and host key. Transport
  setup, authentication enforcement, semantic input validation and idempotency
  behaviour belong to hosts and their future conformance suite.

### Compatibility and validation

Per-environment routes use `/v1/providers/{provider}/environments`: POST provisions,
GET lists, and GET/DELETE on `/{id}` inspect/destroy. Reach (POST), relay (GET),
suspend/resume/exec/export (POST) append their operation after `/{id}`.
Provider-level prepare, credential, usage and quota stay directly under
`/v1/providers/{provider}`. IDs such as `usage` and `quota` therefore remain opaque
without colliding with provider-level operations. There are no route aliases.
Host configuration is `PUT /v1/config`; the host-wide stream is `GET /v1/events`.

Optional fields serialize as explicit `null`; absent optional fields are accepted
as `None`. Unknown object fields are ignored for additive compatibility. Unknown
enum variants are rejected, including readiness and loss causes: hosts must
negotiate the protocol version and report mismatches as not ready. Incompatible
new variants require a protocol version bump. OpenAPI info.version equals the
handshake's `PROTOCOL_VERSION`; it is a wire version, not a Cargo package version.

Hosts perform semantic validation: CPUs must be finite and strictly positive;
memory/disk sizes and usage hours must be nonnegative, and hours and reported
credits must be finite. Credits may be negative when a vendor reports a debt.
The protocol's validated HostAddress, Cidr, Port, Timestamp and Period types enforce
destination syntax and ordered RFC 3339 periods. The generated schema carries the
same patterns, formats, bounds and period invariant for other hosts. Providers
validate their own resource bounds before vendor calls.

`Secret` redacts Debug output, including nested credential and reach recipes,
but deliberately serializes the original string for transport. Never log their
serialized JSON. Raw `Internal.provider_error` is sensitive, untrusted vendor
text: do not log it at info level or forward it to end users.

Paused is an explicit billing transition; Stopped is the general stopped event
and observation, whose `PausedByProvider` cause is valid under ADR 0058. Consumers
must count both as non-running rather than infer loss. `MissingOnList` records
absence from an authoritative complete list; `DestroyedByRequest` records a
confirmed client deletion, matching ADR 0058's loss vocabulary.

Relay and exec clients send `Connection: Upgrade` and respectively
`Upgrade: drydock-relay` or `Upgrade: drydock-stream`;
a successful 101 response echoes both headers before the raw byte stream begins.

`Hello::is_compatible()` performs exact wire-version comparison; callers still
check each provider's readiness. `Secret::expose()` makes plaintext access
explicit. Secret's value equality is for protocol data tests and is not a
constant-time authentication primitive. Hosts must compare authentication tokens
in constant time and own secret-buffer lifetimes; this wire wrapper does not
promise secure erasure of SDK or serialization copies. Secret intentionally has
no Display implementation. Explicit-null serialization is part of protocol v1.

Exec intentionally uses POST with a 101 upgrade, while relay uses GET; some HTTP
proxies and generated clients handle POST upgrades poorly, so hosts and clients
must use a transport that preserves the upgrade rather than changing the method.

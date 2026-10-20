# drydock

The substrate for just launching vessels: isolated environments for AI coding agents, on any provider.

Drydock hosts out-of-process provider adaptors behind one HTTP protocol, reaches an agent inside each vessel over a bidirectional stream transport, and carries the vessel's egress. [Flotilla](https://github.com/flotilla-org/flotilla) embeds it; it is also usable on its own.

Status: design decided ([flotilla-org/flotilla#3503](https://github.com/flotilla-org/flotilla/issues/3503)); protocol workspace, [`drydock-transport`](crates/drydock-transport), the [Rust reference host](crates/drydock-host), [typed client](crates/drydock-client), and [supervision/CLI](crates/drydock) implemented; vendor modules and the agent are next.

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

## Conformance

`drydock conformance --provider NAME --options probe.json` runs destructive
ADR 0070 scenarios against exactly one provider in the normal `--config` host
configuration. Unix sockets, managed host binaries and authenticated loopback
TCP hosts all use the same client and scenario list. A built-in provider can
expose that same endpoint without a special test interface. The Rust reference
binary and a small independent Python socket fixture run this list in CI; the
fixture also deliberately violates each reported check. The checked-in
[`broken-matrix.json`](crates/drydock-host/tests/fixtures/broken-matrix.json)
must exactly match the healthy full report: removing a verdict fails CI too.
Endpoint scenarios own deterministic polling, lifecycle sequences, provider
isolation, typed errors, optional operations and stream upgrades. Unix admission
and TCP bearer scenarios use the same endpoint client; host-internal poll races
remain implementation tests.

For example, choose the image and tools digests in the request:

```json
{
  "request": {
    "label": "conformance-unique-run-id",
    "prepared": {
      "provider": "reference", "id": "prepared-1",
      "image_digest": "sha256:image", "tools_digest": "sha256:tools"
    },
    "size": {"cpus": 1, "memory_bytes": 1024, "disk_bytes": 0},
    "egress": {"mode": "deny_all", "direct": []},
    "ssh_public_key": null
  },
  "echo_relay": true,
  "reach_probe": null,
  "egress_probe": null
}
```

```sh
drydock --config hosts.json --runtime-directory /private/runtime \
  conformance --provider reference --options probe.json
# Vendor modules require explicit consent to charges:
drydock --config hosts.json --runtime-directory /private/runtime \
  conformance --provider daytona --options daytona-probe.json --live
```

The configuration and options files are trusted operator input: probe argv can
execute local programs or guest commands. The `reference` entrypoint convention
is a guard against accidental charges, not a security boundary; a host can load
anything under that name. Treat externally supplied hosts and configs accordingly.

Use a unique label and an idle test account. The concurrent-idempotency scenario
makes two simultaneous provision calls. A broken provider can create two billable
resources; refusal and range probes can also create strays on a broken host.
The runner tracks their IDs and exact probe labels, retries final teardown once,
and records a verified final cleanup sweep before reporting spend. It avoids a
label-prefix wildcard so another run sharing a prefix is preserved. Failed
cleanup remains a failing verdict and requires operator attention.

The runner provisions, suspends and resumes when supported, and destroys its environment, including after failed
checks. It returns nonzero if any check fails and prints a JSON report with
individual verdicts, elapsed resource exposure, provider-reported usage for the
run period, before/after quota, and a credit delta when available in the same
unit. Missing cost data is `null`, never an assertion of zero spend. These account
figures can include concurrent workloads and delayed vendor accounting; they are
not a monetary estimate. The runner prepares the selected image/tools digests twice and checks
look-up-or-build identity before provisioning; the input prepared ID is replaced.
Operators can also obtain a complete prepared form with
`drydock --config hosts.json prepare HOST NAME IMAGE_DIGEST TOOLS_DIGEST`.
Preparation can incur provider charges. Live Daytona and then Namespace validation
are operator runs once their modules and test credentials exist.

For slow providers, add an optional `timeouts` object to `probe.json`. Defaults
are `startup_seconds: 15`, `request_seconds: 30`, `headers_seconds: 20`,
`record_seconds: 20`, `transition_seconds: 30`, and `probe_seconds: 30`. Each is
independent and accepts 1–86400 seconds. For example, a cold start can use
`{"startup_seconds":120,"request_seconds":180,"record_seconds":300,"transition_seconds":600}`.
Startup includes host configuration/credential readiness; request deadlines cover
buffered HTTP calls and upgrade setup. Record and transition deadlines bound
observation waits, while headers and probes have their own deadlines. Failure
details contain safe categories (`timeout`, `decode`, `transport`, or typed HTTP
status/class), never vendor reasons or probe output.

`echo_relay` is only for fixtures whose relay is an echo server. Real agents have
a protocol: provide `reach_probe: ["/absolute/path/to/round-trip-probe", ...]`.
It receives the returned SSH, Dial or Relay recipe as JSON on stdin, establishes
and authenticates the recipe, exchanges bytes with the agent, then exits zero
only on success. It owns SSH private-key material matching `ssh_public_key`.
The runner suppresses probe output and never puts recipe secrets in argv or
reports. Missing probes fail the stream check rather than silently accepting a
recipe declaration. The same seam supports every declared recipe as providers
are added; it does not assume arbitrary agent streams echo input.

An `Enforced` provider must also use `DenyAll` with exactly one direct destination
and supply `egress_probe: {"command": [...]}`. Copy
[`tools/egress-probe.py`](tools/egress-probe.py) into the prepared guest and run it
through exec as root, with these arguments: listed IP, listed port, unlisted
canary IP, canary port, and raw DNS server IP. Use IP literals and independently
verify that both TCP services and the DNS server are reachable outside the
sandbox before the run. This avoids confusing an unavailable canary with an
enforced policy. The probe bypasses process proxy settings with direct sockets
and sends an actual UDP DNS query. Its entire output must be the following JSON,
followed by stream EOF. Guest exec exposes a byte stream without an exit-status
channel, so the checker validates output and EOF rather than certifying the
process exit code:

```json
{"uid":0,"listed_direct":true,"unlisted_canary":false,"raw_dns":false}
```

Any other result, missing root evidence, missing probe, refusal of the required
allowlist, or downgrade to Advisory fails an Enforced claim. Providers without
exec can supply the probe through a guest bridge when that tooling is available;
currently this check requires exec and cannot silently pass without it.

TCP authentication checks reject absent tokens and tokens changed at each byte
position through the injected HTTP client and configured request timeout. A Unix
endpoint without a bearer reports that this scenario needs a bearer fixture;
it cannot silently pass. The separate `unix_peer_admission` endpoint scenario
requires a client connected as an unauthorized UID.

Select groups with `"scenarios": ["prepare", "lifecycle", "observation", "destroy"]`.
The available groups are `capabilities`, `authentication`, `prepare`, `lifecycle`,
`observation`, `semantics`, `nulls`, `reach`, `refusal`, `egress`, `destroy`,
`metering`, and `host_fixtures`. An omitted/empty list selects the provider suite
excluding host fixtures. Dependencies (for example provisioning for observation)
are still run; unrelated verdicts are omitted. A capabilities-only selection
allocates nothing. The full reference/independent-host CI profile selects all.

`host_fixtures` is for disposable host validation: supply `fixture_configuration`
with two fixture-capable providers. It exercises configuration atomicity,
credential refresh, all typed error classes/statuses/retry headers, provider
isolation, modelled create/delete sequences, stream upgrades, and deterministic
poll recovery, timestamps, pause/halt billing and typed loss causes. Its exec
control vocabulary is `drydock-fixture` plus `null_environment`, `forget`,
`state`, `timestamp`, `inventory_error`, or `pause`. Reference settings must
explicitly enable `fixture`; vendor providers must not enable this profile.

Environment null checks require a genuinely unlabeled environment with unknown
granted size: use the fixture profile or supply `null_environment_id`. Without
such evidence the verdict fails. Quota nulls are checked separately. Each invalid
CPU, memory, disk, destination and usage-period request gets its own verdict.
Billing checks require the exact stopped cause and vendor usage facts over a
sample window (`billing_sample_millis`, default 25); use a distinct granted size
and an idle account so aggregate usage does not mix in another running guest.
Providers with delayed accounting may need a longer window.

Constant-time authentication has an executable evidence requirement:
`auth_audit: ["/absolute/path/to/audit", ...]`. Missing or unsuccessful evidence
fails `authentication_constant_time`. Network timing cannot prove constant-time
machine execution. CI runs [`tools/auth-audit.py`](tools/auth-audit.py) against
the exact linked Rust admission source (fixed-size SHA-256 plus
`ConstantTimeEq`) and the Python comparator source actually loaded by its host
(`hmac.compare_digest`). Equality mutations fail the audit; endpoint probes
exercise the real admission path. Other language hosts supply an equivalent
audit of their loaded comparator.

CI also executes the real guest egress script, including denied UDP-connect
handling, and real TCP, WebSocket, SSH and relay recipe exchanges. Wrong tokens,
SSH pins and corrupt relay bytes fail the exact reach verdict. The fixture
[`tools/recipe-probe.py`](tools/recipe-probe.py) speaks the fixture echo-agent
protocol; production agents provide their own round-trip executable through
`reach_probe`. Additional transport/probe fault coverage is listed in
[`boundary-matrix.json`](crates/drydock-host/tests/fixtures/boundary-matrix.json).

# drydock

The substrate for just launching vessels: isolated environments for AI coding agents, on any provider.

Drydock hosts out-of-process provider adaptors behind one HTTP protocol, reaches an agent inside each vessel over a bidirectional stream transport, and carries the vessel's egress. [Flotilla](https://github.com/flotilla-org/flotilla) can embed the crate or delegate to the same provider API; standalone use runs `drydockd`.

Status: design decided ([flotilla-org/flotilla#3503](https://github.com/flotilla-org/flotilla/issues/3503)); protocol workspace, [`drydock-transport`](crates/drydock-transport), the [Rust reference host](crates/drydock-host), [typed client](crates/drydock-client), [daemon/client CLI](crates/drydock), Daytona module, and [vessel agent and client](crates/drydock-agent) implemented; additional language hosts, the tools image, and egress capture follow.

See the [transport guide](crates/drydock-transport/README.md) for the API, wire format, lifecycle, and transport test instructions.

Project contents and roadmap:

- the protocol crate: Rust types, the generated OpenAPI document and a drift test;
- the Rust reference host and in-memory module; TypeScript and Python hosts follow, each with its own provider interface;
- provider modules, Daytona first in Rust, and Namespace through the TypeScript SDK;
- a conformance suite runnable against any language host or built-in provider.

Licensed under either of Apache License 2.0 or MIT, at your option.

## Standalone daemon and CLI

Build and install `drydock`, `drydockd`, `drydock-host` and `drydock-agent` together:

```sh
cargo build -p drydock -p drydock-host -p drydock-agent --locked
# Install the four binaries beside one another on PATH.
```

Create `~/.config/drydock/drydock.toml` (TOML 1.1 multiline inline tables work):

```toml
[provider.daytona]
module = "daytona"
credential = { file = "~/.config/flotilla/credentials/daytona.token" }
image = "ubuntu:24.04"
size = { cpus = 1, memory = "1GiB", disk = "1GiB" }
egress = "open"
settings = {
  organization_id = "YOUR_ORGANIZATION_ID",
  ssh_host_key = "ssh-ed25519 YOUR_VERIFIED_GATEWAY_PUBLIC_KEY",
}
```

Every drydock build uses the checked-in [tools image pin](crates/drydock/tools-image.txt),
including `cargo install` and Git dependencies. `DRYDOCK_TOOLS_IMAGE` can override
it at build time. The pin can lag the host build: after hello, the host pushes
and re-execs its current agent when fingerprints differ. Before the first image
is published the pin reads `unpublished`; publish through the operator workflow
and merge its generated pin PR before using `launch` or `prepare` (or compile
with a published image override). See the [tools image and module guide](ci/tools-image/README.md).
Daytona prepare layers the tools under `/opt/drydock` without changing the base
entrypoint or command. Launch returns after the agent hello and any required
upgrade. Its baked supervisor restarts the agent after a crash; start and resume
run bootstrap again. No Python, `flock`, or agent command setting is needed.

```sh
drydock providers
drydock launch daytona
drydock launch daytona --image registry.example/team/agent-image:current --cpus 2
drydock list daytona
drydock inspect daytona PROVIDER_ID
drydock shell daytona PROVIDER_ID
drydock destroy daytona PROVIDER_ID
# Optional warming; launch always prepares implicitly.
drydock prepare daytona --egress deny-all
```

Commands connect to the same long-lived daemon, starting the companion `drydockd`
when absent. It keeps hosts, polling, status caching and credential refresh alive
between calls. `drydockd` also runs directly in the foreground. The daemon owns
provider configuration; restart it after edits. Stop its foreground process or
send SIGTERM to the owning `drydockd`; the next CLI command starts it again.
Provider settings are opaque to
drydock and reach only the module. Credentials are `{ env = "NAME" }` or
`{ file = "PATH", json_field = "token" }`; only the resolved value is delivered
by credential refresh on the authenticated host connection.

Rigging resolves XDG paths: `XDG_CONFIG_HOME/drydock/drydock.toml`, falling back
to `~/.config/drydock/drydock.toml`. `DRYDOCK_ROOT` overrides all directories
(config under `$DRYDOCK_ROOT/config`). The socket intentionally lives at
`config/run/drydock.sock`, with a private directory and a kernel peer-UID check.
`--config PATH` and `--socket PATH` override the defaults; the socket selects the
daemon, so use distinct sockets for distinct configurations. Startup is serialized
across concurrent clients. Diagnostics go to `run/drydock.log`; each daemon
start rotates the previous run to `drydock.log.1`, replacing the older backup.
[Within-run size caps #62](https://github.com/flotilla-org/drydock/issues/62) track
bounding a single long-running daemon's log.

Defaults belong beside settings: `image`, `size = { cpus, memory, disk }`, and
`egress = "open"` or `"deny-all"`. Memory/disk accept bytes or integer quantities
such as `2GiB`/`512MiB`. Suffixes are case-sensitive; `"5 GiB"` also works,
and a numeric string such as `"12"` means bytes. Missing size fields use the module's declared smallest
size. The standalone default is Open, declared Advisory by today's modules;
low-level protocol requests retain deny-all as their default. Image tags are
resolved through the OCI registry at prepare/launch and recorded as immutable
SHA-256 references in the prepared form and local launch evidence. A key pair
is generated per vessel under `run/keys`; SSH uses that identity and the recipe's
pinned host key. Dial/Relay shells refuse with a reason until the agent supports
them. Keys and launch evidence currently remain after errors and destruction;
[safe retention/GC #61](https://github.com/flotilla-org/drydock/issues/61) tracks
cleanup without losing access after ambiguous provider outcomes. Progress is on
stderr; JSON results are on stdout.

The daemon discovers loadable modules from host `hello`, then sends only the
providers assigned to each host. A failed optional host is logged and skipped;
providers with no available module remain visible with a missing-tool reason.
The Rust host is bundled. TypeScript/Python
companions (`drydock-host-typescript`, `drydock-host-python`) become candidates
when installed beside the daemon and `node`/`uv` are detected; they are not yet
shipped in this repository. `drydockd --external-host /private/host.sock` uses
explicit external hosts instead of installed companions. Embedders may supply
managed or authenticated external TCP `HostOption`s through the crate. Binary
lookup overrides are `DRYDOCK_DAEMON_BIN`, `DRYDOCK_HOST_BIN`,
`DRYDOCK_TYPESCRIPT_HOST_BIN` and `DRYDOCK_PYTHON_HOST_BIN`.

The daemon serves `/v1/providers/{provider}/…`, including existing prepare,
provision, inspect, destroy, reach, optional operations and stream upgrades,
plus `/v1/providers`, `/launch` and `/shell` conveniences. It never exposes host
configuration or credential refresh to CLI clients. The public `ProviderApi`
trait works against the embedded `Daemon` or a Unix-socket `Client`. `/v1/events`
merges host streams with an opaque vector cursor; partial snapshots explicitly
mark other hosts' providers unavailable so they cannot imply deletion.

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

Protocol version 6 exposes masked provider diagnostics and maps permission
denials to `Refused`. It retains version 5's required `size` in every prepare request. Modules choose their
prepared key; Daytona includes size because snapshots fix sandbox resources.
Clients and hosts must upgrade together.

Protocol version 4 adds transitional observations and scoped resource measurements
with UCUM units, exact decimal money plus currency, and structured quota keys.
The host retains the last stable billing state across known progress samples;
Unknown breaks that baseline. Resource vocabulary additions require a version bump.

Protocol version 3 adds returned `CommandFailed` errors (HTTP 424, typed exit
code and redacted merged output) and `DestroyedAtProvider` causes. Version 2
clients cannot decode these new enum variants, so the exact hello gate rejects
them until upgraded. Version 3 also includes the generic host-only destination
and optional persistence, resource-quota and aggregate-usage data.

Protocol version 2 changed snapshot reconciliation semantics. Clients must check
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
- Prepare is look-up-or-build by a module-defined key (Daytona: image/tools
  digests and size); a prepared form belongs to its named provider. Hosts must
  refuse cross-provider use. Baking and upload start the agent with fixed flags,
  without per-vessel configuration.
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
serialized JSON. `Internal.provider_error` and optional
`Unavailable.provider_error` carry provider explanations to the operator. The host
masks configured credential values (including proxy placeholders) by content
before returning errors or logging them at warn level. CLI errors include the
provider, operation, category, reason, upstream HTTP status and provider message.
A Daytona 401 rejects the key; a 403 is `Refused` for the named operation and
leaves the provider ready. No additional permission error variant is needed.
Masking covers literal, JSON-escaped, percent-encoded and base64 echoes, before
limiting diagnostics to 16 KiB per field. Derived patterns are cached when a
credential is first delivered, rather than rebuilt on every failed call. Base64
matching covers the complete encoded credential; it does not detect a credential
embedded within a larger encoded payload (for example `base64(user:key)`) or
arbitrarily transformed/nested encodings. Masking covers configured credentials,
not other secret-like values such as provider-minted SSH tokens echoed in vendor
error bodies. Malformed response diagnostics omit reach recipes and guest output.
Display escapes control characters.
Empty credential values are ignored. Every nonempty value is masked, including
short placeholders; a short or common value can therefore obscure unrelated
words in a diagnostic. Use distinctive placeholders for readable diagnostics.
Registering a unique value shorter than four bytes emits a debug-level note with
its byte length, never its content.
The host masks currently configured credentials plus the 32 most recent distinct
replaced values across providers. Older historical values are evicted and their
cached patterns removed; they are no longer covered by that recent window.
An in-flight call also masks the credential it used even if that value has been
evicted. Provider removal requires a host restart. Successful response bodies,
reach recipes and guest/probe output are omitted from validation diagnostics.

Rust API compatibility: `provider_error` is now `String` (or `Option<String>`),
and its Debug output is visible. Modules return complete diagnostics to the host;
they should not log raw errors themselves. The host performs credential masking
before returning or logging them. Credential and recipe Debug output stays redacted.
`provider_state_unknown` means the vendor returned an unrecognized state; it is
an Unknown observation, not evidence that the environment stopped or disappeared.

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
ADR 0070 scenarios against exactly one provider in the daemon
provider configuration. Unix sockets, managed host binaries and authenticated loopback
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
drydock --config drydock.toml \
  conformance --provider reference --options probe.json
# Vendor modules require explicit consent to charges:
drydock --config drydock.toml \
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

```sh
drydock prepare NAME --image registry.example/team/agent-image:current \
  --cpus 2 --memory 4GiB --disk 10GiB
```

The size flags override per-provider defaults; their order is flexible.
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
details include error categories, reasons and provider messages after host
credential masking. Guest probe output and reach recipes remain redacted.

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
The sample lasts 1..60000 ms. `billing_settle_millis` (default 0, range 0..86400000)
waits after the sample ends before querying that exact window, without moving its endpoints.
Set it to the provider accounting delay; a longer sample alone does not settle it.

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

Daytona API key permissions for this module (see [Daytona API keys](https://www.daytona.io/docs/api-keys)):

| Operation | Required scope |
| --- | --- |
| Prepare (create an image snapshot) | `write:snapshots` |
| Launch, suspend, resume, export from a sandbox | `write:sandboxes` |
| Destroy | `delete:sandboxes` |
| List, inspect, poll, snapshot lookup | Read access is always granted |
| Exec and bootstrap through toolbox | Valid organization key; no separate runtime scope |
| Usage | `read:billing` or `write:sandboxes` |
| Quota | `read:limits` |

Organization membership must also match the key. Permission failures
report the exact upstream operation and message; they do not invalidate the key.

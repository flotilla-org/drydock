# Rust host

`drydock-host` loads the compiled-in reference, local and Daytona modules and serves
them through the same `/v1` API as the drydock server, with the same routes and
types (`drydock_client::api::router` over its `ProviderApi`), apart from the
server-only credential and event extensions. Common provider policy lives in
`drydock::runtime`, owned by the main server's supervisor in both `drydockd` and
an embedded `Daemon`. The TypeScript and Python hosts are to serve the same API.

```text
public API → Daemon / server Runtime → Provider traits → public API → Rust host → vendor
```

The host decodes requests, resolves providers, invokes their shared-reference
methods and serializes results. Module settings remain opaque and are validated
by the module. The host has no provider operation lock, credential store,
credential rejection state, rate budget, poller, inventory reconciliation, billing
transitions, public snapshots or event history. It never retries provider calls.

## What the server asks of a host

`PUT /v1/config` (or `PATCH` with an RFC 7396 merge patch) sets the providers the
host serves, keyed by instance name, each with a `module` and opaque `settings`.
The whole document is built before any of it applies; an entry identical to the
current one keeps its provider and any in-memory state. The server-only
`credential` key is refused. `GET /v1/hello` reports the protocol and host
versions and the loadable modules. `GET /v1/providers` and
`GET /v1/providers/{provider}` declare each provider's module, capabilities,
readiness, rate limits, optional `ports` and `observation` (the poll interval).
Every other call is the public provider route, carrying the credential to use in
its `Drydock-Credential` header; a call without one has no credential. Prepare
resolves the platform and image route before the module sees them, as the server
does. Provision answers 201 when it created the environment and 200 when it
already existed. Inspect returns the environment even when a guest probe fails,
with `egress_measured` false.

Disconnect drops provider futures. Cancellation does not prove vendor rollback:
a mutating call may have taken effect before cancellation. Relay and exec
forward stream bytes until disconnection or shutdown. Ctrl-C and SIGTERM close
streams and unlink the managed socket.

## Transport

```sh
mkdir -m 700 /tmp/drydock-example
cargo run -p drydock-host -- --unix /tmp/drydock-example/host.sock
# Existing loopback TCP: --tcp 127.0.0.1:9280 --token-file /tmp/drydock-example/token
```

The supervisor/server owns the 0700 directory; the socket is 0600. There is no
peer UID/SO_PEERCRED admission check on this managed transport. Existing
loopback TCP bearer authentication and Host/Origin restrictions are unchanged.
Main-server public network admission is unchanged.

## Validation ownership

Server unit tests and `drydock/tests/runtime.rs` exercise admission, credential
state, budgets, polling, raw evidence retention, billing and public event replay.
Host tests exercise configuration through the public routes and per-call
credentials, stream forwarding and cancellation. Managed daemon and conformance
tests run the server policy through the real Rust binary. Daytona tests retain
the replay/stand-in boundary and run policy assertions against the server Runtime.
No live paid-provider provisioning is part of these checks.

## Tools prepare and startup contract

Module authors should follow the [tools prepare/start contract and conformance
guide](../../ci/tools-image/README.md). It defines the OCI tools reference,
provider-owned prepared keys, preservation of base configuration, agent startup
and upgrade layout, and the `drydock::conformance::vessel_tools` probe. The
reference module supplies explicitly simulated guest evidence; stock-Ubuntu OCI
acceptance runs separately in CI.

Capabilities list `platforms` and `image_routes`, the ways a vessel image
reaches the provider, preferred first: `provider_push` (protocol and credential
lifetime), `registry_pull` (auth kind, how the credential is registered, whether
digest references work) and `remote_build` (input kind, multi-stage support).
Each route states whether the tools layer is added by the provider or by the
host. Clients choose by these properties and their own policy, never by
provider name. The server resolves each prepare request's platform and `route`
before the module sees them (omitted means the first declared; an undeclared one
is refused). Modules read them with `prepare_platform` and `prepare_route`, and
must record the platform in the prepared form, or the server returns `Internal`.
A platform, image size or push credential a provider cannot take is the typed
`image_refused` error, whose `refusal` carries a stable cause.

Every host build uses drydock's checked-in bootstrap tools pin unless a build-time
override is supplied. The pin can be older than the host: use the agent client's
`connect_current` handshake to push/re-exec the current binary after mismatched
hello, then verify hello before configuration. Before the first image publish,
prepare/launch explain how to publish and merge the pin; see the guide above.

## Local module

`local` runs vessels as child processes on the host's own machine, so vessel
paths can be exercised end to end without a cloud provider or a container
runtime. It is a test fixture, not a sandbox: a vessel shares the host's
filesystem, network and users, and nothing is isolated.

```toml
[providers.local]
module = "local"
image = "ubuntu@sha256:…"   # recorded, never pulled
settings = { root = "/tmp/drydock-local" }
```

No `credential` is needed: a provider configured without one and reported ready
by its host holds none to deliver. Settings are both optional. `root` is where
environment directories live (default: `local` under drydock's state directory)
and `agent` is the `drydock-agent` build to run. Without `agent` the build is
found the way drydock finds the one it pushes: `DRYDOCK_AGENT_BIN_<OS>_<ARCH>`,
`DRYDOCK_AGENT_BIN`, then `drydock-agent` beside `drydock-host`. A provider with
no build reports `missing_tool`.

- **Prepare** records the image reference, tools digest and the host's platform
  (the only one declared). Nothing is pulled.
- **Provision** makes `<root>/<id>/`, copies the agent to its `opt/drydock/`, and
  starts it with its socket at `<root>/<id>/run/drydock/agent.sock`, in a session
  of its own. It returns once the agent answers hello. The id comes from the
  label, so a repeated label is the same environment. The agent is the vessel's
  own copy, so an upgrade pushed by drydock never touches the installed build.
- **Reach** is the relay: the host connects to that socket, and exposures work
  through the agent like on any provider.
- **Suspend** kills the agent and everything in its session and keeps the
  directory; **resume** starts the agent again. Memory and processes are not kept.
- **Destroy** kills the agent and its session, then removes the directory. Anything
  that started its own session escapes.
- **Egress** is declared open and advisory. A deny-all request is refused with a
  reason, because the host's network cannot be restricted per vessel.
- **Capabilities** declare no usage, quota or export. Conformance reports the
  checks that follow from that as not applicable.

Each agent's output is appended to `agent.log` in its directory, unrotated.
Process tracking reads procfs, so the module is ready only on Linux (elsewhere
it reports `missing_tool`). Nothing is held in memory: environments are found by their directories, so they
survive a restart of the host, and agents keep running meanwhile. An agent that
died is reported stopped (`guest_halted`) and is started again by resume. The
workspace root declared is `root`; vessels share one filesystem, so a client must
pick a distinct directory below it for each.

## Daytona module

The binary also registers `daytona`; embedders can register `daytona::DaytonaModule`.
It uses the published [REST](https://www.daytona.io/docs/openapi.json),
[toolbox](https://www.daytona.io/docs/toolbox-openapi.json) and
[analytics](https://www.daytona.io/docs/analytics-openapi.json) contracts, checked
2026-10-20. Configuration example (no credentials in settings):

```json
{
  "providers": {
    "daytona-eu": {
      "module": "daytona",
      "settings": {
        "organization_id":"YOUR_ORGANIZATION_ID",
        "region":"eu", "tier":1,
        "ssh_host_key":"ssh-ed25519 YOUR_VERIFIED_GATEWAY_PUBLIC_KEY"
      }
    }
  }
}
```

The organisation API key arrives in each call's `Drydock-Credential` header and
is sent as the bearer token on REST, toolbox and analytics calls, using the
host's injected HTTP client. There are no module retries or ambient credentials.
The key needs sandbox creation/modification/deletion, snapshot creation and billing
read access. API-key scope is the organisation; this is not isolation between
sandboxes in that organisation.

Daytona declares two image routes. The default is `provider_push` with the
tools layer added by the host, for images in registries Daytona cannot reach.
The host reads the base and tools manifests for `linux/amd64` (with
`PrepareRequest.image_pull`, sent only to the base's registry, for a private
base), appends the tools image's layer to the base manifest (a manifest and
blob operation: no container build, no local Docker), mints push access with
`GET /docker-registry/registry-push-access`, copies the blobs into Daytona's
registry in `push_chunk_bytes` requests (default 16 MiB), pushes the manifest,
waits until a pull by digest succeeds, and creates the snapshot from
`imageName: <registry>/<project>/drydock-vessel@sha256:…` with no `buildInfo`.
Images above `max_image_gib` (default 20, Daytona's default snapshot maximum;
compressed size is the lower bound checked), platforms other than amd64 and
push access that expires mid-upload are typed refusals.

On this route the host itself contacts the registries the request names, and
their token realms, over HTTPS. It applies no registry allowlist or address
policy, because lab registries usually sit on private networks. Prepare callers
are authenticated host clients and are trusted to name registries. A pull
credential goes only to its registry's origin, or to Docker Hub's
`auth.docker.io` token service for `docker.io`.

The fallback, `registry_pull` with the tools layer added by the provider, builds
the snapshot with `buildInfo.dockerfileContent`: the pinned base plus
`COPY --from` the pinned tools image's `/opt/drydock/`. Daytona's builder pulls
both references itself, so a private registry must first be registered for the
organisation through `POST /docker-registry` (`name`, `url`, `username`,
`password`; needs `write:registries`). Request it with `--image-route
registry_pull` or `route` on the prepare request.

Neither route sets entrypoint, command or init. The build selects the tools
reference through `crates/drydock/tools-image.txt` (or `DRYDOCK_TOOLS_IMAGE` at
build time); the `unpublished` pin refuses preparation until the first publish.
Both references must be immutable SHA-256 image references.

The snapshot name includes the digest pair, platform and size, not the route:
both routes produce the same filesystem. Prepare reuses it and waits
for `active`, for up to four minutes per call. Provision inherits the snapshot's
resources and refuses a size that differs from the prepared key. Requests must
use whole vCPU and GiB within the default 4 vCPU, 8 GiB RAM and 10 GiB disk cap.

Provision writes `flotilla.label`, uses a deterministic unique sandbox name,
disables auto-stop/auto-pause and auto-delete, waits for started, then executes
`/opt/drydock/drydock-agent --supervise --socket /run/drydock/agent.sock`.
The baked binary detaches a supervisor, uses an OS file lock to make concurrent
bootstraps converge, and restarts the fixed agent after a crash. It requires
neither Python nor util-linux `flock`. PID 1 remains Daytona's daemon.

Toolbox bootstrap has a 25-second execution budget; ordinary exec/probes get
20 seconds. Bootstrap starts supervision; it does not claim agent readiness.
`drydockd` waits up to 60 seconds for the agent's `Client::connect_current`
handshake over the SSH gateway before returning launch success. It upgrades an
older tools agent to the build for the platform recorded in the prepared form,
then verifies the current hello. Daytona declares only `linux/amd64`: its
sandboxes run on x86_64, and its snapshot API takes no platform, so the push
route composes the amd64 manifests, both `FROM` lines of the fallback's
Dockerfile carry `--platform=linux/amd64`, and the snapshot name includes the
platform. Lookup order for platform `<os>/<arch>`:

1. `DRYDOCK_AGENT_BIN_<OS>_<ARCH>` (for example `DRYDOCK_AGENT_BIN_LINUX_ARM64`);
2. `DRYDOCK_AGENT_BIN`, only when the guest's platform is the host's own;
3. `drydock-agent-<os>-<arch>` installed beside `drydockd`;
4. the sibling `drydock-agent`, only when the guest's platform is the host's own.

Each variable holds one path. With no build for the prepared platform, launch is
refused before provisioning with the platform and the file or variable that
would supply it. A hello reporting a different platform is refused naming both;
a hello without a platform (an agent older than platform reporting) is not
checked, and the prepared platform's build is pushed.
The gateway refuses remote Unix-socket forwards; drydock needs only a local
forward to the agent socket, and one HTTP/2 connection through it carries
requests, byte streams and the vessel's outward connections. If
the handshake never succeeds, launch fails with the last attempt's error (SSH
user redacted), and `drydockd` logs each failed attempt to stderr. A failed bootstrap leaves a labelled
resource discoverable for retry or cleanup. Duplicate labels re-adopt the existing
resource; size or egress mismatches (including missing policy evidence) are refused
with guidance to use a new label. They never change the existing resource's policy.
Vendor name uniqueness arbitrates concurrent creates, so one slow startup does not
hold a provider-wide creation mutex.

Suspend is stop, resume is start plus bootstrap. The whole filesystem persists;
memory and resident processes do not. `suspend_preserves_memory: false` declares
this explicitly. There is no pause operation on the container class. Resume
starts supervision again; the agent removes its stale socket. Repeated resume of
an already running sandbox keeps the existing singleton supervisor.
The deterministic resume token is an id-bound continuation marker, not an access
credential; every call still requires the organisation API key. It uses `Secret`
because that is the protocol's resume-token representation.

Every reach call requests a fresh five-minute SSH token. Daytona authenticates it
as the gateway username, so `Reach::Ssh.user` now uses the redacting `Secret` type
(the JSON is still a string). Supply the SSH gateway's host public key verified
out of band: the mint route does not supply one. `ssh_endpoint` defaults to
`ssh.app.daytona.io:22`; no host key is discovered through unauthenticated scanning.
Never log or record a mint response or the serialized reach recipe.

Egress always supplies exactly one networking control, avoiding Daytona's default
allowlist: `networkBlockAll: true` for deny-all, `networkAllowList` for IPv4 CIDRs
(or `0.0.0.0/0` for Open), and `domainAllowList` for host-only requests. Native
domain rules follow Daytona's DNS updates; the module does no DNS pinning or
AAAA rejection of dual-stack names. IPv6 literals/CIDRs, port-specific entries
and mixed domain/CIDR requests are refused. Label retries compare normalized
requested policies, not the results of a new DNS lookup.

The provider capability remains Advisory, including on low tiers where vendor
organization restrictions may take precedence. Individual running sandboxes
become Enforced only after an operator-configured `egress_probe` executes as root
and proves blocked unlisted canary and raw DNS, plus successful listed access
when the policy has listed destinations:

```json
{"uid":0,"listed_direct":true,"unlisted_canary":false,"raw_dns":false}
```

For deny-all the command receives `DRYDOCK_PROBE_DENY_ALL=1`; `listed_direct`
is unnecessary. `tools/egress-probe.py` supports that mode. The probe must test
real externally verified reachable services; never print constants as evidence.
Provision, server resume completion and explicit inspect measure the claim. Cheap
list/poll calls do not exec. Every Daytona observation carries an opaque effective
policy fingerprint; the server retains measured evidence while running with the
same fingerprint, and invalidates it on policy change, stopped/gone/unknown state
or disappearance. A changed-back policy requires another measurement. Providers
without policy fingerprints retain the conservative 60-second fallback TTL.
A negative proof is Advisory. Probe command/transport/malformed-proof failures
leave successful provision/resume Advisory and emit a tracing diagnostic with the
typed error class; explicit inspect still returns the typed error. Open/nonrunning
rows are Advisory. Transport outages return Unavailable, not adaptor-bug Internal.

Observation polls every 30 seconds, with complete cursor pagination, provider
`updatedAt` timestamps and actual granted sizes (GiB converted to bytes). The main server
owns all state diffs and event emission. Error reasons map OOM/eviction to loss
causes, unreachable to host-unreachable, and other provider errors to API-error;
known progress maps to `Transitioning` phases; unestablished states alone are
Unknown. The main server keeps stable billing state across progress samples. No webhooks.

The module declares per-organization Tier 1–4 general/create/lifecycle limits
(10k/300/10k through 50k/600/50k per minute). Optional `rate_limits` overrides
accept explicit provider `RateLimit` rows for Enterprise contracts. A 429 reads
`Retry-After-{throttler}`, falling back to the exhausted bucket's
`X-RateLimit-Reset-{throttler}` remaining seconds (or plain Retry-After). It never retries.
Unused cached rate-window state was removed: the server does not yet dynamically
adjust its admission budget using successful responses' observed limit/remaining
counters. That is an explicit gap, not global quota coordination. Completion
waits, pagination, toolbox routing lookups and probes consume additional calls
outside route admission; sharing an organization also shares these limits.

Quota reports structured region/class/resource keys with UCUM capacity units.
Analytics reports organization-scoped neutral resource measurements, integrated
UCUM units and exact decimal cost with currency code. Analytics GBSeconds are
interpreted as reserved GiB integrated over time, using Daytona's documented
[resource units](https://www.daytona.io/docs/en/sandboxes/#resources), and converted
to By.s with 2^30. This interpretation of the analytics field naming remains a
live metering acceptance assumption. Money is parsed from the
original decimal lexeme before numeric conversion and uses the documented USD
denomination, without inventing a vendor currency field. `environment_hours` is
filled from the documented per-sandbox usage totals and usage-period routes,
clipping each size period to the requested window. Missing `endAt` denotes an
ongoing period clipped to the earlier of the window end and the current time;
zero-CPU periods are skipped. Scope IDs are opaque.
Conformance uses size-hours when measurements are aggregate and isolated CPU
measurements when explicitly environment-scoped. Size-hours are still grouped
by size across the organization: use an otherwise idle organization or a unique
size for live transition attribution; aggregation cannot distinguish unrelated
sandboxes with the same size. Empty usage windows yield zero size-hours. Aggregate measurements and per-sandbox
periods are separate sequential reads, not an atomic provider snapshot; eventual
updates or ongoing state changes can make them disagree. Compare settled windows
with conformance options `billing_sample_millis` (default 25, range 1..60000)
and `billing_settle_millis` (default 0, range 0..86400000).
For both running and suspended checks,
conformance records the start, waits the sample duration, records the end, then
waits the settle duration before querying that exact period. This wait is separate
from the request/event deadlines in `timeouts`, including host-fixture billing
checks, and adds that duration to each billing check. It keeps the sandbox
in the sampled lifecycle state while waiting. For example,
`"billing_sample_millis": 60000, "billing_settle_millis": 120000` reads a roughly
60-second window that ended at least two minutes before the usage request.
Choose the settle duration to cover vendor accounting delay during live acceptance.
The CLI announces a nonzero per-sample settle delay on stderr; stdout remains the
JSON conformance report.
Usage currently fans out sequentially across all IDs returned for the organization/window;
individual-call budgeting and bounded fan-out are tracked in drydock#35.

For operator acceptance, configure a real baked agent image, pinned gateway key,
matching root/network/reach probes, and run conformance including egress. Retain
`usage.measurements.cost` from the JSON report as spend evidence. This crew's
stand-in spend is **$0**; live conformance and live spend are operator acceptance.

Optional HTTPS base URLs `api_url`, `toolbox_url`, `analytics_url` must end in `/`
and contain no URL credentials, query or fragment. REST and analytics default to Daytona's public endpoints. Toolbox routing uses
each sandbox's required `toolboxProxyUrl` plus sandbox ID; `toolbox_url` is an
explicit override only. Deployments requiring a fixed toolbox destination can
set that override instead of following the API-supplied proxy route.

Daytona toolbox `/process/execute` returns a buffered, merged `result` and an
`exitCode`; it supplies neither separate stderr nor a live stdin/output stream.
Fallback exec preserves that contract: successful merged output is exposed through
the Drydock byte stream after completion; nonzero exits return `CommandFailed`
(HTTP 424) with a typed `exit_code` and sensitive `output` wrapped in `Secret`.
This is a diagnostic runner, not an interactive terminal. Empty output is valid.
Snapshot activation is submitted once and then observed by paced reads. Terminal
sandbox start failures are returned immediately. A provider-reported `destroyed`
without eviction metadata is `DestroyedAtProvider`, rather than claiming that the
guest powered itself off; confirmed Drydock deletion still uses the server's
`DestroyedByRequest` event cause.

The module's bounded completion waits are distinct from the server's observation
poller: prepare permits up to 120 successful state reads at two-second intervals,
and start/stop permit up to 60. A failed GET exits immediately; the caller owns
failure retries. These internal reads do not currently consume separate server
route-budget slots. That is a known limitation under the required rate-window
review work, not an additional module observation/reconciliation loop.

Transport loss during mutation
reports unavailability with an uncertain-outcome reason and never proves rollback;
malformed host responses are internal adapter errors rather than transient outages.

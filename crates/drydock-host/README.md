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
readiness, rate limits, optional `ports` and `ways_in` (the poll interval, and
any vendor webhooks). `POST /v1/providers/{provider}/event` reads one vendor
delivery the server took from its relay into the observations it carries; a
module without a webhook way in refuses it.
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
- **Destroy** kills the agent and everything it started, then removes the directory,
  read-only contents (such as the agent's artifact store) included. Where the host
  may create cgroups (cgroup v2, writable, kernel 5.14 or later; often not inside a
  container) each vessel gets one and `cgroup.kill` ends it whole, so nothing
  escapes. Elsewhere the vessel is the session its agent leads, and anything that
  started its own session escapes. Either way only what is known to be the vessel's
  is signalled: the agent is identified by its start time and PID namespace, not by
  a PID read from a file, so a recycled PID, or a directory left by an earlier life of
  the machine, signals nothing. The scope is recorded in `agent.scope`.
- **Egress** is declared open and unfiltered. A deny-all request is refused with a
  reason, because the host's network cannot be restricted per vessel.
- **Capabilities** declare `host_processes`: the vessels are processes of the host's
  machine, with its user and PID namespace and no isolation, so the module is not a
  sandbox and nothing may treat it as one. They declare `host_filesystem`: a guest path is a host path, so a
  client lays each vessel out below paths it can write, never at fixed guest
  locations such as `/opt`. They declare `exclusive_label`, since the id comes
  from the label and creation is serialized. They declare no usage, quota or
  export; conformance reports the checks that follow from that as not
  applicable.

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
        "ssh_host_key":"ssh-ed25519 YOUR_VERIFIED_GATEWAY_PUBLIC_KEY"
      }
    }
  }
}
```

The module translates: each verb is Daytona's own operation, and each answer
is what Daytona said. Rows carry Daytona's own state name, its `errorReason`
and its labels in `vendor`, beside the coarse `state`. It declares no
guarantee beyond `token_is_id`: drydockd adds waiting, idempotence and
ownership as the instance's `semantics` and `ownership` ask (see the
top-level README). Sandboxes are named by Daytona; a label is a tag, and
provisioning a label twice makes two sandboxes.

| Verb | Daytona calls |
|---|---|
| prepare | `GET /snapshots/{name}`, then `POST /snapshots` when absent (or `POST .../activate` when inactive); unavailable until `active` |
| provision | `POST /sandbox` |
| list | `GET /sandbox`, every page, every state (including `destroying`) |
| inspect | `GET /sandbox/{id}` |
| destroy | `DELETE /sandbox/{id}` |
| suspend / resume | `POST /sandbox/{id}/stop` / `start`; the resume token is the id |
| reach | `POST /sandbox/{id}/ssh-access` |
| exec | toolbox `POST /process/execute` |
| files | toolbox `POST /files/upload-v2`, then `POST /files/permissions` |
| quota | `GET /organizations/{id}/usage` |
| usage | analytics `GET /organization/{id}/usage/aggregated` |
| push access | `GET /docker-registry/registry-push-access` |

Daytona answers 409 while a sandbox's state change is in progress (unavailable,
retryable) and 400 when the request does not fit the sandbox's state, for
example a stop of a stopped sandbox (refused, in Daytona's words).

The organisation API key arrives in each call's `Drydock-Credential` header and
is sent as the bearer token on REST, toolbox and analytics calls. The key needs
sandbox creation/modification/deletion, snapshot creation and billing read
access. API-key scope is the organisation; this is not isolation between
sandboxes in that organisation.

Settings, with their defaults: `api_url` (`https://app.daytona.io/api/`),
`analytics_url` (`https://analytics.app.daytona.io/`), `toolbox_url`
(`https://proxy.app-eu.daytona.io/toolbox/`, the `eu` region's proxy, which
Daytona also reports on each sandbox), `region` (`eu`; set `toolbox_url` to
match), `ssh_endpoint` (`ssh.app.daytona.io:22`), `max_cpus` (4),
`max_memory_gib` (8), `max_disk_gib` (10), `rate_limits` (Tier 1: 10,000
requests and 300 creates a minute), `max_image_gib` (20), `push_chunk_bytes`
(16 MiB), `push_credential_seconds` (3600), `ssh_token_minutes` (5),
`upload_seconds` (300), `exec_seconds` (20), `poll_seconds` (30) and
`page_size` (200). Bases must be HTTPS and end in `/`.

Daytona takes upload bootstrap (`BootstrapRoute::Upload`): a snapshot is the
base image alone, and drydockd puts its own agent build in each sandbox through
the files port, then runs
`/opt/drydock/drydock-agent --supervise --socket /run/drydock/agent.sock`. The
upload is one request with `upload_seconds` as its deadline. The module starts
no agent itself.

Daytona declares two image routes, both `tools_layer: upload`. The default is
`provider_push`: drydockd copies the base's `linux/amd64` image into Daytona's
registry with access the push-access port mints, and the module creates the
snapshot from that `imageName`. The fallback, `registry_pull`, has Daytona build
the snapshot from a one-line Dockerfile pinning the base to the platform; a
private registry must first be registered through `POST /docker-registry`.
The snapshot name includes the image digest, platform and size, not the route
and not the tools pin, so a pin bump makes no new snapshot. A sandbox gets the
snapshot's resources; `granted_size` reports them.

Provision labels the sandbox `flotilla.label=<label>`, and, on a shared
account only, `drydock.provider=<instance>`. Daytona names the sandbox; no name
derives from the label. It disables auto-stop, auto-pause and auto-delete.

Egress always supplies exactly one networking control, avoiding Daytona's default
allowlist: `networkBlockAll: true` for deny-all, `networkAllowList` for IPv4 CIDRs
(or `0.0.0.0/0` for Open), and `domainAllowList` for host-only requests. IPv6,
port-specific entries and mixed domain/CIDR requests are refused. The capability
declares Daytona's documented egress model; every row is Advisory, unmeasured,
with an opaque policy fingerprint.

Usage is the organization's aggregate for the period, as Daytona's analytics
reports it, in one call: GBSeconds converted to By.s with 2^30, and the price
passed through as Daytona's own number text, in USD. Daytona reports no
per-size hours, so `environment_hours` is empty.

Toolbox `/process/execute` returns a buffered, merged `result` and an
`exitCode`; nonzero exits return `CommandFailed` with the output in `Secret`.
Every reach call requests a fresh SSH gateway token; supply the gateway's host
public key verified out of band.

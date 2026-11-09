# Adding a provider

How to add a provider module to drydock, as the code stands today. It was
written while adding the Docker Cloud Sandboxes module
([`docker_sandboxes.rs`](../crates/drydock-host/src/docker_sandboxes.rs)), which
is the worked example throughout. The Runtime, E2B, Tensorlake and Daytona
modules in the same directory are the other Rust examples; Namespace and Modal
are the TypeScript ones.

A module is a translator. It turns drydock's verbs into the vendor's API calls
and reports what the vendor said. Everything else (waiting, idempotence,
ownership, polling, retries, credential state, the agent's upload and start)
belongs to drydockd, and the module must not do it.

## 1. Choose the host language

There are two hosts:

- **Rust**, in [`crates/drydock-host`](../crates/drydock-host). Modules are
  compiled in and share the [`kit`](../crates/drydock-host/src/kit/mod.rs): an
  HTTP client for the vendor's API with typed answers and a status table
  ([`kit::api`](../crates/drydock-host/src/kit/api.rs)), lifecycle state
  tables, prepare's checks, guest commands (`kit::guest::Guest`, its
  `run_argv` overridden where the exec takes an argv, as Docker's does), and a
  WebSocket dialer
  ([`drydock_transport::websocket`](../crates/drydock-transport/src/websocket.rs)).
- **TypeScript**, in [`hosts/typescript`](../hosts/typescript). Each module is
  a thin bridge over the vendor's TypeScript SDK. Read its
  [`AGENTS.md`](../hosts/typescript/AGENTS.md) first.

How to decide:

1. **Bootstrap comes first.** The TypeScript host has no exec or files ports
   yet (drydock#85). Without them drydockd cannot upload and start the agent
   (`BootstrapRoute::Upload`), so a TypeScript module must place and start the
   agent itself, as Namespace and Modal do. If the vendor's sandboxes start
   the agent only through an exec call, as Docker's do, use Rust.
2. **Then the API.** A REST API with a published OpenAPI document suits the
   Rust kit. An API that is only practical through the vendor's SDK (gRPC,
   Connect, a custom WebSocket protocol) suits TypeScript.
3. **Check what the SDK does by default.** Modules never retry or wait. An SDK
   that retries, waits or refreshes tokens on its own must have each of those
   turned off. Docker's TypeScript SDK retries safe requests twice by
   default, and renews its own access token.

Docker has a TypeScript SDK, but its REST API is fully specified, and Docker
starts the agent through exec. So the Docker module is written in Rust.

## 2. The module's surface

A Rust module is two types:

- a `Module` (the factory), whose `configure` reads the instance's settings
  and returns a `Provider`;
- the `Provider`, which implements the verbs in
  [`drydock-provider`](../crates/drydock-provider/src/lib.rs): `capabilities`,
  `ways_in`, `prepare`, `provision`, `list`, `inspect`, `destroy`, `reach` and
  `relay`. Optional ports (`Exec`, `GuestFiles`, `SuspendResume`, `QuotaOperation`,
  `UsageOperation`, `ExportOperation`, `PushAccessOperation`, `VendorEvents`)
  are separate traits, returned from `operations()` when the vendor has them.

Register the module in two places: `pub mod` in
[`lib.rs`](../crates/drydock-host/src/lib.rs), and `registry.insert` in
[`main.rs`](../crates/drydock-host/src/main.rs). The registry key is the
`module` name in drydock's configuration.

### What the module translates

- **One vendor call per verb**, where the vendor allows it. Docker's verbs
  map like this:

  | Verb | Docker calls |
  |---|---|
  | prepare | none: a sandbox runs the image by digest |
  | provision | `POST /v1/sandboxes` |
  | list | `GET /v1/sandboxes`, every page |
  | inspect | `GET /v1/sandboxes/{id}`, `GET /v1/sandboxes/{id}/network-policies` |
  | destroy, suspend, resume | `GET /v1/sandboxes/{id}` for the etag, then `DELETE`, `POST …/stop` or `POST …/start` |
  | exec, files, relay | `POST /v1/sandboxes/{id}/endpoint-credentials`, then the sandbox's own endpoint |

  A second call is right when the vendor requires it, for example Docker's
  etag precondition on every change. A second call that only makes the answer
  look like another vendor's is not.
- **The vendor's state, through a table.** Each vendor state name maps to an
  `Observation` in a `StateTable`, read with `kit::observe`. A name the table
  lacks reads as `Unknown`.
- **The vendor's own words, in `VendorState`.** Every row carries the
  vendor's state name, its explanation when it gives one (Docker's `failure`
  message), and its tags. Absent means not stated: `tags: None` when the row
  has no labels, `granted_size: None` when the vendor does not state all
  three of CPU, memory and disk, `timestamp: None` when it gives no time for
  the state. A stop cause goes on only when the vendor says who stopped the
  sandbox. Docker does not, so `stopped` has no cause.
- **Refusals in the vendor's terms**, before any call, for what the vendor
  cannot express. For example: *"Docker Sandboxes installs a sandbox's own
  network policy beside the account's default layer, which allows every
  network, so it cannot deny egress"*. A policy field the vendor accepts is not
  proof that it applies: check what the vendor reports as installed before
  declaring a shape. A vendor that sizes in fixed shapes gets
  them as a table in the module, and a size outside them is refused naming
  them; `smallest_size` is the smallest shape. Never widen a request to
  something the vendor can express, and never round a size to a shape.
- **The vendor's errors**, through `Api::classify`. Start from
  `Failure::standard` (401 rejects the credential, 403 is a refusal, 404 not
  found, 429 rate limited, 5xx unavailable) and override only what the vendor
  says differently. Docker overrides two things: a `QuotaFailure` detail is
  exhausted quota, and 412 (the etag moved on) is unavailable.
- **Quirks of the wire format.** Docker answers in protobuf's JSON form, which
  leaves out empty lists and zero numbers. `Api::paged` reads a page without
  its rows key as no rows. A field that can be zero takes `#[serde(default)]`
  (an exec answer without `exitCode` exited 0), and a 64-bit integer, a
  string in protobuf, is a `kit::api::IntText`.

### What the module leaves to drydockd

- **Waiting.** Return when the vendor answers. drydockd's `settle` option
  waits for the state.
- **Idempotence.** A stop of a stopped sandbox gets the vendor's answer.
  drydockd's `idempotent` option makes repeats succeed.
- **Ownership.** On a `shared_account` (`config.ownership`), tag what you make
  with `OWNER_TAG` and report tags in `VendorState`; drydockd filters lists
  and refuses changes to other instances' environments. On an
  `owned_account`, tag nothing. Filter lists by tag only if the vendor's own
  list call filters (Runtime's does; Docker's does not).
- **Polling and events.** Declare a way in; drydockd lists and diffs.
- **Retries.** Never retry. Classify the failure and return it.
- **The agent.** On `BootstrapRoute::Upload` drydockd puts its own agent
  build in the guest through the files port and starts it through exec. The
  module starts no agent.
- **Image staging.** A private image reaches a public-pull vendor through a
  staging registry drydockd copies it to (`pull_from`), not through the module.

## 3. Capabilities, `Semantics` and ways in

`capabilities()` is the module's declaration. State only what the vendor
does:

- **Lifecycle.** `suspend_resume` when the vendor can stop and start a
  sandbox; `suspend_preserves_memory` when its stop keeps memory. Docker's
  stop hibernates, and resumed with memory in a trial.
- **Bootstrap and reach.** `bootstrap: Upload` needs the exec and files
  ports. `agent_tcp_port` asks drydockd to start the agent listening on
  loopback for a dial reach (E2B, Runtime). Without one, reach is a relay:
  `reach` returns `Reach::relay(name, id)` and `relay` returns a byte stream
  to the agent's socket. Docker's relay runs `drydock-agent --bridge` as a
  process and carries its stdin and stdout over Docker's interact WebSocket,
  through `kit::relay` given Docker's `Framing`.
- **Platforms and image routes.** `platforms` lists what the vendor runs,
  first preferred. `image_routes` says how an image gets in. Docker takes a
  public image by digest: `RegistryPull` with `Anonymous` auth, credential
  registration `NotRequired`, and `tools_layer: Upload`. In `prepare`, call
  `kit::image::check_prepare`, which refuses routes the module lacks,
  undigested references and other platforms. In `provision`, call
  `check_prepared`.
- **Egress.** `egress.model` is the vendor's documented claim: the shapes it
  can apply, where it enforces them, documented side effects,
  `mutable_while_running`, and the documentation it rests on (`sources`). A
  row is `Enforcement::Advisory` unless `inspect` reads the vendor's own
  per-sandbox statement that the policy is in force. Docker's `inspect` reports
  `Enforced` only when the sandbox's installed policy is deny-all, holds the
  sandbox's own (`attached`) document, and allows nothing from another layer: a
  deny-all mode has been seen beside a default layer allowing `**`. Docker states that policy only for a
  running sandbox (it answers 409 otherwise), so inspect reads it only then; in
  any other state egress is not stated: `Advisory`, with no `egress_policy`.
  A call that fails for a state the sandbox can be in breaks suspend, destroy
  and cleanup, which inspect between steps. An account's default policy alone is not
  enough: a trial saw it not apply. `egress_policy` is the vendor's identity
  for the installed policy (Docker's `revision`), or a digest of the rules the
  vendor states.
- **`Semantics`** says what the vendor's operations already guarantee. Each
  flag defaults to false, and drydockd adds what the instance's
  `semantics` option asks for (see [Semantics drydockd adds](../README.md#semantics-drydockd-adds)).
  Docker declares only `token_is_id`, because it starts a sandbox by id
  alone.
- **`exclusive_label`** only when a second provision of a label returns the
  first environment. Docker's labels are tags, so it is false.
- **`ways_in`.** `WayIn::Poll { interval_ms }` from a `poll_seconds` setting.
  A vendor with webhooks also declares `WayIn::Webhook` and implements
  `VendorEvents`; see the Tensorlake and E2B modules.
- **Usage, quota, export** are false unless the vendor has an API for them.
  Usage is passed through as the vendor reports it, or not declared. It is
  never derived.

## 4. Credentials and settings

**The credential** arrives with each call in `Credentials`. The host keeps
none between calls. drydockd reads it from the instance's `credential` (a
token file, an environment variable, or a JSON file). A JSON object without
`json_field` arrives as one compacted line. Use `kit::api::Api` with
`Auth::Bearer` or `Auth::Header(name)` to send it. Never put a secret in
settings.

Docker takes `{"username": …, "personal_access_token": …}`: the module asks
Docker Hub for an access token, as Docker's SDK does, and
`kit::exchange::Exchanged` holds it until a minute before it expires. This is
the only state the module keeps. Docker's API rejects a personal access token
sent as the bearer, so the module rejects any other credential form before a
call. Offer only the forms a live run has shown the vendor takes.

Commands and files go to each sandbox's own endpoint (`core.endpoint.uri`) with
a short-lived credential the management API issues for that sandbox. The
module builds an `Api` for that endpoint per call.

**Settings** are a struct with `#[serde(default, deny_unknown_fields)]` and
a `Default` impl. Every key has a default. `configure` refuses zeroes where a
zero makes no sense. Endpoints are settings, so a test or a self-hosted
vendor can change them; `Api::new` accepts HTTPS URLs only. Docker's
settings are `api_url`, `token_exchange_url`, `poll_seconds`, `exec_seconds`
and `upload_seconds`.

**Document both** in [`provider-credentials.md`](provider-credentials.md):
what the credential is, how to mint it with the least access, the calls the
module makes, and the vendor's quirks an operator will meet.

## 5. Tests

A vendor module ships without tests of its vendor calls. A hand-written
stand-in of the vendor (a scripted `HttpClient`, an in-process WebSocket
server) and the module encode the same assumptions twice and check them
against each other, so they prove nothing about the vendor. Don't write one.

The module's check is the operator's live `drydock conformance` run (§6).
Tests of how drydock talks to a vendor will replay interactions recorded
against the real vendor, once that facility is designed; until then, none.

Run what CI runs:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

No test calls the vendor. Live runs are the operator's.

## 6. Conformance

`drydock conformance` runs the ADR 0070 scenarios against one configured
provider through drydockd (see [Conformance](../README.md#conformance)).

**Against a stand-in.** The stand-in is the `reference` module, which needs no
`--live`. Run it first to learn the runner and its options file:

```toml
[providers.reference]
module = "reference"
```

```sh
drydock --config drydock.toml conformance --provider reference --options probe.json
```

A vendor module does not run against a stand-in of its vendor. The live run
is its check.

**Live.** This runs on the operator's account and costs money. It needs
`--live`. Configure the instance with its credential and a size the vendor
takes, for example:

```toml
[providers.docker]
module = "docker_sandboxes"
credential = { file = "~/.config/flotilla/credentials/docker-sandboxes.json" }
image = "ubuntu@sha256:…"
size = { cpus = 1, memory = "2GiB" }   # Docker's Micro shape; no disk: Docker takes none
egress = "open"
semantics = { settle = true, idempotent = true }
```

```sh
drydock --config drydock.toml conformance --provider docker --options docker-probe.json --live
```

- `settle` must be on for an upload-bootstrap provider whose provision
  answers before the sandbox runs. Otherwise drydockd uploads no agent, and
  the reach check is reported not applicable.
- `reach_probe` is an executable that takes the reach recipe on stdin and
  round-trips bytes with the agent. `tools/recipe-probe.py` speaks only the CI
  echo fixture's protocol, so it cannot be used here.
- The egress check runs only for an environment reported `Enforced`. It needs
  a deny-all request with exactly one destination, and `tools/egress-probe.py`
  in the guest, run through exec as root. Docker takes open egress only, so
  its runs report the check not applicable; whether a deny-all request was
  really applied needs a hand check of the vendor's installed policy.
- Use a unique `label` and an idle account. Check the report's `cleanup`
  verdict. A failed cleanup means a sandbox may still be running and billing.

## 7. What the PR reports

- **The host language and why.**
- **The verb-to-call table**, and the vendor's documentation it rests on.
- **What the module declares**, and what it refuses, in the vendor's words.
- **The module's line count**, beside the other modules'.
- **Findings from following this guide**: boilerplate, shared gaps and
  unclear steps, listed and left for their own changes.
- **What only a live run can settle**: anything the documentation leaves
  open, for the operator's conformance run.
- **The credential entry** in `provider-credentials.md`.

# TypeScript language host

`drydock-host-typescript` implements the current `openapi.json` protocol in Node.
One process loads multiple modules and independently configured provider instances.
The `reference` module stores resources in memory, echoes relay and `exec ["cat"]`,
and supports `exec ["echo", ...]`, suspend/resume, export, usage and quota. Its
`fixture` option enables simulated guest evidence for the shared conformance suite;
it never creates a guest or accesses vendor credentials.

## Build, validate and package

Runtime: **Linux, Node >=24.18.0**. The Unix listener uses Linux `SO_PEERCRED`
through Koffi; unsupported platforms fail closed. Koffi includes native prebuilds;
a C/C++ toolchain is needed if none matches the installation platform.
Development also needs Corepack (tested with 0.35.0), Rust from the repository's
pinned toolchain and Python 3 for the existing CLI conformance runner.

From this directory, use a private Corepack home, outside shared toolchain mounts:

```sh
export COREPACK_HOME="$(mktemp -d)"
chmod 700 "$COREPACK_HOME"
corepack pnpm install --frozen-lockfile
corepack pnpm check
corepack pnpm conformance
corepack pnpm pack:companion
```

`packageManager` pins pnpm and `pnpm-lock.yaml` pins dependencies. No global shims
or `corepack enable` are needed. Only Koffi's native installation script is allowed
by `pnpm-workspace.yaml`. `check` verifies generated types and runtime schema drift,
formatting, TypeScript and real Unix/TCP tests, then builds `dist/`. `conformance`
runs the **entire existing Rust endpoint conformance checker**, including host
fixtures, against a real TCP TypeScript process. It also runs the `drydock
conformance` CLI through `drydockd` over Unix for daemon-forwarded scenarios.
Authentication, module declarations, null fixtures and host configuration are
checked directly because the daemon's public API does not forward those host
contracts. No conformance checks or workflows are weakened.

Generated ownership follows this chain:

```text
crates/drydock-protocol/src/{lib.rs,validation.rs,openapi.rs}
  -> Rust generate-openapi exporter
  -> /openapi.json (canonical generated document)
  -> src/protocol.ts (generated bindings)
     src/openapi.json (byte-identical runtime AJV schema)
  -> dist/ (standalone package, including its runtime schema)
```

`src/provider.ts` and the runtime implementation are handwritten. The JSON files
and protocol bindings are generated artifacts; do not hand-edit them. See
[AGENTS.md](AGENTS.md) for the short source map.

After a Rust protocol change, export the canonical document from the repository
root, then generate the TypeScript outputs:

```sh
cargo run --locked -p drydock-protocol --bin generate-openapi > openapi.json
(cd hosts/typescript && corepack pnpm generate)
(cd hosts/typescript && corepack pnpm check:generated)
```

Ordinary `corepack pnpm build` runs the same drift check before compiling;
`corepack pnpm pack:companion` invokes that build before packaging. Production
installation and execution use the packaged schema and do not need the repository
root or a Rust export step.

The types and runtime schema are generated from the same document; the host reads
its protocol version from that document. The generator preserves the schema's
nonempty exec argv and arbitrary trailing string arguments (a workaround for
openapi-typescript 7's handling of `prefixItems` plus `items`). Runtime validation
also enforces wire integer widths and the ordered usage-period invariant.

The existing CI job runs the same commands. `ci/check.sh` includes these commands
after the Rust checks; set `COREPACK_HOME` before invoking it.

## Install beside drydockd

Keep the package and its dependencies together. For example, unpack the generated
`.tgz` into a dedicated, versioned directory and install its pinned production
packages there; retain that directory while the symlink is installed:

```sh
mkdir -p "$HOME/.local/lib/drydock-typescript"
tar -xzf flotilla-drydock-host-typescript-0.1.0.tgz \
  -C "$HOME/.local/lib/drydock-typescript" --strip-components=1
cd "$HOME/.local/lib/drydock-typescript"
corepack pnpm install --prod --frozen-lockfile
mkdir -p "$HOME/.local/bin"
ln -s "$PWD/dist/main.js" "$HOME/.local/bin/drydock-host-typescript"
```

Alternatively, build this checkout and link its executable `dist/main.js` beside
`drydockd`, keeping this checkout's `node_modules` installed. The packed release
includes the lockfile and build policy. Node must be on `PATH`. The daemon discovers
`drydock-host-typescript` beside itself, or uses `DRYDOCK_TYPESCRIPT_HOST_BIN`.
The executable uses a Node shebang; no wrapper runtime or Rust provider is needed.

## Launch and configuration

```sh
mkdir -m 700 /tmp/drydock-ts
./dist/main.js --unix /tmp/drydock-ts/host.sock
# Or: --tcp 127.0.0.1:9280 --token-file /tmp/drydock-ts/token
```

The runtime directory must belong to the host user with mode 0700. Unix socket
mode is 0600; the kernel peer UID must equal the supervisor/host UID. The TCP
listener accepts only numeric loopback addresses, an exact bound `Host`, an absent or exact same-origin
`Origin`, and `Authorization: Bearer <token>`. It creates a mode-0600 token file
and rotates it on restart. Comparison hashes both operands and uses Node's
`timingSafeEqual`. Transport admission failures are bare HTTP errors: Host failures use 421, Origin failures 403, and invalid credentials 401.

Send `PUT /v1/config` with `Content-Type: application/json`:

```json
{
  "modules": [{ "name": "memory", "entrypoint": "reference" }],
  "providers": [
    {
      "name": "test",
      "module": "memory",
      "settings": {},
      "credential": { "mode": "direct", "credential_reference": "test-only" }
    }
  ]
}
```

`GET /v1/hello` reports loadable modules, loaded aliases, capabilities, rate limits
and instance readiness. Configuration validates all additions before committing;
exact repeats preserve resources and credentials. Replacing/removing a live provider
requires restart. Settings are opaque to the host and passed unchanged to its module.
The reference accepts `poll_interval_ms` (positive; default 10), `platforms`,
`rate_limits`, `agent`, `reach` and a typed `fault`. Test options are `fixture`,
`fixture_push`, `fixture_bad_relay` and `disabled` (optional operation names).

Deliver direct credentials via `PUT /v1/providers/test/credential` with
`{"value":"test-only-secret"}`, repeating on refresh. The host stores values only
in memory, never logs bodies or raw module errors, and masks delivered credentials
in typed error/readiness diagnostics, including JSON/UTF-16, percent/form and standard/URL-safe base64 echoes. The diagnostic owner caches active values and at most 32 retired credentials, protects each in-flight call's captured credential separately, and bounds masked diagnostic text to 16 KiB at UTF-8 character boundaries. No credential reference resolution occurs in
the host. Proxied instances refuse direct refresh and receive the supervisor's
inherited `HTTPS_PROXY`, `NODE_USE_ENV_PROXY` and `NODE_EXTRA_CA_CERTS` environment.
Modules must honor their credential mode and cancellation context, avoid logging
secrets and perform no automatic retries. Do not put secrets in settings.

## Module interface and lifecycle

Implement `ProviderModule` and `Provider` from `src/provider.ts` (published as
`dist/provider.d.ts`), using the generated `Types` aliases. A module exports a
version, smallest supported size and asynchronous configuration factory. Register
additional ESM modules with the supervisor's comma-separated
`DRYDOCK_TYPESCRIPT_MODULES` allowlist of absolute paths/file URLs. The configured
entrypoint is that exact allowlisted value. A wire request cannot import an
unregistered path. A factory must validate settings without starting background
work, and observe cancellation before/while allocating resources.

Fastify owns ordinary HTTP routing, body parsing/limits and response piping. Route
paths, methods and body schemas come from the canonical OpenAPI document; typed
bindings use its generated operation IDs. The shared AJV2020 validator never
coerces values, inserts defaults or removes fields. Request/error logging stays
disabled, and all HTTP failures use the host's sanitized protocol envelope.
Provider interfaces contain no Fastify types. Custom transport admission and raw
exec/relay framing stay outside the framework's HTTP parsing.

`operations.ts` owns the optional-operation metadata and checked invocation;
`observation.ts` owns inventory, poll/push lifetime, history and stream cursors.
The reference module owns its settings schema, reusing canonical protocol schema
references for wire-shaped values.

The host owns readiness, credential generations, cached capabilities, rate budgets,
prepare platform resolution, optional operation gates and HTTP statuses. Optional
ports must agree with capabilities; unsupported operations return typed `Refused`.
Providers return a Created/Existing provision result, with labels as idempotency
keys; the host selects HTTP 201/200. Provider calls execute concurrently without a
host operation lock. Factories/configuration transactions serialize separately.

Poll modules return complete `Observed[]` inventories. The host owns one poller,
diffs stable state, retains a 1024-event process-local history and stamps events
with provider timestamps when supplied, otherwise adaptor time. Failed/unready
lists retain inventory and cannot infer deletion. Polling is paced within declared
list/global limits, reserving foreground capacity. Push modules may start a single
post-commit `run(sink, credentials, signal)` task, and must cooperate with shutdown.

`GET /v1/events` is NDJSON. Initial/unknown/expired cursors receive a snapshot;
`?since=<opaque cursor>` replays exclusively. Partial snapshots include typed
`unavailable_providers`; consumers must preserve previous inventory for those
providers. Push lists share a five-second snapshot deadline; shutdown cancels
pending configuration, lists and observers. SIGINT/SIGTERM close event bodies and
upgraded streams, wait up to five seconds for observer cleanup and unlink the Unix
socket. No terminal NDJSON error variant is invented.

Relay uses GET with `Upgrade: drydock-relay`; exec uses POST JSON with
`Upgrade: drydock-stream`. Both require `Connection: Upgrade`, return 101 and hand
modules raw duplex streams with backpressure and half-close propagation. Client disconnect cancels relay/exec setup; a late stream from a provider that ignores cancellation is disposed. Exec
upgrade bodies accept content-length and chunked framing. Reach relay
paths are built and escaped by the host. Implement all optional ports actually
advertised by a module.

Prepare receives the caller's `tools_digest` and selected platform. Modules choose
their prepared key and must follow [the tools/agent contract](../../ci/tools-image/README.md):
preserve the image's own process/init, start the agent alongside it and report
vessel readiness only after agent hello. The in-memory reference explicitly
simulates this boundary; live vendor provisioning is separate work.

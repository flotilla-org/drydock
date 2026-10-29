# Thin TypeScript provider bridge

Node >=24.18.0 on Linux/Unix, with pinned pnpm via Corepack. Daemon owns all
admission, rate, credential-state, inventory, billing and replay policy. This
companion loads modules and delegates the common `/v1` API to provider methods.
Suspend/resume and quota are optional ports: a provider declares the ones whose
methods it implements, and the host refuses the others. Exec, export and usage
are absent until drydock#85.
Workspace validation (`check`/`conformance`) requires the pinned Rust toolchain and
Cargo; an installed production companion only needs Node and its dependencies.

```sh
export COREPACK_HOME="$(mktemp -d)" # private writable directory
corepack pnpm install --frozen-lockfile
corepack pnpm check
corepack pnpm pack:companion
```

Build generates `src/generated/protocol.ts` and `schema.json` from canonical
`/openapi.json` host-tagged paths. Rust declarations and the actual shared handlers
in `crates/drydock-client/src/api.rs` own the document; export it with
`cargo run --locked -p drydock-client --bin generate-openapi > openapi.json`.
Generated outputs are untracked, marked GENERATED and verified by
`check:generated`. Rust's drift test verifies the canonical document. The package
includes compiled bindings and runtime schemas; no repository files are needed at
runtime. AJV uses the generated schema as-is, declares the `int32`/`int64` width
formats, and never coerces values, inserts defaults or strips fields.

The root `package.json` repeats the pnpm pin so Corepack selects the same version
when CI invokes `corepack pnpm --dir hosts/typescript ...` from the repository root.
Keep both pins aligned; `--dir` is interpreted by pnpm after Corepack selects it.

Unpack the tarball into a dedicated installation directory, run `corepack pnpm
install --prod --frozen-lockfile`, and link executable `dist/main.js` beside
`drydockd` as `drydock-host-typescript` (or set `DRYDOCK_TYPESCRIPT_HOST_BIN`).
Keep the installation directory/dependencies together. No global Corepack shims,
FFI/native module or shared toolchain changes are needed.

Launch: `drydock-host-typescript --unix /private/run/host.sock`. The supervisor
owns the same-user directory (0700), socket (0600) and launched process/path.
There are no peer UID checks or TCP listener. Request/error logging is disabled;
unexpected exceptions become static Internal errors. Typed provider diagnostics
are sent to Daemon, which owns public credential masking; modules must never log
secrets.

Set `DRYDOCK_TYPESCRIPT_MODULES` to comma-separated absolute ESM paths/file URLs.
Entries are comma-separated; use a file URL with `%2C` for a comma in a path.
Each exports a default `ProviderModule` from handwritten `src/provider.ts`.
Configuration selects only these modules by name; settings cannot import code.
PUT `/v1/config` replaces `{providers: {instance: {module, settings}}}`; PATCH uses
RFC7396 merge patch and validates the merged document. Unchanged configurations reuse their provider; failed
configuration leaves the previous document intact. Credential configuration is
server-only and rejected by the host. The optional `Drydock-Credential` header is
an opaque per-call string, never retained in configuration. A module may keep an
SDK client for the credential its calls carry, when the SDK holds connections
that outlive one call (a relay does).

Providers return generated Environment values; provision's internal `created`
flag chooses HTTP201 or200 without a wire wrapper. Provider declarations expose
facts; observation is polling performed by the main server. There are no host
handles, push subscriptions, cursors, credential refresh routes or policy loops.
Modules validate opaque settings and honor cancellation; cancellation does not
prove rollback. Factories own cleanup on rejection/abort, and modules own their
SDK resources. Client disconnect aborts the call's signal.

A provider whose reach is `relay` implements `relay(id)`, returning a Node
`Duplex` to its vessel's agent socket. Only a GET of the relay route carrying
`Connection: upgrade` and `Upgrade: drydock-relay` leaves Fastify (Node's
`shouldUpgradeCallback`); one without them is refused. The provider is called
before protocols switch, so its refusals are ordinary error responses; after the
101, bytes pass both ways and either side's end half-closes the other.

`server.ts` contains direct Fastify routes and a small RFC7396 merge.
`provider.ts` is handwritten and free of framework types. `src/generated/**` and
`dist/**` are generated outputs, including JSON. Rust types → canonical OpenAPI →
TypeScript bindings and packaged AJV schema form one generation chain.

The built-in `reference` module is always loadable in every companion, and used
only when selected by provider configuration; it creates no vendor resources. Its optional
settings are `{seed_unlabelled: boolean}`; unknown settings are refused. It stores
prepared forms and Environment rows, implements label idempotency, refuses reach
until exposures land (#132), and exposes a 10ms polling declaration. It owns no event stream or replay.

The built-in `namespace` module drives Namespace devboxes through
`@namespacelabs/sdk/devbox` (`src/namespace/`). Settings: `workspace` (required:
images go to `nscr.io/<workspace>/<repository>`), `repository` (default
`drydock-vessel`), `site` (default the SDK's `iad`), `push_chunk_bytes` and
`egress_probe` (`{command: [...]}`, run as root on inspect). The credential is
`{"bearer_token": …}`, handed to the SDK through a TokenSource, never its
defaults or token files, and used as the `nscr.io` push password (user `token`)
without touching any docker configuration. It needs the grants `devbox *`,
`devbox/image *`, `instance create, dial_host, ssh, exec, get, list, refresh,
wait`, `ingress access` and `containerregistry *`,
`containerregistry/repository *`, `containerregistry/image *`.

- Prepare layers the tools image onto the base by digest here (no build),
  pushes it to the workspace registry tagged with the key's name, and registers
  it by digest. The key is both digests and the platform (linux/amd64); the
  prepared form's ID is the registered reference. A registration with the key's
  name is reused, so re-preparing adds no version. Optimize is never called.
- Provision creates a devbox from it with the client's label in
  `drydock.label`, a named size (s, m, l, xl: 4/8/16/32 CPUs with 2 GiB per
  CPU; disk is whole GiB of volume), the egress policy, no tenant checkout and
  never `ephemeral`. PID 1 is Namespace's agent and the image's entrypoint
  never runs, so drydock's agent is the service `drydock-agent`
  (`/opt/drydock/drydock-agent`, on boot, always restarted, keeping the devbox
  awake). A label finds its devbox again; a running one gets the service if it
  is missing, a stopped one is returned untouched.
- Reach is this host's relay route; the relay is an SSH exec channel over the
  SDK's gateway running `drydock-agent --bridge`, since the gateway refuses
  Unix-socket forwards. Exposures travel over that one agent connection.
- Suspend and resume are devbox stop and start: files survive, memory does not.
  A devbox stopped by its lifetime cap or idling reads as `paused_by_provider`
  and resumes; one this host stopped reads as `suspended_by_request` until the
  host restarts (devbox labels are fixed at create, so that fact is not durable).
- Observation polls every 30 s. List reports devboxes carrying `drydock.label`,
  with state from `refresh` (list itself says `unknown`). Nothing that observes
  runs a command or opens a connection on a stopped devbox, since those start it.
- Egress maps host names to `networkPolicy.allowedDomains` (non-advisory) and
  refuses CIDR, port and address entries; an absent request is deny all. Declared enforcement is advisory; an
  environment reports enforced only when `egress_probe` passes as root.
- Quota reads `UsageService/GetConcurrency` (CPU, memory and instances per
  platform class). Usage is undeclared.
- SDK calls through the gateway can fail with `Premature close` after taking
  effect; `src/namespace/vendor.ts` is the one place that retries them, and it
  checks the resulting state first, so nothing is created or stopped twice.
- One SDK client is kept per credential. One a newer credential replaces is
  closed only after its last call and relay end, so rotation never cuts a live
  agent connection.

Module tests run against in-process stand-ins for the SDK and OCI registries
(`test/support/namespace.ts`), never a live token.

`corepack pnpm conformance` builds the companion, then discovers and runs the ignored Rust integration test
against this actual child host through the main Daemon and its existing checker.
Authentication is exercised by the shared server serving tests; private UDS uses
filesystem authorization. Exec-based host fixtures await #85 and reach awaits #132. The test drains
and counts child output without retaining credentials, checks optional-operation
admission in the embedded server, and requires the shared conformance report to
pass. The script fails if its named test is missing, rather than silently running
zero tests. The existing CI check command includes this test without another job.

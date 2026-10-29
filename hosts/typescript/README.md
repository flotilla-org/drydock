# Thin TypeScript provider bridge

Node >=24.18.0 on Linux/Unix, with pinned pnpm via Corepack. Daemon owns all
admission, rate, credential-state, inventory, billing and replay policy. This
companion loads modules and delegates the common `/v1` API to provider methods.
Exec, suspend/resume, export, usage and quota are absent until drydock#85.
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
an opaque per-call string, never retained in configuration or provider bindings.

Providers return generated Environment values; provision's internal `created`
flag chooses HTTP201 or200 without a wire wrapper. Provider declarations expose
facts; observation is polling performed by the main server. There are no host
handles, push subscriptions, cursors, credential refresh routes or policy loops.
Modules validate opaque settings and honor cancellation; cancellation does not
prove rollback. Factories own cleanup on rejection/abort, and modules own their
SDK resources. Client disconnect aborts the call's signal. The relay route is
not served; vessel connections are being redesigned as exposures (#132).

`server.ts` contains direct Fastify routes and a small RFC7396 merge.
`provider.ts` is handwritten and free of framework types. `src/generated/**` and
`dist/**` are generated outputs, including JSON. Rust types → canonical OpenAPI →
TypeScript bindings and packaged AJV schema form one generation chain.

The built-in `reference` module is always loadable in every companion, and used
only when selected by provider configuration; it creates no vendor resources. Its optional
settings are `{seed_unlabelled: boolean}`; unknown settings are refused. It stores
prepared forms and Environment rows, implements label idempotency, refuses reach
until exposures land (#132), and exposes a 10ms polling declaration. It owns no event stream or replay.

`corepack pnpm conformance` builds the companion, then discovers and runs the ignored Rust integration test
against this actual child host through the main Daemon and its existing checker.
Authentication is exercised by the shared server serving tests; private UDS uses
filesystem authorization. Exec-based host fixtures await #85 and reach awaits #132. The test drains
and counts child output without retaining credentials, checks optional-operation
admission in the embedded server, and requires the shared conformance report to
pass. The script fails if its named test is missing, rather than silently running
zero tests. The existing CI check command includes this test without another job.

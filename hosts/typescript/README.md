# Thin TypeScript provider bridge

Node >=24.18.0 on Linux/Unix, with pinned pnpm via Corepack. Daemon owns all
admission, rate, credential, inventory, billing and replay policy. This companion
only loads modules, invokes provider methods and forwards private REST/streams.
Exec, suspend/resume, export, usage and quota are absent until drydock#85.

```sh
export COREPACK_HOME="$(mktemp -d)"  # private writable directory
corepack pnpm install --frozen-lockfile
corepack pnpm check
corepack pnpm pack:companion
```

Build generates `src/generated/protocol.ts` and `schema.json` from canonical
`/openapi.json` host-tagged paths (Rust exporter: `drydock-host/src/lib.rs`). Generated
outputs are untracked, marked GENERATED and verified by `check:generated`.
Rust's workspace drift test verifies the canonical document. The package includes
compiled bindings and runtime schemas; no repository files are needed at runtime.
AJV never coerces values, inserts defaults or strips fields.

Unpack the tarball into a dedicated installation directory, run `corepack pnpm
install --prod --frozen-lockfile`, and link executable `dist/main.js` beside
`drydockd` as `drydock-host-typescript` (or set `DRYDOCK_TYPESCRIPT_HOST_BIN`).
Keep the installation directory/dependencies together. No global Corepack shims,
FFI/native module or shared toolchain changes are needed.

Launch: `drydock-host-typescript --unix /private/run/host.sock`. The supervisor
owns the same-user directory (0700), socket (0600) and launched process/path.
There are no peer UID checks or TCP listener. This is a private provider channel,
not a network-facing public API. Request/error logging is disabled; unexpected
exceptions become static Internal errors. Typed provider diagnostics are sent to
Daemon, which owns public credential masking; modules must never log secrets.

Set `DRYDOCK_TYPESCRIPT_MODULES` to comma-separated absolute ESM paths/file URLs.
Each exports a default `ProviderModule` from `src/provider.ts`. Requests select
only those modules by name; wire settings cannot import code. Modules validate
opaque settings and honor cancellation. Credentials are frozen per-call snapshots;
rotation/rejection state belongs to Daemon. Cancellation does not prove rollback.
Push subscriptions yield raw Update facts with immutable lifetime credentials;
there are no host cursors or retry loops. Slow readers apply stream backpressure.

Handwritten sources: `provider.ts` is the transport-independent interface;
`server.ts` contains direct framework routes; `stream.ts` handles raw HTTP upgrade
framing and duplex forwarding. `src/generated/**` and `dist/**` are build outputs.

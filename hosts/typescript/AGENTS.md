# TypeScript host sources

Generated outputs — do not edit by hand, including the JSON files:

- `/openapi.json`: canonical OpenAPI export from
  `crates/drydock-protocol/src/{lib.rs,validation.rs,openapi.rs}`, via
  `crates/drydock-protocol/src/bin/generate-openapi.rs`.
- `src/protocol.ts`: TypeScript bindings generated from `/openapi.json`.
- `src/openapi.json`: byte-identical copy of `/openapi.json`, used by runtime AJV.
- `dist/**`: compiler output, including the runtime schema shipped in the package.

`src/provider.ts` is **handwritten**: it defines module/provider ports using the
aliases from generated `src/protocol.ts`. The remaining runtime sources are
handwritten too. Keep runtime AJV validation and the schema in standalone packages.

Generation chain: Rust declarations/exporter -> canonical `/openapi.json` ->
TypeScript bindings and runtime schema copy -> compiled standalone package.

When the Rust contract changes, export from the repository root:

```sh
cargo run --locked -p drydock-protocol --bin generate-openapi > openapi.json
```

Then regenerate from `hosts/typescript/` with a private writable `COREPACK_HOME`:

```sh
corepack pnpm generate
corepack pnpm check:generated
```

`corepack pnpm build` verifies drift before compiling. `corepack pnpm
pack:companion` invokes that build and packages the runtime schema without needing
repository sources at install/run time. Run `corepack pnpm check` and `corepack pnpm
conformance` for host validation. Do not change the wire contract to suit generation.

Handwritten runtime ownership:

- `http.ts`: Fastify route bindings from canonical OpenAPI operation IDs and schemas.
  Preserve explicit methods, strict AJV input validation, sanitized errors and raw upgrades.
- `server.ts` / `upgrade.ts`: authenticated listeners and raw duplex framing/lifecycle.
- `host.ts` / `operations.ts`: configuration, readiness, credential/rate admission and
  one optional-operation declaration plus checked invocation.
- `observation.ts`: inventory, push/poll lifetime, diffing, cursor history and NDJSON source.
- `reference.ts`: reference-owned settings schema and in-memory provider.

Keep Fastify types inside `http.ts`; provider ports remain transport independent.
Do not enable request/error logging or AJV coercion, defaults or field stripping.

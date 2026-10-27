# Thin bridge

Rust `/openapi.json` is canonical; select its `host`-tagged paths. `corepack pnpm generate` creates untracked
`src/generated/{protocol.ts,schema.json}`; `dist/**` is also generated. Never write
wire types by hand. `provider.ts` and the other runtime sources are handwritten.
No admission/rate/credential-state/poll/diff/billing/replay policy belongs here;
Daemon owns it once. Keep direct Fastify routes, UDS/private filesystem access,
immutable call credentials, cancellation and raw byte streams. Optional ports
are absent until #85. No FFI, peer checks, retries or request/error logging.

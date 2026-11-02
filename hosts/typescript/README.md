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
  Unix-socket forwards. Exposures travel over that one agent connection. The
  tools image's agent must have `--bridge`: an older pin's agent never answers
  hello, so Namespace needs a tools image published from this revision on.
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
  platform class). The grants above do not cover it: without its grant quota
  is refused and the provider stays ready. Usage is undeclared.
- A permission denial (a token lacking a grant) is a refusal; only an
  unauthenticated token is a rejected credential.
- SDK calls through the gateway can fail with `Premature close` after taking
  effect; `src/namespace/vendor.ts` is the one place that retries them, and it
  checks the resulting state first, so nothing is created or stopped twice.
- One SDK client is kept per credential. One a newer credential replaces is
  closed only after its last call and relay end, so rotation never cuts a live
  agent connection.

Module tests run against in-process stand-ins for the SDK and OCI registries
(`test/support/namespace.ts`), never a live token.

The built-in `modal` module drives Modal sandboxes through the JavaScript SDK
(`modal`, gRPC to `api.modal.com`; `src/modal/`). Settings: `app` (default
`drydock`: the one app holding every sandbox of the instance, created if
missing), `environment`, `runtime` (`vm`, the default, or `gvisor`),
`concurrency_limit` and `egress_probe` (as Namespace's). The credential is
`{"token_id": …, "token_secret": …}`, handed to the SDK client directly, never
through `~/.modal.toml` or `MODAL_TOKEN_*`; the SDK still reads its server URL
and sandbox backend from those, so run the host without them.

- Prepare (route `registry_pull`, linux/amd64 only) has Modal build the base
  by digest with `COPY --from=<tools>@sha256 /opt/drydock/ /opt/drydock/`, in
  the module's app; the prepared form's ID is the `im-…` image. Modal caches by
  definition, so the same digests give the same image. A pull credential
  becomes an ephemeral secret for the base's registry only, so the tools image
  must pull anonymously. A registry that resolves here to a private address is
  refused before building, since Modal pulls only from the public internet;
  that is a best-effort check, as Modal resolves the name again itself.
- Provision creates a sandbox named from the label (unique per app), tagged
  with the instance, the label, its egress policy, size and expiry, with a
  timeout of 86400 s (Modal's longest), CPUs and whole MiB of memory (no disk
  size), and `sleep infinity` as its command, which only keeps it alive. A
  label whose name is taken re-adopts that sandbox when its tags say it is
  this instance's, with the same size and policy, and refuses it otherwise.
  Either way the module then starts the agent by a root exec that gets a
  fresh TCP token on stdin: it keeps the token already in
  `/run/drydock/tcp.token` (0600) or writes this one, runs
  `--supervise --tcp 0.0.0.0:7811 --tcp-token-file … --socket …`
  (idempotent; all addresses, since Modal's edge cannot reach loopback), waits for the socket and prints the token in use, which the
  module remembers. The token is never on an argv, in the environment or in
  Modal's configuration. A sandbox it just created and cannot hand over is
  terminated (if that terminate fails too, the sandbox stays listed: `destroy`
  it). The SDK takes no abort signal, so a cancelled call stops between SDK
  calls, never during one.
- Reach is `dial`: the agent's TCP listener behind Modal's connect-token edge,
  which drydock dials itself. Each reach mints a connect token for port 7811
  and returns its URL at `/v1/connect` with the token in the
  `_modal_connect_token` query parameter, and the agent's token as the
  reach's. drydock asks for a WebSocket upgrade, the only kind the edge
  splices, and both ends carry raw bytes after the agent's 101. A host that lost
  the token (a restart) reads it back by the same exec. Exec carries no agent
  traffic: each stdin write is one round trip, too slow for agent uploads. A
  reach to a terminated sandbox is refused, not retried.
- Egress: open sets nothing; deny all is an empty CIDR allowlist (Modal
  refuses a connect token to a sandbox with `blockNetwork`); IPv4 CIDRs and
  literals become the CIDR allowlist and names the domain allowlist; ports and
  IPv6 are refused. Destinations are enforced outside the guest, against root,
  by a transparent proxy (a connect succeeds; an unlisted destination is reset
  at TLS or HTTP), so the declaration is enforced; DNS resolution is never
  filtered, and an
  `egress_probe` that counts it reports that vessel advisory.
- There is no suspend: snapshots restore under a new id. A sandbox that
  reached its timeout reads as gone at its lifetime cap; one terminated
  elsewhere as destroyed at the provider.
- List is the app's running sandboxes tagged with the instance (Modal lists no
  terminated ones); inspect and destroy find a sandbox by id, and refuse one
  without the instance's tag. Destroy terminates and waits; an absent sandbox
  is already destroyed.
- Quota is the count of listed sandboxes against `concurrency_limit`; Modal has
  no quota API. Usage is undeclared: the JavaScript SDK has no billing report.
- A role lacking a right is a refusal; only an unauthenticated token is a
  rejected credential. One SDK client is kept per credential, retired as
  Namespace's are.

Its tests run against an in-process stand-in for the SDK
(`test/support/modal.ts`) that enforces what Modal documents and the probe in
drydock#192 observed. `scripts/live-modal.py` checks it against Modal itself.

`corepack pnpm conformance` builds the companion, then discovers and runs the ignored Rust integration test
against this actual child host through the main Daemon and its existing checker.
Authentication is exercised by the shared server serving tests; private UDS uses
filesystem authorization. Exec-based host fixtures await #85 and reach awaits #132. The test drains
and counts child output without retaining credentials, checks optional-operation
admission in the embedded server, and requires the shared conformance report to
pass. The script fails if its named test is missing, rather than silently running
zero tests. The existing CI check command includes this test without another job.

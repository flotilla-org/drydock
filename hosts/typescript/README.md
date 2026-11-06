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
pnpm is pinned to 10 because corepack 0.34 cannot run pnpm 12 (it ships
`pnpm.mjs`, not `pnpm.cjs`; drydock#252); lift the pin once the corepack in use
supports it. Keep both pins aligned; `--dir` is interpreted by pnpm after Corepack selects it.

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
facts; observation is polling performed by the main server (TypeScript modules
declare only a `poll` way in). There are no host
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
`@namespacelabs/sdk/devbox` (`src/namespace/`). It translates: each verb is
Namespace's own operation and each answer is what Namespace said, with
Namespace's state word and the devbox's labels in `vendor`. It declares
`settles`, `idempotent` and `owner_scoped` false and `token_is_id` true, so
waiting, already-done success and the ownership of a shared account are
drydockd's, as the instance's `semantics` and `ownership` ask. Settings:
`workspace` (required: images go to `nscr.io/<workspace>/<repository>`),
`repository` (default `drydock-vessel`), `site` (default the SDK's `iad`),
`push_chunk_bytes` (default 64 MiB), `poll_interval_ms` (default 30000),
`list_refreshes` (concurrent refreshes while listing, default 8) and
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
- Provision is one create from the prepared form with the client's label in
  `drydock.label` (and, on a `shared_account`, the instance's name in
  `drydock.provider`), a named size (s, m, l, xl: 4/8/16/32 CPUs with 2 GiB
  per CPU; disk is whole GiB of volume), the egress policy, no tenant checkout
  and never `ephemeral`. PID 1 is Namespace's agent and the image's entrypoint
  never runs, so the create is followed by drydock's agent as the service
  `drydock-agent` (`/opt/drydock/drydock-agent`, on boot, always restarted,
  keeping the devbox awake); if the service cannot be added provision fails
  and leaves the devbox, naming its id, for the client to inspect or destroy.
  It keeps billing until destroyed, and a retry makes another devbox. A label is the client's name: provisioning it
  again makes another devbox. An unknown prepared form is Namespace's refusal.
- Reach is this host's relay route, with no call to Namespace; the relay is an
  SSH exec channel over the SDK's gateway running `drydock-agent --bridge`,
  since the gateway refuses Unix-socket forwards. Opening it is Namespace's
  activate, which starts a stopped devbox. Exposures travel over that one agent
  connection. The tools image's agent must have `--bridge`.
- Suspend and resume are devbox stop and start, sent as asked: files survive,
  memory does not, and the agent service, being on boot, starts again by itself.
  The resume token is the devbox id. Namespace's Stop and Expire take a
  devbox's name, so the SDK looks the id up before stop, start and delete. A
  stopped devbox has no cause: Namespace does not say whether its idle or
  lifetime cap or a client stopped it.
- Namespace offers no webhooks or state stream, so drydockd polls. List is
  Namespace's list (on a `shared_account`, of devboxes carrying the instance's
  `drydock.provider`), and each listed devbox is refreshed, since Namespace's
  list states every state as `unknown`. A size, platform or label is reported
  only when Namespace states it.
- Egress maps host names to `networkPolicy.allowedDomains` (non-advisory) and
  refuses CIDR, port and address entries; an absent request is deny all. The
  capability declares Namespace's documented egress model (`EGRESS_MODEL`),
  never a verification; an environment reports enforced only when
  `egress_probe` passes as root, and a probe that fails or prints no proof
  fails the inspect.
- Quota reads `UsageService/GetConcurrency` (CPU, memory and instances per
  platform class) as Namespace gives it: a class without stated use has no row.
  The grants above do not cover it: without its grant quota is refused and the
  provider stays ready. Usage is undeclared.
- A permission denial (a token lacking a grant) is a refusal; only an
  unauthenticated token is a rejected credential.
- SDK calls through the gateway can fail with `Premature close` after taking
  effect; `src/namespace/vendor.ts` is the one place that retries them, and it
  checks the resulting state first, so no call is made twice. That gets one
  call through the SDK's transport; it adds no guarantee of drydock's.
- One SDK client is kept per credential. One a newer credential replaces is
  closed only after its last call and relay end, so rotation never cuts a live
  agent connection.

Module tests run against in-process stand-ins for the SDK and OCI registries
(`test/support/namespace.ts`), never a live token.

The built-in `modal` module drives Modal sandboxes through the JavaScript SDK
(`modal`, gRPC to `api.modal.com`; `src/modal/`). Settings: `app` (default
`drydock`: the one app holding every sandbox of the instance, created if
missing), `environment`, `runtime` (`vm`, the default, or `gvisor`),
`lifetime_seconds` (Modal's timeout for each sandbox; default 86400, Modal's
longest), `list_concurrency` (tag reads list runs at once; default 8, at most 64) and
`agent_wait_seconds` (how long the agent's socket is waited for; default 10).
`concurrency_limit` is gone with quota: a configuration that still sets it is
refused, as any unknown key is. The credential is
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
- The module translates: each verb is Modal's own operation, and each row is
  what Modal said. It declares `settles`, `idempotent` and `owner_scoped`
  false, so drydockd waits, makes lifecycle calls idempotent and scopes a
  shared account to the instance (`semantics.rs`), as the instance's options
  and `ownership` ask. That scope covers list, destroy and suspend; until
  drydock#276, inspect and reach on a shared account are not scoped, so this
  instance's credential can inspect, and mint a connect token for, any
  sandbox in the app whose id it is given.
- Provision is one create of an unnamed sandbox, tagged `flotilla.label` with
  the client's label and, on a `shared_account` (the default), `drydock.provider`
  with the instance; on an `owned_account` nothing else is tagged. A label is
  the client's, so provisioning it twice makes two sandboxes. The sandbox has a
  timeout of `lifetime_seconds`, CPUs and whole MiB of memory, and
  `sleep infinity` as its command, which only keeps it alive. Modal's disk is
  fixed and cannot be sized, so a requested disk is accepted and not applied.
  Modal answers a create with the sandbox's id alone, so the row's state is
  unknown. A refused create is refused in Modal's words.
  The module then starts the agent by a root exec that gets a
  fresh TCP token on stdin: it keeps the token already in
  `/run/drydock/tcp.token` (0600) or writes this one, runs
  `--supervise --tcp 0.0.0.0:7811 --tcp-token-file … --socket …`
  (idempotent; all addresses, since Modal's edge cannot reach loopback), waits up
  to `agent_wait_seconds` for the socket and prints the token in use, which the
  module remembers. The token is never on an argv, in the environment or in
  Modal's configuration. drydockd cannot start the agent itself: its upload
  bootstrap needs the files and exec ports this host does not offer, and
  listens on loopback. A sandbox whose agent does not start is left as it is:
  provision fails, and the sandbox stays listed under its label until it is
  destroyed. Until then it runs, and is billed, for up to `lifetime_seconds`
  (default 24 hours), the only bound until drydock#292. The SDK takes no abort signal, so a cancelled call stops between
  SDK calls, never during one.
- Reach is `dial`: the agent's TCP listener behind Modal's connect-token edge,
  which drydock dials itself. Each reach mints a connect token for port 7811
  and returns its URL at `/v1/connect` with the token in the
  `_modal_connect_token` query parameter, and the agent's token as the
  reach's. drydock asks for a WebSocket upgrade, the only kind the edge
  splices, and both ends carry raw bytes after the agent's 101. TLS ends at
  the edge, so Modal sees both tokens and the agent's traffic in transit. A host that lost
  the token (a restart) reads it back by the same exec. Exec carries no agent
  traffic: each stdin write is one round trip, too slow for agent uploads.
  Modal states no lifetime for a connect token, so the reach has no
  `expires_at`.
- Egress: open sets nothing; deny all is an empty CIDR allowlist (Modal
  refuses a connect token to a sandbox with `blockNetwork`); IPv4 CIDRs and
  literals become the CIDR allowlist and names the domain allowlist; ports and
  IPv6 are refused. Destinations are enforced outside the guest, against root,
  by a transparent proxy (a connect succeeds; an unlisted destination is reset
  at TLS or HTTP). The egress model declares that (`outside_guest`, shapes
  open, deny all, addresses and domains, the allowlists changeable while
  running) with DNS as a side effect: resolution is never filtered. The
  module measures nothing, so each vessel reports egress advisory, and Modal
  reports no policy back, so a row has no `egress_policy`.
- There is no suspend: snapshots restore under a new id.
- Rows report what Modal states. Inspect is Modal's `poll()` and the sandbox's
  tags (Modal has no one read of both): null is `running`, and an exit code is
  `gone` with no cause, the code in `vendor.reason` (`exit code 137`); the
  module does not guess whether Modal's timeout, a terminate or the guest ended
  it. The vendor state is `running` or `finished`, Modal's SDK words, with the
  tags as read. No row states a size, platform or time: Modal's SDK gives none.
- List is the app's running sandboxes (Modal lists no ended ones), filtered by
  the instance's tag on a shared account only, then each one's tags,
  `list_concurrency` at a time: the SDK's list yields ids alone. Its wire
  answer has a tags field that no Modal client reads, so the module does not
  rely on it. A sandbox gone between the two calls is left out.
- Inspect, reach and destroy take a sandbox by id and check no tag. Destroy is
  one terminate that does not wait; Modal's not found is its answer.
- Quota is undeclared: Modal has no quota API. Usage is undeclared: the
  JavaScript SDK has no billing report.
- A role lacking a right is a refusal; only an unauthenticated token is a
  rejected credential. One SDK client is kept per credential; one a newer
  credential replaced closes once its last call ends.

`corepack pnpm conformance` builds the companion, then discovers and runs the ignored Rust integration test
against this actual child host through the main Daemon and its existing checker.
Authentication is exercised by the shared server serving tests; private UDS uses
filesystem authorization. Exec-based host fixtures await #85 and reach awaits #132. The test drains
and counts child output without retaining credentials, checks optional-operation
admission in the embedded server, and requires the shared conformance report to
pass. The script fails if its named test is missing, rather than silently running
zero tests. The existing CI check command includes this test without another job.

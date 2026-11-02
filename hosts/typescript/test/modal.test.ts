import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { NotFoundError, ResourceExhaustedError } from "modal";
import {
  AGENT,
  COMMAND,
  LIFETIME_SECONDS,
  SOCKET,
  PORT,
  TOKEN_FILE,
  CONNECT_PATH,
  CONNECT_TOKEN_PARAM,
  TAGS,
  modalModule,
  networkFields,
} from "../dist/modal/index.js";
import { protocolError } from "../dist/modal/vendor.js";
import { ClientError, CREDENTIAL, StandIn, TOKEN } from "./support/modal.ts";
import { ports } from "../dist/provider.js";
import type { Provider, Types } from "../src/provider.ts";

const MiB = 1024 ** 2;
const GiB = 1024 * MiB;
const SIZE = { cpus: 1, memory_bytes: 2 * GiB, disk_bytes: 0 };
const kind = (k: string) => (e: any) => e.detail?.kind === k;
const digest = (c: string) => `sha256:${c.repeat(64)}`;
const BASE = `docker.io/library/alpine@${digest("a")}`;
const TOOLS = `ghcr.io/flotilla-org/drydock-tools@${digest("b")}`;

async function setup(
  settings: Record<string, unknown> = {},
  addresses: Record<string, string[]> = {},
) {
  const standIn = new StandIn();
  let clock = Date.parse("2026-11-02T12:00:00Z");
  const resolved: string[] = [];
  const module = modalModule(
    standIn.connect,
    async (host) => {
      resolved.push(host);
      const found = addresses[host];
      if (!found) throw new Error("ENOTFOUND");
      return found;
    },
    () => clock,
  );
  const abort = new AbortController();
  const provider: Provider = await module.configure(
    "modal",
    { module: "modal", settings },
    abort.signal,
  );
  const context = { credential: CREDENTIAL, signal: abort.signal };
  const request: Types["PrepareRequest"] = {
    size: SIZE,
    image_digest: BASE,
    tools_digest: TOOLS,
  };
  const provision = async (
    label: string,
    egress: Types["EgressRequest"] = { mode: "deny_all" },
    size = SIZE,
  ) =>
    provider.provision(
      {
        label,
        prepared: await provider.prepare(request, context),
        size,
        egress,
      },
      context,
    );
  const advance = (seconds: number) => (clock += seconds * 1000);
  return {
    standIn,
    provider,
    context,
    request,
    provision,
    resolved,
    advance,
    module,
  };
}

// Settings name the app and the runtime; the credential is a token pair, and
// anything else is not ready. The pair and the environment reach the client.
test("configure validates settings; readiness needs a token pair", async () => {
  const module = modalModule(new StandIn().connect);
  const signal = new AbortController().signal;
  for (const settings of [
    { unknown: 1 },
    { app: "bad/name" },
    { runtime: "firecracker" },
    { concurrency_limit: 0 },
  ])
    await assert.rejects(
      module.configure("modal", { module: "modal", settings }, signal),
      kind("refused"),
    );
  const provider = await module.configure(
    "modal",
    { module: "modal", settings: {} },
    signal,
  );
  for (const credential of [
    undefined,
    "token",
    "{}",
    '{"token_id":"ak-1"}',
    '{"token_id":"","token_secret":"x"}',
  ])
    assert.equal(
      (await provider.readiness({ credential, signal })).status,
      "missing_credential",
    );
  assert.deepEqual(
    await provider.readiness({ credential: CREDENTIAL, signal }),
    { status: "ready" },
  );
  // The daemon refuses capabilities that disagree with the ports present.
  const declared = ports(provider);
  const { capabilities } = provider;
  assert.deepEqual(
    [
      capabilities.fallback_runner,
      capabilities.suspend_resume,
      capabilities.export,
      capabilities.usage,
      capabilities.quota,
    ],
    [
      declared.exec,
      declared.suspend_resume,
      declared.export,
      declared.usage,
      declared.quota,
    ],
  );
  const {
    standIn,
    provider: scoped,
    context,
  } = await setup({
    environment: "drydock",
  });
  await scoped.list(context);
  assert.deepEqual(standIn.tokens, [TOKEN]);
  assert.deepEqual(standIn.environments, ["drydock"]);
});

// Prepare has Modal build the base by digest with the tools copied in, in the
// module's app, and records the image id. Modal caches by definition, so the
// same digests give the same id again.
test("prepare builds the base with the tools layer, and finds it again", async () => {
  const { standIn, provider, context, request } = await setup({ app: "dd" });
  const prepared = await provider.prepare(request, context);
  assert.match(prepared.id, /^im-/);
  assert.deepEqual(prepared, {
    id: prepared.id,
    provider: "modal",
    platform: { os: "linux", architecture: "amd64" },
    image_digest: BASE,
    tools_digest: TOOLS,
  });
  assert.deepEqual(standIn.builds, [
    {
      base: BASE,
      commands: [`COPY --from=${TOOLS} /opt/drydock/ /opt/drydock/`],
      pull: undefined,
    },
  ]);
  assert.deepEqual([...standIn.apps.keys()], ["dd"]);
  assert.deepEqual(await provider.prepare(request, context), prepared);
  assert.equal(standIn.images.size, 1);
  await assert.rejects(
    provider.prepare(
      { ...request, platform: { os: "linux", architecture: "arm64" } },
      context,
    ),
    kind("image_refused"),
  );
  await assert.rejects(
    provider.prepare({ ...request, route: "provider_push" }, context),
    kind("refused"),
  );
  await assert.rejects(
    provider.prepare({ ...request, image_digest: "alpine:3.20" }, context),
    kind("refused"),
  );
});

// Modal's builders pull only from the public internet: a registry resolving
// to a private address is refused before anything is built. A name that does
// not resolve here may still be public, so it goes to Modal.
test("prepare refuses a registry at a private address", async () => {
  const lab = `forgejo.lab.example/flotilla/crew@${digest("c")}`;
  const { standIn, provider, context, request } = await setup(
    {},
    {
      "forgejo.lab.example": ["192.168.1.31"],
      "ghcr.io": ["140.82.121.34"],
    },
  );
  for (const image_digest of [
    lab,
    `10.1.2.3:5000/crew@${digest("c")}`,
    `127.0.0.1:5000/crew@${digest("c")}`,
  ])
    await assert.rejects(
      provider.prepare({ ...request, image_digest }, context),
      (e: any) => /public internet/.test(e.detail?.reason),
    );
  assert.equal(standIn.builds.length, 0);
  await provider.prepare(request, context);
  assert.equal(standIn.builds.length, 1);
});

// A pull credential becomes the base's ephemeral registry secret only; the
// tools layer is copied without it.
test("prepare sends the pull credential for the base only", async () => {
  const { standIn, provider, context, request } = await setup();
  const secret = randomBytes(12).toString("hex");
  await provider.prepare(
    { ...request, image_pull: { username: "crew", secret } },
    context,
  );
  const [build] = standIn.builds;
  assert.deepEqual(build.pull, { username: "crew", password: secret });
  assert.ok(build.commands.every((c) => !c.includes(secret)));
  assert.ok(!build.base.includes(secret));
});

// Provision creates a named, tagged sandbox for the label: a day's timeout,
// the VM runtime, its size and egress, and the agent's start as its command,
// then waits for the agent's socket. No secrets go into the request.
test("provision creates a tagged sandbox that starts the agent", async () => {
  const { standIn, provision } = await setup();
  const { created, environment } = await provision("vessel");
  assert.equal(created, true);
  const row = standIn.rows.get(environment.id)!;
  const { tags, ...params } = row.params;
  assert.deepEqual(params, {
    name: params.name,
    cpu: 1,
    memoryMiB: 2048,
    timeoutMs: LIFETIME_SECONDS * 1000,
    runtime: "vm",
    command: COMMAND,
    outboundCidrAllowlist: [],
  });
  assert.match(params.name!, /^drydock-[0-9a-f]{24}$/);
  assert.deepEqual(tags, {
    [TAGS.provider]: "modal",
    [TAGS.label]: "vessel",
    [TAGS.egress]: "deny",
    [TAGS.size]: "1/2048",
    [TAGS.expires]: String(
      Date.parse("2026-11-02T12:00:00Z") / 1000 + LIFETIME_SECONDS,
    ),
  });
  assert.deepEqual(environment, {
    provider: "modal",
    id: environment.id,
    label: "vessel",
    state: { state: "running" },
    granted_size: SIZE,
    platform: { os: "linux", architecture: "amd64" },
    egress: "enforced",
    egress_measured: false,
    egress_policy: "deny",
    timestamp: null,
  });
  // The agent starts with its TCP listener; its token went by stdin alone.
  assert.ok(
    standIn.calls.some(
      (c) =>
        c.startsWith("exec sh -c") &&
        c.includes(
          `${AGENT} --supervise --tcp 0.0.0.0:${PORT} --tcp-token-file ${TOKEN_FILE} --socket ${SOCKET} `,
        ),
    ),
  );
  assert.match(row.token!, /^[A-Za-z0-9_-]{43}$/);
  assert.ok(standIn.calls.every((c) => !c.includes(row.token!)));
  assert.ok(
    standIn.processes.every((p) => !p.running),
    "no exec left running",
  );
  // gVisor on request; disks and odd memory are refused.
  const gvisor = await setup({ runtime: "gvisor" });
  const { environment: g } = await gvisor.provision("g");
  assert.equal(gvisor.standIn.rows.get(g.id)!.params.runtime, "gvisor");
  await assert.rejects(
    gvisor.provision("d", undefined, { ...SIZE, disk_bytes: GiB }),
    kind("refused"),
  );
  await assert.rejects(
    gvisor.provision("m", undefined, { ...SIZE, memory_bytes: GiB + 1 }),
    kind("refused"),
  );
});

// The sandbox command only keeps it alive: the agent starts by exec, which
// carries its token. A start that fails is reported.
test("the agent starts by exec, and a failed start is reported", async () => {
  assert.deepEqual(COMMAND, ["sleep", "infinity"]);
  const { standIn, provision } = await setup();
  standIn.agentStart = 1;
  await assert.rejects(provision("vessel"), kind("internal"));
  // The sandbox it made is not left running for a day.
  assert.deepEqual(
    [...standIn.rows.values()].map((r) => r.exit),
    [137],
  );
});

// The label names the sandbox, so provisioning it again finds the same one
// (and starts the agent again, idempotently). A sandbox under that name with
// another provider's or label's tags, or another size or policy, is refused.
test("provision re-adopts its sandbox and refuses a mismatch", async () => {
  const { standIn, provider, context, request, provision } = await setup();
  const first = await provision("vessel");
  const again = await provision("vessel");
  assert.equal(again.created, false);
  assert.equal(again.environment.id, first.environment.id);
  assert.equal(standIn.rows.size, 1);
  assert.equal(
    standIn.calls.filter((c) => c.includes("--supervise")).length,
    2,
  );
  await assert.rejects(provision("vessel", { mode: "open" }), kind("refused"));
  await assert.rejects(
    provision("vessel", undefined, { ...SIZE, cpus: 2 }),
    (e: any) =>
      /different size \(1\/2048, requested 2\/2048\)/.test(e.detail?.reason),
  );
  // Another instance in the same app owns a sandbox under this label's name.
  const prepared = await provider.prepare(request, context);
  const [app] = standIn.apps.values();
  const name = standIn.rows.get(first.environment.id)!.params.name!;
  standIn.rows.get(first.environment.id)!.exit = 137;
  await standIn.create({ appId: app }, prepared.id, {
    name,
    tags: { [TAGS.provider]: "other", [TAGS.label]: "vessel" },
  });
  await assert.rejects(provision("vessel"), (e: any) =>
    /another provider or label/.test(e.detail?.reason),
  );
  // A prepared form Modal does not know is refused.
  await assert.rejects(
    provider.provision(
      {
        label: "forged",
        prepared: { ...prepared, id: "im-unknown" },
        size: SIZE,
      },
      context,
    ),
    kind("refused"),
  );
});

// Egress requests map to Modal's create fields; ports and IPv6 are refused,
// never widened; absent is deny all, as an empty CIDR allowlist (Modal gives
// no connect token to a sandbox with `blockNetwork`).
test("egress maps to create fields or is refused", () => {
  assert.deepEqual(networkFields({ mode: "open" }), {});
  assert.deepEqual(networkFields(undefined), { outboundCidrAllowlist: [] });
  assert.deepEqual(networkFields({ mode: "deny_all", direct: [] }), {
    outboundCidrAllowlist: [],
  });
  assert.deepEqual(
    networkFields({
      mode: "deny_all",
      direct: [
        { kind: "host", host: "B.example." },
        { kind: "host", host: "a.example" },
        { kind: "host", host: "192.0.2.1" },
        { kind: "cidr", cidr: "10.0.0.0/8" },
      ],
    }),
    {
      outboundCidrAllowlist: ["10.0.0.0/8", "192.0.2.1/32"],
      outboundDomainAllowlist: ["a.example", "b.example"],
    },
  );
  assert.deepEqual(
    networkFields({
      mode: "deny_all",
      direct: [{ kind: "cidr", cidr: "198.51.100.0/24" }],
    }),
    { outboundCidrAllowlist: ["198.51.100.0/24"] },
  );
  for (const entry of [
    { kind: "host_port", host: "a.example", port: 443 },
    { kind: "host", host: "2001:db8::1" },
    { kind: "cidr", cidr: "2001:db8::/32" },
    { kind: "cidr", cidr: "10.0.0.0/33" },
  ])
    assert.throws(
      () => networkFields({ mode: "deny_all", direct: [entry as any] }),
      kind("refused"),
    );
});

// Reach is a dial of the agent's TCP listener through a fresh connect token
// for its port: the edge's token in the query, the agent's as the reach's
// token. A host that lost its tokens (a restart) reads the sandbox's back
// rather than replacing it. A terminated sandbox is refused, not retried.
test("reach dials the agent through a connect token", async () => {
  const { standIn, provider, context, provision, module } = await setup();
  const { environment } = await provision("vessel");
  const token = standIn.rows.get(environment.id)!.token!;
  const execs = standIn.processes.length;
  const reach = await provider.reach(environment.id, context);
  assert.deepEqual(reach, {
    kind: "dial",
    url: `https://${environment.id}.modal.test${CONNECT_PATH}?${CONNECT_TOKEN_PARAM}=ct-1`,
    token,
    expires_at: "2026-11-02T12:05:00.000Z",
  });
  assert.deepEqual(standIn.connects, [
    { id: environment.id, port: PORT, token: "ct-1" },
  ]);
  assert.equal(standIn.processes.length, execs, "the token was remembered");
  const again = await provider.reach(environment.id, context);
  assert.ok(again.kind === "dial" && again.url.endsWith("=ct-2"));
  assert.equal(provider.relay, undefined, "exec carries no agent traffic");

  const restarted = await module.configure(
    "modal",
    { module: "modal", settings: {} },
    context.signal,
  );
  const reread = await restarted.reach(environment.id, context);
  assert.ok(reread.kind === "dial" && reread.token === token);
  assert.equal(standIn.rows.get(environment.id)!.token, token);
  assert.ok(
    standIn.processes.every((p) => !p.running),
    "no exec left running",
  );

  await provider.destroy(environment.id, context);
  await assert.rejects(
    provider.reach(environment.id, context),
    kind("refused"),
  );
  assert.equal(standIn.connects.length, 3);
});

// Destroy terminates and is idempotent; the sandbox then reads as gone by
// request, and an unknown id is already destroyed.
test("destroy is idempotent", async () => {
  const { standIn, provider, context, provision } = await setup();
  const { environment } = await provision("vessel");
  await provider.destroy(environment.id, context);
  await provider.destroy(environment.id, context);
  await provider.destroy("sb-missing", context);
  assert.equal(standIn.calls.filter((c) => c === "terminate").length, 2);
  assert.deepEqual((await provider.inspect(environment.id, context)).state, {
    state: "gone",
    cause: { kind: "destroyed_by_request" },
  });
  await assert.rejects(
    provider.inspect("sb-missing", context),
    kind("not_found"),
  );
  // A terminate that failed claims nothing: a later end is the provider's.
  const other = (await provision("other")).environment;
  const box = await standIn.fromId(other.id);
  const fromId = standIn.fromId;
  standIn.fromId = async (id) => ({
    ...box,
    terminate: async () => {
      throw new ClientError(14, "unavailable");
    },
  });
  await assert.rejects(
    provider.destroy(other.id, context),
    kind("unavailable"),
  );
  standIn.fromId = fromId;
  standIn.expire(other.id, 137);
  assert.deepEqual((await provider.inspect(other.id, context)).state, {
    state: "gone",
    cause: { kind: "destroyed_at_provider" },
  });
});

// Inventory is this instance's running sandboxes, by app and tag; another
// instance's are not listed or inspectable. A sandbox ended by its timeout is
// gone at its lifetime cap; one terminated elsewhere is destroyed at Modal.
test("list and inspect observe this instance's sandboxes", async () => {
  const { standIn, provider, context, provision, advance } = await setup();
  const ids: string[] = [];
  for (const label of ["a", "b", "c", "d"])
    ids.push((await provision(label)).environment.id);
  // Another instance's sandbox in the same app.
  const [app] = standIn.apps.values();
  const foreign = (
    await standIn.create({ appId: app }, [...standIn.images][0], {
      tags: { [TAGS.provider]: "other", [TAGS.label]: "x" },
    })
  ).sandboxId;
  standIn.expire(ids[1]);
  standIn.expire(ids[2], 137);
  const rows = await provider.list(context);
  assert.deepEqual(rows.map((r) => r.id).sort(), [ids[0], ids[3]]);
  assert.ok(rows.every((r) => r.state.state === "running"));
  assert.deepEqual((await provider.inspect(ids[1], context)).state, {
    state: "gone",
    cause: { kind: "lifetime_cap_reached" },
  });
  assert.deepEqual((await provider.inspect(ids[2], context)).state, {
    state: "gone",
    cause: { kind: "destroyed_at_provider" },
  });
  // Terminated after its timeout: Modal reports a termination.
  advance(LIFETIME_SECONDS);
  standIn.expire(ids[3], 137);
  assert.deepEqual((await provider.inspect(ids[3], context)).state, {
    state: "gone",
    cause: { kind: "lifetime_cap_reached" },
  });
  await assert.rejects(provider.inspect(foreign, context), kind("not_found"));
});

// Quota is the count of live sandboxes against the configured limit.
test("quota counts live sandboxes", async () => {
  const { standIn, provider, context, provision } = await setup({
    concurrency_limit: 5,
  });
  const { environment } = await provision("a");
  await provision("b");
  standIn.expire(environment.id);
  assert.deepEqual(await provider.quota!(context), {
    resources: [],
    credits_remaining: null,
    credit_unit: null,
    concurrency_in_use: 1,
    concurrency_limit: 5,
  });
});

// Egress is measured only when the operator's probe runs as root on a
// running, restricted sandbox; DNS counted as egress makes it advisory.
test("the egress probe measures a restricted sandbox", async () => {
  const { standIn, provider, context, provision } = await setup({
    egress_probe: { command: ["/opt/drydock/egress-probe"] },
  });
  const deny = (await provision("deny")).environment;
  const open = (await provision("open", { mode: "open" })).environment;
  for (const [proof, egress, measured] of [
    [{ uid: 0, unlisted_canary: false, raw_dns: false }, "enforced", true],
    [{ uid: 0, unlisted_canary: false, raw_dns: true }, "advisory", true],
    [{ uid: 1000, unlisted_canary: false, raw_dns: false }, "advisory", true],
    [{ uid: 0 }, "enforced", false],
    [null, "enforced", false],
  ] as const) {
    standIn.execExit = proof ? 0 : 1;
    standIn.execStdout = JSON.stringify(
      proof ?? { uid: 0, unlisted_canary: false, raw_dns: false },
    );
    const row = await provider.inspect(deny.id, context);
    assert.deepEqual([row.egress, row.egress_measured], [egress, measured]);
  }
  assert.ok(standIn.calls.some((c) => c.includes("DRYDOCK_PROBE_DENY_ALL=1")));
  const probes = standIn.calls.filter((c) => c.includes("probe")).length;
  assert.equal(
    (await provider.inspect(open.id, context)).egress_measured,
    false,
  );
  assert.equal(standIn.calls.filter((c) => c.includes("probe")).length, probes);
  assert.ok(standIn.processes.every((p) => !p.running));
});

// Modal's typed errors and raw gRPC statuses become protocol errors: a token
// lacking a right is refused, only an unauthenticated one is rejected.
test("Modal failures map to protocol errors", async () => {
  for (const [error, expected] of [
    [new ClientError(16, "bad token"), "credential_rejected"],
    [new ClientError(7, "role lacks right"), "refused"],
    [new ClientError(8, "slow down"), "rate_limited"],
    [new ClientError(14, "unavailable"), "unavailable"],
    [new ClientError(5, "gone"), "not_found"],
    [new NotFoundError("App 'x' not found"), "not_found"],
    [new ResourceExhaustedError("Insufficient capacity"), "unavailable"],
    [
      new Error(
        "Image build for im-1 failed with the exception:\nmanifest unknown",
      ),
      "refused",
    ],
    [new Error("boom"), "internal"],
  ] as const)
    assert.equal(protocolError(error).detail.kind, expected, String(error));
  const { standIn, provider, context } = await setup();
  standIn.app = async () => {
    throw new ClientError(16, "invalid token");
  };
  await assert.rejects(provider.list(context), kind("credential_rejected"));
});

// A rotated credential gets a new client, and the old one closes.
test("a rotated credential closes its old client once", async () => {
  const { standIn, provider, context } = await setup();
  await provider.list(context);
  const rotated = {
    ...context,
    credential: JSON.stringify({ ...TOKEN, token_secret: "as-rotated" }),
  };
  await provider.list(rotated);
  await provider.list(rotated);
  assert.equal(standIn.closed, 1);
  assert.deepEqual(
    standIn.tokens.map((t) => t.token_secret),
    ["as-test-only", "as-rotated"],
  );
});

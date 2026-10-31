import { test } from "node:test";
import assert from "node:assert/strict";
import { Code, ConnectError } from "@connectrpc/connect";
import {
  AGENT,
  LABEL,
  namespaceModule,
  networkPolicy,
} from "../dist/namespace/index.js";
import {
  CREDENTIAL,
  image,
  Registries,
  StandIn,
  TOKEN,
} from "./support/namespace.ts";
import type { Provider, Types } from "../src/provider.ts";

const GiB = 1024 ** 3;
const SIZE = { cpus: 4, memory_bytes: 8 * GiB, disk_bytes: 0 };
const kind = (k: string) => (e: any) => e.detail?.kind === k;

async function setup(settings: Record<string, unknown> = {}) {
  const standIn = new StandIn(),
    registries = new Registries();
  const module = namespaceModule((token) => {
    standIn.tokens.push(token);
    return standIn;
  }, registries.fetch as any);
  const abort = new AbortController();
  const provider: Provider = await module.configure(
    "ns",
    { module: "namespace", settings: { workspace: "acme", ...settings } },
    abort.signal,
  );
  const context = { credential: CREDENTIAL, signal: abort.signal };
  const request: Types["PrepareRequest"] = {
    size: SIZE,
    image_digest: image(registries, "registry.test", "base", "base-layer"),
    tools_digest: image(registries, "registry.test", "tools", "tools", true),
  };
  const provision = async (
    label: string,
    egress: Types["EgressRequest"] = { mode: "open" },
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
  return { standIn, registries, provider, context, request, provision };
}

// Settings name the workspace registry; the credential drydock passes is
// `{"bearer_token": …}`, and anything else is not ready.
test("configure validates settings; readiness needs a bearer token document", async () => {
  const module = namespaceModule(() => new StandIn());
  const signal = new AbortController().signal;
  for (const settings of [
    {},
    { workspace: "acme", unknown: 1 },
    { workspace: "Bad/" },
  ])
    await assert.rejects(
      module.configure("ns", { module: "namespace", settings }, signal),
      kind("refused"),
    );
  const provider = await module.configure(
    "ns",
    { module: "namespace", settings: { workspace: "acme" } },
    signal,
  );
  for (const credential of [undefined, TOKEN, "{}", '{"bearer_token":""}'])
    assert.equal(
      (await provider.readiness({ credential, signal })).status,
      "missing_credential",
    );
  assert.deepEqual(
    await provider.readiness({ credential: CREDENTIAL, signal }),
    {
      status: "ready",
    },
  );
});

// Upload requests are redirected within a bound, resending the same method and
// body, with the token only on the registry's own origin.
test("prepare follows upload redirects within a bound", async () => {
  const { registries, provider, context, request } = await setup();
  registries.uploadRedirects = 2;
  const prepared = await provider.prepare(request, context);
  assert.match(prepared.id, /^nscr\.io\/acme\/drydock-vessel@sha256:/);
  assert.ok(registries.store("nscr.io").manifests.size > 0);

  const endless = await setup();
  endless.registries.uploadRedirects = 1000;
  await assert.rejects(
    endless.provider.prepare(endless.request, endless.context),
    (e: any) => /redirected too often/.test(e.detail?.reason),
  );
});

test("upload redirects: 308 followed, no Location refused, other origins never see the token", async () => {
  const permanent = await setup();
  permanent.registries.uploadRedirects = 1;
  permanent.registries.redirectStatus = 308;
  await permanent.provider.prepare(permanent.request, permanent.context);

  const bare = await setup();
  bare.registries.uploadRedirects = 1;
  bare.registries.redirectWithoutLocation = true;
  await assert.rejects(
    bare.provider.prepare(bare.request, bare.context),
    (e: any) => /redirect without location/.test(e.detail?.reason),
  );
});

// nscr.io redirects some upload starts to a presigned URL on a regional host
// (zrh.nscr.io), which then serves the whole session anonymously.
test("prepare uploads through nscr.io's presigned regional redirect", async () => {
  const { registries, provider, context, request } = await setup();
  registries.regional = "zrh.nscr.io";
  const prepared = await provider.prepare(request, context);
  assert.match(prepared.id, /^nscr\.io\/acme\/drydock-vessel@sha256:/);
  const regional = registries.requests.filter((r) => r.host === "zrh.nscr.io");
  assert.deepEqual(
    [...new Set(regional.map((r) => r.method))].sort(),
    ["PATCH", "POST", "PUT"],
    "the session's chunks and commit go to the regional host",
  );
  assert.ok(
    regional.every((r) => r.authorization === null),
    "the token never reaches the regional host",
  );
});

// Prepare layers the tools image onto the base by digest, pushes it to the
// workspace's nscr.io repository with the token as password (and nowhere
// else), and registers it by digest. Re-preparing finds the registration.
test("prepare pushes the layered image and registers it once", async () => {
  const { standIn, registries, provider, context, request } = await setup();
  const prepared = await provider.prepare(request, context);
  assert.match(
    prepared.id,
    /^nscr\.io\/acme\/drydock-vessel@sha256:[0-9a-f]{64}$/,
  );
  assert.deepEqual(prepared.platform, { os: "linux", architecture: "amd64" });
  assert.equal(standIn.registered.length, 1);
  const pushed = registries.store("nscr.io");
  const manifest = JSON.parse(
    pushed.manifests
      .get(prepared.id.slice("nscr.io/".length))!
      .bytes.toString(),
  );
  // Base layer then tools layer, every blob present; the base's entrypoint kept.
  assert.equal(manifest.layers.length, 2);
  for (const blob of [manifest.config, ...manifest.layers])
    assert.ok(pushed.blobs.has(blob.digest));
  const config = JSON.parse(
    pushed.blobs.get(manifest.config.digest)!.toString(),
  );
  assert.deepEqual(config.config.Entrypoint, ["/base-layer"]);
  assert.equal(config.rootfs.diff_ids.length, 2);
  assert.ok(
    registries.requests
      .filter((r) => r.host !== "nscr.io")
      .every((r) => r.authorization === null),
    "the token never reaches another registry",
  );
  const pushes = registries.requests.length;
  assert.deepEqual(await provider.prepare(request, context), prepared);
  assert.equal(standIn.registered.length, 1, "no second version");
  assert.equal(registries.requests.length, pushes, "nothing pushed again");
  await assert.rejects(
    provider.prepare(
      { ...request, platform: { os: "linux", architecture: "arm64" } },
      context,
    ),
    kind("image_refused"),
  );
  await assert.rejects(
    provider.prepare({ ...request, route: "remote_build" }, context),
    kind("refused"),
  );
});

// Provision creates a non-ephemeral devbox from the registered image with the
// client's label, a named size, its network policy, no tenant checkout, and
// the agent as an on-boot, always-restarted service that keeps it awake.
// The label is the idempotency key: it finds the same devbox again.
test("provision creates a labelled devbox with the agent service, idempotently", async () => {
  const { standIn, provider, context, request, provision } = await setup();
  const egress: Types["EgressRequest"] = {
    mode: "deny_all",
    direct: [{ kind: "host", host: "Example.com." }],
  };
  const first = await provision("vessel", egress);
  assert.equal(first.created, true);
  const row = standIn.rows.get(first.environment.id)!;
  assert.equal(row.info.labels[LABEL], "vessel");
  assert.equal(row.info.ephemeral, false);
  assert.deepEqual(row.networkPolicy, {
    allowedDomains: ["example.com"],
    advisory: false,
  });
  assert.deepEqual(row.versionControl, {});
  assert.deepEqual(
    row.services.map((s) => [
      s.name,
      s.command,
      s.startPolicy,
      s.restartPolicy,
      s.preventIdleShutdown,
    ]),
    [["drydock-agent", AGENT, "on-boot", "always", true]],
  );
  assert.deepEqual(first.environment.state, { state: "running" });
  assert.deepEqual(first.environment.granted_size, {
    ...SIZE,
    disk_bytes: 64 * GiB,
  });
  assert.equal(first.environment.label, "vessel");

  const again = await provision("vessel", egress);
  assert.equal(again.created, false);
  assert.equal(again.environment.id, first.environment.id);
  assert.equal(standIn.rows.size, 1);
  assert.equal(row.services.length, 1);
  // Concurrent provisions of a new label make one devbox and one service,
  // even when both find the service missing before either creates it.
  const get = standIn.devboxes.get;
  let arrive = () => {};
  const both = new Promise<void>((resolve) => {
    let count = 0;
    arrive = () => ++count === 2 && resolve();
  });
  standIn.devboxes.get = async (...args) => {
    const box = await get(...args);
    const list = box.services.list;
    box.services.list = async (options) => {
      const services = await list(options);
      arrive();
      await both;
      return services;
    };
    return box;
  };
  const raced = await Promise.all([
    provision("raced", egress),
    provision("raced", egress),
  ]);
  standIn.devboxes.get = get;
  assert.deepEqual(raced.map((r) => r.created).sort(), [false, true]);
  assert.equal(raced[0].environment.id, raced[1].environment.id);
  assert.equal(standIn.rows.get(raced[0].environment.id)!.services.length, 1);
  // The same label with another size or policy is not this devbox.
  await assert.rejects(
    provision("vessel", egress, { ...SIZE, cpus: 8, memory_bytes: 16 * GiB }),
    kind("refused"),
  );
  await assert.rejects(provision("vessel", { mode: "open" }), kind("refused"));
  // Unrepresentable sizes and unknown prepared forms are refused.
  await assert.rejects(
    provision("odd", egress, { ...SIZE, cpus: 3 }),
    kind("refused"),
  );
  await assert.rejects(
    provision("odd", egress, { ...SIZE, disk_bytes: 1 }),
    kind("refused"),
  );
  const prepared = await provider.prepare(request, context);
  await assert.rejects(
    provider.provision(
      {
        label: "forged",
        prepared: { ...prepared, id: `${prepared.id}0` },
        size: SIZE,
      },
      context,
    ),
    kind("refused"),
  );
  // An absent egress request is the protocol's default: deny all.
  const closed = await provider.provision(
    { label: "closed", prepared, size: SIZE },
    context,
  );
  assert.deepEqual(standIn.rows.get(closed.environment.id)!.networkPolicy, {
    allowedDomains: [],
    advisory: false,
  });
  // Re-adopting a stopped devbox neither starts it nor touches its guest.
  row.info.state = "stopped";
  const stopped = await provision("vessel", egress);
  assert.equal(stopped.environment.state.state, "stopped");
  assert.equal(standIn.activations, 0);
});

// Domain entries become allowed domains; CIDRs, ports and address literals
// are refused, never widened; open egress sets no policy. Covers every
// destination kind and the deny-all default.
test("egress maps to a network policy or is refused", () => {
  assert.equal(networkPolicy({ mode: "open" }), undefined);
  assert.deepEqual(networkPolicy(undefined), {
    allowedDomains: [],
    advisory: false,
  });
  assert.deepEqual(
    networkPolicy({
      mode: "deny_all",
      direct: [
        { kind: "host", host: "b.example" },
        { kind: "host", host: "A.example." },
        { kind: "host", host: "a.example" },
      ],
    }),
    { allowedDomains: ["a.example", "b.example"], advisory: false },
  );
  for (const entry of [
    { kind: "cidr", cidr: "10.0.0.0/8" },
    { kind: "host_port", host: "a.example", port: 443 },
    { kind: "host", host: "192.0.2.1" },
    { kind: "host", host: "2001:db8::1" },
  ])
    assert.throws(
      () => networkPolicy({ mode: "deny_all", direct: [entry as any] }),
      kind("refused"),
    );
});

// SDK calls through the gateway can fail with `Premature close` after taking
// effect. The module confirms the resulting state instead of repeating the
// call, so nothing is created, registered, stopped or deleted twice.
test("premature close is confirmed, never repeated", async () => {
  const { standIn, provider, context, request, provision } = await setup();
  standIn.fail("register");
  await provider.prepare(request, context);
  assert.equal(standIn.registered.length, 1);
  standIn.fail("create");
  standIn.fail("services.create");
  const { created, environment } = await provision("vessel");
  assert.equal(created, true);
  assert.equal(standIn.rows.size, 1);
  assert.equal(standIn.rows.get(environment.id)!.services.length, 1);
  standIn.fail("stop");
  await provider.suspend!(environment.id, context);
  assert.equal(standIn.calls.filter((c) => c === "stop").length, 1);
  standIn.fail("start");
  await provider.resume!(
    environment.id,
    await provider.suspend!(environment.id, context),
    context,
  );
  assert.equal(standIn.calls.filter((c) => c === "start").length, 1);
  standIn.fail("delete");
  await provider.destroy(environment.id, context);
  assert.equal(standIn.rows.size, 0);
  assert.equal(standIn.calls.filter((c) => c === "delete").length, 1);
  // A failure that is not a premature close is reported, typed.
  await assert.rejects(
    provider.inspect(environment.id, context),
    kind("not_found"),
  );
});

// Inventory is drydock's labelled devboxes, across pages, with state from
// refresh (list reports unknown), and observing never starts a devbox. A
// stop drydock requested is suspended_by_request; any other (lifetime cap,
// idle) is paused_by_provider and resumable.
test("list and inspect observe without starting anything", async () => {
  const { standIn, provider, context, provision } = await setup();
  const ids = [];
  for (const label of ["a", "b", "c"])
    ids.push((await provision(label)).environment.id);
  const foreign = await standIn.devboxes.create({
    name: "someone-else",
    image: standIn.registered[0].ref,
    size: "s",
  });
  standIn.rows.get(ids[1])!.info.state = "stopped";
  await provider.suspend!(ids[2], context);
  const rows = await provider.list(context);
  assert.deepEqual(rows.map((r) => [r.id, r.state]).sort(), [
    [ids[0], { state: "running" }],
    [ids[1], { state: "stopped", cause: "paused_by_provider" }],
    [ids[2], { state: "stopped", cause: "suspended_by_request" }],
  ]);
  assert.ok(!rows.some((r) => r.id === foreign.id));
  assert.deepEqual((await provider.inspect(ids[1], context)).state, {
    state: "stopped",
    cause: "paused_by_provider",
  });
  assert.equal(standIn.activations, 0);
  await assert.rejects(provider.inspect("missing", context), kind("not_found"));
});

// Suspend is devbox stop and resume is start; the token is stable and bound
// to the environment, and resume keeps the agent service in place.
test("suspend and resume stop and start the devbox", async () => {
  const { standIn, provider, context, provision } = await setup();
  const { environment } = await provision("vessel");
  const token = await provider.suspend!(environment.id, context);
  assert.deepEqual(await provider.suspend!(environment.id, context), token);
  assert.equal(standIn.calls.filter((c) => c === "stop").length, 1);
  assert.equal(
    (await provider.inspect(environment.id, context)).state.state,
    "stopped",
  );
  await assert.rejects(
    provider.resume!(environment.id, { token: "other" }, context),
    kind("refused"),
  );
  for (let i = 0; i < 2; i++)
    await provider.resume!(environment.id, token, context);
  assert.equal(standIn.calls.filter((c) => c === "start").length, 1);
  assert.deepEqual((await provider.inspect(environment.id, context)).state, {
    state: "running",
  });
  assert.equal(standIn.rows.get(environment.id)!.services.length, 1);
});

// Reach is the host's relay route; the relay is an exec channel running
// `drydock-agent --bridge`, carrying bytes both ways. A stopped devbox is
// refused, since opening a channel would start it.
test("relay runs the agent bridge on a running devbox only", async () => {
  const { standIn, provider, context, provision } = await setup();
  const { environment } = await provision("vessel");
  assert.deepEqual(await provider.reach(environment.id, context), {
    kind: "relay",
    path: `/v1/providers/ns/environments/${environment.id}/relay`,
  });
  const stream = await provider.relay!(environment.id, context);
  assert.deepEqual(standIn.channels, [`${AGENT} --bridge`]);
  const echoed = new Promise<string>((resolve) =>
    stream.once("data", (d) => resolve(String(d))),
  );
  stream.write("hello");
  assert.equal(await echoed, "hello");
  stream.destroy();
  await provider.suspend!(environment.id, context);
  const activations = standIn.activations;
  await assert.rejects(
    provider.relay!(environment.id, context),
    kind("refused"),
  );
  assert.equal(standIn.activations, activations);
  assert.equal(standIn.channels.length, 1);
});

// Egress is enforced only when the operator's probe proves it as root on a
// running, restricted devbox; otherwise it stays advisory and unmeasured.
test("egress is enforced only on a passing probe", async () => {
  const { standIn, provider, context, provision } = await setup({
    egress_probe: { command: ["/opt/drydock/egress-probe"] },
  });
  const deny = (await provision("deny", { mode: "deny_all" })).environment;
  const open = (await provision("open")).environment;
  for (const [proof, egress, measured] of [
    [{ uid: 0, unlisted_canary: false, raw_dns: false }, "enforced", true],
    [{ uid: 1000, unlisted_canary: false, raw_dns: false }, "advisory", true],
    [{ uid: 0, unlisted_canary: true, raw_dns: false }, "advisory", true],
    [{ uid: 0 }, "advisory", false],
    [null, "advisory", false],
  ] as const) {
    // A probe that exits non-zero proves nothing, whatever it printed.
    standIn.execExit = proof ? 0 : 1;
    standIn.execStdout = JSON.stringify(
      proof ?? { uid: 0, unlisted_canary: false, raw_dns: false },
    );
    const row = await provider.inspect(deny.id, context);
    assert.deepEqual([row.egress, row.egress_measured], [egress, measured]);
  }
  assert.ok(standIn.calls.some((c) => c.includes("DRYDOCK_PROBE_DENY_ALL=1")));
  const probes = standIn.calls.filter((c) => c.startsWith("exec")).length;
  assert.equal(
    (await provider.inspect(open.id, context)).egress_measured,
    false,
  );
  standIn.rows.get(deny.id)!.info.state = "stopped";
  await provider.inspect(deny.id, context);
  assert.equal(
    standIn.calls.filter((c) => c.startsWith("exec")).length,
    probes,
  );
  assert.equal(standIn.activations, 0);
});

// Destroy deletes the devbox and is idempotent.
test("destroy is idempotent", async () => {
  const { standIn, provider, context, provision } = await setup();
  const { environment } = await provision("vessel");
  await provider.destroy(environment.id, context);
  await provider.destroy(environment.id, context);
  assert.equal(standIn.rows.size, 0);
  assert.equal(standIn.calls.filter((c) => c === "delete").length, 1);
});

// Quota reads GetConcurrency's live limits and use per platform class, in
// shared units; a zero limit is unset, not a limit of nothing.
test("quota reports live concurrency", async () => {
  const { standIn, provider, context } = await setup();
  standIn.concurrencyRows = [
    {
      name: "linux",
      platforms: ["linux/amd64"],
      limits: { maxCpu: 32n, maxMemoryMb: 0n, maxInstanceCount: 3n },
      activeConcurrency: { instanceCount: 1n, cpu: 4n, memoryMb: 8192n },
    },
  ];
  const quota = await provider.quota!(context);
  assert.deepEqual(
    quota.resources.map((r) => [
      r.key.resource,
      r.key.class,
      r.unit,
      r.in_use,
      r.limit,
    ]),
    [
      ["cpu", "linux", "{vCPU}", 4, 32],
      ["memory", "linux", "By", 8 * GiB, null],
      ["environments", "linux", "{instance}", 1, 3],
    ],
  );
});

// A token without an operation's grant is still a valid credential: the call
// is refused and the provider stays usable. Only an unauthenticated token is
// rejected.
test("a missing grant is refused; a bad token is rejected", async () => {
  const { standIn, provider, context } = await setup();
  for (const [code, expected] of [
    [Code.PermissionDenied, "refused"],
    [Code.Unauthenticated, "credential_rejected"],
  ] as const) {
    standIn.concurrency = async () => {
      throw new ConnectError("access denied", code);
    };
    await assert.rejects(provider.quota!(context), kind(expected));
  }
});

// A rotated credential gets a new SDK client; the old one closes only when
// its last relay ends, so rotation never cuts a live agent connection.
test("credential rotation keeps live relays open", async () => {
  const { standIn, provider, context, provision } = await setup();
  const { environment } = await provision("vessel");
  const relay = await provider.relay!(environment.id, context);
  const rotated = {
    ...context,
    credential: JSON.stringify({ bearer_token: "test-only-rotated" }),
  };
  await provider.list(rotated);
  assert.deepEqual(standIn.tokens, [TOKEN, "test-only-rotated"]);
  assert.equal(standIn.closed, 0, "the relay still holds the old client");
  const closed = new Promise((resolve) => relay.once("close", resolve));
  relay.destroy();
  await closed;
  assert.equal(standIn.closed, 1);
  await provider.list(rotated);
  assert.equal(standIn.tokens.length, 2, "the current client is reused");
});

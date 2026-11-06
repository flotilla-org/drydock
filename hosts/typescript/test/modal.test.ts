import { test } from "node:test";
import assert from "node:assert/strict";
import { modalModule, resources, TAGS } from "../dist/modal/index.js";
import { AGENT_TOKEN, CREDENTIAL, StandIn } from "./support/modal.ts";
import type { Provider, Types } from "../src/provider.ts";

const MiB = 1024 ** 2;
const SIZE = { cpus: 2, memory_bytes: 512 * MiB, disk_bytes: 0 };
const DIGEST = `sha256:${"0".repeat(64)}`;
const kind = (k: string) => (e: any) => e.detail?.kind === k;

async function setup(
  settings: Record<string, unknown> = {},
  ownership?: Types["Ownership"],
) {
  const standIn = new StandIn();
  const module = modalModule(() => standIn.client() as any);
  const signal = new AbortController().signal;
  const provider: Provider = await module.configure(
    "modal",
    { module: "modal", settings, ...(ownership && { ownership }) },
    signal,
  );
  const context = { credential: CREDENTIAL, signal };
  const provision = (
    label = "work",
    egress: Types["EgressRequest"] = { mode: "open" },
  ) =>
    provider.provision(
      {
        label,
        size: SIZE,
        egress,
        prepared: {
          provider: "modal",
          id: "im-1",
          platform: { os: "linux", architecture: "amd64" },
          image_digest: `198.51.100.1/base@${DIGEST}`,
          tools_digest: `198.51.100.1/tools@${DIGEST}`,
        },
      },
      context,
    );
  return { standIn, provider, context, provision };
}

test("a requested disk is accepted and not applied", () => {
  const size = { cpus: 2, memory_bytes: 512 * MiB, disk_bytes: 10 * 1024 ** 3 };
  assert.deepEqual(resources(size), { cpu: 2, memoryMiB: 512 });
});

test("memory still must be whole MiB", () => {
  assert.throws(() =>
    resources({ cpus: 1, memory_bytes: MiB + 1, disk_bytes: 0 }),
  );
});

test("the module declares that it settles, dedupes and scopes nothing itself", async () => {
  const { provider } = await setup();
  assert.deepEqual(provider.capabilities.semantics, {
    settles: false,
    idempotent: false,
    owner_scoped: false,
    token_is_id: false,
  });
  assert.equal(provider.capabilities.exclusive_label, undefined);
  assert.equal(provider.capabilities.quota, false);
  assert.equal(provider.quota, undefined);
});

test("settings outside their bounds are refused", async () => {
  for (const settings of [
    { lifetime_seconds: 0 },
    { lifetime_seconds: 86_401 },
    { list_concurrency: 0 },
    { agent_wait_seconds: 0 },
    { concurrency_limit: 4 },
  ])
    await assert.rejects(setup(settings), kind("refused"));
});

test("prepare builds the base with drydock's tools copied in, with the pull secret", async () => {
  const { standIn, provider, context } = await setup();
  const prepared = await provider.prepare(
    {
      size: SIZE,
      image_digest: `198.51.100.1/base@${DIGEST}`,
      tools_digest: `198.51.100.1/tools@${DIGEST}`,
      image_pull: { username: "u", secret: "p" },
    },
    context,
  );
  assert.equal(prepared.id, "im-1");
  assert.deepEqual(standIn.builds, [
    {
      reference: `198.51.100.1/base@${DIGEST}`,
      commands: [
        `COPY --from=198.51.100.1/tools@${DIGEST} /opt/drydock/ /opt/drydock/`,
      ],
      secret: { entries: { REGISTRY_USERNAME: "u", REGISTRY_PASSWORD: "p" } },
    },
  ]);
});

test("prepare refuses a registry on a private address", async () => {
  const { provider, context } = await setup();
  await assert.rejects(
    provider.prepare(
      {
        size: SIZE,
        image_digest: `10.0.0.1:5000/base@${DIGEST}`,
        tools_digest: `198.51.100.1/tools@${DIGEST}`,
      },
      context,
    ),
    kind("refused"),
  );
});

test("provision is one unnamed create tagged with the label and owner, then the agent's start", async () => {
  const { standIn, provision } = await setup({
    lifetime_seconds: 3600,
    agent_wait_seconds: 5,
  });
  const { created, environment } = await provision("work", {
    mode: "deny_all",
    direct: [
      { kind: "host", host: "Example.COM." },
      { kind: "cidr", cidr: "192.0.2.0/24" },
    ],
  });
  assert.equal(created, true);
  // Modal's create answers with the id alone.
  assert.deepEqual(environment, {
    provider: "modal",
    id: "sb-1",
    label: "work",
    state: { state: "unknown", reason: "provider_state_unknown" },
    egress: "advisory",
  });
  const params = standIn.rows.get("sb-1")!.params;
  assert.equal(params.name, undefined);
  assert.deepEqual(params.tags, {
    [TAGS.label]: "work",
    [TAGS.provider]: "modal",
  });
  assert.equal(params.timeoutMs, 3_600_000);
  assert.deepEqual(params.outboundCidrAllowlist, ["192.0.2.0/24"]);
  assert.deepEqual(params.outboundDomainAllowlist, ["example.com"]);
  assert.deepEqual(standIn.calls, ["create", "exec sb-1"]);
  assert.match(standIn.scripts[0], /seq 50\b/);
});

test("on an owned account a sandbox carries the label alone", async () => {
  const { standIn, provision } = await setup({}, "owned_account");
  await provision();
  assert.deepEqual(standIn.rows.get("sb-1")!.params.tags, {
    [TAGS.label]: "work",
  });
});

test("provisioning a label twice makes two sandboxes", async () => {
  const { provision } = await setup();
  const first = await provision();
  const second = await provision();
  assert.notEqual(first.environment.id, second.environment.id);
});

test("a create Modal refuses is refused in Modal's words", async () => {
  const { standIn, provision } = await setup();
  standIn.refuseCreate = "name already taken";
  await assert.rejects(provision(), (e: any) => {
    assert.equal(e.detail.kind, "refused");
    assert.match(e.detail.reason, /name already taken/);
    return true;
  });
});

test("an agent that does not start fails provision and leaves the sandbox", async () => {
  const { standIn, provision } = await setup();
  standIn.agentExit = 1;
  await assert.rejects(provision(), kind("internal"));
  assert.equal(standIn.rows.get("sb-1")!.exit, null);
  assert.ok(!standIn.calls.some((c) => c.startsWith("terminate")));
});

test("list on a shared account asks Modal for this instance's sandboxes and reads each one's tags", async () => {
  const { standIn, provider, context } = await setup({ list_concurrency: 2 });
  const tags = { [TAGS.label]: "a", [TAGS.provider]: "modal" };
  standIn.add(tags);
  standIn.add({ [TAGS.provider]: "other" });
  standIn.add(tags, 0);
  assert.deepEqual(await provider.list(context), [
    {
      provider: "modal",
      id: "sb-1",
      label: "a",
      state: { state: "running" },
      egress: "advisory",
      vendor: { state: "running", tags },
    },
  ]);
  assert.equal(standIn.calls[0], `list {"${TAGS.provider}":"modal"}`);
});

test("list on an owned account reports every running sandbox, labelled or not", async () => {
  const { standIn, provider, context } = await setup({}, "owned_account");
  standIn.add({ [TAGS.label]: "a" });
  standIn.add({});
  const rows = await provider.list(context);
  assert.deepEqual(
    rows.map((r) => [r.id, r.label, r.vendor?.tags]),
    [
      ["sb-1", "a", { [TAGS.label]: "a" }],
      ["sb-2", undefined, {}],
    ],
  );
  assert.equal(standIn.calls[0], "list {}");
});

test("a sandbox gone between the list and its tag read is left out", async () => {
  const { standIn, provider, context } = await setup();
  standIn.vanishAfterList.add(standIn.add({ [TAGS.provider]: "modal" }));
  assert.deepEqual(await provider.list(context), []);
});

test("inspect reports a running sandbox as Modal's poll states it, with its tags, unchecked", async () => {
  const { standIn, provider, context } = await setup();
  const tags = { [TAGS.label]: "x", [TAGS.provider]: "someone-else" };
  const id = standIn.add(tags);
  assert.deepEqual(await provider.inspect(id, context), {
    provider: "modal",
    id,
    label: "x",
    state: { state: "running" },
    egress: "advisory",
    vendor: { state: "running", tags },
  });
});

test("inspect reports an ended sandbox gone with no cause, and its exit code as Modal's reason", async () => {
  const { standIn, provider, context } = await setup();
  const id = standIn.add({}, 137);
  const row = await provider.inspect(id, context);
  assert.deepEqual(row.state, { state: "gone" });
  assert.deepEqual(row.vendor, {
    state: "finished",
    reason: "exit code 137",
    tags: {},
  });
});

test("inspect of a sandbox Modal does not know is not found", async () => {
  const { provider, context } = await setup();
  await assert.rejects(provider.inspect("sb-404", context), kind("not_found"));
});

test("destroy is one terminate that does not wait, and Modal's not found is the answer", async () => {
  const { standIn, provider, context } = await setup();
  const id = standIn.add({ [TAGS.provider]: "someone-else" });
  await provider.destroy(id, context);
  assert.deepEqual(standIn.calls, [`terminate ${id} {}`]);
  await assert.rejects(provider.destroy("sb-404", context), kind("not_found"));
});

test("reach dials the agent through Modal's edge with no expiry, starting the agent only when its token is unknown", async () => {
  const { standIn, provider, context, provision } = await setup();
  const { environment } = await provision();
  standIn.calls.length = 0;
  const reach = await provider.reach(environment.id, context);
  assert.deepEqual(reach, {
    kind: "dial",
    url: `https://${environment.id}.modal.test/v1/connect?_modal_connect_token=connect-token`,
    token: AGENT_TOKEN,
  });
  assert.deepEqual(standIn.calls, [
    `createConnectToken ${environment.id} 7811`,
  ]);
  // Another host process knows no token: it starts the agent, which hands back the one it has.
  const other = standIn.add({});
  standIn.calls.length = 0;
  await provider.reach(other, context);
  assert.deepEqual(standIn.calls, [
    `exec ${other}`,
    `createConnectToken ${other} 7811`,
  ]);
});

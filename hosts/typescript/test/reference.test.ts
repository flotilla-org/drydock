import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import reference from "../dist/reference.js";
import { serve } from "../dist/server.js";
import { bodySchema, compile } from "../dist/validation.js";
// Main-server conformance owns lifecycle, idempotency and polling/replay.
// This trait-level scenario covers only reference-owned settings, canonical
// prepared keys and clone isolation across reordered object members.
test("reference validates settings and owns deterministic prepared keys", async () => {
  const abort = new AbortController(),
    context = { credential: "test-only", signal: abort.signal };
  for (const settings of [{ unknown: true }, { seed_unlabelled: "true" }])
    await assert.rejects(
      reference.configure("a", { module: "reference", settings }, abort.signal),
      (e: any) => e.detail.kind === "refused",
    );
  const provider = await reference.configure(
    "a",
    { module: "reference" },
    abort.signal,
  );
  await assert.rejects(
    provider.inspect("unknown", context),
    (e: any) => e.detail.kind === "not_found",
  );
  const input = {
    platform: { os: "linux", architecture: "amd64" },
    route: "remote_build",
    size: { cpus: 1, memory_bytes: 1, disk_bytes: 0 },
    image_digest: "image",
    tools_digest: "tools",
  };
  for (const invalid of [
    { ...input, platform: undefined },
    { ...input, route: "registry_pull" },
  ])
    await assert.rejects(
      provider.prepare(invalid, context),
      (e: any) => e.detail.kind === "refused",
    );
  const prepared = await provider.prepare(input, context);
  assert.deepEqual(
    await provider.prepare(
      {
        ...input,
        platform: { architecture: "amd64", os: "linux" },
        size: { disk_bytes: 0, memory_bytes: 1, cpus: 1 },
      },
      context,
    ),
    prepared,
  );
  assert.equal(
    (await provider.prepare({ ...input, tools_digest: "other-tools" }, context))
      .id,
    prepared.id,
  );
  prepared.platform.os = "mutated";
  assert.equal((await provider.prepare(input, context)).platform.os, "linux");
  abort.abort();
  await assert.rejects(provider.prepare(input, context), {
    name: "AbortError",
  });
});
// The built-in reference is always loaded, so a user module cannot shadow it.
test("a user module named reference is refused at startup", async (t) => {
  const dir = await mkdtemp(`${tmpdir()}/drydock-reference-`);
  t.after(() => rm(dir, { recursive: true, force: true }));
  await assert.rejects(
    serve([reference, { ...reference }], `${dir}/host.sock`),
    /duplicate module/,
  );
});
// Absent optional fields are omitted from the written JSON, never `null`.
test("reference writes omit absent optional fields", async () => {
  const abort = new AbortController(),
    provider = await reference.configure(
      "a",
      { module: "reference", settings: { seed_unlabelled: true } },
      abort.signal,
    ),
    row = await provider.inspect("unlabelled", {
      credential: "test-only",
      signal: abort.signal,
    }),
    written = JSON.parse(JSON.stringify(row));
  for (const field of ["label", "granted_size", "platform", "timestamp"])
    assert.equal(field in written, false, field);
  assert.equal(written.id, "unlabelled");
});
// Readers take a missing optional field and an explicit `null` as the same absence.
test("readers accept omitted and null optional fields", () => {
  const environment = compile(bodySchema("Environment")),
    quota = compile(bodySchema("Quota")),
    omitted = {
      id: "e",
      provider: "a",
      state: { state: "running" },
      egress: "advisory",
    };
  assert.equal(environment(omitted), true);
  assert.equal(
    environment({
      ...omitted,
      label: null,
      granted_size: null,
      platform: null,
      timestamp: null,
      egress_policy: null,
    }),
    true,
  );
  assert.equal(quota({}), true);
  assert.equal(quota({ credits_remaining: null, credit_unit: null }), true);
});

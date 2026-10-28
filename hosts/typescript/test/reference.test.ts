import { test } from "node:test";
import assert from "node:assert/strict";
import reference from "../dist/reference.js";
// Main-server conformance owns lifecycle, idempotency, polling/replay and relay.
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
  assert.notEqual(
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

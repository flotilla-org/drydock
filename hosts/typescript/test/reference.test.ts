import { test } from "node:test";
import assert from "node:assert/strict";
import reference from "../dist/reference.js";
// The reference's only extra unit scenario is its push source: updates and
// explicit removals are provider facts. Main-server conformance covers lifecycle.
test("reference push source emits facts/removals and honors cancellation", async () => {
  const signal = new AbortController();
  const context = {
    credentials: {
      mode: { mode: "direct" as const, credential_reference: "test" },
      value: "test-only",
    },
    signal: signal.signal,
  };
  const p = await reference.configure(
    {
      name: "a",
      module: "reference",
      settings: { push: true },
      credential: context.credentials.mode,
    },
    signal.signal,
  );
  assert.equal(p.observation, "Push");
  const updates = p.subscribe(context)[Symbol.asyncIterator]();
  const next = updates.next();
  const size = { cpus: 1, memory_bytes: 1, disk_bytes: 0 };
  const prepared = await p.prepare(
    {
      platform: { os: "linux", architecture: "amd64" },
      route: "remote_build",
      size,
      image_digest: "image",
      tools_digest: "tools",
    },
    context,
  );
  const created = await p.provision(
    { prepared, size, label: "push", egress: { mode: "deny_all" } },
    context,
  );
  assert.ok("Created" in created);
  assert.deepEqual((await next).value, { Observed: created.Created });
  const removed = updates.next();
  await p.destroy(created.Created.environment.id, context);
  const update = (await removed).value;
  assert.ok(update && "Removed" in update);
  assert.equal(update.Removed.id, created.Created.environment.id);
  const stopped = updates.next();
  signal.abort();
  await assert.rejects(stopped, { name: "AbortError" });
});

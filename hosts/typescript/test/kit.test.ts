import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { privateAddress, privateRegistry, Suspensions } from "../dist/kit.js";

test("private addresses and registries", async () => {
  for (const address of [
    "10.1.2.3",
    "192.0.0.5",
    "198.19.0.1",
    "255.255.255.255",
    "fec0::1",
    "::1",
    "::ffff:10.0.0.1",
    "::ffff:a00:1",
  ])
    assert.ok(privateAddress(address), address);
  for (const address of ["8.8.8.8", "2606:4700::1", "::ffff:808:808"])
    assert.ok(!privateAddress(address), address);
  for (const registry of [
    "localhost:5000",
    "registry",
    "r.internal",
    "10.0.0.1:443",
    "[::1]:5000",
    "::1",
  ])
    assert.ok(await privateRegistry(registry), registry);
  assert.ok(!(await privateRegistry("8.8.8.8")));
});

test("suspensions survive a restart and tolerate an unwritable directory", () => {
  const dir = mkdtempSync(join(tmpdir(), "drydock-"));
  const before = new Suspensions("Test", "i", dir);
  before.record("a");
  assert.ok(new Suspensions("Test", "i", dir).has("a"));
  new Suspensions("Test", "i", dir).forget("a");
  assert.ok(!new Suspensions("Test", "i", dir).has("a"));
  const file = join(dir, "file");
  writeFileSync(file, "");
  const blocked = new Suspensions("Test", "i", join(file, "below"));
  blocked.record("b");
  assert.ok(blocked.has("b"));
  blocked.forget("b");
  assert.ok(!blocked.has("b"));
});

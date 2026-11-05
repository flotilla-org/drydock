import { test } from "node:test";
import assert from "node:assert/strict";
import { resources } from "../dist/modal/index.js";

const MiB = 1024 ** 2;

test("a requested disk is accepted and not applied", () => {
  const size = { cpus: 2, memory_bytes: 512 * MiB, disk_bytes: 10 * 1024 ** 3 };
  assert.deepEqual(resources(size), { cpu: 2, memoryMiB: 512 });
});

test("memory still must be whole MiB", () => {
  assert.throws(() =>
    resources({ cpus: 1, memory_bytes: MiB + 1, disk_bytes: 0 }),
  );
});

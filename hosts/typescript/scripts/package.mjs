// pnpm pack intentionally omits pnpm-lock.yaml. Retain it in the companion
// distribution so production dependency installation can use --frozen-lockfile.
import { mkdtemp, cp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const root = fileURLToPath(new URL("../", import.meta.url));
const temporary = await mkdtemp(join(tmpdir(), "drydock-typescript-package-"));
try {
  const directory = join(temporary, "package");
  await mkdir(directory);
  for (const name of [
    "dist",
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "README.md",
  ])
    await cp(join(root, name), join(directory, name), { recursive: true });
  const archive = join(root, "flotilla-drydock-host-typescript-0.1.0.tgz");
  const result = spawnSync(
    "tar",
    ["-czf", archive, "-C", temporary, "package"],
    { stdio: "inherit" },
  );
  if (result.status !== 0) throw Error("companion packaging failed");
  console.log(archive);
} finally {
  await rm(temporary, { recursive: true, force: true });
}

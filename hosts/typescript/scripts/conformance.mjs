import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const root = new URL("../../../", import.meta.url);
const result = spawnSync(
  "cargo",
  [
    "test",
    "--locked",
    "-p",
    "drydock",
    "--test",
    "typescript_conformance",
    "--",
    "--nocapture",
  ],
  {
    cwd: root,
    stdio: "inherit",
    env: {
      ...process.env,
      DRYDOCK_TYPESCRIPT_TEST_BIN: fileURLToPath(
        new URL("../dist/main.js", import.meta.url),
      ),
    },
  },
);
if (result.status !== 0) process.exit(result.status ?? 1);
// Exercise the installed daemon/CLI path too. Host-only contracts above use the
// direct endpoint because the daemon does not forward /v1/config or bearer auth.
const cli = spawnSync(
  "python3",
  [fileURLToPath(new URL("./conformance.py", import.meta.url))],
  { cwd: root, stdio: "inherit" },
);
process.exit(cli.status ?? 1);

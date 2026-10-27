// The existing checker runs above the actual main server, not inside this host.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const result = spawnSync(
  "cargo",
  [
    "test",
    "--locked",
    "-p",
    "drydock",
    "--test",
    "typescript",
    "--",
    "--ignored",
    "--nocapture",
  ],
  {
    cwd: new URL("../../../", import.meta.url),
    stdio: "inherit",
    env: {
      ...process.env,
      DRYDOCK_TYPESCRIPT_TEST_BIN: fileURLToPath(
        new URL("../dist/main.js", import.meta.url),
      ),
    },
  },
);
process.exit(result.status ?? 1);

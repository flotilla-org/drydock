// The existing checker runs above the actual main server, not inside this host.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const test = "typescript_reference_conforms_through_main_server";
const args = [
  "test",
  "--locked",
  "-p",
  "drydock",
  "--test",
  "typescript",
  "--",
  "--ignored",
  "--exact",
  test,
];
const options = {
  cwd: new URL("../../../", import.meta.url),
  env: {
    ...process.env,
    DRYDOCK_TYPESCRIPT_TEST_BIN: fileURLToPath(
      new URL("../dist/main.js", import.meta.url),
    ),
  },
};
// Test-name filtering alone would silently pass if the function lost its ignore
// attribute or was renamed. Verify discovery before executing its body once.
const listed = spawnSync("cargo", [...args, "--list"], {
  ...options,
  encoding: "utf8",
});
if (listed.error) {
  console.error(`Cannot start Cargo conformance: ${listed.error.message}`);
  process.exit(1);
}
if (listed.status !== 0) {
  process.stderr.write(listed.stderr);
  process.exit(listed.status ?? 1);
}
if (!listed.stdout.split("\n").includes(`${test}: test`)) {
  console.error(
    `Expected ignored conformance test was not discovered: ${test}`,
  );
  process.exit(1);
}
const result = spawnSync("cargo", [...args, "--nocapture"], {
  ...options,
  stdio: "inherit",
});
if (result.error)
  console.error(`Cannot start Cargo conformance: ${result.error.message}`);
process.exit(result.status ?? 1);

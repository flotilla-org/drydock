#!/usr/bin/env node
import { Host } from "./host.js";
import { serve, type Listener } from "./server.js";
import { reference } from "./reference.js";
import type { ProviderModule } from "./provider.js";
async function main() {
  const args = process.argv.slice(2);
  let listener: Listener;
  if (args.length === 2 && args[0] === "--unix") listener = { unix: args[1] };
  else if (
    args.length === 4 &&
    args[0] === "--tcp" &&
    args[2] === "--token-file"
  )
    listener = { tcp: args[1], tokenFile: args[3] };
  else
    throw Error(
      "usage: drydock-host-typescript --unix PATH | --tcp LOOPBACK:PORT --token-file PATH",
    );
  const registry = new Map<string, ProviderModule>([["reference", reference]]);
  // Explicit supervisor allowlist; wire configuration cannot execute arbitrary paths.
  // Entries are ESM URLs/absolute paths exporting a ProviderModule as default.
  for (const path of (process.env.DRYDOCK_TYPESCRIPT_MODULES ?? "")
    .split(",")
    .filter(Boolean)) {
    const loaded = await import(path);
    const module = loaded.default;
    if (
      !module ||
      typeof module.configure !== "function" ||
      typeof module.version !== "string"
    )
      throw Error("invalid provider module");
    registry.set(path, module);
  }
  let running: Awaited<ReturnType<typeof serve>> | undefined;
  let closing = false;
  const close = () => {
    if (!closing) {
      closing = true;
      if (running) void running.close().then(() => process.exit(0));
    }
  };
  process.on("SIGTERM", close);
  process.on("SIGINT", close);
  running = await serve(new Host(registry), listener);
  if (closing) await running.close();
}
main().catch(() => {
  console.error(
    "drydock-host-typescript: startup failed; verify listener and module configuration",
  );
  process.exitCode = 1;
});

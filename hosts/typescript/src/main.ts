#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { serve } from "./server.js";
import type { ProviderModule } from "./provider.js";
async function main() {
  if (process.argv.length !== 4 || process.argv[2] !== "--unix")
    throw Error("usage: drydock-host-typescript --unix PATH");
  const modules: ProviderModule[] = [];
  for (const entry of (process.env.DRYDOCK_TYPESCRIPT_MODULES ?? "")
    .split(",")
    .filter(Boolean)) {
    if (!entry.startsWith("/") && !entry.startsWith("file:"))
      throw Error("module path must be absolute");
    modules.push(
      (
        await import(
          entry.startsWith("file:") ? entry : pathToFileURL(entry).href
        )
      ).default,
    );
  }
  const host = await serve(modules, process.argv[3]);
  for (const signal of ["SIGINT", "SIGTERM"] as const)
    process.once(signal, () => {
      void host.close();
    });
}
main().catch(() => {
  process.stderr.write("drydock TypeScript bridge failed\n");
  process.exitCode = 1;
});

#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { serve } from "./server.js";
import { compile, bodySchema } from "./validation.js";
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
    const module = (
      await import(
        entry.startsWith("file:") ? entry : pathToFileURL(entry).href
      )
    ).default;
    if (
      typeof module?.configure !== "function" ||
      !compile(bodySchema("LoadableModule"))({
        name: module?.name,
        version: module?.version,
        smallest_size: module?.smallestSize,
      })
    ) {
      // Name the configuration entry, never echo module exceptions or credentials.
      process.stderr.write(
        `drydock TypeScript bridge: invalid default ProviderModule export at entry ${modules.length + 1}\n`,
      );
      process.exitCode = 1;
      return;
    }
    modules.push(module);
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

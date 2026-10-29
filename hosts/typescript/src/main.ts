#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { serve } from "./server.js";
import { compile, bodySchema } from "./validation.js";
import type { ProviderModule } from "./provider.js";

class InvalidModule extends Error {}

function moduleEntries(): string[] {
  const list = process.env.DRYDOCK_TYPESCRIPT_MODULES ?? "";
  return list.split(",").filter(Boolean);
}

function moduleUrl(entry: string): string {
  if (entry.startsWith("file:")) return entry;
  if (entry.startsWith("/")) return pathToFileURL(entry).href;
  throw Error("module path must be absolute");
}

async function loadModules(): Promise<ProviderModule[]> {
  const validModule = compile(bodySchema("LoadableModule"));
  const modules: ProviderModule[] = [];
  for (const entry of moduleEntries()) {
    const module = (await import(moduleUrl(entry))).default;
    const metadata = {
      name: module?.name,
      version: module?.version,
      smallest_size: module?.smallestSize,
    };
    if (typeof module?.configure !== "function" || !validModule(metadata))
      throw new InvalidModule(String(modules.length + 1));
    modules.push(module);
  }
  return modules;
}

async function main() {
  if (process.argv.length !== 4 || process.argv[2] !== "--unix")
    throw Error("usage: drydock-host-typescript --unix PATH");
  const host = await serve(await loadModules(), process.argv[3]);
  for (const signal of ["SIGINT", "SIGTERM"] as const)
    process.once(signal, () => {
      host.close().catch(() => {
        process.exitCode = 1;
      });
    });
}

// Name the configuration entry, never echo module exceptions or credentials.
main().catch((error) => {
  if (error instanceof InvalidModule)
    process.stderr.write(
      `drydock TypeScript bridge: invalid default ProviderModule export at entry ${error.message}\n`,
    );
  else process.stderr.write("drydock TypeScript bridge failed\n");
  process.exitCode = 1;
});

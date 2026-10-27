// GENERATED outputs are untracked build artifacts. Rust owns the root openapi.json.
import { readFile, writeFile, mkdir } from "node:fs/promises";
import openapiTS, { astToString } from "openapi-typescript";
const input = new URL("../../../openapi.json", import.meta.url);
const document = JSON.parse(await readFile(input, "utf8"));
// Generate the private host surface while retaining canonical shared schemas.
document.paths = Object.fromEntries(
  Object.entries(document.paths)
    .map(([path, item]) => [
      path,
      Object.fromEntries(
        Object.entries(item).filter(([, operation]) =>
          operation.tags?.includes("host"),
        ),
      ),
    ])
    .filter(([, item]) => Object.keys(item).length),
);
const directory = new URL("../src/generated/", import.meta.url);
await mkdir(directory, { recursive: true });
const types =
  "// GENERATED / DO NOT EDIT: Rust provider declarations + real host handlers -> /openapi.json (host tag).\n// Regenerate: corepack pnpm generate (hosts/typescript/).\n" +
  astToString(await openapiTS(document));
for (const [name, content] of [
  ["protocol.ts", types],
  ["schema.json", JSON.stringify(document, null, 2) + "\n"],
]) {
  const file = new URL(name, directory);
  if (process.argv.includes("--check")) {
    if ((await readFile(file, "utf8")) !== content)
      throw Error(`Generated drift: ${name}; run corepack pnpm generate`);
  } else await writeFile(file, content);
}

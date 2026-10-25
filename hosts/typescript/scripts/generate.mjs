import ts from "typescript";
import openapiTS, { astToString } from "openapi-typescript";
import { readFile, writeFile } from "node:fs/promises";
const source = new URL("../../../openapi.json", import.meta.url);
const output = new URL("../src/protocol.ts", import.meta.url);
const text =
  "// Generated from openapi.json; run corepack pnpm generate.\n" +
  astToString(
    await openapiTS(source, {
      // openapi-typescript 7 drops trailing items when prefixItems is present.
      // Preserve the schema's nonempty argv plus unrestricted string arguments.
      transform(schema) {
        if (
          schema.type === "array" &&
          schema.prefixItems?.length === 1 &&
          schema.items?.type === "string"
        )
          return ts.factory.createTupleTypeNode([
            ts.factory.createKeywordTypeNode(ts.SyntaxKind.StringKeyword),
            ts.factory.createRestTypeNode(
              ts.factory.createArrayTypeNode(
                ts.factory.createKeywordTypeNode(ts.SyntaxKind.StringKeyword),
              ),
            ),
          ]);
      },
    }),
  );
if (process.argv.includes("--check")) {
  if ((await readFile(output, "utf8")) !== text)
    throw new Error("Protocol types drifted: run corepack pnpm generate");
} else await writeFile(output, text);
const schemaOutput = new URL("../src/openapi.json", import.meta.url);
const document = await readFile(source, "utf8");
if (process.argv.includes("--check")) {
  if ((await readFile(schemaOutput, "utf8")) !== document)
    throw new Error("Runtime schema drifted");
} else await writeFile(schemaOutput, document);

import { Ajv2020 } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import document from "./openapi.json" with { type: "json" };
import { fail } from "./provider.js";
const ajv = new Ajv2020({ strict: false, validateFormats: true });
(addFormats as unknown as (ajv: Ajv2020) => void)(ajv);
// OpenAPI integer formats describe Rust wire widths; AJV does not enforce them.
function widths(value: unknown): void {
  if (!value || typeof value !== "object") return;
  const schema = value as Record<string, unknown>;
  if (schema.format === "int64" && schema.minimum === 0)
    schema.exclusiveMaximum = 2 ** 64;
  if (schema.format === "int32") {
    schema.maximum = schema.minimum === 0 ? 2 ** 32 - 1 : 2 ** 31 - 1;
    if (schema.minimum === undefined) schema.minimum = -(2 ** 31);
  }
  for (const child of Object.values(schema)) widths(child);
}
const runtime = structuredClone(document);
widths(runtime);
ajv.addSchema({ $id: "protocol", ...runtime });
const validators = new Map<string, ReturnType<typeof ajv.compile>>();
export const protocolVersion = document.info.version;
export function validate(name: string, value: unknown): void {
  let validator = validators.get(name);
  if (!validator) {
    validator = ajv.compile({ $ref: `protocol#/components/schemas/${name}` });
    validators.set(name, validator);
  }
  if (!validator(value)) fail("refused", "invalid request");
  if (name === "Period") {
    const p = value as { start: string; end: string };
    if (Date.parse(p.start) >= Date.parse(p.end))
      fail("refused", "invalid usage period");
  }
}

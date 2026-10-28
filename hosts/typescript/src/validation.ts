import { Ajv2020 } from "ajv/dist/2020.js";
import formats from "ajv-formats";
import schema from "./generated/schema.json" with { type: "json" };
// OpenAPI carries annotation/format keywords beyond JSON Schema (e.g. int64).
// Tolerate those keywords only; never coerce/default/strip request data.
const ajv = new Ajv2020({
  strict: false,
  coerceTypes: false,
  useDefaults: false,
  removeAdditional: false,
});
(formats as unknown as (value: Ajv2020) => void)(ajv);
// Rust integer formats carry wire widths, not JavaScript's unconstrained integer.
function widths(value: unknown): void {
  if (!value || typeof value !== "object") return;
  const item = value as Record<string, unknown>;
  if (item.format === "int64" && item.minimum === 0)
    item.exclusiveMaximum = 2 ** 64;
  if (item.format === "int32") {
    item.maximum = item.minimum === 0 ? 2 ** 32 - 1 : 2 ** 31 - 1;
    item.minimum ??= -(2 ** 31);
  }
  for (const child of Object.values(item)) widths(child);
}
const runtime = structuredClone(schema);
widths(runtime);
ajv.addSchema({ $id: "host", ...runtime });
export const protocolVersion = schema.info.version;
export const bodySchema = (name: keyof import("./provider.js").Types) => ({
  $ref: `host#/components/schemas/${name}`,
});
export const compile = (value: object | boolean) => ajv.compile(value);

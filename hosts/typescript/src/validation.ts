import { Ajv2020 } from "ajv/dist/2020.js";
import formats from "ajv-formats";
import schema from "./generated/schema.json" with { type: "json" };
// OpenAPI carries annotation keywords beyond JSON Schema. Tolerate those
// keywords only; never coerce/default/strip request data.
const ajv = new Ajv2020({
  strict: false,
  coerceTypes: false,
  useDefaults: false,
  removeAdditional: false,
});
(formats as unknown as (value: Ajv2020) => void)(ajv);

// The canonical document keeps utoipa's strict integer formats: `int32` and
// `int64` name the Rust width, and `minimum: 0` marks an unsigned type
// (u32/u64). A format sees only the value, so each one accepts the union of
// the signed and unsigned ranges for its width.
// JSON.parse uses JS numbers: integers beyond 2^53 are not lossless, so modules
// must account for that when interpreting large counters.
function integerWidth(bits: number) {
  return {
    type: "number" as const,
    validate: (value: number) =>
      Number.isInteger(value) &&
      value >= -(2 ** (bits - 1)) &&
      value < 2 ** bits,
  };
}
// Intentionally replaces ajv-formats' signed-only and safe-integer versions.
ajv.addFormat("int32", integerWidth(32));
ajv.addFormat("int64", integerWidth(64));

ajv.addSchema({ $id: "host", ...schema });
export const protocolVersion = schema.info.version;
export function bodySchema(name: keyof import("./provider.js").Types) {
  return { $ref: `host#/components/schemas/${name}` };
}
export function compile(value: object | boolean) {
  return ajv.compile(value);
}

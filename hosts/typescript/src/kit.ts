// What a TypeScript module shares with the others, as the Rust kit does for
// its modules: ownership, names and re-adoption. A module keeps only what its
// vendor does differently.
import { createHash } from "node:crypto";
import { refused } from "./provider.js";

export const hex = (value: string) =>
  createHash("sha256").update(value).digest("hex");

/** The provider-side tags (the Rust kit's `PROVIDER_TAG` and `LABEL_TAG`). */
export const PROVIDER_TAG = "drydock.provider";
export const LABEL_TAG = "flotilla.label";

/**
 * The deterministic name of the sandbox holding `label` under `instance`:
 * `prefix` and 160 bits of identity. The instance is in it, so two instances
 * sharing one vendor account never name the same sandbox.
 */
export function sandboxName(prefix: string, instance: string, label: string) {
  return `${prefix}${hex(`${instance}\0${label}`).slice(0, 40)}`;
}

/** Destroy and inspect refuse what another instance made, and leave it alone. */
export function requireOurs(
  vendor: string,
  id: string,
  tags: Record<string, string>,
  instance: string,
) {
  if (tags[PROVIDER_TAG] !== instance || !tags[LABEL_TAG])
    refused(
      `${vendor} resource ${id} was not made by provider ${instance}; it is left alone`,
    );
}

/**
 * Re-adoption of a label: what the module read back holds the size and egress
 * policy now requested, else it is refused and the caller provisions a new label.
 */
export function checkReadopt(
  vendor: string,
  held: { size: string | null; egress: string | null },
  wanted: { size: string; egress: string },
) {
  if (held.size !== wanted.size || held.egress !== wanted.egress)
    refused(
      `an existing ${vendor} sandbox holds this label with a different size or egress policy; provision a new label`,
    );
}

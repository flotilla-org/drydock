// What a TypeScript module shares with the others, as the Rust kit does for
// its modules: ownership, names and re-adoption. A module keeps only what its
// vendor does differently.
import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { BlockList, isIP, isIPv6 } from "node:net";
import { dirname, isAbsolute, join } from "node:path";
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

/**
 * Addresses no public builder or proxy reaches, as the Rust kit's
 * `kit::egress::private` has them: private, loopback, link-local, unspecified,
 * broadcast, shared (100.64/10), IETF protocol (192.0.0/24) and benchmarking
 * (198.18/15) IPv4; loopback, unique-local, link- and site-local IPv6;
 * IPv4-mapped IPv6 by its IPv4 address.
 */
const PRIVATE = new BlockList();
for (const [address, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["255.255.255.255", 32],
] as const)
  PRIVATE.addSubnet(address, prefix, "ipv4");
for (const [address, prefix] of [
  ["::", 127],
  ["fc00::", 7],
  ["fe80::", 10],
  ["fec0::", 10],
] as const)
  PRIVATE.addSubnet(address, prefix, "ipv6");

export function privateAddress(address: string) {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address)?.[1];
  if (mapped) return PRIVATE.check(mapped, "ipv4");
  return PRIVATE.check(address, isIPv6(address) ? "ipv6" : "ipv4");
}

const PRIVATE_SUFFIXES = [
  ".localhost",
  ".local",
  ".internal",
  ".lan",
  ".home.arpa",
  ".test",
  ".invalid",
];

/**
 * Whether a registry (host, perhaps with a port) is plainly private: a private
 * address literal, a name that cannot be public, or a name that resolves to a
 * private address (best effort: a name that does not resolve here is left to
 * the vendor). This is `kit::egress::private_registry`, for TypeScript.
 */
export async function privateRegistry(registry: string): Promise<boolean> {
  // A bare IPv6 literal is whole; any other host may carry a port or brackets.
  const bare = registry.toLowerCase();
  const host = isIP(bare)
    ? bare
    : bare.replace(/^\[|\](:\d+)?$|:\d+$/g, "").replace(/\.$/, "");
  if (isIP(host)) return privateAddress(host);
  if (
    host === "localhost" ||
    !host.includes(".") ||
    PRIVATE_SUFFIXES.some((s) => host.endsWith(s))
  )
    return true;
  // Best effort: the vendor's builder resolves the name from its own network
  // (split-horizon DNS can answer differently), and a name that does not
  // resolve here is left to the vendor.
  try {
    return (await lookup(host, { all: true })).some((a) =>
      privateAddress(a.address),
    );
  } catch {
    return false;
  }
}

/**
 * The resources this host suspended, so a vendor's "paused" reads as suspended
 * by request. For vendors that cannot change a resource's labels once it is
 * made (Namespace), it is a file per resource under the host's state directory,
 * as the Rust kit's `Suspensions`: it survives a restart. With no usable
 * directory it is in memory alone.
 */
export class Suspensions {
  private memory = new Set<string>();
  private dir: string | undefined;

  constructor(vendor: string, instance: string, stateDir = defaultStateDir()) {
    if (stateDir)
      this.dir = join(
        stateDir,
        "suspensions",
        vendor.toLowerCase(),
        hex(instance).slice(0, 16),
      );
  }

  private file(id: string) {
    return this.dir && join(this.dir, hex(id).slice(0, 32));
  }

  record(id: string) {
    this.memory.add(id);
    const file = this.file(id);
    if (!file) return;
    try {
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, "");
    } catch (error) {
      console.warn(
        `could not record a suspend; after a host restart it will read as the provider's: ${error}`,
      );
    }
  }

  forget(id: string) {
    this.memory.delete(id);
    const file = this.file(id);
    if (!file) return;
    try {
      rmSync(file, { force: true });
    } catch (error) {
      console.warn(`could not clear a suspend record: ${error}`);
    }
  }

  has(id: string) {
    const file = this.file(id);
    return this.memory.has(id) || (file !== undefined && existsSync(file));
  }
}

/** The host's state directory, as rigging-paths resolves it for `drydock`. */
function defaultStateDir(): string | undefined {
  const root = process.env.DRYDOCK_ROOT;
  if (root) return join(root, "state");
  const xdg = process.env.XDG_STATE_HOME;
  if (xdg && isAbsolute(xdg)) return join(xdg, "drydock");
  const home = process.env.HOME;
  return home ? join(home, ".local", "state", "drydock") : undefined;
}

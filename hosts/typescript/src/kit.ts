// Shared by the TypeScript modules, as the Rust kit is by its modules.
import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { BlockList, isIP, isIPv6 } from "node:net";
import { dirname, isAbsolute, join } from "node:path";
import { refused } from "./provider.js";

export const hex = (value: string) =>
  createHash("sha256").update(value).digest("hex");

export const PROVIDER_TAG = "drydock.provider";
export const LABEL_TAG = "flotilla.label";

export function sandboxName(prefix: string, instance: string, label: string) {
  return `${prefix}${hex(`${instance}\0${label}`).slice(0, 40)}`;
}

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

// The ranges of the Rust kit's `kit::egress::private`.
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
  // A name that does not resolve here is left to the vendor.
  try {
    return (await lookup(host, { all: true })).some((a) =>
      privateAddress(a.address),
    );
  } catch {
    return false;
  }
}

// Suspends this host made, one file each under the state directory so they survive a restart.
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
      console.warn(`could not record a suspend: ${error}`);
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

function defaultStateDir(): string | undefined {
  const root = process.env.DRYDOCK_ROOT;
  if (root) return join(root, "state");
  const xdg = process.env.XDG_STATE_HOME;
  if (xdg && isAbsolute(xdg)) return join(xdg, "drydock");
  const home = process.env.HOME;
  return home ? join(home, ".local", "state", "drydock") : undefined;
}

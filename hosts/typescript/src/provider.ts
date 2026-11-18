import type { Duplex } from "node:stream";
import type { components } from "./generated/protocol.js";
export type Types = components["schemas"];
export type Context = {
  readonly credential: string | undefined;
  signal: AbortSignal;
};
export interface ProviderModule {
  name: string;
  version: string;
  smallestSize: Types["Size"];
  // Factories own cleanup on rejection/abort; retain no call-scoped SDK work.
  configure(
    name: string,
    config: Types["ProviderConfiguration"],
    signal: AbortSignal,
  ): Promise<Provider>;
}
/** SDK facts and operations only; Daemon owns admission, rates and observation policy. */
export interface Provider {
  capabilities: Types["Capabilities"];
  waysIn: Types["WayIn"][];
  rateLimits: Types["RateLimit"][];
  readiness(context: Context): Types["Readiness"] | Promise<Types["Readiness"]>;
  prepare(
    request: Types["PrepareRequest"],
    context: Context,
  ): Promise<Types["Prepared"]>;
  /**
   * drydockd hands over deny-all destinations in normal form: host names
   * lowercase with no final dot, an IPv4 literal host as its /32 CIDR, and
   * IPv4 CIDRs with their host bits cleared.
   */
  provision(
    request: Types["ProvisionRequest"],
    context: Context,
  ): Promise<{ created: boolean; environment: Types["Environment"] }>;
  list(context: Context): Promise<Types["Environment"][]>;
  inspect(id: string, context: Context): Promise<Types["Environment"]>;
  destroy(id: string, context: Context): Promise<void>;
  reach(id: string, context: Context): Promise<Types["Reach"]>;
  /** The connection behind a relay reach; without it relay is refused. */
  relay?(id: string, context: Context): Promise<Duplex>;
  // Optional ports: a provider declares the ones it implements. Exec, export
  // and usage stay absent until drydock#85 reshapes them.
  suspend?(id: string, context: Context): Promise<Types["ResumeToken"]>;
  resume?(
    id: string,
    token: Types["ResumeToken"],
    context: Context,
  ): Promise<void>;
  quota?(context: Context): Promise<Types["Quota"]>;
}
export function ports(provider: Provider): Types["Ports"] {
  return {
    exec: false,
    suspend_resume: !!provider.suspend && !!provider.resume,
    export: false,
    usage: false,
    quota: !!provider.quota,
  };
}
export class ProtocolFailure extends Error {
  /** On a provision, what the failure left at the vendor; absent is none. */
  constructor(
    readonly detail: Types["ProtocolError"],
    readonly left?: Types["Left"],
  ) {
    super(detail.kind);
  }
}
/** A step's failure after the vendor made `id`, which it leaves as it is. */
export function made(
  failure: ProtocolFailure,
  provider: string,
  id: string,
): ProtocolFailure {
  return new ProtocolFailure(failure.detail, { kind: "made", provider, id });
}
/** The vendor's create call failed: a refusal made nothing, and any other
 * failure may have. The refusal kinds are those of the Rust
 * `ProvisionFailure::creating`; a kind not listed is safely unknown. */
export function creating(failure: ProtocolFailure): ProtocolFailure {
  const answered = [
    "not_found",
    "method_not_allowed",
    "refused",
    "image_refused",
    "rate_limited",
    "quota_exhausted",
    "credential_rejected",
  ];
  if (answered.includes(failure.detail.kind)) return failure;
  return new ProtocolFailure(failure.detail, { kind: "unknown" });
}
export function refused(reason: string): never {
  throw new ProtocolFailure({ kind: "refused", reason });
}

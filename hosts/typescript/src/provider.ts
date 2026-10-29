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
  observation: Types["ObservationMode"];
  rateLimits: Types["RateLimit"][];
  readiness(context: Context): Types["Readiness"] | Promise<Types["Readiness"]>;
  prepare(
    request: Types["PrepareRequest"],
    context: Context,
  ): Promise<Types["Prepared"]>;
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
  constructor(readonly detail: Types["ProtocolError"]) {
    super(detail.kind);
  }
}
export function refused(reason: string): never {
  throw new ProtocolFailure({ kind: "refused", reason });
}

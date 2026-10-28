import type { Duplex } from "node:stream";
import type { components } from "./generated/protocol.js";
export type Types = components["schemas"];
export type Context = {
  readonly credentials: Readonly<Types["Credentials"]>;
  signal: AbortSignal;
};
export interface ProviderModule {
  name: string;
  version: string;
  smallestSize: Types["Size"];
  // Factories own cleanup on rejection/abort; retain no call-scoped SDK work.
  configure(
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
  ): Promise<Types["Provisioned"]>;
  list(context: Context): Promise<Types["ObservedEnvironment"][]>;
  inspect(id: string, context: Context): Promise<Types["ObservedEnvironment"]>;
  inspectAfterLifecycle(
    id: string,
    context: Context,
  ): Promise<Types["ObservedEnvironment"]>;
  destroy(id: string, context: Context): Promise<void>;
  reach(id: string, context: Context): Promise<Types["Connection"]>;
  relay(id: string, context: Context): Promise<Duplex>;
  /** Must settle pending next() on signal abort; async iterator return cannot preempt it. */
  subscribe(context: Context): AsyncIterable<Types["Update"]>;
}
// Optional ports are deliberately absent until drydock#85's interface lands.
export const absentPorts: Types["Ports"] = {
  exec: false,
  suspend_resume: false,
  export: false,
  usage: false,
  quota: false,
};
export class ProtocolFailure extends Error {
  constructor(readonly detail: Types["ProtocolError"]) {
    super(detail.kind);
  }
}
export function refused(reason: string): never {
  throw new ProtocolFailure({ kind: "refused", reason });
}

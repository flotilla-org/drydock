import type { Duplex } from "node:stream";
import type { components } from "./protocol.js";
export type Types = components["schemas"];
export type Observed = {
  environment: Types["Environment"];
  timestamp?: string;
};
export type Credentials = Readonly<{
  mode: Types["CredentialMode"];
  value?: string;
  generation: number;
}>;
export type Context = { credentials: Credentials; signal: AbortSignal };
export type Sink = (row: Observed, event: Types["EventKind"]) => void;
/** Factories must be cancellation safe: no background work until run is called after commit. */
export interface ProviderModule {
  version: string;
  configure(
    config: Types["ProviderConfiguration"],
    signal: AbortSignal,
  ): Promise<Provider>;
  smallestSize?: Types["Size"];
}
export interface Provider {
  capabilities: Types["Capabilities"];
  rateLimits?: Types["RateLimit"][];
  observation: { mode: "poll"; intervalMs: number } | { mode: "push" };
  readiness?(credentials: Credentials): Types["Readiness"];
  prepare(
    request: Types["PrepareRequest"],
    context: Context,
  ): Promise<Types["Prepared"]>;
  provision(
    request: Types["ProvisionRequest"],
    context: Context,
  ): Promise<{ created: boolean; row: Observed }>;
  list(context: Context): Promise<Observed[]>;
  inspect(id: string, context: Context): Promise<Observed>;
  destroy(id: string, context: Context): Promise<void>;
  reach(
    id: string,
    context: Context,
  ): Promise<Types["Reach"] | { kind: "relay" }>;
  relay(id: string, context: Context): Promise<Duplex>;
  exec?(
    id: string,
    request: Types["ExecRequest"],
    context: Context,
  ): Promise<Duplex>;
  suspend?(id: string, context: Context): Promise<Types["ResumeToken"]>;
  resume?(
    id: string,
    token: Types["ResumeToken"],
    context: Context,
  ): Promise<void>;
  export?(id: string, context: Context): Promise<Types["Export"]>;
  usage?(period: Types["Period"], context: Context): Promise<Types["Usage"]>;
  quota?(context: Context): Promise<Types["Quota"]>;
  run?(
    sink: Sink,
    credentials: () => Credentials,
    signal: AbortSignal,
  ): Promise<void>;
}
export class ProtocolFailure extends Error {
  constructor(readonly detail: Types["ProtocolError"]) {
    super(detail.kind);
  }
}
export function fail(
  kind: "refused" | "not_found" | "unavailable",
  reason: string,
): never {
  throw new ProtocolFailure({ kind, reason });
}

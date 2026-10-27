import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { EventEmitter, on } from "node:events";
import { PassThrough } from "node:stream";
import {
  ProtocolFailure,
  refused,
  type Context,
  type Provider,
  type ProviderModule,
  type Types,
} from "./provider.js";
import { compile } from "./validation.js";
const settingsValid = compile({
  type: "object",
  additionalProperties: false,
  properties: {
    push: { type: "boolean" },
    seed_unlabelled: { type: "boolean" },
  },
});
const digest = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const reference: ProviderModule = {
  name: "reference",
  version: "0.1.0",
  smallestSize: { cpus: 1, memory_bytes: 1, disk_bytes: 0 },
  async configure(config) {
    if (!settingsValid(config.settings)) refused("invalid reference settings");
    return new Memory(config.name, config.settings);
  },
};
export default reference;
/** Provider facts only. Daemon derives all public transitions, snapshots and replay. */
class Memory implements Provider {
  capabilities: Types["Capabilities"] = {
    material_modes: ["frozen", "pushed", "shared"],
    checkout_strategies: ["host_worktree", "host_clone", "clone_in_vessel"],
    workspace_root: "/workspace",
    suspend_resume: false,
    suspend_preserves_memory: false,
    export: false,
    fallback_runner: false,
    usage: false,
    quota: false,
    agent: false,
    egress: { routes: ["none", "open"], enforcement: "advisory" },
    bootstrap: "bake",
    platforms: [{ os: "linux", architecture: "amd64" }],
    image_routes: [
      {
        route: "remote_build",
        input: "dockerfile",
        multi_stage: true,
        tools_layer: "host",
      },
    ],
  };
  observation: Types["ObservationMode"];
  rateLimits: Types["RateLimit"][] = [];
  private builds = new Map<string, Types["Prepared"]>();
  private rows = new Map<string, Types["ObservedEnvironment"]>();
  private updates = new EventEmitter();
  private next = 0;
  constructor(
    private name: string,
    settings: Record<string, unknown>,
  ) {
    this.observation = settings.push
      ? "Push"
      : { Poll: { interval: { secs: 0, nanos: 10000000 } } };
    if (settings.seed_unlabelled)
      this.rows.set("unlabelled", {
        environment: {
          provider: name,
          id: "unlabelled",
          label: null,
          granted_size: null,
          platform: null,
          egress: "advisory",
          state: { state: "transitioning", phase: "starting" },
        },
        timestamp: null,
        egress_measured: false,
        egress_policy: null,
      });
  }
  readiness({ credentials }: Context): Types["Readiness"] {
    return credentials.value || credentials.mode.mode === "proxied"
      ? { status: "ready" }
      : { status: "missing_credential", reason: "credential not delivered" };
  }
  async prepare(
    request: Types["PrepareRequest"],
    { signal }: Context,
  ): Promise<Types["Prepared"]> {
    signal.throwIfAborted();
    if (!request.platform || request.route !== "remote_build")
      refused("reference requires resolved platform and image route");
    const prepared: Types["Prepared"] = {
      id: digest([
        request.image_digest,
        request.tools_digest,
        request.platform,
        request.size,
      ]),
      provider: this.name,
      platform: request.platform,
      image_digest: request.image_digest,
      tools_digest: request.tools_digest,
    };
    this.builds.set(prepared.id, prepared);
    return structuredClone(prepared);
  }
  async provision(
    request: Types["ProvisionRequest"],
    { signal }: Context,
  ): Promise<Types["Provisioned"]> {
    signal.throwIfAborted();
    const existing = [...this.rows.values()].find(
      (row) => row.environment.label === request.label,
    );
    if (existing) return { Existing: structuredClone(existing) };
    if (
      !isDeepStrictEqual(this.builds.get(request.prepared.id), request.prepared)
    )
      refused("unknown prepared form");
    const row: Types["ObservedEnvironment"] = {
      environment: {
        provider: this.name,
        id: `${this.name}-${++this.next}`,
        label: request.label,
        granted_size: structuredClone(request.size),
        platform: request.prepared.platform,
        state: { state: "running" },
        egress: "advisory",
      },
      timestamp: new Date().toISOString(),
      egress_measured: true,
      egress_policy: digest(request.egress),
    };
    this.rows.set(row.environment.id, row);
    this.updates.emit("update", { Observed: structuredClone(row) });
    return { Created: structuredClone(row) };
  }
  async list({ signal }: Context) {
    signal.throwIfAborted();
    return structuredClone([...this.rows.values()]);
  }
  async inspect(id: string, { signal }: Context) {
    signal.throwIfAborted();
    const row = this.rows.get(id);
    if (!row)
      throw new ProtocolFailure({
        kind: "not_found",
        reason: "unknown environment",
      });
    return structuredClone(row);
  }
  inspectAfterLifecycle(id: string, context: Context) {
    return this.inspect(id, context);
  }
  async destroy(id: string, { signal }: Context) {
    signal.throwIfAborted();
    if (this.rows.delete(id))
      this.updates.emit("update", {
        Removed: { id, timestamp: new Date().toISOString() },
      });
  }
  async reach(id: string, context: Context): Promise<Types["Connection"]> {
    await this.inspect(id, context);
    return "Relay";
  }
  async relay(id: string, context: Context) {
    await this.inspect(id, context);
    return new PassThrough();
  }
  async *subscribe({ signal }: Context): AsyncIterable<Types["Update"]> {
    for await (const [update] of on(this.updates, "update", { signal }))
      yield update as Types["Update"];
  }
}

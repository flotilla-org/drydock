import { Duplex, PassThrough } from "node:stream";
import { isDeepStrictEqual } from "node:util";
import {
  fail,
  ProtocolFailure,
  type Context,
  type Observed,
  type Provider,
  type ProviderModule,
  type Types,
} from "./provider.js";
import { validate, compile, protocolSchema } from "./validation.js";
import { disableOperations, optionalControls } from "./operations.js";
type Settings = {
  fault?: Types["ProtocolError"];
  fixture?: boolean;
  fixture_push?: boolean;
  fixture_bad_relay?: boolean;
  reach?: Types["Reach"];
  agent?: boolean;
  platforms?: Types["Platform"][];
  rate_limits?: Types["RateLimit"][];
  poll_interval_ms?: number;
  disabled?: string[];
};
const settingsSchema = compile({
  type: "object",
  additionalProperties: false,
  properties: {
    fault: { anyOf: [protocolSchema("ProtocolError"), { type: "null" }] },
    reach: { anyOf: [protocolSchema("Reach"), { type: "null" }] },
    fixture: { type: "boolean" },
    fixture_push: { type: "boolean" },
    fixture_bad_relay: { type: "boolean" },
    agent: { type: "boolean" },
    platforms: { type: "array", items: protocolSchema("Platform") },
    rate_limits: { type: "array", items: protocolSchema("RateLimit") },
    poll_interval_ms: {
      type: "integer",
      minimum: 1,
      maximum: Number.MAX_SAFE_INTEGER,
    },
    disabled: {
      type: "array",
      items: { type: "string", enum: optionalControls },
    },
  },
});
export const reference: ProviderModule = {
  version: "0.1.0",
  async configure(config) {
    if (!settingsSchema(config.settings))
      fail("refused", "invalid reference settings");
    const settings = config.settings as Settings;
    const provider = new Reference(config.name, settings);
    disableOperations(provider, settings.disabled ?? []);
    return provider;
  },
};
class Reference implements Provider {
  capabilities: Types["Capabilities"];
  observation: Provider["observation"];
  rateLimits: Types["RateLimit"][];
  private prepared: Types["Prepared"][] = [];
  private rows = new Map<string, Types["Environment"]>();
  private tokens = new Map<string, string>();
  private next = 0;
  private timestamp?: string;
  private inventoryError = false;
  private generation = new Map<string, number>();
  private running = new Map<string, number>();
  private segments: { size: Types["Size"]; start: number; end: number }[] = [];
  constructor(
    private name: string,
    private settings: Settings,
  ) {
    this.observation =
      settings.fixture && settings.fixture_push
        ? { mode: "push" }
        : { mode: "poll", intervalMs: settings.poll_interval_ms ?? 10 };
    this.rateLimits = settings.rate_limits ?? [];
    this.capabilities = {
      material_modes: ["frozen", "pushed", "shared"],
      checkout_strategies: ["host_worktree", "host_clone", "clone_in_vessel"],
      workspace_root: "/workspace",
      suspend_resume: true,
      suspend_preserves_memory: true,
      export: true,
      egress: { routes: ["none", "open"], enforcement: "advisory" },
      fallback_runner: true,
      bootstrap: "bake",
      agent: settings.agent ?? false,
      platforms: settings.platforms ?? [
        { os: "linux", architecture: "amd64" },
        { os: "linux", architecture: "arm64" },
      ],
      usage: true,
      quota: true,
    };
  }
  private check() {
    if (this.settings.fault)
      throw new ProtocolFailure(structuredClone(this.settings.fault));
  }
  private find(id: string) {
    const row = this.rows.get(id);
    if (!row) fail("not_found", "unknown environment");
    return row;
  }
  private observed(row: Types["Environment"]): Observed {
    return { environment: structuredClone(row), timestamp: this.timestamp };
  }
  private stop(id: string) {
    const start = this.running.get(id),
      size = this.rows.get(id)?.granted_size;
    if (start !== undefined && size)
      this.segments.push({ size, start, end: Date.now() });
    this.running.delete(id);
  }
  async prepare(r: Types["PrepareRequest"]) {
    this.check();
    const old = this.prepared.find(
      (p) =>
        p.image_digest === r.image_digest &&
        p.tools_digest === r.tools_digest &&
        isDeepStrictEqual(p.platform, r.platform),
    );
    if (old) return structuredClone(old);
    const result: Types["Prepared"] = {
      provider: this.name,
      id: `prepared-${this.prepared.length + 1}`,
      platform: r.platform!,
      image_digest: r.image_digest,
      tools_digest: r.tools_digest,
    };
    this.prepared.push(result);
    return structuredClone(result);
  }
  async provision(r: Types["ProvisionRequest"]) {
    this.check();
    const old = [...this.rows.values()].find((e) => e.label === r.label);
    if (old) return { created: false, row: this.observed(old) };
    if (!this.prepared.some((p) => isDeepStrictEqual(p, r.prepared)))
      fail("refused", "unknown prepared form");
    if (r.egress?.mode === "deny_all" && (r.egress.direct?.length ?? 0))
      fail("refused", "reference cannot implement direct destinations");
    const row: Types["Environment"] = {
      id: `environment-${++this.next}`,
      label: r.label,
      provider: this.name,
      state: { state: "running" },
      granted_size: r.size,
      egress: "advisory",
      platform: r.prepared.platform,
    };
    this.rows.set(row.id, row);
    this.running.set(row.id, Date.now());
    return { created: true, row: this.observed(row) };
  }
  async list() {
    this.check();
    if (this.inventoryError)
      fail("unavailable", "fixture inventory unavailable");
    return [...this.rows.values()].map((r) => this.observed(r));
  }
  async inspect(id: string) {
    this.check();
    return this.observed(this.find(id));
  }
  async destroy(id: string) {
    this.check();
    this.stop(id);
    this.rows.delete(id);
    this.tokens.delete(id);
    this.generation.delete(id);
  }
  async reach(id: string): Promise<Types["Reach"] | { kind: "relay" }> {
    this.check();
    this.find(id);
    return this.settings.reach ?? { kind: "relay" };
  }
  async relay(id: string): Promise<Duplex> {
    this.check();
    this.find(id);
    return new PassThrough({
      transform: (chunk, _encoding, callback) => {
        const bytes = Buffer.from(chunk);
        if (
          this.settings.fixture &&
          this.settings.fixture_bad_relay &&
          bytes.length
        )
          bytes[0] ^= 1;
        callback(null, bytes);
      },
    });
  }
  async exec(
    id: string,
    r: Types["ExecRequest"],
    _context: Context,
  ): Promise<Duplex> {
    this.find(id);
    if (this.settings.fixture && r.command[0] === "drydock-fixture") {
      return this.fixture(id, r.command);
    }
    this.check();
    if (r.command.length === 1 && r.command[0] === "cat") return this.relay(id);
    if (r.command[0] !== "echo")
      fail("refused", "reference exec supports cat and echo");
    return output(r.command.slice(1).join(" ") + "\n");
  }
  /** Explicit conformance-only guest model; ordinary exec stays a small example. */
  private async fixture(id: string, command: string[]): Promise<Duplex> {
    const [, action, target = id, arg] = command;
    let value: unknown = null;
    if (action === "tools") {
      if (
        !["initial", "crash", "resumed"].includes(target) ||
        this.find(id).state.state !== "running"
      )
        fail("refused", "invalid tools probe");
      let generation = this.generation.get(id) ?? 2;
      if (target === "crash") generation++;
      this.generation.set(id, generation);
      value = {
        files: ["/opt/drydock/drydock-agent"],
        base_entrypoint: ["base-init"],
        prepared_entrypoint: ["base-init"],
        base_command: ["base-command"],
        prepared_command: ["base-command"],
        command: ["/opt/drydock/drydock-agent"],
        pid: generation,
        incarnation: `reference-model-${generation}`,
        fingerprint: "reference-model",
        challenge: arg,
      };
    } else if (action === "forget") {
      this.stop(target);
      this.rows.delete(target);
    } else if (action === "timestamp") {
      if (target) validate("Timestamp", target);
      this.timestamp = target || undefined;
    } else if (action === "inventory_error")
      this.inventoryError = target === "true";
    else if (action === "pause" || action === "state") {
      const state =
        action === "pause"
          ? { state: "stopped", cause: "paused_by_provider" }
          : JSON.parse(arg);
      validate("Observation", state);
      this.stop(target);
      this.find(target).state = state;
      if (state.state === "running") this.running.set(target, Date.now());
    } else if (action === "null_environment") {
      const row: Types["Environment"] = {
        id: `null-${id}`,
        label: null,
        provider: this.name,
        state: { state: "unknown", reason: "provider_api_error" },
        granted_size: null,
        egress: "advisory",
        platform: null,
      };
      this.rows.set(row.id, row);
      value = row;
    } else fail("refused", "unknown fixture action");
    return output(JSON.stringify(value));
  }
  async suspend(id: string) {
    this.check();
    const row = this.find(id);
    if (row.state.state === "stopped") {
      const token = this.tokens.get(id);
      if (!token) fail("refused", "missing resume token");
      return { token };
    }
    this.stop(id);
    row.state = { state: "stopped", cause: "suspended_by_request" };
    const token = `${this.name}:${id}`;
    this.tokens.set(id, token);
    return { token };
  }
  async resume(id: string, token: Types["ResumeToken"]) {
    this.check();
    const row = this.find(id);
    if (this.tokens.get(id) !== token.token)
      fail("refused", "invalid resume token");
    row.state = { state: "running" };
    if (!this.running.has(id)) this.running.set(id, Date.now());
  }
  async export(id: string) {
    this.check();
    this.find(id);
    return { reference: `memory://${this.name}/${id}` };
  }
  async usage(period: Types["Period"]): Promise<Types["Usage"]> {
    this.check();
    const segments = [...this.segments];
    for (const [id, start] of this.running) {
      const size = this.find(id).granted_size;
      if (size) segments.push({ size, start, end: Date.now() });
    }
    const environment_hours: Types["SizeUsage"][] = [];
    for (const s of segments) {
      const ms =
        Math.min(s.end, Date.parse(period.end)) -
        Math.max(s.start, Date.parse(period.start));
      if (ms <= 0) continue;
      let row = environment_hours.find((r) =>
        isDeepStrictEqual(r.size, s.size),
      );
      if (!row) {
        row = { size: s.size, hours: 0 };
        environment_hours.push(row);
      }
      row.hours += ms / 3600000;
    }
    return { period, environment_hours, measurements: null };
  }
  async quota() {
    this.check();
    return {
      resources: [],
      credits_remaining: null,
      credit_unit: null,
      concurrency_in_use: [...this.rows.values()].filter(
        (e) => e.state.state === "running",
      ).length,
      concurrency_limit: null,
    };
  }
}
function output(text: string): Duplex {
  const stream = new PassThrough();
  stream.end(text);
  return stream;
}

import { DiagnosticSecrets } from "./diagnostic.js";
import { Observation } from "./observation.js";
import {
  checkDeclaration,
  checkSupported,
  invoke,
  type Operation,
  type OperationArgs,
  type OperationResult,
} from "./operations.js";
import { isDeepStrictEqual } from "node:util";
import {
  fail,
  ProtocolFailure,
  type Context,
  type Credentials,
  type Observed,
  type Provider,
  type ProviderModule,
  type Types,
} from "./provider.js";
import { protocolVersion, validate } from "./validation.js";

type Instance = {
  config: Types["ProviderConfiguration"];
  provider: Provider;
  capabilities: Types["Capabilities"];
  rateLimits: Types["RateLimit"][];
  credentials: Credentials;
  rejected: boolean;
  rejectionGeneration: number;
  budget: Map<string, number[]>;
  pollBudget: Map<string, number[]>;
};
export class Host {
  readonly stop = new AbortController();
  readonly observation = new Observation(this.stop.signal);
  private instances = new Map<string, Instance>();
  private modules: Types["ModuleConfiguration"][] = [];
  private configuring: Promise<unknown> = Promise.resolve();
  constructor(readonly registry: Map<string, ProviderModule>) {}
  hello(): Types["Hello"] {
    return {
      protocol_version: protocolVersion,
      host_version: "0.1.0",
      loadable_modules: [...this.registry].map(([name, m]) => ({
        name,
        version: m.version,
        smallest_size: m.smallestSize ?? {
          cpus: 1,
          memory_bytes: 1 << 30,
          disk_bytes: 1 << 30,
        },
      })),
      modules: this.modules.map((m) => ({
        name: m.name,
        version: this.registry.get(m.entrypoint)!.version,
      })),
      providers: [...this.instances].map(([provider, i]) => ({
        provider,
        module: i.config.module,
        capabilities: i.capabilities,
        readiness: this.readiness(i),
        rate_limits: i.rateLimits,
      })),
    };
  }
  private instance(name: string) {
    const i = this.instances.get(name);
    if (!i) fail("not_found", "unknown provider");
    return i;
  }
  private readiness(i: Instance): Types["Readiness"] {
    const module = i.provider.readiness?.(i.credentials) ?? { status: "ready" };
    if (module.status !== "ready")
      return this.mask(module) as Types["Readiness"];
    if (
      i.credentials.mode.mode === "direct" &&
      (!i.credentials.value || i.rejected)
    )
      return {
        status: "missing_credential",
        reason: "credential not delivered or rejected",
      };
    if (i.rejected)
      return { status: "unknown", reason: "proxy credential rejected" };
    return { status: "ready" };
  }
  private secrets = new DiagnosticSecrets();
  private sanitized = new WeakSet<ProtocolFailure>();
  mask(value: unknown, extra?: string): unknown {
    return this.secrets.mask(value, extra);
  }
  /** Never re-mask a captured-token diagnostic after that token is retired. */
  errorDetail(error: ProtocolFailure): Types["ProtocolError"] {
    return this.sanitized.has(error)
      ? error.detail
      : (this.mask(error.detail) as Types["ProtocolError"]);
  }
  private failure(
    detail: Types["ProtocolError"],
    extra?: string,
  ): ProtocolFailure {
    const error = new ProtocolFailure(
      this.mask(detail, extra) as Types["ProtocolError"],
    );
    this.sanitized.add(error);
    return error;
  }
  async configure(document: Types["HostConfiguration"]) {
    validate("HostConfiguration", document);
    // Serialize transactions without making provider calls share an operation lock.
    const task = this.configuring
      .catch(() => {})
      .then(() => this.configureTransaction(structuredClone(document)));
    this.configuring = task;
    return task;
  }
  private async configureTransaction(document: Types["HostConfiguration"]) {
    if (this.stop.signal.aborted) fail("unavailable", "host stopping");
    const modules = new Map<string, string>();
    for (const m of document.modules) {
      if (modules.has(m.name) || !this.registry.has(m.entrypoint))
        fail("refused", "duplicate or unregistered module");
      modules.set(m.name, m.entrypoint);
    }
    const names = new Set<string>();
    for (const p of document.providers) {
      if (!p.name || names.has(p.name) || !modules.has(p.module))
        fail("refused", "invalid or duplicate provider/module");
      names.add(p.name);
      const old = this.instances.get(p.name);
      if (
        old &&
        (!isDeepStrictEqual(old.config, p) ||
          this.modules.find((m) => m.name === p.module)?.entrypoint !==
            modules.get(p.module))
      )
        fail("refused", "cannot replace a configured provider; restart host");
      if (p.credential.mode === "proxied") {
        try {
          const url = new URL(p.credential.proxy_url);
          if (!["http:", "https:"].includes(url.protocol)) throw Error();
        } catch {
          fail("refused", "invalid proxy URL");
        }
      }
    }
    if ([...this.instances.keys()].some((k) => !names.has(k)))
      fail("refused", "cannot remove a configured provider; restart host");
    const additions: [string, Instance][] = [];
    for (const p of document.providers) {
      if (this.instances.has(p.name)) continue;
      let provider: Provider;
      try {
        provider = await this.cancel(
          this.registry
            .get(modules.get(p.module)!)!
            .configure(p, this.stop.signal),
        );
      } catch (error) {
        if (error instanceof ProtocolFailure)
          throw this.failure(
            error.detail,
            p.credential.mode === "proxied"
              ? p.credential.placeholder_token
              : undefined,
          );
        throw error;
      }
      validate("Capabilities", provider.capabilities);
      checkDeclaration(provider);
      for (const rate of provider.rateLimits ?? []) {
        validate("RateLimit", rate);
        if (!rate.requests || !rate.period_seconds)
          fail("refused", "invalid declared rate limit");
      }
      if (
        provider.observation.mode === "poll" &&
        !(provider.observation.intervalMs > 0)
      )
        fail("refused", "invalid poll interval");
      additions.push([
        p.name,
        {
          config: p,
          provider,
          capabilities: structuredClone(provider.capabilities),
          rateLimits: structuredClone(provider.rateLimits ?? []),
          credentials: { mode: p.credential, generation: 0 },
          rejected: false,
          rejectionGeneration: 0,
          budget: new Map(),
          pollBudget: new Map(),
        },
      ]);
    }
    if (this.stop.signal.aborted) fail("unavailable", "host stopping");
    this.modules = document.modules;
    for (const [name, i] of additions) {
      this.instances.set(name, i);
      if (i.config.credential.mode === "proxied")
        this.secrets.remember(name, i.config.credential.placeholder_token);
    }
    for (const [name, i] of additions)
      this.observation.register({
        name,
        observation: i.provider.observation,
        rateLimits: i.rateLimits,
        credentials: () => i.credentials,
        readiness: () => this.readiness(i),
        list: (poll, signal) => this.invoke(name, "list", [], { poll, signal }),
        run: i.provider.run?.bind(i.provider),
      });
  }
  refresh(name: string, value: string) {
    validate("CredentialRefresh", { value });
    const i = this.instance(name);
    if (i.credentials.mode.mode !== "direct")
      fail("refused", "proxied provider cannot accept direct credentials");
    this.secrets.remember(name, value);
    i.credentials = {
      ...i.credentials,
      value,
      generation: i.credentials.generation + 1,
    };
    i.rejected = false;
    this.observation.credentialsChanged(name);
  }
  private async cancel<T>(
    task: Promise<T>,
    signal = this.stop.signal,
  ): Promise<T> {
    if (signal.aborted) fail("unavailable", "operation cancelled");
    let listener: () => void;
    const stopped = new Promise<never>((_, reject) => {
      listener = () =>
        reject(
          new ProtocolFailure({ kind: "unavailable", reason: "host stopping" }),
        );
      signal.addEventListener("abort", listener, { once: true });
    });
    try {
      return await Promise.race([task, stopped]);
    } finally {
      signal.removeEventListener("abort", listener!);
    }
  }
  private reserve(i: Instance, operation: Operation, poll: boolean) {
    const now = Date.now();
    const limits = i.rateLimits.filter(
      (r) =>
        r.operation === operation ||
        r.operation === "all" ||
        r.operation === "*",
    );
    const applicable = limits.map((r) => ({
      r,
      key: r.operation,
      times: (i.budget.get(r.operation) ?? []).filter(
        (t) => now - t < r.period_seconds * 1000,
      ),
      pollTimes: (i.pollBudget.get(r.operation) ?? []).filter(
        (t) => now - t < (r.requests === 1 ? 2 : 1) * r.period_seconds * 1000,
      ),
    }));
    for (const { r, times, pollTimes } of applicable) {
      if (
        times.length >= r.requests ||
        (poll &&
          (pollTimes.length >= Math.max(1, Math.floor(r.requests / 2)) ||
            (r.requests === 1 &&
              now - (pollTimes.at(-1) ?? -Infinity) <
                2 * r.period_seconds * 1000))) ||
        (!poll &&
          this.observation.pendingPoll(i.config.name) &&
          r.requests === 1)
      ) {
        throw new ProtocolFailure({
          kind: "rate_limited",
          reason: "declared rate limit",
          retry_after: Math.max(
            1,
            Math.ceil(
              ((times[0] ?? now) + r.period_seconds * 1000 - now) / 1000,
            ),
          ),
        });
      }
    }
    for (const key of new Set(limits.map((r) => r.operation))) {
      const same = limits.filter((r) => r.operation === key);
      const longest = Math.max(...same.map((r) => r.period_seconds)) * 1000;
      const pollLongest =
        Math.max(
          ...same.map((r) => r.period_seconds * (r.requests === 1 ? 2 : 1)),
        ) * 1000;
      i.budget.set(key, [
        ...(i.budget.get(key) ?? []).filter((t) => now - t < longest),
        now,
      ]);
      if (poll)
        i.pollBudget.set(key, [
          ...(i.pollBudget.get(key) ?? []).filter((t) => now - t < pollLongest),
          now,
        ]);
    }
  }

  private async call<T>(
    name: string,
    operation: Operation,
    invoke: (p: Provider, c: Context) => Promise<T>,
    poll = false,
    signal?: AbortSignal,
  ): Promise<T> {
    const i = this.instance(name);
    checkSupported(i.capabilities, operation);
    const readiness = this.readiness(i);
    if (
      readiness.status !== "ready" &&
      !(
        i.credentials.mode.mode === "proxied" &&
        i.rejected &&
        readiness.status === "unknown"
      )
    )
      fail("unavailable", "provider not ready");
    this.reserve(i, operation, poll);
    const callSignal = signal
      ? AbortSignal.any([signal, this.stop.signal])
      : this.stop.signal;
    const credentials = i.credentials,
      rejectionGeneration = i.rejectionGeneration;
    try {
      const result = await this.cancel(
        invoke(i.provider, { credentials, signal: callSignal }),
        callSignal,
      );
      if (
        i.credentials.mode.mode === "proxied" &&
        rejectionGeneration === i.rejectionGeneration
      )
        i.rejected = false;
      return result;
    } catch (error) {
      if (error instanceof ProtocolFailure) {
        if (
          error.detail.kind === "credential_rejected" &&
          credentials.generation === i.credentials.generation
        ) {
          i.rejected = true;
          i.rejectionGeneration++;
          this.observation.notify();
        }
        throw this.failure(
          {
            ...error.detail,
            reason: `provider ${name} operation ${operation}: ${error.detail.reason}`,
          },
          credentials.mode.mode === "direct"
            ? credentials.value
            : credentials.mode.placeholder_token,
        );
      }
      throw new ProtocolFailure({
        kind: "internal",
        reason: "module operation failed",
        provider_error: "",
      });
    }
  }
  invoke<K extends Operation>(
    name: string,
    operation: K,
    args: OperationArgs<K>,
    options: { poll?: boolean; signal?: AbortSignal } = {},
  ) {
    return this.call<OperationResult<K>>(
      name,
      operation,
      (provider, context) => invoke(provider, operation, args, context),
      options.poll,
      options.signal,
    );
  }
  async prepare(name: string, request: Types["PrepareRequest"]) {
    validate("PrepareRequest", request);
    const platforms = this.instance(name).capabilities.platforms ?? [];
    const platform = request.platform ?? platforms[0];
    if (!platform || !platforms.some((p) => isDeepStrictEqual(p, platform)))
      fail("refused", "provider does not support requested platform");
    const result = await this.invoke(name, "prepare", [
      { ...request, platform },
    ]);
    if (!isDeepStrictEqual(result.platform, platform))
      throw new ProtocolFailure({
        kind: "internal",
        reason: "module prepared wrong platform",
        provider_error: "",
      });
    return result;
  }
  async provision(name: string, request: Types["ProvisionRequest"]) {
    validate("ProvisionRequest", request);
    if (request.prepared.provider !== name)
      fail("refused", "prepared provider mismatch");
    return this.invoke(name, "provision", [request]);
  }
  async destroy(name: string, id: string) {
    this.instance(name);
    const finish = this.observation.destroying(name, id);
    try {
      await this.invoke(name, "destroy", [id]);
      finish(true);
    } catch (error) {
      finish(false);
      throw error;
    }
  }
  async shutdown() {
    this.stop.abort();
    await this.observation.shutdown();
    this.instances.clear();
    this.secrets.clear();
  }
}

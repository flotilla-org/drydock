import { DiagnosticSecrets } from "./diagnostic.js";
import { randomUUID } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { EventEmitter } from "node:events";
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
  cache?: Observed[];
  pollError?: Types["ProtocolError"];
  destroyed: Set<string>;
  pendingDestroy: Map<string, number>;
  budget: Map<string, number[]>;
  pollBudget: Map<string, number[]>;
  pollPending: boolean;
  pushStarted?: boolean;
  refreshPending?: boolean;
  seen?: Observed[];
  timer?: NodeJS.Timeout;
  polling?: Promise<void>;
};
export class Host {
  readonly changes = new EventEmitter();
  readonly stop = new AbortController();
  private instances = new Map<string, Instance>();
  private modules: Types["ModuleConfiguration"][] = [];
  private history: Types["Event"][] = [];
  private cursor: string;
  private sequence = 0;
  private epoch = randomUUID();
  private configuring: Promise<unknown> = Promise.resolve();
  private tasks = new Set<Promise<void>>();
  constructor(readonly registry: Map<string, ProviderModule>) {
    this.cursor = `${this.epoch}:0`;
  }
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
      const ports = [
        ["fallback_runner", "exec"],
        ["suspend_resume", "suspend"],
        ["suspend_resume", "resume"],
        ["export", "export"],
        ["usage", "usage"],
        ["quota", "quota"],
      ] as const;
      for (const [cap, port] of ports)
        if (
          provider.capabilities[cap] !==
          (typeof provider[port] === "function")
        )
          fail("refused", "capabilities must match optional operation ports");
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
          destroyed: new Set(),
          pendingDestroy: new Map(),
          budget: new Map(),
          pollBudget: new Map(),
          pollPending: false,
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
    for (const [, i] of additions) this.observe(i);
    this.changes.emit("change");
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
    i.pollError = undefined;
    if (i.polling) i.refreshPending = true;
    if (i.timer) clearTimeout(i.timer);
    this.observe(i);
    this.changes.emit("change");
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
  private reserve(i: Instance, operation: string, poll: boolean) {
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
        (!poll && i.pollPending && r.requests === 1)
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

  async call<T>(
    name: string,
    operation: string,
    invoke: (p: Provider, c: Context) => Promise<T>,
    poll = false,
    signal?: AbortSignal,
  ): Promise<T> {
    const i = this.instance(name);
    const capability = {
      exec: "fallback_runner",
      suspend: "suspend_resume",
      resume: "suspend_resume",
      export: "export",
      usage: "usage",
      quota: "quota",
    }[operation] as keyof Types["Capabilities"] | undefined;
    if (capability && !i.capabilities[capability])
      fail("refused", "unsupported operation");
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
          this.changes.emit("change");
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
  async prepare(name: string, request: Types["PrepareRequest"]) {
    validate("PrepareRequest", request);
    const platforms = this.instance(name).capabilities.platforms ?? [];
    const platform = request.platform ?? platforms[0];
    if (!platform || !platforms.some((p) => isDeepStrictEqual(p, platform)))
      fail("refused", "provider does not support requested platform");
    const result = await this.call(name, "prepare", (p, c) =>
      p.prepare({ ...request, platform }, c),
    );
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
    return this.call(name, "provision", (p, c) => p.provision(request, c));
  }
  async destroy(name: string, id: string) {
    const i = this.instance(name);
    i.pendingDestroy.set(id, (i.pendingDestroy.get(id) ?? 0) + 1);
    try {
      await this.call(name, "destroy", (p, c) => p.destroy(id, c));
      i.destroyed.add(id);
    } finally {
      const count = (i.pendingDestroy.get(id) ?? 1) - 1;
      if (count) i.pendingDestroy.set(id, count);
      else i.pendingDestroy.delete(id);
    }
  }
  private emit(i: Instance, row: Observed, event: Types["EventKind"]) {
    const cursor = `${this.epoch}:${++this.sequence}`;
    this.cursor = cursor;
    this.history.push({
      cursor,
      id: row.environment.id,
      label: row.environment.label,
      provider: i.config.name,
      timestamp: row.timestamp ?? new Date().toISOString(),
      timestamp_source: row.timestamp ? "provider" : "adaptor",
      event,
    });
    if (this.history.length > 1024) this.history.shift();
    this.changes.emit("change");
  }
  private reconcile(i: Instance, rows: Observed[]) {
    const old = new Map((i.seen ?? []).map((r) => [r.environment.id, r]));
    for (const row of rows) {
      const before = old.get(row.environment.id),
        state = row.environment.state;
      old.delete(row.environment.id);
      if (!before) this.emit(i, row, { kind: "created" });
      if (
        state.state === "running" &&
        before?.environment.state.state === "stopped"
      )
        this.emit(i, row, { kind: "resumed" });
      if (
        state.state === "running" &&
        row.environment.granted_size &&
        (!before ||
          before.environment.state.state !== "running" ||
          !isDeepStrictEqual(
            before.environment.granted_size,
            row.environment.granted_size,
          ))
      ) {
        this.emit(i, row, {
          kind: "running",
          granted_size: row.environment.granted_size,
        });
      }
      if (
        state.state === "stopped" &&
        !isDeepStrictEqual(before?.environment.state, state)
      ) {
        this.emit(i, row, {
          kind: state.cause === "paused_by_provider" ? "paused" : "stopped",
          cause: state.cause,
        });
      }
      if (
        state.state === "gone" &&
        !isDeepStrictEqual(before?.environment.state, state)
      )
        this.emit(i, row, { kind: "gone", cause: state.cause });
    }
    const deferred: Observed[] = [];
    for (const [id, row] of old) {
      if (i.pendingDestroy.has(id) && !i.destroyed.has(id)) {
        deferred.push(row);
        continue;
      }
      if (row.environment.state.state === "gone") continue;
      this.emit(
        i,
        { environment: row.environment },
        {
          kind: "gone",
          cause: {
            kind: i.destroyed.has(id)
              ? "destroyed_by_request"
              : "missing_on_list",
          },
        },
      );
      i.destroyed.delete(id);
    }
    i.cache = structuredClone(rows);
    i.seen = [
      ...deferred,
      ...rows.map((row) =>
        row.environment.state.state === "transitioning"
          ? (i.seen?.find((old) => old.environment.id === row.environment.id) ??
            row)
          : row,
      ),
    ];
    i.pollError = undefined;
    this.changes.emit("change");
  }
  private observe(i: Instance) {
    if (this.stop.signal.aborted || i.polling) return;
    if (i.provider.observation.mode === "push") {
      if (i.provider.run && !i.pushStarted) {
        i.pushStarted = true;
        const task = i.provider
          .run(
            (row, event) => {
              if (!this.stop.signal.aborted) this.emit(i, row, event);
            },
            () => i.credentials,
            this.stop.signal,
          )
          .catch(() => {});
        this.tasks.add(task);
        void task.finally(() => this.tasks.delete(task));
      }
      return;
    }
    let interval = i.provider.observation.intervalMs;
    for (const r of i.rateLimits)
      if (r.operation === "list" || r.operation === "*")
        interval = Math.max(
          interval,
          (r.period_seconds * 1000 * (r.requests === 1 ? 2 : 1)) /
            Math.max(1, Math.floor(r.requests / 2)),
        );
    const generation = i.credentials.generation;
    i.polling = (async () => {
      try {
        i.pollPending = true;
        const rows = await this.call(
          i.config.name,
          "list",
          (p, c) => p.list(c),
          true,
        );
        i.pollPending = false;
        if (generation === i.credentials.generation) this.reconcile(i, rows);
      } catch (error) {
        i.pollPending =
          error instanceof ProtocolFailure &&
          error.detail.kind === "rate_limited";
        if (generation === i.credentials.generation && !i.rejected)
          i.pollError =
            error instanceof ProtocolFailure
              ? error.detail
              : { kind: "unavailable", reason: "observation failed" };
        this.changes.emit("change");
      } finally {
        i.polling = undefined;
        if (!this.stop.signal.aborted) {
          const delay = i.refreshPending ? 0 : interval;
          i.refreshPending = false;
          i.timer = setTimeout(() => this.observe(i), delay);
        }
      }
    })();
  }
  async records(since?: string): Promise<Types["ObserveRecord"][]> {
    if (this.stop.signal.aborted) fail("unavailable", "host stopping");
    if (since === this.cursor) return [];
    const index = this.history.findIndex((e) => e.cursor === since);
    if (since === `${this.epoch}:0` && this.sequence <= 1024)
      return this.history.map((event) => ({ type: "event", event }));
    if (since && index >= 0)
      return this.history
        .slice(index + 1)
        .map((event) => ({ type: "event", event }));
    // Capture cursor before push lists, so events arriving during listing are replayed.
    const before = this.cursor;
    const push = new Map<string, Observed[] | Types["ProtocolError"]>();
    await Promise.all(
      [...this.instances]
        .filter(([, i]) => i.provider.observation.mode === "push")
        .map(async ([name]) => {
          let timer: NodeJS.Timeout | undefined;
          try {
            push.set(
              name,
              await Promise.race([
                this.call(
                  name,
                  "list",
                  (p, c) => p.list(c),
                  false,
                  AbortSignal.timeout(5000),
                ),
                new Promise<never>((_, reject) => {
                  timer = setTimeout(
                    () =>
                      reject(
                        new ProtocolFailure({
                          kind: "unavailable",
                          reason: "snapshot deadline",
                        }),
                      ),
                    5000,
                  );
                }),
              ]),
            );
          } catch (e) {
            push.set(
              name,
              e instanceof ProtocolFailure
                ? e.detail
                : { kind: "unavailable", reason: "snapshot failed" },
            );
          } finally {
            clearTimeout(timer);
          }
        }),
    );
    while (
      [...this.instances.values()].some(
        (i) =>
          i.provider.observation.mode === "poll" &&
          this.readiness(i).status === "ready" &&
          !i.cache &&
          !i.pollError,
      )
    ) {
      if (this.stop.signal.aborted) fail("unavailable", "host stopping");
      await this.changed();
    }
    if (this.stop.signal.aborted) fail("unavailable", "host stopping");
    const environments: Types["Environment"][] = [],
      unavailable: Record<string, Types["ProtocolError"]> = {};
    for (const [name, i] of this.instances) {
      if (this.readiness(i).status !== "ready") {
        unavailable[name] = {
          kind: "unavailable",
          reason: "provider not ready",
        };
        continue;
      }
      const rows =
        i.provider.observation.mode === "poll" ? i.cache : push.get(name);
      if (!rows || !Array.isArray(rows))
        unavailable[name] = (rows as Types["ProtocolError"]) ??
          i.pollError ?? {
            kind: "unavailable",
            reason: "inventory unavailable",
          };
      else environments.push(...rows.map((r) => r.environment));
    }
    const cursor = push.size ? before : this.cursor;
    return [
      {
        type: "snapshot",
        cursor,
        environments,
        ...(Object.keys(unavailable).length
          ? { unavailable_providers: unavailable }
          : {}),
      },
    ];
  }
  async changed(signal?: AbortSignal) {
    if (this.stop.signal.aborted || signal?.aborted) return;
    await new Promise<void>((resolve) => {
      const done = () => {
        this.changes.off("change", done);
        this.stop.signal.removeEventListener("abort", done);
        signal?.removeEventListener("abort", done);
        resolve();
      };
      this.changes.once("change", done);
      this.stop.signal.addEventListener("abort", done, { once: true });
      signal?.addEventListener("abort", done, { once: true });
    });
  }
  async shutdown() {
    this.stop.abort();
    for (const i of this.instances.values()) clearTimeout(i.timer);
    let timer: NodeJS.Timeout | undefined;
    await Promise.race([
      Promise.allSettled([...this.tasks]),
      new Promise((resolve) => {
        timer = setTimeout(resolve, 5000);
      }),
    ]);
    clearTimeout(timer);
    this.instances.clear();
    this.secrets.clear();
  }
}

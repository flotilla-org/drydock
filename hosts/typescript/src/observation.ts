import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { isDeepStrictEqual } from "node:util";
import {
  fail,
  ProtocolFailure,
  type Credentials,
  type Observed,
  type Provider,
  type Types,
} from "./provider.js";
export type ObservationSource = {
  name: string;
  observation: Provider["observation"];
  rateLimits: Types["RateLimit"][];
  credentials: () => Credentials;
  readiness: () => Types["Readiness"];
  list: (poll: boolean, signal?: AbortSignal) => Promise<Observed[]>;
  run?: Provider["run"];
};
type State = {
  source: ObservationSource;
  cache?: Observed[];
  pollError?: Types["ProtocolError"];
  destroyed: Set<string>;
  pendingDestroy: Map<string, number>;
  pollPending: boolean;
  pushStarted?: boolean;
  refreshPending?: boolean;
  seen?: Observed[];
  timer?: NodeJS.Timeout;
  polling?: Promise<void>;
};
/** Owns inventories, stable billing baselines, polling/push lifetime and replay. */
export class Observation {
  private sources = new Map<string, State>();
  private changes = new EventEmitter();
  private history: Types["Event"][] = [];
  private epoch = randomUUID();
  private sequence = 0;
  private cursor = `${this.epoch}:0`;
  private tasks = new Set<Promise<void>>();
  constructor(private stopping: AbortSignal) {}
  register(source: ObservationSource) {
    const state: State = {
      source,
      destroyed: new Set(),
      pendingDestroy: new Map(),
      pollPending: false,
    };
    this.sources.set(source.name, state);
    this.observe(state);
    this.notify();
  }
  notify() {
    this.changes.emit("change");
  }
  credentialsChanged(name: string) {
    const i = this.sources.get(name)!;
    i.pollError = undefined;
    if (i.polling) i.refreshPending = true;
    clearTimeout(i.timer);
    this.observe(i);
    this.notify();
  }
  pendingPoll(name: string) {
    return this.sources.get(name)?.pollPending ?? false;
  }
  destroying(name: string, id: string) {
    const i = this.sources.get(name)!;
    i.pendingDestroy.set(id, (i.pendingDestroy.get(id) ?? 0) + 1);
    return (confirmed: boolean) => {
      if (confirmed) i.destroyed.add(id);
      const count = (i.pendingDestroy.get(id) ?? 1) - 1;
      if (count) i.pendingDestroy.set(id, count);
      else i.pendingDestroy.delete(id);
    };
  }
  private emit(i: State, row: Observed, event: Types["EventKind"]) {
    const cursor = `${this.epoch}:${++this.sequence}`;
    this.cursor = cursor;
    this.history.push({
      cursor,
      id: row.environment.id,
      label: row.environment.label,
      provider: i.source.name,
      timestamp: row.timestamp ?? new Date().toISOString(),
      timestamp_source: row.timestamp ? "provider" : "adaptor",
      event,
    });
    if (this.history.length > 1024) this.history.shift();
    this.changes.emit("change");
  }
  private reconcile(i: State, rows: Observed[]) {
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
  private observe(i: State) {
    if (this.stopping.aborted || i.polling) return;
    if (i.source.observation.mode === "push") {
      if (i.source.run && !i.pushStarted) {
        i.pushStarted = true;
        const task = i.source
          .run(
            (row, event) => {
              if (!this.stopping.aborted) this.emit(i, row, event);
            },
            i.source.credentials,
            this.stopping,
          )
          .catch(() => {});
        this.tasks.add(task);
        void task.finally(() => this.tasks.delete(task));
      }
      return;
    }
    let interval = i.source.observation.intervalMs;
    for (const r of i.source.rateLimits)
      if (r.operation === "list" || r.operation === "*")
        interval = Math.max(
          interval,
          (r.period_seconds * 1000 * (r.requests === 1 ? 2 : 1)) /
            Math.max(1, Math.floor(r.requests / 2)),
        );
    const generation = i.source.credentials().generation;
    i.polling = (async () => {
      try {
        i.pollPending = true;
        const rows = await i.source.list(true);
        i.pollPending = false;
        if (generation === i.source.credentials().generation)
          this.reconcile(i, rows);
      } catch (error) {
        i.pollPending =
          error instanceof ProtocolFailure &&
          error.detail.kind === "rate_limited";
        if (
          generation === i.source.credentials().generation &&
          i.source.readiness().status === "ready"
        )
          i.pollError =
            error instanceof ProtocolFailure
              ? error.detail
              : { kind: "unavailable", reason: "observation failed" };
        this.changes.emit("change");
      } finally {
        i.polling = undefined;
        if (!this.stopping.aborted) {
          const delay = i.refreshPending ? 0 : interval;
          i.refreshPending = false;
          i.timer = setTimeout(() => this.observe(i), delay);
        }
      }
    })();
  }
  async records(
    since?: string,
    signal?: AbortSignal,
  ): Promise<Types["ObserveRecord"][]> {
    if (this.stopping.aborted || signal?.aborted)
      fail("unavailable", "host stopping");
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
      [...this.sources]
        .filter(([, i]) => i.source.observation.mode === "push")
        .map(async ([name, i]) => {
          let timer: NodeJS.Timeout | undefined;
          try {
            push.set(
              name,
              await Promise.race([
                i.source.list(
                  false,
                  AbortSignal.any([
                    AbortSignal.timeout(5000),
                    signal ?? this.stopping,
                  ]),
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
      [...this.sources.values()].some(
        (i) =>
          i.source.observation.mode === "poll" &&
          i.source.readiness().status === "ready" &&
          !i.cache &&
          !i.pollError,
      )
    ) {
      if (this.stopping.aborted || signal?.aborted)
        fail("unavailable", "host stopping");
      await this.changed(signal);
    }
    if (this.stopping.aborted || signal?.aborted)
      fail("unavailable", "host stopping");
    const environments: Types["Environment"][] = [],
      unavailable: Record<string, Types["ProtocolError"]> = {};
    for (const [name, i] of this.sources) {
      if (i.source.readiness().status !== "ready") {
        unavailable[name] = {
          kind: "unavailable",
          reason: "provider not ready",
        };
        continue;
      }
      const rows =
        i.source.observation.mode === "poll" ? i.cache : push.get(name);
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
  private async changed(signal?: AbortSignal) {
    if (this.stopping.aborted || signal?.aborted) return;
    await new Promise<void>((resolve) => {
      const done = () => {
        this.changes.off("change", done);
        this.stopping.removeEventListener("abort", done);
        signal?.removeEventListener("abort", done);
        resolve();
      };
      this.changes.once("change", done);
      this.stopping.addEventListener("abort", done, { once: true });
      signal?.addEventListener("abort", done, { once: true });
    });
  }
  /** Read the first batch before HTTP headers, then follow with bounded replay. */
  async stream(since?: string, signal = this.stopping) {
    const first = await this.records(since, signal);
    return this.follow(first, since, signal);
  }
  private async *follow(
    records: Types["ObserveRecord"][],
    cursor: string | undefined,
    signal: AbortSignal,
  ) {
    while (!signal.aborted && !this.stopping.aborted) {
      const pending = new AbortController();
      const wake = this.changed(AbortSignal.any([pending.signal, signal]));
      try {
        for (const record of records) {
          if (signal.aborted || this.stopping.aborted) return;
          cursor =
            record.type === "snapshot" ? record.cursor : record.event.cursor;
          yield record;
        }
        const more = await this.records(cursor, signal);
        if (more.length) records = more;
        else {
          await wake;
          if (signal.aborted || this.stopping.aborted) return;
          records = await this.records(cursor, signal);
        }
      } finally {
        pending.abort();
        await wake;
      }
    }
  }
  async shutdown() {
    for (const i of this.sources.values()) clearTimeout(i.timer);
    let timer: NodeJS.Timeout | undefined;
    await Promise.race([
      Promise.allSettled([...this.tasks]),
      new Promise((resolve) => {
        timer = setTimeout(resolve, 5000);
      }),
    ]);
    clearTimeout(timer);
    this.sources.clear();
  }
}

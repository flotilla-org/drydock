import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { mkdtemp, rm, stat, readFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import fc from "fast-check";
import { Host } from "../dist/host.js";
import { serve } from "../dist/server.js";
import { reference } from "../dist/reference.js";
import { peerUid } from "../dist/peer.js";
import type { Types } from "../src/provider.ts";
const size = { cpus: 1, memory_bytes: 1024, disk_bytes: 0 };
const configuration = (settings = {}) => ({
  modules: [{ name: "memory", entrypoint: "reference" }],
  providers: ["a", "b"].map((name) => ({
    name,
    module: "memory",
    settings,
    credential: { mode: "direct" as const, credential_reference: "test" },
  })),
});
async function fixture(
  t: { after: (fn: () => Promise<void>) => void },
  config = configuration(),
) {
  const dir = await mkdtemp(`${tmpdir()}/drydock-ts-`),
    socketPath = `${dir}/host.sock`;
  const host = new Host(new Map([["reference", reference]])),
    running = await serve(host, { unix: socketPath });
  t.after(async () => {
    await running.close();
    await rm(dir, { recursive: true, force: true });
  });
  const call = async (method: string, path: string, body?: unknown) =>
    request({ socketPath, method, path }, body);
  assert.equal((await call("PUT", "/v1/config", config)).status, 204);
  return { dir, socketPath, host, call };
}
function request(
  options: http.RequestOptions,
  body?: unknown,
): Promise<{ status: number; body: any; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        ...options,
        agent: false,
        headers: {
          ...(body === undefined ? {} : { "content-type": "application/json" }),
          ...options.headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (b) => chunks.push(b));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString();
          resolve({
            status: res.statusCode!,
            body: text ? JSON.parse(text) : null,
            headers: res.headers,
          });
        });
      },
    );
    req.on("error", reject);
    req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}
async function ready(
  call: Awaited<ReturnType<typeof fixture>>["call"],
  name = "a",
) {
  assert.equal(
    (
      await call("PUT", `/v1/providers/${name}/credential`, {
        value: "test-secret-one",
      })
    ).status,
    204,
  );
}
async function provision(
  call: Awaited<ReturnType<typeof fixture>>["call"],
  label = "label",
  name = "a",
) {
  const prepared = await call("POST", `/v1/providers/${name}/prepare`, {
    image_digest: "image",
    tools_digest: "tools",
    size,
  });
  assert.equal(prepared.status, 200);
  const body = {
    prepared: prepared.body,
    label,
    size,
    egress: { mode: "open" },
  };
  return {
    body,
    result: await call("POST", `/v1/providers/${name}/environments`, body),
  };
}
// The real Unix endpoint advertises modules, keeps instances independent and preserves
// credentials/resources across exact configuration repeats; additions commit atomically.
test("discovery, transactional configuration and routing", async (t) => {
  const { call } = await fixture(t);
  const hello = (await call("GET", "/v1/hello")).body;
  assert.equal(hello.protocol_version, "7");
  assert.equal(hello.loadable_modules[0].name, "reference");
  assert.equal(hello.providers.length, 2);
  assert.equal((await call("GET", "/v1/providers/a/environments")).status, 503);
  await ready(call);
  const { result } = await provision(call);
  assert.equal(result.status, 201);
  assert.equal((await call("GET", "/v1/providers/b/environments")).status, 503);
  await ready(call, "b");
  assert.deepEqual(
    (await call("GET", "/v1/providers/b/environments")).body,
    [],
  );
  assert.equal((await call("PUT", "/v1/config", configuration())).status, 204);
  assert.equal(
    (await call("GET", "/v1/providers/a/environments")).body.length,
    1,
  );
  const invalid = configuration();
  invalid.providers.push({
    ...invalid.providers[0],
    name: "c",
    module: "missing",
  });
  assert.equal((await call("PUT", "/v1/config", invalid)).status, 422);
  assert.equal((await call("GET", "/v1/hello")).body.providers.length, 2);
  assert.equal(
    (await call("PUT", "/v1/config", { ...configuration(), providers: [] }))
      .status,
    422,
  );
});
// Labels are idempotency keys even for changed valid bodies. Generated operation
// sequences include duplicate labels, missing IDs and destroy/provision interleavings.
test("generated lifecycle preserves label idempotency and inventory", async (t) => {
  const { call } = await fixture(t);
  await ready(call);
  await fc.assert(
    fc.asyncProperty(
      fc.array(
        fc.record({
          label: fc.integer({ min: 0, max: 4 }),
          destroy: fc.boolean(),
        }),
        { minLength: 1, maxLength: 25 },
      ),
      async (operations) => {
        for (const row of (await call("GET", "/v1/providers/a/environments"))
          .body)
          await call("DELETE", `/v1/providers/a/environments/${row.id}`);
        const model = new Map<number, string>();
        for (const op of operations) {
          if (op.destroy) {
            await call(
              "DELETE",
              `/v1/providers/a/environments/${model.get(op.label) ?? "missing"}`,
            );
            model.delete(op.label);
          } else {
            const { body, result } = await provision(call, String(op.label));
            assert.equal(result.status, model.has(op.label) ? 200 : 201);
            if (model.has(op.label))
              assert.equal(result.body.id, model.get(op.label));
            model.set(op.label, result.body.id);
            const repeat = await call("POST", "/v1/providers/a/environments", {
              ...body,
              size: { ...size, cpus: 2 },
            });
            assert.equal(repeat.body.id, result.body.id);
          }
          const inventory = (await call("GET", "/v1/providers/a/environments"))
            .body;
          assert.deepEqual(
            inventory.map((r: any) => r.id).sort(),
            [...model.values()].sort(),
          );
        }
      },
    ),
    { numRuns: 15 },
  );
});
// Refresh makes a direct provider ready; typed diagnostics redact both current and
// previous delivered secrets and never expose them through hello or errors.
test("credential rotation, redaction and typed errors", async (t) => {
  const { call } = await fixture(
    t,
    configuration({
      fault: {
        kind: "internal",
        reason: "test-secret-one test-secret-two",
        provider_error: "test-secret-one test-secret-two",
      },
    }),
  );
  await ready(call);
  await call("PUT", "/v1/providers/a/credential", { value: "test-secret-two" });
  const result = await call("GET", "/v1/providers/a/environments");
  assert.equal(result.status, 500);
  assert.equal(result.body.kind, "internal");
  assert.ok(!JSON.stringify(result).includes("test-secret"));
  assert.ok(
    !JSON.stringify((await call("GET", "/v1/hello")).body).includes(
      "test-secret",
    ),
  );
  assert.equal(
    (await call("PUT", "/v1/providers/a/credential", { value: "" })).status,
    422,
  );
  assert.equal(
    (await call("GET", "/v1/providers/absent/environments")).body.kind,
    "not_found",
  );
  assert.equal(
    (await call("POST", "/v1/hello")).body.kind,
    "method_not_allowed",
  );
});
async function observe(socketPath: string, since?: string) {
  const req = http.get({
    socketPath,
    path: "/v1/events" + (since ? "?since=" + encodeURIComponent(since) : ""),
    agent: false,
  });
  const res = await new Promise<http.IncomingMessage>((resolve, reject) => {
    req.once("response", resolve);
    req.once("error", reject);
  });
  let text = "";
  const queue: any[] = [];
  let notify: (() => void) | undefined;
  res.on("data", (b) => {
    text += b.toString();
    while (text.includes("\n")) {
      const index = text.indexOf("\n");
      queue.push(JSON.parse(text.slice(0, index)));
      text = text.slice(index + 1);
    }
    notify?.();
  });
  return {
    close: () => {
      req.destroy();
      res.destroy();
    },
    next: async () => {
      const deadline = Date.now() + 3000;
      while (!queue.length) {
        if (Date.now() > deadline) throw Error("event timeout");
        await new Promise<void>((r) => {
          const timer = setTimeout(r, 20);
          notify = () => {
            clearTimeout(timer);
            r();
          };
        });
      }
      return queue.shift();
    },
  };
}
// Observation begins with a snapshot, resumes exclusively from retained cursors,
// and substitutes a snapshot for unknown/previous-process/evicted cursors.
test("observation snapshots, transitions, exclusive replay and gaps", async (t) => {
  const { call, socketPath } = await fixture(t);
  await ready(call);
  await ready(call, "b");
  const stream = await observe(socketPath);
  t.after(async () => stream.close());
  const first = await stream.next();
  assert.equal(first.type, "snapshot");
  const { result } = await provision(call);
  const id = result.body.id;
  let running;
  for (let n = 0; n < 5; n++) {
    const r = await stream.next();
    if (r.type === "event" && r.event.event.kind === "running") {
      running = r.event;
      break;
    }
  }
  assert.equal(running.id, id);
  const token = (
    await call("POST", `/v1/providers/a/environments/${id}/suspend`)
  ).body;
  let stopped;
  for (let n = 0; n < 5; n++) {
    const r = await stream.next();
    if (r.type === "event" && r.event.event.kind === "stopped") {
      stopped = r.event;
      break;
    }
  }
  assert.equal(stopped.id, id);
  const replay = await observe(socketPath, running.cursor);
  t.after(async () => replay.close());
  const record = await replay.next();
  assert.equal(record.type, "event");
  assert.notEqual(record.event.cursor, running.cursor);
  assert.equal(record.event.event.kind, "stopped");
  assert.equal(
    (await call("POST", `/v1/providers/a/environments/${id}/resume`, token))
      .status,
    204,
  );
  const gap = await observe(socketPath, "previous-process:1");
  t.after(async () => gap.close());
  assert.equal((await gap.next()).type, "snapshot");
});
async function upgrade(
  socketPath: string,
  path: string,
  command?: string[],
  chunked = false,
) {
  const data = command ? JSON.stringify({ command }) : "";
  const socket = net.connect(socketPath);
  await new Promise<void>((r) => socket.once("connect", r));
  const framed = chunked
    ? `${Buffer.byteLength(data).toString(16)}\r\n${data}\r\n0\r\n\r\n`
    : data;
  const contentHeaders = chunked
    ? "Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n"
    : `Content-Type: application/json\r\nContent-Length: ${Buffer.byteLength(data)}\r\n`;
  socket.write(
    `${command ? "POST" : "GET"} ${path} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: ${command ? "drydock-stream" : "drydock-relay"}\r\n${command ? contentHeaders : ""}\r\n${framed}`,
  );
  let bytes = Buffer.alloc(0);
  await new Promise<void>((resolve, reject) => {
    const onData = (chunk: Buffer) => {
      bytes = Buffer.concat([bytes, chunk]);
      const end = bytes.indexOf("\r\n\r\n");
      if (end >= 0) {
        socket.off("data", onData);
        try {
          assert.match(bytes.subarray(0, end).toString(), /^HTTP\/1.1 101/);
          const head = bytes.subarray(end + 4);
          socket.pause();
          if (head.length) socket.unshift(head);
          resolve();
        } catch (e) {
          reject(e);
        }
      }
    };
    socket.on("data", onData);
    socket.once("error", reject);
  });
  return socket;
}
// Relay and exec upgrades bridge bytes and propagate EOF without OS subprocesses.
test("relay and exec round trips; optional capability gates", async (t) => {
  const { call, socketPath } = await fixture(t);
  await ready(call);
  const { result } = await provision(call);
  const base = `/v1/providers/a/environments/${result.body.id}`;
  const relay = await upgrade(socketPath, base + "/relay");
  t.after(async () => relay.destroy());
  const echoed = new Promise<Buffer>((r) => relay.once("data", r));
  relay.resume();
  relay.write("relay bytes");
  assert.equal((await echoed).toString(), "relay bytes");
  const exec = await upgrade(socketPath, base + "/exec", ["echo", "hello"]);
  t.after(async () => exec.destroy());
  const output = new Promise<Buffer>((r) => exec.once("data", r));
  exec.resume();
  assert.equal((await output).toString(), "hello\n");
  assert.equal(
    (await call("POST", base + "/export")).body.reference,
    `memory://a/${result.body.id}`,
  );
  assert.equal(
    (await call("GET", "/v1/providers/a/quota")).body.concurrency_in_use,
    1,
  );
  assert.equal(
    (
      await call(
        "GET",
        "/v1/providers/a/usage?start=2026-01-01T00:00:00Z&end=2025-01-01T00:00:00Z",
      )
    ).status,
    422,
  );
  const basic = await fixture(
    t,
    configuration({
      disabled: ["exec", "suspend", "export", "usage", "quota"],
    }),
  );
  await ready(basic.call);
  const created = await provision(basic.call);
  for (const op of ["suspend", "export"]) {
    const error = await basic.call(
      "POST",
      `/v1/providers/a/environments/${created.result.body.id}/${op}`,
    );
    assert.equal(error.status, 422);
    assert.equal(error.body.kind, "refused");
  }
});
// TCP admits only an exact numeric loopback Host, no Origin, and the bearer
// token. Restart rotates the token; Unix directories/socket modes are private.
test("TCP authentication and Unix filesystem/peer policy", async (t) => {
  const { dir, socketPath } = await fixture(t);
  assert.equal((await stat(socketPath)).mode & 0o777, 0o600);
  const peer = net.createServer((socket) => {
    assert.equal(peerUid(socket), process.geteuid!());
    socket.end();
  });
  await new Promise<void>((r) => peer.listen(`${dir}/peer`, r));
  const conn = net.connect(`${dir}/peer`);
  await new Promise<void>((r) => conn.once("end", r));
  peer.close();
  const tokenFile = `${dir}/token`;
  const host = () => new Host(new Map([["reference", reference]]));
  let running = await serve(host(), { tcp: "127.0.0.1:0", tokenFile });
  t.after(async () => running.close());
  const first = await readFile(tokenFile, "utf8");
  const address = running.server.address() as net.AddressInfo;
  const options = {
    hostname: "127.0.0.1",
    port: address.port,
    path: "/v1/hello",
    method: "GET",
  };
  assert.equal((await request(options)).status, 401);
  assert.equal(
    (
      await request({
        ...options,
        headers: { authorization: `Bearer ${first}` },
      })
    ).status,
    200,
  );
  for (const headers of [
    { authorization: `Bearer ${first}`, origin: "http://localhost" },
    { authorization: `Bearer ${first}`, host: "localhost" },
    { authorization: `Bearer ${first}wrong` },
  ])
    assert.equal(
      (await request({ ...options, headers })).status,
      "origin" in headers ? 403 : "host" in headers ? 421 : 401,
    );
  await running.close();
  running = await serve(host(), { tcp: "127.0.0.1:0", tokenFile });
  assert.notEqual(await readFile(tokenFile, "utf8"), first);
  await chmod(dir, 0o755);
  await assert.rejects(serve(host(), { unix: `${dir}/unsafe.sock` }));
  await chmod(dir, 0o700);
  await assert.rejects(
    serve(host(), { tcp: "0.0.0.0:0", tokenFile: `${dir}/invalid` }),
  );
});
// SIGTERM closes observers/upgrades and unlinks the Unix endpoint; no secrets
// or request bodies appear in subprocess diagnostics.
test("binary shutdown closes streams and removes socket", async (t) => {
  const dir = await mkdtemp(`${tmpdir()}/drydock-ts-process-`),
    socketPath = `${dir}/host.sock`;
  const child = spawn(
    process.execPath,
    ["dist/main.js", "--unix", socketPath],
    { cwd: new URL("..", import.meta.url), stdio: ["ignore", "pipe", "pipe"] },
  );
  let logs = "";
  child.stderr.on("data", (b) => (logs += b));
  child.stdout.on("data", (b) => (logs += b));
  t.after(async () => {
    child.kill("SIGKILL");
    await rm(dir, { recursive: true, force: true });
  });
  const deadline = Date.now() + 5000;
  while (true) {
    try {
      await stat(socketPath);
      break;
    } catch {
      if (Date.now() > deadline) throw Error(logs || "startup timeout");
      await new Promise((r) => setTimeout(r, 20));
    }
  }
  assert.equal(
    (
      await request(
        { socketPath, method: "PUT", path: "/v1/config" },
        configuration(),
      )
    ).status,
    204,
  );
  assert.equal(
    (
      await request(
        { socketPath, method: "PUT", path: "/v1/providers/a/credential" },
        { value: "never-log-this-test-credential" },
      )
    ).status,
    204,
  );
  assert.equal(
    (
      await request(
        { socketPath, method: "POST", path: "/v1/providers/a/prepare" },
        {
          image_digest: "never-log-this-test-credential",
          tools_digest: "test",
          size: { ...size, cpus: "1" },
        },
      )
    ).status,
    422,
  );
  const stream = await observe(socketPath);
  await stream.next();
  const exited = new Promise((r) => child.once("exit", r));
  child.kill("SIGTERM");
  await exited;
  stream.close();
  await assert.rejects(stat(socketPath));
  assert.equal(logs, "");
});
// The host preserves stable event baselines across transitional observations,
// emits exactly one stop variant, and never re-emits Gone after disappearance.
test("exact observation sequences retain stable billing baseline", async (t) => {
  const { host, call } = await fixture(t, configuration({ fixture: true }));
  await ready(call);
  await ready(call, "b");
  const { result } = await provision(call);
  const id = result.body.id;
  const wait = async (
    predicate: (records: any[]) => boolean,
    since?: string,
  ) => {
    const until = Date.now() + 2000;
    while (true) {
      const records = await host.observation.records(since);
      if (predicate(records)) return records;
      if (Date.now() > until) throw Error("observation deadline");
      await new Promise((r) => setTimeout(r, 5));
    }
  };
  let snapshot = (
    await wait(
      (r) =>
        r[0]?.type === "snapshot" &&
        r[0].environments.some((e: any) => e.id === id),
    )
  )[0];
  let cursor = snapshot.type === "snapshot" ? snapshot.cursor : "";
  const control = async (state: unknown) => {
    const stream = await host.invoke("a", "exec", [
      id,
      {
        command: ["drydock-fixture", "state", id, JSON.stringify(state)] as any,
      },
    ]);
    stream.resume();
  };
  await control({ state: "stopped", cause: "paused_by_provider" });
  const paused = await wait(
    (r) => r.some((x) => x.type === "event" && x.event.id === id),
    cursor,
  );
  assert.deepEqual(
    paused
      .filter((r: any) => r.type === "event" && r.event.id === id)
      .map((r: any) => r.event.event.kind),
    ["paused"],
  );
  cursor = (paused.at(-1) as any).event.cursor;
  await control({ state: "transitioning", phase: "starting" });
  await new Promise((r) => setTimeout(r, 25));
  assert.deepEqual(await host.observation.records(cursor), []);
  await control({ state: "running" });
  const resumed = await wait((r) => r.length > 0, cursor);
  assert.deepEqual(
    resumed.map((r: any) => r.event.event.kind),
    ["resumed", "running"],
  );
  cursor = (resumed.at(-1) as any).event.cursor;
  await control({ state: "gone", cause: { kind: "evicted_by_provider" } });
  const gone = await wait((r) => r.length > 0, cursor);
  assert.deepEqual(
    gone.map((r: any) => r.event.event.kind),
    ["gone"],
  );
  cursor = (gone.at(-1) as any).event.cursor;
  const stream = await host.invoke("a", "exec", [
    id,
    { command: ["drydock-fixture", "forget", id] as any },
  ]);
  stream.resume();
  await new Promise((r) => setTimeout(r, 30));
  assert.deepEqual(await host.observation.records(cursor), []);
});
// A push observer starts once after commit. Refresh changes the credential view,
// while snapshot list failures withhold only that provider's inventory.
test("push lifetime, credential generations and partial snapshots", async (t) => {
  let starts = 0,
    current: any,
    emit: any;
  let release: (() => void) | undefined;
  const module = {
    version: "test",
    async configure(config: any) {
      const p = await reference.configure(config, new AbortController().signal);
      p.observation = { mode: "push" };
      p.run = async (sink, credentials, signal) => {
        starts++;
        current = credentials;
        emit = sink;
        await new Promise<void>((resolve) => {
          release = resolve;
          signal.addEventListener("abort", () => resolve(), { once: true });
        });
      };
      return p;
    },
  };
  const host = new Host(new Map([["reference", module]]));
  t.after(() => host.shutdown());
  await host.configure(configuration());
  assert.equal(starts, 2);
  host.refresh("a", "first");
  host.refresh("a", "second");
  assert.equal(starts, 2);
  assert.equal(current().generation, 0); // last callback belongs to b
  host.refresh("b", "third");
  assert.equal(current().generation, 1);
  const records = await host.observation.records();
  assert.equal(records[0].type, "snapshot");
  assert.equal((records[0] as any).unavailable_providers, undefined);
  release?.();
  assert.equal(typeof emit, "function");
});
// Retention is bounded host-wide. An evicted cursor gets a fresh authoritative
// snapshot, while retained cursors replay exclusively without a provider list.
test("event history eviction and retained exclusive replay", async (t) => {
  let sink: any,
    lists = 0;
  const module = {
    version: "test",
    async configure(config: any) {
      const p = await reference.configure(config, new AbortController().signal);
      p.observation = { mode: "push" };
      const list = p.list.bind(p);
      p.list = async (c) => {
        lists++;
        return list(c);
      };
      p.run = async (s) => {
        sink = s;
      };
      return p;
    },
  };
  const host = new Host(new Map([["reference", module]]));
  t.after(() => host.shutdown());
  const config = configuration();
  config.providers = config.providers.slice(0, 1);
  await host.configure(config);
  host.refresh("a", "test");
  const first = await host.observation.records();
  const initial = (first[0] as any).cursor;
  const row = {
    environment: {
      id: "row",
      label: null,
      provider: "a",
      state: { state: "running" },
      granted_size: size,
      egress: "advisory",
      platform: { os: "linux", architecture: "amd64" },
    },
  };
  sink(row, { kind: "created" });
  const one = await host.observation.records(initial);
  const oldest = (one[0] as any).event.cursor;
  for (let n = 0; n < 1025; n++)
    sink(row, { kind: "running", granted_size: size });
  const gap = await host.observation.records(oldest);
  assert.equal(gap[0].type, "snapshot");
  const count = lists;
  const latest = (gap[0] as any).cursor;
  sink(row, { kind: "stopped", cause: "suspended_by_request" });
  const replay = await host.observation.records(latest);
  assert.equal(replay.length, 1);
  assert.equal(replay[0].type, "event");
  assert.equal(lists, count);
});
// A single-request list budget grants polling only every two windows, leaving
// a whole window for foreground operations instead of starving callers.
test("single-slot rate budgets reserve foreground capacity", async (t) => {
  const { call } = await fixture(
    t,
    configuration({
      rate_limits: [{ operation: "list", requests: 1, period_seconds: 1 }],
    }),
  );
  await ready(call);
  await ready(call, "b");
  await new Promise((r) => setTimeout(r, 1100));
  assert.equal((await call("GET", "/v1/providers/a/environments")).status, 200);
  const second = await call("GET", "/v1/providers/a/environments");
  assert.equal(second.status, 429);
  assert.equal(second.body.kind, "rate_limited");
  assert.ok(Number(second.headers["retry-after"]) >= 1);
});
// Unix admission compares the kernel peer UID with the supervisor-selected UID,
// before protocol handling, and rejects a mismatch with a bare 403.
test("Unix rejects a peer outside the allowed UID", async (t) => {
  const dir = await mkdtemp(`${tmpdir()}/drydock-ts-uid-`),
    socketPath = `${dir}/host.sock`;
  const running = await serve(
    new Host(new Map([["reference", reference]])),
    { unix: socketPath },
    process.geteuid!() + 1,
  );
  t.after(async () => {
    await running.close();
    await rm(dir, { recursive: true, force: true });
  });
  const response = await request({
    socketPath,
    method: "GET",
    path: "/v1/hello",
  });
  assert.equal(response.status, 403);
  assert.equal(response.body, null);
});
// Multiple windows for one operation must retain history for the longest window,
// regardless of declaration order, and record each accepted call exactly once.
test("overlapping rate windows retain long-window history", async (t) => {
  const host = new Host(new Map([["reference", reference]]));
  t.after(() => host.shutdown());
  const limits = [
    { operation: "list", requests: 3, period_seconds: 3600 },
    { operation: "list", requests: 1, period_seconds: 1 },
  ];
  const config = configuration({
    fixture: true,
    fixture_push: true,
    rate_limits: limits,
  });
  config.providers = config.providers.slice(0, 1);
  await host.configure(config);
  host.refresh("a", "test");
  let now = 10000;
  t.mock.method(Date, "now", () => now);
  for (let n = 0; n < 3; n++) {
    await host.invoke("a", "list", []);
    now += 1001;
  }
  await assert.rejects(
    host.invoke("a", "list", []),
    (error: any) => error.detail.kind === "rate_limited",
  );
});
// TCP authenticates case-insensitive bearer schemes, refuses duplicate credentials
// or authorities, and closes its listener if token publication fails.
test("TCP singleton headers and startup rollback", async (t) => {
  const dir = await mkdtemp(`${tmpdir()}/drydock-ts-auth-`),
    tokenFile = `${dir}/token`;
  const create = () => new Host(new Map([["reference", reference]]));
  const running = await serve(create(), { tcp: "127.0.0.1:0", tokenFile });
  t.after(async () => {
    await running.close();
    await rm(dir, { recursive: true, force: true });
  });
  const address = running.server.address() as net.AddressInfo,
    authority = `127.0.0.1:${address.port}`,
    token = await readFile(tokenFile, "utf8");
  assert.equal(
    (
      await request({
        hostname: "127.0.0.1",
        port: address.port,
        path: "/v1/hello",
        headers: { authorization: `bEaReR ${token}` },
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await request({
        hostname: "127.0.0.1",
        port: address.port,
        path: "/v1/hello",
        headers: {
          authorization: `Bearer ${token}`,
          origin: `http://${authority}`,
        },
      })
    ).status,
    200,
  );
  for (const duplicate of ["Host", "Authorization"]) {
    const raw = net.connect(address.port, "127.0.0.1");
    const response = new Promise<string>((r) => {
      let text = "";
      raw.on("data", (b) => (text += b));
      raw.on("end", () => r(text));
    });
    raw.write(
      `GET /v1/hello HTTP/1.1\r\nHost: ${authority}\r\nAuthorization: Bearer ${token}\r\n${duplicate}: ${duplicate === "Host" ? authority : `Bearer ${token}`}\r\nConnection: close\r\n\r\n`,
    );
    assert.match(await response, /^HTTP\/1.1 (401|421|400)/);
  }
  const portProbe = net.createServer();
  await new Promise<void>((r) => portProbe.listen(0, "127.0.0.1", r));
  const port = (portProbe.address() as net.AddressInfo).port;
  await new Promise<void>((r) => portProbe.close(() => r()));
  await assert.rejects(
    serve(create(), { tcp: `127.0.0.1:${port}`, tokenFile: dir }),
  );
  const rebound = net.createServer();
  await new Promise<void>((r, reject) => {
    rebound.once("error", reject);
    rebound.listen(port, "127.0.0.1", r);
  });
  await new Promise<void>((r) => rebound.close(() => r()));
  assert.equal(await readFile(tokenFile, "utf8"), token);
});
// A crashed process leaves a stale inode. Restart safely removes that socket,
// while refusing live endpoints, regular files and symlinks.
test("Unix restart recovers stale sockets and protects live paths", async (t) => {
  const dir = await mkdtemp(`${tmpdir()}/drydock-ts-stale-`),
    socketPath = `${dir}/host.sock`;
  const child = spawn(
    process.execPath,
    ["dist/main.js", "--unix", socketPath],
    { cwd: new URL("..", import.meta.url), stdio: "ignore" },
  );
  t.after(async () => {
    child.kill("SIGKILL");
    await rm(dir, { recursive: true, force: true });
  });
  const deadline = Date.now() + 5000;
  while (true) {
    try {
      await stat(socketPath);
      break;
    } catch {
      if (Date.now() > deadline) throw Error("startup timeout");
      await new Promise((r) => setTimeout(r, 10));
    }
  }
  const create = () => new Host(new Map([["reference", reference]]));
  await assert.rejects(serve(create(), { unix: socketPath }));
  const exited = new Promise((r) => child.once("exit", r));
  child.kill("SIGKILL");
  await exited;
  assert.ok((await stat(socketPath)).isSocket());
  const running = await serve(create(), { unix: socketPath });
  assert.equal((await request({ socketPath, path: "/v1/hello" })).status, 200);
  await running.close();
  const { writeFile, symlink } = await import("node:fs/promises");
  await writeFile(socketPath, "preserve");
  await assert.rejects(serve(create(), { unix: socketPath }));
  assert.equal(await readFile(socketPath, "utf8"), "preserve");
  await rm(socketPath);
  await symlink(`${dir}/elsewhere`, socketPath);
  await assert.rejects(serve(create(), { unix: socketPath }));
});
// Refresh during an in-flight poll must retain a wakeup. A stale rejection cannot
// change new-generation readiness or postpone a fresh snapshot to the long interval.
test("credential refresh wakes a poll after stale rejection", async (t) => {
  const { ProtocolFailure } = await import("../dist/provider.js");
  let rejectOld: (e: unknown) => void = () => {},
    started: (() => void) | undefined;
  const firstStarted = new Promise<void>((r) => (started = r));
  let calls = 0;
  const module = {
    version: "test",
    async configure(config: any) {
      const p = await reference.configure(config, new AbortController().signal);
      p.observation = { mode: "poll", intervalMs: 100000 };
      p.list = async (c) => {
        calls++;
        if (calls === 1) {
          started?.();
          await new Promise((_, reject) => (rejectOld = reject));
        }
        assert.equal(c.credentials.value, "new");
        return [];
      };
      return p;
    },
  };
  const host = new Host(new Map([["reference", module]]));
  t.after(() => host.shutdown());
  const config = configuration();
  config.providers = config.providers.slice(0, 1);
  await host.configure(config);
  host.refresh("a", "old");
  await firstStarted;
  host.refresh("a", "new");
  rejectOld(
    new ProtocolFailure({ kind: "credential_rejected", reason: "stale" }),
  );
  const deadline = Date.now() + 1000;
  while (calls < 2) {
    if (Date.now() > deadline) throw Error("refresh wakeup lost");
    await new Promise((r) => setTimeout(r, 5));
  }
  assert.equal(host.hello().providers[0].readiness.status, "ready");
  const snapshot = (await host.observation.records())[0];
  assert.equal(snapshot.type, "snapshot");
  assert.equal((snapshot as any).unavailable_providers, undefined);
});
// Chunked POST upgrade bodies are decoded before raw stream bytes, just like
// content-length framing. Shutdown closes incomplete body readers and active relays.
test("chunked exec upgrade and shutdown of incomplete bodies", async (t) => {
  const { call, socketPath, host } = await fixture(t);
  await ready(call);
  const { result } = await provision(call);
  const base = `/v1/providers/a/environments/${result.body.id}`;
  const stream = await upgrade(
    socketPath,
    base + "/exec",
    ["echo", "chunked"],
    true,
  );
  const output = new Promise<Buffer>((r) => stream.once("data", r));
  stream.resume();
  assert.equal((await output).toString(), "chunked\n");
  stream.destroy();
  const incomplete = net.connect(socketPath);
  await new Promise<void>((r) => incomplete.once("connect", r));
  incomplete.write(
    `POST ${base}/exec HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: drydock-stream\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{`,
  );
  incomplete.destroy();
  await host.shutdown();
});
// Shutdown cancels an uncommitted factory and an initial snapshot waiting for a
// blocked first poll. Neither can hold the process alive or publish partial state.
test("shutdown cancels configuration and cold observation", async (t) => {
  let entered: () => void = () => {};
  const entering = new Promise<void>((r) => (entered = r));
  const module = {
    version: "test",
    async configure() {
      entered();
      return await new Promise<any>(() => {});
    },
  };
  const host = new Host(new Map([["reference", module]]));
  const configuring = host.configure(configuration());
  await entering;
  await host.shutdown();
  await assert.rejects(
    configuring,
    (e: any) => e.detail.kind === "unavailable",
  );
  assert.equal(host.hello().providers.length, 0);
  const blocked = {
    version: "test",
    async configure(config: any) {
      const p = await reference.configure(config, new AbortController().signal);
      p.list = async () => await new Promise(() => {});
      return p;
    },
  };
  const cold = new Host(new Map([["reference", blocked]]));
  const config = configuration();
  config.providers = config.providers.slice(0, 1);
  await cold.configure(config);
  cold.refresh("a", "test");
  const snapshot = cold.observation.records();
  await cold.shutdown();
  await assert.rejects(snapshot, (e: any) => e.detail.kind === "unavailable");
});

function credentialForms(secret: string) {
  const json = JSON.stringify(secret).slice(1, -1),
    percent = encodeURIComponent(secret).replace(
      /[!'()*]/g,
      (ch) => "%" + ch.charCodeAt(0).toString(16).toUpperCase(),
    ),
    base64 = Buffer.from(secret).toString("base64");
  return [
    ...new Set([
      secret,
      json,
      ...[false, true].map((upper) =>
        json.replace(
          /[^\x00-\x7f]/g,
          (ch) =>
            "\\u" +
            (upper
              ? ch.charCodeAt(0).toString(16).toUpperCase()
              : ch.charCodeAt(0).toString(16)
            ).padStart(4, "0"),
        ),
      ),
      percent,
      percent.replace(/%[0-9A-F]{2}/g, (x) => x.toLowerCase()),
      percent.replace(/%20/g, "+"),
      base64,
      base64.replace(/=+$/, ""),
      base64.replace(/\+/g, "-").replace(/\//g, "_"),
      base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
    ]),
  ];
}
async function diagnosticFixture(t: {
  after: (fn: () => Promise<void>) => void;
}) {
  let detail = "",
    readiness = false,
    delay = false,
    finish: (() => void) | undefined,
    entered: (() => void) | undefined;
  const { ProtocolFailure } = await import("../dist/provider.js");
  const module = {
    version: "test",
    async configure(config: any, signal: AbortSignal) {
      const p = await reference.configure(config, signal);
      p.observation = { mode: "push" };
      p.readiness = () =>
        readiness ? { status: "unknown", reason: detail } : { status: "ready" };
      p.list = async () => {
        if (delay) {
          entered?.();
          await new Promise<void>((r) => (finish = r));
        }
        throw new ProtocolFailure({
          kind: "internal",
          reason: detail,
          provider_error: detail,
        });
      };
      return p;
    },
  };
  const dir = await mkdtemp(`${tmpdir()}/drydock-ts-diagnostic-`),
    socketPath = `${dir}/host.sock`,
    host = new Host(new Map([["reference", module]])),
    running = await serve(host, { unix: socketPath });
  t.after(async () => {
    await running.close();
    await rm(dir, { recursive: true, force: true });
  });
  const call = (method: string, path: string, body?: unknown) =>
    request({ socketPath, method, path }, body);
  assert.equal((await call("PUT", "/v1/config", configuration())).status, 204);
  return {
    host,
    call,
    setDetail: (value: string) => (detail = value),
    setReadiness: (value: boolean) => (readiness = value),
    startDelayed: () => {
      delay = true;
      return new Promise<void>((r) => (entered = r));
    },
    finishDelayed: () => {
      delay = false;
      finish?.();
    },
  };
}
// Typed HTTP errors and hello readiness must redact literal and common encoded
// forms of both current and recently retired credentials across instances.
test("diagnostics redact encoded old and current credential echoes over HTTP", async (t) => {
  const f = await diagnosticFixture(t),
    old = 'old é😀"\\\n /+=!#%',
    current = 'new 雪😀"\\\t /+=!#%',
    peer = "peer-secret-credential";
  for (const [name, value] of [
    ["a", old],
    ["b", peer],
    ["a", current],
  ])
    assert.equal(
      (await f.call("PUT", `/v1/providers/${name}/credential`, { value }))
        .status,
      204,
    );
  for (const form of [
    ...credentialForms(old),
    ...credentialForms(current),
    ...credentialForms(peer),
  ]) {
    f.setDetail("diagnostic " + form + " end");
    const response = await f.call("GET", "/v1/providers/a/environments");
    assert.equal(response.status, 500);
    for (const field of ["reason", "provider_error"])
      assert.ok(
        !response.body[field].includes(form),
        "encoded credential escaped error redaction",
      );
    f.setReadiness(true);
    for (const p of (await f.call("GET", "/v1/hello")).body.providers)
      assert.ok(
        !p.readiness.reason.includes(form),
        "encoded credential escaped readiness redaction",
      );
    f.setReadiness(false);
  }
});
// Retire old credentials after a bounded window; an in-flight older generation
// must remain protected when it eventually returns a diagnostic.
test("diagnostics bound retired credentials and protect delayed generations", async (t) => {
  const f = await diagnosticFixture(t),
    old = "generation-000-token";
  await f.call("PUT", "/v1/providers/a/credential", { value: old });
  const entered = f.startDelayed(),
    delayed = f.call("GET", "/v1/providers/a/environments");
  await entered;
  for (let n = 1; n <= 100; n++)
    await f.call("PUT", "/v1/providers/a/credential", {
      value: `generation-${String(n).padStart(3, "0")}-token`,
    });
  f.setDetail(credentialForms(old).join(" | "));
  f.finishDelayed();
  const response = await delayed;
  assert.equal(response.status, 500);
  for (const form of credentialForms(old))
    assert.ok(!response.body.provider_error.includes(form));
  f.setDetail(old + " generation-099-token generation-100-token");
  const later = await f.call("GET", "/v1/providers/a/environments");
  assert.ok(
    later.body.provider_error.includes(old),
    "retired generation should no longer be retained",
  );
  assert.ok(!later.body.provider_error.includes("generation-099-token"));
  assert.ok(!later.body.provider_error.includes("generation-100-token"));
});
// Mask before a Unicode-safe 16 KiB truncation, including credentials spanning
// the truncation point, in both typed errors and readiness diagnostics.
test("diagnostics bound UTF-8 text after redacting boundary secrets", async (t) => {
  const f = await diagnosticFixture(t),
    secret = "CROSSING-BOUNDARY-CREDENTIAL-1234567890";
  await f.call("PUT", "/v1/providers/a/credential", { value: secret });
  f.setDetail("🙂".repeat(4090) + secret + "界".repeat(1000));
  const error = (await f.call("GET", "/v1/providers/a/environments")).body;
  for (const key of ["reason", "provider_error"]) {
    assert.ok(Buffer.byteLength(error[key]) <= 16384);
    assert.ok(!error[key].includes("CROSSING"));
    assert.ok(!error[key].includes("\uFFFD"));
    assert.ok(error[key].endsWith("...<truncated>"));
  }
  f.setReadiness(true);
  for (const p of (await f.call("GET", "/v1/hello")).body.providers) {
    assert.ok(Buffer.byteLength(p.readiness.reason) <= 16384);
    assert.ok(!p.readiness.reason.includes("\uFFFD"));
  }
});
// Disconnecting during relay/exec setup cancels the provider context and disposes
// a late Duplex even if its provider ignores cancellation.
test("upgrade disconnect cancels setup and disposes late streams", async (t) => {
  const { PassThrough } = await import("node:stream");
  for (const operation of ["relay", "exec"]) {
    let signal: AbortSignal | undefined,
      release: ((stream: any) => void) | undefined,
      entered: () => void = () => {};
    const started = new Promise<void>((r) => (entered = r));
    const module = {
      version: "test",
      async configure(config: any, abort: AbortSignal) {
        const p = await reference.configure(config, abort),
          setup = async (_id: string, context: any) => {
            signal = context.signal;
            entered();
            return await new Promise<any>((r) => (release = r));
          };
        p.relay = setup;
        p.exec = async (id, _request, context) => setup(id, context);
        return p;
      },
    };
    const dir = await mkdtemp(`${tmpdir()}/drydock-ts-upgrade-cancel-`),
      socketPath = `${dir}/host.sock`,
      host = new Host(new Map([["reference", module]])),
      running = await serve(host, { unix: socketPath });
    t.after(async () => {
      await running.close();
      await rm(dir, { recursive: true, force: true });
    });
    await host.configure(configuration());
    host.refresh("a", "test");
    const socket = net.connect(socketPath);
    await new Promise<void>((r) => socket.once("connect", r));
    const body =
      operation === "exec" ? JSON.stringify({ command: ["cat"] }) : "";
    socket.write(
      `${operation === "exec" ? "POST" : "GET"} /v1/providers/a/environments/example/${operation} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: ${operation === "exec" ? "drydock-stream" : "drydock-relay"}\r\n${body ? `Content-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n` : ""}\r\n${body}`,
    );
    await started;
    socket.destroy();
    const deadline = Date.now() + 1000;
    while (!signal?.aborted && Date.now() < deadline)
      await new Promise((r) => setTimeout(r, 5));
    const stream = new PassThrough();
    release!(stream);
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(
      signal?.aborted,
      true,
      "disconnected upgrade must cancel setup",
    );
    assert.equal(stream.destroyed, true, "late stream must be disposed");
  }
});
// Longest matching credentials win; inserted redaction markers and protocol
// discriminants must survive a second HTTP serialization boundary unchanged.
test("short credentials cannot corrupt redaction markers or error kinds", async (t) => {
  const f = await diagnosticFixture(t);
  await f.call("PUT", "/v1/providers/a/credential", { value: "ABCDE" });
  await f.call("PUT", "/v1/providers/a/credential", { value: "E" });
  f.setDetail("ABCDE E");
  const error = (await f.call("GET", "/v1/providers/a/environments")).body;
  assert.equal(error.kind, "internal");
  assert.equal(error.provider_error, "<REDACTED> <REDACTED>");
  f.setReadiness(true);
  assert.equal(
    (await f.call("GET", "/v1/hello")).body.providers[0].readiness.reason,
    "<REDACTED> <REDACTED>",
  );
});

// Exclusive resume can be idle: the HTTP headers must arrive before any new
// event, rather than leaving a reconnect blocked waiting for a body record.
test("idle retained-cursor observation flushes headers immediately", async (t) => {
  const { host, call, socketPath } = await fixture(t);
  await ready(call);
  const snapshot = (await host.observation.records())[0];
  assert.equal(snapshot.type, "snapshot");
  const req = http.get({
    socketPath,
    path: "/v1/events?since=" + encodeURIComponent((snapshot as any).cursor),
    agent: false,
  });
  try {
    let timer: NodeJS.Timeout | undefined;
    const response = await Promise.race([
      new Promise<http.IncomingMessage>((resolve, reject) => {
        req.once("response", resolve);
        req.once("error", reject);
      }),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(Error("idle resume headers timed out")),
          1000,
        );
      }),
    ]).finally(() => clearTimeout(timer));
    assert.equal(response.statusCode, 200);
    assert.equal(response.headers["content-type"], "application/x-ndjson");
    response.destroy();
  } finally {
    req.destroy();
  }
});
// Framework validation must neither coerce wire values nor insert defaults or
// strip fields in opaque module settings. Provider interfaces see unchanged JSON.
test("strict framework validation preserves opaque settings and typed refusals", async (t) => {
  let received: unknown;
  const module = {
    version: "test",
    async configure(config: any, signal: AbortSignal) {
      received = structuredClone(config.settings);
      return reference.configure({ ...config, settings: {} }, signal);
    },
  };
  const dir = await mkdtemp(`${tmpdir()}/drydock-ts-strict-`),
    socketPath = `${dir}/host.sock`,
    host = new Host(new Map([["reference", module]])),
    running = await serve(host, { unix: socketPath });
  t.after(async () => {
    await running.close();
    await rm(dir, { recursive: true, force: true });
  });
  const settings = JSON.parse(
    '{"nested":{"count":"1","constructor":{"keep":true},"__proto__":{"kept":"opaque"}},"extra":false}',
  );
  const config = configuration(settings);
  config.providers = config.providers.slice(0, 1);
  const call = (method: string, path: string, body?: unknown) =>
    request({ socketPath, method, path }, body);
  assert.equal((await call("PUT", "/v1/config", config)).status, 204);
  assert.deepEqual(received, settings);
  await ready(call);
  for (const bad of [
    { ...size, cpus: "2" },
    { ...size, memory_bytes: "1024" },
  ]) {
    const response = await call("POST", "/v1/providers/a/prepare", {
      size: bad,
      image_digest: "image",
      tools_digest: "tools",
    });
    assert.equal(response.status, 422);
    assert.equal(response.body.kind, "refused");
  }
  const { body } = await provision(call);
  const response = await call("POST", "/v1/providers/a/environments", {
    ...body,
    label: "missing-size",
    size: { cpus: 1, disk_bytes: 0 },
  });
  assert.equal(response.status, 422);
});
// Fastify supplies matching/decoding; preserve Rust's typed 404/405/422 contract,
// including HEAD (no automatic GET alias), bad escapes and long opaque names.
test("router keeps methods, encoded provider names and path errors typed", async (t) => {
  const name = "space / percent% " + "x".repeat(180),
    config = configuration();
  config.providers = config.providers.slice(0, 1);
  config.providers[0].name = name;
  const { call } = await fixture(t, config),
    base = "/v1/providers/" + encodeURIComponent(name);
  assert.equal(
    (await call("PUT", base + "/credential", { value: "test-secret-one" }))
      .status,
    204,
  );
  const prepared = await call("POST", base + "/prepare", {
    size,
    image_digest: "image",
    tools_digest: "tools",
  });
  assert.equal(prepared.status, 200);
  for (const [method, path, status, kind] of [
    ["POST", "/v1/hello", 405, "method_not_allowed"],
    ["GET", base + "/prepare", 405, "method_not_allowed"],
    ["GET", "/v1/absent", 404, "not_found"],
    ["GET", "/v1/providers/%ZZ/environments", 422, "refused"],
  ] as const) {
    const response = await call(method, path);
    assert.equal(response.status, status);
    assert.equal(response.body.kind, kind);
  }
  assert.equal((await call("HEAD", "/v1/hello")).status, 405);
  assert.equal((await call("GET", "/v1/../v1/hello")).status, 200);
});
// The reference settings schema is module-owned, shares canonical protocol refs,
// rejects unknown/ill-typed settings and makes no coercion/default mutations.
test("reference settings schema rejects wrong types and declaration mismatches", async (t) => {
  const { call } = await fixture(t);
  for (const settings of [
    { extra: true },
    { fixture: "true" },
    { platforms: {} },
    { rate_limits: {} },
    { poll_interval_ms: 0 },
    { poll_interval_ms: "10" },
    { disabled: ["not-an-operation"] },
  ]) {
    const config = configuration();
    config.providers.push({
      ...config.providers[0],
      name: "invalid",
      settings,
    });
    const response = await call("PUT", "/v1/config", config);
    assert.equal(response.status, 422);
    assert.equal(response.body.kind, "refused");
    assert.equal((await call("GET", "/v1/hello")).body.providers.length, 2);
  }
});
// Framework parser errors must retain typed Refused responses, including the
// exact existing 2 MiB boundary; JSON-compatible media types remain accepted.
test("HTTP parser keeps typed JSON errors and the 2 MiB boundary", async (t) => {
  const { socketPath } = await fixture(t);
  const config = JSON.stringify(configuration());
  const raw = (body: string, type?: string) =>
    new Promise<{ status: number; body: any }>((resolve, reject) => {
      const req = http.request(
        {
          socketPath,
          method: "PUT",
          path: "/v1/config",
          agent: false,
          headers: {
            ...(type ? { "content-type": type } : {}),
            "content-length": Buffer.byteLength(body),
          },
        },
        (res) => {
          let text = "";
          res.setEncoding("utf8");
          res.on("data", (chunk) => (text += chunk));
          res.on("end", () =>
            resolve({
              status: res.statusCode!,
              body: text ? JSON.parse(text) : null,
            }),
          );
        },
      );
      req.once("error", reject);
      req.end(body);
    });
  for (const [body, media] of [
    ["{", "application/json"],
    [config, "text/plain"],
    [config, undefined],
    [
      config + " ".repeat(2 * 1024 * 1024 - config.length + 1),
      "application/json",
    ],
  ]) {
    const response = await raw(body!, media);
    assert.equal(response.status, 422);
    assert.equal(response.body.kind, "refused");
  }
  assert.equal(
    (
      await raw(
        config + " ".repeat(2 * 1024 * 1024 - config.length),
        "application/json",
      )
    ).status,
    204,
  );
  assert.equal(
    (await raw(config, "application/vnd.drydock+json; charset=utf-8")).status,
    204,
  );
});

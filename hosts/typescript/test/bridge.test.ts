import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { PassThrough } from "node:stream";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { serve } from "../dist/server.js";
import { ProtocolFailure } from "../dist/provider.js";
import type {
  Provider,
  ProviderModule,
  Context,
  Types,
} from "../src/provider.ts";
const size = { cpus: 1, memory_bytes: 1024, disk_bytes: 0 };
const credentials = (value = "test-only-one") => ({
  mode: { mode: "direct", credential_reference: "test" },
  value,
});
const observed: Types["ObservedEnvironment"] = {
  environment: {
    id: "opaque / percent%",
    provider: "a",
    label: "test",
    state: { state: "running" },
    granted_size: size,
    egress: "advisory",
  },
  timestamp: "2026-01-01T00:00:00Z",
  egress_measured: true,
  egress_policy: "raw-policy",
};
const capabilities = {
  material_modes: [],
  checkout_strategies: [],
  workspace_root: "/workspace",
  suspend_resume: false,
  suspend_preserves_memory: false,
  export: false,
  usage: false,
  quota: false,
  fallback_runner: false,
  egress: { routes: ["none"], enforcement: "advisory" },
  bootstrap: "bake",
  agent: false,
  platforms: [{ os: "linux", architecture: "amd64" }],
  image_routes: [{ route: "remote_build" }],
} as Types["Capabilities"];
// In-memory provider fake at the module interface; it records facts/calls rather
// than implementing inventory, billing, readiness recovery or replay policy.
function provider(): Provider {
  return {
    capabilities,
    observation: "Push",
    rateLimits: [],
    readiness: () => ({ status: "ready" }),
    prepare: async (r) => ({
      ...r,
      id: "prepared",
      provider: "a",
      platform: capabilities.platforms[0],
    }),
    provision: async (r) =>
      r.label === "existing" ? { Existing: observed } : { Created: observed },
    list: async () => [observed],
    inspect: async () => observed,
    inspectAfterLifecycle: async () => ({
      ...observed,
      timestamp: "2026-01-02T00:00:00Z",
    }),
    destroy: async () => {},
    reach: async () => "Relay",
    relay: async () => new PassThrough(),
    async *subscribe(ctx) {
      yield { Observed: observed };
      yield {
        Removed: { id: observed.environment.id, timestamp: observed.timestamp },
      };
      await new Promise<void>((resolve) => {
        if (ctx.signal.aborted) resolve();
        else
          ctx.signal.addEventListener("abort", () => resolve(), { once: true });
      });
    },
  };
}
function request(
  socketPath: string,
  path: string,
  body?: unknown,
  method = "POST",
  wire?: { payload: string; headers?: Record<string, string> },
) {
  return new Promise<{ status: number; body: any }>((resolve, reject) => {
    const req = http.request(
      {
        socketPath,
        path,
        method,
        agent: false,
        headers: {
          ...(body === undefined ? {} : { "content-type": "application/json" }),
          ...wire?.headers,
        },
      },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (s) => (text += s));
        res.on("end", () =>
          resolve({
            status: res.statusCode!,
            body: text ? JSON.parse(text) : null,
          }),
        );
      },
    );
    req.on("error", reject);
    req.end(
      wire?.payload ?? (body === undefined ? undefined : JSON.stringify(body)),
    );
  });
}
async function fixture(t: any, p = provider(), replacement = provider()) {
  const dir = await mkdtemp(`${tmpdir()}/drydock-thin-`),
    socketPath = `${dir}/host.sock`;
  let configurations = 0,
    settings: unknown;
  const name = "module /% " + "x".repeat(150);
  const module: ProviderModule = {
    name,
    version: "test",
    smallestSize: size,
    async configure(c) {
      configurations++;
      settings = c.settings;
      return c.settings.replacement === true ? replacement : p;
    },
  };
  const host = await serve([module], socketPath);
  t.after(async () => {
    await host.close();
    await rm(dir, { recursive: true, force: true });
  });
  const config = {
    name: "a",
    module: "alias",
    settings: JSON.parse(
      '{"constructor":{"opaque":true},"__proto__":{"opaque":1},"custom":[1,"x"]}',
    ),
    credential: credentials().mode,
  };
  const configure = () =>
    request(
      socketPath,
      `/private/modules/${encodeURIComponent(name)}/configure`,
      config,
    );
  const response = await configure();
  assert.equal(response.status, 200);
  const handle: string = response.body.instance;
  const call = (operation: string, argument: unknown = null, value?: string) =>
    request(
      socketPath,
      `/private/providers/${encodeURIComponent(handle)}/${operation}`,
      { credentials: credentials(value), argument },
    );
  return {
    socketPath,
    name,
    host,
    p,
    call,
    configure,
    handle,
    config,
    settings: () => settings,
    configurations: () => configurations,
  };
}
// One real-socket scenario specifies discovery/configuration/handle routing and
// exact trait result serialization, with immutable independent per-call secrets.
test("UDS trait routing preserves payloads, credentials and handles", async (t) => {
  const p = provider(),
    captured: Context[] = [];
  p.list = async (c) => {
    captured.push(c);
    return [observed];
  };
  p.inspect = async (id) => {
    if (id === "quota")
      throw new ProtocolFailure({
        kind: "quota_exhausted",
        reason: "typed vendor result",
      });
    if (id === "unexpected") throw Error("test-only-one must not escape");
    assert.equal(id, observed.environment.id);
    return observed;
  };
  const replacement = provider();
  replacement.inspect = async () => ({
    ...observed,
    timestamp: "2026-02-01T00:00:00Z",
  });
  const f = await fixture(t, p, replacement);
  for (const [path, method, status, kind] of [
    ["/v1/hello?opaque=%3F", "POST", 405, "method_not_allowed"],
    ["/unknown", "GET", 404, "not_found"],
  ] as const) {
    const response = await request(f.socketPath, path, undefined, method);
    assert.equal(response.status, status);
    assert.equal(response.body.kind, kind);
  }
  assert.equal(
    (await request(f.socketPath, "/v1/hello", undefined, "HEAD")).status,
    405,
  );
  for (const [payload, media] of [
    ['{"secret":"test-only-one"', "application/json"],
    ["x".repeat(2 * 1024 * 1024 + 1), "application/json"],
    ["test-only-one", "application/octet-stream"],
  ]) {
    const response = await request(
      f.socketPath,
      `/private/providers/${f.handle}/inspect`,
      undefined,
      "POST",
      { payload, headers: { "content-type": media } },
    );
    assert.equal(response.status, 422);
    assert.equal(response.body.kind, "refused");
    assert.ok(!JSON.stringify(response.body).includes("test-only-one"));
  }
  const wrongUpgrade = await request(
    f.socketPath,
    `/private/providers/${f.handle}/relay`,
    undefined,
    "GET",
    {
      payload: "",
      headers: { connection: "Upgrade", upgrade: "drydock-relay" },
    },
  );
  assert.equal(wrongUpgrade.status, 405);
  assert.equal(wrongUpgrade.body.kind, "method_not_allowed");
  assert.equal((await stat(f.socketPath)).mode & 0o777, 0o600);
  const hello = await request(f.socketPath, "/v1/hello", undefined, "GET");
  assert.equal(
    hello.body.incarnation,
    (await request(f.socketPath, "/v1/hello", undefined, "GET")).body
      .incarnation,
  );
  assert.equal(hello.body.modules[0].name, "alias");
  assert.deepEqual(f.settings(), f.config.settings);
  assert.deepEqual((await f.call("facts")).body.ports, {
    exec: false,
    suspend_resume: false,
    export: false,
    usage: false,
    quota: false,
  });
  const repeat = await f.configure();
  assert.notEqual(repeat.body.instance, f.handle);
  assert.equal(f.configurations(), 1);
  const results = await Promise.all([
    f.call("list", null, "test-only-one"),
    f.call("list", null, "test-only-two"),
  ]);
  assert.deepEqual(
    results.map((r) => r.body),
    [[observed], [observed]],
  );
  assert.deepEqual(captured.map((c) => c.credentials.value).sort(), [
    "test-only-one",
    "test-only-two",
  ]);
  assert.ok(
    captured.every(
      (c) =>
        Object.isFrozen(c.credentials) && Object.isFrozen(c.credentials.mode),
    ),
  );
  assert.deepEqual(
    (await f.call("inspect", observed.environment.id)).body,
    observed,
  );
  assert.equal(
    (await f.call("inspect-after-lifecycle", observed.environment.id)).body
      .timestamp,
    "2026-01-02T00:00:00Z",
  );
  const preparation = {
    size,
    image_digest: "image",
    tools_digest: "tools",
    platform: capabilities.platforms[0],
    route: "remote_build",
  };
  const prepared = await f.call("prepare", preparation);
  assert.equal(prepared.status, 200);
  for (const [label, variant] of [
    ["new", "Created"],
    ["existing", "Existing"],
  ]) {
    const result = await f.call("provision", {
      label,
      prepared: prepared.body,
      size,
    });
    assert.deepEqual(result.body, { [variant]: observed });
  }
  assert.equal((await f.call("destroy", observed.environment.id)).body, null);
  assert.equal((await f.call("reach", observed.environment.id)).body, "Relay");
  assert.equal((await f.call("inspect", "quota")).status, 402);
  const unexpected = await f.call("inspect", "unexpected");
  assert.equal(unexpected.status, 500);
  assert.ok(!JSON.stringify(unexpected).includes("test-only"));
  assert.equal((await f.call("inspect", 123)).status, 422);
  assert.equal(
    (await f.call("prepare", { ...preparation, size: { ...size, cpus: "1" } }))
      .status,
    422,
  );
  assert.equal(
    (await f.call("exec", ["id", { command: ["cat"] }])).status,
    404,
  );
  await request(
    f.socketPath,
    `/private/providers/${f.handle}`,
    undefined,
    "DELETE",
  );
  assert.equal((await f.call("list")).status, 404);
  assert.equal(
    (
      await request(
        f.socketPath,
        `/private/providers/${repeat.body.instance}/list`,
        { credentials: credentials(), argument: null },
      )
    ).status,
    200,
  );
  // Replacing a binding cannot invalidate the old handles still owned by Daemon.
  const changed = await request(
    f.socketPath,
    `/private/modules/${encodeURIComponent(f.name)}/configure`,
    { ...f.config, settings: { replacement: true } },
  );
  assert.equal(changed.status, 200);
  const old = await request(
    f.socketPath,
    `/private/providers/${repeat.body.instance}/inspect`,
    { credentials: credentials(), argument: observed.environment.id },
  );
  const current = await request(
    f.socketPath,
    `/private/providers/${changed.body.instance}/inspect`,
    { credentials: credentials(), argument: observed.environment.id },
  );
  assert.deepEqual(old.body, observed);
  assert.equal(current.body.timestamp, "2026-02-01T00:00:00Z");
  await request(
    f.socketPath,
    `/private/modules/${encodeURIComponent(f.name)}/configure`,
    { ...f.config, name: "b" },
  );
  replacement.readiness = () => {
    throw Error("test-only-two must not escape");
  };
  const degraded = await request(f.socketPath, "/v1/hello", undefined, "GET");
  assert.equal(degraded.status, 200);
  assert.equal(
    degraded.body.providers.find((p: any) => p.provider === "a").readiness
      .status,
    "unknown",
  );
  assert.equal(
    degraded.body.providers.find((p: any) => p.provider === "b").readiness
      .status,
    "ready",
  );
  assert.ok(!JSON.stringify(degraded).includes("test-only"));
});
async function upgraded(socketPath: string, path: string, chunked = false) {
  const socket = net.connect(socketPath);
  const body = JSON.stringify({
    credentials: credentials(),
    argument: observed.environment.id,
  });
  const framed = chunked
    ? `${Buffer.byteLength(body).toString(16)}\r\n${body}\r\n0\r\n\r\n`
    : body;
  socket.write(
    `POST ${path} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: drydock-relay\r\nContent-Type: application/json\r\n${chunked ? "Transfer-Encoding: chunked" : `Content-Length: ${Buffer.byteLength(body)}`}\r\n\r\n${framed}`,
  );
  await new Promise<void>((resolve, reject) => {
    let text = "";
    const data = (b: Buffer) => {
      text += b;
      if (text.includes("\r\n\r\n")) {
        socket.off("data", data);
        assert.match(text, /^HTTP\/1.1 101/);
        resolve();
      }
    };
    socket.on("data", data);
    socket.once("error", reject);
  });
  return socket;
}
// Raw duplex bytes and both HTTP body framings remain independent of NDJSON.
// Subscription updates/removals pass through without deriving public events.
test("raw relay and subscription forwarding have disconnect cleanup", async (t) => {
  const f = await fixture(t);
  for (const chunked of [false, true]) {
    const socket = await upgraded(
      f.socketPath,
      `/private/providers/${f.handle}/relay`,
      chunked,
    );
    const echo = new Promise<Buffer>((resolve) => socket.once("data", resolve));
    socket.write("raw\0bytes");
    assert.equal((await echo).toString(), "raw\0bytes");
    socket.destroy();
  }
  // Invalid hand-rolled chunk framing must return a typed refusal, not hang.
  for (const frame of [
    "f".repeat(8193),
    "0\r\n" + ("x:" + "x".repeat(70) + "\r\n").repeat(1000),
  ]) {
    const socket = net.connect(f.socketPath);
    const response = new Promise<string>((resolve, reject) => {
      let text = "";
      socket.on("data", (b) => (text += b));
      socket.once("end", () => resolve(text));
      socket.once("error", reject);
    });
    socket.write(
      `POST /private/providers/${f.handle}/relay HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: drydock-relay\r\nTransfer-Encoding: chunked\r\n\r\n${frame}`,
    );
    const text = await response;
    assert.match(text, /^HTTP\/1.1 422/);
    assert.equal(JSON.parse(text.split("\r\n\r\n")[1]).kind, "refused");
    socket.destroy();
  }
  const req = http.request({
    socketPath: f.socketPath,
    path: `/private/providers/${f.handle}/subscribe`,
    method: "POST",
    agent: false,
    headers: { "content-type": "application/json" },
  });
  const response = new Promise<http.IncomingMessage>((r) =>
    req.once("response", r),
  );
  req.end(JSON.stringify({ credentials: credentials(), argument: null }));
  const res = await response;
  assert.equal(res.headers["content-type"], "application/x-ndjson");
  const lines: any[] = [];
  let text = "";
  await new Promise<void>((resolve) => {
    res.on("data", (b) => {
      text += b;
      let i;
      while ((i = text.indexOf("\n")) >= 0) {
        lines.push(JSON.parse(text.slice(0, i)));
        text = text.slice(i + 1);
      }
      if (lines.length === 2) resolve();
    });
  });
  assert.deepEqual(lines, [
    { Update: { Observed: observed } },
    {
      Update: {
        Removed: { id: observed.environment.id, timestamp: observed.timestamp },
      },
    },
  ]);
  res.destroy();
  req.destroy();
});
// Client disconnect must abort an ordinary call and a pending relay setup.
// A provider ignoring abort may finish late, but its returned duplex is disposed.
test("disconnect aborts pending provider calls and disposes late relay", async (t) => {
  const p = provider();
  let entered!: () => void,
    aborted!: () => void,
    release!: (value: PassThrough) => void;
  let started = new Promise<void>((r) => (entered = r)),
    cancelled = new Promise<void>((r) => (aborted = r));
  p.inspect = async (_id, ctx) => {
    entered();
    await new Promise<void>((resolve) =>
      ctx.signal.addEventListener(
        "abort",
        () => {
          aborted();
          resolve();
        },
        { once: true },
      ),
    );
    return observed;
  };
  const f = await fixture(t, p);
  const req = http.request({
    socketPath: f.socketPath,
    path: `/private/providers/${f.handle}/inspect`,
    method: "POST",
    headers: { "content-type": "application/json" },
  });
  req.on("error", () => {});
  req.end(JSON.stringify({ credentials: credentials(), argument: "id" }));
  await started;
  req.destroy();
  await cancelled;
  started = new Promise<void>((r) => (entered = r));
  cancelled = new Promise<void>((r) => (aborted = r));
  p.relay = async (_id, ctx) => {
    ctx.signal.addEventListener("abort", () => aborted(), { once: true });
    entered();
    return new Promise<PassThrough>((r) => (release = r));
  };
  const socket = net.connect(f.socketPath),
    body = JSON.stringify({ credentials: credentials(), argument: "id" });
  socket.write(
    `POST /private/providers/${f.handle}/relay HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: drydock-relay\r\nContent-Length: ${body.length}\r\n\r\n${body}`,
  );
  await started;
  socket.destroy();
  await cancelled;
  const stream = new PassThrough();
  release(stream);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.ok(stream.destroyed);
});

// The real executable diagnoses malformed supervisor-selected exports without
// echoing imported exceptions or starting a listener.
test("CLI rejects invalid provider module exports before listen", async (t) => {
  const dir = await mkdtemp(`${tmpdir()}/drydock-loader-`);
  t.after(() => rm(dir, { recursive: true, force: true }));
  const module = `${dir}/invalid.mjs`;
  await writeFile(module, "export default undefined;");
  await assert.rejects(
    promisify(execFile)(
      process.execPath,
      [
        new URL("../dist/main.js", import.meta.url).pathname,
        "--unix",
        `${dir}/host.sock`,
      ],
      { env: { PATH: process.env.PATH, DRYDOCK_TYPESCRIPT_MODULES: module } },
    ),
    (error: any) =>
      error.code === 1 &&
      error.stdout === "" &&
      /invalid default ProviderModule export/.test(error.stderr),
  );
});

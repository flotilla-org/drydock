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
const environment: Types["Environment"] = {
  id: "opaque /%",
  provider: "a",
  label: "test",
  state: { state: "running" },
  granted_size: size,
  egress: "advisory",
  egress_measured: true,
  egress_policy: "raw-policy",
  timestamp: "2026-01-01T00:00:00Z",
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
// Fake SDK boundary: only trait calls, no main-server policy.
function provider(): Provider {
  return {
    capabilities,
    observation: { mode: "poll", interval_ms: 1000 },
    rateLimits: [],
    readiness: () => ({ status: "ready" }),
    prepare: async (r) => ({
      id: "prepared",
      provider: "a",
      image_digest: r.image_digest,
      tools_digest: r.tools_digest,
      platform: capabilities.platforms[0],
    }),
    provision: async (r) => ({ created: r.label !== "existing", environment }),
    list: async () => [environment],
    inspect: async () => environment,
    destroy: async () => {},
    reach: async () => ({ kind: "relay", path: "/opaque" }),
    relay: async () => new PassThrough(),
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
async function fixture(t: any, p = provider()) {
  const dir = await mkdtemp(`${tmpdir()}/drydock-thin-`),
    socketPath = `${dir}/host.sock`;
  let configurations = 0;
  const configured: { name: string; settings: unknown }[] = [];
  const name = "module /% " + "x".repeat(150);
  const module: ProviderModule = {
    name,
    version: "test",
    smallestSize: size,
    async configure(name, config) {
      configurations++;
      configured.push({ name, settings: config.settings });
      return p;
    },
  };
  const host = await serve([module], socketPath);
  t.after(async () => {
    await host.close();
    await rm(dir, { recursive: true, force: true });
  });
  const config = {
    providers: {
      a: {
        module: name,
        settings: JSON.parse(
          '{"constructor":{"opaque":true},"__proto__":{"opaque":1},"custom":[1,"x"]}',
        ),
      },
    },
  };
  assert.equal(
    (await request(socketPath, "/v1/config", config, "PUT")).status,
    204,
  );
  return {
    socketPath,
    host,
    name,
    config,
    configured,
    configurations: () => configurations,
  };
}
// Shared resource routes pass exact payloads and request-only credentials. A
// configuration transaction keeps unchanged instances and applies RFC7396 atomically.
test("shared UDS API delegates lifecycle and atomic configuration", async (t) => {
  const p = provider(),
    captured: Context[] = [];
  p.list = async (ctx) => {
    captured.push(ctx);
    return [environment];
  };
  p.inspect = async (id) => {
    if (id === "typed")
      throw new ProtocolFailure({
        kind: "quota_exhausted",
        reason: "typed result",
      });
    if (id === "unexpected") throw Error("secret-must-not-escape");
    assert.equal(id, environment.id);
    return environment;
  };
  const f = await fixture(t, p),
    url = "/v1/providers/a/environments",
    id = encodeURIComponent(environment.id);
  assert.equal((await stat(f.socketPath)).mode & 0o777, 0o600);
  const hello = await request(f.socketPath, "/v1/hello", undefined, "GET");
  assert.equal(hello.body.protocol_version, "9");
  assert.equal(hello.body.loadable_modules[0].name, f.name);
  assert.equal(
    (await request(f.socketPath, "/v1/hello", undefined, "HEAD")).status,
    200,
  );
  const declarations = await request(
    f.socketPath,
    "/v1/providers",
    undefined,
    "GET",
  );
  assert.equal(declarations.body[0].provider, "a");
  assert.equal(declarations.body[0].ports.exec, false);
  assert.deepEqual(
    (await request(f.socketPath, "/v1/providers/a", undefined, "GET")).body,
    declarations.body[0],
  );
  for (const credential of ["test-only-first", "test-only-second"]) {
    const result = await request(f.socketPath, url, undefined, "GET", {
      payload: "",
      headers: { "Drydock-Credential": credential },
    });
    assert.deepEqual(result.body, [environment]);
    assert.equal(captured.at(-1)!.credential, credential);
    assert.ok(!JSON.stringify(result).includes(credential));
  }
  await request(f.socketPath, url, undefined, "GET");
  assert.equal(captured.at(-1)!.credential, undefined);
  const prepare = { image_digest: "image", tools_digest: "tools", size };
  const prepared = await request(
    f.socketPath,
    "/v1/providers/a/prepare",
    prepare,
  );
  assert.equal(prepared.status, 200);
  for (const [label, status] of [
    ["new", 201],
    ["existing", 200],
  ] as const) {
    const result = await request(f.socketPath, url, {
      label,
      prepared: prepared.body,
      size,
    });
    assert.equal(result.status, status);
    assert.deepEqual(result.body, environment);
  }
  assert.deepEqual(
    (await request(f.socketPath, `${url}/${id}`, undefined, "GET")).body,
    environment,
  );
  assert.deepEqual((await request(f.socketPath, `${url}/${id}/reach`)).body, {
    kind: "relay",
    path: "/opaque",
  });
  assert.equal(
    (await request(f.socketPath, `${url}/${id}`, undefined, "DELETE")).status,
    204,
  );
  for (const [path, method, status, kind] of [
    ["/v1/hello?query=1", "POST", 405, "method_not_allowed"],
    ["/unknown", "GET", 404, "not_found"],
    ["/v1/events", "GET", 404, "not_found"],
    ["/v1/providers/a/credential", "PUT", 404, "not_found"],
    [`${url}/typed`, "GET", 402, "quota_exhausted"],
    [`${url}/unexpected`, "GET", 500, "internal"],
    [`${url}/x/exec`, "POST", 404, "not_found"],
  ] as const) {
    const result = await request(f.socketPath, path, undefined, method);
    assert.equal(result.status, status, path);
    assert.equal(result.body.kind, kind);
    assert.ok(!JSON.stringify(result).includes("secret-must-not-escape"));
  }
  for (const body of [
    { ...prepare, size: { ...size, cpus: "1" } },
    { ...prepare, image_digest: "" },
  ])
    assert.equal(
      (await request(f.socketPath, "/v1/providers/a/prepare", body)).status,
      422,
    );
  for (const [payload, type] of [
    ["{", "application/json"],
    ["{}", "text/plain"],
    [" ".repeat(2 * 1024 * 1024 + 1), "application/json"],
  ]) {
    const result = await request(
      f.socketPath,
      "/v1/providers/a/prepare",
      undefined,
      "POST",
      { payload, headers: { "content-type": type } },
    );
    assert.equal(result.status, 422);
  }
  await request(f.socketPath, "/v1/config", f.config, "PUT");
  assert.equal(f.configurations(), 1);
  const patch = JSON.parse(
    '{"providers":{"a":{"settings":{"constructor":{"added":2},"__proto__":{"opaque":null,"new":3},"custom":[2],"fresh":{"__proto__":{"data":true}}}}}}',
  );
  assert.equal(
    (
      await request(f.socketPath, "/v1/config", patch, "PATCH", {
        payload: JSON.stringify(patch),
        headers: { "content-type": "application/merge-patch+json" },
      })
    ).status,
    204,
  );
  assert.deepEqual(
    f.configured.at(-1)!.settings,
    JSON.parse(
      '{"constructor":{"opaque":true,"added":2},"__proto__":{"new":3},"custom":[2],"fresh":{"__proto__":{"data":true}}}',
    ),
  );
  assert.equal(({} as any).new, undefined);
  assert.equal(
    (
      await request(
        f.socketPath,
        "/v1/config",
        { providers: { bad: { module: "missing" } } },
        "PATCH",
      )
    ).status,
    422,
  );
  assert.equal(
    (await request(f.socketPath, "/v1/providers", undefined, "GET")).body
      .length,
    1,
  );
  assert.equal(
    (
      await request(
        f.socketPath,
        "/v1/config",
        { providers: { a: { credential: { env: "TEST_ONLY" } } } },
        "PATCH",
      )
    ).status,
    422,
  );
  assert.equal(
    (
      await request(
        f.socketPath,
        "/v1/config",
        { providers: { a: null } },
        "PATCH",
      )
    ).status,
    204,
  );
  assert.deepEqual(
    (await request(f.socketPath, "/v1/providers", undefined, "GET")).body,
    [],
  );
});
// A real raw upgrade retains bytes after the HTTP headers and closes both ends.
test("GET relay forwards raw bytes and host stop closes upgrades", async (t) => {
  const f = await fixture(t);
  const socket = net.connect(f.socketPath);
  t.after(() => socket.destroy());
  socket.write(
    "GET /v1/providers/a/environments/opaque/relay HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: drydock-relay\r\n\r\nround-trip",
  );
  let received = "";
  await new Promise<void>((resolve, reject) => {
    socket.on("error", reject);
    socket.on("data", (chunk) => {
      received += chunk;
      if (received.endsWith("round-trip")) resolve();
    });
  });
  assert.match(received, /^HTTP\/1.1 101 /);
  const closed = new Promise<void>((resolve) => socket.once("close", resolve));
  await f.host.close();
  await closed;
});
// Client disconnect cancels awaited trait work; a late duplex must be disposed.
test("disconnect aborts inspect and disposes late relay setup", async (t) => {
  const p = provider();
  let inspectStarted!: () => void,
    relayStarted!: () => void,
    release!: (stream: PassThrough) => void;
  const inspectReady = new Promise<void>((r) => (inspectStarted = r)),
    relayReady = new Promise<void>((r) => (relayStarted = r));
  let inspectSignal!: AbortSignal, relaySignal!: AbortSignal;
  p.inspect = async (_id, ctx) => {
    inspectSignal = ctx.signal;
    inspectStarted();
    await new Promise<void>((resolve) =>
      ctx.signal.addEventListener("abort", () => resolve(), { once: true }),
    );
    return environment;
  };
  p.relay = async (_id, ctx) => {
    relaySignal = ctx.signal;
    relayStarted();
    return new Promise((r) => (release = r));
  };
  const f = await fixture(t, p);
  const req = http.request({
    socketPath: f.socketPath,
    path: "/v1/providers/a/environments/x",
    method: "GET",
  });
  req.on("error", () => {});
  req.end();
  await inspectReady;
  req.destroy();
  await new Promise<void>((r) => {
    if (inspectSignal.aborted) r();
    else inspectSignal.addEventListener("abort", () => r(), { once: true });
  });
  const socket = net.connect(f.socketPath);
  socket.on("error", () => {});
  socket.write(
    "GET /v1/providers/a/environments/x/relay HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: drydock-relay\r\n\r\n",
  );
  await relayReady;
  socket.destroy();
  await new Promise<void>((r) => {
    if (relaySignal.aborted) r();
    else relaySignal.addEventListener("abort", () => r(), { once: true });
  });
  const late = new PassThrough(),
    disposed = new Promise<void>((r) => late.once("close", r));
  release(late);
  await disposed;
  assert.equal(late.destroyed, true);
});
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

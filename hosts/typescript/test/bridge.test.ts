import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { serve } from "../dist/server.js";
import { ProtocolFailure } from "../dist/provider.js";
import { compile } from "../dist/validation.js";
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
  };
}
function request(
  socketPath: string,
  path: string,
  body?: unknown,
  method = "POST",
  wire?: { payload: string; headers?: Record<string, string | string[]> },
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
  assert.equal(hello.body.protocol_version, "10");
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
  // Invalid credentials are refused before SDK work; duplicate values follow
  // Rust HeaderMap::get's first-value semantics instead of Node's comma joining.
  for (const credential of ["", "\x80"]) {
    const count = captured.length;
    const result = await request(f.socketPath, url, undefined, "GET", {
      payload: "",
      headers: { "Drydock-Credential": credential },
    });
    assert.equal(result.status, 422);
    assert.equal(result.body.kind, "refused");
    assert.equal(captured.length, count);
  }
  await request(f.socketPath, url, undefined, "GET", {
    payload: "",
    headers: { "Drydock-Credential": ["first-only", "ignored-second"] },
  });
  assert.equal(captured.at(-1)!.credential, "first-only");
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
  assert.equal(
    (
      await request(f.socketPath, "/unknown", undefined, "GET", {
        payload: "",
        headers: { "Drydock-Credential": "" },
      })
    ).status,
    404,
  );
  // Unsigned 64-bit sizes accept values beyond 2^53 but not past their width.
  assert.equal(
    (
      await request(f.socketPath, "/v1/providers/a/prepare", {
        ...prepare,
        size: { ...size, memory_bytes: 2 ** 60 },
      })
    ).status,
    200,
  );
  for (const body of [
    { ...prepare, size: { ...size, cpus: "1" } },
    { ...prepare, size: { ...size, memory_bytes: -1 } },
    { ...prepare, size: { ...size, memory_bytes: 2 ** 64 } },
    { ...prepare, size: { ...size, memory_bytes: 1.5 } },
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
  await request(f.socketPath, "/v1/config", {}, "PATCH");
  assert.equal(f.configurations(), 1, "empty patch keeps unchanged instances");
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
        {
          providers: {
            a: { settings: { uncommitted: true } },
            bad: { module: "missing" },
          },
        },
        "PATCH",
      )
    ).status,
    422,
  );
  const afterFailure = f.configurations();
  await request(f.socketPath, "/v1/config", {}, "PATCH");
  assert.equal(
    f.configurations(),
    afterFailure,
    "failed transaction retains previous configs",
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
// Integer formats bound their Rust width; `minimum: 0` marks unsigned types.
test("integer formats accept signed and unsigned widths", () => {
  // The largest doubles below 2^32 and 2^64 (doubles near 2^64 are 2^11 apart).
  for (const [format, max, below] of [
    ["int32", 2 ** 32, 2 ** 32 - 1],
    ["int64", 2 ** 64, 2 ** 64 - 2 ** 11],
  ] as const) {
    const valid = compile({ type: "integer", format });
    assert.equal(valid(below), true, format);
    assert.equal(valid(-(max / 2)), true, format);
    assert.equal(valid(max), false, format);
    assert.equal(valid(-(max / 2) - 2 ** 12), false, format);
  }
});
// Client disconnect cancels awaited trait work.
test("disconnect aborts inspect", async (t) => {
  const p = provider();
  let started!: () => void;
  const ready = new Promise<void>((r) => (started = r));
  let signal!: AbortSignal;
  p.inspect = async (_id, ctx) => {
    signal = ctx.signal;
    started();
    await new Promise<void>((resolve) =>
      ctx.signal.addEventListener("abort", () => resolve(), { once: true }),
    );
    return environment;
  };
  const f = await fixture(t, p);
  const req = http.request({
    socketPath: f.socketPath,
    path: "/v1/providers/a/environments/x",
    method: "GET",
  });
  req.on("error", () => {});
  req.end();
  await ready;
  req.destroy();
  await new Promise<void>((r) => {
    if (signal.aborted) r();
    else signal.addEventListener("abort", () => r(), { once: true });
  });
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

import http, { type IncomingMessage } from "node:http";
import { type Socket } from "node:net";
import { chmod, stat, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { isDeepStrictEqual } from "node:util";
import Fastify, { type HTTPMethods } from "fastify";
import mergePatch from "tiny-merge-patch";
import {
  absentPorts,
  ProtocolFailure,
  refused,
  type Context,
  type Provider,
  type ProviderModule,
  type Types,
} from "./provider.js";
import { bodySchema, compile, protocolVersion } from "./validation.js";
import { errorResponse } from "./errors.js";
import { bridge } from "./stream.js";
type Instance = { provider: string; id: string };
type Binding = { config: Types["ProviderConfiguration"]; provider: Provider };
// Preserve arbitrary JSON member names through a library implemented with JS
// property assignment. Prefixing is reversible and avoids prototype setters.
function keys(value: unknown, encode: boolean): unknown {
  if (Array.isArray(value)) return value.map((v) => keys(v, encode));
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [
        encode ? "$" + k : k.slice(1),
        keys(v, encode),
      ]),
    );
  return value;
}
export async function serve(modules: ProviderModule[], unix: string) {
  const { version } = JSON.parse(
    await readFile(new URL("../package.json", import.meta.url), "utf8"),
  );
  const directory = await stat(dirname(unix));
  if (!directory.isDirectory() || (directory.mode & 0o777) !== 0o700)
    throw Error("private directory must have mode 0700");
  const validConfiguration = compile(bodySchema("Configuration"));
  const registry = new Map(modules.map((m) => [m.name, m]));
  if (registry.size !== modules.length) throw Error("duplicate module");
  let bindings = new Map<string, Binding>();
  let configuring: Promise<unknown> = Promise.resolve();
  const stopping = new AbortController();
  const sockets = new Set<Socket>();
  const calls = new WeakMap<IncomingMessage, AbortSignal>();
  const upgrades = new WeakMap<
    IncomingMessage,
    { socket: Socket; head: Buffer }
  >();
  const app = Fastify({
    logger: false,
    exposeHeadRoutes: true,
    bodyLimit: 2 * 1024 * 1024,
    schemaErrorFormatter: () =>
      new ProtocolFailure({ kind: "refused", reason: "invalid request" }),
    onProtoPoisoning: "ignore",
    onConstructorPoisoning: "ignore",
    routerOptions: { maxParamLength: 16 * 1024 },
  });
  app.addContentTypeParser(
    "application/merge-patch+json",
    { parseAs: "string" },
    app.getDefaultJsonParser("ignore", "ignore"),
  );
  const methods = new Set<HTTPMethods>();
  app.addHook("onRoute", (route) => {
    for (const method of [route.method].flat()) methods.add(method);
  });
  app.setNotFoundHandler((request, reply) => {
    const known = [...methods].some(
      (method) =>
        app.findRoute({ method, url: request.raw.url!.split("?")[0] }) !== null,
    );
    const result = errorResponse(
      new ProtocolFailure(
        known
          ? { kind: "method_not_allowed", reason: "method not allowed" }
          : { kind: "not_found", reason: "unknown route" },
      ),
    );
    reply.code(result.status).headers(result.headers).send(result.detail);
  });
  app.setValidatorCompiler(({ schema }) => compile(schema as object));
  app.setErrorHandler((error, _request, reply) => {
    const codes = Fastify.errorCodes;
    if (
      error instanceof codes.FST_ERR_CTP_INVALID_JSON_BODY ||
      error instanceof codes.FST_ERR_CTP_BODY_TOO_LARGE ||
      error instanceof codes.FST_ERR_CTP_EMPTY_JSON_BODY ||
      error instanceof codes.FST_ERR_CTP_INVALID_MEDIA_TYPE
    )
      error = new ProtocolFailure({
        kind: "refused",
        reason: "invalid request",
      });
    // Never expose parser text, credential values or unexpected SDK exceptions.
    const result = errorResponse(error);
    reply.code(result.status).headers(result.headers).send(result.detail);
  });
  const binding = (name: string) => {
    const value = bindings.get(name);
    if (!value)
      throw new ProtocolFailure({
        kind: "not_found",
        reason: "unknown provider",
      });
    return value;
  };
  function context(request: IncomingMessage): Context {
    const credential = request.headersDistinct["drydock-credential"]?.[0];
    if (
      credential !== undefined &&
      (typeof credential !== "string" || !/^[\x20-\x7e]+$/.test(credential))
    )
      refused("Drydock-Credential must be nonempty visible ASCII");
    return { credential, signal: calls.get(request)! };
  }
  async function declaration(
    name: string,
    ctx: Context,
  ): Promise<Types["ProviderDeclaration"]> {
    const { config, provider } = binding(name);
    return {
      provider: name,
      module: config.module,
      ports: { ...absentPorts },
      capabilities: provider.capabilities,
      observation: provider.observation,
      rate_limits: provider.rateLimits,
      readiness: await Promise.resolve()
        .then(() => provider.readiness(ctx))
        .catch(() => ({
          status: "unknown" as const,
          reason: "provider readiness failed",
        })),
    };
  }
  app.addHook("onRequest", async (request, reply) => {
    const abort = new AbortController();
    reply.raw.once("close", () => abort.abort());
    request.raw.once("aborted", () => abort.abort());
    calls.set(request.raw, AbortSignal.any([abort.signal, stopping.signal]));
    if (!request.is404) context(request.raw);
    const raw = upgrades.get(request.raw);
    if (!raw) return;
    if (!(request.routeOptions.config as { relay?: boolean }).relay) {
      if (
        !app.findRoute({
          method: request.method as HTTPMethods,
          url: request.raw.url!.split("?")[0],
        })
      )
        return;
      refused("not a stream route");
    }
    reply.hijack();
    const signal = calls.get(request.raw)!;
    const closed = () => abort.abort();
    raw.socket.once("close", closed);
    raw.socket.once("end", closed);
    raw.socket.once("error", closed);
    try {
      if (
        request.headers.upgrade?.toLowerCase() !== "drydock-relay" ||
        !request.headers.connection
          ?.toLowerCase()
          .split(",")
          .some((part) => part.trim() === "upgrade")
      )
        refused("missing relay upgrade headers");
      const params = request.params as Instance;
      const stream = await binding(params.provider).provider.relay(
        params.id,
        context(request.raw),
      );
      if (signal.aborted || raw.socket.destroyed) {
        stream.destroy();
        return;
      }
      raw.socket.write(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: drydock-relay\r\n\r\n",
      );
      bridge(raw.socket, stream, raw.head);
    } catch (error) {
      if (!raw.socket.destroyed && !signal.aborted) {
        const result = errorResponse(error),
          body = JSON.stringify(result.detail);
        raw.socket.end(
          `HTTP/1.1 ${result.status} Error\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
        );
      }
    } finally {
      // Keep once-only close cancellation for the established stream lifetime;
      // bridge owns half-closes and errors after setup.
      raw.socket.off("end", closed);
      raw.socket.off("error", closed);
    }
  });
  app.server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  app.server.on("upgrade", (request, socket, head) => {
    const response = new http.ServerResponse(request);
    response.assignSocket(socket as Socket);
    socket.on("error", () => socket.destroy());
    response.once("finish", () => socket.destroy());
    upgrades.set(request, { socket: socket as Socket, head });
    app.routing(request, response);
  });
  app.get<{ Reply: Types["Hello"] }>("/v1/hello", async () => ({
    protocol_version: protocolVersion,
    host_version: version,
    loadable_modules: modules.map((m) => ({
      name: m.name,
      version: m.version,
      smallest_size: m.smallestSize,
    })),
  }));
  for (const method of ["PUT", "PATCH"] as const)
    app.route<{ Body: unknown }>({
      method,
      url: "/v1/config",
      ...(method === "PUT"
        ? { schema: { body: bodySchema("Configuration") } }
        : {}),
      async handler(request, reply) {
        const action = configuring.then(async () => {
          const current = {
            providers: Object.fromEntries(
              [...bindings].map(([name, b]) => [name, b.config]),
            ),
          };
          // Validate the merged document, not a partial patch with null deletions.
          const document =
            method === "PUT"
              ? request.body
              : keys(
                  mergePatch(keys(current, true), keys(request.body, true)),
                  false,
                );
          if (!validConfiguration(document)) refused("invalid configuration");
          const next = new Map<string, Binding>();
          const signal = calls.get(request.raw)!;
          for (const [name, entry] of Object.entries(
            (document as Types["Configuration"]).providers ?? {},
          )) {
            signal.throwIfAborted();
            if (entry.credential != null)
              refused("credential is a server-only configuration key");
            const old = bindings.get(name),
              module = registry.get(entry.module);
            if (!module) refused("unknown module");
            const provider =
              old && isDeepStrictEqual(old.config, entry)
                ? old.provider
                : await module.configure(name, structuredClone(entry), signal);
            next.set(name, { config: structuredClone(entry), provider });
          }
          signal.throwIfAborted();
          bindings = next;
        });
        configuring = action.catch(() => {});
        await action;
        return reply.code(204).send();
      },
    });
  app.get("/v1/providers", (r) =>
    Promise.all(
      [...bindings.keys()].map((name) => declaration(name, context(r.raw))),
    ),
  );
  app.get<{ Params: Instance }>("/v1/providers/:provider", (r) =>
    declaration(r.params.provider, context(r.raw)),
  );
  app.post<{ Params: Instance; Body: Types["PrepareRequest"] }>(
    "/v1/providers/:provider/prepare",
    { schema: { body: bodySchema("PrepareRequest") } },
    (r) => binding(r.params.provider).provider.prepare(r.body, context(r.raw)),
  );
  const environments = "/v1/providers/:provider/environments";
  app.get<{ Params: Instance }>(environments, (r) =>
    binding(r.params.provider).provider.list(context(r.raw)),
  );
  app.post<{ Params: Instance; Body: Types["ProvisionRequest"] }>(
    environments,
    { schema: { body: bodySchema("ProvisionRequest") } },
    async (r, reply) => {
      const result = await binding(r.params.provider).provider.provision(
        r.body,
        context(r.raw),
      );
      return reply.code(result.created ? 201 : 200).send(result.environment);
    },
  );
  app.get<{ Params: Instance }>(environments + "/:id", (r) =>
    binding(r.params.provider).provider.inspect(r.params.id, context(r.raw)),
  );
  app.delete<{ Params: Instance }>(environments + "/:id", async (r, reply) => {
    await binding(r.params.provider).provider.destroy(
      r.params.id,
      context(r.raw),
    );
    return reply.code(204).send();
  });
  app.post<{ Params: Instance }>(environments + "/:id/reach", (r) =>
    binding(r.params.provider).provider.reach(r.params.id, context(r.raw)),
  );
  app.get(environments + "/:id/relay", { config: { relay: true } }, () =>
    refused("missing relay upgrade headers"),
  );
  await app.listen({ path: unix });
  // The verified0700 parent controls access during bind-to-chmod.
  await chmod(unix, 0o600);
  return {
    app,
    async close() {
      stopping.abort();
      for (const socket of sockets) socket.destroy();
      await app.close();
      bindings.clear();
    },
  };
}

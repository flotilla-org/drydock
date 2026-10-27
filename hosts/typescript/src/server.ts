import http, { type IncomingMessage } from "node:http";
import { type Socket } from "node:net";
import { Readable } from "node:stream";
import { chmod, stat } from "node:fs/promises";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import Fastify, { type HTTPMethods } from "fastify";
import type { paths } from "./generated/protocol.js";
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
import { bridge, upgradeBody } from "./stream.js";
type Instance =
  paths["/private/providers/{provider}/facts"]["post"]["parameters"]["path"];

export async function serve(modules: ProviderModule[], unix: string) {
  const directory = await stat(dirname(unix));
  if (!directory.isDirectory() || (directory.mode & 0o777) !== 0o700)
    throw Error("private directory must have mode 0700");
  const registry = new Map(modules.map((m) => [m.name, m]));
  if (registry.size !== modules.length) throw Error("duplicate module");
  const handles = new Map<string, Provider>();
  const bindings = new Map<
    string,
    {
      module: string;
      config: Types["ProviderConfiguration"];
      provider: Provider;
    }
  >();
  const loaded = new Map<string, string>();
  let configuring: Promise<unknown> = Promise.resolve();
  const incarnation = randomUUID();
  const stopping = new AbortController();
  const sockets = new Set<Socket>();
  const calls = new WeakMap<IncomingMessage, AbortSignal>();
  const upgrades = new WeakMap<
    IncomingMessage,
    { socket: Socket; head: Buffer }
  >();
  const app = Fastify({
    logger: false,
    exposeHeadRoutes: false,
    bodyLimit: 2 * 1024 * 1024,
    schemaErrorFormatter: () =>
      new ProtocolFailure({ kind: "refused", reason: "invalid request" }),
    onProtoPoisoning: "ignore",
    onConstructorPoisoning: "ignore",
    routerOptions: { maxParamLength: 16 * 1024 },
  });
  const methods = new Set<HTTPMethods>();
  app.addHook("onRoute", (route) => {
    for (const method of [route.method].flat()) methods.add(method);
  });
  app.setNotFoundHandler((request, reply) => {
    const known = [...methods].some(
      (method) => app.findRoute({ method, url: request.raw.url! }) !== null,
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
    // Only framework validation/parser errors become Refused. Never echo parser
    // text, body, credential values or unexpected SDK exceptions into diagnostics.
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
    const result = errorResponse(error);
    reply.code(result.status).headers(result.headers).send(result.detail);
  });
  const instance = (handle: string) => {
    const provider = handles.get(handle);
    if (!provider)
      throw new ProtocolFailure({
        kind: "not_found",
        reason: "unknown provider handle",
      });
    return provider;
  };
  function context(
    request: IncomingMessage,
    credentials: Types["Credentials"],
  ): Context {
    const snapshot = structuredClone(credentials);
    Object.freeze(snapshot.mode);
    return {
      credentials: Object.freeze(snapshot),
      signal: calls.get(request)!,
    };
  }
  async function facts(
    provider: Provider,
    ctx: Context,
  ): Promise<Types["Facts"]> {
    return {
      ports: { ...absentPorts },
      capabilities: provider.capabilities,
      observation: provider.observation,
      rate_limits: provider.rateLimits,
      readiness: await provider.readiness(ctx),
    };
  }
  app.addHook("onRequest", async (request, reply) => {
    const abort = new AbortController();
    reply.raw.once("close", () => abort.abort());
    request.raw.once("aborted", () => abort.abort());
    calls.set(request.raw, AbortSignal.any([abort.signal, stopping.signal]));
    const raw = upgrades.get(request.raw);
    if (!raw) return;
    if (!(request.routeOptions.config as { relay?: boolean }).relay) {
      if (
        !app.findRoute({
          method: request.method as HTTPMethods,
          url: request.raw.url!,
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
      const { body, remainder } = await upgradeBody(
        request.raw,
        raw.socket,
        raw.head,
      );
      let call: Types["Call_IdArgument"];
      try {
        call = JSON.parse(body.toString());
      } catch {
        refused("invalid stream request");
      }
      if (!compile(bodySchema("Call_IdArgument"))(call))
        refused("invalid stream request");
      const stream = await instance(
        (request.params as Instance).provider,
      ).relay(call.argument, context(request.raw, call.credentials));
      if (signal.aborted || raw.socket.destroyed) {
        stream.destroy();
        return;
      }
      raw.socket.write(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: drydock-relay\r\n\r\n",
      );
      bridge(raw.socket, stream, remainder);
    } catch (error) {
      if (!raw.socket.destroyed && !signal.aborted) {
        const result = errorResponse(error),
          body = JSON.stringify(result.detail);
        raw.socket.end(
          `HTTP/1.1 ${result.status} Error\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
        );
      }
    } finally {
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

  app.get<{ Reply: Types["BridgeHello"] }>("/v1/hello", async () => ({
    incarnation,
    protocol_version: protocolVersion,
    host_version: "0.1.0",
    loadable_modules: modules.map((m) => ({
      name: m.name,
      version: m.version,
      smallest_size: m.smallestSize,
    })),
    modules: [...loaded].map(([name, version]) => ({ name, version })),
    providers: await Promise.all(
      [...bindings.values()].map(async ({ config, provider }) => ({
        provider: config.name,
        module: config.module,
        capabilities: provider.capabilities,
        rate_limits: provider.rateLimits,
        readiness: await provider.readiness({
          credentials: { mode: config.credential },
          signal: stopping.signal,
        }),
      })),
    ),
  }));
  app.post<{
    Params: paths["/private/modules/{module}/configure"]["post"]["parameters"]["path"];
    Body: Types["ProviderConfiguration"];
    Reply: Types["ConfiguredProvider"];
  }>(
    "/private/modules/:module/configure",
    { schema: { body: bodySchema("ProviderConfiguration") } },
    async (request) => {
      const action = configuring.then(async () => {
        const module = registry.get(request.params.module);
        if (!module) refused("unknown module");
        const config = request.body,
          signal = calls.get(request.raw)!;
        signal.throwIfAborted();
        const old = bindings.get(config.name);
        const provider =
          old?.module === module.name && isDeepStrictEqual(old.config, config)
            ? old.provider
            : await module.configure(structuredClone(config), signal);
        const declared = await facts(
          provider,
          context(request.raw, { mode: config.credential }),
        );
        signal.throwIfAborted();
        const handle = randomUUID();
        bindings.set(config.name, {
          module: module.name,
          config: structuredClone(config),
          provider,
        });
        handles.set(handle, provider);
        loaded.set(config.module, module.version);
        return { instance: handle, facts: declared };
      });
      configuring = action.catch(() => {});
      return action;
    },
  );
  app.delete<{ Params: Instance }>(
    "/private/providers/:provider",
    (request, reply) => {
      handles.delete(request.params.provider);
      return reply.code(204).send();
    },
  );
  app.post<{
    Params: Instance;
    Body: Types["Call_NoArgument"];
    Reply: Types["Facts"];
  }>(
    "/private/providers/:provider/facts",
    { schema: { body: bodySchema("Call_NoArgument") } },
    (r) =>
      facts(instance(r.params.provider), context(r.raw, r.body.credentials)),
  );
  app.post<{
    Params: Instance;
    Body: Types["Call_PrepareRequest"];
    Reply: Types["Prepared"];
  }>(
    "/private/providers/:provider/prepare",
    { schema: { body: bodySchema("Call_PrepareRequest") } },
    (r) =>
      instance(r.params.provider).prepare(
        r.body.argument,
        context(r.raw, r.body.credentials),
      ),
  );
  app.post<{
    Params: Instance;
    Body: Types["Call_ProvisionRequest"];
    Reply: Types["Provisioned"];
  }>(
    "/private/providers/:provider/provision",
    { schema: { body: bodySchema("Call_ProvisionRequest") } },
    (r) =>
      instance(r.params.provider).provision(
        r.body.argument,
        context(r.raw, r.body.credentials),
      ),
  );
  app.post<{
    Params: Instance;
    Body: Types["Call_NoArgument"];
    Reply: Types["ObservedEnvironment"][];
  }>(
    "/private/providers/:provider/list",
    { schema: { body: bodySchema("Call_NoArgument") } },
    (r) => instance(r.params.provider).list(context(r.raw, r.body.credentials)),
  );
  app.post<{
    Params: Instance;
    Body: Types["Call_IdArgument"];
    Reply: Types["ObservedEnvironment"];
  }>(
    "/private/providers/:provider/inspect",
    { schema: { body: bodySchema("Call_IdArgument") } },
    (r) =>
      instance(r.params.provider).inspect(
        r.body.argument,
        context(r.raw, r.body.credentials),
      ),
  );
  app.post<{
    Params: Instance;
    Body: Types["Call_IdArgument"];
    Reply: Types["ObservedEnvironment"];
  }>(
    "/private/providers/:provider/inspect-after-lifecycle",
    { schema: { body: bodySchema("Call_IdArgument") } },
    (r) =>
      instance(r.params.provider).inspectAfterLifecycle(
        r.body.argument,
        context(r.raw, r.body.credentials),
      ),
  );
  app.post<{ Params: Instance; Body: Types["Call_IdArgument"]; Reply: null }>(
    "/private/providers/:provider/destroy",
    { schema: { body: bodySchema("Call_IdArgument") } },
    async (r) => {
      await instance(r.params.provider).destroy(
        r.body.argument,
        context(r.raw, r.body.credentials),
      );
      return null;
    },
  );
  app.post<{
    Params: Instance;
    Body: Types["Call_IdArgument"];
    Reply: Types["Connection"];
  }>(
    "/private/providers/:provider/reach",
    { schema: { body: bodySchema("Call_IdArgument") } },
    async (r, reply) =>
      reply
        .type("application/json")
        .serializer(JSON.stringify)
        .send(
          await instance(r.params.provider).reach(
            r.body.argument,
            context(r.raw, r.body.credentials),
          ),
        ),
  );
  app.post(
    "/private/providers/:provider/relay",
    { config: { relay: true } },
    () => refused("missing relay upgrade headers"),
  );
  app.post<{ Params: Instance; Body: Types["Call_NoArgument"] }>(
    "/private/providers/:provider/subscribe",
    { schema: { body: bodySchema("Call_NoArgument") } },
    (r, reply) => {
      const provider = instance(r.params.provider),
        ctx = context(r.raw, r.body.credentials);
      const stream = Readable.from(
        (async function* () {
          try {
            for await (const update of provider.subscribe(ctx)) {
              if (ctx.signal.aborted) return;
              const record: Types["SubscriptionRecord"] = { Update: update };
              yield JSON.stringify(record) + "\n";
            }
          } catch (error) {
            if (!ctx.signal.aborted)
              yield JSON.stringify({
                Failed: errorResponse(error).detail,
              } satisfies Types["SubscriptionRecord"]) + "\n";
          }
        })(),
      );
      reply.type("application/x-ndjson").send(stream);
      reply.raw.flushHeaders();
      return reply;
    },
  );
  await app.listen({ path: unix });
  await chmod(unix, 0o600);
  return {
    app,
    async close() {
      stopping.abort();
      for (const socket of sockets) socket.destroy();
      await app.close();
      handles.clear();
      bindings.clear();
    },
  };
}

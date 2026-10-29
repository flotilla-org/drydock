import { createServer, STATUS_CODES, type IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import { chmod, stat, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { isDeepStrictEqual } from "node:util";
import Fastify, {
  type FastifyError,
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
  type HTTPMethods,
} from "fastify";
import {
  ports,
  ProtocolFailure,
  refused,
  type Context,
  type Provider,
  type ProviderModule,
  type Types,
} from "./provider.js";
import { bodySchema, compile, protocolVersion } from "./validation.js";
import { errorResponse } from "./errors.js";
type Instance = { provider: string; id: string };
type Binding = { config: Types["ProviderConfiguration"]; provider: Provider };
type Configuration = Types["Configuration"];

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * RFC 7396 JSON merge patch. `Object.fromEntries` defines own data properties,
 * so opaque member names such as `__proto__` and `constructor` stay plain keys.
 */
export function mergePatch(target: unknown, patch: unknown): unknown {
  if (!isObject(patch)) return patch;
  const base = isObject(target) ? target : {};
  const entries: [string, unknown][] = [];
  for (const [key, value] of Object.entries(base)) {
    if (!Object.hasOwn(patch, key)) entries.push([key, value]);
    else if (patch[key] !== null)
      entries.push([key, mergePatch(value, patch[key])]);
  }
  for (const [key, value] of Object.entries(patch)) {
    if (Object.hasOwn(base, key) || value === null) continue;
    entries.push([key, mergePatch(undefined, value)]);
  }
  return Object.fromEntries(entries);
}

function sendError(reply: FastifyReply, error: unknown) {
  const result = errorResponse(error);
  return reply.code(result.status).headers(result.headers).send(result.detail);
}

function isUnreadableBody(error: FastifyError) {
  const codes = Fastify.errorCodes;
  return (
    error instanceof codes.FST_ERR_CTP_INVALID_JSON_BODY ||
    error instanceof codes.FST_ERR_CTP_BODY_TOO_LARGE ||
    error instanceof codes.FST_ERR_CTP_EMPTY_JSON_BODY ||
    error instanceof codes.FST_ERR_CTP_INVALID_MEDIA_TYPE
  );
}

function invalidRequest() {
  return new ProtocolFailure({ kind: "refused", reason: "invalid request" });
}

// Rust's HeaderMap::get selects the first value; Node's joined view would not.
function credential(request: IncomingMessage): string | undefined {
  const value = request.headersDistinct["drydock-credential"]?.[0];
  if (value === undefined) return undefined;
  if (!/^[\x20-\x7e]+$/.test(value))
    refused("Drydock-Credential must be nonempty visible ASCII");
  return value;
}

async function requirePrivateDirectory(unix: string) {
  const directory = await stat(dirname(unix));
  if (!directory.isDirectory() || (directory.mode & 0o777) !== 0o700)
    throw Error("private directory must have mode 0700");
}

async function hostVersion(): Promise<string> {
  const manifest = new URL("../package.json", import.meta.url);
  return JSON.parse(await readFile(manifest, "utf8")).version;
}

function moduleRegistry(modules: ProviderModule[]) {
  const registry = new Map(modules.map((module) => [module.name, module]));
  if (registry.size !== modules.length) throw Error("duplicate module");
  return registry;
}

async function readiness(
  provider: Provider,
  context: Context,
): Promise<Types["Readiness"]> {
  try {
    return await provider.readiness(context);
  } catch {
    return { status: "unknown", reason: "provider readiness failed" };
  }
}

const relayProtocol = "drydock-relay";
const relayRoute = /^\/v1\/providers\/([^/]+)\/environments\/([^/]+)\/relay$/;

/**
 * The relay a request upgrades to: a GET of a relay route carrying both upgrade
 * headers. Any other request, a relay without them included, stays in Fastify.
 */
function relayTarget(request: IncomingMessage): Instance | undefined {
  const match = relayRoute.exec(request.url!.split("?")[0]);
  const upgrade = request.headers.upgrade?.toLowerCase() === relayProtocol;
  const connection = String(request.headers.connection ?? "")
    .split(",")
    .some((value) => value.trim().toLowerCase() === "upgrade");
  if (request.method !== "GET" || !match || !upgrade || !connection) return;
  try {
    return {
      provider: decodeURIComponent(match[1]),
      id: decodeURIComponent(match[2]),
    };
  } catch {
    return;
  }
}

/** A protocol error as a raw HTTP response on a socket that never upgraded. */
function rawError(socket: Duplex, error: unknown) {
  const result = errorResponse(error);
  const body = JSON.stringify(result.detail);
  const headers = {
    ...result.headers,
    "content-length": String(Buffer.byteLength(body)),
    connection: "close",
  };
  socket.end(
    [
      `HTTP/1.1 ${result.status} ${STATUS_CODES[result.status]}`,
      ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`),
      "",
      body,
    ].join("\r\n"),
  );
}

function createApp(): FastifyInstance {
  const app = Fastify({
    serverFactory: (handler) =>
      createServer(
        { shouldUpgradeCallback: (request) => !!relayTarget(request) },
        handler,
      ),
    logger: false,
    exposeHeadRoutes: true,
    forceCloseConnections: true,
    bodyLimit: 2 * 1024 * 1024,
    schemaErrorFormatter: invalidRequest,
    onProtoPoisoning: "ignore",
    onConstructorPoisoning: "ignore",
    routerOptions: { maxParamLength: 16 * 1024 },
  });
  app.addContentTypeParser(
    "application/merge-patch+json",
    { parseAs: "string" },
    app.getDefaultJsonParser("ignore", "ignore"),
  );
  app.setValidatorCompiler(({ schema }) => compile(schema as object));
  // Never expose parser text, credential values or unexpected SDK exceptions.
  app.setErrorHandler((error: FastifyError, _request, reply) =>
    sendError(reply, isUnreadableBody(error) ? invalidRequest() : error),
  );
  // An unknown method on a known path is 405; anything else is 404.
  const methods = new Set<HTTPMethods>();
  app.addHook("onRoute", (route) => {
    for (const method of [route.method].flat()) methods.add(method);
  });
  app.setNotFoundHandler((request, reply) => {
    const url = request.raw.url!.split("?")[0];
    const known = [...methods].some(
      (method) => app.findRoute({ method, url }) !== null,
    );
    if (known)
      return sendError(
        reply,
        new ProtocolFailure({
          kind: "method_not_allowed",
          reason: "method not allowed",
        }),
      );
    return sendError(
      reply,
      new ProtocolFailure({ kind: "not_found", reason: "unknown route" }),
    );
  });
  return app;
}

export async function serve(modules: ProviderModule[], unix: string) {
  await requirePrivateDirectory(unix);
  const version = await hostVersion();
  const registry = moduleRegistry(modules);
  const validConfiguration = compile(bodySchema("Configuration"));
  const stopping = new AbortController();
  const signals = new WeakMap<IncomingMessage, AbortSignal>();
  let bindings = new Map<string, Binding>();
  let configuring: Promise<unknown> = Promise.resolve();

  function binding(name: string): Binding {
    const value = bindings.get(name);
    if (!value)
      throw new ProtocolFailure({
        kind: "not_found",
        reason: "unknown provider",
      });
    return value;
  }

  function provider(request: FastifyRequest<{ Params: Instance }>) {
    return binding(request.params.provider).provider;
  }

  function context(request: FastifyRequest): Context {
    return {
      credential: credential(request.raw),
      signal: signals.get(request.raw)!,
    };
  }

  async function declaration(
    name: string,
    ctx: Context,
  ): Promise<Types["ProviderDeclaration"]> {
    const { config, provider } = binding(name);
    return {
      provider: name,
      module: config.module,
      ports: ports(provider),
      capabilities: provider.capabilities,
      observation: provider.observation,
      rate_limits: provider.rateLimits,
      readiness: await readiness(provider, ctx),
    };
  }

  function currentConfiguration(): Configuration {
    const providers = [...bindings].map(([name, b]) => [name, b.config]);
    return { providers: Object.fromEntries(providers) };
  }

  // Build every binding before swapping, so a failure keeps the old document.
  async function commit(document: unknown, signal: AbortSignal) {
    if (!validConfiguration(document)) refused("invalid configuration");
    const next = new Map<string, Binding>();
    const entries = Object.entries((document as Configuration).providers ?? {});
    for (const [name, entry] of entries) {
      signal.throwIfAborted();
      if (entry.credential != null)
        refused("credential is a server-only configuration key");
      const module = registry.get(entry.module);
      if (!module) refused("unknown module");
      const old = bindings.get(name);
      const provider =
        old && isDeepStrictEqual(old.config, entry)
          ? old.provider
          : await module.configure(name, structuredClone(entry), signal);
      next.set(name, { config: structuredClone(entry), provider });
    }
    signal.throwIfAborted();
    bindings = next;
  }

  // Configuration changes run one at a time against the latest committed state.
  function configure(
    update: (current: Configuration) => unknown,
    signal: AbortSignal,
  ) {
    const action = configuring.then(() =>
      commit(update(currentConfiguration()), signal),
    );
    configuring = action.catch(() => {});
    return action;
  }

  const app = createApp();
  app.addHook("onRequest", async (request, reply) => {
    const abort = new AbortController();
    reply.raw.once("close", () => abort.abort());
    request.raw.once("aborted", () => abort.abort());
    signals.set(request.raw, AbortSignal.any([abort.signal, stopping.signal]));
    // Like Rust, routing precedes the credential extractor.
    if (!request.is404) credential(request.raw);
  });

  app.get<{ Reply: Types["Hello"] }>("/v1/hello", async () => ({
    protocol_version: protocolVersion,
    host_version: version,
    loadable_modules: modules.map((module) => ({
      name: module.name,
      version: module.version,
      smallest_size: module.smallestSize,
    })),
  }));

  app.put<{ Body: Configuration }>(
    "/v1/config",
    { schema: { body: bodySchema("Configuration") } },
    async (request, reply) => {
      await configure(() => request.body, context(request).signal);
      return reply.code(204).send();
    },
  );

  // Validation applies to the merged document: patches use null for deletion.
  app.patch<{ Body: unknown }>("/v1/config", async (request, reply) => {
    await configure(
      (current) => mergePatch(current, request.body),
      context(request).signal,
    );
    return reply.code(204).send();
  });

  app.get("/v1/providers", (request) => {
    const ctx = context(request);
    return Promise.all([...bindings.keys()].map((n) => declaration(n, ctx)));
  });

  app.get<{ Params: Instance }>("/v1/providers/:provider", (request) =>
    declaration(request.params.provider, context(request)),
  );

  app.post<{ Params: Instance; Body: Types["PrepareRequest"] }>(
    "/v1/providers/:provider/prepare",
    { schema: { body: bodySchema("PrepareRequest") } },
    (request) => provider(request).prepare(request.body, context(request)),
  );

  const environments = "/v1/providers/:provider/environments";

  app.get<{ Params: Instance }>(environments, (request) =>
    provider(request).list(context(request)),
  );

  app.post<{ Params: Instance; Body: Types["ProvisionRequest"] }>(
    environments,
    { schema: { body: bodySchema("ProvisionRequest") } },
    async (request, reply) => {
      const result = await provider(request).provision(
        request.body,
        context(request),
      );
      return reply.code(result.created ? 201 : 200).send(result.environment);
    },
  );

  app.get<{ Params: Instance }>(`${environments}/:id`, (request) =>
    provider(request).inspect(request.params.id, context(request)),
  );

  app.delete<{ Params: Instance }>(
    `${environments}/:id`,
    async (request, reply) => {
      await provider(request).destroy(request.params.id, context(request));
      return reply.code(204).send();
    },
  );

  app.post<{ Params: Instance }>(`${environments}/:id/reach`, (request) =>
    provider(request).reach(request.params.id, context(request)),
  );

  // A relay with both upgrade headers never reaches Fastify (see relayTarget).
  app.get<{ Params: Instance }>(`${environments}/:id/relay`, () =>
    refused(`missing ${relayProtocol} upgrade headers`),
  );

  function port<T>(method: T | undefined): T {
    if (!method) refused("operation port unavailable");
    return method;
  }

  app.post<{ Params: Instance }>(`${environments}/:id/suspend`, (request) => {
    const p = provider(request);
    return port(p.suspend).call(p, request.params.id, context(request));
  });

  app.post<{ Params: Instance; Body: Types["ResumeToken"] }>(
    `${environments}/:id/resume`,
    { schema: { body: bodySchema("ResumeToken") } },
    async (request, reply) => {
      const p = provider(request);
      await port(p.resume).call(
        p,
        request.params.id,
        request.body,
        context(request),
      );
      return reply.code(204).send();
    },
  );

  app.get<{ Params: Instance }>("/v1/providers/:provider/quota", (request) => {
    const p = provider(request);
    return port(p.quota).call(p, context(request));
  });

  // Like Rust, the provider is called before switching protocols, so its
  // refusals are ordinary error responses; then bytes pass both ways, and
  // either side's end half-closes the other.
  const relays = new Set<Duplex>();
  async function relay(request: IncomingMessage, socket: Duplex, head: Buffer) {
    relays.add(socket);
    const abort = new AbortController();
    socket.once("close", () => {
      relays.delete(socket);
      abort.abort();
    });
    socket.on("error", () => socket.destroy());
    const signal = AbortSignal.any([abort.signal, stopping.signal]);
    let stream: Duplex;
    try {
      const target = relayTarget(request)!;
      const ctx = { credential: credential(request), signal };
      const p = binding(target.provider).provider;
      stream = await port(p.relay).call(p, target.id, ctx);
    } catch (error) {
      if (!socket.destroyed) rawError(socket, error);
      return;
    }
    if (signal.aborted) {
      stream.destroy();
      socket.destroy();
      return;
    }
    socket.write(
      `HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: ${relayProtocol}\r\n\r\n`,
    );
    if (head.length) stream.write(head);
    stream.on("error", () => socket.destroy());
    socket.once("close", () => stream.destroy());
    stream.once("close", () => socket.end(() => socket.destroy()));
    socket.pipe(stream);
    stream.pipe(socket);
  }
  app.server.on("upgrade", (request, socket, head) => {
    void relay(request, socket, head);
  });

  await app.listen({ path: unix });
  // The verified 0700 parent controls access during bind-to-chmod.
  await chmod(unix, 0o600);
  return {
    app,
    async close() {
      stopping.abort();
      for (const socket of relays) socket.destroy();
      await app.close();
      bindings.clear();
    },
  };
}

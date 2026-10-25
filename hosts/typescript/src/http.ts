import http, { type IncomingMessage } from "node:http";
import type { Socket } from "node:net";
import { Readable } from "node:stream";
import Fastify, {
  type FastifyRequest,
  type FastifyReply,
  type HTTPMethods,
} from "fastify";
import type { operations as Contract } from "./protocol.js";
import document from "./openapi.json" with { type: "json" };
import type { Host } from "./host.js";
import { fail, ProtocolFailure } from "./provider.js";
import { compile, protocolSchema, validate } from "./validation.js";
import { errorResponse } from "./http-errors.js";
import { jsonContentType, upgrade } from "./upgrade.js";

type Id = keyof Contract;
type Body<I extends Id> = Contract[I] extends {
  requestBody: { content: { "application/json": infer B } };
}
  ? B
  : undefined;
type Params<I extends Id> = Contract[I] extends {
  parameters: { path: infer P };
}
  ? P
  : Record<string, never>;
type Query<I extends Id> = Contract[I] extends {
  parameters: { query?: infer Q };
}
  ? NonNullable<Q>
  : Record<string, never>;
type Request<I extends Id> = FastifyRequest<{
  Body: Body<I>;
  Params: Params<I>;
  Querystring: Query<I>;
}>;
type Binding<I extends Id> = (
  request: Request<I>,
  reply: FastifyReply,
) => unknown;
const contracts = Object.entries(document.paths).flatMap(([url, item]) =>
  Object.entries(item).map(([method, value]) => ({
    id: value.operationId as Id,
    url: url.replace(/\{([^}]+)\}/g, ":$1"),
    method: method.toUpperCase() as HTTPMethods,
    body:
      "requestBody" in value
        ? value.requestBody.content["application/json"].schema.$ref
        : undefined,
  })),
);
const methods = [...new Set(contracts.map((c) => c.method))];

/** HTTP is the only module that knows Fastify. Wire schemas always come from Rust. */
export function createHttp(
  host: Host,
  admission: (request: IncomingMessage) => number,
) {
  const upgrades = new WeakMap<
    IncomingMessage,
    { socket: Socket; head: Buffer }
  >();
  const app = Fastify({
    logger: false,
    exposeHeadRoutes: false,
    // Preserve the previous URL parser's dot-segment handling before matching.
    rewriteUrl: (request) => {
      const url = new URL(request.url!, "http://localhost");
      return url.pathname + url.search;
    },
    bodyLimit: 2 * 1024 * 1024,
    keepAliveTimeout: 5000,
    requestTimeout: 300000,
    onProtoPoisoning: "ignore",
    onConstructorPoisoning: "ignore",
    routerOptions: {
      maxParamLength: 16 * 1024,
      querystringParser: (text) => {
        const query = new URLSearchParams(text);
        return Object.fromEntries(
          [...query.keys()].map((key) => [key, query.get(key)]),
        );
      },
      onBadUrl: (_path, _req, res) => {
        const result = errorResponse(
          host,
          new ProtocolFailure({ kind: "refused", reason: "invalid path" }),
        );
        res.writeHead(result.status, result.headers);
        res.end(JSON.stringify(result.detail));
      },
    },
    serverFactory: (handler) =>
      http.createServer((req, res) => {
        const refusal = admission(req);
        if (refusal) {
          res.writeHead(refusal);
          res.end();
        } else handler(req, res);
      }),
  });
  // Fastify owns buffering, limits and JSON parsing. Do not parse bodies on
  // routes whose Rust contract has no body extractor, and never mutate input.
  app.removeAllContentTypeParsers();
  const json = app.getDefaultJsonParser("ignore", "ignore");
  app.addContentTypeParser(
    "*",
    { parseAs: "string" },
    (request, body, done) => {
      if (!request.routeOptions.schema?.body) {
        done(null, undefined);
        return;
      }
      if (!jsonContentType(request.headers["content-type"])) {
        done(
          new ProtocolFailure({
            kind: "refused",
            reason: "invalid JSON request",
          }),
        );
        return;
      }
      json(request, body.toString(), done);
    },
  );
  app.setValidatorCompiler(({ schema }) => compile(schema as object));
  app.setErrorHandler((error, _request, reply) => {
    const result = errorResponse(host, error);
    reply.code(result.status).headers(result.headers).send(result.detail);
  });
  const missing = (url: string) =>
    new ProtocolFailure({
      kind: methods.some((method) => app.findRoute({ method, url }))
        ? "method_not_allowed"
        : "not_found",
      reason: "unknown route or method",
    });
  app.setNotFoundHandler((request) => {
    throw missing(request.raw.url!);
  });
  // Raw upgrades use this very router and its decoded params, before ordinary
  // body parsing. The socket is still a byte duplex, never a WebSocket.
  app.addHook("onRequest", async (request, reply) => {
    const raw = upgrades.get(request.raw);
    if (!raw) return;
    const operation = (
      request.routeOptions.config as { upgrade?: "relay" | "exec" }
    ).upgrade;
    if (!operation) throw missing(request.raw.url!);
    reply.hijack();
    await upgrade(
      host,
      operation,
      request.params as { provider: string; id: string },
      request.raw,
      raw.socket,
      raw.head,
    );
  });
  app.server.on("upgrade", (req, socket, head) => {
    const refusal = admission(req);
    if (refusal) {
      socket.end(`HTTP/1.1 ${refusal} Refused\r\nContent-Length: 0\r\n\r\n`);
      return;
    }
    const guard = () => socket.destroy();
    socket.on("error", guard);
    const response = new http.ServerResponse(req);
    response.assignSocket(socket as Socket);
    response.once("finish", () => socket.destroy());
    socket.once("close", () => socket.off("error", guard));
    upgrades.set(req, { socket: socket as Socket, head });
    app.routing(req, response);
  });
  const bound = new Set<Id>();
  function bind<I extends Id>(
    id: I,
    handler: Binding<I>,
    options: {
      query?: keyof import("./provider.js").Types;
      empty?: boolean;
      upgrade?: "relay" | "exec";
    } = {},
  ) {
    const contract = contracts.find((c) => c.id === id);
    if (!contract || bound.has(id))
      throw Error("invalid protocol route binding");
    bound.add(id);
    app.route<{ Body: Body<I>; Params: Params<I>; Querystring: Query<I> }>({
      method: contract.method,
      url: contract.url,
      config: options.upgrade ? { upgrade: options.upgrade } : {},
      schema: {
        ...(contract.body
          ? { body: { $ref: "protocol" + contract.body } }
          : {}),
        ...(options.query
          ? { querystring: protocolSchema(options.query) }
          : {}),
      },
      handler: async (request, reply) => {
        const value = await handler(request, reply);
        return options.empty ? reply.code(204).send() : value;
      },
    });
  }
  bind("hello", () => host.hello());
  bind("configure", (request) => host.configure(request.body), { empty: true });
  bind(
    "refresh_credential",
    (request) => host.refresh(request.params.provider, request.body.value),
    { empty: true },
  );
  bind("prepare", (request) =>
    host.prepare(request.params.provider, request.body),
  );
  bind("provision", async (request, reply) => {
    const result = await host.provision(request.params.provider, request.body);
    reply.code(result.created ? 201 : 200);
    return result.row.environment;
  });
  bind("list", async (request) =>
    (await host.invoke(request.params.provider, "list", [])).map(
      (row) => row.environment,
    ),
  );
  bind(
    "inspect",
    async (request) =>
      (
        await host.invoke(request.params.provider, "inspect", [
          request.params.id,
        ])
      ).environment,
  );
  bind(
    "destroy",
    (request) => host.destroy(request.params.provider, request.params.id),
    { empty: true },
  );
  bind("reach", async (request) => {
    const { provider, id } = request.params;
    const reach = await host.invoke(provider, "reach", [id]);
    return reach.kind === "relay"
      ? {
          kind: "relay",
          path: `/v1/providers/${encodeURIComponent(provider)}/environments/${encodeURIComponent(id)}/relay`,
        }
      : reach;
  });
  bind("suspend", (request) =>
    host.invoke(request.params.provider, "suspend", [request.params.id]),
  );
  bind(
    "resume",
    (request) =>
      host.invoke(request.params.provider, "resume", [
        request.params.id,
        request.body,
      ]),
    { empty: true },
  );
  bind("export", (request) =>
    host.invoke(request.params.provider, "export", [request.params.id]),
  );
  bind("quota", (request) => host.invoke(request.params.provider, "quota", []));
  bind(
    "usage",
    (request) => {
      validate("Period", request.query);
      return host.invoke(request.params.provider, "usage", [request.query]);
    },
    { query: "Period" },
  );
  bind("relay", () => fail("refused", "missing stream upgrade headers"), {
    upgrade: "relay",
  });
  bind("exec", () => fail("refused", "missing stream upgrade headers"), {
    upgrade: "exec",
  });
  bind("observe", async (request, reply) => {
    const abort = new AbortController();
    reply.raw.once("close", () => abort.abort());
    const stream = await host.observation.stream(
      request.query.since,
      abort.signal,
    );
    const response = reply.type("application/x-ndjson").send(
      Readable.from(
        (async function* () {
          for await (const record of stream)
            yield JSON.stringify(record) + "\n";
        })(),
      ),
    );
    // Exclusive replay may have no initial rows; announce the stream before
    // waiting for the next event. Fastify still owns piping and backpressure.
    reply.raw.flushHeaders();
    return response;
  });
  if (contracts.some((contract) => !bound.has(contract.id)))
    throw Error("unbound protocol operation");
  return app;
}

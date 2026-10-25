import http, { type IncomingMessage, type ServerResponse } from "node:http";
import { type Socket, isIP, connect } from "node:net";
import { randomBytes, timingSafeEqual, createHash } from "node:crypto";
import { lstat, chmod, open, rename, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import type { Duplex } from "node:stream";
import { Host } from "./host.js";
import { fail, ProtocolFailure, type Types } from "./provider.js";
import { validate } from "./validation.js";
import { upgradeBody } from "./upgrade.js";
import { peerUid } from "./peer.js";
const status: Record<Types["ProtocolError"]["kind"], number> = {
  not_found: 404,
  method_not_allowed: 405,
  refused: 422,
  unavailable: 503,
  rate_limited: 429,
  quota_exhausted: 402,
  credential_rejected: 502,
  command_failed: 424,
  internal: 500,
};
export type Listener = { unix: string } | { tcp: string; tokenFile: string };
export async function serve(
  host: Host,
  listener: Listener,
  unixUid = process.geteuid?.(),
) {
  let token: string | undefined, authority: string | undefined;
  const sockets = new Set<Socket>();
  const server = http.createServer((req, res) => {
    void handle(req, res).catch((e) => error(res, e));
  });
  const admission = (req: IncomingMessage) => {
    if ("unix" in listener) return peerUid(req.socket) === unixUid ? 0 : 403;
    if (
      req.headers.host !== authority ||
      req.headersDistinct.host?.length !== 1
    )
      return 421;
    if (
      req.headers.origin !== undefined &&
      (req.headersDistinct.origin?.length !== 1 ||
        req.headers.origin !== `http://${authority}`)
    )
      return 403;
    if (req.headersDistinct.authorization?.length !== 1) return 401;
    const authorization = req.headers.authorization?.split(" ");
    if (
      authorization?.length !== 2 ||
      authorization[0].toLowerCase() !== "bearer"
    )
      return 401;
    const actual = createHash("sha256").update(authorization[1]).digest(),
      expected = createHash("sha256")
        .update(token ?? "")
        .digest();
    return timingSafeEqual(actual, expected) ? 0 : 401;
  };

  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    if ("unix" in listener && peerUid(socket) !== unixUid) {
      socket.end(
        "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
      );
    }
  });
  function error(res: ServerResponse, error: unknown) {
    if (res.headersSent) {
      res.destroy();
      return;
    }
    const detail =
      error instanceof ProtocolFailure
        ? host.errorDetail(error)
        : {
            kind: "internal" as const,
            reason: "host request failed",
            provider_error: "",
          };
    const headers: Record<string, string> = {
      "content-type": "application/json",
    };
    if (
      "retry_after" in detail &&
      detail.retry_after !== undefined &&
      detail.retry_after !== null
    )
      headers["retry-after"] = String(detail.retry_after);
    res.writeHead(status[detail.kind], headers);
    res.end(JSON.stringify(detail));
  }
  async function body(req: IncomingMessage, schema: string) {
    if (!jsonContentType(req.headers["content-type"]))
      fail("refused", "invalid JSON request");
    let bytes = 0;
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      bytes += chunk.length;
      if (bytes > 2 * 1024 * 1024) fail("refused", "request too large");
      chunks.push(chunk);
    }
    let result: unknown;
    try {
      result = JSON.parse(Buffer.concat(chunks).toString());
    } catch {
      fail("refused", "invalid JSON request");
    }
    validate(schema, result);
    return result;
  }
  function route(req: IncomingMessage) {
    let url: URL, parts: string[];
    try {
      url = new URL(req.url!, "http://localhost");
      parts = url.pathname.split("/").slice(1).map(decodeURIComponent);
    } catch {
      fail("refused", "invalid path");
    }
    return { url, parts };
  }
  function method(req: IncomingMessage, allowed: string[]) {
    if (!allowed.includes(req.method!))
      throw new ProtocolFailure({
        kind: "method_not_allowed",
        reason: "method not allowed",
      });
  }
  async function handle(req: IncomingMessage, res: ServerResponse) {
    const refusal = admission(req);
    if (refusal) {
      res.writeHead(refusal);
      res.end();
      return;
    }
    const { url, parts } = route(req);
    const json = (value: unknown, code = 200) => {
      res.writeHead(code, { "content-type": "application/json" });
      res.end(JSON.stringify(value));
    };
    const empty = () => {
      res.writeHead(204);
      res.end();
    };
    if (parts.length === 2 && parts[0] === "v1") {
      if (parts[1] === "hello") {
        method(req, ["GET"]);
        json(host.hello());
        return;
      }
      if (parts[1] === "config") {
        method(req, ["PUT"]);
        await host.configure(
          (await body(req, "HostConfiguration")) as Types["HostConfiguration"],
        );
        empty();
        return;
      }
      if (parts[1] === "events") {
        method(req, ["GET"]);
        const abort = new AbortController();
        res.on("close", () => abort.abort());
        let cursor = url.searchParams.get("since") ?? undefined;
        let records = await host.records(cursor);
        res.writeHead(200, { "content-type": "application/x-ndjson" });
        res.flushHeaders();
        while (!abort.signal.aborted && !host.stop.signal.aborted) {
          // Subscribe before reading to avoid losing a wakeup between reads.
          const pending = new AbortController();
          const wake = host.changed(
            AbortSignal.any([pending.signal, abort.signal]),
          );
          for (const record of records) {
            cursor =
              record.type === "snapshot" ? record.cursor : record.event.cursor;
            if (!res.write(JSON.stringify(record) + "\n")) {
              await new Promise<void>((resolve) => {
                const done = () => {
                  res.off("drain", done);
                  res.off("close", done);
                  resolve();
                };
                res.once("drain", done);
                res.once("close", done);
              });
            }
          }
          const more = await host.records(cursor);
          if (more.length) {
            pending.abort();
            await wake;
            records = more;
            continue;
          }
          await wake;
          pending.abort();
          if (abort.signal.aborted || host.stop.signal.aborted) break;
          records = await host.records(cursor);
        }
        res.end();
        return;
      }
    }
    if (parts[0] !== "v1" || parts[1] !== "providers" || !parts[2])
      fail("not_found", "unknown route");
    const name = parts[2];
    if (parts.length === 4) {
      switch (parts[3]) {
        case "credential":
          method(req, ["PUT"]);
          host.refresh(
            name,
            (
              (await body(
                req,
                "CredentialRefresh",
              )) as Types["CredentialRefresh"]
            ).value,
          );
          empty();
          return;
        case "prepare":
          method(req, ["POST"]);
          json(
            await host.prepare(
              name,
              (await body(req, "PrepareRequest")) as Types["PrepareRequest"],
            ),
          );
          return;
        case "quota":
          method(req, ["GET"]);
          json(
            await host.call(name, "quota", (p, c) =>
              p.quota
                ? p.quota(c)
                : Promise.reject(
                    new ProtocolFailure({
                      kind: "refused",
                      reason: "operation port unavailable",
                    }),
                  ),
            ),
          );
          return;
        case "usage": {
          method(req, ["GET"]);
          const period = {
            start: url.searchParams.get("start"),
            end: url.searchParams.get("end"),
          };
          validate("Period", period);
          json(
            await host.call(name, "usage", (p, c) =>
              p.usage
                ? p.usage(period as Types["Period"], c)
                : Promise.reject(
                    new ProtocolFailure({
                      kind: "refused",
                      reason: "operation port unavailable",
                    }),
                  ),
            ),
          );
          return;
        }
        case "environments":
          method(req, ["GET", "POST"]);
          if (req.method === "GET")
            json(
              (await host.call(name, "list", (p, c) => p.list(c))).map(
                (row) => row.environment,
              ),
            );
          else {
            const result = await host.provision(
              name,
              (await body(
                req,
                "ProvisionRequest",
              )) as Types["ProvisionRequest"],
            );
            json(result.row.environment, result.created ? 201 : 200);
          }
          return;
      }
    }
    if (parts[3] === "environments" && parts[4]) {
      const id = parts[4];
      if (parts.length === 5) {
        method(req, ["GET", "DELETE"]);
        if (req.method === "GET")
          json(
            (await host.call(name, "inspect", (p, c) => p.inspect(id, c)))
              .environment,
          );
        else {
          await host.destroy(name, id);
          empty();
        }
        return;
      }
      if (parts.length === 6) {
        const op = parts[5];
        if (op === "relay" || op === "exec") {
          method(req, [op === "relay" ? "GET" : "POST"]);
          fail("refused", "missing stream upgrade headers");
        }
        if (op === "reach") {
          method(req, ["POST"]);
          const reach = await host.call(name, "reach", (p, c) =>
            p.reach(id, c),
          );
          json(
            reach.kind === "relay"
              ? {
                  kind: "relay",
                  path: `/v1/providers/${encodeURIComponent(name)}/environments/${encodeURIComponent(id)}/relay`,
                }
              : reach,
          );
          return;
        }
        if (op === "suspend") {
          method(req, ["POST"]);
          json(
            await host.call(name, "suspend", (p, c) =>
              p.suspend
                ? p.suspend(id, c)
                : Promise.reject(
                    new ProtocolFailure({
                      kind: "refused",
                      reason: "operation port unavailable",
                    }),
                  ),
            ),
          );
          return;
        }
        if (op === "resume") {
          method(req, ["POST"]);
          const token = (await body(
            req,
            "ResumeToken",
          )) as Types["ResumeToken"];
          await host.call(name, "resume", (p, c) =>
            p.resume
              ? p.resume(id, token, c)
              : Promise.reject(
                  new ProtocolFailure({
                    kind: "refused",
                    reason: "operation port unavailable",
                  }),
                ),
          );
          empty();
          return;
        }
        if (op === "export") {
          method(req, ["POST"]);
          json(
            await host.call(name, "export", (p, c) =>
              p.export
                ? p.export(id, c)
                : Promise.reject(
                    new ProtocolFailure({
                      kind: "refused",
                      reason: "operation port unavailable",
                    }),
                  ),
            ),
          );
          return;
        }
      }
    }
    fail("not_found", "unknown route");
  }
  server.on("upgrade", (req, socket, head) => {
    const setup = new AbortController();
    const disconnected = () => {
      setup.abort();
      socket.destroy();
    };
    const cleanup = () => {
      socket.off("close", disconnected);
      socket.off("end", disconnected);
      socket.off("error", disconnected);
    };
    socket.once("close", disconnected);
    socket.once("end", disconnected);
    socket.once("error", disconnected);
    if (socket.destroyed || socket.readableEnded) setup.abort();
    void (async () => {
      const refusal = admission(req);
      if (refusal) {
        socket.end(`HTTP/1.1 ${refusal} Refused\r\nContent-Length: 0\r\n\r\n`);
        return;
      }
      const { parts } = route(req),
        op = parts[5];
      if (
        parts.length !== 6 ||
        parts[0] !== "v1" ||
        parts[1] !== "providers" ||
        parts[3] !== "environments" ||
        !["relay", "exec"].includes(op)
      )
        fail("not_found", "unknown route");
      method(req, [op === "relay" ? "GET" : "POST"]);
      const protocol = op === "relay" ? "drydock-relay" : "drydock-stream";
      if (
        req.headers.upgrade?.toLowerCase() !== protocol ||
        !req.headers.connection
          ?.toLowerCase()
          .split(",")
          .some((v) => v.trim() === "upgrade")
      )
        fail("refused", "missing stream upgrade headers");
      let remainder: Buffer = head,
        request: Types["ExecRequest"] | undefined;
      if (op === "exec") {
        if (!jsonContentType(req.headers["content-type"]))
          fail("refused", "invalid JSON request");
        const result = await upgradeBody(req, socket, head);
        remainder = result.remainder;
        try {
          request = JSON.parse(result.body.toString());
        } catch {
          fail("refused", "invalid exec body");
        }
        validate("ExecRequest", request);
      }
      const stream = await host.call(
        parts[2],
        op,
        async (p, c) => {
          const value = await (op === "relay"
            ? p.relay(parts[4], c)
            : p.exec
              ? p.exec(parts[4], request!, c)
              : Promise.reject(
                  new ProtocolFailure({
                    kind: "refused",
                    reason: "operation port unavailable",
                  }),
                ));
          if (c.signal.aborted || socket.destroyed || socket.readableEnded)
            value.destroy();
          return value;
        },
        false,
        setup.signal,
      );
      if (
        setup.signal.aborted ||
        host.stop.signal.aborted ||
        socket.destroyed ||
        socket.readableEnded
      ) {
        stream.destroy();
        socket.destroy();
        return;
      }
      socket.write(
        `HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: ${protocol}\r\n\r\n`,
      );
      cleanup();
      bridge(socket, stream, remainder);
    })()
      .catch((e) => {
        if (setup.signal.aborted || socket.destroyed) return;
        const detail =
          e instanceof ProtocolFailure
            ? host.errorDetail(e)
            : {
                kind: "internal" as const,
                reason: "stream failed",
                provider_error: "",
              };
        const data = JSON.stringify(detail);
        socket.end(
          `HTTP/1.1 ${status[detail.kind]} Error\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(data)}\r\n\r\n${data}`,
        );
      })
      .finally(cleanup);
  });
  try {
    if ("unix" in listener) {
      if (process.platform !== "linux")
        throw Error("Unix peer authentication requires Linux");
      await privateDirectory(dirname(listener.unix));
      await clearStaleSocket(listener.unix);
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(listener.unix, resolve);
      });
      await chmod(listener.unix, 0o600);
    } else {
      await privateDirectory(dirname(listener.tokenFile));
      const parsed = /^(127\.\d+\.\d+\.\d+|\[::1\]):(\d+)$/.exec(listener.tcp);
      if (
        !parsed ||
        !isIP(parsed[1].replace(/[\[\]]/g, "")) ||
        Number(parsed[2]) > 65535
      )
        throw Error("TCP must use a numeric loopback address");
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(
          Number(parsed[2]),
          parsed[1].replace(/[\[\]]/g, ""),
          resolve,
        );
      });
      const address = server.address() as { address: string; port: number };
      authority = `${address.address.includes(":") ? "[" + address.address + "]" : address.address}:${address.port}`;
      token = randomBytes(32).toString("hex");
      const temporary = `${listener.tokenFile}.${randomBytes(8).toString("hex")}.tmp`;
      try {
        try {
          const old = await lstat(listener.tokenFile);
          if (
            !old.isFile() ||
            old.uid !== process.geteuid?.() ||
            (old.mode & 0o777) !== 0o600
          )
            throw Error("unsafe token file");
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        }
        const file = await open(temporary, "wx", 0o600);
        try {
          await file.writeFile(token);
          await file.sync();
        } finally {
          await file.close();
        }
        await rename(temporary, listener.tokenFile);
      } finally {
        await unlink(temporary).catch(() => {});
      }
    }
  } catch (error) {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await host.shutdown();
    throw error;
  }

  return {
    server,
    async close() {
      const stopped = host.shutdown();
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await stopped;
    },
  };
}
async function privateDirectory(path: string) {
  const info = await lstat(path);
  if (
    !info.isDirectory() ||
    info.uid !== process.geteuid?.() ||
    (info.mode & 0o777) !== 0o700
  )
    throw Error("runtime directory must be owned by host user with mode 0700");
}
function bridge(socket: Duplex, stream: Duplex, head: Buffer) {
  const close = () => {
    socket.destroy();
    stream.destroy();
  };
  socket.on("error", close);
  stream.on("error", close);
  socket.on("close", () => stream.destroy());
  stream.on("close", () => socket.end());
  if (head.length) stream.write(head);
  socket.pipe(stream);
  stream.pipe(socket);
  socket.resume();
}

async function clearStaleSocket(path: string) {
  let old;
  try {
    old = await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (!old.isSocket()) throw Error("existing Unix path is not a socket");
  const code = await new Promise<string | undefined>((resolve) => {
    const socket = connect(path);
    socket.once("connect", () => {
      socket.destroy();
      resolve(undefined);
    });
    socket.once("error", (error: NodeJS.ErrnoException) => resolve(error.code));
  });
  if (code !== "ECONNREFUSED")
    throw Error("Unix socket is live or cannot be safely replaced");
  const current = await lstat(path);
  if (current.dev !== old.dev || current.ino !== old.ino)
    throw Error("Unix socket changed during probe");
  await unlink(path);
}

function jsonContentType(value?: string) {
  return (
    value !== undefined &&
    /^application\/(?:json|[\w!#$&^_.+-]+\+json)(?:\s*;|$)/i.test(value)
  );
}

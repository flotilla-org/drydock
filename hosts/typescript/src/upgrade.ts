import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import type { Host } from "./host.js";
import { errorResponse } from "./http-errors.js";
import { validate } from "./validation.js";
import type { Types } from "./provider.js";
import { fail, ProtocolFailure } from "./provider.js";
/** Node hands upgraded bodies to us unparsed, including bytes past the body. */
export async function upgradeBody(
  req: IncomingMessage,
  socket: Duplex,
  head: Buffer,
) {
  let buffer: Buffer = head,
    framing = 0;
  const next = async () => {
    if (socket.destroyed || socket.readableEnded)
      fail("refused", "truncated exec body");
    return new Promise<Buffer>((resolve, reject) => {
      const clean = () => {
        socket.off("data", data);
        socket.off("end", closed);
        socket.off("close", closed);
        socket.off("error", closed);
      };
      const data = (chunk: Buffer) => {
        socket.pause();
        clean();
        resolve(chunk);
      };
      const closed = () => {
        clean();
        reject(
          new ProtocolFailure({
            kind: "refused",
            reason: "exec transport closed",
          }),
        );
      };
      socket.once("data", data);
      socket.once("end", closed);
      socket.once("close", closed);
      socket.once("error", closed);
      socket.resume();
    });
  };
  const ensure = async (n: number) => {
    while (buffer.length < n) buffer = Buffer.concat([buffer, await next()]);
  };
  const take = async (n: number) => {
    await ensure(n);
    const bytes = buffer.subarray(0, n);
    buffer = buffer.subarray(n);
    return bytes;
  };
  const line = async () => {
    while (buffer.indexOf("\r\n") < 0) {
      if (buffer.length > 8192) fail("refused", "invalid chunk framing");
      buffer = Buffer.concat([buffer, await next()]);
    }
    const end = buffer.indexOf("\r\n");
    framing += end + 2;
    if (end > 8192 || framing > 65536) fail("refused", "invalid chunk framing");
    const value = buffer.subarray(0, end).toString("ascii");
    buffer = buffer.subarray(end + 2);
    return value;
  };
  let body: Buffer;
  if (req.headers["transfer-encoding"]) {
    if (req.headers["transfer-encoding"].toLowerCase() !== "chunked")
      fail("refused", "invalid transfer encoding");
    const chunks: Buffer[] = [];
    let size = 0;
    while (true) {
      const header = (await line()).split(";")[0];
      if (!/^[0-9a-f]+$/i.test(header)) fail("refused", "invalid chunk size");
      const length = Number.parseInt(header, 16);
      size += length;
      if (!Number.isSafeInteger(length) || size > 2 * 1024 * 1024)
        fail("refused", "exec body too large");
      if (length === 0) {
        while (await line()) {}
        break;
      }
      chunks.push(await take(length));
      if ((await take(2)).toString() !== "\r\n")
        fail("refused", "invalid chunk ending");
    }
    body = Buffer.concat(chunks);
  } else {
    const length = Number(req.headers["content-length"] ?? 0);
    if (
      !Number.isSafeInteger(length) ||
      length <= 0 ||
      length > 2 * 1024 * 1024
    )
      fail("refused", "invalid exec body");
    body = await take(length);
  }
  return { body, remainder: buffer };
}

export function jsonContentType(value?: string) {
  return (
    value !== undefined &&
    /^application\/(?:json|[\w!#$&^_.+-]+\+json)(?:\s*;|$)/i.test(value)
  );
}
/** Raw non-WebSocket upgrades run after Fastify has matched the same routes. */
export async function upgrade(
  host: Host,
  operation: "relay" | "exec",
  params: { provider: string; id: string },
  req: IncomingMessage,
  socket: Duplex,
  head: Buffer,
) {
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
  try {
    const protocol = operation === "relay" ? "drydock-relay" : "drydock-stream";
    if (
      req.headers.upgrade?.toLowerCase() !== protocol ||
      !req.headers.connection
        ?.toLowerCase()
        .split(",")
        .some((v) => v.trim() === "upgrade")
    )
      fail("refused", "missing stream upgrade headers");
    let remainder = head,
      command: Types["ExecRequest"] | undefined;
    if (operation === "exec") {
      if (!jsonContentType(req.headers["content-type"]))
        fail("refused", "invalid JSON request");
      const parsed = await upgradeBody(req, socket, head);
      remainder = parsed.remainder;
      try {
        command = JSON.parse(parsed.body.toString());
      } catch {
        fail("refused", "invalid exec body");
      }
      validate("ExecRequest", command);
    }
    const options = { signal: setup.signal };
    const stream = await (operation === "relay"
      ? host.invoke(params.provider, "relay", [params.id], options)
      : host.invoke(params.provider, "exec", [params.id, command!], options));
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
  } catch (error) {
    if (setup.signal.aborted || socket.destroyed) return;
    const response = errorResponse(host, error),
      body = JSON.stringify(response.detail);
    socket.end(
      `HTTP/1.1 ${response.status} Error\r\n${Object.entries(response.headers)
        .map(([name, value]) => `${name}: ${value}\r\n`)
        .join("")}Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
    );
  } finally {
    cleanup();
  }
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

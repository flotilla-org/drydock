import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
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

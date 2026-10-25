import type { IncomingMessage } from "node:http";
import { createHttp } from "./http.js";
import { type Socket, isIP, connect } from "node:net";
import { randomBytes, timingSafeEqual, createHash } from "node:crypto";
import { lstat, chmod, open, rename, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import { Host } from "./host.js";
import { peerUid } from "./peer.js";
export type Listener = { unix: string } | { tcp: string; tokenFile: string };
export async function serve(
  host: Host,
  listener: Listener,
  unixUid = process.geteuid?.(),
) {
  let token: string | undefined, authority: string | undefined;
  const sockets = new Set<Socket>();
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

  const app = createHttp(host, admission),
    server = app.server;
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    if ("unix" in listener && peerUid(socket) !== unixUid) {
      socket.end(
        "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
      );
    }
  });
  await app.ready();
  try {
    if ("unix" in listener) {
      if (process.platform !== "linux")
        throw Error("Unix peer authentication requires Linux");
      await privateDirectory(dirname(listener.unix));
      await clearStaleSocket(listener.unix);
      await app.listen({ path: listener.unix });
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
      await app.listen({
        port: Number(parsed[2]),
        host: parsed[1].replace(/[\[\]]/g, ""),
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
    await app.close();
    await host.shutdown();
    throw error;
  }

  return {
    server,
    async close() {
      const stopped = host.shutdown();
      for (const socket of sockets) socket.destroy();
      await app.close();
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

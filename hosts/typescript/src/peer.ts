import koffi from "koffi";
import type { Socket } from "node:net";
// Linux SO_PEERCRED is checked on the accepted descriptor, before HTTP parsing.
// Fail closed on unsupported platforms; filesystem permissions alone are insufficient.
const libc = process.platform === "linux" ? koffi.load("libc.so.6") : undefined;
const get = libc?.func(
  "int getsockopt(int fd, int level, int option, _Out_ void *value, _Inout_ uint32_t *length)",
);
export function peerUid(socket: Socket): number | undefined {
  const fd = (socket as Socket & { _handle?: { fd: number } })._handle?.fd;
  if (!get || fd === undefined) return undefined;
  const buffer = Buffer.alloc(12),
    length = [12];
  if (get(fd, 1, 17, buffer, length) !== 0 || length[0] !== 12)
    return undefined;
  return buffer.readUInt32LE(4);
}

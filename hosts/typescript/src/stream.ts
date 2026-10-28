import type { Duplex } from "node:stream";
/** Node pipes provide backpressure and preserve both half-closes. */
export function bridge(socket: Duplex, stream: Duplex, head: Buffer) {
  const close = () => {
    socket.destroy();
    stream.destroy();
  };
  socket.on("error", close);
  stream.on("error", close);
  socket.once("close", () => stream.destroy());
  stream.once("close", () => socket.end());
  if (head.length) stream.write(head);
  socket.pipe(stream);
  stream.pipe(socket);
  socket.resume();
}

export class Clients<V extends { close(): void }> {
  private clients = new Map<
    string,
    { vendor: V; users: number; current: boolean }
  >();

  constructor(private connect: (key: string) => V) {}

  acquire(key: string) {
    let client = this.clients.get(key);
    if (!client?.current) {
      for (const other of this.clients.values()) other.current = false;
      client ??= { vendor: this.connect(key), users: 0, current: true };
      client.current = true;
      this.clients.set(key, client);
    }
    const held = client;
    held.users++;
    this.retire();
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      held.users--;
      this.retire();
    };
    return { vendor: held.vendor, release };
  }

  async using<T>(key: string, work: (vendor: V) => Promise<T>): Promise<T> {
    const { vendor, release } = this.acquire(key);
    try {
      return await work(vendor);
    } finally {
      release();
    }
  }

  private retire() {
    for (const [key, client] of this.clients)
      if (!client.current && client.users === 0) {
        client.vendor.close();
        this.clients.delete(key);
      }
  }
}

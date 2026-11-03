// An in-process stand-in for the Modal module's one network boundary, the
// SDK (the `Vendor` seam). It enforces what Modal documents and live runs
// observed (drydock#192), so the module fails here as it would there.
import { createHash } from "node:crypto";
import { Duplex, PassThrough } from "node:stream";
import {
  AlreadyExistsError,
  ConflictError,
  InvalidError,
  NotFoundError,
} from "modal";
import type {
  App,
  Box,
  Build,
  Create,
  Process,
  Token,
  Vendor,
} from "../../src/modal/vendor.ts";

export const TOKEN: Token = {
  token_id: "ak-test-only",
  token_secret: "as-test-only",
};
export const CREDENTIAL = JSON.stringify(TOKEN);

/** Raw gRPC failures, as nice-grpc's ClientError carries them. */
export class ClientError extends Error {
  name = "ClientError";
  code: number;
  details: string;
  constructor(code: number, details: string) {
    super(details);
    this.code = code;
    this.details = details;
  }
}

type Row = {
  id: string;
  app: string;
  imageId: string;
  params: Create;
  tags: Record<string, string>;
  /** Null while running; else the code `poll` reports. */
  exit: number | null;
  /** The agent's TCP token file, once the agent start wrote it. */
  token?: string;
};

/** One exec. It runs until its stdin ends, as Modal's do: there is no kill. */
export class StandInProcess implements Process {
  running = true;
  stdin: WritableStream<Uint8Array>;
  stdout: ReadableStream<Uint8Array>;
  readonly command: string[];
  private exited: Promise<number>;
  private input = new PassThrough();

  constructor(command: string[], serve: (remote: Duplex) => number | void) {
    this.command = command;
    // Stdin and stdout are separate channels: reading less of stdout never
    // ends stdin, and only stdin's end ends the process.
    const output = new PassThrough();
    const remote = Duplex.from({ readable: this.input, writable: output });
    remote.on("error", () => remote.destroy());
    let code = 0;
    this.exited = new Promise((resolve) =>
      this.input.once("finish", () => {
        this.running = false;
        resolve(code);
      }),
    );
    code = serve(remote) ?? 0;
    this.stdin = new WritableStream({
      write: (chunk) =>
        new Promise<void>((resolve) =>
          this.input.write(chunk, () => resolve()),
        ),
      close: () => {
        this.input.end();
      },
    });
    // Cancelling stdout stops reading it, nothing more.
    let reading = true;
    this.stdout = new ReadableStream<Uint8Array>({
      start(controller) {
        output.on("data", (d: Buffer) => reading && controller.enqueue(d));
        output.once("end", () => reading && controller.close());
      },
      cancel() {
        reading = false;
      },
    });
  }

  async closeStdin() {
    this.input.end();
  }

  wait() {
    return this.exited;
  }
}

const imageId = (definition: unknown) =>
  `im-${createHash("sha256").update(JSON.stringify(definition)).digest("hex").slice(0, 22)}`;

/** Modal SDK stand-in for one token pair. */
export class StandIn implements Vendor {
  apps = new Map<string, string>();
  images = new Set<string>();
  builds: Build[] = [];
  rows = new Map<string, Row>();
  processes: StandInProcess[] = [];
  calls: string[] = [];
  tokens: Token[] = [];
  environments: (string | undefined)[] = [];
  closed = 0;
  /** Exit code of the agent start exec. */
  agentStart = 0;
  /** Exit code of any other exec, which prints nothing. */
  execExit = 0;
  /** Each connect token minted: its sandbox and port. */
  connects: { id: string; port: number; token: string }[] = [];
  private next = 0;

  connect = (token: Token, environment?: string) => {
    this.tokens.push(token);
    this.environments.push(environment);
    return this;
  };

  private row(id: string): Row {
    const row = this.rows.get(id);
    if (!row) throw new ClientError(5, `sandbox ${id} not found`);
    return row;
  }

  /** Ends a sandbox as its timeout does. */
  expire(id: string, code = 124) {
    this.end(this.row(id), code);
  }

  private end(row: Row, code: number) {
    row.exit ??= code;
    // Its processes die with it.
    for (const p of this.processes)
      if (p.running && (p as any).sandbox === row.id) p.closeStdin();
  }

  async app(name: string): Promise<App> {
    this.calls.push(`app ${name}`);
    let id = this.apps.get(name);
    if (!id) this.apps.set(name, (id = `ap-${this.apps.size + 1}`));
    return { appId: id, name };
  }

  async build(app: App, build: Build) {
    this.calls.push("build");
    if (![...this.apps.values()].includes(app.appId))
      throw new NotFoundError(`App '${app.appId}' not found`);
    if (!/@sha256:[0-9a-f]{64}$/.test(build.base))
      throw new Error(
        `Image build for im-x failed with the exception:\nbad ref`,
      );
    this.builds.push(structuredClone(build));
    // The cache key is the definition; credentials are not part of it.
    const id = imageId([build.base, build.commands]);
    this.images.add(id);
    return id;
  }

  async image(id: string) {
    if (!this.images.has(id))
      throw new NotFoundError(`Could not find image with ID ${id}`);
  }

  async create(app: App, imageId: string, params: Create): Promise<Box> {
    this.calls.push("create");
    await this.image(imageId);
    const timeout = params.timeoutMs ?? 300_000;
    if (timeout < 10_000 || timeout > 86_400_000 || timeout % 1000)
      throw new InvalidError(`timeout ${timeout} ms out of range`);
    if (
      params.blockNetwork &&
      (params.outboundCidrAllowlist || params.outboundDomainAllowlist)
    )
      throw new InvalidError("allowlists cannot be used with blockNetwork");
    if (params.name && !/^[A-Za-z0-9._-]{1,63}$/.test(params.name))
      throw new InvalidError(`Invalid Sandbox name: '${params.name}'`);
    if (
      params.name &&
      [...this.rows.values()].some(
        (r) => r.app === app.appId && r.name === params.name && r.exit === null,
      )
    )
      throw new AlreadyExistsError(`Sandbox '${params.name}' already exists`);
    const row: Row & { name?: string } = {
      id: `sb-${++this.next}`,
      app: app.appId,
      imageId,
      params: structuredClone(params),
      tags: { ...params.tags },
      exit: null,
      name: params.name,
    };
    this.rows.set(row.id, row);
    return this.box(row.id);
  }

  async fromName(appName: string, name: string, includeTerminated = false) {
    this.calls.push("fromName");
    const app = this.apps.get(appName);
    const rows = [...this.rows.values()].filter(
      (r: any) => r.app === app && r.name === name,
    );
    const row =
      rows.find((r) => r.exit === null) ??
      (includeTerminated ? rows.at(-1) : undefined);
    if (!row)
      throw new NotFoundError(
        `Sandbox with name '${name}' not found in App '${appName}'`,
      );
    return this.box(row.id);
  }

  // As the SDK's: a handle without a round trip; its calls find out.
  async fromId(id: string) {
    return this.box(id);
  }

  async *list(appId: string, tags: Record<string, string>) {
    this.calls.push("list");
    if (!appId) throw new InvalidError("listing without an app is deprecated");
    for (const row of this.rows.values())
      if (
        row.app === appId &&
        row.exit === null &&
        Object.entries(tags).every(([k, v]) => row.tags[k] === v)
      )
        yield this.box(row.id);
  }

  detached = 0;

  private box(id: string): Box & {
    updateNetworkPolicy(p: {
      outboundCidrAllowlist: string[];
      outboundDomainAllowlist: string[];
    }): Promise<void>;
  } {
    const standIn = this;
    return {
      sandboxId: id,
      async getTags() {
        return { ...standIn.row(id).tags };
      },
      async poll() {
        return standIn.row(id).exit;
      },
      async terminate() {
        standIn.calls.push("terminate");
        standIn.end(standIn.row(id), 137);
      },
      async exec(command: string[]) {
        const row = standIn.row(id);
        if (row.exit !== null) throw new ClientError(9, "sandbox has finished");
        standIn.calls.push(`exec ${command.join(" ")}`);
        const process = new StandInProcess(command, (remote) => {
          // The agent start keeps the token file it finds, else writes stdin
          // there, and prints the file.
          const agentStart = command.join(" ").includes("--supervise");
          let input = "";
          remote.on("data", (d: Buffer) => (input += d));
          remote.once("end", () => {
            if (agentStart && standIn.agentStart === 0) row.token ||= input;
            remote.end(
              agentStart && standIn.agentStart === 0 ? `${row.token}\n` : "",
            );
          });
          return agentStart ? standIn.agentStart : standIn.execExit;
        });
        (process as any).sandbox = id;
        standIn.processes.push(process);
        return process;
      },
      // Modal's edge forwards to `port` in the sandbox, for its token; never
      // to a sandbox whose network is blocked.
      async connectToken(port: number) {
        const row = standIn.row(id);
        if (!Number.isInteger(port) || port < 1 || port > 65535)
          throw new InvalidError(`port ${port} out of range`);
        if (row.exit !== null) throw new ClientError(9, "sandbox has finished");
        if (row.params.blockNetwork)
          throw new ConflictError(
            "Cannot create a connect token for a Sandbox with blocked network access",
          );
        const token = `ct-${standIn.connects.length + 1}`;
        standIn.connects.push({ id, port, token });
        return { url: `https://${id}.modal.test`, token };
      },
      detach() {
        standIn.detached++;
      },
      // Modal refuses live domain filtering unless created with a domain list.
      async updateNetworkPolicy(p) {
        const row = standIn.row(id);
        if (
          p.outboundDomainAllowlist.length &&
          !row.params.outboundDomainAllowlist
        )
          throw new ClientError(
            9,
            "domain allowlist requires one at sandbox creation",
          );
        row.params.outboundCidrAllowlist = p.outboundCidrAllowlist;
        row.params.outboundDomainAllowlist = p.outboundDomainAllowlist;
      },
    };
  }

  close() {
    this.closed++;
  }
}

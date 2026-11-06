// An in-process stand-in for the Modal SDK calls the Modal module makes. It
// answers as the SDK documents: `poll()` is null while a sandbox runs, else
// its exit code; `list()` yields running sandboxes having the given tags.
import { AlreadyExistsError, ConflictError, NotFoundError } from "modal";

export const CREDENTIAL = JSON.stringify({
  token_id: "ak-test",
  token_secret: "as-test",
});
export const AGENT_TOKEN = "a".repeat(43);

type Row = {
  id: string;
  params: Record<string, any>;
  tags: Record<string, string>;
  exit: number | null;
};

export class StandIn {
  rows = new Map<string, Row>();
  calls: string[] = [];
  scripts: string[] = [];
  /** What the agent script prints, and how it exits. */
  agentOutput = AGENT_TOKEN;
  agentExit = 0;
  /** A message Modal refuses the next create with. */
  refuseCreate: string | undefined;
  /** Sandboxes that end right after Modal lists them. */
  vanishAfterList = new Set<string>();
  builds: { reference: string; commands: string[]; secret?: unknown }[] = [];
  private next = 0;

  private row(id: string) {
    const row = this.rows.get(id);
    if (!row) throw new NotFoundError(`Sandbox ${id} not found`);
    return row;
  }

  add(tags: Record<string, string>, exit: number | null = null) {
    const id = `sb-${++this.next}`;
    this.rows.set(id, { id, params: {}, tags, exit });
    return id;
  }

  private sandbox(id: string) {
    const standIn = this;
    return {
      sandboxId: id,
      async getTags() {
        standIn.calls.push(`getTags ${id}`);
        return { ...standIn.row(id).tags };
      },
      async poll() {
        standIn.calls.push(`poll ${id}`);
        return standIn.row(id).exit;
      },
      async terminate(params?: unknown) {
        standIn.calls.push(`terminate ${id} ${JSON.stringify(params ?? {})}`);
        standIn.row(id).exit = 137;
      },
      async exec(argv: string[]) {
        standIn.calls.push(`exec ${id}`);
        // The SDK's answer when the sandbox ended before exec found its task.
        if (standIn.row(id).exit !== null)
          throw new ConflictError(`Sandbox ${id} has already finished`);
        standIn.scripts.push(argv[2]);
        const output = new TextEncoder().encode(standIn.agentOutput);
        return {
          stdin: new WritableStream(),
          stdout: new ReadableStream({
            start(controller) {
              controller.enqueue(output);
              controller.close();
            },
          }),
          wait: async () => standIn.agentExit,
        };
      },
      async createConnectToken(params: { port: number }) {
        standIn.calls.push(`createConnectToken ${id} ${params.port}`);
        return { url: `https://${id}.modal.test`, token: "connect-token" };
      },
      detach() {},
    };
  }

  client() {
    const standIn = this;
    return {
      apps: {
        async fromName(name: string) {
          return { appId: `ap-${name}`, name };
        },
      },
      secrets: {
        async fromObject(entries: Record<string, string>) {
          return { entries };
        },
      },
      images: {
        async fromId(id: string) {
          if (id !== "im-1") throw new NotFoundError(`Image ${id} not found`);
          return { imageId: id };
        },
        fromRegistry(reference: string, secret?: unknown) {
          return {
            dockerfileCommands(commands: string[]) {
              return {
                async build() {
                  standIn.builds.push({ reference, commands, secret });
                  return { imageId: "im-1" };
                },
              };
            },
          };
        },
      },
      sandboxes: {
        async create(_app: unknown, _image: unknown, params: any) {
          standIn.calls.push("create");
          if (standIn.refuseCreate)
            throw new AlreadyExistsError(standIn.refuseCreate);
          const id = standIn.add(params.tags);
          standIn.row(id).params = params;
          return standIn.sandbox(id);
        },
        async fromId(id: string) {
          return standIn.sandbox(id);
        },
        async *list(params: { tags?: Record<string, string> }) {
          standIn.calls.push(`list ${JSON.stringify(params.tags ?? {})}`);
          for (const row of [...standIn.rows.values()])
            if (
              row.exit === null &&
              Object.entries(params.tags ?? {}).every(
                ([k, v]) => row.tags[k] === v,
              )
            ) {
              yield standIn.sandbox(row.id);
              if (standIn.vanishAfterList.has(row.id))
                standIn.rows.delete(row.id);
            }
        },
      },
      close() {},
    };
  }
}

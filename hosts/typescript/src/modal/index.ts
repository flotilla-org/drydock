import { randomBytes } from "node:crypto";
import { lookup } from "node:dns/promises";
import { BlockList, isIP, isIPv4, isIPv6 } from "node:net";
import {
  AlreadyExistsError,
  ClientClosedError,
  ConflictError,
  InvalidError,
  ModalClient,
  NotFoundError,
  ResourceExhaustedError,
  type App,
  type Sandbox,
  type SandboxCreateParams,
} from "modal";
import { parseImageRef, type ImageRef } from "../oci.js";
import {
  ProtocolFailure,
  refused,
  type Context,
  type Provider,
  type ProviderModule,
  type Types,
} from "../provider.js";
import { compile } from "../validation.js";
import { Clients } from "./clients.js";

const MiB = 1024 * 1024;
/** The tags drydock puts on a sandbox: the client's label, and on a shared
 * account the instance that made it. */
export const TAGS = {
  provider: "drydock.provider",
  label: "flotilla.label",
} as const;
const AGENT = "/opt/drydock/drydock-agent";
const SOCKET = "/run/drydock/agent.sock";
const TOKEN_FILE = "/run/drydock/tcp.token";
const PORT = 7811;
const PLATFORM: Types["Platform"] = { os: "linux", architecture: "amd64" };
// drydockd cannot start the agent here: its upload bootstrap needs the files
// and exec ports, which this host does not offer, and listens on loopback,
// which Modal's connect-token edge (https://modal.com/docs/guide/sandbox-networking)
// was seen not to reach. So the module starts it, listening on all addresses,
// and waits up to `agent_wait_seconds` for its socket.
const ensureAgent = (waitSeconds: number) =>
  [
    "t=$(head -c 256)",
    "umask 077",
    "mkdir -p /run/drydock",
    `if [ ! -s ${TOKEN_FILE} ]; then printf %s "$t" > ${TOKEN_FILE}.$$ && ln ${TOKEN_FILE}.$$ ${TOKEN_FILE} 2>/dev/null; rm -f ${TOKEN_FILE}.$$; fi`,
    `${AGENT} --supervise --tcp 0.0.0.0:${PORT} --tcp-token-file ${TOKEN_FILE} --socket ${SOCKET} || exit 1`,
    `for i in $(seq ${waitSeconds * 10}); do [ -S ${SOCKET} ] && exec cat ${TOKEN_FILE}; sleep 0.1; done`,
    "exit 1",
  ].join("\n");

export type Token = { token_id: string; token_secret: string };
type Settings = {
  app: string;
  environment?: string;
  runtime: "vm" | "gvisor";
  /** Modal's timeout for each sandbox, after which Modal ends it. */
  lifetime_seconds: number;
  /** How many tag reads list runs at once (see `list`). */
  list_concurrency: number;
  /** How long provision and reach wait for the agent's socket. */
  agent_wait_seconds: number;
};
const DEFAULTS: Settings = {
  app: "drydock",
  runtime: "vm",
  lifetime_seconds: 86_400,
  list_concurrency: 8,
  agent_wait_seconds: 10,
};
const objectName = "^[A-Za-z0-9._-]{1,63}$";
const settingsValid = compile({
  type: "object",
  additionalProperties: false,
  properties: {
    app: { type: "string", pattern: objectName },
    environment: { type: "string", pattern: objectName },
    runtime: { enum: ["vm", "gvisor"] },
    // Modal's sandbox timeout is at most 24 hours.
    lifetime_seconds: { type: "integer", minimum: 1, maximum: 86_400 },
    list_concurrency: { type: "integer", minimum: 1, maximum: 64 },
    agent_wait_seconds: { type: "integer", minimum: 1, maximum: 600 },
  },
});

const PRIVATE = new BlockList();
for (const [address, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.168.0.0", 16],
] as const)
  PRIVATE.addSubnet(address, prefix, "ipv4");
for (const [address, prefix] of [
  ["::", 127],
  ["fc00::", 7],
  ["fe80::", 10],
] as const)
  PRIVATE.addSubnet(address, prefix, "ipv6");

function privateAddress(address: string) {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address)?.[1];
  if (mapped) return PRIVATE.check(mapped, "ipv4");
  return PRIVATE.check(address, isIPv6(address) ? "ipv6" : "ipv4");
}

type Network = Pick<
  SandboxCreateParams,
  "outboundCidrAllowlist" | "outboundDomainAllowlist"
>;

// Deny all is an empty CIDR allowlist: Modal was seen to refuse a connect token
// to a sandbox with blockNetwork (https://modal.com/docs/guide/sandbox-networking).
function networkFields(egress: Types["EgressRequest"] | undefined): Network {
  if (egress?.mode === "open") return {};
  const cidrs = new Set<string>(),
    domains = new Set<string>();
  for (const entry of egress?.direct ?? []) {
    if (entry.kind === "host_port")
      refused("Modal egress policies cannot restrict ports");
    if (entry.kind === "cidr") {
      const [address, prefix] = entry.cidr.split("/");
      if (!isIPv4(address))
        refused("Modal egress policies allow IPv4 CIDRs only");
      if (!/^(?:[0-9]|[12][0-9]|3[0-2])$/.test(prefix ?? ""))
        refused(`invalid IPv4 CIDR ${entry.cidr}`);
      cidrs.add(entry.cidr);
      continue;
    }
    const host = entry.host.replace(/\.$/, "").toLowerCase();
    if (isIPv4(host)) cidrs.add(`${host}/32`);
    else if (host.includes(":") || host.startsWith("["))
      refused("Modal egress policies cannot allow IPv6");
    else domains.add(host);
  }
  if (!cidrs.size && !domains.size) return { outboundCidrAllowlist: [] };
  return {
    ...(cidrs.size && { outboundCidrAllowlist: [...cidrs].sort() }),
    ...(domains.size && { outboundDomainAllowlist: [...domains].sort() }),
  };
}

const EGRESS_MODEL: Types["EgressModel"] = {
  shapes: ["open", "deny_all", "allow_addresses", "allow_domains"],
  enforced: "outside_guest",
  side_effects: [
    {
      shapes: ["deny_all", "allow_addresses", "allow_domains"],
      note: "DNS resolution is not filtered (seen in live runs; Modal's docs do not say).",
    },
  ],
  mutable_while_running: true,
  sources: ["https://modal.com/docs/guide/sandbox-networking"],
};

// Modal's disk is fixed and cannot be sized, so a requested disk is accepted
// but not applied.
export function resources(size: Types["Size"]) {
  if (size.memory_bytes % MiB !== 0 || size.memory_bytes <= 0)
    refused("Modal sandbox memory is whole MiB");
  if (size.cpus <= 0) refused("Modal sandboxes need a positive CPU count");
  return { cpu: size.cpus, memoryMiB: size.memory_bytes / MiB };
}

function credentialToken(credential: string | undefined): Token {
  let token: Partial<Token> = {};
  try {
    token = JSON.parse(credential ?? "");
  } catch {}
  const valid = (value: unknown) => typeof value === "string" && !!value;
  if (!valid(token?.token_id) || !valid(token?.token_secret))
    throw new ProtocolFailure({
      kind: "credential_rejected",
      reason: 'Modal credential must be {"token_id": …, "token_secret": …}',
    });
  return { token_id: token.token_id!, token_secret: token.token_secret! };
}

const GRPC = {
  INVALID_ARGUMENT: 3,
  DEADLINE_EXCEEDED: 4,
  NOT_FOUND: 5,
  ALREADY_EXISTS: 6,
  PERMISSION_DENIED: 7,
  RESOURCE_EXHAUSTED: 8,
  FAILED_PRECONDITION: 9,
  ABORTED: 10,
  UNAVAILABLE: 14,
  UNAUTHENTICATED: 16,
} as const;

const brief = (text: string) =>
  text.length > 400 ? `${text.slice(0, 400)}…` : text;

function protocolError(error: unknown): ProtocolFailure {
  if (error instanceof ProtocolFailure) return error;
  const detail = String((error as Error)?.message ?? error);
  const failure = (detail: Types["ProtocolError"]) =>
    new ProtocolFailure(detail);
  if (error instanceof NotFoundError)
    return failure({ kind: "not_found", reason: `Modal: ${detail}` });
  if (
    error instanceof AlreadyExistsError ||
    error instanceof ConflictError ||
    error instanceof InvalidError
  )
    return failure({
      kind: "refused",
      reason: `Modal refused the request: ${brief(detail)}`,
    });
  if (error instanceof ResourceExhaustedError)
    return failure({
      kind: "unavailable",
      reason: "Modal has no capacity for the sandbox",
      provider_error: detail,
    });
  if (error instanceof ClientClosedError)
    return failure({
      kind: "unavailable",
      reason: "Modal client closed",
      provider_error: detail,
    });
  if (/^Image build for \S+ (failed|terminated|timed out)/.test(detail))
    return failure({
      kind: "refused",
      reason: `Modal could not build the image: ${brief(detail)}`,
    });
  const code = (error as { code?: unknown })?.code;
  if ((error as Error)?.name === "ClientError" && typeof code === "number") {
    const message = brief(
      String((error as { details?: string }).details ?? detail),
    );
    switch (code) {
      case GRPC.UNAUTHENTICATED:
        return failure({
          kind: "credential_rejected",
          reason: `Modal refused the credential: ${message}`,
        });
      case GRPC.PERMISSION_DENIED:
        return failure({
          kind: "refused",
          reason: `Modal denied the operation (the token lacks a right): ${message}`,
        });
      case GRPC.NOT_FOUND:
        return failure({ kind: "not_found", reason: `Modal: ${message}` });
      case GRPC.INVALID_ARGUMENT:
      case GRPC.FAILED_PRECONDITION:
      case GRPC.ALREADY_EXISTS:
        return failure({
          kind: "refused",
          reason: `Modal refused the request: ${message}`,
        });
      case GRPC.RESOURCE_EXHAUSTED:
        return failure({ kind: "rate_limited", reason: `Modal: ${message}` });
      case GRPC.UNAVAILABLE:
      case GRPC.DEADLINE_EXCEEDED:
      case GRPC.ABORTED:
        return failure({
          kind: "unavailable",
          reason: "Modal is unavailable",
          provider_error: detail,
        });
    }
  }
  return failure({
    kind: "internal",
    reason: "Modal call failed",
    provider_error: detail,
  });
}

async function call<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    throw protocolError(error);
  }
}

const kind = (error: unknown) => protocolError(error).detail.kind;

/** A Modal client for one credential: the SDK's, or a test's stand-in. */
export type Connect = (token: Token, environment?: string) => ModalClient;
const sdkClient: Connect = ({ token_id, token_secret }, environment) =>
  new ModalClient({
    tokenId: token_id,
    tokenSecret: token_secret,
    environment,
  });

export function modalModule(connect: Connect = sdkClient): ProviderModule {
  return {
    name: "modal",
    version: "0.1.0",
    smallestSize: { cpus: 0.25, memory_bytes: 512 * MiB, disk_bytes: 0 },
    async configure(name, config) {
      if (!settingsValid(config.settings ?? {}))
        refused("invalid modal settings");
      const settings = { ...DEFAULTS, ...config.settings } as Settings;
      const shared =
        (config.ownership ?? "shared_account") === "shared_account";
      return new Modal(name, settings, shared, connect);
    },
  };
}
export default modalModule();

/** Modal's sandbox lifecycle, translated: each verb is Modal's own operation
 * and each row is what Modal said. Waiting, idempotence and ownership are
 * drydockd's, as the declared semantics leave them. */
class Modal implements Provider {
  capabilities: Types["Capabilities"] = {
    material_modes: ["frozen"],
    checkout_strategies: ["clone_in_vessel"],
    workspace_root: "/workspace",
    suspend_resume: false,
    // Create and terminate answer once Modal accepted them, a terminate of an
    // ended or unknown sandbox gets Modal's own answer, and list and terminate
    // reach every sandbox in the app.
    semantics: {
      settles: false,
      idempotent: false,
      owner_scoped: false,
      token_is_id: false,
    },
    export: false,
    fallback_runner: false,
    usage: false,
    // Modal reports no quota to a token.
    quota: false,
    agent: true,
    // The agent carries outward exposures.
    reach_ways: ["outward_exposure"],
    egress: { routes: ["none", "explicit_proxy", "open"], model: EGRESS_MODEL },
    bootstrap: "bake",
    platforms: [PLATFORM],
    image_routes: [
      {
        route: "registry_pull",
        auth: "basic",
        registration: "per_request",
        digest_references: true,
        tools_layer: "provider",
      },
    ],
  };
  waysIn: Types["WayIn"][] = [{ way: "poll", interval_ms: 30_000 }];
  rateLimits: Types["RateLimit"][] = [];
  private clients: Clients<ModalClient>;
  private apps = new WeakMap<ModalClient, Promise<App>>();
  private tokens = new Map<string, string>();

  constructor(
    private name: string,
    private settings: Settings,
    private shared: boolean,
    connect: Connect,
  ) {
    this.clients = new Clients((key) =>
      connect(JSON.parse(key) as Token, settings.environment),
    );
  }

  private using<T>(
    credential: string | undefined,
    work: (client: ModalClient) => Promise<T>,
  ): Promise<T> {
    return this.clients.using(
      JSON.stringify(credentialToken(credential)),
      work,
    );
  }

  private app(client: ModalClient): Promise<App> {
    let app = this.apps.get(client);
    if (!app) {
      app = call(() =>
        client.apps.fromName(this.settings.app, {
          environment: this.settings.environment,
          createIfMissing: true,
        }),
      );
      app.catch(() => this.apps.delete(client));
      this.apps.set(client, app);
    }
    return app;
  }

  /** A handle on a sandbox by id: no Modal call until it is used. */
  private async sandbox<T>(
    client: ModalClient,
    id: string,
    work: (sandbox: Sandbox) => Promise<T>,
  ): Promise<T> {
    const sandbox = await call(() => client.sandboxes.fromId(id));
    try {
      return await work(sandbox);
    } finally {
      sandbox.detach();
    }
  }

  readiness({ credential }: Context): Types["Readiness"] {
    if (!credential)
      return {
        status: "missing_credential",
        reason: "credential not delivered",
      };
    try {
      credentialToken(credential);
    } catch (error) {
      return {
        status: "missing_credential",
        reason: (error as ProtocolFailure).message,
      };
    }
    return { status: "ready" };
  }

  private async publicRegistry(ref: ImageRef) {
    const host = ref.registry.replace(/:\d+$/, "");
    let addresses = [host];
    try {
      if (!isIP(host))
        addresses = (await lookup(host, { all: true })).map((a) => a.address);
    } catch {
      return;
    }
    if (addresses.some(privateAddress))
      refused(
        `${ref.registry} resolves to a private address; Modal pulls only from registries on the public internet`,
      );
  }

  async prepare(
    request: Types["PrepareRequest"],
    { credential, signal }: Context,
  ): Promise<Types["Prepared"]> {
    const platform = request.platform ?? PLATFORM;
    if (platform.os !== PLATFORM.os || platform.architecture !== "amd64")
      throw new ProtocolFailure({
        kind: "image_refused",
        reason: "Modal runs only linux/amd64 sandboxes",
        refusal: { cause: "unsupported_platform", platform },
      });
    if ((request.route ?? "registry_pull") !== "registry_pull")
      refused("Modal declares only the registry_pull image route");
    const base = parseImageRef(request.image_digest);
    const tools = parseImageRef(request.tools_digest);
    await this.publicRegistry(base);
    await this.publicRegistry(tools);
    const reference = (r: ImageRef) =>
      `${r.registry}/${r.repository}@${r.digest}`;
    const pull = request.image_pull ?? undefined;
    const id = await this.using(credential, async (client) => {
      const app = await this.app(client);
      signal.throwIfAborted();
      return call(async () => {
        const secret = pull
          ? await client.secrets.fromObject(
              {
                REGISTRY_USERNAME: pull.username,
                REGISTRY_PASSWORD: pull.secret,
              },
              { environment: this.settings.environment },
            )
          : undefined;
        const image = client.images
          .fromRegistry(reference(base), secret)
          .dockerfileCommands([
            `COPY --from=${reference(tools)} /opt/drydock/ /opt/drydock/`,
          ]);
        return (await image.build(app)).imageId;
      });
    });
    return {
      id,
      provider: this.name,
      platform,
      image_digest: request.image_digest,
      tools_digest: request.tools_digest,
    };
  }

  /** One create: unnamed, so Modal never refuses a label, which is a tag.
   * Then the agent starts (see `ensureAgent`). Modal answers a create with
   * the sandbox's id alone, so its state is not stated. */
  async provision(
    request: Types["ProvisionRequest"],
    { credential, signal }: Context,
  ): Promise<{ created: boolean; environment: Types["Environment"] }> {
    if (request.prepared.provider !== this.name)
      refused("prepared form belongs to another provider");
    const { cpu, memoryMiB } = resources(request.size);
    const network = networkFields(request.egress);
    const tags: Record<string, string> = { [TAGS.label]: request.label };
    if (this.shared) tags[TAGS.provider] = this.name;
    return this.using(credential, async (client) => {
      const app = await this.app(client);
      let image;
      try {
        image = await client.images.fromId(request.prepared.id);
      } catch (error) {
        if (kind(error) === "not_found") refused("unknown prepared form");
        throw protocolError(error);
      }
      signal.throwIfAborted();
      const sandbox = await call(() =>
        client.sandboxes.create(app, image, {
          tags,
          cpu,
          memoryMiB,
          timeoutMs: this.settings.lifetime_seconds * 1000,
          runtime: this.settings.runtime,
          command: ["sleep", "infinity"],
          ...network,
        }),
      );
      try {
        await this.ensureAgent(sandbox);
      } finally {
        sandbox.detach();
      }
      return {
        created: true,
        environment: {
          ...this.row(sandbox.sandboxId, undefined),
          label: request.label,
        },
      };
    });
  }

  private async ensureAgent(sandbox: Sandbox) {
    const process = await call(() =>
      sandbox.exec(
        ["sh", "-c", ensureAgent(this.settings.agent_wait_seconds)],
        {
          mode: "binary",
          stdout: "pipe",
          stderr: "ignore",
        },
      ),
    );
    const stdin = process.stdin.getWriter();
    await call(() =>
      stdin.write(
        new TextEncoder().encode(randomBytes(32).toString("base64url")),
      ),
    );
    await call(() => stdin.close());
    const [stdout, code] = await Promise.all([
      new Response(process.stdout as ReadableStream).text(),
      call(() => process.wait()),
    ]);
    const token = stdout.trim();
    if (code !== 0 || !/^[A-Za-z0-9_-]{43,}$/.test(token))
      throw new ProtocolFailure({
        kind: "internal",
        reason: "drydock's agent did not start in the Modal sandbox",
        provider_error: `exit ${code}`,
      });
    this.tokens.set(sandbox.sandboxId, token);
    return token;
  }

  /** A row of what Modal stated: `poll()`'s answer (null while the sandbox
   * runs, else its exit code) or a listing, which holds running sandboxes
   * only, and the tags read back. Modal states no size, platform, time or
   * cause of an end; the exit code is its reason. */
  private row(
    id: string,
    observed: { exit: number | null; tags: Record<string, string> } | undefined,
  ): Types["Environment"] {
    const row: Types["Environment"] = {
      provider: this.name,
      id,
      state: { state: "unknown", reason: "provider_state_unknown" },
      egress: "advisory",
    };
    if (!observed) return row;
    const { exit, tags } = observed;
    const label = tags[TAGS.label];
    return {
      ...row,
      ...(label !== undefined && { label }),
      state: exit === null ? { state: "running" } : { state: "gone" },
      vendor:
        exit === null
          ? { state: "running", tags }
          : { state: "finished", reason: `exit code ${exit}`, tags },
    };
  }

  private async listed(client: ModalClient) {
    const app = await this.app(client);
    return call(async () => {
      const sandboxes: Sandbox[] = [];
      for await (const sandbox of client.sandboxes.list({
        appId: app.appId,
        ...(this.shared && { tags: { [TAGS.provider]: this.name } }),
      }))
        sandboxes.push(sandbox);
      return sandboxes;
    });
  }

  /** Every running sandbox Modal lists in the app (on a shared account, those
   * with this instance's tag), then each one's tags. Modal's SDK list yields
   * sandbox ids alone: its wire answer has a tags field that no Modal client
   * reads ("not yet exposed in client library"), so tags take a second call
   * per sandbox, `list_concurrency` at a time. A sandbox gone between the
   * two calls is left out. */
  async list({ credential }: Context) {
    return this.using(credential, async (client) => {
      const queue = await this.listed(client);
      const rows: Types["Environment"][] = [];
      const worker = async () => {
        for (let sandbox = queue.shift(); sandbox; sandbox = queue.shift()) {
          try {
            const tags = await call(() => sandbox.getTags());
            rows.push(this.row(sandbox.sandboxId, { exit: null, tags }));
          } catch (error) {
            if (kind(error) !== "not_found") throw error;
          } finally {
            sandbox.detach();
          }
        }
      };
      try {
        await Promise.all(
          Array.from({ length: this.settings.list_concurrency }, worker),
        );
      } finally {
        // A failed read ends the list; the handles not yet read are let go.
        for (const sandbox of queue.splice(0)) sandbox.detach();
      }
      return rows;
    });
  }

  /** Modal's poll and the sandbox's tags: Modal has no one read of both. */
  async inspect(id: string, { credential }: Context) {
    return this.using(credential, (client) =>
      this.sandbox(client, id, async (sandbox) => {
        const [exit, tags] = await Promise.all([
          call(() => sandbox.poll()),
          call(() => sandbox.getTags()),
        ]);
        if (exit !== null) this.tokens.delete(id);
        return this.row(id, { exit, tags });
      }),
    );
  }

  /** Modal's terminate, which answers once Modal accepted it. */
  async destroy(id: string, { credential }: Context) {
    return this.using(credential, (client) =>
      this.sandbox(client, id, async (sandbox) => {
        this.tokens.delete(id);
        await call(() => sandbox.terminate());
      }),
    );
  }

  // The edge takes its connect token in the query, leaving Authorization to
  // the agent: https://modal.com/docs/guide/sandbox-networking. Modal states
  // no lifetime for a connect token, so the reach gives no expiry.
  async reach(id: string, { credential }: Context): Promise<Types["Reach"]> {
    return this.using(credential, (client) =>
      this.sandbox(client, id, async (sandbox) => {
        const token = this.tokens.get(id) ?? (await this.ensureAgent(sandbox));
        const connect = await call(() =>
          sandbox.createConnectToken({ port: PORT }),
        );
        const url = new URL("/v1/connect", connect.url);
        url.searchParams.set("_modal_connect_token", connect.token);
        return { kind: "dial", url: url.href, token };
      }),
    );
  }
}

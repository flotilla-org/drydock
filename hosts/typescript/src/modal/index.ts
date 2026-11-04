import { createHash, randomBytes } from "node:crypto";
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
const TAGS = {
  provider: "drydock.provider",
  label: "flotilla.label",
  egress: "drydock.egress",
  size: "drydock.size",
  expires: "drydock.expires",
} as const;
const AGENT = "/opt/drydock/drydock-agent";
const SOCKET = "/run/drydock/agent.sock";
const TOKEN_FILE = "/run/drydock/tcp.token";
const PORT = 7811;
const LIFETIME_SECONDS = 86_400;
const DIAL_SECONDS = 300;
const PLATFORM: Types["Platform"] = { os: "linux", architecture: "amd64" };
// Modal's connect-token edge (https://modal.com/docs/guide/sandbox-networking)
// was seen not to reach loopback, so the agent listens on all addresses.
const ENSURE_AGENT = [
  "t=$(head -c 256)",
  "umask 077",
  "mkdir -p /run/drydock",
  `if [ ! -s ${TOKEN_FILE} ]; then printf %s "$t" > ${TOKEN_FILE}.$$ && ln ${TOKEN_FILE}.$$ ${TOKEN_FILE} 2>/dev/null; rm -f ${TOKEN_FILE}.$$; fi`,
  `${AGENT} --supervise --tcp 0.0.0.0:${PORT} --tcp-token-file ${TOKEN_FILE} --socket ${SOCKET} || exit 1`,
  `for i in $(seq 100); do [ -S ${SOCKET} ] && exec cat ${TOKEN_FILE}; sleep 0.1; done`,
  "exit 1",
].join("\n");

type Token = { token_id: string; token_secret: string };
type Settings = {
  app?: string;
  environment?: string;
  runtime?: "vm" | "gvisor";
  concurrency_limit?: number;
};
const objectName = "^[A-Za-z0-9._-]{1,63}$";
const settingsValid = compile({
  type: "object",
  additionalProperties: false,
  properties: {
    app: { type: "string", pattern: objectName },
    environment: { type: "string", pattern: objectName },
    runtime: { enum: ["vm", "gvisor"] },
    concurrency_limit: { type: "integer", minimum: 1 },
  },
});

const hex = (value: string) => createHash("sha256").update(value).digest("hex");

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

function policyIdentity(network: Network) {
  const { outboundCidrAllowlist: cidrs, outboundDomainAllowlist: domains } =
    network;
  if (cidrs?.length === 0 && !domains?.length) return "deny";
  if (!cidrs && !domains) return "open";
  return `allow-${hex(JSON.stringify(network)).slice(0, 24)}`;
}

// Modal's disk is fixed and cannot be sized, so a requested disk is a floor
// Modal neither checks nor raises; the granted disk stays 0 (not stated).
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

function alreadyExists(error: unknown) {
  return (
    error instanceof AlreadyExistsError ||
    ((error as Error)?.name === "ClientError" &&
      (error as { code?: unknown }).code === GRPC.ALREADY_EXISTS)
  );
}

async function call<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    throw protocolError(error);
  }
}

const kind = (error: unknown) => protocolError(error).detail.kind;

export default {
  name: "modal",
  version: "0.1.0",
  smallestSize: { cpus: 0.25, memory_bytes: 512 * MiB, disk_bytes: 0 },
  async configure(name, config) {
    if (!settingsValid(config.settings ?? {}))
      refused("invalid modal settings");
    return new Modal(name, (config.settings ?? {}) as Settings);
  },
} satisfies ProviderModule;

class Modal implements Provider {
  capabilities: Types["Capabilities"] = {
    material_modes: ["frozen"],
    checkout_strategies: ["clone_in_vessel"],
    workspace_root: "/workspace",
    suspend_resume: false,
    exclusive_label: true,
    export: false,
    fallback_runner: false,
    usage: false,
    quota: true,
    agent: true,
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
  observation: Types["ObservationMode"] = { mode: "poll", interval_ms: 30_000 };
  rateLimits: Types["RateLimit"][] = [];
  private clients: Clients<ModalClient>;
  private apps = new WeakMap<ModalClient, Promise<App>>();
  private destroyed = new Set<string>();
  private tokens = new Map<string, string>();
  private appName: string;

  constructor(
    private name: string,
    private settings: Settings,
  ) {
    this.appName = settings.app ?? "drydock";
    this.clients = new Clients((key) => {
      const { token_id, token_secret } = JSON.parse(key) as Token;
      return new ModalClient({
        tokenId: token_id,
        tokenSecret: token_secret,
        environment: settings.environment,
      });
    });
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
        client.apps.fromName(this.appName, {
          environment: this.settings.environment,
          createIfMissing: true,
        }),
      );
      app.catch(() => this.apps.delete(client));
      this.apps.set(client, app);
    }
    return app;
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

  async provision(
    request: Types["ProvisionRequest"],
    { credential, signal }: Context,
  ): Promise<{ created: boolean; environment: Types["Environment"] }> {
    if (request.prepared.provider !== this.name)
      refused("prepared form belongs to another provider");
    const { cpu, memoryMiB } = resources(request.size);
    const network = networkFields(request.egress);
    const tags = {
      [TAGS.provider]: this.name,
      [TAGS.label]: request.label,
      [TAGS.egress]: policyIdentity(network),
      [TAGS.size]: `${cpu}/${memoryMiB}`,
    };
    const name = `drydock-${hex(request.label).slice(0, 24)}`;
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
      let created = true;
      let sandbox: Sandbox;
      try {
        sandbox = await client.sandboxes.create(app, image, {
          name,
          tags: {
            ...tags,
            [TAGS.expires]: String(
              Math.floor(Date.now() / 1000) + LIFETIME_SECONDS,
            ),
          },
          cpu,
          memoryMiB,
          timeoutMs: LIFETIME_SECONDS * 1000,
          runtime: this.settings.runtime ?? "vm",
          command: ["sleep", "infinity"],
          ...network,
        });
      } catch (error) {
        if (!alreadyExists(error)) throw protocolError(error);
        sandbox = await call(() =>
          client.sandboxes.fromName(this.appName, name, {
            environment: this.settings.environment,
          }),
        );
        created = false;
      }
      try {
        const actual = await call(() => sandbox.getTags());
        if (!created) this.adopt(actual, tags);
        await this.ensureAgent(sandbox);
        return {
          created,
          environment: this.row(sandbox.sandboxId, actual, null),
        };
      } catch (error) {
        if (created) await sandbox.terminate().catch(() => {});
        throw error;
      } finally {
        sandbox.detach();
      }
    });
  }

  private adopt(
    actual: Record<string, string>,
    wanted: Record<string, string>,
  ) {
    if (
      actual[TAGS.provider] !== wanted[TAGS.provider] ||
      actual[TAGS.label] !== wanted[TAGS.label]
    )
      refused(
        "a Modal sandbox with this label's name belongs to another provider or label",
      );
    for (const [tag, what] of [
      [TAGS.size, "size"],
      [TAGS.egress, "egress policy"],
    ])
      if (actual[tag] !== wanted[tag])
        refused(
          `existing Modal sandbox for this label has a different ${what} (${actual[tag] ?? "none"}, requested ${wanted[tag]}); provision a new label`,
        );
  }

  private async ensureAgent(sandbox: Sandbox) {
    const process = await call(() =>
      sandbox.exec(["sh", "-c", ENSURE_AGENT], {
        mode: "binary",
        stdout: "pipe",
        stderr: "ignore",
      }),
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

  private row(
    id: string,
    tags: Record<string, string>,
    code: number | null,
  ): Types["Environment"] {
    const [cpus, mib] = (tags[TAGS.size] ?? "").split("/").map(Number);
    return {
      provider: this.name,
      id,
      label: tags[TAGS.label] ?? null,
      state: code === null ? { state: "running" } : this.gone(id, tags, code),
      granted_size:
        cpus > 0 && mib > 0
          ? { cpus, memory_bytes: mib * MiB, disk_bytes: 0 }
          : null,
      platform: PLATFORM,
      egress: "advisory",
      egress_policy: tags[TAGS.egress] ?? null,
      timestamp: null,
    };
  }

  // Terminate exits 137 (https://modal.com/docs/guide/sandbox); a timeout was
  // seen to exit 124.
  private gone(
    id: string,
    tags: Record<string, string>,
    code: number,
  ): Types["Observation"] {
    const expires = Number(tags[TAGS.expires]);
    const capped =
      code === 124 ||
      (code === 137 && expires > 0 && Date.now() / 1000 >= expires);
    return {
      state: "gone",
      cause: capped
        ? { kind: "lifetime_cap_reached" }
        : this.destroyed.has(id)
          ? { kind: "destroyed_by_request" }
          : code === 137
            ? { kind: "destroyed_at_provider" }
            : { kind: "guest_powered_off" },
    };
  }

  private async owned(client: ModalClient, id: string) {
    const sandbox = await call(() => client.sandboxes.fromId(id));
    const tags = await call(() => sandbox.getTags());
    if (tags[TAGS.provider] !== this.name)
      throw new ProtocolFailure({
        kind: "not_found",
        reason: "no such sandbox for this provider",
      });
    return { sandbox, tags };
  }

  private async listed(client: ModalClient) {
    const app = await this.app(client);
    return call(async () => {
      const sandboxes: Sandbox[] = [];
      for await (const sandbox of client.sandboxes.list({
        appId: app.appId,
        tags: { [TAGS.provider]: this.name },
      }))
        sandboxes.push(sandbox);
      return sandboxes;
    });
  }

  async list({ credential }: Context) {
    return this.using(credential, async (client) => {
      const queue = await this.listed(client);
      const rows: Types["Environment"][] = [];
      const worker = async () => {
        for (let sandbox = queue.shift(); sandbox; sandbox = queue.shift()) {
          try {
            const tags = await call(() => sandbox.getTags());
            rows.push(this.row(sandbox.sandboxId, tags, null));
          } catch (error) {
            if (kind(error) !== "not_found") throw error;
          }
        }
      };
      await Promise.all(Array.from({ length: 8 }, worker));
      return rows;
    });
  }

  async inspect(id: string, { credential }: Context) {
    return this.using(credential, async (client) => {
      const { sandbox, tags } = await this.owned(client, id);
      try {
        const code = await call(() => sandbox.poll());
        if (code !== null) this.tokens.delete(id);
        return this.row(sandbox.sandboxId, tags, code);
      } finally {
        sandbox.detach();
      }
    });
  }

  async destroy(id: string, { credential }: Context) {
    return this.using(credential, async (client) => {
      let sandbox: Sandbox;
      try {
        ({ sandbox } = await this.owned(client, id));
      } catch (error) {
        if (kind(error) === "not_found") return;
        throw error;
      }
      this.destroyed.add(id);
      this.tokens.delete(id);
      try {
        await call(() => sandbox.terminate({ wait: true }));
      } catch (error) {
        if (kind(error) !== "not_found") {
          this.destroyed.delete(id);
          throw error;
        }
      } finally {
        sandbox.detach();
      }
    });
  }

  // The edge takes its connect token in the query, leaving Authorization to
  // the agent: https://modal.com/docs/guide/sandbox-networking
  async reach(id: string, { credential }: Context): Promise<Types["Reach"]> {
    return this.using(credential, async (client) => {
      const { sandbox } = await this.owned(client, id);
      try {
        if ((await call(() => sandbox.poll())) !== null)
          refused("Modal sandbox has terminated");
        const token = this.tokens.get(id) ?? (await this.ensureAgent(sandbox));
        const connect = await call(() =>
          sandbox.createConnectToken({ port: PORT }),
        );
        const url = new URL("/v1/connect", connect.url);
        url.searchParams.set("_modal_connect_token", connect.token);
        return {
          kind: "dial",
          url: url.href,
          token,
          expires_at: new Date(Date.now() + DIAL_SECONDS * 1000).toISOString(),
        };
      } finally {
        sandbox.detach();
      }
    });
  }

  async quota({ credential }: Context): Promise<Types["Quota"]> {
    return this.using(credential, async (client) => {
      const count = (await this.listed(client)).length;
      return {
        resources: [],
        credits_remaining: null,
        credit_unit: null,
        concurrency_in_use: count,
        concurrency_limit: this.settings.concurrency_limit ?? null,
      };
    });
  }
}

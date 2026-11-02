// Modal sandboxes through the JavaScript SDK (owner ruling 2026-11-02: the
// TypeScript host, reached by the exec bridge). One Modal app per provider
// instance holds every sandbox. Prepare has Modal build the base by digest
// with the tools image copied in; provision creates a named, tagged sandbox
// whose command starts drydock's agent; drydock reaches it through the relay
// route, which this module carries over an exec of `drydock-agent --bridge`.
// Sandboxes cannot be suspended, and live at most a day.
import { createHash, randomBytes } from "node:crypto";
import { lookup } from "node:dns/promises";
import { BlockList, isIP, isIPv4, isIPv6 } from "node:net";
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
import { Clients } from "../clients.js";
import {
  alreadyExists,
  call,
  protocolError,
  sdkVendor,
  type App,
  type Box,
  type Create,
  type Token,
  type Vendor,
} from "./vendor.js";

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;
/** Sandbox tags: the owning provider instance, the client's label, and the facts re-adoption checks. */
export const TAGS = {
  provider: "drydock.provider",
  label: "flotilla.label",
  egress: "drydock.egress",
  size: "drydock.size",
  /** Unix seconds when the sandbox reaches its timeout. */
  expires: "drydock.expires",
} as const;
export const AGENT = "/opt/drydock/drydock-agent";
export const SOCKET = "/run/drydock/agent.sock";
/** The agent's TCP token, root's alone (0600). */
export const TOKEN_FILE = "/run/drydock/tcp.token";
/** The agent's TCP listener, which connect tokens route to. */
export const PORT = 7811;
/** Where the agent's listener takes its handshake (drydock-transport's `CONNECT_PATH`). */
export const CONNECT_PATH = "/v1/connect";
/** Modal's edge takes its connect token here, leaving `Authorization` to the agent. */
export const CONNECT_TOKEN_PARAM = "_modal_connect_token";
/** Modal's longest sandbox lifetime; the default is five minutes. */
export const LIFETIME_SECONDS = 86_400;
/**
 * The sandbox command (it replaces the image's, and is not an init). It only
 * keeps the sandbox alive: the agent needs its token, which reaches it by exec.
 */
export const COMMAND = ["sleep", "infinity"];
/**
 * Run as root with a fresh token on stdin: keeps the token already in the
 * sandbox, if any (written once, atomically, 0600), starts the agent's
 * supervisor with its TCP listener (its lock makes that idempotent; `--socket`
 * must come last), waits for the socket, and prints the token in use. The
 * token is never on an argv or in the environment.
 */
export const ENSURE_AGENT = [
  "t=$(head -c 256)",
  "umask 077",
  "mkdir -p /run/drydock",
  `if [ ! -s ${TOKEN_FILE} ]; then printf %s "$t" > ${TOKEN_FILE}.$$ && ln ${TOKEN_FILE}.$$ ${TOKEN_FILE} 2>/dev/null; rm -f ${TOKEN_FILE}.$$; fi`,
  `${AGENT} --supervise --tcp 127.0.0.1:${PORT} --tcp-token-file ${TOKEN_FILE} --socket ${SOCKET} || exit 1`,
  `for i in $(seq 100); do [ -S ${SOCKET} ] && exec cat ${TOKEN_FILE}; sleep 0.1; done`,
  "exit 1",
].join("\n");
/** How long a reach's connect token is offered for; drydock dials at once. */
const DIAL_SECONDS = 300;
const PLATFORM: Types["Platform"] = { os: "linux", architecture: "amd64" };
/** Concurrent tag reads while listing. */
const READS = 8;

const objectName = "^[A-Za-z0-9._-]{1,63}$";
const settingsValid = compile({
  type: "object",
  additionalProperties: false,
  properties: {
    /** The app holding every sandbox of this instance (default `drydock`). */
    app: { type: "string", pattern: objectName },
    environment: { type: "string", pattern: objectName },
    runtime: { enum: ["vm", "gvisor"] },
    concurrency_limit: { type: "integer", minimum: 1 },
    /** Operator-supplied egress conformance command, run as root on inspect. */
    egress_probe: {
      type: "object",
      additionalProperties: false,
      required: ["command"],
      properties: {
        command: {
          type: "array",
          minItems: 1,
          items: { type: "string", minLength: 1 },
        },
      },
    },
  },
});
type Settings = {
  app?: string;
  environment?: string;
  runtime?: "vm" | "gvisor";
  concurrency_limit?: number;
  egress_probe?: { command: string[] };
};

const hex = (value: string) => createHash("sha256").update(value).digest("hex");

/** Addresses Modal's builders cannot reach: Modal pulls only from the public internet. */
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

export function privateAddress(address: string) {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address)?.[1];
  if (mapped) return PRIVATE.check(mapped, "ipv4");
  return PRIVATE.check(address, isIPv6(address) ? "ipv6" : "ipv4");
}

/** Every address a registry host resolves to here; a literal is itself. */
export type Resolve = (host: string) => Promise<string[]>;
const resolveHost: Resolve = async (host) =>
  (await lookup(host, { all: true })).map((a) => a.address);

/**
 * Egress as Modal's create fields. An absent request is the protocol's
 * default, deny all. IPv4 CIDRs and literals become the CIDR allowlist and
 * names the domain allowlist; ports and IPv6 are refused, never widened.
 */
export function networkFields(
  egress: Types["EgressRequest"] | undefined,
): Pick<
  Create,
  "blockNetwork" | "outboundCidrAllowlist" | "outboundDomainAllowlist"
> {
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
  if (!cidrs.size && !domains.size) return { blockNetwork: true };
  return {
    ...(cidrs.size && { outboundCidrAllowlist: [...cidrs].sort() }),
    ...(domains.size && { outboundDomainAllowlist: [...domains].sort() }),
  };
}

/** A tag-sized identity of a policy, and whether it denies everything. */
function policyIdentity(fields: ReturnType<typeof networkFields>) {
  if (fields.blockNetwork) return "deny";
  if (!fields.outboundCidrAllowlist && !fields.outboundDomainAllowlist)
    return "open";
  return `allow-${hex(JSON.stringify(fields)).slice(0, 24)}`;
}

/** Modal's resources for a size: fractional CPUs, whole MiB, no disk. */
function resources(size: Types["Size"]) {
  if (size.disk_bytes !== 0)
    refused("Modal sandboxes have no disk size; request disk 0");
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
  return token as Token;
}

export function modalModule(
  vendor: (token: Token, environment?: string) => Vendor = sdkVendor,
  resolve: Resolve = resolveHost,
  now: () => number = Date.now,
): ProviderModule {
  return {
    name: "modal",
    version: "0.1.0",
    smallestSize: { cpus: 0.25, memory_bytes: 512 * MiB, disk_bytes: 0 },
    async configure(name, config) {
      if (!settingsValid(config.settings ?? {}))
        refused("invalid modal settings");
      return new Modal(
        name,
        (config.settings ?? {}) as Settings,
        vendor,
        resolve,
        now,
      );
    },
  };
}
export default modalModule();

class Modal implements Provider {
  capabilities: Types["Capabilities"] = {
    material_modes: ["frozen"],
    checkout_strategies: ["clone_in_vessel"],
    workspace_root: "/workspace",
    suspend_resume: false,
    export: false,
    // Modal execs could run commands, but this host has no exec port until
    // drydock#85, and the daemon refuses a declaration without its port.
    fallback_runner: false,
    usage: false,
    quota: true,
    agent: true,
    // Destinations are enforced outside the guest, against root, by a
    // transparent proxy: a connect succeeds, but an unlisted destination is
    // reset at TLS or HTTP. DNS resolution is never filtered; `egress_probe`
    // measures each vessel.
    egress: {
      routes: ["none", "explicit_proxy", "open"],
      enforcement: "enforced",
    },
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
  private clients: Clients<Vendor>;
  /** The app's handle per client; one lookup (or create) each. */
  private apps = new WeakMap<Vendor, Promise<App>>();
  /**
   * Sandboxes this host terminated, so their end reads as requested. It is
   * process-local: after a host restart such an end reads as destroyed at the
   * provider. Modal lists no terminated sandboxes, so it stays small.
   */
  private destroyed = new Set<string>();
  /** Each sandbox's agent TCP token, as `ensureAgent` last read it. */
  private tokens = new Map<string, string>();
  private appName: string;

  constructor(
    private name: string,
    private settings: Settings,
    connect: (token: Token, environment?: string) => Vendor,
    private resolve: Resolve,
    private now: () => number,
  ) {
    this.appName = settings.app ?? "drydock";
    this.clients = new Clients((key) =>
      connect(JSON.parse(key), settings.environment),
    );
  }

  private key(credential: string | undefined) {
    const { token_id, token_secret } = credentialToken(credential);
    return JSON.stringify({ token_id, token_secret });
  }

  private using<T>(
    credential: string | undefined,
    work: (vendor: Vendor) => Promise<T>,
  ): Promise<T> {
    return this.clients.using(this.key(credential), work);
  }

  private app(vendor: Vendor): Promise<App> {
    let app = this.apps.get(vendor);
    if (!app) {
      app = call(() => vendor.app(this.appName));
      app.catch(() => this.apps.delete(vendor));
      this.apps.set(vendor, app);
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

  /**
   * Refuses a registry Modal's builders cannot reach, before building. A
   * best-effort check of what it resolves to here: Modal resolves again, and
   * a name unknown here goes on to fail (or not) in Modal's build.
   */
  private async publicRegistry(ref: ImageRef) {
    const host = ref.registry.replace(/:\d+$/, "");
    let addresses = [host];
    try {
      if (!isIP(host)) addresses = await this.resolve(host);
    } catch {
      // Modal resolves names itself; one unknown here may still be public.
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
    const id = await this.using(credential, async (vendor) => {
      const app = await this.app(vendor);
      // The SDK takes no signal: an abort is seen between calls, never
      // during one, so a build already started runs to its end.
      signal.throwIfAborted();
      // Modal caches by definition, so the same digests give the same image.
      return call(() =>
        vendor.build(app, {
          base: reference(base),
          commands: [
            `COPY --from=${reference(tools)} /opt/drydock/ /opt/drydock/`,
          ],
          // The pull credential is the base's registry's, and goes nowhere else.
          pull: pull && { username: pull.username, password: pull.secret },
        }),
      );
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
    const egress = networkFields(request.egress);
    const tags = {
      [TAGS.provider]: this.name,
      [TAGS.label]: request.label,
      [TAGS.egress]: policyIdentity(egress),
      [TAGS.size]: `${cpu}/${memoryMiB}`,
    };
    const name = `drydock-${hex(request.label).slice(0, 24)}`;
    return this.using(credential, async (vendor) => {
      const app = await this.app(vendor);
      try {
        await call(() => vendor.image(request.prepared.id));
      } catch (error) {
        if (protocolError(error).detail.kind === "not_found")
          refused("unknown prepared form");
        throw error;
      }
      signal.throwIfAborted();
      let created = true;
      let box: Box;
      try {
        box = await vendor.create(app, request.prepared.id, {
          name,
          tags: {
            ...tags,
            [TAGS.expires]: String(
              Math.floor(this.now() / 1000) + LIFETIME_SECONDS,
            ),
          },
          cpu,
          memoryMiB,
          timeoutMs: LIFETIME_SECONDS * 1000,
          runtime: this.settings.runtime ?? "vm",
          command: COMMAND,
          ...egress,
        });
      } catch (error) {
        // The name is the label's: a running sandbox already holds it.
        if (!alreadyExists(error)) throw protocolError(error);
        box = await call(() => vendor.fromName(this.appName, name));
        created = false;
      }
      try {
        const actual = await call(() => box.getTags());
        if (!created) this.adopt(actual, tags);
        await this.ensureAgent(box);
        return {
          created,
          environment: await this.observe(box, actual, signal),
        };
      } catch (error) {
        // A sandbox this call made and cannot hand over would run for a day.
        if (created) await box.terminate().catch(() => {});
        throw error;
      } finally {
        box.detach();
      }
    });
  }

  /** Refuses a sandbox under this name that is not this request's (drydock#168). */
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

  /** Runs a command to its end, with `input` as its whole stdin; its exit code and stdout. */
  private async run(box: Box, argv: string[], input = "") {
    const process = await call(() => box.exec(argv));
    // An exec keeps running until its stdin ends.
    const stdin = process.stdin.getWriter();
    if (input) await call(() => stdin.write(new TextEncoder().encode(input)));
    await call(() => stdin.close());
    const [stdout, code] = await Promise.all([
      new Response(process.stdout as ReadableStream).text(),
      call(() => process.wait()),
    ]);
    return { code, stdout };
  }

  /** Starts the agent if it is not running; the TCP token it holds. */
  private async ensureAgent(box: Box) {
    const fresh = randomBytes(32).toString("base64url");
    const { code, stdout } = await this.run(
      box,
      ["sh", "-c", ENSURE_AGENT],
      fresh,
    );
    const token = stdout.trim();
    if (code !== 0 || !/^[A-Za-z0-9_-]{43,}$/.test(token))
      throw new ProtocolFailure({
        kind: "internal",
        reason: "drydock's agent did not start in the Modal sandbox",
        provider_error: `exit ${code}`,
      });
    this.tokens.set(box.sandboxId, token);
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
      egress: "enforced",
      egress_measured: false,
      egress_policy: tags[TAGS.egress] ?? null,
      timestamp: null,
    };
  }

  /** Why a sandbox ended: 124 is Modal's timeout, 137 a termination. */
  private gone(
    id: string,
    tags: Record<string, string>,
    code: number,
  ): Types["Observation"] {
    const expires = Number(tags[TAGS.expires]);
    const capped =
      code === 124 ||
      (code === 137 && expires > 0 && this.now() / 1000 >= expires);
    return {
      state: "gone",
      cause: capped
        ? { kind: "lifetime_cap_reached" }
        : this.destroyed.has(id)
          ? { kind: "destroyed_by_request" }
          : code === 137
            ? { kind: "destroyed_at_provider" }
            : // The sandbox command never exits on its own.
              { kind: "guest_powered_off" },
    };
  }

  /**
   * The row, measuring a restricted running sandbox's egress with the
   * operator's probe. DNS is never filtered, so a probe that counts it
   * reports advisory.
   */
  private async observe(
    box: Box,
    tags: Record<string, string>,
    signal: AbortSignal,
    code: number | null = null,
  ): Promise<Types["Environment"]> {
    const row = this.row(box.sandboxId, tags, code);
    const probe = this.settings.egress_probe;
    const policy = row.egress_policy ?? "open";
    if (!probe || policy === "open" || code !== null) return row;
    signal.throwIfAborted();
    const deny = policy === "deny" ? "1" : "0";
    try {
      const result = await this.run(box, [
        "sh",
        "-c",
        `test "$(id -u)" = 0 && DRYDOCK_PROBE_DENY_ALL=${deny} exec "$@"`,
        "probe",
        ...probe.command,
      ]);
      if (result.code !== 0) return row;
      const proof = JSON.parse(result.stdout);
      const flags = ["unlisted_canary", "raw_dns"];
      if (deny === "0") flags.push("listed_direct");
      if (
        typeof proof?.uid !== "number" ||
        flags.some((f) => typeof proof[f] !== "boolean")
      )
        return row;
      const enforced =
        proof.uid === 0 &&
        proof.unlisted_canary === false &&
        proof.raw_dns === false &&
        (deny === "1" || proof.listed_direct === true);
      return {
        ...row,
        egress: enforced ? "enforced" : "advisory",
        egress_measured: true,
      };
    } catch {
      // A failed probe still returns the environment, unmeasured.
      return row;
    }
  }

  /** This provider's sandbox by id, or not found; tags say whose it is. */
  private async owned(vendor: Vendor, id: string) {
    const box = await call(() => vendor.fromId(id));
    const tags = await call(() => box.getTags());
    if (tags[TAGS.provider] !== this.name)
      throw new ProtocolFailure({
        kind: "not_found",
        reason: "no such sandbox for this provider",
      });
    return { box, tags };
  }

  /** Running sandboxes of this instance; Modal lists no terminated ones. */
  private async listed(vendor: Vendor) {
    const app = await this.app(vendor);
    return call(async () => {
      const boxes: Box[] = [];
      for await (const box of vendor.list(app.appId, {
        [TAGS.provider]: this.name,
      }))
        boxes.push(box);
      return boxes;
    });
  }

  async list({ credential }: Context) {
    return this.using(credential, async (vendor) => {
      const queue = await this.listed(vendor);
      const rows: Types["Environment"][] = [];
      const worker = async () => {
        for (let box = queue.shift(); box; box = queue.shift()) {
          try {
            rows.push(
              this.row(box.sandboxId, await call(() => box.getTags()), null),
            );
          } catch (error) {
            if (protocolError(error).detail.kind !== "not_found") throw error;
          }
        }
      };
      await Promise.all(Array.from({ length: READS }, worker));
      return rows;
    });
  }

  async inspect(id: string, { credential, signal }: Context) {
    return this.using(credential, async (vendor) => {
      const { box, tags } = await this.owned(vendor, id);
      try {
        const code = await call(() => box.poll());
        return await this.observe(box, tags, signal, code);
      } finally {
        box.detach();
      }
    });
  }

  async destroy(id: string, { credential }: Context) {
    return this.using(credential, async (vendor) => {
      let box: Box;
      try {
        ({ box } = await this.owned(vendor, id));
      } catch (error) {
        // Destroy is idempotent: an absent sandbox is already destroyed.
        if (protocolError(error).detail.kind === "not_found") return;
        throw error;
      }
      this.destroyed.add(id);
      this.tokens.delete(id);
      try {
        await call(() => box.terminate());
      } catch (error) {
        if (protocolError(error).detail.kind !== "not_found") {
          // Not ours to claim: a later end is someone else's.
          this.destroyed.delete(id);
          throw error;
        }
      } finally {
        box.detach();
      }
    });
  }

  /** A running sandbox of this provider; a terminated one is refused, not retried. */
  private async running(vendor: Vendor, id: string) {
    const { box } = await this.owned(vendor, id);
    if ((await call(() => box.poll())) !== null) {
      box.detach();
      refused("Modal sandbox has terminated");
    }
    return box;
  }

  // Reach is the agent's TCP listener behind Modal's connect-token edge:
  // drydock dials it (Reach::Dial). The edge takes its token from the query
  // and splices the bytes after the agent's 101; `Authorization` carries the
  // agent's token. Exec carries no agent traffic.
  async reach(id: string, { credential }: Context): Promise<Types["Reach"]> {
    return this.using(credential, async (vendor) => {
      const box = await this.running(vendor, id);
      try {
        // After a host restart, the token is read back from the sandbox.
        const token = this.tokens.get(id) ?? (await this.ensureAgent(box));
        const connect = await call(() => box.connectToken(PORT));
        const url = new URL(CONNECT_PATH, connect.url);
        url.searchParams.set(CONNECT_TOKEN_PARAM, connect.token);
        return {
          kind: "dial",
          url: url.href,
          token,
          expires_at: new Date(this.now() + DIAL_SECONDS * 1000).toISOString(),
        };
      } finally {
        box.detach();
      }
    });
  }

  async quota({ credential }: Context): Promise<Types["Quota"]> {
    return this.using(credential, async (vendor) => {
      const count = (await this.listed(vendor)).length;
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

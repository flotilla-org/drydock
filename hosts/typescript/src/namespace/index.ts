// Namespace devboxes through `@namespacelabs/sdk/devbox` (owner ruling
// 2026-10-19: devboxes and the SDK, not the public compute API). Each verb is
// Namespace's own operation and each answer is what Namespace said; waiting,
// idempotence and ownership are drydockd's, as the declared semantics leave
// them (see `capabilities`). Prepare
// layers the tools image onto the base here and registers the result; the
// agent runs as a devbox service, because PID 1 is Namespace's own agent and
// the image's entrypoint never runs; drydock reaches it through the relay
// route, which this module carries over an SSH exec channel to
// `drydock-agent --bridge`. Suspend is devbox stop: files survive, memory not.
import { createHash, randomBytes } from "node:crypto";
import type { Duplex } from "node:stream";
import type { NetworkPolicy } from "@namespacelabs/sdk/devbox";
import {
  compose,
  copyBlob,
  parseImageRef,
  Registry,
  type ImageRef,
  type Fetch,
} from "../oci.js";
import {
  ProtocolFailure,
  refused,
  type Context,
  type Provider,
  type ProviderModule,
  type Types,
} from "../provider.js";
import { compile } from "../validation.js";
import {
  call,
  protocolError,
  sdkVendor,
  type Box,
  type Vendor,
} from "./vendor.js";

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;
/** The devbox label holding the client's label: its name, not a handle. */
export const LABEL = "drydock.label";
/** The devbox label naming the instance that made it, on a shared account. */
export const OWNER = "drydock.provider";
/** The devbox label holding the egress policy identity requested at create. */
export const POLICY = "drydock.egress";
export const SERVICE = "drydock-agent";
export const AGENT = "/opt/drydock/drydock-agent";
const PLATFORM: Types["Platform"] = { os: "linux", architecture: "amd64" };
const REGISTRY = "nscr.io";
/**
 * Linux machine sizes, as the SDK resolves them client-side. Namespace sells
 * these fixed shapes; the SDK keeps its table private and offers no call that
 * lists them, so the table is copied here.
 */
const SIZES: Record<string, { cpus: number; memoryMB: number }> = {
  s: { cpus: 4, memoryMB: 8 * 1024 },
  m: { cpus: 8, memoryMB: 16 * 1024 },
  l: { cpus: 16, memoryMB: 32 * 1024 },
  xl: { cpus: 32, memoryMB: 64 * 1024 },
};

const component = "[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?";
const settingsValid = compile({
  type: "object",
  additionalProperties: false,
  required: ["workspace"],
  properties: {
    /** The workspace's registry namespace: images go to nscr.io/<workspace>/. */
    workspace: { type: "string", pattern: `^${component}$` },
    repository: { type: "string", pattern: `^${component}(?:/${component})*$` },
    site: { type: "string", minLength: 1 },
    push_chunk_bytes: { type: "integer", minimum: 1 },
    /** How often drydockd lists this instance's devboxes. */
    poll_interval_ms: { type: "integer", minimum: 1 },
    /** Concurrent `refresh` calls while listing. */
    list_refreshes: { type: "integer", minimum: 1 },
    /** Operator-supplied egress conformance command, run on inspect. */
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
  workspace: string;
  repository?: string;
  site?: string;
  push_chunk_bytes?: number;
  poll_interval_ms?: number;
  list_refreshes?: number;
  egress_probe?: { command: string[] };
};

const hex = (value: string) => createHash("sha256").update(value).digest("hex");
const samePlatform = (a: Types["Platform"], b: Types["Platform"]) =>
  a.os === b.os && a.architecture === b.architecture;

/** The registered image's name: its key is both digests and the platform. */
export function imageName(
  imageDigest: string,
  toolsDigest: string,
  platform: Types["Platform"],
) {
  const key = [imageDigest, toolsDigest, platform.os, platform.architecture];
  return `drydock-${hex(JSON.stringify(key)).slice(0, 32)}`;
}

/** A named machine size and volume for a requested size; others are refused. */
function machine(size: Types["Size"]) {
  const name = Object.entries(SIZES).find(
    ([, s]) => s.cpus === size.cpus && s.memoryMB * MiB === size.memory_bytes,
  )?.[0];
  if (!name)
    refused(
      `Namespace sizes are ${Object.values(SIZES)
        .map((s) => `${s.cpus} CPUs with ${s.memoryMB / 1024} GiB`)
        .join(", ")}`,
    );
  if (size.disk_bytes % GiB !== 0) refused("Namespace volumes are whole GiB");
  return {
    size: name,
    volumeSizeGB: size.disk_bytes ? size.disk_bytes / GiB : undefined,
  };
}

/**
 * Egress as a devbox network policy, or undefined for open egress. An absent
 * request is the protocol's default, deny all (fail closed). Host names map to
 * allowed domains; anything Namespace cannot express is refused, never widened.
 */
export function networkPolicy(
  egress: Types["EgressRequest"] | undefined,
): NetworkPolicy | undefined {
  if (egress?.mode === "open") return undefined;
  const domains = new Set<string>();
  for (const entry of egress?.direct ?? []) {
    if (entry.kind === "cidr")
      refused("Namespace network policies cannot allow CIDRs");
    if (entry.kind === "host_port")
      refused("Namespace network policies cannot restrict ports");
    if (entry.host.includes(":") || /^[0-9.]+$/.test(entry.host))
      refused("Namespace network policies allow domain names only");
    domains.add(entry.host);
  }
  return { allowedDomains: [...domains].sort(), advisory: false };
}

const DOCS = "https://namespace.so/docs";
/**
 * Namespace's egress as its documentation states it (2026-11-03). The module
 * applies devbox `networkPolicy.allowedDomains` with `advisory: false`; an
 * empty list denies all (see `networkPolicy`).
 */
export const EGRESS_MODEL: Types["EgressModel"] = {
  shapes: ["open", "deny_all", "allow_domains"],
  // Namespace's egress filtering runs outside the workload; the docs do not
  // say whether guest root can bypass it.
  enforced: "outside_guest",
  side_effects: [
    {
      shapes: ["deny_all", "allow_domains"],
      note: "Namespace infrastructure domains are always allowed.",
    },
  ],
  // `devbox.update()` accepts a network policy, but the docs do not say
  // whether a running devbox picks it up.
  mutable_while_running: false,
  sources: [
    `${DOCS}/reference/typescript-sdk/devbox/manage`,
    `${DOCS}/reference/devbox-cli/spec-file#network-policy`,
    `${DOCS}/security/egress-policy`,
  ],
};

/** A label-sized identity of a policy, and whether it denies everything. */
function policyIdentity(policy: NetworkPolicy | undefined) {
  if (!policy) return "open";
  const kind = policy.allowedDomains.length ? "domains" : "deny";
  return `${kind}-${hex(JSON.stringify(policy)).slice(0, 24)}`;
}

function credentialToken(credential: string | undefined): string {
  let token: unknown;
  try {
    token = JSON.parse(credential ?? "").bearer_token;
  } catch {}
  if (typeof token !== "string" || !token)
    throw new ProtocolFailure({
      kind: "credential_rejected",
      reason: 'Namespace credential must be {"bearer_token": …}',
    });
  return token;
}

export function namespaceModule(
  vendor: (token: string) => Vendor = sdkVendor,
  fetcher: Fetch = fetch,
): ProviderModule {
  return {
    name: "namespace",
    version: "0.1.0",
    smallestSize: { cpus: 4, memory_bytes: 8 * GiB, disk_bytes: 0 },
    async configure(name, config) {
      if (!settingsValid(config.settings ?? {}))
        refused("invalid namespace settings");
      return new Namespace(
        name,
        config.settings as Settings,
        config.ownership ?? "shared_account",
        vendor,
        fetcher,
      );
    },
  };
}
export default namespaceModule();

class Namespace implements Provider {
  capabilities: Types["Capabilities"] = {
    material_modes: ["frozen"],
    checkout_strategies: ["clone_in_vessel"],
    workspace_root: "/workspace",
    suspend_resume: true,
    // A label is the client's name for what it made: every provision creates.
    exclusive_label: false,
    // Each verb is Namespace's own operation: no waiting, no already-done
    // success, no ownership check. Namespace resumes by id.
    semantics: {
      settles: false,
      idempotent: false,
      owner_scoped: false,
      token_is_id: true,
    },
    // Devbox stop keeps the filesystem; memory and processes are lost.
    suspend_preserves_memory: false,
    export: false,
    fallback_runner: false,
    usage: false,
    quota: true,
    agent: true,
    // The agent carries outward exposures.
    reach_ways: ["outward_exposure"],
    // Enforced per environment only when the operator's probe passes as
    // root (see `egress_probe`).
    egress: { routes: ["none", "explicit_proxy", "open"], model: EGRESS_MODEL },
    bootstrap: "bake",
    platforms: [PLATFORM],
    image_routes: [
      {
        route: "provider_push",
        protocol: "oci_distribution",
        credential_lifetime_seconds: null,
        tools_layer: "host",
      },
    ],
  };
  // Namespace offers no webhooks or state stream (WaitInstance streams only
  // until an instance runs), so listing is the only way to hear of a stop at
  // its idle or lifetime cap.
  waysIn: Types["WayIn"][];
  rateLimits: Types["RateLimit"][] = [];
  /** SDK clients by token, with the calls and relays using each. */
  private clients = new Map<
    string,
    { vendor: Vendor; users: number; current: boolean }
  >();

  constructor(
    private name: string,
    private settings: Settings,
    private ownership: Types["Ownership"],
    private connect: (token: string) => Vendor,
    private fetcher: Fetch,
  ) {
    this.waysIn = [
      { way: "poll", interval_ms: settings.poll_interval_ms ?? 30_000 },
    ];
  }

  /**
   * The SDK client for the credential a call carries, held until `release`.
   * A client a newer credential replaced closes once its last call and relay
   * end, so rotating the credential never cuts a live agent connection.
   */
  private acquire(credential: string | undefined) {
    const token = credentialToken(credential);
    let client = this.clients.get(token);
    if (!client?.current) {
      for (const other of this.clients.values()) other.current = false;
      client ??= { vendor: this.connect(token), users: 0, current: true };
      client.current = true;
      this.clients.set(token, client);
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

  /** Closes replaced clients that nothing uses any more. */
  private retire() {
    for (const [token, client] of this.clients)
      if (!client.current && client.users === 0) {
        client.vendor.close();
        this.clients.delete(token);
      }
  }

  private async using<T>(
    credential: string | undefined,
    work: (vendor: Vendor) => Promise<T>,
  ): Promise<T> {
    const { vendor, release } = this.acquire(credential);
    try {
      return await work(vendor);
    } finally {
      release();
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

  private async registered(vendor: Vendor, name: string, signal: AbortSignal) {
    try {
      return await call(() => vendor.images.get({ name }, { signal }));
    } catch (error) {
      if (protocolError(error).detail.kind === "not_found") return undefined;
      throw error;
    }
  }

  async prepare(
    request: Types["PrepareRequest"],
    { credential, signal }: Context,
  ): Promise<Types["Prepared"]> {
    const platform = request.platform ?? PLATFORM;
    if (!samePlatform(platform, PLATFORM))
      throw new ProtocolFailure({
        kind: "image_refused",
        reason: "Namespace runs only linux/amd64 devboxes",
        refusal: { cause: "unsupported_platform", platform },
      });
    if ((request.route ?? "provider_push") !== "provider_push")
      refused("Namespace declares only the provider_push image route");
    const base = parseImageRef(request.image_digest);
    const tools = parseImageRef(request.tools_digest);
    const name = imageName(
      request.image_digest,
      request.tools_digest,
      platform,
    );
    const token = credentialToken(credential);
    return this.using(credential, (vendor) =>
      this.prepared(vendor, request, base, tools, name, token, signal),
    );
  }

  private async prepared(
    vendor: Vendor,
    request: Types["PrepareRequest"],
    base: ImageRef,
    tools: ImageRef,
    name: string,
    token: string,
    signal: AbortSignal,
  ): Promise<Types["Prepared"]> {
    const platform = request.platform ?? PLATFORM;
    // Re-preparing the same inputs finds the registration, adding no version.
    let image = await this.registered(vendor, name, signal);
    if (!image) {
      const pull = request.image_pull ?? undefined;
      // The pull credential belongs to the base's registry and goes nowhere else.
      const baseRegistry = new Registry(base.registry, pull, this.fetcher);
      const toolsRegistry = new Registry(
        tools.registry,
        tools.registry === base.registry ? pull : undefined,
        this.fetcher,
      );
      const baseManifest = await baseRegistry.platformManifest(base, platform);
      const baseConfig = await baseRegistry.config(
        base.repository,
        baseManifest,
      );
      const toolsManifest = await toolsRegistry.platformManifest(
        tools,
        platform,
      );
      const toolsConfig = await toolsRegistry.config(
        tools.repository,
        toolsManifest,
      );
      const composed = compose(
        baseManifest,
        baseConfig,
        toolsManifest,
        toolsConfig,
        platform,
      );
      // The bearer token is the workspace registry's password; it never
      // reaches a docker config or any other registry.
      const target = new Registry(
        REGISTRY,
        { username: "token", secret: token },
        this.fetcher,
      );
      const repository = `${this.settings.workspace}/${this.settings.repository ?? "drydock-vessel"}`;
      for (const [source, layer] of composed.layers) {
        signal.throwIfAborted();
        const [from, fromRepository] =
          source === "base"
            ? [baseRegistry, base.repository]
            : [toolsRegistry, tools.repository];
        await copyBlob(
          from,
          fromRepository,
          target,
          repository,
          layer,
          this.settings.push_chunk_bytes ?? 64 * MiB,
        );
      }
      await target.putBlob(repository, composed.configDigest, composed.config);
      // Tagged so the registry retains it; Namespace registers the digest.
      await target.putManifest(repository, name, composed);
      const ref = `${REGISTRY}/${repository}@${composed.digest}`;
      image = await call(
        () => vendor.images.register({ ref, name }, { signal }),
        () => this.registered(vendor, name, signal),
      );
      if (image.digest !== composed.digest)
        throw new ProtocolFailure({
          kind: "internal",
          reason: "Namespace registered a different image digest",
          provider_error: `${image.ref} for ${ref}`,
        });
    }
    return {
      id: image.ref,
      provider: this.name,
      platform,
      image_digest: request.image_digest,
      tools_digest: request.tools_digest,
    };
  }

  /** The agent service; on-boot, so Namespace starts it again on resume. */
  private async addAgent(box: Box, signal: AbortSignal) {
    await call(
      () =>
        box.services.create(
          {
            name: SERVICE,
            command: AGENT,
            description: "drydock vessel agent",
            startPolicy: "on-boot",
            restartPolicy: "always",
            preventIdleShutdown: true,
          },
          { signal },
        ),
      async () =>
        (await box.services.list({ signal })).find((s) => s.name === SERVICE),
    );
  }

  async provision(
    request: Types["ProvisionRequest"],
    { credential, signal }: Context,
  ): Promise<{ created: boolean; environment: Types["Environment"] }> {
    if (request.prepared.provider !== this.name)
      refused("prepared form belongs to another provider");
    const shape = machine(request.size);
    const policy = networkPolicy(request.egress);
    return this.using(credential, (vendor) =>
      this.provisioned(vendor, request, shape, policy, signal),
    );
  }

  /** One create, then the agent service: PID 1 is Namespace's own agent. */
  private async provisioned(
    vendor: Vendor,
    request: Types["ProvisionRequest"],
    shape: ReturnType<typeof machine>,
    policy: NetworkPolicy | undefined,
    signal: AbortSignal,
  ): Promise<{ created: boolean; environment: Types["Environment"] }> {
    const labels: Record<string, string> = {
      [LABEL]: request.label,
      [POLICY]: policyIdentity(policy),
    };
    if (this.ownership === "shared_account") labels[OWNER] = this.name;
    // Namespace names must be unique, and a label may be provisioned again.
    const name = `drydock-${randomBytes(12).toString("hex")}`;
    const box = await call(
      () =>
        vendor.devboxes.create(
          {
            name,
            image: request.prepared.id,
            ...shape,
            site: this.settings.site,
            labels,
            networkPolicy: policy,
            // No tenant-default checkout: drydock owns the workspace.
            versionControl: {},
            purpose: "drydock vessel",
            start: true,
          },
          { signal },
        ),
      async () => {
        try {
          return await vendor.devboxes.get(name, { signal });
        } catch (error) {
          if (protocolError(error).detail.kind === "not_found") return;
          throw error;
        }
      },
    );
    try {
      await this.addAgent(box, signal);
    } catch (error) {
      // The devbox stays for the client to inspect or destroy; the failure
      // names it, since a failed provision returns no environment.
      const failure = protocolError(error);
      const detail = failure.detail as { reason?: string };
      detail.reason = `${detail.reason ?? failure.detail.kind}; devbox ${box.id} was left for inspection`;
      throw failure;
    }
    return { created: true, environment: this.row(box) };
  }

  /** The devbox as Namespace states it, without touching the guest. */
  private row(box: Box): Types["Environment"] {
    const { info } = box;
    const state: Types["Observation"] =
      info.state === "running"
        ? { state: "running" }
        : info.state === "stopped"
          ? // Namespace does not say whether its idle or lifetime cap or a
            // client stopped it.
            { state: "stopped" }
          : { state: "unknown", reason: "provider_state_unknown" };
    const shape = info.shape;
    const disk = info.volumeSizeGB;
    const row: Types["Environment"] = {
      provider: this.name,
      id: info.id,
      state,
      egress: "advisory",
      egress_measured: false,
      vendor: { state: info.state, tags: { ...info.labels } },
    };
    if (info.labels[LABEL] !== undefined) row.label = info.labels[LABEL];
    if (info.labels[POLICY] !== undefined)
      row.egress_policy = info.labels[POLICY];
    // A size is all three, as Namespace states them, or none.
    if (shape?.vCPUs && shape.memoryMB && disk)
      row.granted_size = {
        cpus: shape.vCPUs,
        memory_bytes: shape.memoryMB * MiB,
        disk_bytes: disk * GiB,
      };
    if (shape?.os && shape.architecture)
      row.platform = { os: shape.os, architecture: shape.architecture };
    return row;
  }

  /**
   * The row, measuring a restricted running devbox's egress with the
   * operator's probe. Enforced only when the probe's proof says it ran as
   * root; a proof from another user reads as advisory. A probe that fails, or
   * whose output is not a proof, fails the inspect.
   */
  private async observe(
    box: Box,
    signal: AbortSignal,
  ): Promise<Types["Environment"]> {
    const row = this.row(box);
    const probe = this.settings.egress_probe;
    const policy = row.egress_policy ?? "open";
    // Commands start a stopped devbox: probe only one observed running. A
    // stop landing between that observation and the exec would be undone;
    // the SDK offers no conditional exec, so that window remains.
    if (!probe || policy === "open" || row.state.state !== "running")
      return row;
    const deny = policy.startsWith("deny-") ? "1" : "0";
    const result = await call(() =>
      box.exec(probe.command, {
        env: { DRYDOCK_PROBE_DENY_ALL: deny },
        signal,
      }),
    );
    const failed = (reason: string): never => {
      throw new ProtocolFailure({
        kind: "internal",
        reason: `Namespace egress probe failed: ${reason}`,
        provider_error: result.stderr || result.stdout,
      });
    };
    if (result.exitCode !== 0) failed(`exit status ${result.exitCode}`);
    let proof: any;
    try {
      proof = JSON.parse(result.stdout);
    } catch {
      failed("output is not JSON");
    }
    const flags = ["unlisted_canary", "raw_dns"];
    if (deny === "0") flags.push("listed_direct");
    if (
      typeof proof?.uid !== "number" ||
      flags.some((f) => typeof proof[f] !== "boolean")
    )
      failed(`output lacks uid or ${flags.join(", ")}`);
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
  }

  async list({ credential, signal }: Context) {
    return this.using(credential, (vendor) => this.listed(vendor, signal));
  }

  /**
   * Every devbox Namespace lists, or on a shared account those carrying this
   * instance's tag. Namespace's list states every devbox's state as
   * `unknown` ("a list skips per-Devbox runtime lookups"), so each listed
   * devbox is refreshed: a second call, a few devboxes at a time.
   */
  private async listed(vendor: Vendor, signal: AbortSignal) {
    const labelFilters =
      this.ownership === "shared_account"
        ? [{ name: OWNER, value: this.name }]
        : undefined;
    const boxes: Box[] = [];
    let cursor: string | undefined;
    do {
      const page = await call(() =>
        vendor.devboxes.list({ labelFilters, cursor, signal }),
      );
      boxes.push(...page.items);
      cursor = page.nextCursor;
    } while (cursor);
    // In Namespace's list order. One failed refresh fails the list: a
    // partial inventory would read the missing devboxes as gone.
    const rows: (Types["Environment"] | undefined)[] = [];
    const queue = boxes.entries();
    const worker = async () => {
      for (const [index, box] of queue) {
        try {
          await call(() => box.refresh({ signal }));
          rows[index] = this.row(box);
        } catch (error) {
          // Destroyed since the list: it is not in the inventory.
          if (protocolError(error).detail.kind !== "not_found") throw error;
        }
      }
    };
    const workers = this.settings.list_refreshes ?? 8;
    await Promise.all(Array.from({ length: workers }, worker));
    return rows.filter((row) => row !== undefined);
  }

  async inspect(id: string, { credential, signal }: Context) {
    return this.using(credential, async (vendor) =>
      this.observe(
        await call(() => vendor.devboxes.get(id, { signal })),
        signal,
      ),
    );
  }

  /** Namespace's delete; an absent devbox is Namespace's not-found. */
  async destroy(id: string, { credential, signal }: Context) {
    await this.using(credential, (vendor) =>
      call(
        async () => {
          await vendor.devboxes.delete(id, { signal });
          return true;
        },
        async () => {
          try {
            await vendor.devboxes.get(id, { signal });
            return undefined;
          } catch (error) {
            if (protocolError(error).detail.kind === "not_found") return true;
            throw error;
          }
        },
      ),
    );
  }

  /** This host's relay route, without a call to Namespace. */
  async reach(id: string): Promise<Types["Reach"]> {
    const segment = encodeURIComponent;
    return {
      kind: "relay",
      path: `/v1/providers/${segment(this.name)}/environments/${segment(id)}/relay`,
    };
  }

  /** Opening the channel is Namespace's activate: it starts a stopped devbox. */
  async relay(id: string, { credential, signal }: Context): Promise<Duplex> {
    // The relay holds its SDK client until the channel closes.
    const { vendor, release } = this.acquire(credential);
    try {
      const stream = await call(() =>
        vendor.channel(id, `${AGENT} --bridge`, signal),
      );
      stream.once("close", release);
      return stream;
    } catch (error) {
      release();
      throw error;
    }
  }

  /** Namespace's stop, sent as asked. Namespace resumes by id: the token. */
  async suspend(id: string, { credential, signal }: Context) {
    await this.using(credential, (vendor) =>
      call(
        async () => {
          await vendor.devboxes.stop(id, { signal });
          return true;
        },
        async () =>
          (await vendor.devboxes.get(id, { signal })).info.state ===
            "stopped" || undefined,
      ),
    );
    return { token: id };
  }

  /**
   * Namespace's start, sent as asked. The agent service is on-boot and
   * Namespace keeps services across a stop, so it comes back by itself.
   */
  async resume(
    id: string,
    _token: Types["ResumeToken"],
    { credential, signal }: Context,
  ) {
    await this.using(credential, (vendor) =>
      call(
        async () => {
          await vendor.devboxes.start(id, { signal });
          return true;
        },
        async () =>
          (await vendor.devboxes.get(id, { signal })).info.state ===
            "running" || undefined,
      ),
    );
  }

  async quota({ credential, signal }: Context): Promise<Types["Quota"]> {
    return this.using(credential, (vendor) => this.quoted(vendor, signal));
  }

  private async quoted(
    vendor: Vendor,
    signal: AbortSignal,
  ): Promise<Types["Quota"]> {
    const rows: Types["ResourceQuota"][] = [];
    for (const entry of await call(() => vendor.concurrency(signal))) {
      // Use is reported only where Namespace states it, limits as it gives
      // them: Namespace does not document what a zero limit means.
      const active = entry.activeConcurrency;
      if (!active) continue;
      const limits = entry.limits;
      for (const [resource, unit, used, max, factor] of [
        ["cpu", "{vCPU}", active.cpu, limits?.maxCpu, 1],
        ["memory", "By", active.memoryMb, limits?.maxMemoryMb, MiB],
        [
          "environments",
          "{instance}",
          active.instanceCount,
          limits?.maxInstanceCount,
          1,
        ],
      ] as const)
        rows.push({
          key: { resource, class: entry.name || null, region: null },
          unit,
          in_use: Number(used) * factor,
          limit: max === undefined ? null : Number(max) * factor,
        });
    }
    return {
      resources: rows,
      credits_remaining: null,
      credit_unit: null,
      concurrency_in_use: null,
      concurrency_limit: null,
    };
  }
}

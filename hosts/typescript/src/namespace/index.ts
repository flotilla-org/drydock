// Namespace devboxes through `@namespacelabs/sdk/devbox` (owner ruling
// 2026-10-19: devboxes and the SDK, not the public compute API). Prepare
// layers the tools image onto the base here and registers the result; the
// agent runs as a devbox service, because PID 1 is Namespace's own agent and
// the image's entrypoint never runs; drydock reaches it through the relay
// route, which this module carries over an SSH exec channel to
// `drydock-agent --bridge`. Suspend is devbox stop: files survive, memory not.
import { createHash } from "node:crypto";
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
/** The devbox label holding the client's label, which keys idempotency. */
export const LABEL = "drydock.label";
/** The devbox label holding the egress policy identity requested at create. */
export const POLICY = "drydock.egress";
export const SERVICE = "drydock-agent";
export const AGENT = "/opt/drydock/drydock-agent";
const PLATFORM: Types["Platform"] = { os: "linux", architecture: "amd64" };
const REGISTRY = "nscr.io";
/** Concurrent `refresh` calls while listing. */
const REFRESHES = 8;
/** Linux machine sizes, as the SDK resolves them client-side. */
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
  workspace: string;
  repository?: string;
  site?: string;
  push_chunk_bytes?: number;
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
    const host = entry.host.replace(/\.$/, "").toLowerCase();
    if (host.includes(":") || /^[0-9.]+$/.test(host))
      refused("Namespace network policies allow domain names only");
    domains.add(host);
  }
  return { allowedDomains: [...domains].sort(), advisory: false };
}

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
      return new Namespace(name, config.settings as Settings, vendor, fetcher);
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
    // Devbox stop keeps the filesystem; memory and processes are lost.
    suspend_preserves_memory: false,
    export: false,
    fallback_runner: false,
    usage: false,
    quota: true,
    agent: true,
    // Untested against a live devbox: enforced only per environment, when
    // the operator's probe passes as root (see `egress_probe`).
    egress: {
      routes: ["none", "explicit_proxy", "open"],
      enforcement: "advisory",
    },
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
  observation: Types["ObservationMode"] = { mode: "poll", interval_ms: 30_000 };
  rateLimits: Types["RateLimit"][] = [];
  /**
   * Devboxes this host stopped, so their stop reads as requested. Labels are
   * fixed at create, so this is process-local: after a host restart such a stop
   * reads as paused_by_provider, which is still resumable.
   */
  private suspended = new Set<string>();
  /** SDK clients by token, with the calls and relays using each. */
  private clients = new Map<
    string,
    { vendor: Vendor; users: number; current: boolean }
  >();

  constructor(
    private name: string,
    private settings: Settings,
    private connect: (token: string) => Vendor,
    private fetcher: Fetch,
  ) {}

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

  private async labelled(vendor: Vendor, label: string, signal: AbortSignal) {
    const page = await call(() =>
      vendor.devboxes.list({
        labelFilters: [{ name: LABEL, value: label }],
        limit: 2,
        signal,
      }),
    );
    return page.items.find((box) => box.info.labels[LABEL] === label);
  }

  /** The devbox with its authoritative runtime state. */
  private current(vendor: Vendor, id: string, signal: AbortSignal) {
    return call(() => vendor.devboxes.get(id, { signal }));
  }

  /** The agent service, created once; on-boot, so it returns after resume. */
  private async ensureAgent(box: Box, signal: AbortSignal) {
    const present = async () =>
      (await box.services.list({ signal })).find((s) => s.name === SERVICE);
    if (await call(present)) return;
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
      present,
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

  /** A devbox this label names, if its size and egress policy are the request's. */
  private adopt(
    box: Box,
    shape: ReturnType<typeof machine>,
    policy: NetworkPolicy | undefined,
  ) {
    if (
      box.info.size !== shape.size ||
      (shape.volumeSizeGB !== undefined &&
        box.info.volumeSizeGB !== shape.volumeSizeGB) ||
      (box.info.labels[POLICY] ?? null) !== policyIdentity(policy)
    )
      refused(
        "existing Namespace label has a different size or egress policy; provision a new label",
      );
  }

  private async provisioned(
    vendor: Vendor,
    request: Types["ProvisionRequest"],
    shape: ReturnType<typeof machine>,
    policy: NetworkPolicy | undefined,
    signal: AbortSignal,
  ): Promise<{ created: boolean; environment: Types["Environment"] }> {
    const existing = await this.labelled(vendor, request.label, signal);
    if (existing) {
      const box = await this.current(vendor, existing.id, signal);
      this.adopt(box, shape, policy);
      // Re-adoption never resumes: a stopped devbox stays as it is.
      if (box.info.state !== "running")
        return { created: false, environment: this.row(box) };
      await this.ensureAgent(box, signal);
      return {
        created: false,
        environment: await this.observe(vendor, box, signal),
      };
    }
    const { prepared } = request;
    const image = await this.registered(
      vendor,
      imageName(
        prepared.image_digest,
        prepared.tools_digest,
        prepared.platform,
      ),
      signal,
    );
    if (!image || image.ref !== prepared.id) refused("unknown prepared form");
    let created = true;
    let box: Box;
    try {
      box = await call(
        () =>
          vendor.devboxes.create(
            {
              name: `drydock-${hex(request.label).slice(0, 24)}`,
              image: prepared.id,
              ...shape,
              site: this.settings.site,
              labels: {
                [LABEL]: request.label,
                [POLICY]: policyIdentity(policy),
              },
              networkPolicy: policy,
              // No tenant-default checkout: drydock owns the workspace.
              versionControl: {},
              purpose: "drydock vessel",
              start: true,
            },
            { signal },
          ),
        () => this.labelled(vendor, request.label, signal),
      );
    } catch (error) {
      // A concurrent provision of the same label created it first.
      const raced = await this.labelled(vendor, request.label, signal);
      if (!raced) throw error;
      this.adopt(raced, shape, policy);
      box = raced;
      created = false;
    }
    box = await this.current(vendor, box.id, signal);
    if (box.info.state === "running") await this.ensureAgent(box, signal);
    return { created, environment: await this.observe(vendor, box, signal) };
  }

  /** The provider's facts about one devbox, without touching the guest. */
  private row(box: Box): Types["Environment"] {
    const { info } = box;
    const state: Types["Observation"] =
      info.state === "running"
        ? { state: "running" }
        : info.state === "stopped"
          ? {
              state: "stopped",
              // Namespace stops a devbox at its lifetime cap or when idle, and
              // it stays resumable; only a stop this host requested is ours.
              cause: this.suspended.has(info.id)
                ? "suspended_by_request"
                : "paused_by_provider",
            }
          : { state: "unknown", reason: "provider_state_unknown" };
    const shape = info.shape;
    return {
      provider: this.name,
      id: info.id,
      label: info.labels[LABEL] ?? null,
      state,
      granted_size: shape
        ? {
            cpus: shape.vCPUs,
            memory_bytes: shape.memoryMB * MiB,
            disk_bytes: (info.volumeSizeGB ?? 0) * GiB,
          }
        : null,
      platform:
        shape?.os && shape.architecture
          ? { os: shape.os, architecture: shape.architecture }
          : PLATFORM,
      egress: "advisory",
      egress_measured: false,
      egress_policy: info.labels[POLICY] ?? null,
      timestamp: null,
    };
  }

  /**
   * The row, measuring a restricted running devbox's egress with the
   * operator's probe. Enforced only when the probe proves it as root.
   */
  private async observe(
    vendor: Vendor,
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
    try {
      const result = await call(() =>
        box.exec(
          [
            "sh",
            "-c",
            `test "$(id -u)" = 0 && DRYDOCK_PROBE_DENY_ALL=${deny} exec "$@"`,
            "probe",
            ...probe.command,
          ],
          { signal },
        ),
      );
      if (result.exitCode !== 0) return row;
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

  async list({ credential, signal }: Context) {
    return this.using(credential, (vendor) => this.listed(vendor, signal));
  }

  private async listed(vendor: Vendor, signal: AbortSignal) {
    const boxes: Box[] = [];
    let cursor: string | undefined;
    do {
      const page = await call(() =>
        vendor.devboxes.list({
          labelFilters: [{ name: LABEL, operator: "exists" }],
          cursor,
          signal,
        }),
      );
      boxes.push(...page.items);
      cursor = page.nextCursor;
    } while (cursor);
    // List reports state unknown; refresh resolves it without starting
    // anything, a few devboxes at a time.
    const rows: Types["Environment"][] = [];
    const queue = [...boxes];
    const worker = async () => {
      for (let box = queue.shift(); box; box = queue.shift()) {
        try {
          await call(() => box.refresh({ signal }));
          rows.push(this.row(box));
        } catch (error) {
          if (protocolError(error).detail.kind !== "not_found") throw error;
        }
      }
    };
    await Promise.all(Array.from({ length: REFRESHES }, worker));
    return rows;
  }

  async inspect(id: string, { credential, signal }: Context) {
    return this.using(credential, async (vendor) =>
      this.observe(vendor, await this.current(vendor, id, signal), signal),
    );
  }

  async destroy(id: string, { credential, signal }: Context) {
    return this.using(credential, (vendor) =>
      this.destroyed(vendor, id, signal),
    );
  }

  private async destroyed(vendor: Vendor, id: string, signal: AbortSignal) {
    const gone = async () => {
      try {
        await vendor.devboxes.get(id, { signal });
        return undefined;
      } catch (error) {
        if (protocolError(error).detail.kind === "not_found") return true;
        throw error;
      }
    };
    let box: Box;
    try {
      box = await this.current(vendor, id, signal);
    } catch (error) {
      // Destroy is idempotent: an absent devbox is already destroyed.
      if (protocolError(error).detail.kind === "not_found") return;
      throw error;
    }
    await call(async () => {
      await box.delete({ signal });
      return true;
    }, gone);
    this.suspended.delete(id);
  }

  async reach(
    id: string,
    { credential, signal }: Context,
  ): Promise<Types["Reach"]> {
    await this.using(credential, (vendor) => this.current(vendor, id, signal));
    const segment = encodeURIComponent;
    return {
      kind: "relay",
      path: `/v1/providers/${segment(this.name)}/environments/${segment(id)}/relay`,
    };
  }

  async relay(id: string, { credential, signal }: Context): Promise<Duplex> {
    // The relay holds its SDK client until the channel closes.
    const { vendor, release } = this.acquire(credential);
    try {
      const box = await this.current(vendor, id, signal);
      // Opening a channel starts a stopped devbox; reach never resumes one.
      if (box.info.state !== "running")
        refused("Namespace devbox is not running; resume it first");
      const stream = await call(() =>
        vendor.channel(box, `${AGENT} --bridge`, signal),
      );
      stream.once("close", release);
      return stream;
    } catch (error) {
      release();
      throw error;
    }
  }

  private resumeToken(id: string): Types["ResumeToken"] {
    // Binds provider and id; not an access credential.
    return { token: hex(`resume\0${this.name}\0${id}`) };
  }

  async suspend(id: string, { credential, signal }: Context) {
    return this.using(credential, (vendor) => this.stopped(vendor, id, signal));
  }

  private async stopped(vendor: Vendor, id: string, signal: AbortSignal) {
    const box = await this.current(vendor, id, signal);
    if (box.info.state !== "stopped")
      await call(
        async () => {
          await box.stop({ signal });
          return true;
        },
        async () =>
          (await vendor.devboxes.get(id, { signal })).info.state ===
            "stopped" || undefined,
      );
    this.suspended.add(id);
    return this.resumeToken(id);
  }

  async resume(
    id: string,
    token: Types["ResumeToken"],
    { credential, signal }: Context,
  ) {
    if (token.token !== this.resumeToken(id).token)
      refused("resume token belongs to another environment");
    return this.using(credential, (vendor) => this.resumed(vendor, id, signal));
  }

  private async resumed(vendor: Vendor, id: string, signal: AbortSignal) {
    let box = await this.current(vendor, id, signal);
    if (box.info.state !== "running") {
      await call(
        async () => {
          await box.start({ signal });
          return true;
        },
        async () =>
          (await vendor.devboxes.get(id, { signal })).info.state ===
            "running" || undefined,
      );
      box = await this.current(vendor, id, signal);
    }
    this.suspended.delete(id);
    await this.ensureAgent(box, signal);
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
      const limits = entry.limits;
      const active = entry.activeConcurrency;
      // Zero is Namespace's unset limit, not a limit of nothing.
      const limit = (value: bigint | undefined, factor = 1) =>
        value ? Number(value) * factor : null;
      for (const [resource, unit, used, max, factor] of [
        ["cpu", "{vCPU}", active?.cpu, limits?.maxCpu, 1],
        ["memory", "By", active?.memoryMb, limits?.maxMemoryMb, MiB],
        [
          "environments",
          "{instance}",
          active?.instanceCount,
          limits?.maxInstanceCount,
          1,
        ],
      ] as const)
        rows.push({
          key: { resource, class: entry.name || null, region: null },
          unit,
          in_use: Number(used ?? 0n) * factor,
          limit: limit(max, factor),
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

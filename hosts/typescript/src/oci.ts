// OCI distribution client and host-side layering, ported from the Rust host's
// oci.rs: manifests and blobs only, no container build and no local Docker.
// Distribution spec v1.1:
// https://github.com/opencontainers/distribution-spec/blob/v1.1.0/spec.md
import { createHash } from "node:crypto";
import { ProtocolFailure, refused, type Types } from "./provider.js";

export const OCI_INDEX = "application/vnd.oci.image.index.v1+json";
export const OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json";
export const DOCKER_LIST =
  "application/vnd.docker.distribution.manifest.list.v2+json";
export const DOCKER_MANIFEST =
  "application/vnd.docker.distribution.manifest.v2+json";
const OCI_LAYER_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip";
const DOCKER_LAYER_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip";

export type Fetch = typeof fetch;
type Platform = Types["Platform"];
type Json = Record<string, any>;

export function sha256(bytes: Uint8Array | string): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function digestValid(digest: string) {
  return /^sha256:[0-9a-f]{64}$/.test(digest);
}

function malformed(reason: string): ProtocolFailure {
  return new ProtocolFailure({
    kind: "internal",
    reason: `invalid OCI image: ${reason}`,
    provider_error: "",
  });
}

function unsupported(platform: Platform, reason: string): ProtocolFailure {
  return new ProtocolFailure({
    kind: "image_refused",
    reason,
    refusal: { cause: "unsupported_platform", platform },
  });
}

const platformName = (p: Platform) => `${p.os}/${p.architecture}`;

/** A base or tools image reference pinned by digest. */
export type ImageRef = { registry: string; repository: string; digest: string };

/**
 * `[registry/]repository[:tag]@sha256:<hex>`. Docker Hub short forms expand as
 * Docker expands them; a tag beside the digest is ignored, as pulls do.
 */
export function parseImageRef(reference: string): ImageRef {
  const invalid = () =>
    refused("image references must be name@sha256:<64 lowercase hex>");
  const at = reference.indexOf("@");
  if (at < 0) invalid();
  const name = reference.slice(0, at),
    digest = reference.slice(at + 1);
  if (!digestValid(digest)) invalid();
  const slash = name.indexOf("/");
  const first = slash < 0 ? "" : name.slice(0, slash);
  let registry: string, repository: string;
  if (slash >= 0 && (/[.:]/.test(first) || first === "localhost")) {
    registry = first;
    repository = name.slice(slash + 1);
  } else {
    registry = "docker.io";
    repository = slash >= 0 ? name : `library/${name}`;
  }
  const last = repository.lastIndexOf("/");
  repository =
    repository.slice(0, last + 1) + repository.slice(last + 1).split(":")[0];
  const component = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/;
  if (
    !registryHostValid(registry) ||
    !repository.split("/").every((c) => component.test(c))
  )
    invalid();
  return { registry, repository, digest };
}

/** `host[:port]`: a DNS name or address, with no path or credentials. */
export function registryHostValid(host: string) {
  return /^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$/.test(host) && !host.startsWith(".");
}

export type Descriptor = { mediaType: string; digest: string; size: number };

function descriptor(value: Json | undefined): Descriptor {
  if (typeof value?.digest !== "string" || !digestValid(value.digest))
    throw malformed("descriptor digest is not sha256");
  if (typeof value.mediaType !== "string")
    throw malformed("descriptor has no media type");
  if (!Number.isSafeInteger(value.size) || value.size < 0)
    throw malformed("descriptor has no size");
  return { mediaType: value.mediaType, digest: value.digest, size: value.size };
}

export class Manifest {
  constructor(
    readonly mediaType: string,
    readonly json: Json,
  ) {}
  static parse(bytes: Uint8Array, contentType: string | null): Manifest {
    let json: Json;
    try {
      json = JSON.parse(Buffer.from(bytes).toString("utf8"));
    } catch {
      throw malformed("manifest is not JSON");
    }
    const mediaType = json?.mediaType ?? contentType;
    if (typeof mediaType !== "string")
      throw malformed("manifest has no media type");
    return new Manifest(mediaType, json);
  }
  config(): Descriptor {
    return descriptor(this.json.config);
  }
  layers(): Descriptor[] {
    if (!Array.isArray(this.json.layers))
      throw malformed("manifest has no layers");
    return this.json.layers.map(descriptor);
  }
}

/** Where a composed layer's bytes come from. */
export type Source = "base" | "tools";

/** The base image with the tools layers appended, ready to push. */
export type Composed = {
  mediaType: string;
  manifest: Buffer;
  digest: string;
  config: Buffer;
  configDigest: string;
  layers: [Source, Descriptor][];
};

/**
 * Appends the tools image's layers to the base image's manifest. The base's
 * entrypoint, command, environment and user are untouched: only the root
 * filesystem and history grow. Output is a function of the inputs alone, so
 * the composed digest is stable across hosts and retries.
 */
export function compose(
  base: Manifest,
  baseConfig: Uint8Array,
  tools: Manifest,
  toolsConfig: Uint8Array,
  platform: Platform,
): Composed {
  const imageConfig = (
    manifest: Manifest,
    bytes: Uint8Array,
    what: string,
  ): Json => {
    if (![OCI_MANIFEST, DOCKER_MANIFEST].includes(manifest.mediaType))
      throw malformed(`${what} is not a single-platform image manifest`);
    let config: Json;
    try {
      config = JSON.parse(Buffer.from(bytes).toString("utf8"));
    } catch {
      throw malformed("image config is not JSON");
    }
    if (
      config?.os !== platform.os ||
      config?.architecture !== platform.architecture
    )
      throw unsupported(
        platform,
        `the ${what} image is not built for ${platformName(platform)}`,
      );
    const diffIds = config.rootfs?.diff_ids;
    if (
      (Array.isArray(diffIds) ? diffIds.length : 0) !== manifest.layers().length
    )
      throw malformed(`${what} config and manifest list different layers`);
    return config;
  };
  const config = imageConfig(base, baseConfig, "base");
  const toolsImage = imageConfig(tools, toolsConfig, "tools");
  const docker = base.mediaType === DOCKER_MANIFEST;
  const layers: [Source, Descriptor][] = base
    .layers()
    .map((layer) => ["base", layer]);
  for (const layer of tools.layers()) {
    // The same gzip tar bytes carry a different name in each manifest family.
    if (![OCI_LAYER_GZIP, DOCKER_LAYER_GZIP].includes(layer.mediaType))
      throw malformed("the tools layer is not a gzip tar layer");
    layers.push([
      "tools",
      { ...layer, mediaType: docker ? DOCKER_LAYER_GZIP : OCI_LAYER_GZIP },
    ]);
  }
  const added: unknown[] = toolsImage.rootfs.diff_ids;
  config.rootfs.diff_ids.push(...added);
  // History is optional and also lists empty layers, so its length need not
  // match diff_ids; it gains one entry per added layer only when present.
  if (Array.isArray(config.history))
    for (const _ of added)
      config.history.push({ created_by: "drydock tools layer: /opt/drydock" });
  const configBytes = Buffer.from(JSON.stringify(config));
  const configDigest = sha256(configBytes);
  // A referrer of some other image the base pointed at; the composed image is not.
  const { subject: _subject, ...manifest } = base.json;
  manifest.config = {
    mediaType: base.config().mediaType,
    digest: configDigest,
    size: configBytes.length,
  };
  manifest.layers = layers.map(([, l]) => ({
    mediaType: l.mediaType,
    digest: l.digest,
    size: l.size,
  }));
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  return {
    mediaType: base.mediaType,
    manifest: manifestBytes,
    digest: sha256(manifestBytes),
    config: configBytes,
    configDigest,
    layers,
  };
}

/** `key="value", key=value` pairs from a WWW-Authenticate challenge. */
function challengeParams(params: string): Map<string, string> {
  const result = new Map<string, string>();
  const pattern = /\s*,?\s*([A-Za-z0-9_-]+)=(?:"([^"]*)"|([^,]*))/g;
  for (const match of params.matchAll(pattern))
    result.set(match[1].toLowerCase(), (match[2] ?? match[3]).trim());
  return result;
}

const pullScope = (repository: string) => `repository:${repository}:pull`;
const pushScope = (repository: string) => `repository:${repository}:pull,push`;

export type RegistryCredential = { username: string; secret: string };

/**
 * One registry, with pull or push access. Authentication follows the
 * registry's own challenge: Basic, or a bearer token from its realm. The
 * credential never leaves the registry's origin (or Docker Hub's token service).
 */
const MAX_REDIRECTS = 5;

export class Registry {
  readonly origin: URL;
  private authorizations = new Map<string, string>();
  constructor(
    readonly host: string,
    private credential: RegistryCredential | undefined,
    private fetcher: Fetch = fetch,
  ) {
    if (!registryHostValid(host)) refused("invalid registry host");
    const endpoint = host === "docker.io" ? "registry-1.docker.io" : host;
    this.origin = new URL(`https://${endpoint}/`);
  }

  url(repository: string, ...tail: string[]): URL {
    return new URL(`v2/${repository}/${tail.join("/")}`, this.origin);
  }

  /** Never carries a registry body: those can echo credentials. */
  private statusError(
    status: number,
    what: string,
    retryAfter: number | null = null,
  ): ProtocolFailure {
    const reason = `registry ${this.host} ${what} HTTP ${status}`;
    if (status === 401 || status === 403)
      return new ProtocolFailure({ kind: "credential_rejected", reason });
    if (status === 404)
      return new ProtocolFailure({ kind: "not_found", reason });
    if (status === 429)
      return new ProtocolFailure({
        kind: "rate_limited",
        reason,
        retry_after: retryAfter,
      });
    if (status === 408 || status >= 500)
      return new ProtocolFailure({
        kind: "unavailable",
        reason,
        retry_after: retryAfter,
      });
    return new ProtocolFailure({
      kind: "internal",
      reason,
      provider_error: "",
    });
  }

  check(response: Response, expected: number[], what: string) {
    if (expected.includes(response.status)) return;
    // Integer seconds only; an HTTP-date leaves the retry hint unset.
    const after = response.headers.get("retry-after");
    const seconds = after && /^[0-9]+$/.test(after) ? Number(after) : null;
    throw this.statusError(response.status, what, seconds);
  }

  private sameOrigin(url: URL) {
    return url.origin === this.origin.origin;
  }

  private realmTrusted(realm: URL) {
    return (
      this.sameOrigin(realm) ||
      (this.host === "docker.io" && realm.origin === "https://auth.docker.io")
    );
  }

  private async execute(url: URL, init: RequestInit, what: string) {
    try {
      return await this.fetcher(url, { ...init, redirect: "manual" });
    } catch {
      throw new ProtocolFailure({
        kind: "unavailable",
        reason: `registry ${this.host} ${what} transport failed`,
      });
    }
  }

  private basic(): string | undefined {
    if (!this.credential) return;
    const { username, secret } = this.credential;
    return `Basic ${Buffer.from(`${username}:${secret}`).toString("base64")}`;
  }

  private async authenticate(scope: string, challenge: string | null) {
    const rejected = () =>
      new ProtocolFailure({
        kind: "credential_rejected",
        reason: `registry ${this.host} refused access to ${scope}`,
      });
    if (!challenge) throw rejected();
    const trimmed = challenge.trim();
    const space = trimmed.indexOf(" ");
    const scheme = (
      space < 0 ? trimmed : trimmed.slice(0, space)
    ).toLowerCase();
    if (scheme === "basic") {
      const basic = this.basic();
      if (!basic) throw rejected();
      return basic;
    }
    if (scheme !== "bearer") throw rejected();
    const params = challengeParams(space < 0 ? "" : trimmed.slice(space + 1));
    let realm: URL;
    try {
      realm = new URL(params.get("realm") ?? "");
    } catch {
      throw rejected();
    }
    if (realm.protocol !== "https:") throw rejected();
    const service = params.get("service");
    if (service) realm.searchParams.append("service", service);
    realm.searchParams.append("scope", scope);
    const headers: Record<string, string> = {};
    const basic = this.basic();
    // A realm elsewhere gets an anonymous token request, never our credential.
    if (basic && this.realmTrusted(realm)) headers.authorization = basic;
    const response = await this.execute(realm, { headers }, "token");
    if (!response.ok) throw this.statusError(response.status, "token");
    const body = await response.json().catch(() => undefined);
    const token = body?.token ?? body?.access_token;
    if (typeof token !== "string") throw rejected();
    return `Bearer ${token}`;
  }

  /** Sends with this registry's authorization for `scope`, authenticating once on a challenge. */
  async send(
    scope: string,
    method: string,
    url: URL,
    headers: Record<string, string>,
    body: Uint8Array | undefined,
    what: string,
    follow = false,
  ): Promise<Response> {
    for (let hops = 0, challenged = false; ; ) {
      const sameOrigin = this.sameOrigin(url);
      const authorization = sameOrigin
        ? this.authorizations.get(scope)
        : undefined;
      const response = await this.execute(
        url,
        {
          method,
          headers: { ...headers, ...(authorization ? { authorization } : {}) },
          body: body as BodyInit | undefined,
        },
        what,
      );
      if (response.status === 401 && sameOrigin && !challenged) {
        await response.body?.cancel();
        this.authorizations.set(
          scope,
          await this.authenticate(
            scope,
            response.headers.get("www-authenticate"),
          ),
        );
        challenged = true;
        continue;
      }
      // Upload requests may be redirected (307/308 keep method and body).
      // Authorization is attached per request only for this registry's origin.
      if ([307, 308].includes(response.status) && follow) {
        const location = response.headers.get("location");
        await response.body?.cancel();
        if (!location) throw malformed("redirect without location");
        if (++hops > MAX_REDIRECTS)
          throw new ProtocolFailure({
            kind: "internal",
            reason: `registry ${this.host} ${what} redirected too often`,
            provider_error: "",
          });
        url = new URL(location, url);
        challenged = false;
        continue;
      }
      return response;
    }
  }

  /**
   * GET following redirects (blob stores hand out short-lived URLs on other
   * origins), dropping authorization at the origin boundary.
   */
  async get(
    scope: string,
    url: URL,
    headers: Record<string, string>,
    what: string,
  ): Promise<Response> {
    for (let hops = 0; hops < 5; hops++) {
      const response = this.sameOrigin(url)
        ? await this.send(scope, "GET", url, headers, undefined, what)
        : await this.execute(url, { headers }, what);
      if (response.status < 300 || response.status >= 400) return response;
      const location = response.headers.get("location");
      await response.body?.cancel();
      if (!location) throw malformed("redirect without location");
      url = new URL(location, url);
    }
    throw new ProtocolFailure({
      kind: "internal",
      reason: `registry ${this.host} ${what} redirected too often`,
      provider_error: "",
    });
  }

  private async manifest(repository: string, digest: string) {
    const accept = [OCI_INDEX, OCI_MANIFEST, DOCKER_LIST, DOCKER_MANIFEST].join(
      ", ",
    );
    const response = await this.get(
      pullScope(repository),
      this.url(repository, "manifests", digest),
      { accept },
      "manifest",
    );
    this.check(response, [200], "manifest");
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (sha256(bytes) !== digest)
      throw malformed("manifest content does not match its digest");
    return Manifest.parse(bytes, response.headers.get("content-type"));
  }

  /** The image manifest for `platform`, choosing from an index when the reference names one. */
  async platformManifest(image: ImageRef, platform: Platform) {
    const manifest = await this.manifest(image.repository, image.digest);
    if (![OCI_INDEX, DOCKER_LIST].includes(manifest.mediaType)) return manifest;
    if (!Array.isArray(manifest.json.manifests))
      throw malformed("index has no manifests");
    const entry = manifest.json.manifests.find(
      (m: Json) =>
        m?.platform?.os === platform.os &&
        m?.platform?.architecture === platform.architecture,
    );
    if (!entry)
      throw unsupported(
        platform,
        `${this.host}/${image.repository} has no ${platformName(platform)} image`,
      );
    const chosen = await this.manifest(
      image.repository,
      descriptor(entry).digest,
    );
    if ([OCI_INDEX, DOCKER_LIST].includes(chosen.mediaType))
      throw malformed("nested image index");
    return chosen;
  }

  /** A small blob (an image config), verified against its digest. */
  async config(repository: string, manifest: Manifest): Promise<Buffer> {
    const { digest } = manifest.config();
    const response = await this.get(
      pullScope(repository),
      this.url(repository, "blobs", digest),
      {},
      "config",
    );
    this.check(response, [200], "config");
    const bytes = Buffer.from(await response.arrayBuffer());
    if (sha256(bytes) !== digest)
      throw malformed("config content does not match its digest");
    return bytes;
  }

  async blobExists(repository: string, digest: string): Promise<boolean> {
    const response = await this.send(
      pushScope(repository),
      "HEAD",
      this.url(repository, "blobs", digest),
      {},
      undefined,
      "blob",
    );
    await response.body?.cancel();
    if (response.status === 404) return false;
    // A redirect to object storage says the blob exists; never follow it, so
    // our authorization stays on this origin.
    if (
      [301, 302, 303, 307, 308].includes(response.status) &&
      response.headers.has("location")
    )
      return true;
    this.check(response, [200], "blob");
    return true;
  }

  location(response: Response): URL {
    const location = response.headers.get("location");
    if (!location) throw malformed("upload without location");
    const url = new URL(location, this.origin);
    // Upload sessions carry our authorization, so they stay on this registry.
    if (!this.sameOrigin(url))
      throw malformed("upload location on another origin");
    return url;
  }

  async startUpload(repository: string): Promise<URL> {
    const response = await this.send(
      pushScope(repository),
      "POST",
      this.url(repository, "blobs", "uploads", ""),
      {},
      new Uint8Array(),
      "upload",
      true,
    );
    await response.body?.cancel();
    this.check(response, [202], "upload");
    return this.location(response);
  }

  async finishUpload(
    repository: string,
    location: URL,
    digest: string,
    body: Uint8Array,
  ) {
    const url = new URL(location);
    url.searchParams.append("digest", digest);
    const response = await this.send(
      pushScope(repository),
      "PUT",
      url,
      { "content-type": "application/octet-stream" },
      body,
      "upload",
      true,
    );
    await response.body?.cancel();
    this.check(response, [201], "upload");
  }

  /** Uploads a small blob in one request unless the registry already has it. */
  async putBlob(repository: string, digest: string, body: Uint8Array) {
    if (await this.blobExists(repository, digest)) return;
    const location = await this.startUpload(repository);
    await this.finishUpload(repository, location, digest, body);
  }

  async putManifest(repository: string, tag: string, composed: Composed) {
    const response = await this.send(
      pushScope(repository),
      "PUT",
      this.url(repository, "manifests", tag),
      { "content-type": composed.mediaType },
      composed.manifest,
      "manifest",
    );
    await response.body?.cancel();
    this.check(response, [201], "manifest");
    const stored = response.headers.get("docker-content-digest");
    if (stored && stored !== composed.digest)
      throw malformed("registry stored a different manifest digest");
  }
}

/**
 * Copies one blob between registries in bounded chunks: ranged reads from the
 * source, a chunked upload session at the target. Each request moves at most
 * `chunk` bytes, and the stream is verified against its digest before the
 * upload is committed.
 */
export async function copyBlob(
  source: Registry,
  sourceRepository: string,
  target: Registry,
  targetRepository: string,
  layer: Descriptor,
  chunk: number,
) {
  if (await target.blobExists(targetRepository, layer.digest)) return;
  let location = await target.startUpload(targetRepository);
  const hash = createHash("sha256");
  const url = source.url(sourceRepository, "blobs", layer.digest);
  let offset = 0;
  while (offset < layer.size) {
    const end = Math.min(offset + chunk, layer.size) - 1;
    const response = await source.get(
      pullScope(sourceRepository),
      url,
      { range: `bytes=${offset}-${end}` },
      "blob",
    );
    source.check(response, [200, 206], "blob");
    // A registry may ignore Range and send the whole blob; accept that only
    // when the whole blob fits one bounded request.
    if (response.status === 200 && !(offset === 0 && layer.size <= chunk)) {
      await response.body?.cancel();
      throw malformed("registry ignored a ranged blob read");
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length === 0 || offset + bytes.length > layer.size)
      throw malformed("blob size does not match its descriptor");
    hash.update(bytes);
    const last = offset + bytes.length - 1;
    const patched = await target.send(
      pushScope(targetRepository),
      "PATCH",
      location,
      {
        "content-type": "application/octet-stream",
        "content-range": `${offset}-${last}`,
      },
      bytes,
      "upload",
      true,
    );
    await patched.body?.cancel();
    target.check(patched, [202], "upload");
    location = target.location(patched);
    offset = last + 1;
  }
  if (`sha256:${hash.digest("hex")}` !== layer.digest)
    throw malformed("blob content does not match its digest");
  await target.finishUpload(
    targetRepository,
    location,
    layer.digest,
    new Uint8Array(),
  );
}

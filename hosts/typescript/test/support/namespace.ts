// In-process stand-ins for the Namespace module's two network boundaries: the
// devbox SDK (the `Vendor` seam) and OCI registries (the `fetch` it is given).
// They enforce what the SDK documents, so the module fails here as it would there.
import { createHash } from "node:crypto";
import { Duplex, PassThrough } from "node:stream";
import { Code, ConnectError } from "@connectrpc/connect";
import type {
  CreateDevboxInput,
  CreateServiceInput,
  DevboxInfo,
  Image,
  ListDevboxesOptions,
  Service,
} from "@namespacelabs/sdk/devbox";
import type { Box, Concurrency, Vendor } from "../../src/namespace/vendor.ts";

export const TOKEN = "test-only-namespace-token";
export const CREDENTIAL = JSON.stringify({ bearer_token: TOKEN });
const SHAPES: Record<string, { vCPUs: number; memoryMB: number }> = {
  s: { vCPUs: 4, memoryMB: 8192 },
  m: { vCPUs: 8, memoryMB: 16384 },
};

type Row = {
  info: DevboxInfo;
  services: Service[];
  networkPolicy: CreateDevboxInput["networkPolicy"];
  versionControl: unknown;
};

/** Devbox SDK stand-in. `fail(op)` makes the next `op` take effect, then fail with `Premature close`. */
export class StandIn implements Vendor {
  rows = new Map<string, Row>();
  registered: Image[] = [];
  calls: string[] = [];
  /** Connection-backed calls that started a stopped devbox. */
  activations = 0;
  /** What each opened channel ran. */
  channels: string[] = [];
  concurrencyRows: Concurrency[] = [];
  /** Probe output for exec; the argv is recorded in `calls`. */
  execStdout = "";
  execExit = 0;
  /** How often the module closed its SDK client. */
  closed = 0;
  private faults = new Map<string, number>();
  private next = 0;
  tokens: string[] = [];

  fail(operation: string, times = 1) {
    this.faults.set(operation, times);
  }

  private effect(operation: string) {
    this.calls.push(operation);
    const left = this.faults.get(operation) ?? 0;
    if (left > 0) {
      this.faults.set(operation, left - 1);
      return () => {
        throw new Error("Premature close");
      };
    }
    return () => {};
  }

  private row(ref: string): Row {
    const row =
      this.rows.get(ref) ??
      [...this.rows.values()].find((r) => r.info.name === ref);
    if (!row) throw new ConnectError("devbox not found", Code.NotFound);
    return row;
  }

  // Connection-backed calls activate a stopped devbox, as the SDK documents.
  private connect(row: Row) {
    if (row.info.state !== "running") {
      this.activations++;
      row.info.state = "running";
    }
  }

  private handle(row: Row, state: DevboxInfo["state"]): Box {
    const standIn = this;
    const id = row.info.id;
    const box = {
      id,
      name: row.info.name,
      info: { ...structuredClone(row.info), state } as DevboxInfo,
      services: {
        async list() {
          standIn.connect(standIn.row(id));
          return structuredClone(standIn.row(id).services);
        },
        async create(input: CreateServiceInput) {
          const done = standIn.effect("services.create");
          const target = standIn.row(id);
          standIn.connect(target);
          if (target.services.some((s) => s.name === input.name))
            // As Namespace answers it: an invalid argument, not AlreadyExists.
            throw new ConnectError(
              `conflict: service name "${input.name}" conflicts with svc-0`,
              Code.InvalidArgument,
            );
          const service = {
            id: `svc-${target.services.length}`,
            name: input.name,
            command: input.command,
            args: [...(input.args ?? [])],
            environment: {},
            startPolicy: input.startPolicy ?? "on-boot",
            restartPolicy: input.restartPolicy ?? "on-failure",
            preventIdleShutdown: input.preventIdleShutdown ?? false,
            stopped: false,
            owner: "user",
            ports: [],
          } as Service;
          target.services.push(service);
          done();
          return service;
        },
      },
      async exec(argv: readonly string[]) {
        standIn.calls.push(`exec ${argv.join(" ")}`);
        standIn.connect(standIn.row(id));
        return {
          exitCode: standIn.execExit,
          signal: null,
          stdout: standIn.execStdout,
          stderr: "",
        };
      },
      async start() {
        const done = standIn.effect("start");
        standIn.row(id).info.state = "running";
        box.info = { ...structuredClone(standIn.row(id).info) };
        done();
      },
      async stop() {
        const done = standIn.effect("stop");
        standIn.row(id).info.state = "stopped";
        box.info = { ...structuredClone(standIn.row(id).info) };
        done();
      },
      async delete() {
        const done = standIn.effect("delete");
        standIn.rows.delete(standIn.row(id).info.id);
        done();
      },
      async refresh() {
        standIn.calls.push("refresh");
        box.info = { ...structuredClone(standIn.row(id).info) };
      },
      async update() {
        throw new Error("not used");
      },
    };
    return box;
  }

  devboxes = {
    create: async (input: CreateDevboxInput) => {
      const done = this.effect("create");
      // The module never asks for ephemeral devboxes: they are deleted on stop.
      if (input.ephemeral !== undefined)
        throw new Error("ephemeral devboxes are deleted on stop");
      if ([...this.rows.values()].some((r) => r.info.name === input.name))
        throw new ConnectError("name taken", Code.AlreadyExists);
      if (!this.registered.some((i) => i.ref === input.image))
        throw new ConnectError("unknown image", Code.InvalidArgument);
      const shape = SHAPES[input.size as string];
      if (!shape) throw new TypeError("unknown size");
      const info: DevboxInfo = {
        id: `devbox-${++this.next}`,
        name: input.name,
        labels: { ...input.labels },
        state: input.start === false ? "stopped" : "running",
        image: input.image as string,
        size: input.size,
        shape: { ...shape, architecture: "amd64", os: "linux" },
        site: input.site ?? "iad",
        volumeSizeGB: input.volumeSizeGB ?? 64,
        ephemeral: false,
      };
      const row = {
        info,
        services: [],
        networkPolicy: input.networkPolicy,
        versionControl: input.versionControl,
      };
      this.rows.set(info.id, row);
      done();
      return this.handle(row, info.state);
    },
    get: async (ref: string) => {
      this.calls.push("get");
      const row = this.row(ref);
      return this.handle(row, row.info.state);
    },
    // List is cheap: state unknown. Two per page, so paging is exercised.
    list: async (options: ListDevboxesOptions = {}) => {
      this.calls.push("list");
      const matching = [...this.rows.values()].filter((row) =>
        (options.labelFilters ?? []).every((filter) => {
          if ("anyOf" in filter) throw new Error("not used");
          const value = row.info.labels[filter.name];
          return filter.operator === "exists"
            ? value !== undefined
            : value === filter.value;
        }),
      );
      const start = Number(options.cursor ?? 0);
      const end = start + Math.min(options.limit ?? 2, 2);
      return {
        items: matching
          .slice(start, end)
          .map((row) => this.handle(row, "unknown")),
        nextCursor: end < matching.length ? String(end) : undefined,
      };
    },
  };

  images = {
    register: async (input: { ref: string; name: string }) => {
      const done = this.effect("register");
      const [repository, digest] = input.ref.split("@");
      const image: Image = {
        id: `image-${this.registered.length}`,
        name: input.name,
        repository,
        digest,
        ref: input.ref,
        version: BigInt(this.registered.length + 1),
        managed: false,
      };
      this.registered.push(image);
      done();
      return image;
    },
    get: async (selector: unknown) => {
      this.calls.push("images.get");
      const name = (selector as { name: string }).name;
      const image = this.registered.findLast((i) => i.name === name);
      if (!image) throw new ConnectError("image not found", Code.NotFound);
      return image;
    },
  };

  /** Each channel is answered by `agent`, standing in for the bridge to the agent's socket. */
  agent: (stream: Duplex) => void = (stream) => stream.pipe(stream);

  async channel(box: Box, command: string) {
    const done = this.effect("channel");
    this.connect(this.row(box.id));
    this.channels.push(command);
    done();
    const [local, remote] = pair();
    this.agent(remote);
    return local;
  }

  async concurrency() {
    return this.concurrencyRows;
  }

  close() {
    this.closed++;
  }
}

/** Two connected in-memory duplex ends. */
export function pair(): [Duplex, Duplex] {
  const ab = new PassThrough(),
    ba = new PassThrough();
  const a = Duplex.from({ readable: ba, writable: ab });
  const b = Duplex.from({ readable: ab, writable: ba });
  // Either end going away is the other's ordinary end, not a failure.
  for (const end of [a, b]) end.on("error", () => end.destroy());
  return [a, b];
}

const digest = (bytes: Uint8Array | string) =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

type Store = {
  blobs: Map<string, Buffer>;
  manifests: Map<string, { type: string; bytes: Buffer }>;
  uploads: Map<string, Buffer[]>;
};

/**
 * OCI registries behind `fetch`. `nscr.io` demands Basic `token:<bearer>`,
 * as Namespace's workspace registry does; others are anonymous.
 */
export class Registries {
  stores = new Map<string, Store>();
  requests: {
    host: string;
    method: string;
    path: string;
    authorization: string | null;
  }[] = [];

  /** Answers every upload request with a 307 to the same path plus `hop=N`, up to this many hops. */
  uploadRedirects = 0;
  /** Status of those redirects. */
  redirectStatus = 307;
  /** When set, starting an upload is redirected to this host, which opens the session on nscr.io. */
  redirectStartTo: string | undefined;
  /** Drops the Location header from redirects. */
  redirectWithoutLocation = false;

  store(host: string): Store {
    let store = this.stores.get(host);
    if (!store) {
      store = { blobs: new Map(), manifests: new Map(), uploads: new Map() };
      this.stores.set(host, store);
    }
    return store;
  }

  putBlob(host: string, bytes: Buffer) {
    this.store(host).blobs.set(digest(bytes), bytes);
    return { digest: digest(bytes), size: bytes.length };
  }

  putManifest(host: string, repository: string, type: string, json: object) {
    const bytes = Buffer.from(JSON.stringify(json));
    const key = digest(bytes);
    this.store(host).manifests.set(`${repository}@${key}`, { type, bytes });
    return { digest: key, size: bytes.length };
  }

  fetch = async (input: URL | RequestInfo, init: RequestInit = {}) => {
    const url = new URL(input instanceof Request ? input.url : input);
    const method = init.method ?? "GET";
    const headers = new Headers(init.headers);
    this.requests.push({
      host: url.host,
      method,
      path: url.pathname,
      authorization: headers.get("authorization"),
    });
    if (url.host === "nscr.io") {
      const expected = `Basic ${Buffer.from(`token:${TOKEN}`).toString("base64")}`;
      if (headers.get("authorization") !== expected)
        return new Response(null, {
          status: 401,
          headers: { "www-authenticate": 'Basic realm="nscr.io"' },
        });
    }
    if (url.host === this.redirectStartTo) {
      const repository = /^\/v2\/(.+)\/blobs\/uploads\/$/.exec(
        url.pathname,
      )![1];
      const nscr = this.store("nscr.io");
      const id = String(nscr.uploads.size);
      nscr.uploads.set(id, []);
      return new Response(null, {
        status: 202,
        headers: {
          location: `https://nscr.io/v2/${repository}/blobs/uploads/${id}`,
        },
      });
    }
    if (
      this.redirectStartTo &&
      url.host === "nscr.io" &&
      method === "POST" &&
      url.pathname.endsWith("/blobs/uploads/")
    ) {
      const next = new URL(url);
      next.host = this.redirectStartTo;
      return new Response(null, {
        status: this.redirectStatus,
        headers: { location: next.href },
      });
    }
    const hop = Number(url.searchParams.get("hop") ?? 0);
    if (
      url.host === "nscr.io" &&
      /\/blobs\/uploads\//.test(url.pathname) &&
      hop < this.uploadRedirects
    ) {
      const next = new URL(url);
      next.searchParams.set("hop", String(hop + 1));
      return new Response(null, {
        status: this.redirectStatus,
        headers: this.redirectWithoutLocation
          ? {}
          : { location: next.pathname + next.search },
      });
    }
    url.searchParams.delete("hop");
    const store = this.store(url.host);
    const match = /^\/v2\/(.+)\/(manifests|blobs)\/(.*)$/.exec(url.pathname);
    if (!match) return new Response(null, { status: 404 });
    const [, repository, kind, rest] = match;
    const body = init.body
      ? Buffer.from(init.body as Uint8Array)
      : Buffer.alloc(0);
    if (kind === "manifests") {
      if (method === "PUT") {
        const entry = {
          type: headers.get("content-type")!,
          bytes: body,
        };
        store.manifests.set(`${repository}@${digest(body)}`, entry);
        store.manifests.set(`${repository}:${rest}`, entry);
        return new Response(null, {
          status: 201,
          headers: { "docker-content-digest": digest(body) },
        });
      }
      const entry = store.manifests.get(`${repository}@${rest}`);
      if (!entry) return new Response(null, { status: 404 });
      return new Response(method === "HEAD" ? null : entry.bytes, {
        headers: { "content-type": entry.type },
      });
    }
    if (rest === "uploads/" && method === "POST") {
      const id = String(store.uploads.size);
      store.uploads.set(id, []);
      return new Response(null, {
        status: 202,
        headers: { location: `/v2/${repository}/blobs/uploads/${id}` },
      });
    }
    const upload = /^uploads\/(\d+)$/.exec(rest);
    if (upload) {
      const parts = store.uploads.get(upload[1])!;
      parts.push(body);
      if (method === "PATCH")
        return new Response(null, {
          status: 202,
          headers: { location: url.pathname },
        });
      const bytes = Buffer.concat(parts);
      if (digest(bytes) !== url.searchParams.get("digest"))
        return new Response(null, { status: 400 });
      store.blobs.set(digest(bytes), bytes);
      return new Response(null, { status: 201 });
    }
    const blob = store.blobs.get(rest);
    if (!blob) return new Response(null, { status: 404 });
    if (method === "HEAD") return new Response(null, { status: 200 });
    const range = /^bytes=(\d+)-(\d+)$/.exec(headers.get("range") ?? "");
    if (!range) return new Response(blob);
    return new Response(blob.subarray(Number(range[1]), Number(range[2]) + 1), {
      status: 206,
    });
  };
}

const OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json";

/** A one-layer linux/amd64 image in `repository` on `host`, as a digest reference. */
export function image(
  registries: Registries,
  host: string,
  repository: string,
  layer: string,
  index = false,
) {
  const content = Buffer.from(layer);
  const blob = registries.putBlob(host, content);
  const config = registries.putBlob(
    host,
    Buffer.from(
      JSON.stringify({
        os: "linux",
        architecture: "amd64",
        config: { Entrypoint: [`/${layer}`] },
        rootfs: { type: "layers", diff_ids: [digest(`${layer}-tar`)] },
        history: [{ created_by: layer }],
      }),
    ),
  );
  const manifest = registries.putManifest(host, repository, OCI_MANIFEST, {
    schemaVersion: 2,
    mediaType: OCI_MANIFEST,
    config: {
      mediaType: "application/vnd.oci.image.config.v1+json",
      ...config,
    },
    layers: [
      { mediaType: "application/vnd.oci.image.layer.v1.tar+gzip", ...blob },
    ],
  });
  if (!index) return `${host}/${repository}@${manifest.digest}`;
  const type = "application/vnd.oci.image.index.v1+json";
  const top = registries.putManifest(host, repository, type, {
    schemaVersion: 2,
    mediaType: type,
    manifests: [
      {
        mediaType: OCI_MANIFEST,
        ...manifest,
        platform: { os: "linux", architecture: "amd64" },
      },
    ],
  });
  return `${host}/${repository}@${top.digest}`;
}

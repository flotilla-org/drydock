// The Modal SDK seam: the slice of `modal` (the JavaScript SDK, gRPC to
// api.modal.com) the module uses, narrowed so tests can stand in for it, and
// the one place Modal's failures become protocol errors.
import {
  AlreadyExistsError,
  ClientClosedError,
  ConflictError,
  InvalidError,
  ModalClient,
  NotFoundError,
  ResourceExhaustedError,
  type App as SdkApp,
  type Sandbox,
  type SandboxCreateParams,
} from "modal";
import { ProtocolFailure } from "../provider.js";

/** A Modal token pair, as the credential document carries it. */
export type Token = { token_id: string; token_secret: string };

/** An app the module owns, looked up or created by name. */
export type App = { readonly appId: string; readonly name?: string };

/** What prepare asks Modal to build: a registry base, then Dockerfile lines. */
export type Build = {
  base: string;
  commands: string[];
  /** Basic credentials for the base's registry, minted as an ephemeral secret. */
  pull?: { username: string; password: string };
};

/** The create parameters the module sets; nothing else reaches Modal. */
export type Create = Pick<
  SandboxCreateParams,
  | "name"
  | "tags"
  | "cpu"
  | "memoryMiB"
  | "timeoutMs"
  | "runtime"
  | "command"
  | "blockNetwork"
  | "outboundCidrAllowlist"
  | "outboundDomainAllowlist"
>;

/** One exec'd process, binary both ways, stderr discarded. */
export interface Process {
  readonly stdin: WritableStream<Uint8Array>;
  readonly stdout: ReadableStream<Uint8Array>;
  /** Stdin EOF. Modal never kills an exec, so this is how one ends. */
  closeStdin(): Promise<void>;
  wait(): Promise<number>;
}

/** One sandbox, by id. */
export interface Box {
  readonly sandboxId: string;
  getTags(): Promise<Record<string, string>>;
  /** Null while running, else its exit code (124 at its timeout, 137 terminated). */
  poll(): Promise<number | null>;
  terminate(): Promise<void>;
  exec(command: string[]): Promise<Process>;
  /** Frees this handle's connections; the sandbox keeps running. */
  detach(): void;
}

/** What the module needs from Modal, for one credential. */
export interface Vendor {
  app(name: string): Promise<App>;
  /** Builds (or finds by its definition) an image; returns its `im-…` id. */
  build(app: App, build: Build): Promise<string>;
  /** Refuses with NotFoundError an id Modal does not know. */
  image(id: string): Promise<void>;
  create(app: App, imageId: string, params: Create): Promise<Box>;
  fromName(appName: string, name: string): Promise<Box>;
  fromId(id: string): Promise<Box>;
  list(appId: string, tags: Record<string, string>): AsyncIterable<Box>;
  close(): void;
}

function box(sandbox: Sandbox): Box {
  return {
    sandboxId: sandbox.sandboxId,
    getTags: () => sandbox.getTags(),
    poll: () => sandbox.poll(),
    terminate: async () => {
      await sandbox.terminate({ wait: true });
    },
    exec: (command) =>
      sandbox.exec(command, {
        mode: "binary",
        stdout: "pipe",
        stderr: "ignore",
      }),
    detach: () => sandbox.detach(),
  };
}

/**
 * The real SDK for one token pair, passed to the client directly: never
 * `~/.modal.toml` or `MODAL_TOKEN_*`. The SDK still reads its server URL and
 * sandbox backend from those, so the host runs without them.
 */
export function sdkVendor(token: Token, environment?: string): Vendor {
  const client = new ModalClient({
    tokenId: token.token_id,
    tokenSecret: token.token_secret,
    environment,
  });
  // The SDK's own App handles, by id, for the calls that take one.
  const apps = new Map<string, SdkApp>();
  const sdkApp = (app: App) => {
    const found = apps.get(app.appId);
    if (!found) throw new TypeError("app not looked up by this client");
    return found;
  };
  return {
    async app(name) {
      const app = await client.apps.fromName(name, {
        environment,
        createIfMissing: true,
      });
      apps.set(app.appId, app);
      return app;
    },
    async build(app, { base, commands, pull }) {
      // Ephemeral: never named or listed, so nothing persists in the workspace.
      const secret = pull
        ? await client.secrets.fromObject(
            {
              REGISTRY_USERNAME: pull.username,
              REGISTRY_PASSWORD: pull.password,
            },
            { environment },
          )
        : undefined;
      const image = client.images
        .fromRegistry(base, secret)
        .dockerfileCommands(commands);
      return (await image.build(sdkApp(app))).imageId;
    },
    async image(id) {
      await client.images.fromId(id);
    },
    async create(app, imageId, params) {
      const image = await client.images.fromId(imageId);
      return box(await client.sandboxes.create(sdkApp(app), image, params));
    },
    async fromName(appName, name) {
      return box(
        await client.sandboxes.fromName(appName, name, { environment }),
      );
    },
    async fromId(id) {
      return box(await client.sandboxes.fromId(id));
    },
    async *list(appId, tags) {
      for await (const sandbox of client.sandboxes.list({ appId, tags }))
        yield box(sandbox);
    },
    close: () => client.close(),
  };
}

/** gRPC status codes (nice-grpc's `Status`), as Modal's raw errors carry them. */
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

/** Bounded so a build log never becomes a reason. */
const brief = (text: string) =>
  text.length > 400 ? `${text.slice(0, 400)}…` : text;

/** Modal and gRPC failures as protocol errors. Raw text is masked by the server. */
export function protocolError(error: unknown): ProtocolFailure {
  if (error instanceof ProtocolFailure) return error;
  const detail = String((error as Error)?.message ?? error);
  if (error instanceof Error && error.name === "AbortError")
    return new ProtocolFailure({ kind: "unavailable", reason: "call aborted" });
  if (error instanceof NotFoundError)
    return new ProtocolFailure({
      kind: "not_found",
      reason: `Modal: ${detail}`,
    });
  if (
    error instanceof AlreadyExistsError ||
    error instanceof ConflictError ||
    error instanceof InvalidError
  )
    return new ProtocolFailure({
      kind: "refused",
      reason: `Modal refused the request: ${brief(detail)}`,
    });
  if (error instanceof ResourceExhaustedError)
    return new ProtocolFailure({
      kind: "unavailable",
      reason: "Modal has no capacity for the sandbox",
      provider_error: detail,
    });
  if (error instanceof ClientClosedError)
    return new ProtocolFailure({
      kind: "unavailable",
      reason: "Modal client closed",
      provider_error: detail,
    });
  // The SDK throws plain errors for failed image builds (a pull refused, a
  // digest unknown): the image is the problem, not the service.
  if (/^Image build for \S+ (failed|terminated|timed out)/.test(detail))
    return new ProtocolFailure({
      kind: "refused",
      reason: `Modal could not build the image: ${brief(detail)}`,
    });
  const code = (error as { name?: string; code?: unknown })?.code;
  if ((error as Error)?.name === "ClientError" && typeof code === "number") {
    const message = brief(
      String((error as { details?: string }).details ?? detail),
    );
    switch (code) {
      case GRPC.UNAUTHENTICATED:
        return new ProtocolFailure({
          kind: "credential_rejected",
          reason: `Modal refused the credential: ${message}`,
        });
      case GRPC.PERMISSION_DENIED:
        // The token is valid but its role in the environment lacks the right.
        return new ProtocolFailure({
          kind: "refused",
          reason: `Modal denied the operation (the token lacks a right): ${message}`,
        });
      case GRPC.NOT_FOUND:
        return new ProtocolFailure({
          kind: "not_found",
          reason: `Modal: ${message}`,
        });
      case GRPC.INVALID_ARGUMENT:
      case GRPC.FAILED_PRECONDITION:
      case GRPC.ALREADY_EXISTS:
        return new ProtocolFailure({
          kind: "refused",
          reason: `Modal refused the request: ${message}`,
        });
      case GRPC.RESOURCE_EXHAUSTED:
        return new ProtocolFailure({
          kind: "rate_limited",
          reason: `Modal: ${message}`,
        });
      case GRPC.UNAVAILABLE:
      case GRPC.DEADLINE_EXCEEDED:
      case GRPC.ABORTED:
        return new ProtocolFailure({
          kind: "unavailable",
          reason: "Modal is unavailable",
          provider_error: detail,
        });
    }
  }
  return new ProtocolFailure({
    kind: "internal",
    reason: "Modal call failed",
    provider_error: detail,
  });
}

/** Whether a create failed because its name is taken in the app. */
export function alreadyExists(error: unknown) {
  return (
    error instanceof AlreadyExistsError ||
    ((error as Error)?.name === "ClientError" &&
      (error as { code?: unknown }).code === GRPC.ALREADY_EXISTS)
  );
}

/** Runs one SDK call; every failure becomes a protocol error. */
export async function call<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    throw protocolError(error);
  }
}

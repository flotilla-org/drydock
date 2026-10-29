// The Namespace SDK seam: the slice of `@namespacelabs/sdk` the module uses,
// typed so the real client satisfies it and tests can stand in for it, and the
// one place SDK calls are retried and their failures become protocol errors.
import type { Duplex } from "node:stream";
import { Code, ConnectError } from "@connectrpc/connect";
import { createComputeClient } from "@namespacelabs/sdk/api/compute";
import {
  createDevboxClient,
  DevboxGatewayError,
  DevboxTimeoutError,
  type CreateDevboxInput,
  type CreateServiceInput,
  type DevboxInfo,
  type ExecOptions,
  type ExecResult,
  type Image,
  type ImageSelector,
  type ListDevboxesOptions,
  type OperationOptions,
  type Page,
  type RegisterImageInput,
  type Service,
  type UpdateDevboxInput,
} from "@namespacelabs/sdk/devbox";
import { ProtocolFailure } from "../provider.js";

/** One devbox, as `devboxes.create`, `get` and `list` return it. */
export interface Box {
  readonly id: string;
  readonly name: string;
  readonly info: Readonly<DevboxInfo>;
  readonly services: {
    create(
      input: CreateServiceInput,
      options?: OperationOptions,
    ): Promise<Service>;
    list(options?: OperationOptions): Promise<Service[]>;
  };
  exec(argv: readonly string[], options?: ExecOptions): Promise<ExecResult>;
  start(options?: OperationOptions): Promise<unknown>;
  stop(options?: OperationOptions): Promise<unknown>;
  delete(options?: OperationOptions): Promise<void>;
  refresh(options?: OperationOptions): Promise<unknown>;
  update(
    input: UpdateDevboxInput,
    options?: OperationOptions,
  ): Promise<unknown>;
}

/** Live concurrency limits and use, from `UsageService/GetConcurrency`. */
export type Concurrency = {
  name: string;
  platforms: string[];
  limits?: { maxCpu: bigint; maxMemoryMb: bigint; maxInstanceCount: bigint };
  activeConcurrency?: { instanceCount: bigint; cpu: bigint; memoryMb: bigint };
};

/** What the module needs from Namespace, for one credential. */
export interface Vendor {
  devboxes: {
    create(input: CreateDevboxInput, options?: OperationOptions): Promise<Box>;
    get(ref: string, options?: OperationOptions): Promise<Box>;
    list(options?: ListDevboxesOptions): Promise<Page<Box>>;
  };
  images: {
    register(
      input: RegisterImageInput,
      options?: OperationOptions,
    ): Promise<Image>;
    get(selector: ImageSelector, options?: OperationOptions): Promise<Image>;
  };
  /**
   * A byte channel to `command` running in the devbox: an SSH exec channel over
   * the SDK's gateway, without a terminal, so bytes pass unchanged both ways.
   * Opening it starts a stopped devbox.
   */
  channel(box: Box, command: string, signal: AbortSignal): Promise<Duplex>;
  concurrency(signal: AbortSignal): Promise<Concurrency[]>;
  close(): void;
}

// The SDK keeps its ssh2 client private, but its gateway refuses Unix-socket
// forwards; an exec channel is the only binary-safe way to the agent's socket.
type SshClient = {
  exec(
    command: string,
    callback: (error: Error | undefined, channel: Duplex) => void,
  ): boolean;
};

/**
 * The real SDK for one bearer token. The token goes to the SDK through a
 * TokenSource only, never `loadDefaults`, `NSC_TOKEN_FILE` or a token file.
 */
export function sdkVendor(token: string): Vendor {
  const tokenSource = { issueToken: async () => token };
  const client = createDevboxClient({ tokenSource });
  return {
    devboxes: client.devboxes,
    images: client.images,
    async channel(box, command, signal) {
      const connection = await (box as any).connection({ signal });
      const ssh: SshClient | undefined = connection?.client;
      if (typeof ssh?.exec !== "function")
        throw new ProtocolFailure({
          kind: "internal",
          reason: "Namespace SDK no longer exposes its SSH client",
          provider_error: "",
        });
      return new Promise((resolve, reject) =>
        ssh.exec(command, (error, channel) =>
          error ? reject(error) : resolve(channel),
        ),
      );
    },
    async concurrency(signal) {
      const compute = createComputeClient({ tokenSource });
      return (await compute.usage.getConcurrency({}, { signal })).concurrency;
    },
    close: () => client.close(),
  };
}

function messages(error: unknown): string[] {
  const seen: string[] = [];
  for (let e: any = error; e && seen.length < 8; e = e.cause)
    seen.push(String(e.message ?? e), String(e.code ?? ""));
  return seen;
}

/** Gateway calls can fail with `Premature close` after they took effect. */
export function prematureClose(error: unknown) {
  return messages(error).some(
    (m) => m.includes("Premature close") || m === "ERR_STREAM_PREMATURE_CLOSE",
  );
}

const ATTEMPTS = 3;

/**
 * Runs one SDK call. On `Premature close`, `settled` says whether the call
 * took effect anyway (returning its result) or not (undefined), and the call
 * is repeated only if not. A `settled` check that itself closes early counts
 * as not settled, so the call repeats; `ATTEMPTS` bounds both. Every other
 * failure becomes a protocol error.
 */
export async function call<T>(
  operation: () => Promise<T>,
  settled: () => Promise<T | undefined> = async () => undefined,
): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await operation();
    } catch (error) {
      if (!prematureClose(error) || attempt === ATTEMPTS)
        throw protocolError(error);
    }
    try {
      const result = await settled();
      if (result !== undefined) return result;
    } catch (error) {
      if (!prematureClose(error)) throw protocolError(error);
    }
  }
}

/** SDK and RPC failures as protocol errors. Raw text is masked by the server. */
export function protocolError(error: unknown): ProtocolFailure {
  if (error instanceof ProtocolFailure) return error;
  if (error instanceof Error && error.name === "AbortError")
    return new ProtocolFailure({ kind: "unavailable", reason: "call aborted" });
  const detail = String((error as Error)?.message ?? error);
  if (error instanceof DevboxGatewayError)
    return error.statusCode === 401 || error.statusCode === 403
      ? new ProtocolFailure({
          kind: "credential_rejected",
          reason: `Namespace gateway refused the credential (HTTP ${error.statusCode})`,
        })
      : new ProtocolFailure({
          kind: "unavailable",
          reason: `Namespace gateway HTTP ${error.statusCode}`,
          provider_error: detail,
        });
  if (error instanceof DevboxTimeoutError)
    return new ProtocolFailure({
      kind: "unavailable",
      reason: "Namespace call timed out",
      provider_error: detail,
    });
  const connect = error instanceof ConnectError ? error : undefined;
  switch (connect?.code) {
    case Code.Unauthenticated:
    case Code.PermissionDenied:
      return new ProtocolFailure({
        kind: "credential_rejected",
        reason: `Namespace refused the credential: ${connect.rawMessage}`,
      });
    case Code.NotFound:
      return new ProtocolFailure({
        kind: "not_found",
        reason: `Namespace: ${connect.rawMessage}`,
      });
    case Code.InvalidArgument:
    case Code.FailedPrecondition:
    case Code.AlreadyExists:
    case Code.OutOfRange:
      return new ProtocolFailure({
        kind: "refused",
        reason: `Namespace refused the request: ${connect.rawMessage}`,
      });
    case Code.ResourceExhausted:
      return new ProtocolFailure({
        kind: "quota_exhausted",
        reason: `Namespace: ${connect.rawMessage}`,
      });
    case Code.Unavailable:
    case Code.DeadlineExceeded:
    case Code.Aborted:
      return new ProtocolFailure({
        kind: "unavailable",
        reason: "Namespace is unavailable",
        provider_error: detail,
      });
  }
  if (prematureClose(error))
    return new ProtocolFailure({
      kind: "unavailable",
      reason: "Namespace gateway closed the call early",
      provider_error: detail,
    });
  return new ProtocolFailure({
    kind: "internal",
    reason: "Namespace call failed",
    provider_error: detail,
  });
}

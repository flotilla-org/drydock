import type { Host } from "./host.js";
import { ProtocolFailure, type Types } from "./provider.js";
const statuses: Record<Types["ProtocolError"]["kind"], number> = {
  not_found: 404,
  method_not_allowed: 405,
  refused: 422,
  unavailable: 503,
  rate_limited: 429,
  quota_exhausted: 402,
  credential_rejected: 502,
  command_failed: 424,
  internal: 500,
};
/** Framework/parser diagnostics never cross the protocol boundary or enter logs. */
export function errorResponse(host: Host, error: unknown) {
  const framework = error as { code?: string; statusCode?: number } | undefined;
  const detail: Types["ProtocolError"] =
    error instanceof ProtocolFailure
      ? host.errorDetail(error)
      : framework?.code?.startsWith("FST_ERR_") &&
          framework.statusCode !== undefined &&
          framework.statusCode >= 400 &&
          framework.statusCode < 500
        ? { kind: "refused", reason: "invalid request" }
        : {
            kind: "internal",
            reason: "host request failed",
            provider_error: "",
          };
  const headers: Record<string, string> = {
    "content-type": "application/json",
  };
  if (
    "retry_after" in detail &&
    detail.retry_after !== undefined &&
    detail.retry_after !== null
  )
    headers["retry-after"] = String(detail.retry_after);
  return { detail, status: statuses[detail.kind], headers };
}

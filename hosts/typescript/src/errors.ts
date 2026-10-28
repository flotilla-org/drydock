import { ProtocolFailure, type Types } from "./provider.js";
const status: Record<Types["ProtocolError"]["kind"], number> = {
  not_found: 404,
  method_not_allowed: 405,
  refused: 422,
  image_refused: 422,
  unavailable: 503,
  rate_limited: 429,
  quota_exhausted: 402,
  credential_rejected: 502,
  command_failed: 424,
  internal: 500,
};
/** Private provider errors reach Daemon, whose policy masks public diagnostics. */
export function errorResponse(error: unknown) {
  const detail: Types["ProtocolError"] =
    error instanceof ProtocolFailure
      ? error.detail
      : {
          kind: "internal",
          reason: "provider bridge failed",
          provider_error: "",
        };
  const headers: Record<string, string> = {
    "content-type": "application/json",
  };
  // Canonical OpenAPI defines retry_after as whole seconds (HTTP Retry-After).
  if ("retry_after" in detail && detail.retry_after != null)
    headers["retry-after"] = String(detail.retry_after);
  return { status: status[detail.kind], headers, detail };
}

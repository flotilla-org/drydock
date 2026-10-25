// Keep parity with drydock-protocol/src/diagnostic.rs. Patterns contain secrets:
// never log this owner, its cached patterns, or the retired credential values.
export const DIAGNOSTIC_LIMIT = 16 * 1024;
export const RECENT_CREDENTIAL_LIMIT = 32;
const marker = "<REDACTED>";
const truncated = "...<truncated>";

function patterns(secret: string): string[] {
  if (!secret) return [];
  const json = JSON.stringify(secret).slice(1, -1);
  const percent = [...Buffer.from(secret)]
    .map((byte) =>
      /[A-Za-z0-9._~-]/.test(String.fromCharCode(byte))
        ? String.fromCharCode(byte)
        : "%" + byte.toString(16).toUpperCase().padStart(2, "0"),
    )
    .join("");
  const lower = percent.replace(/%[0-9A-F]{2}/g, (part) => part.toLowerCase());
  const base64 = Buffer.from(secret).toString("base64");
  const url64 = base64.replace(/\+/g, "-").replace(/\//g, "_");
  return [
    secret,
    json,
    ...[false, true].map((upper) =>
      json.replace(
        /[^\x00-\x7f]/g,
        (char) =>
          "\\u" +
          (upper
            ? char.charCodeAt(0).toString(16).toUpperCase()
            : char.charCodeAt(0).toString(16)
          ).padStart(4, "0"),
      ),
    ),
    percent,
    lower,
    percent.replace(/%20/g, "+"),
    lower.replace(/%20/g, "+"),
    base64,
    base64.replace(/=+$/, ""),
    url64,
    url64.replace(/=+$/, ""),
  ];
}
function sorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort(
    (a, b) => b.length - a.length || a.localeCompare(b),
  );
}
function redact(text: string, known: string[]): string {
  let rest = 0,
    result = "";
  while (rest < text.length) {
    let at = -1,
      length = 0;
    for (const pattern of known) {
      const next = text.indexOf(pattern, rest);
      if (
        next >= 0 &&
        (at < 0 || next < at || (next === at && pattern.length > length))
      ) {
        at = next;
        length = pattern.length;
      }
    }
    if (at < 0) return result + text.slice(rest);
    result += text.slice(rest, at) + marker;
    rest = at + length;
  }
  return result;
}
function bounded(text: string): string {
  if (Buffer.byteLength(text) <= DIAGNOSTIC_LIMIT) return text;
  let bytes = 0,
    prefix = "";
  for (const char of text) {
    const size = Buffer.byteLength(char);
    if (bytes + size > DIAGNOSTIC_LIMIT - Buffer.byteLength(truncated)) break;
    prefix += char;
    bytes += size;
  }
  return prefix + truncated;
}
export class DiagnosticSecrets {
  private current = new Map<string, string>();
  private recent: string[] = [];
  private cached: string[] = [];
  private contains(value: string) {
    return (
      [...this.current.values()].includes(value) || this.recent.includes(value)
    );
  }
  remember(provider: string, value: string): void {
    if (!value || this.current.get(provider) === value) return;
    const previous = this.current.get(provider);
    this.current.set(provider, value);
    if (previous) {
      this.recent = this.recent.filter((item) => item !== previous);
      if (![...this.current.values()].includes(previous))
        this.recent.push(previous);
    }
    this.recent = this.recent
      .filter((item) => item !== value)
      .slice(-RECENT_CREDENTIAL_LIMIT);
    this.cached = sorted(
      [...this.current.values(), ...this.recent].flatMap(patterns),
    );
  }
  /** Extra is owned by this call only; it must not extend global retirement. */
  mask(value: unknown, extra?: string): unknown {
    const known =
      extra && !this.contains(extra)
        ? sorted([...this.cached, ...patterns(extra)])
        : this.cached;
    const text = (value: string, limit = true) => {
      const masked = redact(value, known);
      return limit ? bounded(masked) : masked;
    };
    if (typeof value === "string") return text(value);
    if (!value || typeof value !== "object") return value;
    // Preserve protocol discriminants. Command output is sensitive payload rather
    // than bounded diagnostic text, matching Rust's CommandFailed contract.
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        typeof item === "string" &&
        ["reason", "provider_error", "output"].includes(key)
          ? text(item, key !== "output")
          : item,
      ]),
    );
  }
  clear(): void {
    this.current.clear();
    this.recent = [];
    this.cached = [];
  }
}

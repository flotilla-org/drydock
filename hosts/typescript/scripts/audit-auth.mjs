// Audit the exact admission helper compiled into this host, plus executable
// endpoint tests. HTTP timing measurements cannot prove constant-time execution.
import { readFileSync } from "node:fs";
const source = readFileSync(
  new URL("../dist/server.js", import.meta.url),
  "utf8",
)
  .replace(/\s+/g, "")
  .replace(/"/g, "'");
if (
  !source.includes(
    "import{randomBytes,timingSafeEqual,createHash}from'node:crypto'",
  ) ||
  !source.includes("returntimingSafeEqual(actual,expected)?0:401") ||
  !source.includes(
    "actual=createHash('sha256').update(authorization[1]).digest(),expected=createHash('sha256').update(token??'').digest()",
  ) ||
  !source.includes("req.headersDistinct.authorization?.length!==1") ||
  !source.includes("authorization[0].toLowerCase()")
)
  process.exit(1);

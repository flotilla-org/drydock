import { chmodSync } from "node:fs";
chmodSync(new URL("../dist/main.js", import.meta.url), 0o755);

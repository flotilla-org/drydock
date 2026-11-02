#!/usr/bin/env python3
"""Live check of the Tensorlake module through drydockd and drydock.

    scripts/live-tensorlake.py KEY_FILE --organization-id ID [--bin-dir DIR] [--agent PATH] [--image IMAGE]

KEY_FILE holds a Tensorlake project API key; ID is its organization (shown by
`tl whoami`, or `POST /platform/v1/keys/introspect`). DIR holds drydock,
drydockd and drydock-host built from this branch (default target/release,
from `cargo build --release -p drydock -p drydock-host -p drydock-agent`).
PATH is a linux/amd64 drydock-agent, which launch pushes into the vessel; by
default $DRYDOCK_AGENT_BIN_LINUX_AMD64, else DIR/drydock-agent-linux-amd64,
else DIR/drydock-agent on a Linux x86_64 host. IMAGE is a public
linux/amd64 image with a glibc userland, bash and curl, pinned by digest
(default buildpack-deps:bookworm-curl as of 2026-11-02). Only the Python standard library is needed.

It starts drydockd with a throwaway DRYDOCK_ROOT and a generated drydock.toml
whose credential is `{ file = KEY_FILE }`, then, printing PASS or FAIL for
each check:

- prepares the image (a CAS build at Tensorlake, or the one already there);
- launches a vessel, which returns only after the agent's hello through
  Tensorlake's tunnel;
- confirms a non-root guest process gets 401 from the agent's TCP listener
  and cannot read its token;
- provisions a second vessel under deny-all with one allowed host name and
  checks, as root, that the host answers and others do not;
- suspends and resumes the vessel, then reads the agent's /hello again
  through drydockd's relay;
- destroys both, and lists sandboxes and snapshots through Tensorlake's API
  to show none of drydock's are left.

Cleanup runs whatever happened. The prepared `dd-` image stays: API keys
cannot delete images, so the script reports it for a project admin to remove
with `tl sbx image rm`. Exit status 0 means every check passed.
"""
import argparse
import hashlib
import http.client
import json
import os
import platform
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

API = "https://api.tensorlake.ai"
DOMAIN = "sandbox.tensorlake.ai"
INSTANCE = "tensorlake"
# The module's sandbox names: dd-<8 hex of the instance name>-…
PREFIX = f"dd-{hashlib.sha256(INSTANCE.encode()).hexdigest()[:8]}-"
FAILED = []
# buildpack-deps:bookworm-curl on 2026-11-02.
IMAGE = "docker.io/library/buildpack-deps@sha256:f5c5d07ea24ee91272739fe451c280aa4b7fa5120b9278815db5fcd713d83772"


class Stop(Exception):
    """A check failed that later checks depend on; cleanup and the summary still run."""


def check(condition, message):
    print(("PASS " if condition else "FAIL ") + message, flush=True)
    if not condition:
        FAILED.append(message)
    return condition


def tensorlake(method, url, key, body=None, timeout=120):
    """One Tensorlake request: (status, body bytes)."""
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url if url.startswith("https://") else API + url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {key}")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def paged(path, rows, key):
    """Every row of a cursor-paged Tensorlake list."""
    found, cursor = [], None
    for _ in range(100):
        status, body = tensorlake("GET", path + (f"?limit=100&cursor={cursor}" if cursor else "?limit=100"), key)
        if status != 200:
            raise RuntimeError(f"GET {path}: HTTP {status}: {body[:300]!r}")
        page = json.loads(body)
        found += page.get(rows) or []
        cursor = page.get("next_cursor") or page.get("cursor")
        if not cursor:
            return found
    raise RuntimeError(f"GET {path}: too many pages")


def run_in_guest(name, key, script, user="root"):
    """`bash -c script` in a sandbox through Tensorlake: (exit code, lines)."""
    body = {"command": "bash", "args": ["-c", script], "user": user, "timeout": 60}
    status, raw = tensorlake("POST", f"https://{name}.{DOMAIN}/api/v1/processes/run", key, body)
    if status != 200:
        return None, [f"HTTP {status}: {raw[:300]!r}"]
    lines, code = [], None
    for line in raw.decode(errors="replace").splitlines():
        if line.startswith("data:"):
            event = json.loads(line[5:])
            if "line" in event:
                lines.append(event["line"])
            if "exit_code" in event:
                code = event["exit_code"]
    return code, lines


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=900):
        super().__init__("drydock", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Drydock:
    def __init__(self, bin_dir, root, key_file, organization, image, agent):
        self.bin_dir, self.root, self.image = bin_dir, root, image
        self.config = os.path.join(root, "drydock.toml")
        self.socket = os.path.join(root, "run", "drydock.sock")
        os.makedirs(os.path.dirname(self.socket), mode=0o700)
        os.chmod(os.path.dirname(self.socket), 0o700)
        with open(self.config, "w") as file:
            file.write(
                f'[providers.{INSTANCE}]\nmodule = "tensorlake"\ncredential = {{ file = {json.dumps(key_file)} }}\n'
                f"image = {json.dumps(image)}\n\n[providers.{INSTANCE}.settings]\n"
                f"organization_id = {json.dumps(organization)}\n"
            )
        self.env = dict(
            os.environ,
            DRYDOCK_ROOT=root,
            DRYDOCK_DAEMON_BIN=os.path.join(bin_dir, "drydockd"),
            DRYDOCK_HOST_BIN=os.path.join(bin_dir, "drydock-host"),
            DRYDOCK_AGENT_BIN_LINUX_AMD64=agent,
        )
        log = open(os.path.join(root, "drydockd.log"), "w")
        self.daemon = subprocess.Popen(
            [self.env["DRYDOCK_DAEMON_BIN"], "--config", self.config, "--socket", self.socket],
            env=self.env, stdout=log, stderr=subprocess.STDOUT,
        )
        for _ in range(300):
            if os.path.exists(self.socket):
                return
            if self.daemon.poll() is not None:
                break
            time.sleep(0.1)
        raise SystemExit(f"drydockd did not start; see {log.name}")

    def cli(self, *args, timeout=900):
        """`drydock ARGS`: (exit code, parsed stdout or its text, stderr)."""
        command = [os.path.join(self.bin_dir, "drydock"), "--config", self.config, "--socket", self.socket, *args]
        result = subprocess.run(command, env=self.env, capture_output=True, text=True, timeout=timeout)
        try:
            output = json.loads(result.stdout) if result.stdout.strip() else None
        except json.JSONDecodeError:
            output = result.stdout
        return result.returncode, output, result.stderr.strip()

    def api(self, method, path, body=None):
        """One call on drydockd's socket: (status, parsed body)."""
        connection = UnixConnection(self.socket)
        headers = {"Content-Type": "application/json"} if body is not None else {}
        connection.request(method, path, body=None if body is None else json.dumps(body), headers=headers)
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        try:
            return response.status, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return response.status, raw.decode(errors="replace")

    def hello(self, environment):
        """The agent's GET /hello through drydockd's relay, as HTTP/1.1."""
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(60)
        connection.connect(self.socket)
        connection.sendall(
            f"GET /v1/providers/{INSTANCE}/environments/{environment}/relay HTTP/1.1\r\nHost: drydock\r\n"
            "Connection: Upgrade\r\nUpgrade: drydock-relay\r\n\r\n".encode()
        )
        head = read_head(connection)
        if not head.startswith(b"HTTP/1.1 101"):
            return None, head.decode(errors="replace").splitlines()[:1]
        connection.sendall(b"GET /hello HTTP/1.1\r\nHost: agent\r\nConnection: close\r\n\r\n")
        head = read_head(connection)
        body = b""
        while chunk := connection.recv(65536):
            body += chunk
        connection.close()
        if b"chunked" in head.lower():
            body = b"".join(body.split(b"\r\n")[1::2])
        if not head.startswith(b"HTTP/1.1 200"):
            return None, head.decode(errors="replace").splitlines()[:1]
        return json.loads(body), None

    def stop(self):
        self.daemon.send_signal(signal.SIGTERM)
        try:
            self.daemon.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.daemon.kill()


def read_head(connection):
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = connection.recv(1)
        if not chunk:
            break
        head += chunk
    return head


# A non-root guest process: bash's /dev/tcp, without and with a guessed token.
GUEST_PROBE = r"""
id -u
if cat /run/drydock/tcp.token >/dev/null 2>&1; then echo "TOKEN READABLE"; else echo "token file unreadable"; fi
for authorization in "" "Authorization: Bearer $GUESS"; do
  exec 3<>/dev/tcp/127.0.0.1/7811 || exit 3
  printf "GET /v1/connect HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: drydock-agent\r\n%s\r\n\r\n" "$authorization" >&3
  timeout 10 head -n 1 <&3 | tr -d '\r'
  exec 3<&-
done
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("key_file")
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--bin-dir", default="target/release")
    parser.add_argument("--agent", help="a linux/amd64 drydock-agent (Tensorlake's platform)")
    # Pinned: drydock's resolver cannot yet resolve Docker Hub tags (drydock#200).
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("--allowed-host", default="github.com")
    parser.add_argument("--denied-host", default="example.com")
    options = parser.parse_args()
    key_file = os.path.abspath(options.key_file)
    key = open(key_file).read().strip()
    bin_dir = os.path.abspath(options.bin_dir)
    for binary in ("drydock", "drydockd", "drydock-host"):
        if not os.access(os.path.join(bin_dir, binary), os.X_OK):
            raise SystemExit(f"{bin_dir}/{binary} is missing; cargo build --release -p drydock -p drydock-host -p drydock-agent")
    agent = options.agent or os.environ.get("DRYDOCK_AGENT_BIN_LINUX_AMD64")
    if not agent and os.access(os.path.join(bin_dir, "drydock-agent-linux-amd64"), os.X_OK):
        agent = os.path.join(bin_dir, "drydock-agent-linux-amd64")
    if not agent and platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64"):
        agent = os.path.join(bin_dir, "drydock-agent")
    if not agent or not os.access(agent, os.X_OK):
        raise SystemExit(f"no linux/amd64 drydock-agent at {agent or bin_dir + '/drydock-agent-linux-amd64'}; "
                         "pass --agent PATH (the tools-image release artifact carries one)")
    agent = os.path.abspath(agent)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    # Short, so the daemon's socket path fits a Unix socket address.
    root = tempfile.mkdtemp(prefix="dd-tl-", dir="/tmp")
    os.chmod(root, 0o700)
    drydock = Drydock(bin_dir, root, key_file, options.organization_id, options.image, agent)
    environments, sandbox_ids, prepared = [], set(), None
    try:
        code, providers, error = drydock.cli("providers")
        declaration = next((p for p in providers or [] if p.get("provider") == INSTANCE), {})
        check(code == 0 and declaration.get("readiness", {}).get("status") == "ready", f"drydockd loads the tensorlake module: {error or declaration.get('readiness')}")

        started = time.time()
        code, prepared, error = drydock.cli("prepare", INSTANCE, "--image", options.image)
        check(code == 0 and str((prepared or {}).get("id", "")).startswith("dd-"), f"prepare in {time.time() - started:.1f}s: {(prepared or {}).get('id') or error}")

        started = time.time()
        code, environment, error = drydock.cli("launch", INSTANCE, "--image", options.image)
        launched = (environment or {}).get("id") if code == 0 else None
        if launched:
            environments.append(launched)
        check(bool(launched) and environment.get("state", {}).get("state") == "running",
              f"launch returned after the agent's hello in {time.time() - started:.1f}s: {launched or error}")
        if not launched:
            raise Stop
        status, body = tensorlake("GET", f"/sandboxes/{launched}", key)
        if status == 200:
            sandbox_ids.add(json.loads(body)["id"])

        code, lines = run_in_guest(launched, key, f"GUESS={secrets.token_urlsafe(32)}; {GUEST_PROBE}", user="nobody")
        print(f"guest probe as nobody (exit {code}): {lines}", flush=True)
        check(len(lines) >= 1 and lines[0] != "0", "the probe ran as a non-root user")
        check("token file unreadable" in lines, "the non-root user cannot read the token file")
        refusals = [line for line in lines if line.startswith("HTTP/1.1 ")]
        check(refusals == ["HTTP/1.1 401 Unauthorized"] * 2, f"no token and a guessed token both get 401: {refusals}")

        if prepared:
            request = {
                "label": f"live-egress-{secrets.token_hex(4)}",
                "prepared": prepared,
                "size": {"cpus": 1.0, "memory_bytes": 1 << 30, "disk_bytes": 10 << 30},
                "egress": {"mode": "deny_all", "direct": [{"kind": "host", "host": options.allowed_host}]},
            }
            status, egress = drydock.api("POST", f"/v1/providers/{INSTANCE}/environments", request)
            egress_id = (egress or {}).get("id") if status in (200, 201) else None
            if egress_id:
                environments.append(egress_id)
                status, body = tensorlake("GET", f"/sandboxes/{egress_id}", key)
                if status == 200:
                    sandbox_ids.add(json.loads(body)["id"])
            check(bool(egress_id), f"provisioned under deny-all allowing {options.allowed_host}: {egress_id or egress}")
            if egress_id:
                probe = lambda target: run_in_guest(egress_id, key, f"curl -sS -m 15 -o /dev/null -w '%{{http_code}}' {target}")
                code, lines = probe(f"https://{options.allowed_host}/")
                check(code == 0, f"root reaches the allowed {options.allowed_host}: exit {code} {lines[-1:]}")
                code, lines = probe(f"https://{options.denied_host}/")
                check(code not in (0, None), f"root cannot reach {options.denied_host}: exit {code} {lines[-1:]}")
                code, lines = probe("https://1.1.1.1/")
                check(code not in (0, None), f"root cannot reach an unlisted address: exit {code} {lines[-1:]}")
                code, lines = run_in_guest(egress_id, key, "nft flush ruleset 2>&1; echo 'nameserver 1.1.1.1' > /etc/resolv.conf; "
                                           f"curl -sS -m 15 -o /dev/null -w '%{{http_code}}' https://{options.denied_host}/")
                check(code not in (0, None), f"root stays confined after flushing nftables and rewriting resolv.conf: exit {code}")
                code, _, error = drydock.cli("destroy", INSTANCE, egress_id)
                check(code == 0, f"destroyed the egress vessel: {error}")

        status, token = drydock.api("POST", f"/v1/providers/{INSTANCE}/environments/{launched}/suspend")
        check(status == 200 and isinstance(token, dict) and "token" in token, f"suspend: HTTP {status}")
        code, inspected, error = drydock.cli("inspect", INSTANCE, launched)
        check((inspected or {}).get("state", {}).get("state") == "stopped", f"suspended vessel reads stopped: {(inspected or {}).get('state') or error}")
        status, body = drydock.api("POST", f"/v1/providers/{INSTANCE}/environments/{launched}/resume", token)
        check(200 <= status < 300, f"resume: HTTP {status} {body if status >= 300 else ''}")
        hello, error = drydock.hello(launched)
        check(bool(hello and hello.get("fingerprint")), f"/hello through drydockd's relay after resume: {error or hello.get('fingerprint', '')[:16]}")

        code, _, error = drydock.cli("destroy", INSTANCE, launched)
        check(code == 0, f"destroyed the vessel: {error}")
    except Stop:
        pass
    finally:
        for environment in environments:
            drydock.cli("destroy", INSTANCE, environment, timeout=300)
        try:
            # Anything of ours drydock could not remove goes here, snapshots too.
            for row in paged("/sandboxes", "sandboxes", key):
                if str(row.get("name", "")).startswith(PREFIX):
                    sandbox_ids.add(row["id"])
                    tensorlake("DELETE", f"/sandboxes/{row['name']}", key)
            leftovers = [s for s in paged("/snapshots", "snapshots", key) if s.get("sandbox_id") in sandbox_ids]
            for snapshot in leftovers:
                tensorlake("DELETE", f"/snapshots/{snapshot.get('snapshot_id') or snapshot.get('id')}", key)
            remaining = [r["name"] for r in paged("/sandboxes", "sandboxes", key) if str(r.get("name", "")).startswith(PREFIX)]
            check(not remaining, f"no drydock sandboxes are left: {remaining}")
            check(not leftovers, f"drydock's destroy left no snapshots: {[s.get('snapshot_id') or s.get('id') for s in leftovers]}")
            if prepared:
                status, body = tensorlake("GET", f"/images/v4/images/name/{prepared['id']}", key)
                if status == 200:
                    image = json.loads(body)
                    status, body = tensorlake("DELETE", f"/images/v4/images/{image['id']}", key)
                    if status in (200, 202, 204):
                        print(f"deleted the prepared image {prepared['id']}", flush=True)
                    else:
                        print(f"NOTE the prepared image {prepared['id']} ({image['id']}) remains (HTTP {status}); "
                              f"a project admin removes it with: tl sbx image rm {prepared['id']}", flush=True)
        except Exception as error:  # Cleanup reports, never hides, what it could not do.
            check(False, f"cleanup through Tensorlake's API: {error}")
        drydock.stop()
        print(f"drydockd's log: {os.path.join(root, 'drydockd.log')}", flush=True)
    print("ALL CHECKS PASSED" if not FAILED else f"{len(FAILED)} CHECKS FAILED", flush=True)
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()

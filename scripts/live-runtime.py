#!/usr/bin/env python3
"""Live check of the Runtime (withruntime.com) module through drydockd and drydock.

    scripts/live-runtime.py KEY_FILE [--bin-dir DIR] [--agent PATH] [--image IMAGE]

KEY_FILE holds a Runtime API key (`rtcloud_…`) with full access; reach
`agent` is expected, so listings show only what this key made. DIR holds
drydock, drydockd and drydock-host built from this branch (default
target/release, from `cargo build --release -p drydock -p drydock-host -p
drydock-agent`). PATH is a linux/amd64 drydock-agent, which launch pushes
into the vessel; by default $DRYDOCK_AGENT_BIN_LINUX_AMD64, else
DIR/drydock-agent-linux-amd64, else DIR/drydock-agent on a Linux x86_64
host. On a Mac, extract the one in the pinned tools image:

    id=$(docker create --platform linux/amd64 "$(cat crates/drydock/tools-image.txt)")
    docker cp "$id":/opt/drydock/drydock-agent target/release/drydock-agent-linux-amd64
    docker rm "$id"

or cross-build it with cargo-zigbuild:

    cargo zigbuild --release -p drydock-agent --target x86_64-unknown-linux-gnu
    # then --agent target/x86_64-unknown-linux-gnu/release/drydock-agent

IMAGE is a public linux/amd64 image with a glibc userland, bash, curl and
python3, pinned by digest (default python:3.13-bookworm as of 2026-11-03).
Runtime's tunnel runs a python3 helper inside the sandbox, which its docs
don't say; without python3 the module refuses at provision.
Only the Python standard library is needed.

It starts drydockd with a throwaway DRYDOCK_ROOT (a short directory under
/tmp, so Unix socket paths fit macOS's 104 bytes) and a generated
drydock.toml whose credential is `{ file = KEY_FILE }`, then, printing PASS
or FAIL for each check:

- prepares the image (a Dockerfile build at Runtime, or the one already there);
- launches a vessel, which returns only after the agent's hello through
  Runtime's tunnel;
- confirms a non-root guest process gets 401 from the agent's TCP listener
  on 127.0.0.1:7811 and cannot read its token, and that the agent's
  environment holds no RUNTIME_ID_TOKEN_REQUEST_TOKEN;
- provisions a second vessel under deny-all with one allowed host name and
  checks, as root, that the host answers and others do not, even after
  root rewrites the guest's DNS and firewall;
- suspends and resumes the vessel, then reads the agent's /hello again
  through drydockd's relay;
- destroys both, then lists sandboxes (stopped ones included) and
  snapshots through Runtime's API to show none of drydock's are left, and
  deletes the image prepare built.

Cleanup runs whatever happened. Each FAIL names its step and what the other
side said; the script exits non-zero after any FAIL. At the end it prints
what the key spent (GET /v1/limits and /v1/usage).
"""
import argparse
import http.client
import json
import os
import platform
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.withruntime.com/v1"
INSTANCE = "runtime"
FAILED = []
# python:3.13-bookworm on 2026-11-03: Runtime's tunnel needs python3 in the guest.
IMAGE = "docker.io/library/python@sha256:3856e3e7bf4d0ba061501a84ed2eb0d429663307c0f54f191dc4de03c7081c3e"


class Stop(Exception):
    """A check failed that later checks depend on; cleanup and the summary still run."""


def check(condition, message):
    print(("PASS " if condition else "FAIL ") + message, flush=True)
    if not condition:
        FAILED.append(message)
    return condition


def runtime(method, path, key, body=None, timeout=120):
    """One Runtime request: (status, parsed body or text)."""
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(path if path.startswith("https://") else API + path, data=data, method=method)
    request.add_header("Authorization", f"Bearer {key}")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read()
    try:
        return status, json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return status, raw.decode(errors="replace")[:500]


def paged(path, key):
    """Every row of a `{data, nextCursor}` list."""
    found, cursor = [], None
    for _ in range(100):
        joiner = "&" if "?" in path else "?"
        status, page = runtime("GET", path + (f"{joiner}cursor={cursor}" if cursor else ""), key)
        if status != 200:
            raise RuntimeError(f"GET {path}: HTTP {status}: {page}")
        found += page.get("data") or []
        cursor = page.get("nextCursor")
        if not cursor:
            return found
    raise RuntimeError(f"GET {path}: too many pages")


def run_in_guest(sandbox, key, script, user="root"):
    """`bash -c script` in a sandbox through Runtime's exec: (exit code, output lines)."""
    status, body = runtime("POST", f"/sandboxes/{sandbox}:exec", key, {"command": script, "user": user, "timeoutMs": 60000})
    if status != 200:
        return None, [f"HTTP {status}: {body}"]
    return body.get("exitCode"), (body.get("stdout", "") + body.get("stderr", "")).splitlines()


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=900):
        super().__init__("drydock", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Drydock:
    def __init__(self, bin_dir, root, key_file, image, agent):
        self.bin_dir, self.root, self.image = bin_dir, root, image
        self.config = os.path.join(root, "drydock.toml")
        self.socket = os.path.join(root, "run", "drydock.sock")
        os.makedirs(os.path.dirname(self.socket), mode=0o700)
        os.chmod(os.path.dirname(self.socket), 0o700)
        with open(self.config, "w") as file:
            file.write(
                f'[providers.{INSTANCE}]\nmodule = "runtime"\ncredential = {{ file = {json.dumps(key_file)} }}\n'
                f"image = {json.dumps(image)}\n"
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
            return None, head.decode(errors="replace")
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


# A non-root guest process (Runtime's sandbox user, uid 1000): bash's
# /dev/tcp, without and with a guessed token.
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
# Whether any drydock-agent process holds Runtime's identity-token credential.
# The pattern is anchored to the agent's argv[0], so this probe's own shell,
# whose command line names the agent too, is not counted.
IDENTITY_PROBE = r"""
found=0
for pid in $(pgrep -f '^/opt/drydock/drydock-agent( |$)'); do
  if tr '\0' '\n' < /proc/$pid/environ | grep -q '^RUNTIME_ID_TOKEN_REQUEST_TOKEN='; then found=1; fi
done
echo "agents $(pgrep -fc '^/opt/drydock/drydock-agent( |$)') identity $found"
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("key_file")
    parser.add_argument("--bin-dir", default="target/release")
    parser.add_argument("--agent", help="a linux/amd64 drydock-agent (Runtime's platform)")
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
                         "pass --agent PATH: extract /opt/drydock/drydock-agent from the pinned tools image "
                         "(crates/drydock/tools-image.txt) or cargo zigbuild it; see --help")
    agent = os.path.abspath(agent)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    status, limits = runtime("GET", "/limits", key)
    if status != 200:
        raise SystemExit(f"GET /v1/limits: HTTP {status}: {limits}")
    print(f"key access {limits.get('access')}, credit {limits.get('credit', {}).get('state')}, "
          f"daily limit {limits.get('daily', {}).get('limitMicros')} micros", flush=True)
    # Short, so the daemon's socket path fits a Unix socket address on macOS.
    root = tempfile.mkdtemp(prefix="dd-rt-", dir="/tmp")
    os.chmod(root, 0o700)
    drydock = Drydock(bin_dir, root, key_file, options.image, agent)
    environments, prepared = [], None
    try:
        code, providers, error = drydock.cli("providers")
        declaration = next((p for p in providers or [] if p.get("provider") == INSTANCE), {})
        check(code == 0 and declaration.get("readiness", {}).get("status") == "ready",
              f"providers: drydockd loads the runtime module: {error or declaration.get('readiness')}")

        started = time.time()
        code, prepared, error = drydock.cli("prepare", INSTANCE, "--image", options.image)
        prepared = prepared if code == 0 and isinstance(prepared, dict) else None
        check(bool(prepared) and str(prepared.get("id", "")).startswith("dd-"),
              f"prepare in {time.time() - started:.1f}s: {(prepared or {}).get('id') or error}")

        started = time.time()
        code, environment, error = drydock.cli("launch", INSTANCE, "--image", options.image)
        launched = (environment or {}).get("id") if code == 0 and isinstance(environment, dict) else None
        if launched:
            environments.append(launched)
        check(bool(launched) and environment.get("state", {}).get("state") == "running",
              f"launch returned after the agent's hello in {time.time() - started:.1f}s: {launched or error}")
        if not launched:
            raise Stop

        code, lines = run_in_guest(launched, key, f"GUESS={secrets.token_urlsafe(32)}; {GUEST_PROBE}", user="sandbox")
        print(f"guest probe as the sandbox user (exit {code}): {lines}", flush=True)
        check(len(lines) >= 1 and lines[0] != "0", f"tcp listener: the probe ran as a non-root user: {lines[:1]}")
        check("token file unreadable" in lines, "tcp listener: the non-root user cannot read the token file")
        refusals = [line for line in lines if line.startswith("HTTP/1.1 ")]
        check(refusals == ["HTTP/1.1 401 Unauthorized"] * 2, f"tcp listener: no token and a guessed token both get 401: {refusals}")
        code, lines = run_in_guest(launched, key, IDENTITY_PROBE)
        check(code == 0 and lines and lines[-1].endswith("identity 0") and not lines[-1].startswith("agents 0"),
              f"identity: no drydock-agent holds RUNTIME_ID_TOKEN_REQUEST_TOKEN: exit {code} {lines[-1:]}")

        if prepared:
            request = {
                "label": f"live-egress-{secrets.token_hex(4)}",
                "prepared": prepared,
                "size": {"cpus": 1.0, "memory_bytes": 1 << 30, "disk_bytes": 4 << 30},
                "egress": {"mode": "deny_all", "direct": [{"kind": "host", "host": options.allowed_host}]},
            }
            status, egress = drydock.api("POST", f"/v1/providers/{INSTANCE}/environments", request)
            egress_id = (egress or {}).get("id") if status in (200, 201) and isinstance(egress, dict) else None
            if egress_id:
                environments.append(egress_id)
            check(bool(egress_id), f"egress: provisioned under deny-all allowing {options.allowed_host}: {egress_id or egress}")
            if egress_id:
                status, rules = runtime("GET", f"/sandboxes/{egress_id}/network", key)
                print(f"network rules: {rules}", flush=True)
                check(status == 200 and rules.get("enforcedVersion") == rules.get("version"),
                      f"egress: Runtime enforces the rules' version: HTTP {status}")
                probe = lambda target: run_in_guest(egress_id, key, f"curl -sS -m 15 -o /dev/null -w '%{{http_code}}' {target}")
                code, lines = probe(f"https://{options.allowed_host}/")
                check(code == 0, f"egress: root reaches the allowed {options.allowed_host}: exit {code} {lines[-1:]}")
                code, lines = probe(f"https://{options.denied_host}/")
                check(code not in (0, None), f"egress: root cannot reach {options.denied_host}: exit {code} {lines[-1:]}")
                code, lines = probe("https://1.1.1.1/")
                check(code not in (0, None), f"egress: root cannot reach an unlisted address: exit {code} {lines[-1:]}")
                code, lines = run_in_guest(egress_id, key, "nft flush ruleset 2>/dev/null; iptables -F 2>/dev/null; "
                                           "echo 'nameserver 1.1.1.1' > /etc/resolv.conf; "
                                           f"curl -sS -m 15 -o /dev/null -w '%{{http_code}}' https://{options.denied_host}/")
                check(code not in (0, None), f"egress: root stays confined after rewriting the guest's firewall and DNS: exit {code} {lines[-1:]}")
                code, _, error = drydock.cli("destroy", INSTANCE, egress_id)
                check(code == 0, f"egress: destroyed the egress vessel: {error}")

        status, token = drydock.api("POST", f"/v1/providers/{INSTANCE}/environments/{launched}/suspend")
        check(status == 200 and isinstance(token, dict) and "token" in token, f"suspend: HTTP {status} {token if status != 200 else ''}")
        code, inspected, error = drydock.cli("inspect", INSTANCE, launched)
        check((inspected or {}).get("state", {}).get("state") == "stopped" if isinstance(inspected, dict) else False,
              f"suspend: the suspended vessel reads stopped: {(inspected or {}).get('state') if isinstance(inspected, dict) else error}")
        status, body = drydock.api("POST", f"/v1/providers/{INSTANCE}/environments/{launched}/resume", token)
        check(200 <= status < 300, f"resume: HTTP {status} {body if status >= 300 else ''}")
        hello, error = drydock.hello(launched)
        check(bool(hello and hello.get("fingerprint")), f"resume: /hello through drydockd's relay after resume: {error or hello.get('fingerprint', '')[:16]}")

        code, _, error = drydock.cli("destroy", INSTANCE, launched)
        check(code == 0, f"destroy: destroyed the vessel: {error}")
        status, body = runtime("GET", f"/sandboxes/{launched}", key)
        check(status == 404, f"destroy: Runtime no longer knows the sandbox: HTTP {status}")
    except Stop:
        pass
    except Exception as error:  # A crash is a failure too; cleanup still runs.
        check(False, f"the script itself: {type(error).__name__}: {error}")
    finally:
        for environment in environments:
            drydock.cli("destroy", INSTANCE, environment, timeout=300)
        try:
            # Anything of ours drydock could not remove goes here.
            label = urllib.parse.quote(f"drydock.provider:{INSTANCE}")
            ours = paged(f"/sandboxes?label={label}&includeStopped=true&limit=100", key)
            for row in ours:
                runtime("DELETE", f"/sandboxes/{row['id']}", key)
            remaining = paged(f"/sandboxes?label={label}&includeStopped=true&limit=100", key)
            check(not remaining, f"cleanup: no drydock sandboxes are left: {[r['id'] for r in remaining]} (deleted {len(ours)} leftovers)")
            ids = set(environments) | {row["id"] for row in ours}
            snapshots = [s for s in paged("/snapshots?limit=100", key) if s.get("sourceSandboxId") in ids]
            for snapshot in snapshots:
                runtime("POST", f"/snapshots/{snapshot['id']}:delete", key)
            check(not snapshots, f"cleanup: drydock left no snapshots: {[s['id'] for s in snapshots]}")
            if prepared:
                for image in paged(f"/images?name={urllib.parse.quote(prepared['id'])}", key):
                    status, body = runtime("POST", f"/images/{image['id']}:delete", key)
                    check(status in (200, 202, 204), f"cleanup: deleted the prepared image {prepared['id']} ({image['id']}): HTTP {status} {body if status >= 300 else ''}")
        except Exception as error:  # Cleanup reports, never hides, what it could not do.
            check(False, f"cleanup through Runtime's API: {error}")
        drydock.stop()
        status, limits = runtime("GET", "/limits", key)
        if status == 200:
            daily = limits.get("daily", {})
            print(f"SPEND this key's agent committed {int(daily.get('usedMicros') or 0) / 1e6:.6f} USD in the last 24 h "
                  f"(limit {daily.get('limitMicros')} micros)", flush=True)
        status, usage = runtime("GET", "/usage", key)
        if status == 200:
            print(f"SPEND account: spent {int(usage.get('spent') or 0) / 1e6:.6f} USD, held {int(usage.get('held') or 0) / 1e6:.6f} USD, "
                  f"available {int(usage.get('available') or 0) / 1e6:.6f} USD", flush=True)
        print(f"drydockd's log: {os.path.join(root, 'drydockd.log')}", flush=True)
    print("ALL CHECKS PASSED" if not FAILED else f"{len(FAILED)} CHECKS FAILED:\n  " + "\n  ".join(FAILED), flush=True)
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()

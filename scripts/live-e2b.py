#!/usr/bin/env python3
"""Live check of the E2B module through drydockd and drydock.

    scripts/live-e2b.py KEY_FILE --team-id ID [--bin-dir DIR] [--agent PATH] [--image IMAGE]

KEY_FILE holds an E2B team API key (`e2b_…`); ID is that team's id (the
dashboard's Team → General, or the `teamID` of any sandbox event). DIR holds
drydock, drydockd and drydock-host built from this branch (default
target/release, from `cargo build --release -p drydock -p drydock-host`).

PATH is a linux/amd64 drydock-agent, which launch pushes into the vessel if
the template's agent is older; by default $DRYDOCK_AGENT_BIN_LINUX_AMD64,
else DIR/drydock-agent-linux-amd64, else DIR/drydock-agent on a Linux x86_64
host. On a Mac, take the one in the pinned tools image:

    id=$(docker create --platform linux/amd64 "$(cat crates/drydock/tools-image.txt)" /x)
    docker cp "$id":/opt/drydock/drydock-agent target/release/drydock-agent-linux-amd64
    docker rm "$id"

or cross-build it with cargo-zigbuild (`brew install zig`, `cargo install cargo-zigbuild`):

    cargo zigbuild --release -p drydock-agent --target x86_64-unknown-linux-gnu
    # then --agent target/x86_64-unknown-linux-gnu/release/drydock-agent

IMAGE is a public linux/amd64 image with curl, pinned by digest (default
buildpack-deps:bookworm-curl as of 2026-11-02). Only the Python standard
library is needed.

It starts drydockd with a throwaway DRYDOCK_ROOT (a short directory under
/tmp, so socket paths fit macOS's 104 bytes) and a generated drydock.toml
whose credential is `{ file = KEY_FILE }`, then, printing PASS or FAIL for
each check:

- prepares the image (a template build at E2B, or the template already there);
- launches a vessel, which returns only after the agent's hello through
  E2B's proxy (this proves Google's front end passes the agent's 101 and
  E2B's proxy passes `Authorization`);
- notes whether `GET /sandboxes/{id}` and connect return the traffic token;
- checks from this machine that the proxy refuses the agent's port without
  the traffic token (403), and that with it a wrong agent token gets the
  agent's own 401;
- provisions a vessel under deny-all allowing one address and one host name,
  and checks as root in it that both answer and an unlisted name and address
  do not, also after root flushes nftables and iptables;
- suspends and resumes the first vessel, then reads the agent's /hello again
  through drydockd's relay;
- destroys both, reads a destroyed vessel as gone, and lists sandboxes
  through E2B's API to show none of drydock's are left.

Every sandbox it made is killed at the end, whatever happened. The prepared
`drydock-` template stays (templates are retired by a retention decision,
drydock#61); the script prints its name. Exit status 0 means every check
passed; each FAIL line names its step and what E2B or drydock said.
"""
import argparse
import base64
import http.client
import json
import os
import platform
import secrets
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.e2b.app"
DOMAIN = "e2b.app"
INSTANCE = "e2b"
AGENT_PORT = 7811
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


def e2b(method, path, key, body=None, timeout=120):
    """One E2B control-plane request: (status, parsed body or text, headers)."""
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(API + path, data=data, method=method)
    request.add_header("X-API-Key", key)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status, raw, headers = response.status, response.read(), response.headers
    except urllib.error.HTTPError as error:
        status, raw, headers = error.code, error.read(), error.headers
    try:
        return status, json.loads(raw) if raw else None, headers
    except json.JSONDecodeError:
        return status, raw.decode(errors="replace")[:300], headers


def ours(key):
    """Every sandbox E2B lists with this instance's provider tag, running or paused."""
    found, token = [], None
    query = urllib.parse.urlencode({"drydock.provider": INSTANCE})
    for _ in range(100):
        path = "/v2/sandboxes?" + urllib.parse.urlencode({"metadata": query, "state": "running,paused", "limit": 100})
        if token:
            path += "&" + urllib.parse.urlencode({"nextToken": token})
        status, rows, headers = e2b("GET", path, key)
        if status != 200:
            raise RuntimeError(f"GET /v2/sandboxes: HTTP {status}: {rows}")
        found += rows
        token = headers.get("X-Next-Token")
        if not token:
            return found
    raise RuntimeError("GET /v2/sandboxes: too many pages")


def run_as_root(sandbox, key, script):
    """`sh -c script` as root through envd's process service: (exit code, output)."""
    status, detail, _ = e2b("GET", f"/sandboxes/{sandbox}", key)
    if status != 200:
        return None, f"GET /sandboxes/{sandbox}: HTTP {status}: {detail}"
    message = json.dumps({"process": {"cmd": "/bin/sh", "args": ["-c", script], "envs": {}}, "stdin": False}).encode()
    request = urllib.request.Request(f"https://49983-{sandbox}.{DOMAIN}/process.Process/Start",
                                     data=b"\0" + struct.pack(">I", len(message)) + message, method="POST")
    request.add_header("Content-Type", "application/connect+json")
    request.add_header("Connect-Timeout-Ms", "60000")
    request.add_header("Authorization", "Basic " + base64.b64encode(b"root:").decode())
    if detail.get("envdAccessToken"):
        request.add_header("X-Access-Token", detail["envdAccessToken"])
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            body = response.read()
    except urllib.error.HTTPError as error:
        return None, f"envd HTTP {error.code}: {error.read()[:300]!r}"
    output, code = b"", None
    while len(body) >= 5:
        flags, length = body[0], struct.unpack(">I", body[1:5])[0]
        event, body = json.loads(body[5:5 + length]), body[5 + length:]
        if flags & 2:
            if event.get("error"):
                output += f"[envd: {event['error']}]".encode()
            continue
        event = event.get("event", {})
        for stream in ("stdout", "stderr"):
            output += base64.b64decode(event.get("data", {}).get(stream, ""))
        if "end" in event:
            code = event["end"].get("exitCode", 0)
    return code, output.decode(errors="replace").strip()


def proxy_status(sandbox, headers):
    """The status line E2B's proxy answers a WebSocket upgrade to the agent's port with."""
    host = f"{AGENT_PORT}-{sandbox}.{DOMAIN}"
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    with socket.create_connection((host, 443), timeout=30) as raw, context.wrap_socket(raw, server_hostname=host) as tls:
        lines = ["GET /v1/connect HTTP/1.1", f"Host: {host}", "Connection: Upgrade", "Upgrade: websocket",
                 "Sec-WebSocket-Version: 13", "Sec-WebSocket-Key: " + base64.b64encode(secrets.token_bytes(16)).decode()]
        lines += [f"{name}: {value}" for name, value in headers.items()]
        tls.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        return read_head(tls).decode(errors="replace").split("\r\n")[0]


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=900):
        super().__init__("drydock", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Drydock:
    def __init__(self, bin_dir, root, key_file, team, image, agent):
        self.bin_dir, self.root, self.image = bin_dir, root, image
        self.config = os.path.join(root, "drydock.toml")
        self.socket = os.path.join(root, "run", "drydock.sock")
        os.makedirs(os.path.dirname(self.socket), mode=0o700)
        os.chmod(os.path.dirname(self.socket), 0o700)
        with open(self.config, "w") as file:
            file.write(
                f'[providers.{INSTANCE}]\nmodule = "e2b"\ncredential = {{ file = {json.dumps(key_file)} }}\n'
                f"image = {json.dumps(image)}\n\n[providers.{INSTANCE}.settings]\nteam_id = {json.dumps(team)}\n"
            )
        self.env = dict(
            os.environ,
            DRYDOCK_ROOT=root,
            DRYDOCK_DAEMON_BIN=os.path.join(bin_dir, "drydockd"),
            DRYDOCK_HOST_BIN=os.path.join(bin_dir, "drydock-host"),
            DRYDOCK_AGENT_BIN_LINUX_AMD64=agent,
        )
        self.log = os.path.join(root, "drydockd.log")
        self.daemon = subprocess.Popen(
            [self.env["DRYDOCK_DAEMON_BIN"], "--config", self.config, "--socket", self.socket],
            env=self.env, stdout=open(self.log, "w"), stderr=subprocess.STDOUT,
        )
        for _ in range(300):
            if os.path.exists(self.socket):
                return
            if self.daemon.poll() is not None:
                break
            time.sleep(0.1)
        raise SystemExit(f"drydockd did not start; see {self.log}")

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
            return None, head.decode(errors="replace")[:300]
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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("key_file")
    parser.add_argument("--team-id", required=True)
    parser.add_argument("--bin-dir", default="target/release")
    parser.add_argument("--agent", help="a linux/amd64 drydock-agent (E2B's platform)")
    # Pinned: drydock's resolver cannot yet resolve Docker Hub tags (drydock#200).
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("--allowed-address", default="1.1.1.1")
    parser.add_argument("--allowed-host", default="github.com")
    parser.add_argument("--denied-address", default="9.9.9.9")
    parser.add_argument("--denied-host", default="example.com")
    options = parser.parse_args()
    key_file = os.path.abspath(options.key_file)
    key = open(key_file).read().strip()
    bin_dir = os.path.abspath(options.bin_dir)
    for binary in ("drydock", "drydockd", "drydock-host"):
        if not os.access(os.path.join(bin_dir, binary), os.X_OK):
            raise SystemExit(f"{bin_dir}/{binary} is missing; cargo build --release -p drydock -p drydock-host")
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
    root = tempfile.mkdtemp(prefix="dd-e2b-", dir="/tmp")
    os.chmod(root, 0o700)
    drydock = Drydock(bin_dir, root, key_file, options.team_id, options.image, agent)
    environments, prepared = [], None
    try:
        code, providers, error = drydock.cli("providers")
        declaration = next((p for p in providers or [] if p.get("provider") == INSTANCE), {})
        check(code == 0 and declaration.get("readiness", {}).get("status") == "ready",
              f"[providers] drydockd loads the e2b module: {error or declaration.get('readiness')}")

        started = time.time()
        code, prepared, error = drydock.cli("prepare", INSTANCE, "--image", options.image)
        if not check(code == 0 and str((prepared or {}).get("id", "")).startswith("drydock-"),
                     f"[prepare] in {time.time() - started:.1f}s: {(prepared or {}).get('id') or error}"):
            prepared = None
            raise Stop

        started = time.time()
        code, environment, error = drydock.cli("launch", INSTANCE, "--image", options.image)
        launched = (environment or {}).get("id") if code == 0 else None
        if launched:
            environments.append(launched)
        check(bool(launched) and environment.get("state", {}).get("state") == "running",
              f"[launch] returned after the agent's hello through E2B's proxy in {time.time() - started:.1f}s: {launched or error}")
        if not launched:
            raise Stop

        status, detail, _ = e2b("GET", f"/sandboxes/{launched}", key)
        print(f"NOTE GET /sandboxes/{{id}} (HTTP {status}) returns a traffic token: {bool((detail or {}).get('trafficAccessToken'))}; "
              f"allowPublicTraffic: {((detail or {}).get('network') or {}).get('allowPublicTraffic')}", flush=True)
        status, connected, _ = e2b("POST", f"/v2/sandboxes/{launched}/connect", key, {"timeout": 3600})
        traffic = (connected or {}).get("trafficAccessToken")
        check(status in (200, 201) and bool(traffic), f"[connect] a running sandbox's connect returns its traffic token: HTTP {status}")
        line = proxy_status(launched, {"Authorization": "Bearer " + secrets.token_urlsafe(32)})
        check(" 403 " in line + " ", f"[proxy] the agent's port without the traffic token: {line}")
        if traffic:
            line = proxy_status(launched, {"e2b-traffic-access-token": traffic, "Authorization": "Bearer " + secrets.token_urlsafe(32)})
            check(" 401 " in line + " ", f"[proxy] with the traffic token, a wrong agent token gets the agent's 401: {line}")

        request = {
            "label": f"live-egress-{secrets.token_hex(4)}",
            "prepared": prepared,
            "size": {"cpus": 1.0, "memory_bytes": 1 << 30, "disk_bytes": 1 << 30},
            "egress": {"mode": "deny_all", "direct": [{"kind": "host", "host": options.allowed_address},
                                                      {"kind": "host", "host": options.allowed_host}]},
        }
        # The prepared template's size is the launch's; use it.
        status, inspected = drydock.api("GET", f"/v1/providers/{INSTANCE}/environments/{launched}")
        if status == 200 and inspected.get("granted_size"):
            request["size"] = dict(inspected["granted_size"])
        status, egress = drydock.api("POST", f"/v1/providers/{INSTANCE}/environments", request)
        egress_id = (egress or {}).get("id") if status in (200, 201) else None
        if egress_id:
            environments.append(egress_id)
        check(bool(egress_id), f"[egress] provisioned under deny-all allowing {options.allowed_address} and {options.allowed_host}: {egress_id or egress}")
        if egress_id:
            curl = lambda target: run_as_root(egress_id, key, f"curl -sS -m 15 -o /dev/null -w '%{{http_code}}' {target}")
            for target, allowed in [(f"https://{options.allowed_address}/", True), (f"https://{options.allowed_host}/", True),
                                    (f"https://{options.denied_host}/", False), (f"https://{options.denied_address}/", False)]:
                code, output = curl(target)
                if allowed:
                    check(code == 0, f"[egress] root reaches the allowed {target}: exit {code} {output[-200:]}")
                else:
                    check(code not in (0, None), f"[egress] root cannot reach {target}: exit {code} {output[-200:]}")
            code, output = run_as_root(egress_id, key, "id -u; (nft flush ruleset; iptables -F) 2>&1; "
                                       f"curl -sS -m 15 -o /dev/null -w '%{{http_code}}' https://{options.denied_address}/")
            check(code not in (0, None) and output.startswith("0"),
                  f"[egress] root stays confined after flushing nftables and iptables: exit {code} {output[-200:]}")
            code, _, error = drydock.cli("destroy", INSTANCE, egress_id)
            check(code == 0, f"[egress] destroyed the egress vessel: {error}")

        status, token = drydock.api("POST", f"/v1/providers/{INSTANCE}/environments/{launched}/suspend")
        check(status == 200 and isinstance(token, dict) and "token" in token, f"[suspend] HTTP {status} {token if status != 200 else ''}")
        code, inspected, error = drydock.cli("inspect", INSTANCE, launched)
        check((inspected or {}).get("state", {}).get("state") == "stopped",
              f"[suspend] the vessel reads stopped: {(inspected or {}).get('state') or error}")
        status, body = drydock.api("POST", f"/v1/providers/{INSTANCE}/environments/{launched}/resume", token)
        check(200 <= status < 300, f"[resume] HTTP {status} {body if status >= 300 else ''}")
        hello, error = drydock.hello(launched)
        check(bool(hello and hello.get("fingerprint")),
              f"[resume] /hello through drydockd's relay after resume: {error or hello.get('fingerprint', '')[:16]}")

        code, _, error = drydock.cli("destroy", INSTANCE, launched)
        check(code == 0, f"[destroy] destroyed the vessel: {error}")
        code, inspected, error = drydock.cli("inspect", INSTANCE, launched)
        check((inspected or {}).get("state", {}).get("state") == "gone",
              f"[destroy] a destroyed vessel reads gone: {(inspected or {}).get('state') or error}")
    except Stop:
        pass
    except Exception as error:  # A crash is a failure too, and cleanup still runs.
        check(False, f"[script] {type(error).__name__}: {error}")
    finally:
        for environment in environments:
            try:
                drydock.cli("destroy", INSTANCE, environment, timeout=300)
            except Exception as error:
                print(f"NOTE drydock destroy {environment}: {error}", flush=True)
        try:
            # Anything of ours drydock could not remove goes here.
            for row in ours(key):
                status, body, _ = e2b("DELETE", f"/sandboxes/{row['sandboxID']}", key)
                print(f"NOTE killed leftover sandbox {row['sandboxID']}: HTTP {status}", flush=True)
            remaining = [row["sandboxID"] for row in ours(key)]
            check(not remaining, f"[cleanup] no drydock sandboxes are left at E2B: {remaining}")
        except Exception as error:  # Cleanup reports, never hides, what it could not do.
            check(False, f"[cleanup] listing or killing sandboxes through E2B's API: {error}")
        if prepared:
            print(f"NOTE the prepared template {prepared['id']} stays at E2B (drydock#61)", flush=True)
        drydock.stop()
        print(f"drydockd's log: {drydock.log}", flush=True)
    print("ALL CHECKS PASSED" if not FAILED else f"{len(FAILED)} CHECKS FAILED", flush=True)
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()

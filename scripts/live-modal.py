#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["modal>=1.2"]
# ///
"""Live check of the TypeScript host's Modal module, through drydockd and drydock.

    scripts/live-modal.py TOKEN_FILE [--bin-dir DIR] [--host PATH] [--agent PATH]
                          [--image IMAGE] [--app APP] [--environment ENV]
                          [--runtime vm|gvisor]

TOKEN_FILE holds a Modal token pair as JSON, {"token_id": …, "token_secret": …}.
DIR holds `drydock`, `drydockd` and `drydock-host` from this branch (default
target/release, from `cargo build --release -p drydock -p drydock-host -p
drydock-agent`). PATH is the TypeScript host's `dist/main.js` (default
hosts/typescript/dist/main.js, from `corepack pnpm build` there). `--agent`
names the linux/amd64 agent drydockd pushes to the vessel at hello (default
DIR/drydock-agent); it must run on IMAGE's glibc, so a laptop with a newer
glibc than the image passes the tools-image release's `drydock-agent-linux-amd64`.

It writes a drydock.toml for one provider `modal` into a throwaway
DRYDOCK_ROOT, runs its own drydockd, and then:

- prepares IMAGE twice (Modal's definition cache gives the same image);
- launches a deny-all vessel, which returns after the agent's hello over the
  exec bridge;
- runs an egress probe as root in it (a denied address and name, and a DNS
  lookup, recorded either way), then in a second vessel provisioned with an
  allowlist (an allowed name and CIDR, a denied address);
- opens a relay through drydockd, reads the agent's hello over it, sees its
  bridge process in the sandbox, closes it and sees the bridge gone;
- destroys both vessels, and lists the app's sandboxes through Modal to show
  none are left.

Every check prints PASS or FAIL. Every sandbox in APP is terminated at the
end, whatever happened, so use an app of its own (default drydock-live-check).
Exit status 0 means every check passed.
"""
import argparse
import http.client
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

import modal
import modal.exception

PROVIDER = "modal"
GiB = 1 << 30
failures = []


def check(condition, message):
    print(("PASS " if condition else "FAIL ") + message, flush=True)
    if not condition:
        failures.append(message)
    return condition


def must(condition, message):
    if not check(condition, message):
        raise SystemExit(1)


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("drydock", timeout=600)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.path)


class Drydock:
    """A throwaway DRYDOCK_ROOT with its own drydockd and the drydock CLI."""

    def __init__(self, options, token_file):
        self.root = tempfile.mkdtemp(prefix="drydock-live-modal-")
        self.config = os.path.join(self.root, "config", "drydock.toml")
        self.socket = os.path.join(self.root, "config", "run", "drydock.sock")
        os.makedirs(os.path.dirname(self.socket), mode=0o700)
        settings = {"app": options.app, "runtime": options.runtime}
        if options.environment:
            settings["environment"] = options.environment
        with open(self.config, "w") as f:
            f.write(
                f"[providers.{PROVIDER}]\n"
                'module = "modal"\n'
                f"credential = {{ file = {json.dumps(os.path.abspath(token_file))} }}\n"
                f"image = {json.dumps(options.image)}\n"
                'size = { cpus = 1, memory = "2GiB", disk = "0" }\n'
                f"settings = {json.dumps(settings)}\n".replace('": ', '" = ')
            )
        self.env = dict(os.environ)
        for name in list(self.env):
            # The module takes the token from drydock only; the SDK must not see another.
            if name.startswith("MODAL_"):
                del self.env[name]
        self.env.update(
            DRYDOCK_ROOT=self.root,
            DRYDOCK_TYPESCRIPT_HOST_BIN=os.path.abspath(options.host),
            DRYDOCK_HOST_BIN=os.path.join(options.bin_dir, "drydock-host"),
            DRYDOCK_AGENT_BIN_LINUX_AMD64=os.path.abspath(options.agent),
        )
        self.bin = options.bin_dir
        self.log = open(os.path.join(self.root, "drydockd.out"), "w")
        self.daemon = subprocess.Popen(
            [os.path.join(self.bin, "drydockd"), "--config", self.config, "--socket", self.socket],
            env=self.env,
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        deadline = time.time() + 60
        while not os.path.exists(self.socket):
            if self.daemon.poll() is not None or time.time() > deadline:
                raise SystemExit(f"drydockd did not start; see {self.log.name}")
            time.sleep(0.2)

    def cli(self, *args, check_exit=True):
        result = subprocess.run(
            [os.path.join(self.bin, "drydock"), "--config", self.config, "--socket", self.socket, *args],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=900,
        )
        if check_exit and result.returncode != 0:
            raise SystemExit(f"drydock {' '.join(args)} failed: {result.stderr.strip()[-2000:]}")
        return json.loads(result.stdout) if result.stdout.strip() else None

    def api(self, method, path, body=None):
        connection = UnixHTTP(self.socket)
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if data else {}
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        return response.status, json.loads(raw) if raw else None

    def relay(self, id):
        """A raw relay to the vessel's agent socket, through drydockd."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(60)
        sock.connect(self.socket)
        sock.sendall(
            f"GET /v1/providers/{PROVIDER}/environments/{id}/relay HTTP/1.1\r\n"
            "Host: drydock\r\nConnection: Upgrade\r\nUpgrade: drydock-relay\r\n\r\n".encode()
        )
        head, rest = read_head(sock, b"")
        return sock, head, rest

    def stop(self):
        self.daemon.send_signal(signal.SIGTERM)
        try:
            self.daemon.wait(30)
        except subprocess.TimeoutExpired:
            self.daemon.kill()
        self.log.close()


def read_head(sock, buffer):
    while b"\r\n\r\n" not in buffer:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buffer += chunk
    head, _, rest = buffer.partition(b"\r\n\r\n")
    return head.decode(errors="replace"), rest


def hello_over(sock, rest):
    """GET /hello as HTTP/1.1 over a switched connection; its JSON body."""
    sock.sendall(b"GET /hello HTTP/1.1\r\nHost: agent\r\nConnection: keep-alive\r\n\r\n")
    head, body = read_head(sock, rest)
    lines = head.split("\r\n")
    headers = {k.lower(): v.strip() for k, _, v in (line.partition(":") for line in lines[1:])}
    if "content-length" in headers:
        while len(body) < int(headers["content-length"]):
            body += sock.recv(65536)
    else:
        while not body.endswith(b"0\r\n\r\n"):
            body += sock.recv(65536)
        body = b"".join(body.split(b"\r\n")[1::2])
    return lines[0], json.loads(body)


# Run as root in the vessel: python is in the default image, so no client tools.
EGRESS = r"""
import json, os, socket, sys
def tcp(host, port):
    try:
        socket.create_connection((host, port), timeout=6).close()
        return "connected"
    except Exception as e:
        return f"blocked ({type(e).__name__})"
def dns(name):
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)})
    except Exception as e:
        return f"failed ({type(e).__name__})"
print(json.dumps({"uid": os.getuid(), "dns": dns(sys.argv[1]),
                  "tcp": {f"{h}:{p}": tcp(h, int(p)) for h, p in (t.rsplit(":", 1) for t in sys.argv[2:])}}))
"""

BRIDGES = r"""for p in /proc/[0-9]*; do tr '\0' ' ' < $p/cmdline 2>/dev/null; echo; done | grep -c -- '--bridg[e]'"""


def run(client, sandbox_id, *argv):
    sandbox = modal.Sandbox.from_id(sandbox_id, client=client)
    process = sandbox.exec(*argv, timeout=120)
    process.wait()
    return process.returncode, process.stdout.read().strip()


def bridges(client, sandbox_id):
    code, out = run(client, sandbox_id, "sh", "-c", BRIDGES)
    return int(out or 0)


def egress(client, sandbox_id, name, *targets):
    code, out = run(client, sandbox_id, "python3", "-c", EGRESS, name, *targets)
    if code != 0:
        return None
    return json.loads(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("token_file")
    parser.add_argument("--bin-dir", default="target/release")
    parser.add_argument("--host", default="hosts/typescript/dist/main.js")
    parser.add_argument("--agent")
    parser.add_argument("--image", default="python:3.13-slim")
    parser.add_argument("--app", default="drydock-live-check")
    parser.add_argument("--environment")
    parser.add_argument("--runtime", choices=["vm", "gvisor"], default="vm")
    options = parser.parse_args()
    options.agent = options.agent or os.path.join(options.bin_dir, "drydock-agent")
    for path in [options.host, options.agent] + [
        os.path.join(options.bin_dir, b) for b in ("drydock", "drydockd", "drydock-host")
    ]:
        if not os.path.exists(path):
            raise SystemExit(f"missing {path}")
    if shutil.which("node") is None:
        raise SystemExit("the TypeScript host needs node on PATH")
    token = json.load(open(options.token_file))
    client = modal.Client.from_credentials(token["token_id"], token["token_secret"])

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    drydock = Drydock(options, options.token_file)
    print(f"DRYDOCK_ROOT={drydock.root}", flush=True)
    vessels = []
    try:
        providers = drydock.cli("providers")
        modal_provider = next((p for p in providers if p["provider"] == PROVIDER), None)
        must(
            modal_provider is not None and modal_provider["readiness"] == {"status": "ready"},
            f"the modal provider is ready: {modal_provider and modal_provider['readiness']}",
        )

        started = time.time()
        prepared = drydock.cli("prepare", PROVIDER, "--egress", "deny-all")
        must(prepared["id"].startswith("im-"), f"prepare built {prepared['id']} in {time.time() - started:.1f}s")
        started = time.time()
        again = drydock.cli("prepare", PROVIDER, "--egress", "deny-all")
        check(again["id"] == prepared["id"], f"prepare again gave the same image in {time.time() - started:.1f}s: {again['id']}")

        started = time.time()
        launched = drydock.cli("launch", PROVIDER, "--egress", "deny-all")
        vessels.append(launched["id"])
        must(
            launched["state"] == {"state": "running"},
            f"launch returned {launched['id']} after the agent's hello, in {time.time() - started:.1f}s",
        )
        inspected = drydock.cli("inspect", PROVIDER, launched["id"])
        check(inspected["egress_policy"] == "deny", f"inspect: {inspected['state']}, egress {inspected['egress']} ({inspected['egress_policy']})")

        # Deny all: blockNetwork. A denied address and name; DNS recorded either way.
        result = egress(client, launched["id"], "example.com", "1.1.1.1:443", "example.com:443")
        print(f"deny-all probe: {result}", flush=True)
        must(result is not None and result["uid"] == 0, "the egress probe ran as root")
        check(all(v.startswith("blocked") for v in result["tcp"].values()), f"deny-all blocks TCP: {result['tcp']}")
        print(f"RECORD deny-all DNS for example.com: {result['dns']}", flush=True)

        # An allowlist: one name and one CIDR allowed, another address denied.
        status, allowlisted = drydock.api(
            "POST",
            f"/v1/providers/{PROVIDER}/environments",
            {
                "label": f"live-allowlist-{uuid.uuid4()}",
                "prepared": prepared,
                "size": {"cpus": 1, "memory_bytes": 2 * GiB, "disk_bytes": 0},
                "egress": {
                    "mode": "deny_all",
                    "direct": [{"kind": "host", "host": "example.com"}, {"kind": "cidr", "cidr": "1.1.1.1/32"}],
                },
            },
        )
        must(status == 201, f"provisioned an allowlisted vessel: HTTP {status} {allowlisted}")
        vessels.append(allowlisted["id"])
        result = egress(client, allowlisted["id"], "example.org", "example.com:443", "1.1.1.1:443", "9.9.9.9:443")
        print(f"allowlist probe: {result}", flush=True)
        tcp = (result or {}).get("tcp", {})
        check(tcp.get("example.com:443") == "connected", f"an allowed name connects: {tcp.get('example.com:443')}")
        check(tcp.get("1.1.1.1:443") == "connected", f"an allowed CIDR connects: {tcp.get('1.1.1.1:443')}")
        check(str(tcp.get("9.9.9.9:443")).startswith("blocked"), f"an unlisted address is blocked: {tcp.get('9.9.9.9:443')}")
        print(f"RECORD allowlist DNS for unlisted example.org: {(result or {}).get('dns')}", flush=True)

        # The relay: hello over a bridge, which is gone once the relay closes.
        id = launched["id"]
        deadline = time.time() + 30
        while (baseline := bridges(client, id)) and time.time() < deadline:
            time.sleep(1)
        check(baseline == 0, f"no bridge is left from launch's hello: {baseline}")
        sock, head, rest = drydock.relay(id)
        must(head.startswith("HTTP/1.1 101 "), f"drydockd switched to the relay: {head.splitlines()[:1]}")
        status, hello = hello_over(sock, rest)
        check(status.startswith("HTTP/1.1 200 ") and bool(hello.get("fingerprint")), f"GET /hello over the relay: {status}, platform {hello.get('platform')}")
        check(bridges(client, id) == 1, "its bridge runs in the sandbox while the relay is open")
        sock.close()
        deadline = time.time() + 30
        while (left := bridges(client, id)) and time.time() < deadline:
            time.sleep(1)
        check(left == 0, f"the bridge is gone after the relay closed: {left} left")

        for id in list(vessels):
            drydock.cli("destroy", PROVIDER, id)
            vessels.remove(id)
            row = drydock.cli("inspect", PROVIDER, id, check_exit=False)
            check(row is None or row["state"]["state"] == "gone", f"destroyed {id}: {row and row['state']}")
        listed = drydock.cli("list", PROVIDER)
        check(listed == [], f"drydock lists no vessels: {listed}")
    finally:
        for id in vessels:
            drydock.cli("destroy", PROVIDER, id, check_exit=False)
        drydock.stop()
        # Whatever happened: nothing of ours keeps running in the app.
        try:
            try:
                app = modal.App.lookup(options.app, environment_name=options.environment, client=client)
            except modal.exception.NotFoundError:
                app = None  # never created: nothing ran
            left = []
            if app is not None:
                for sandbox in modal.Sandbox.list(app_id=app.app_id, client=client):
                    print(f"terminating leftover sandbox {sandbox.object_id}", flush=True)
                    sandbox.terminate()
                left = [s.object_id for s in modal.Sandbox.list(app_id=app.app_id, client=client)]
            check(left == [], f"Modal lists no sandboxes in app {options.app}: {left}")
        except Exception as error:
            check(False, f"listing app {options.app} through Modal: {error!r}")
    if failures:
        print(f"{len(failures)} CHECKS FAILED", flush=True)
        raise SystemExit(1)
    print("ALL CHECKS PASSED", flush=True)


if __name__ == "__main__":
    main()

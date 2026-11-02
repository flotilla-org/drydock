#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["modal>=1.2"]
# ///
"""Live check of the TypeScript host's Modal module, through drydockd and drydock.

    scripts/live-modal.py TOKEN_FILE [--bin-dir DIR] [--host PATH] [--agent PATH]
                          [--tunnel-check PATH] [--image IMAGE] [--app APP]
                          [--environment ENV] [--runtime vm|gvisor]

TOKEN_FILE holds a Modal token pair as JSON, {"token_id": …, "token_secret": …}.
DIR holds `drydock`, `drydockd`, `drydock-host` and `examples/tunnel_check`
from this branch (default target/release, from `cargo build --release -p
drydock -p drydock-host -p drydock-agent --example tunnel_check`). PATH is the
TypeScript host's `dist/main.js` (default hosts/typescript/dist/main.js, from
`corepack pnpm build` there). `--agent` names the linux/amd64 agent drydockd
pushes to the vessel at hello (default DIR/drydock-agent); it must run on
IMAGE's glibc, so a laptop with a newer glibc than the image passes the
tools-image release's `drydock-agent-linux-amd64`.

The tools image drydockd bakes in must hold an agent with `--tcp` (drydock#187):
build drydockd with `DRYDOCK_TOOLS_IMAGE=<ref>` if the checked-in pin is older.
That agent should differ from `--agent`, so launch exercises an upgrade.

It writes a drydock.toml for one provider `modal` into a throwaway
DRYDOCK_ROOT, runs its own drydockd, and then:

- prepares IMAGE twice (Modal's definition cache gives the same image);
- launches a deny-all vessel, which returns after the agent's hello through
  Modal's connect-token edge (the module's dial reach; exec carries no agent
  traffic), and checks that the agent the image held was upgraded to
  `--agent` within that launch, well inside drydockd's 60 s;
- runs an egress probe as root in it (a TLS handshake to a denied address and
  name, and a DNS lookup, recorded either way), then in a second vessel
  provisioned with an allowlist (an allowed name and CIDR, a denied address);
- mints its own connect token for the agent's port, reads the agent's token
  from the sandbox, and runs `tunnel_check --edge` through Modal's edge:
  hello, 4 MiB written and read back, a wrong agent token refused and a
  wrong connect token refused; and checks the token is on no argv;
- destroys both vessels, and lists the app's sandboxes through Modal to show
  none are left.

Every check prints PASS or FAIL. Every sandbox in APP is terminated at the
end, whatever happened, so use an app of its own (default drydock-live-check).
Exit status 0 means every check passed.
"""
import argparse
import hashlib
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
import urllib.parse
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
        # Short and under /tmp: macOS's TMPDIR puts the socket past its 104-byte limit.
        self.root = tempfile.mkdtemp(prefix="dd-modal-", dir="/tmp")
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

    def stop(self):
        self.daemon.send_signal(signal.SIGTERM)
        try:
            self.daemon.wait(30)
        except subprocess.TimeoutExpired:
            self.daemon.kill()
        self.log.close()


# Run as root in the vessel: python is in the default image, so no client tools.
# Modal enforces an allowlist with a transparent proxy: a TCP connect to any
# address succeeds, and an unlisted destination is reset at TLS. So a target is
# reached only if a TLS handshake (SNI for a name) completes; every target
# serves HTTPS on 443. Certificates are not checked: only reach is measured.
EGRESS = r"""
import json, os, socket, ssl, sys
def tcp(host, port):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    stage = "connect"
    try:
        with socket.create_connection((host, port), timeout=6) as raw:
            stage = "TLS"
            with context.wrap_socket(raw, server_hostname=host):
                return "connected"
    except Exception as e:
        return f"blocked at {stage} ({type(e).__name__})"
def dns(name):
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)})
    except Exception as e:
        return f"failed ({type(e).__name__})"
print(json.dumps({"uid": os.getuid(), "dns": dns(sys.argv[1]),
                  "tcp": {f"{h}:{p}": tcp(h, int(p)) for h, p in (t.rsplit(":", 1) for t in sys.argv[2:])}}))
"""

# The installed agent, the one an upgrade replaced (activation keeps it as
# .prev; null if none did), and the running agents (not their supervisor), by
# digest, and whether any process's argv holds the token given on stdin.
AGENTS = r"""
import hashlib, json, os, sys
token = sys.stdin.read().strip()
digest = lambda path: hashlib.sha256(open(path, "rb").read()).hexdigest()
running, exposed = [], False
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        argv = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
        exposed |= bool(token) and any(token.encode() in a for a in argv)
        if argv[-2:] == [b"/run/drydock/agent.sock", b""] and b"--supervisor" not in argv:
            running.append(digest(f"/proc/{pid}/exe"))
    except OSError:
        pass
agent = "/opt/drydock/drydock-agent"
prev = digest(agent + ".prev") if os.path.exists(agent + ".prev") else None
print(json.dumps({"installed": digest(agent), "prev": prev, "running": sorted(set(running)), "exposed": exposed}))
"""
PORT = 7811
TOKEN_FILE = "/run/drydock/tcp.token"


def run(client, sandbox_id, *argv, stdin=None):
    sandbox = modal.Sandbox.from_id(sandbox_id, client=client)
    process = sandbox.exec(*argv, timeout=120)
    if stdin is not None:
        process.stdin.write(stdin)
        process.stdin.write_eof()
        process.stdin.drain()
    process.wait()
    return process.returncode, process.stdout.read().strip()


def agents(client, sandbox_id, token=""):
    code, out = run(client, sandbox_id, "python3", "-c", AGENTS, stdin=token)
    return json.loads(out) if code == 0 else None


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


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
    parser.add_argument("--tunnel-check")
    parser.add_argument("--image", default="python:3.13-slim")
    parser.add_argument("--app", default="drydock-live-check")
    parser.add_argument("--environment")
    parser.add_argument("--runtime", choices=["vm", "gvisor"], default="vm")
    options = parser.parse_args()
    options.agent = options.agent or os.path.join(options.bin_dir, "drydock-agent")
    options.tunnel_check = options.tunnel_check or os.path.join(options.bin_dir, "examples", "tunnel_check")
    for path in [options.host, options.agent, options.tunnel_check] + [
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
        launch_seconds = time.time() - started
        inspected = drydock.cli("inspect", PROVIDER, launched["id"])
        check(inspected["egress_policy"] == "deny", f"inspect: {inspected['state']}, egress {inspected['egress']} ({inspected['egress_policy']})")

        # Launch's hello went through the dial reach, the module's only one. It
        # pushed --agent over it when the image's agent was another build.
        pushed = sha256(options.agent)
        found = agents(client, launched["id"])
        short = lambda d: d and d[:16]
        print(
            f"agents: replaced {found and short(found['prev'])}, installed {found and short(found['installed'])}, "
            f"running {found and [short(d) for d in found['running']]}, pushed {short(pushed)}",
            flush=True,
        )
        if found and found["prev"] is None and found["installed"] == pushed:
            check(False, "an agent upgrade was exercised: the image already holds --agent; build drydockd with a tools image whose agent is older")
        else:
            check(
                found is not None
                and found["prev"] not in (None, pushed)
                and found["installed"] == pushed
                and found["running"] == [pushed]
                and launch_seconds < 45,
                f"the image's agent was upgraded to --agent through the edge within launch's {launch_seconds:.1f}s (under 45 s; drydockd allows 60 s)",
            )

        # The dial route itself: Modal's edge in front of the agent's listener.
        id = launched["id"]
        code, token = run(client, id, "cat", TOKEN_FILE)
        must(code == 0 and len(token) >= 43, f"the agent's token is in {TOKEN_FILE}")
        found = agents(client, id, token)
        check(found is not None and not found["exposed"], "the agent's token is on no process's argv")
        credentials = modal.Sandbox.from_id(id, client=client).create_connect_token(port=PORT)
        base = urllib.parse.urlsplit(credentials.url)
        url = urllib.parse.urlunsplit(
            (base.scheme, base.netloc, "/v1/connect", urllib.parse.urlencode({"_modal_connect_token": credentials.token}), "")
        )
        token_file = os.path.join(drydock.root, "tcp.token")
        with open(os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
            f.write(token)
        result = subprocess.run([options.tunnel_check, "--edge", url, token_file], capture_output=True, text=True, timeout=300)
        lines = [line for line in result.stdout.splitlines() if line.startswith(("PASS ", "FAIL "))]
        for line in lines:
            check(line.startswith("PASS "), f"tunnel_check: {line[5:]}")
        check(len(lines) == 4 and result.returncode == 0, f"tunnel_check ran its four checks: exit {result.returncode} {result.stderr.strip()[-500:]}")

        # Deny all: blockNetwork. A denied address and name; DNS recorded either way.
        result = egress(client, launched["id"], "example.com", "1.1.1.1:443", "example.com:443")
        print(f"deny-all probe: {result}", flush=True)
        must(result is not None and result["uid"] == 0, "the egress probe ran as root")
        check(all(v.startswith("blocked") for v in result["tcp"].values()), f"deny-all blocks TLS: {result['tcp']}")
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
                # Termination is asynchronous: give the list time to empty.
                deadline = time.time() + 60
                while True:
                    left = [s.object_id for s in modal.Sandbox.list(app_id=app.app_id, client=client)]
                    if not left or time.time() > deadline:
                        break
                    time.sleep(2)
            check(left == [], f"Modal lists no sandboxes in app {options.app}: {left}")
        except Exception as error:
            check(False, f"listing app {options.app} through Modal: {error!r}")
    if failures:
        print(f"{len(failures)} CHECKS FAILED", flush=True)
        raise SystemExit(1)
    print("ALL CHECKS PASSED", flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=13"]
# ///
"""Live check of drydock-agent's TCP listener through a Tensorlake tunnel.

    scripts/live-tcp-listener.py KEY_FILE [--agent PATH] [--image IMAGE]

KEY_FILE holds a Tensorlake API key. PATH is a drydock-agent executable for
linux/amd64, built from this branch (default: target/release/drydock-agent,
from `cargo build --release -p drydock-agent`).

It creates a sandbox, installs the agent as root, writes a fresh token to
/run/drydock/tcp.token (mode 0600, root's, never on any argv), and starts
`drydock-agent --tcp 127.0.0.1:7811 --tcp-token-file ... --socket ...` as
root. From this machine it opens Tensorlake's TCP tunnel to guest port 7811,
does the handshake with the token and reads `GET /hello` over the switched
connection, then checks that a wrong token gets 401 through the tunnel too.
Inside the guest, a process running as the image's non-root user connects to
127.0.0.1:7811 without the token and with a guessed one, and gets 401 both
times; it cannot read the token file either. The sandbox is deleted at the
end, whatever happened. Exit status 0 means every check passed.
"""
import argparse
import json
import os
import secrets
import signal
import sys
import time
import urllib.error
import urllib.request

import websockets.sync.client

API = "https://api.tensorlake.ai"
PORT = 7811
TOKEN_FILE = "/run/drydock/tcp.token"
SOCKET = "/run/drydock/agent.sock"
AGENT = "/opt/drydock/drydock-agent"


def request(method, url, key, body=None, content_type="application/json", timeout=120):
    data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {key}")
    if data is not None:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def check(condition, message):
    print(("PASS " if condition else "FAIL ") + message, flush=True)
    if not condition:
        raise SystemExit(1)


class Sandbox:
    def __init__(self, key, image):
        self.key = key
        status, body = request("POST", f"{API}/sandboxes", key, {"image": image, "timeout_secs": 900})
        if status not in (200, 201, 202):
            raise SystemExit(f"create sandbox: HTTP {status}: {body[:500]!r}")
        self.id = json.loads(body)["sandbox_id"]
        print(f"created sandbox {self.id}", flush=True)
        deadline = time.time() + 300
        while True:
            status, body = request("GET", f"{API}/sandboxes/{self.id}", key)
            info = json.loads(body) if status == 200 else {}
            if info.get("status") == "running":
                break
            if time.time() > deadline:
                raise SystemExit(f"sandbox {self.id} did not start: HTTP {status}: {body[:500]!r}")
            time.sleep(2)
        url = info.get("sandbox_url") or f"https://{self.id}.sandbox.tensorlake.ai"
        self.url = url if url.startswith("http") else f"https://{url}"
        self.url = self.url.rstrip("/")

    def delete(self):
        status, body = request("DELETE", f"{API}/sandboxes/{self.id}", self.key)
        print(f"deleted sandbox {self.id}: HTTP {status}", flush=True)
        status, body = request("GET", f"{API}/sandboxes/{self.id}", self.key)
        state = json.loads(body).get("status") if status == 200 else f"HTTP {status}"
        print(f"sandbox {self.id} afterwards: {state}", flush=True)

    def run(self, script, user="root", env=None):
        """Runs `bash -c script`; returns (exit code, output lines)."""
        body = {"command": "bash", "args": ["-c", script], "user": user, "env": env or {}, "timeout": 60}
        status, raw = request("POST", f"{self.url}/api/v1/processes/run", self.key, body)
        if status != 200:
            raise SystemExit(f"run as {user}: HTTP {status}: {raw[:500]!r}")
        lines, code = [], None
        for line in raw.decode(errors="replace").splitlines():
            if not line.startswith("data:"):
                continue
            event = json.loads(line[5:])
            if "line" in event:
                lines.append(event["line"])
            if "exit_code" in event:
                code = event["exit_code"]
        return code, lines

    def upload(self, path, content):
        status, body = request(
            "PUT", f"{self.url}/api/v1/files?path={path}", self.key, content, "application/octet-stream", timeout=600
        )
        if status not in (200, 201, 204):
            raise SystemExit(f"upload {path}: HTTP {status}: {body[:500]!r}")

    def start(self, command, args):
        body = {"command": command, "args": args, "user": "root", "stdout_mode": "capture", "stderr_mode": "capture"}
        status, raw = request("POST", f"{self.url}/api/v1/processes", self.key, body)
        if status not in (200, 201):
            raise SystemExit(f"start {command}: HTTP {status}: {raw[:500]!r}")
        return json.loads(raw)["pid"]

    def output(self, pid):
        status, raw = request("GET", f"{self.url}/api/v1/processes/{pid}/output", self.key)
        return json.loads(raw).get("lines", []) if status == 200 else [f"HTTP {status}"]

    def tunnel(self):
        url = self.url.replace("https://", "wss://", 1) + f"/api/v1/tunnels/tcp?port={PORT}"
        return websockets.sync.client.connect(
            url, additional_headers={"Authorization": f"Bearer {self.key}"}, open_timeout=30
        )


class Stream:
    """Raw bytes over a WebSocket whose binary frames carry one TCP connection."""

    def __init__(self, ws):
        self.ws, self.buffer = ws, b""

    def send(self, data):
        self.ws.send(data)

    def read_until(self, marker, limit=1 << 20):
        while marker not in self.buffer:
            if len(self.buffer) > limit:
                raise SystemExit("no end of response head")
            try:
                frame = self.ws.recv(timeout=15)
            except websockets.exceptions.ConnectionClosed:
                break
            self.buffer += frame if isinstance(frame, bytes) else frame.encode()
        head, _, self.buffer = self.buffer.partition(marker)
        return head

    def read_rest(self):
        while True:
            try:
                frame = self.ws.recv(timeout=15)
            except (websockets.exceptions.ConnectionClosed, TimeoutError):
                break
            self.buffer += frame if isinstance(frame, bytes) else frame.encode()
        rest, self.buffer = self.buffer, b""
        return rest


def handshake(token):
    authorization = f"Authorization: Bearer {token}\r\n" if token else ""
    return (
        "GET /v1/connect HTTP/1.1\r\nHost: sandbox\r\nConnection: Upgrade\r\n"
        f"Upgrade: drydock-agent\r\n{authorization}\r\n"
    ).encode()


def tunnel_checks(open_tunnel, token):
    """The handshake and /hello through the provider's tunnel, then a wrong token."""
    with open_tunnel() as ws:
        stream = Stream(ws)
        stream.send(handshake(token))
        head = stream.read_until(b"\r\n\r\n").decode(errors="replace")
        check(head.startswith("HTTP/1.1 101 "), f"the token switches protocols through the tunnel: {head.splitlines()[:1]}")
        # The switched connection carries what the Unix socket carries, which
        # serves HTTP/1.1 as well as HTTP/2.
        stream.send(b"GET /hello HTTP/1.1\r\nHost: agent\r\nConnection: close\r\n\r\n")
        head = stream.read_until(b"\r\n\r\n").decode(errors="replace")
        body = stream.read_rest()
        check(head.startswith("HTTP/1.1 200 "), f"GET /hello after the 101: {head.splitlines()[:1]}")
        if b"\r\n" in body and "chunked" in head.lower():
            body = b"".join(body.split(b"\r\n")[1::2])
        hello = json.loads(body)
        check(bool(hello.get("fingerprint")), f"hello: fingerprint {hello['fingerprint'][:16]}…, platform {hello.get('platform')}")
    with open_tunnel() as ws:
        stream = Stream(ws)
        stream.send(handshake(secrets.token_urlsafe(32)))
        answer = stream.read_until(b"\r\n\r\n").decode(errors="replace") + stream.read_rest().decode(errors="replace")
        check(answer.startswith("HTTP/1.1 401 "), f"a wrong token gets 401 through the tunnel: {answer.splitlines()[:1]}")


# A non-root guest process: bash's /dev/tcp, so the image needs no client.
GUEST_PROBE = r"""
id -un; id -u
if cat /run/drydock/tcp.token >/dev/null 2>&1; then echo "TOKEN READABLE"; else echo "token file unreadable"; fi
for authorization in "" "Authorization: Bearer $GUESS\r\n"; do
  exec 3<>/dev/tcp/127.0.0.1/7811 || exit 3
  printf "GET /v1/connect HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: drydock-agent\r\n${authorization}\r\n" >&3
  timeout 10 head -n 1 <&3 | tr -d '\r'
  exec 3<&-
done
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("key_file")
    parser.add_argument("--agent", default="target/release/drydock-agent")
    parser.add_argument("--image", default="tensorlake/ubuntu-minimal")
    options = parser.parse_args()
    key = open(options.key_file).read().strip()
    agent = open(options.agent, "rb").read()
    if agent[:4] != b"\x7fELF" or agent[18] != 62:
        raise SystemExit(f"{options.agent} is not a linux/amd64 executable")
    token = secrets.token_urlsafe(32)

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    sandbox = Sandbox(key, options.image)
    try:
        sandbox.upload("/tmp/drydock-agent.upload", agent)
        # The token travels in root's environment, readable only by root,
        # never on an argv other guest users could read through /proc.
        code, lines = sandbox.run(
            f"set -e; install -d -m 0755 /opt/drydock; install -m 0755 /tmp/drydock-agent.upload {AGENT};"
            " rm -f /tmp/drydock-agent.upload; install -d -m 0700 /run/drydock;"
            f' (umask 077; printf %s "$DRYDOCK_TCP_TOKEN" > {TOKEN_FILE}); chmod 0600 {TOKEN_FILE};'
            f" stat -c '%U %a' {TOKEN_FILE}; uname -m",
            env={"DRYDOCK_TCP_TOKEN": token},
        )
        check(code == 0, f"installed the agent and its token file as root: {lines}")
        pid = sandbox.start(AGENT, ["--tcp", f"127.0.0.1:{PORT}", "--tcp-token-file", TOKEN_FILE, "--socket", SOCKET])
        code, lines = sandbox.run(
            f"for i in $(seq 100); do [ -S {SOCKET} ] && (exec 3<>/dev/tcp/127.0.0.1/{PORT}) 2>/dev/null && exit 0; sleep 0.1; done; exit 1"
        )
        check(code == 0, f"the agent listens on 127.0.0.1:{PORT} (output: {sandbox.output(pid)})")
        code, lines = sandbox.run(f"tr '\\0' ' ' < /proc/$(pgrep -o -f '{AGENT} --tcp')/cmdline")
        check(code == 0 and token not in " ".join(lines), f"the token is not on the agent's argv: {lines}")

        tunnel_checks(sandbox.tunnel, token)

        code, lines = sandbox.run(GUEST_PROBE, user="tl-user", env={"GUESS": secrets.token_urlsafe(32)})
        print(f"guest probe as non-root (exit {code}): {lines}", flush=True)
        check(len(lines) >= 4 and lines[1] != "0", "the probe ran as a non-root user")
        check("token file unreadable" in lines, "the non-root user cannot read the token file")
        refusals = [line for line in lines if line.startswith("HTTP/1.1 ")]
        check(refusals == ["HTTP/1.1 401 Unauthorized"] * 2, f"no token and a guessed token both get 401: {refusals}")
        log = sandbox.output(pid)
        check(any("tcp connection refused" in line for line in log), f"the agent logged the refusals: {log[-3:]}")
        check(not any(token in line for line in log), "the token is not in the agent's log")
        print("ALL CHECKS PASSED", flush=True)
    finally:
        sandbox.delete()


if __name__ == "__main__":
    main()

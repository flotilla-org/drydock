#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Live check of upload bootstrap (drydock#215) against Daytona.

    scripts/live-daytona-upload.py KEY_FILE --organization-id ID \\
        --ssh-host-key 'ssh-ed25519 AAAA...' [--region eu] \\
        [--image ubuntu:24.04] [--image-route provider_push|registry_pull] \\
        [--agent PATH] [--bin DIR] [--keep-snapshot]

KEY_FILE holds a Daytona API key with the permissions in
docs/provider-credentials.md. ID is the organization's id; the host key is
Daytona's SSH gateway key, verified out of band. DIR holds drydockd and
drydock-host built from this branch (default target/release, from
`cargo build --release -p drydock -p drydock-host -p drydock-agent`). PATH is
the linux/amd64 drydock-agent drydockd uploads (default
$DRYDOCK_AGENT_BIN_LINUX_AMD64, else DIR/drydock-agent-linux-amd64, else
DIR/drydock-agent). IMAGE is any linux/amd64 image Daytona can run; a tag is
resolved to a digest at launch. Only the Python standard library is needed.

It starts drydockd with a throwaway configuration naming the key as
`{ file = KEY_FILE }`, then, printing PASS or FAIL for each check:

- Daytona declares upload bootstrap and the files port;
- a launch prepares the base image as a snapshot and returns only after the
  agent's hello over Daytona's SSH gateway;
- the snapshot holds the base image alone (no build, no tools image);
- the agent in the sandbox is byte for byte the build drydockd uploaded;
- preparing the same image again under another (fake) tools pin returns the
  same snapshot, and Daytona's snapshot list shows no new one.

The sandbox is destroyed at the end, whatever happened, and the snapshot is
deleted when this run made it (keep it with --keep-snapshot). Exit status 0
means every check passed.
"""
import argparse
import hashlib
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

PROVIDER = "daytona"
AGENT = "/opt/drydock/drydock-agent"
FAKE_TOOLS = "ghcr.io/flotilla-org/drydock-tools@sha256:" + "f" * 64


def check(condition, message):
    print(("PASS " if condition else "FAIL ") + message, flush=True)
    if not condition:
        raise SystemExit(1)


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=900):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def daemon(sock, method, path, body=None):
    connection = UnixConnection(sock)
    data = None if body is None else json.dumps(body).encode()
    connection.request(method, path, body=data, headers={"Content-Type": "application/json"} if data else {})
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    return response.status, json.loads(payload or b"null")


def guest(sock, environment, argv):
    """Runs argv in the vessel through drydockd's exec route: a POST that
    upgrades to a raw byte stream carrying the command's output."""
    body = json.dumps({"command": argv}).encode()
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(120)
    connection.connect(sock)
    path = f"/v1/providers/{PROVIDER}/environments/{urllib.parse.quote(environment, safe='')}/exec"
    connection.sendall(
        f"POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: drydock-stream\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
    received = b""
    while b"\r\n\r\n" not in received:
        chunk = connection.recv(65536)
        if not chunk:
            break
        received += chunk
    head, _, output = received.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1]) if head else 0
    if status != 101:
        connection.close()
        return status, output.decode(errors="replace")
    connection.shutdown(socket.SHUT_WR)
    while True:
        chunk = connection.recv(65536)
        if not chunk:
            break
        output += chunk
    connection.close()
    return status, output.decode(errors="replace")


def daytona(method, path, key, organization, query=None):
    url = "https://app.daytona.io/api/" + path + ("?" + urllib.parse.urlencode(query) if query else "")
    request = urllib.request.Request(url, method=method, headers={
        "Authorization": f"Bearer {key}", "X-Daytona-Organization-ID": organization})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode(errors="replace")[:300]


def snapshots(key, organization):
    """Every drydock snapshot's name, through Daytona's own paged list."""
    names, page = set(), 1
    while True:
        status, body = daytona("GET", "snapshots", key, organization, {"page": page, "limit": 200})
        check(status == 200, f"Daytona lists snapshots (page {page}, HTTP {status})")
        names |= {item["name"] for item in body["items"] if item["name"].startswith("drydock-snapshot-")}
        if page >= body.get("totalPages", 1):
            return names
        page += 1


def agent_build(args, binaries):
    for path in (args.agent, os.environ.get("DRYDOCK_AGENT_BIN_LINUX_AMD64"),
                 os.path.join(binaries, "drydock-agent-linux-amd64"), os.path.join(binaries, "drydock-agent")):
        if path and os.path.isfile(path):
            return os.path.abspath(path)
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("key_file")
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--ssh-host-key", required=True)
    parser.add_argument("--region", default="eu")
    parser.add_argument("--image", default="ubuntu:24.04")
    parser.add_argument("--image-route", choices=["provider_push", "registry_pull"])
    parser.add_argument("--agent")
    parser.add_argument("--bin", default="target/release")
    parser.add_argument("--keep-snapshot", action="store_true")
    args = parser.parse_args()

    key_file = os.path.abspath(os.path.expanduser(args.key_file))
    with open(key_file) as handle:
        key = handle.read().strip()
    binaries = os.path.abspath(args.bin)
    for name in ("drydockd", "drydock-host"):
        check(os.access(os.path.join(binaries, name), os.X_OK), f"{name} is in {binaries}")
    agent = agent_build(args, binaries)
    check(agent is not None, "a linux/amd64 drydock-agent build is available to upload")
    with open(agent, "rb") as handle:
        uploaded = hashlib.sha256(handle.read()).hexdigest()

    # Short, so socket paths fit macOS's 104 bytes.
    work = tempfile.mkdtemp(prefix="dd-", dir="/tmp")
    os.chmod(work, 0o700)
    config = os.path.join(work, "drydock.toml")
    sock = os.path.join(work, "run", "drydock.sock")
    log = os.path.join(work, "drydockd.log")
    with open(config, "w") as handle:
        handle.write(f"""[providers.{PROVIDER}]
module = "daytona"
credential = {{ file = {json.dumps(key_file)} }}
image = {json.dumps(args.image)}
size = {{ cpus = 1, memory = "1GiB", disk = "3GiB" }}
settings = {{ organization_id = {json.dumps(args.organization_id)}, ssh_host_key = {json.dumps(args.ssh_host_key)}, region = {json.dumps(args.region)} }}
""")
    env = dict(os.environ, DRYDOCK_HOST_BIN=os.path.join(binaries, "drydock-host"), DRYDOCK_AGENT_BIN_LINUX_AMD64=agent,
               RUST_LOG="info")
    with open(log, "w") as stderr:
        process = subprocess.Popen([os.path.join(binaries, "drydockd"), "--config", config, "--socket", sock],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr, env=env)
    environment, snapshot, made = None, None, False
    try:
        deadline = time.monotonic() + 30
        declaration = None
        while time.monotonic() < deadline and declaration is None:
            try:
                status, body = daemon(sock, "GET", f"/v1/providers/{PROVIDER}")
                if status == 200 and body["readiness"]["status"] == "ready":
                    declaration = body
            except OSError:
                pass
            time.sleep(0.2)
        check(declaration is not None, "drydockd serves a ready Daytona provider")
        check(declaration["capabilities"]["bootstrap"] == "upload" and declaration["ports"].get("files"),
              "Daytona declares upload bootstrap and the files port")
        before = snapshots(key, args.organization_id)

        options = {"image": args.image}
        if args.image_route:
            options["image_route"] = args.image_route
        started = time.monotonic()
        status, launched = daemon(sock, "POST", f"/v1/providers/{PROVIDER}/launch", options)
        print(f"     launch took {time.monotonic() - started:.1f} s: HTTP {status} {json.dumps(launched)}")
        if status == 200:
            environment = launched["id"]
        check(status == 200, "launch returns after the uploaded agent's hello over Daytona's SSH gateway")

        with open(os.path.join(work, "run", "keys", launched["label"], "request.json")) as handle:
            prepared = json.load(handle)["prepared"]
        snapshot = prepared["id"]
        made = snapshot not in before
        print(f"     snapshot {snapshot} ({'made by this run' if made else 'already there'}) of {prepared['image_digest']}")
        status, row = daytona("GET", f"snapshots/{snapshot}", key, args.organization_id)
        check(status == 200 and "@sha256:" in (row.get("imageName") or "") and "drydock-tools" not in row["imageName"]
              and not row.get("buildInfo"), f"the snapshot is the base image alone: {row.get('imageName') if status == 200 else row}")

        status, output = guest(sock, environment, ["sha256sum", AGENT])
        check(status == 101 and output.split()[:1] == [uploaded], f"the vessel's agent is the uploaded build {uploaded[:12]}… ({output.strip()})")

        request = {
            "size": launched["granted_size"],
            "platform": prepared["platform"],
            "image_digest": prepared["image_digest"],
            "tools_digest": FAKE_TOOLS,
        }
        if args.image_route:
            request["route"] = args.image_route
        status, again = daemon(sock, "POST", f"/v1/providers/{PROVIDER}/prepare", request)
        check(status == 200 and again["id"] == snapshot and again["tools_digest"] == FAKE_TOOLS,
              f"a bumped tools pin prepares the same snapshot (HTTP {status} {json.dumps(again)})")
        after = snapshots(key, args.organization_id)
        check(after - before <= {snapshot}, f"Daytona holds no new snapshot for it ({len(after - before)} new in this run)")
    finally:
        if environment:
            status, body = daemon(sock, "DELETE", f"/v1/providers/{PROVIDER}/environments/{urllib.parse.quote(environment, safe='')}")
            print(("PASS " if status in (200, 204) else "FAIL ") + f"destroyed sandbox {environment} (HTTP {status} {body})", flush=True)
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
        if snapshot and made and not args.keep_snapshot:
            status, row = daytona("GET", f"snapshots/{snapshot}", key, args.organization_id)
            if status == 200:
                status, body = daytona("DELETE", f"snapshots/{row['id']}", key, args.organization_id)
            print(("PASS " if status in (200, 204, 404) else "FAIL ") + f"deleted snapshot {snapshot} (HTTP {status})", flush=True)
        print(f"     drydockd log: {log}")


if __name__ == "__main__":
    main()

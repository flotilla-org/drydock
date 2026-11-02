#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Live check of image staging (drydock#190) against a private GHCR package.

    scripts/live-staging-registry.py PUSH_TOKEN_FILE --username USER \\
        --repository ghcr.io/OWNER/PACKAGE --image REGISTRY/NAME@sha256:... \\
        [--pull-token-file FILE] [--source-credential FILE] \\
        [--platform linux/amd64] [--bin DIR]

PUSH_TOKEN_FILE holds a GitHub token for USER with write:packages (and
delete:packages, to clean up). --pull-token-file holds a token with
read:packages; it defaults to the push token. PACKAGE is a private container
package the operator created once. --image is the image to stage, pinned by
digest, typically from the lab registry; --source-credential is a file holding
`username:token` for that registry, if it needs one. DIR holds drydockd and
drydock-host built from this branch (default: target/release, from
`cargo build --release -p drydock -p drydock-host`).

It starts drydockd from DIR with a throwaway configuration: one staging
registry (the package) and two `reference` provider instances that pull from
it on the registry-pull route. Preparing the image for the first instance
stages it; the reference module records whatever reference its host is given,
which is checked to be the package by digest. Then a pull of that digest from
GHCR anonymously must fail (the package is private), a pull with the pull
token must succeed with the same bytes, and preparing for the second instance
must reuse the copy without uploading. The staged package version is deleted
at the end, whatever happened. Exit status 0 means every check passed.
"""
import argparse
import base64
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

MANIFESTS = ", ".join([
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
TOOLS = "ghcr.io/flotilla-org/drydock-tools@sha256:" + "0" * 64


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


def https(method, url, headers=None):
    request = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def ghcr_manifest(path, digest, basic=None):
    """Pulls a manifest by digest the way a provider does: a token for the
    pull scope (anonymous, or with Basic credentials), then the manifest."""
    query = urllib.parse.urlencode({"service": "ghcr.io", "scope": f"repository:{path}:pull"})
    headers = {"Authorization": "Basic " + base64.b64encode(basic.encode()).decode()} if basic else {}
    status, body = https("GET", f"https://ghcr.io/token?{query}", headers)
    if status != 200:
        return status, b""
    token = json.loads(body).get("token", "")
    return https("GET", f"https://ghcr.io/v2/{path}/manifests/{digest}",
                 {"Authorization": f"Bearer {token}", "Accept": MANIFESTS})


def github(method, path, token):
    return https(method, f"https://api.github.com{path}", {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })


def delete_version(owner, package, digest, token):
    name = urllib.parse.quote(package, safe="")
    for scope in (f"/orgs/{owner}", f"/users/{owner}"):
        status, body = github("GET", f"{scope}/packages/container/{name}/versions?per_page=100", token)
        if status != 200:
            continue
        for version in json.loads(body):
            if version.get("name") == digest:
                status, body = github("DELETE", f"{scope}/packages/container/{name}/versions/{version['id']}", token)
                return status == 204, f"HTTP {status} {body[:200]!r}"
        return False, "no package version with that digest"
    return False, f"cannot list versions of {owner}/{package}: HTTP {status} {body[:200]!r}"


def read_secret(path):
    with open(os.path.expanduser(path)) as handle:
        return handle.read().strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("push_token_file")
    parser.add_argument("--pull-token-file")
    parser.add_argument("--username", required=True)
    parser.add_argument("--repository", required=True, help="ghcr.io/OWNER/PACKAGE")
    parser.add_argument("--image", required=True, help="REGISTRY/NAME@sha256:...")
    parser.add_argument("--source-credential", help="file holding username:token for the image's registry")
    parser.add_argument("--platform", default="linux/amd64")
    parser.add_argument("--bin", default="target/release")
    args = parser.parse_args()

    push_file = os.path.abspath(os.path.expanduser(args.push_token_file))
    pull_file = os.path.abspath(os.path.expanduser(args.pull_token_file or args.push_token_file))
    host, _, path = args.repository.partition("/")
    check(host == "ghcr.io" and "/" in path, f"repository {args.repository} is a GHCR package")
    owner, _, package = path.partition("/")
    os_name, _, architecture = args.platform.partition("/")
    image_pull = None
    if args.source_credential:
        username, _, secret = read_secret(args.source_credential).partition(":")
        image_pull = {"username": username, "secret": secret}
    binaries = os.path.abspath(args.bin)
    for name in ("drydockd", "drydock-host"):
        check(os.access(os.path.join(binaries, name), os.X_OK), f"{name} is in {binaries}")

    work = tempfile.mkdtemp(prefix="drydock-staging-")
    os.chmod(work, 0o700)
    config = os.path.join(work, "drydock.toml")
    sock = os.path.join(work, "run", "drydock.sock")
    log = os.path.join(work, "drydockd.log")
    platforms = f'[{{os = "{os_name}", architecture = "{architecture}"}}]'
    with open(config, "w") as handle:
        handle.write(f"""[registries.live]
repository = {json.dumps(args.repository)}
push = {{ username = {json.dumps(args.username)}, credential = {{ file = {json.dumps(push_file)} }} }}
pull = {{ username = {json.dumps(args.username)}, credential = {{ file = {json.dumps(pull_file)} }} }}
""")
        for instance in ("first", "second"):
            handle.write(f"""[providers.{instance}]
module = "reference"
credential = {{ env = "DRYDOCK_LIVE_REFERENCE" }}
pull_from = ["live"]
settings = {{ platforms = {platforms} }}
""")
    env = dict(os.environ, DRYDOCK_HOST_BIN=os.path.join(binaries, "drydock-host"), DRYDOCK_LIVE_REFERENCE="unused",
               RUST_LOG="info")
    with open(log, "w") as stderr:
        process = subprocess.Popen([os.path.join(binaries, "drydockd"), "--config", config, "--socket", sock],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr, env=env)
    staged = None
    try:
        deadline = time.monotonic() + 30
        ready = False
        while time.monotonic() < deadline and not ready:
            try:
                status, providers = daemon(sock, "GET", "/v1/providers")
                ready = status == 200 and all(p["readiness"]["status"] == "ready" for p in providers)
            except OSError:
                pass
            time.sleep(0.2)
        check(ready, "drydockd serves both reference instances")

        request = {
            "size": {"cpus": 1, "memory_bytes": 1 << 30, "disk_bytes": 1 << 30},
            "platform": {"os": os_name, "architecture": architecture},
            "image_digest": args.image,
            "tools_digest": TOOLS,
        }
        if image_pull:
            request["image_pull"] = image_pull
        started = time.monotonic()
        status, prepared = daemon(sock, "POST", "/v1/providers/first/prepare", request)
        print(f"     first prepare took {time.monotonic() - started:.1f} s: HTTP {status} {json.dumps(prepared)}")
        check(status == 200, "the first instance prepares the image")
        reference = prepared["image_digest"]
        check(reference.startswith(args.repository + "@sha256:"), f"its host was handed the staged copy {reference}")
        staged = reference.split("@", 1)[1]

        status, _ = ghcr_manifest(path, staged)
        check(status != 200, f"an anonymous pull by digest is refused (HTTP {status}): the package is private")
        status, body = ghcr_manifest(path, staged, f"{args.username}:{read_secret(pull_file)}")
        check(status == 200 and "sha256:" + hashlib.sha256(body).hexdigest() == staged,
              f"a pull by digest with the pull token succeeds (HTTP {status}) with the staged bytes")

        status, again = daemon(sock, "POST", "/v1/providers/second/prepare", request)
        check(status == 200 and again["image_digest"] == reference, "the second instance is handed the same copy")
        with open(log) as handle:
            lines = handle.read()
        print("     drydockd staging log:")
        for line in lines.splitlines():
            if "staged" in line:
                print("       " + line)
        check("image staged" in lines and "image already staged" in lines,
              "drydockd staged once and reused the copy for the second instance")
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
        if staged:
            deleted, detail = delete_version(owner, package, staged, read_secret(push_file))
            print(("PASS " if deleted else "FAIL ") + f"deleted the staged package version {staged}: {detail}", flush=True)
            if not deleted:
                print(f"     delete it by hand: https://github.com/{owner}?tab=packages (package {package})")
                sys.exit(1)
        print(f"     drydockd log: {log}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Round-trip probe for the CI recipe fixtures (not a vendor agent protocol).

Recipe JSON arrives on stdin. Real providers supply their agent-specific probe
through the same executable seam. This fixture uses a token line for TCP, bearer
HTTP auth for WebSocket, and a pinned SSH host key plus the supplied identity.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import urllib.parse

PAYLOAD = b"drydock-recipe\x00\xff\r\n"


def exact(channel, count):
    result = b""
    while len(result) < count:
        chunk = channel.recv(count - len(result))
        if not chunk:
            raise ValueError("truncated stream")
        result += chunk
    return result


def probe(recipe, identity):
    if recipe["kind"] == "ssh":
        host, port = recipe["endpoint"].rsplit(":", 1)
        if any(value.startswith("-") or any(c in value for c in "\r\n ") for value in (host, recipe["user"])):
            raise ValueError("invalid SSH target")
        with tempfile.TemporaryDirectory() as directory:
            known = Path(directory) / "known_hosts"
            known.write_text("drydock-fixture " + recipe["host_key"] + "\n")
            command = ["ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes",
                       "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlias=drydock-fixture", "-o", "GlobalKnownHostsFile=/dev/null",
                       "-o", "UserKnownHostsFile=" + str(known), "-o", "ConnectTimeout=3", "-i", identity,
                       "-p", port, "-l", recipe["user"], host, "cat"]
            result = subprocess.run(command, input=PAYLOAD, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
            return result.returncode == 0 and result.stdout == PAYLOAD
    if recipe["kind"] != "dial":
        raise ValueError("this probe expects SSH or Dial")
    if dt.datetime.fromisoformat(recipe["expires_at"].replace("Z", "+00:00")) <= dt.datetime.now(dt.timezone.utc):
        raise ValueError("expired recipe")
    url = urllib.parse.urlsplit(recipe["url"])
    with socket.create_connection((url.hostname, url.port), timeout=3) as channel:
        if url.scheme == "tcp":
            channel.sendall(recipe["token"].encode() + b"\n" + PAYLOAD)
            return exact(channel, len(PAYLOAD)) == PAYLOAD
        if url.scheme == "wss":
            channel = ssl.create_default_context().wrap_socket(channel, server_hostname=url.hostname)
        if url.scheme not in ("ws", "wss"):
            raise ValueError("unknown dial scheme")
        key = base64.b64encode(os.urandom(16)).decode()
        channel.sendall((f"GET {url.path or '/'} HTTP/1.1\r\nHost: {url.netloc}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nAuthorization: Bearer {recipe['token']}\r\n\r\n").encode())
        headers = b""
        while not headers.endswith(b"\r\n\r\n") and len(headers) < 8192:
            headers += exact(channel, 1)
        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        if not headers.startswith(b"HTTP/1.1 101") or expected not in headers:
            return False
        mask = os.urandom(4)
        channel.sendall(bytes([0x82, 0x80 | len(PAYLOAD)]) + mask + bytes(value ^ mask[i % 4] for i, value in enumerate(PAYLOAD)))
        kind, length = exact(channel, 2)
        return kind == 0x82 and length == len(PAYLOAD) and exact(channel, length) == PAYLOAD


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True)
    args = parser.parse_args()
    try:
        success = probe(json.load(sys.stdin), args.identity)
    except (OSError, ValueError, subprocess.SubprocessError, KeyError):
        success = False
    raise SystemExit(0 if success else 1)

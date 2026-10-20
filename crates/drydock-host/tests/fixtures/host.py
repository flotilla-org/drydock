"""Independent socket-boundary fixture, not a provider implementation.

Implements only the public JSON protocol, with selectable deliberate violations.
The same conformance scenario list runs against this and the Rust binary.
"""
import copy
import hmac
import http.server
import json
import sys
import threading
import urllib.parse

fault = sys.argv[2] if len(sys.argv) > 2 else "none"
rows = {}
delete_attempts = {}
events = []
condition = threading.Condition()
size = {"cpus": 1.0, "memory_bytes": 1024, "disk_bytes": 0}
capabilities = {
    "material_modes": ["frozen"], "checkout_strategies": ["host_clone"],
    "workspace_root": "/workspace", "suspend_resume": True, "export": False,
    "egress": {"routes": ["none"], "enforcement": "advisory"},
    "fallback_runner": True, "bootstrap": "bake", "usage": True, "quota": True,
}

if fault.startswith("egress-"):
    capabilities["egress"]["enforcement"] = "enforced"


def emit(row, kind, **fields):
    with condition:
        event = {"cursor": str(len(events) + 1), "id": row["id"], "provider": "a",
                 "label": row["label"], "timestamp": "2026-10-20T00:00:00Z",
                 "timestamp_source": "adaptor", "event": {"kind": kind, **fields}}
        if fault == "timestamp":
            event.pop("timestamp_source")
        if fault == "time-range":
            event["timestamp"] = "2026-99-99T00:00:00Z"
        if fault == "size" and kind == "running":
            event["event"]["granted_size"] = {**size, "cpus": 2}
        if fault == "loss" and kind == "gone":
            event["event"]["cause"] = {"kind": "evicted_by_provider"}
        events.append({"type": "event", "event": event})
        condition.notify_all()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def respond(self, status, value=None):
        if fault == "booting" and self.command == "POST" and self.path == "/v1/providers/a/environments" and isinstance(value, dict) and "id" in value:
            value = {**value, "granted_size": None, "state": {"state": "unknown", "reason": "provider_api_error"}}
        body = b"" if status == 204 else json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def refused(self):
        self.respond(422, {"kind": "internal" if fault == "refusal" else "refused",
                           "reason": "invalid", **({"provider_error": "invalid"} if fault == "refusal" else {})})

    def do_GET(self):
        self.route()

    def do_POST(self):
        self.route()

    def do_DELETE(self):
        self.route()

    def do_PUT(self):
        self.route()

    def route(self):
        parsed = urllib.parse.urlsplit(self.path)
        parts = parsed.path.split("/")
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"null")
        if fault != "auth" and not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer fixture-token"):
            return self.respond(401, {"kind": "refused", "reason": "unauthorized"})
        if parsed.path == "/v1/hello":
            return self.respond(200, {"protocol_version": "2", "host_version": "fixture", "modules": [],
                "providers": [{"provider": "a", "module": "memory", "readiness": {"status": "ready"},
                               "capabilities": capabilities, "rate_limits": []}]})
        if parsed.path == "/v1/config" or parts[-1] == "credential":
            return self.respond(204)
        if parsed.path == "/v1/events":
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Connection", "close")
            self.end_headers()
            since = urllib.parse.parse_qs(parsed.query).get("since", [None])[0]
            with condition:
                if since is None or not since.isdigit():
                    record = {"type": "snapshot", "cursor": str(len(events)), "environments": list(rows.values())}
                    if fault == "gap" and since is not None:
                        record["type"] = "unmarked"
                    self.wfile.write(json.dumps(record).encode() + b"\n")
                    self.wfile.flush()
                    index = len(events)
                else:
                    index = int(since)
            try:
                while True:
                    with condition:
                        condition.wait_for(lambda: len(events) > index)
                        batch = copy.deepcopy(events[index:])
                        index = len(events)
                    for record in batch:
                        self.wfile.write(json.dumps(record).encode() + b"\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return
        if parts[-1] == "quota":
            value = {"credits_remaining": float("inf") if fault == "credits" else None, "credit_unit": None,
                     "concurrency_in_use": len(rows), "concurrency_limit": None}
            if fault == "null":
                del value["credit_unit"]
            return self.respond(200, value)
        if parts[-1] == "usage":
            period = {key: value[0] for key, value in urllib.parse.parse_qs(parsed.query).items()}
            if period.get("start") == "bad" or period.get("start", "") > period.get("end", ""):
                return self.refused()
            return self.respond(200, {"period": period, "environment_hours": [{"size": size, "hours": -1 if fault == "usage" else 0}]})
        if parts[-1] == "environments":
            if self.command == "GET":
                value = copy.deepcopy(list(rows.values()))
                if fault == "label":
                    for row in value:
                        row["label"] = None
                return self.respond(200, value)
            if body["prepared"]["provider"] != "a" and fault not in ("stray-cleanup", "cleanup-failure"):
                return self.refused()
            for field, value in body["size"].items():
                if not isinstance(value, (int, float)) or value < 0 or (field == "cpus" and value == 0) or (field != "cpus" and not isinstance(value, int)):
                    if fault != "semantic":
                        return self.refused()
            for row in rows.values():
                if row["label"] == body["label"] and fault != "idempotent":
                    if fault == "partial":
                        return self.respond(500, {"kind": "internal", "reason": "SECRET", "provider_error": "SECRET"})
                    return self.respond(200, row)
            row = {"id": str(len(events) + 1), "label": body["label"], "provider": "a",
                   "state": {"state": "running"}, "granted_size": body["size"], "egress": "enforced" if fault.startswith("egress-") else "advisory"}
            rows[row["id"]] = row
            emit(row, "created")
            if fault == "slow":
                threading.Timer(1.5, lambda: emit(row, "running", granted_size=row["granted_size"])).start()
            else:
                emit(row, "running", granted_size=row["granted_size"])
            if fault == "partial":
                return self.respond(500, {"kind": "internal", "reason": "SECRET", "provider_error": "SECRET"})
            return self.respond(201, row)
        identifier = parts[5] if len(parts) > 5 else ""
        row = rows.get(identifier)
        if parts[-1] == "reach":
            return self.respond(200, {"kind": "relay", "path": parsed.path.replace("reach", "relay")})
        if parts[-1] in ("relay", "exec"):
            self.send_response(101)
            self.send_header("Connection", "Upgrade")
            self.send_header("Upgrade", "drydock-relay" if parts[-1] == "relay" else "drydock-stream")
            self.end_headers()
            if parts[-1] == "exec" and fault.startswith("egress-"):
                result = {"uid": 0, "listed_direct": True, "unlisted_canary": False, "raw_dns": False}
                if fault == "egress-listed":
                    result["listed_direct"] = False
                if fault == "egress-canary":
                    result["unlisted_canary"] = True
                if fault == "egress-dns":
                    result["raw_dns"] = True
                if fault == "egress-root":
                    result["uid"] = 1000
                payload = json.dumps(result).encode()
                if fault == "egress-oversized":
                    payload += b" " * 4097 + b"trailing data"
                self.connection.sendall(payload)
                self.close_connection = True
                return
            while True:
                data = self.connection.recv(4096)
                if not data:
                    return
                self.connection.sendall(b"x" * len(data) if fault == "reach" else data)
        if parts[-1] == "suspend":
            row["state"] = {"state": "stopped", "cause": "suspended_by_request"}
            emit(row, "paused" if fault == "paused" else "stopped", cause="suspended_by_request")
            if fault == "billing":
                row["state"] = {"state": "running"}
            return self.respond(200, {"token": "resume"})
        if parts[-1] == "resume":
            row["state"] = {"state": "running"}
            emit(row, "resumed")
            emit(row, "running", granted_size=row["granted_size"])
            return self.respond(204)
        if self.command == "DELETE":
            attempt = delete_attempts.get(identifier, 0)
            delete_attempts[identifier] = attempt + 1
            if row and ((fault == "transient-destroy" and attempt == 0) or
                        (fault == "stray-cleanup" and row["label"].endswith("-refused") and attempt == 0) or
                        (fault == "cleanup-failure" and row["label"].endswith("-refused"))):
                return self.respond(503, {"kind": "unavailable", "reason": "transient", "retry_after": None})
            if row is None and fault == "destroy":
                return self.respond(404, {"kind": "not_found", "reason": "gone"})
            if row:
                del rows[identifier]
                emit(row, "gone", cause={"kind": "destroyed_by_request"})
            return self.respond(204)
        if row:
            return self.respond(200, row)
        self.respond(404, {"kind": "not_found", "reason": "absent"})


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True


server = Server(("127.0.0.1", 0), Handler)
with open(sys.argv[1], "w") as address:
    address.write(f"http://127.0.0.1:{server.server_port}")
server.serve_forever()

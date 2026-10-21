"""Independent endpoint fixture. Faults corrupt observable protocol behaviour.

The comparator is loaded from the exact source file audited by auth-audit.py.
No fixture accepts a check name and simply returns a verdict for that check.
"""
import copy
import datetime as dt
import hmac
import http.server
import ipaddress
import json
import socket
from pathlib import Path
import sys
import threading
import urllib.parse

fault = sys.argv[2] if len(sys.argv) > 2 else "none"
rows, events, delete_attempts, inspect_attempts = {}, [], {}, {}
condition = threading.Condition(threading.RLock())
usage_segments, running_since = [], {}
prepared, prepare_calls, quota_calls = {}, 0, 0
providers = {"a": {"name": "a", "module": "memory", "settings": {}, "credential": {"mode": "direct", "credential_reference": "fixture"}}}
readiness = {"a": "ready"}
modules = [{"name": "memory", "version": "fixture"}]
provider_timestamp, inventory_error = None, False
size = {"cpus": 1.0, "memory_bytes": 1024, "disk_bytes": 0}
capabilities = {"material_modes": ["frozen"], "checkout_strategies": ["host_clone"],
                "workspace_root": "/workspace", "suspend_resume": True, "export": True,
                "egress": {"routes": ["none"], "enforcement": "advisory"},
                "fallback_runner": True, "bootstrap": "bake", "usage": True, "quota": True}
if fault.startswith("egress-"):
    capabilities["egress"]["enforcement"] = "enforced"
if fault == "capabilities":
    capabilities["workspace_root"] = "relative"
auth_path = Path(sys.argv[1] + ".auth.py")
auth_path.write_text("import hmac\ndef token_matches(expected, actual):\n    return " +
                     ("expected == actual\n" if fault == "authentication_constant_time" else "hmac.compare_digest(expected, actual)\n"))
auth_namespace = {}
exec(compile(auth_path.read_text(), str(auth_path), "exec"), auth_namespace)
token_matches = auth_namespace["token_matches"]


def now():
    return dt.datetime.now(dt.timezone.utc)


def instant(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def stop_billing(identifier):
    start = running_since.pop(identifier, None)
    if start is not None and rows[identifier].get("granted_size"):
        usage_segments.append((copy.deepcopy(rows[identifier]["granted_size"]), start, now()))


def emit(row, kind, **fields):
    with condition:
        if (fault == "running_event" and kind == "running" and not fields.get("resuming")) or (fault == "created_event" and kind == "created"):
            return
        if fault == "resumed_event" and fields.pop("resuming", False):
            return
        event = {"cursor": str(len(events) + 1), "id": row["id"], "provider": row["provider"],
                 "label": row["label"], "timestamp": provider_timestamp or now().isoformat(),
                 "timestamp_source": "provider" if provider_timestamp else "adaptor", "event": {"kind": kind, **fields}}
        if fault == "timestamp":
            event.pop("timestamp_source")
        if fault == "time-range":
            event["timestamp"] = "2026-99-99T00:00:00Z"
        if fault == "poll_timestamp":
            event["timestamp_source"] = "adaptor"
        if fault in ("size", "running_state") and kind == "running":
            event["event"]["granted_size"] = {**size, "cpus": 99}
        if kind == "gone":
            cause = fields["cause"]["kind"]
            if fault in ("loss", "typed_loss") or fault == "loss_" + cause:
                event["event"]["cause"] = {"kind": "not-a-cause"}
            if cause == "missing_on_list":
                event["timestamp_source"] = "adaptor"
        events.append({"type": "event", "event": event})
        condition.notify_all()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def log_message(self, *_):
        pass

    def respond(self, status, value=None, retry=None):
        if fault == "booting" and self.command == "POST" and self.path.endswith("/environments") and isinstance(value, dict) and "id" in value:
            value = {**value, "granted_size": None, "state": {"state": "unknown", "reason": "provider_api_error"}}
        if fault == "provision" and self.command == "POST" and self.path.endswith("/environments") and isinstance(value, dict) and "id" in value:
            value = {**value, "label": "wrong-label"}
        if fault in ("explicit_nulls", "environment_nulls") and isinstance(value, dict) and value.get("id", "").startswith("null-"):
            value = {key: val for key, val in value.items() if val is not None}
        body = b"" if status == 204 else json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if retry is not None:
            self.send_header("Retry-After", str(retry))
        self.end_headers()
        self.wfile.write(body)

    def refused(self):
        self.respond(422, {"kind": "refused", "reason": "invalid"})

    def do_GET(self): self.route()
    def do_POST(self): self.route()
    def do_DELETE(self): self.route()
    def do_PUT(self): self.route()

    def route(self):
        global modules, provider_timestamp, inventory_error, prepare_calls, quota_calls
        parsed = urllib.parse.urlsplit(self.path)
        parts = parsed.path.split("/")
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"null")
        if fault not in ("auth", "authentication") and not token_matches("Bearer fixture-token", self.headers.get("Authorization", "")):
            return self.respond(401, {"kind": "refused", "reason": "unauthorized"})
        provider = parts[3] if len(parts) > 3 else "a"
        if parsed.path == "/v1/hello":
            return self.respond(200, {"protocol_version": "wrong" if fault == "hello" else "5", "host_version": "fixture", "modules": modules,
                "providers": [{"provider": name, "module": config["module"], "readiness": {"status": readiness.get(name, "ready"), **({"reason": "missing"} if readiness.get(name) == "missing_credential" else {})},
                               "capabilities": capabilities, "rate_limits": []} for name, config in providers.items()]})
        if parsed.path == "/v1/config":
            if any(module["entrypoint"] != "reference" for module in body["modules"]):
                if fault == "configuration_atomic":
                    modules = []
                return self.refused()
            if fault == "host_configuration" and any(config["name"].startswith("error-") for config in body["providers"]):
                return self.refused()
            if any(config["name"] in providers and any(row["provider"] == config["name"] for row in rows.values()) and config["settings"] != providers[config["name"]]["settings"] for config in body["providers"]):
                return self.refused()
            modules = [{"name": module["name"], "version": "fixture"} for module in body["modules"]]
            for config in body["providers"]:
                providers[config["name"]] = config
                readiness.setdefault(config["name"], "missing_credential")
            return self.respond(204)
        if parts[-1] == "credential":
            if not isinstance(body.get("value"), str) or not body["value"]: return self.refused()
            readiness[provider] = "ready"
            if fault == "credential_preserves_inventory":
                rows.clear()
            return self.respond(204)
        if parsed.path == "/v1/events":
            since = urllib.parse.parse_qs(parsed.query).get("since", [None])[0]
            if fault == "resume_stream" and since and since.isdigit() and int(since) > 0 and events[int(since)-1]["event"]["event"]["kind"] == "running":
                return self.respond(503, {"kind": "unavailable", "reason": "stream unavailable", "retry_after": None})
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Connection", "close")
            self.end_headers()
            with condition:
                if since is None or not since.isdigit():
                    inventory = list(rows.values())
                    if fault == "host_provider_isolation": inventory = [row for row in inventory if row["provider"] == "a"]
                    record = {"type": "snapshot", "cursor": str(len(events)), "environments": inventory}
                    if (fault in ("gap", "gap_snapshot") and since is not None) or (fault == "initial_snapshot" and since is None):
                        record["type"] = "unmarked"
                    self.wfile.write(json.dumps(record).encode() + b"\n")
                    self.wfile.flush()
                    index = len(events)
                else:
                    index = max(0, int(since) - (1 if fault == "cursor_resume" else 0))
            try:
                while True:
                    with condition:
                        condition.wait_for(lambda: len(events) > index)
                        batch = copy.deepcopy(events[index:]); index = len(events)
                    for record in batch:
                        self.wfile.write(json.dumps(record).encode() + b"\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return
        if provider not in providers:
            return self.respond(404, {"kind": "not_found", "reason": "unknown provider"})
        error = providers[provider]["settings"].get("fault")
        if error and parts[-1] == "environments":
            error = copy.deepcopy(error)
            error["reason"] = f"provider {provider} operation list: {error['reason']}"
            if error["kind"] == "credential_rejected":
                readiness[provider] = "missing_credential"
            status = {"refused":422,"unavailable":503,"rate_limited":429,"quota_exhausted":402,"credential_rejected":502,"internal":500,"not_found":404,"method_not_allowed":405}[error["kind"]]
            if fault == "error_" + error["kind"]:
                error["kind"] = "invalid-error"
            return self.respond(status, error, retry=error.get("retry_after"))
        if len(parts) == 5 and parts[-1] == "prepare":
            prepare_calls += 1
            key = (provider, body["image_digest"], body["tools_digest"])
            prepared.setdefault(key, {"provider":provider,"id":str(len(prepared)+1),"image_digest":body["image_digest"],"tools_digest":body["tools_digest"]})
            value = dict(prepared[key])
            if fault == "prepare": value["id"] = str(prepare_calls)
            return self.respond(200, value)
        if len(parts) == 5 and parts[-1] == "quota":
            quota_calls += 1
            value = {"credits_remaining": float("inf") if fault in ("credits", "quota_before") or (fault == "quota_after" and quota_calls >= 3) else None,
                     "credit_unit": None, "concurrency_in_use": sum(row["state"]["state"] == "running" for row in rows.values()), "concurrency_limit": None}
            if fault in ("null", "quota_nulls"): value.pop("credit_unit")
            return self.respond(200, value)
        if len(parts) == 5 and parts[-1] == "usage":
            period = {key: value[0] for key, value in urllib.parse.parse_qs(parsed.query).items()}
            invalid = not period or period.get("start") == "bad" or period.get("start", "") > period.get("end", "")
            index = 0 if period.get("start") == "bad" else 1
            if invalid and fault != "semantic_period_" + str(index): return self.refused()
            if invalid: return self.respond(200, {"period":period,"environment_hours":[]})
            start, end = instant(period["start"]), instant(period["end"])
            segments = usage_segments + [(rows[identifier]["granted_size"], began, now()) for identifier, began in running_since.items() if identifier in rows]
            hours = []
            for granted, began, ended in segments:
                elapsed = max(0., (min(end, ended) - max(start, began)).total_seconds()) / 3600
                if elapsed and granted: hours.append({"size":granted,"hours":elapsed})
            if fault in ("usage",): hours = [{"size":size,"hours":-1}]
            if fault == "billing_running": hours = []
            if fault in ("billing_suspended", "billing_paused_by_provider", "billing_guest_halted"):
                cpus = {"billing_suspended":1.,"billing_paused_by_provider":2.,"billing_guest_halted":3.}[fault]
                hours.append({"size":{**size,"cpus":cpus},"hours":1.})
            return self.respond(200, {"period":period,"environment_hours":hours})
        if parts[-1] == "environments":
            if self.command == "GET":
                if inventory_error:
                    return self.respond(503, {"kind":"unavailable","reason":"inventory unavailable","retry_after":None})
                value = copy.deepcopy([row for row in rows.values() if row["provider"] == provider])
                if fault in ("label", "list_readoption"):
                    for row in value: row["label"] = None
                if fault == "host_lifecycle_sequence":
                    for row in value:
                        if row["label"] and "-sequence-" in row["label"]: row["state"] = {"state":"unknown","reason":"provider_api_error"}
                return self.respond(200, value)
            if body["prepared"]["provider"] != provider and fault not in ("stray-cleanup", "cleanup-failure", "typed_refusal"):
                if fault == "cleanup":
                    row = {"id":provider+"-stray-"+body["label"],"label":body["label"],"provider":provider,"state":{"state":"running"},"granted_size":size,"egress":"advisory"}
                    rows[row["id"]] = row
                return self.refused()
            if fault == "poll_provision" and body["label"].endswith("-poll"):
                return self.respond(503, {"kind":"unavailable","reason":"fixture create unavailable","retry_after":None})
            for destination in body.get("egress", {}).get("direct", []):
                index = None
                if destination["kind"] == "cidr":
                    try: ipaddress.ip_network(destination["cidr"])
                    except ValueError: index = 0
                elif " " in destination["host"]: index = 1
                elif destination["port"] == 0: index = 2
                if index is not None and fault != "semantic_destination_" + str(index): return self.refused()
            for field, value in body["size"].items():
                invalid = not isinstance(value, (int, float)) or value < 0 or (field == "cpus" and value == 0) or (field != "cpus" and (not isinstance(value, int) or value > 2**64-1))
                case_values = {"cpus":[-1,0,None,"NaN"],"memory_bytes":[-1,1.5,1e20],"disk_bytes":[-1,1.5]}
                if invalid and fault not in ("semantic", f"semantic_{field}_{case_values[field].index(value)}"):
                    return self.refused()
            for row in list(rows.values()):
                if row["label"] == body["label"] and row["provider"] == provider and fault != "idempotent":
                    if fault == "partial": return self.respond(500, {"kind":"internal","reason":"SECRET","provider_error":"SECRET"})
                    return self.respond(201 if fault == "concurrent_label" else 200, row)
            row = {"id":str(len(events)+1),"label":body["label"],"provider":provider,"state":{"state":"running"},"granted_size":body["size"],"egress":"enforced" if fault.startswith("egress-") else "advisory"}
            rows[row["id"]] = row; running_since[row["id"]] = now()
            emit(row, "created")
            if fault == "slow": threading.Timer(1.5, lambda: emit(row,"running",granted_size=row["granted_size"])).start()
            else: emit(row,"running",granted_size=row["granted_size"])
            if fault == "partial": return self.respond(500,{"kind":"internal","reason":"SECRET","provider_error":"SECRET"})
            return self.respond(201, row)
        identifier = parts[5] if len(parts) > 5 else ""
        row = rows.get(identifier)
        if not row and self.command != "DELETE":
            return self.respond(200 if fault == "error_not_found_route" else 404, {"kind":"not_found","reason":"absent"})
        if parts[-1] == "reach":
            return self.respond(200, {"kind":"relay","path":parsed.path.replace("reach","relay")})
        if parts[-1] == "export":
            return self.respond(200,{"reference":"" if fault == "host_optional_operations" else "memory://fixture/"+identifier})
        if parts[-1] in ("relay", "exec"):
            expected = "drydock-relay" if parts[-1] == "relay" else "drydock-stream"
            if self.headers.get("Upgrade") != expected or "upgrade" not in self.headers.get("Connection", "").lower(): return self.refused()
            self.send_response(101)
            self.send_header("Connection", "Upgrade")
            self.send_header("Upgrade", "drydock-relay" if parts[-1] == "relay" else "drydock-stream")
            self.end_headers()
            if parts[-1] == "exec" and body["command"][0] == "drydock-fixture":
                command = body["command"]; action = command[1]; target = command[2] if len(command)>2 else identifier
                result = None
                if action == "null_environment":
                    result = {"id":"null-"+identifier,"label":None,"provider":provider,"state":{"state":"unknown","reason":"provider_api_error"},"granted_size":None,"egress":"advisory"}
                    rows[result["id"]] = result
                elif action == "forget":
                    victim = rows[target]; stop_billing(target); del rows[target]; emit(victim,"gone",cause={"kind":"missing_on_list"})
                elif action in ("state", "pause"):
                    stop_billing(target)
                    state = json.loads(command[3]) if action == "state" else {"state":"stopped","cause":"paused_by_provider"}
                    rows[target]["state"] = state
                    if state["state"] == "running": running_since[target]=now(); emit(rows[target],"resumed"); emit(rows[target],"running",granted_size=rows[target]["granted_size"])
                    elif state["state"] == "gone": emit(rows[target],"gone",cause=state["cause"])
                    else: emit(rows[target], "paused" if state["cause"] == "paused_by_provider" else "stopped", cause=state["cause"])
                elif action == "timestamp": provider_timestamp = target
                elif action == "inventory_error":
                    inventory_error = target == "true"
                    if inventory_error and fault == "poll_failed_list":
                        for victim in list(rows.values()): emit(victim,"gone",cause={"kind":"missing_on_list"})
                self.connection.sendall(json.dumps(result).encode()); self.close_connection=True; return
            if parts[-1] == "exec" and body["command"][0] == "echo":
                self.connection.sendall((" ".join(body["command"][1:])+"\n").encode()); self.close_connection=True; return
            if parts[-1] == "exec" and fault.startswith("egress-") and body["command"][0] == "probe":
                result={"uid":0,"listed_direct":True,"unlisted_canary":False,"raw_dns":False}
                if fault=="egress-listed":result["listed_direct"]=False
                if fault=="egress-canary":result["unlisted_canary"]=True
                if fault=="egress-dns":result["raw_dns"]=True
                if fault=="egress-root":result["uid"]=1000
                payload=json.dumps(result).encode()
                if fault=="egress-oversized":payload+=b" "*4097+b"trailing data"
                self.connection.sendall(payload);self.close_connection=True;return
            count=0
            while True:
                data=self.connection.recv(4096)
                if not data:self.close_connection=True;return
                count+=len(data)
                broken=fault in ("reach","reach_byte_stream") or (fault=="host_stream_upgrades" and count>65536)
                self.connection.sendall(b"x"*len(data) if broken else data)
        if parts[-1] == "suspend":
            stop_billing(identifier)
            row["state"]={"state":"stopped","cause":"suspended_by_request"}
            emit(row,"paused" if fault=="paused" else "stopped",cause="guest_halted" if fault=="stopped_event" else "suspended_by_request")
            if fault in ("billing","stopped_billing"):row["state"]={"state":"running"}
            return self.respond(200,{"token":"" if fault=="suspend" else "resume"})
        if parts[-1] == "resume":
            if fault != "resume": row["state"]={"state":"running"}; running_since.setdefault(identifier,now())
            emit(row,"resumed",resuming=True);emit(row,"running",granted_size=row["granted_size"],resuming=True)
            return self.respond(204)
        if self.command == "DELETE":
            attempt=delete_attempts.get(identifier,0);delete_attempts[identifier]=attempt+1
            if row and ((fault=="transient-destroy" and attempt==0) or (fault=="stray-cleanup" and (row["label"] or "").endswith("-refused") and attempt==0) or (fault in ("cleanup-failure","cleanup") and (row["label"] or "").endswith("-refused"))):
                return self.respond(503,{"kind":"unavailable","reason":"transient","retry_after":None})
            if row is None and fault in ("destroy","destroy_absent"):return self.respond(404,{"kind":"not_found","reason":"gone"})
            if row:stop_billing(identifier);del rows[identifier];emit(row,"gone",cause={"kind":"destroyed_by_request"})
            return self.respond(204)
        count=inspect_attempts.get(identifier,0);inspect_attempts[identifier]=count+1
        if fault=="inspect" and count==0:return self.respond(503,{"kind":"unavailable","reason":"inspect not ready","retry_after":None})
        return self.respond(200,row)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads=True

server=Server(("127.0.0.1",0),Handler)
with open(sys.argv[1],"w") as address:address.write(f"http://127.0.0.1:{server.server_port}")
server.serve_forever()

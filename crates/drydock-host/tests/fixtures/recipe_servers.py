"""Real disposable TCP, WebSocket and OpenSSH guest-boundary fixtures."""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time


def exact(channel, count):
    result=b""
    while len(result)<count:
        value=channel.recv(count-len(result))
        if not value: raise EOFError()
        result+=value
    return result


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        token=b""
        while not token.endswith(b"\n") and len(token)<1024:token+=exact(self.request,1)
        if token!=b"fixture-token\n":return
        while True:
            value=self.request.recv(4096)
            if not value:return
            self.request.sendall(value)


class WS(socketserver.BaseRequestHandler):
    def handle(self):
        headers=b""
        while not headers.endswith(b"\r\n\r\n") and len(headers)<8192:headers+=exact(self.request,1)
        fields=dict(line.split(b": ",1) for line in headers.split(b"\r\n")[1:] if b": " in line)
        if fields.get(b"Authorization")!=b"Bearer fixture-token":
            self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");return
        accept=base64.b64encode(hashlib.sha1(fields[b"Sec-WebSocket-Key"]+b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
        self.request.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: "+accept+b"\r\n\r\n")
        kind,length=exact(self.request,2);mask=exact(self.request,4);payload=exact(self.request,length&127)
        payload=bytes(value^mask[i%4] for i,value in enumerate(payload))
        self.request.sendall(bytes([kind,len(payload)])+payload)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True


with tempfile.TemporaryDirectory(prefix="dd-recipes-") as directory:
    directory=Path(directory)
    for name in ("host","identity","wrong"):
        subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",str(directory/name)],check=True)
    socket_=socket.socket();socket_.bind(("127.0.0.1",0));port=socket_.getsockname()[1];socket_.close()
    config=directory/"sshd_config"
    user=pwd.getpwuid(os.geteuid()).pw_name
    config.write_text(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {directory/'host'}\nAuthorizedKeysFile {directory/'identity.pub'}\nPidFile {directory/'pid'}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin yes\nAllowUsers {user}\n")
    sshd=subprocess.Popen([os.environ.get("DRYDOCK_TEST_SSHD","/usr/sbin/sshd"),"-D","-e","-f",str(config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    servers=[]
    try:
        deadline=time.monotonic()+5
        while True:
            if sshd.poll() is not None:raise RuntimeError("sshd exited")
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=.1):break
            except OSError:
                if time.monotonic()>deadline:raise
                time.sleep(.01)
        manifest={"ssh":{"kind":"ssh","endpoint":f"127.0.0.1:{port}","user":user,"host_key":(directory/'host.pub').read_text().strip()},
                  "identity":str(directory/'identity'),"wrong_key":(directory/'wrong.pub').read_text().strip()}
        for name,handler in (("tcp",TCP),("ws",WS)):
            server=Server(("127.0.0.1",0),handler);servers.append(server)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            manifest[name]={"kind":"dial","url":f"{name}://127.0.0.1:{server.server_address[1]}/","token":"fixture-token","expires_at":"2099-01-01T00:00:00Z"}
        Path(sys.argv[1]).write_text(json.dumps(manifest))
        sys.stdin.read()
    finally:
        for server in servers:server.shutdown();server.server_close()
        sshd.terminate();sshd.wait(timeout=5)

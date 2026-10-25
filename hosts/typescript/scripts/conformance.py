#!/usr/bin/env python3
"""Run the existing drydock conformance CLI through drydockd and the TS endpoint."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
HOST = ROOT / 'hosts/typescript/dist/main.js'

def wait_socket(path, process):
    deadline = time.monotonic() + 15
    while not path.exists():
        if process.poll() is not None:
            raise RuntimeError('companion exited before binding')
        if time.monotonic() > deadline:
            raise RuntimeError('companion startup timeout')
        time.sleep(.02)

def main():
    subprocess.run(['cargo', 'build', '--locked', '-p', 'drydock', '--bins'], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='drydock-typescript-conformance-') as temp:
        directory = Path(temp)
        os.chmod(directory, 0o700)
        config = directory / 'drydock.toml'
        config.write_text('[provider.reference]\nmodule="reference"\ncredential={env="DRYDOCK_TEST_TOKEN"}\n[provider.reference.settings]\nfixture=true\n')
        options = directory / 'options.json'
        options.write_text(json.dumps({'request': {'label': 'ts-conformance', 'prepared': {'provider': 'reference', 'id': 'placeholder', 'image_digest': 'image', 'tools_digest': 'tools', 'platform': {'os': 'linux', 'architecture': 'amd64'}}, 'size': {'cpus': 1, 'memory_bytes': 1024, 'disk_bytes': 0}, 'egress': {'mode': 'deny_all', 'direct': []}}, 'echo_relay': True, 'scenarios': ['prepare', 'lifecycle', 'observation', 'semantics', 'reach', 'refusal', 'destroy', 'metering']}))
        host_socket, daemon_socket = directory / 'host.sock', directory / 'daemon.sock'
        host = subprocess.Popen(['node', str(HOST), '--unix', str(host_socket)])
        daemon = None
        try:
            wait_socket(host_socket, host)
            daemon = subprocess.Popen([str(ROOT / 'target/debug/drydockd'), '--config', str(config), '--socket', str(daemon_socket), '--external-host', str(host_socket)], env={**os.environ, 'DRYDOCK_TEST_TOKEN': 'reference-test-only'})
            wait_socket(daemon_socket, daemon)
            subprocess.run([str(ROOT / 'target/debug/drydock'), '--config', str(config), '--socket', str(daemon_socket), 'conformance', '--provider', 'reference', '--options', str(options)], cwd=ROOT, check=True)
        finally:
            for process in [daemon, host]:
                if process is not None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()

if __name__ == '__main__':
    main()

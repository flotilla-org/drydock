"""The real guest probe runs in CI; socket doubles only cover kernel error paths."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch, MagicMock

PATH = Path(__file__).with_name("egress-probe.py")
spec = importlib.util.spec_from_file_location("probe", PATH)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeContract(unittest.TestCase):
    # A deny-all kernel can reject UDP connect before send. That is blocked DNS,
    # and must not crash the probe before it emits its result document.
    def test_unreachable_dns_connect_is_blocked(self):
        channel = MagicMock()
        channel.__enter__.return_value = channel
        channel.connect.side_effect = OSError("network unreachable")
        with patch.object(probe.socket, "socket", return_value=channel):
            self.assertFalse(probe.dns("192.0.2.1"))

    # Execute the actual script against real loopback TCP sockets. This validates
    # stdout/EOF and UID as well as listed/unlisted connectivity; no fake JSON.
    def test_script_with_real_sockets(self):
        with socket.socket() as listed, socket.socket() as closed:
            listed.bind(("127.0.0.1", 0))
            listed.listen()
            closed.bind(("127.0.0.1", 0))
            closed_port = closed.getsockname()[1]
            closed.close()
            result = subprocess.run([sys.executable, str(PATH), "127.0.0.1", str(listed.getsockname()[1]),
                                     "127.0.0.1", str(closed_port), "127.0.0.2"], capture_output=True, timeout=10, check=True)
            self.assertEqual(json.loads(result.stdout), {"uid": os.geteuid(), "listed_direct": True,
                                                        "unlisted_canary": False, "raw_dns": False})
            self.assertEqual(result.stderr, b"")

    # Deny-all does not resolve or connect a nonexistent listed destination.
    def test_deny_all_without_listed_destination(self):
        result = subprocess.run([sys.executable, str(PATH), "unused", "0", "127.0.0.1", "1", "127.0.0.2"],
            env={**os.environ, "DRYDOCK_PROBE_DENY_ALL":"1"}, capture_output=True, timeout=10, check=True)
        self.assertIsNone(json.loads(result.stdout)["listed_direct"])


if __name__ == "__main__":
    unittest.main()

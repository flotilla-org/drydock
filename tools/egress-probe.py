#!/usr/bin/env python3
"""Run inside the guest as root, via the provider's exec route.

Arguments: listed-IP listed-port canary-IP canary-port DNS-server-IP.
All addresses must be IP literals. Use externally verified, reachable canaries;
a dead service cannot demonstrate isolation. Socket calls bypass proxy settings.
"""
import ipaddress
import json
import os
import secrets
import socket
import struct
import sys


def tcp(address, port):
    try:
        with socket.create_connection((str(ipaddress.ip_address(address)), int(port)), timeout=3):
            return True
    except OSError:
        return False


def dns(address):
    target = ipaddress.ip_address(address)
    family = socket.AF_INET6 if target.version == 6 else socket.AF_INET
    identifier = secrets.token_bytes(2)
    # A raw UDP query, independent of /etc/resolv.conf or guest DNS redirection.
    packet = identifier + struct.pack("!5H", 0x100, 1, 0, 0, 0) + b"\x07example\x03com\0" + struct.pack("!2H", 1, 1)
    with socket.socket(family, socket.SOCK_DGRAM) as channel:
        channel.settimeout(3)
        channel.connect((str(target), 53))
        try:
            channel.send(packet)
            response = channel.recv(4096)
            return response[:2] == identifier
        except OSError:
            return False


if __name__ == "__main__":
    listed, listed_port, canary, canary_port, resolver = sys.argv[1:]
    print(json.dumps({"uid": os.geteuid(), "listed_direct": tcp(listed, listed_port),
                      "unlisted_canary": tcp(canary, canary_port), "raw_dns": dns(resolver)}))

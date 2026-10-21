#!/usr/bin/env bash
# Kernel-boundary test in disposable namespaces. No host network rules change.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v nft >/dev/null
command -v ip >/dev/null
executable=$(RUSTC_WORKSPACE_WRAPPER= cargo test -p drydock-agent --lib --no-run --message-format=json |
    python3 -c 'import json,sys; print(next(x["executable"] for line in sys.stdin if (x := json.loads(line)).get("executable") and x["target"]["name"] == "drydock_agent"))')
# Private mount prevents the test CA and nft entrypoint from touching tools.
sudo unshare --net --mount --fork bash -euc '
    mount --make-rprivate /
    mount -t tmpfs tmpfs /opt
    mkdir -p /opt/drydock/bin
    ln -s "$(command -v nft)" /opt/drydock/bin/nft
    ip link set lo up
    ip route add default dev lo
    export DRYDOCK_EGRESS_NETNS=1
    timeout 60 "$1" egress::tests::kernel_redirect --exact --ignored --nocapture
' bash "$executable"

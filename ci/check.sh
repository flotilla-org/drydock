#!/bin/sh
# Requires Rust with rustfmt/clippy and openssh-client + openssh-server.
# DRYDOCK_TEST_SSHD can select an sshd outside /usr/sbin/sshd.
set -eu
cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

if [ -f hosts/typescript/package.json ]; then
    : "${COREPACK_HOME:=$(mktemp -d)}"
    export COREPACK_HOME
    corepack pnpm --dir hosts/typescript install --frozen-lockfile
    corepack pnpm --dir hosts/typescript check
    corepack pnpm --dir hosts/typescript pack:companion
fi

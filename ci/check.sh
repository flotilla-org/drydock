#!/bin/sh
# Requires Rust with rustfmt/clippy and openssh-client + openssh-server.
# DRYDOCK_TEST_SSHD can select an sshd outside /usr/sbin/sshd.
set -eu
cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

# Node >=24.18.0 and corepack; use a private COREPACK_HOME (no global shims).
: "${COREPACK_HOME:?Set COREPACK_HOME to a private writable directory}"
(cd hosts/typescript && corepack pnpm install --frozen-lockfile && corepack pnpm check && corepack pnpm conformance)

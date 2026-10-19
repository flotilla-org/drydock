#!/bin/sh
# Requires Rust with rustfmt/clippy and openssh-client + openssh-server.
# DRYDOCK_TEST_SSHD can select an sshd outside /usr/sbin/sshd.
set -eu
cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

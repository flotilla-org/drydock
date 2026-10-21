# Debian bookworm's glibc 2.36 is compatible with Ubuntu 24.04's glibc 2.39.
# BuildKit selects the target architecture (native workers or QEMU/binfmt).
FROM rust:1.99.0-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p drydock-agent --bins --example tools_probe

FROM scratch AS probe
COPY --from=build /src/target/release/examples/tools_probe /tools_probe

# No OS, init, entrypoint or command: this image is a files-only tools layer.
FROM scratch
COPY --from=build /src/target/release/drydock-agent /opt/drydock/drydock-agent

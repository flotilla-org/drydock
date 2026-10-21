# Vessel tools image

The tools image is drydock's agent, built for linux/amd64 and linux/arm64 as one
OCI index. Its final stage is scratch: only `/opt/drydock/drydock-agent`, with no
base OS, entrypoint, command, init, cleat or Flotilla CLI. Debian bookworm glibc
2.36 builds run on Ubuntu 24.04 (glibc 2.39). Static builds are deferred.

## Build and release

With Docker Buildx and native workers or QEMU/binfmt installed:

```sh
python3 ci/tools_image.py --revision HEAD
# target/tools-image/tools.oci.tar is a local multi-arch OCI archive.
```

Production images are produced by CI from a merged revision. The script archives
that exact revision rather than sending the working tree to the builder. Publish
refuses revisions not reachable from the fetched origin/main:

```sh
python3 ci/tools_image.py --revision "$GITHUB_SHA" --publish \
  --registry "${DRYDOCK_TOOLS_REGISTRY:-ghcr.io/flotilla-org}"
python3 ci/test_tools_runtime.py "$(cat target/tools-image/tools-image.txt)"
DRYDOCK_TOOLS_IMAGE="$(cat target/tools-image/tools-image.txt)" \
  cargo build --locked --release -p drydock -p drydock-host
```

`--registry` is configuration, with default `ghcr.io/flotilla-org`. Publishing
uses Buildx's push-by-digest output; no mutable tag is used for tools selection.
`tools-image.txt` contains the canonical registry/name@sha256 index reference;
`revision.txt` records the source. Archive these beside the resulting drydock
binaries. The operator must configure registry visibility to public. CI must
verify an anonymous pull with an empty Docker credential configuration before
acceptance; the image's existence does not imply public visibility.

The first build creates the tools image. The second builds drydock with that
image reference compiled in through `DRYDOCK_TOOLS_IMAGE`. There is no digest
cycle: the agent does not embed its own image reference. Unstamped development
builds refuse prepare/launch rather than inventing a pin. Changing a runtime
variable cannot change the compiled selection. The workflow diff is supplied in
the implementing PR description for the operator to land.

## Module prepare and start contract

`PrepareRequest.tools_digest` is this drydock build's immutable tools image
reference, including the registry location and index digest. Resolve the index
for the guest architecture. The prepared form is the selected base plus the
tools layer, built at the provider when possible, otherwise by appending its
layer. Record the prepared form at the provider. Leave the base's entrypoint,
command and init unchanged. On `BootstrapRoute::Upload`, deliver the identical
files under `/opt/drydock` instead of baking them.

Each module decides its key, including both image and tools digests and any
provider prepare-time constraints. Daytona adds size (#44). This supersedes the
older ADR 0070 Bootstrap wording that the pair alone keys every prepared form.
Callers always prepare then provision; refuse a provision that does not match.

Start `/opt/drydock/drydock-agent` with **no arguments** through the provider's
own alongside-process mechanism. It listens on `/run/drydock/agent.sock`, dials
`/run/drydock/host.sock`, never runs as PID 1, and is ready only after hello.
Restart it after a crash and after each start/resume. Do not install anything in
the base's init. Keep `/opt/drydock` writable by the agent's identity: upgrade
creates `.upgrade`, `.prev`, and `.probation` beside the binary. Keep the previous
binary for rollback. The agent's fingerprint is the hash of the actual executable,
read through hello, distinct from the multi-arch tools index digest.

## Evidence

Container-free checks:

```sh
python3 -m unittest discover -s ci -p 'test_tools_*.py'
cargo test --workspace --locked
```

Run the CLI tests again with a test-only valid `DRYDOCK_TOOLS_IMAGE` at compile
time to cover the stamped-build prepare/launch path. The default run covers the
unstamped refusal. A fixture reference is test data, never a release default.

`conformance::vessel_tools` runs a supplied module guest probe via exec. Its
argv receives `initial`, `crash`, and `resumed`; it must emit `ToolsEvidence` JSON
including layer file inventory, base/prepared entrypoint and command, actual
agent argv/PID/process incarnation, and the fingerprint read from hello. Crash
must kill the agent and await provider restart before returning. The suite calls
suspend/resume between the latter samples. Memory-preserving resume can keep the
process but must return a new hello. Callers own provision/destruction. Unsupported
or malformed probes fail; there is no silent success for a missing probe.

The reference-host test runs these checks with `drydock-fixture tools`, an
explicit **model**, because reference has no real guest. Real binary upgrade,
rollback and restart tests use an `opt/drydock` install layout. Neither substitutes
for the operator's stock-Ubuntu OCI test: `ci/test_tools_runtime.py` checks both
architectures, the tools filesystem, preservation of base image config, a
non-PID-1 no-argument agent, and its actual hello fingerprint. A separately built
probe is copied into the test container only, outside the prepared form.

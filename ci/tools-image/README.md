# Vessel tools image

The tools image is drydock's agent, built for linux/amd64 and linux/arm64 as one
OCI index. Its final stage is scratch: only `/opt/drydock/drydock-agent`, with no
base OS, entrypoint, command, init, cleat or Flotilla CLI. Debian bookworm glibc
2.36 builds run on Ubuntu 24.04 (glibc 2.39). Both build stages receive the exact
Rust version from the revision's `rust-toolchain.toml`; there is no second pin in
the Dockerfile. Static builds are deferred.

## Build and release

Locally, with Python 3.11+ and Docker Buildx (building a foreign architecture needs
native workers or QEMU/binfmt):

```sh
python3 ci/tools_image.py --revision HEAD
# target/tools-image/tools.oci.tar is a local multi-arch OCI archive.
```

Production images are produced by CI from a merged revision. The script archives
that exact revision rather than sending the working tree to the builder. Publish
refuses revisions not reachable from the fetched origin/main.

CI builds each platform on a runner of that architecture (`ubuntu-24.04` and
`ubuntu-24.04-arm`), so nothing is compiled or tested under emulation. Each
publishes its platform image by digest and runs the stock-Ubuntu check on its own
CPU; a final job combines the two into the index:

```sh
# on each native runner
python3 ci/tools_image.py --revision "$GITHUB_SHA" --publish --platform linux/arm64 \
  --registry "${DRYDOCK_TOOLS_REGISTRY:-ghcr.io/flotilla-org}"
python3 ci/test_tools_runtime.py --arch arm64 "$(cat target/tools-image/platform-arm64.txt)"
# then once, with both platform images
python3 ci/tools_image.py --revision "$GITHUB_SHA" --publish \
  --assemble "$AMD64_IMAGE" "$ARM64_IMAGE"
DRYDOCK_TOOLS_IMAGE="$(cat target/tools-image/tools-image.txt)" \
  cargo build --locked --release -p drydock -p drydock-host
```

A platform image (`platform-<arch>.txt`) is only an input to `--assemble`, never
a tools pin. Assembly checks the index lists exactly both platforms and reads its
digest from the registry's bytes.

`--registry` is configuration, with default `ghcr.io/flotilla-org`. Publishing
uses Buildx's push-by-digest output for each platform image; assembly tags the
index `rev-<commit>` while reading its digest back, then creates a
`rev-<commit>-<index-sha256>` retention tag for that same index. Including the index hash also retains earlier images if a
revision is rebuilt against an updated builder image. Never prune these revision tags or their manifests while
any drydock release references them. No mutable tag is used for tools selection.
If tagging fails after the digest push, rerunning the same command is safe:
metadata is emitted only after the retention tag succeeds. With unchanged builder
inputs it reuses the same content-addressed index and tag. If the builder changed,
a new index gets its own retention tag; prior release pins remain retained. An
untagged index from a failed attempt has no emitted release metadata and can be
cleaned up. Retrying does not guarantee byte-identical builds from a mutable
builder image tag.

`tools-image.txt` contains the canonical registry/name@sha256 index reference;
`revision.txt` records the source. Archive these beside the resulting drydock
binaries.

The publish job also copies `/opt/drydock/drydock-agent` out of each platform
image into the release artifact as `drydock-agent-linux-amd64` and
`drydock-agent-linux-arm64`, beside `drydockd`. A host upgrades an older vessel
agent to the build matching the platform in its hello, so it needs one per guest
platform; those are byte-identical to the agents in this release's tools index. The operator must configure registry visibility to public. CI must
verify an anonymous pull with an empty Docker credential configuration before
acceptance; the image's existence does not imply public visibility.

## Checked-in pin and first publication

[`crates/drydock/tools-image.txt`](../../crates/drydock/tools-image.txt) holds the
published registry/name@sha256 reference. Every drydock build reads this file
relative to the crate manifest, including `cargo install` and a Git dependency
built in another workspace. A build-time `DRYDOCK_TOOLS_IMAGE` overrides the pin;
runtime environment cannot replace the compiled selection. The crate includes
the file so consumers need no CI release metadata.

Before the first publish the file contains the explicit sentinel `unpublished`.
Builds still work, but prepare/launch explain that the tools image has not been
published yet: run the operator publish workflow and merge its pin-bump PR, or
compile with an override naming an already published image. Empty/malformed pins
and explicitly empty/malformed overrides fail compilation. They never silently
fall back to a different image.

The pin need not match the host build exactly. It selects the bootstrap agent;
a host connects with `drydock_agent::Client::connect_current`, supplying its
current agent build for the platform the guest's hello reports and a factory for
fresh provider transports. A
fingerprint mismatch at hello triggers push plus re-exec, followed by reconnect
and verification of the new hello. The host pushes configuration only afterwards.
Raw `Client::connect` is for tooling that explicitly manages this upgrade flow;
its generation-specific methods remain gated until fingerprints match.

After each successful publication/acceptance, the proposed workflow opens or
updates a PR changing only the pin. The operator merges that PR; it is never
merged automatically. A pin-only merge is excluded from the publication trigger
to avoid an endless publish/pin-bump loop. Enable GitHub Actions' permission to
create pull requests (or supply `DRYDOCK_PIN_PR_TOKEN`); a suitable injected token
also allows the pin PR to trigger normal PR checks.

**The first GHCR push creates a private package. The anonymous pull check fails
until the operator makes the package public, once.** Then rerun the publication
job to finish acceptance and open the pin PR. Never merge a pin that points to a
private/unverified image. Other registries likewise need public pull visibility.
The full workflow diff remains in the implementing PR description for the
operator to land.

## Module prepare and start contract

`PrepareRequest.tools_digest` is the immutable bootstrap tools reference selected
by this build's checked-in pin (or build-time override), including registry
location and index digest. It may identify an older agent; upgrade it after hello
as described above, rather than refusing the vessel for a fingerprint mismatch. Resolve the index
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

Run the CLI tests again with a test-only published reference in the pin or a
build-time `DRYDOCK_TOOLS_IMAGE` to cover prepare/launch. Before first publication
the default run covers the explicit unpublished refusal. Selection properties
cover pin fallback and override precedence; real-process tests prove hello from
an older pin upgrades automatically. Fixture references are test data, never a
release default.

`conformance::vessel_tools` runs a supplied module guest probe via exec. Its
argv receives a phase (`initial`, `crash`, or `resumed`) and a fresh challenge;
it must perform a new hello exchange and emit `ToolsEvidence` JSON
including layer file inventory, base/prepared entrypoint and command, actual
agent argv/PID/process incarnation, the fingerprint read from hello, and that
invocation's `challenge`. A cached response fails the challenge comparison. The
module's probe is responsible for truthfully measuring the guest, just as it is
for the filesystem/process evidence; echoing a nonce does not authenticate a
dishonest probe. Crash must kill the agent and await provider restart before returning. The suite calls
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

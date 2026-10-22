#!/usr/bin/env python3
"""Build the tools image from an exact revision; optionally publish by digest.

Requires Python 3.11+ and Docker Buildx. CI builds each platform on a runner of
that architecture (--platform), then combines the published platform images into
one index (--assemble). A local build of both platforms needs native workers or
binfmt emulation. The output reference is build metadata for DRYDOCK_TOOLS_IMAGE,
never user launch config.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REGISTRY = "ghcr.io/flotilla-org"
PLATFORMS = ["linux/amd64", "linux/arm64"]


def image_name(registry):
    # ':' in the registry component permits host:port. Buildx validates the
    # actual hostname/port syntax (this lexical check also accepts e.g. a:b).
    if not re.fullmatch(r"[a-z0-9][a-z0-9.:-]*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*", registry):
        raise ValueError("registry must be a lowercase registry[/namespace], without scheme or tag")
    return f"{registry}/drydock-tools"


def digest_reference(name, metadata):
    digest = metadata.get("containerimage.digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("Buildx did not return an immutable sha256 image digest")
    return f"{name}@{digest}"


def platform_image(name, reference):
    # Only immutable images of this repository can enter the published index.
    digest = reference.removeprefix(f"{name}@")
    if digest == reference or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError(f"platform image must be {name}@sha256:<64 hex digits>: {reference}")
    return reference


def platform_file(platform):
    return "platform-" + platform.removeprefix("linux/") + ".txt"


def toolchain_version(context):
    version = tomllib.loads((context / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("tools image requires an exact Rust version in rust-toolchain.toml")
    return version


def build_command(context, name, metadata, archive, publish, version, platforms=PLATFORMS):
    output = (f"type=image,name={name},push=true,push-by-digest=true,name-canonical=true"
              if publish else f"type=oci,dest={archive}")
    return ["docker", "buildx", "build", "--platform", ",".join(platforms),
            "--provenance=false", "--build-arg", f"RUST_VERSION={version}", "--file", str(context / "ci/tools-image/Dockerfile"),
            "--metadata-file", str(metadata), "--output", output, str(context)]


def retain(name, revision, reference):
    # Retention anchor only: drydock still selects the immutable digest.
    subprocess.run(["docker", "buildx", "imagetools", "create", "--tag", f"{name}:rev-{revision}-{reference.rsplit(':', 1)[1]}", reference], check=True)


def assemble(name, revision, references):
    """Combine published platform images into one index, published by digest."""
    images = [platform_image(name, reference) for reference in references]
    if len(images) != len(PLATFORMS) or len(set(images)) != len(images):
        raise ValueError(f"assemble needs one distinct image per platform ({', '.join(PLATFORMS)})")
    # The commit tag names the index while its digest is read back; selection
    # and the retention tag use only that digest.
    staging = f"{name}:rev-{revision}"
    subprocess.run(["docker", "buildx", "imagetools", "create", "--tag", staging, *images], check=True)
    raw = subprocess.check_output(["docker", "buildx", "imagetools", "inspect", "--raw", staging])
    index = json.loads(raw)
    found = sorted(f"{m['platform']['os']}/{m['platform']['architecture']}" for m in index.get("manifests", []))
    if found != sorted(PLATFORMS):
        raise ValueError(f"assembled index has platforms {found}, expected {PLATFORMS}")
    reference = f"{name}@sha256:{hashlib.sha256(raw).hexdigest()}"
    retain(name, revision, reference)
    return reference


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True, help="exact Git revision to archive, never the working tree")
    parser.add_argument("--registry", default=DEFAULT_REGISTRY)
    parser.add_argument("--publish", action="store_true", help="only revisions reachable from origin/main may publish")
    parser.add_argument("--output", type=Path, default=Path("target/tools-image"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--platform", choices=PLATFORMS, help="build one platform image; CI runs one per native runner")
    mode.add_argument("--assemble", nargs="+", metavar="IMAGE", help="combine published platform images (name@sha256) into the tools index")
    args = parser.parse_args()
    if args.assemble and not args.publish:
        parser.error("--assemble combines published images; pass --publish")
    name = image_name(args.registry)
    revision = subprocess.check_output(["git", "rev-parse", "--verify", f"{args.revision}^{{commit}}"], cwd=ROOT, text=True).strip()
    if args.publish:
        try:
            subprocess.run(["git", "merge-base", "--is-ancestor", revision, "origin/main"], cwd=ROOT, check=True)
        except subprocess.CalledProcessError:
            parser.error("publishing requires a merged revision and a fetched origin/main; run git fetch origin main and verify the revision is an ancestor")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    for stale in ["metadata.json", "tools-image.txt", "revision.txt", *map(platform_file, PLATFORMS)]:
        (output / stale).unlink(missing_ok=True)
    if args.assemble:
        reference = assemble(name, revision, args.assemble)
        (output / "tools-image.txt").write_text(reference + "\n")
        (output / "revision.txt").write_text(revision + "\n")
        print(reference)
        return
    platforms = [args.platform] if args.platform else PLATFORMS
    with tempfile.TemporaryDirectory(prefix="drydock-tools-") as tmp:
        context = Path(tmp)
        archive = subprocess.Popen(["git", "archive", revision], cwd=ROOT, stdout=subprocess.PIPE)
        try:
            subprocess.run(["tar", "-x", "-C", str(context)], stdin=archive.stdout, check=True)
        finally:
            archive.stdout.close()
            archive_status = archive.wait()
        if archive_status != 0:
            raise RuntimeError("git archive failed")
        metadata = output / "metadata.json"
        # Never consume stale metadata after an unsuccessful builder invocation.
        metadata.unlink(missing_ok=True)
        subprocess.run(build_command(context, name, metadata, output / "tools.oci.tar", args.publish, toolchain_version(context), platforms), check=True)
        reference = digest_reference(name, json.loads(metadata.read_text()))
        if args.platform:
            # One platform image is an input to --assemble, never a tools pin.
            (output / platform_file(args.platform)).write_text(reference + "\n")
        else:
            if args.publish:
                retain(name, revision, reference)
            (output / "tools-image.txt").write_text(reference + "\n")
        (output / "revision.txt").write_text(revision + "\n")
        print(reference)


if __name__ == "__main__":
    main()

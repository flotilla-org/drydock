#!/usr/bin/env python3
"""Build the tools index from an exact revision; optionally publish by digest.

Requires Docker Buildx with amd64/arm64 workers or binfmt emulation. The output
reference is build metadata for DRYDOCK_TOOLS_IMAGE, never user launch config.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REGISTRY = "ghcr.io/flotilla-org"


def image_name(registry):
    if not re.fullmatch(r"[a-z0-9][a-z0-9.:-]*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*", registry):
        raise ValueError("registry must be a lowercase registry[/namespace], without scheme or tag")
    return f"{registry}/drydock-tools"


def digest_reference(name, metadata):
    digest = metadata.get("containerimage.digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("Buildx did not return an immutable sha256 index digest")
    return f"{name}@{digest}"


def build_command(context, name, metadata, archive, publish):
    output = (f"type=image,name={name},push=true,push-by-digest=true,name-canonical=true"
              if publish else f"type=oci,dest={archive}")
    return ["docker", "buildx", "build", "--platform", "linux/amd64,linux/arm64",
            "--provenance=false", "--file", str(context / "ci/tools-image/Dockerfile"),
            "--metadata-file", str(metadata), "--output", output, str(context)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True, help="exact Git revision to archive, never the working tree")
    parser.add_argument("--registry", default=DEFAULT_REGISTRY)
    parser.add_argument("--publish", action="store_true", help="only revisions reachable from origin/main may publish")
    parser.add_argument("--output", type=Path, default=Path("target/tools-image"))
    args = parser.parse_args()
    name = image_name(args.registry)
    revision = subprocess.check_output(["git", "rev-parse", "--verify", f"{args.revision}^{{commit}}"], cwd=ROOT, text=True).strip()
    if args.publish:
        subprocess.run(["git", "merge-base", "--is-ancestor", revision, "origin/main"], cwd=ROOT, check=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    for stale in ["metadata.json", "tools-image.txt", "revision.txt"]:
        (output / stale).unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="drydock-tools-") as tmp:
        context = Path(tmp)
        archive = subprocess.Popen(["git", "archive", revision], cwd=ROOT, stdout=subprocess.PIPE)
        try:
            subprocess.run(["tar", "-x", "-C", str(context)], stdin=archive.stdout, check=True)
        finally:
            archive.stdout.close()
        if archive.wait() != 0:
            raise RuntimeError("git archive failed")
        metadata = output / "metadata.json"
        # Never consume stale metadata after an unsuccessful builder invocation.
        metadata.unlink(missing_ok=True)
        subprocess.run(build_command(context, name, metadata, output / "tools.oci.tar", args.publish), check=True)
        reference = digest_reference(name, json.loads(metadata.read_text()))
        (output / "tools-image.txt").write_text(reference + "\n")
        (output / "revision.txt").write_text(revision + "\n")
        print(reference)


if __name__ == "__main__":
    main()

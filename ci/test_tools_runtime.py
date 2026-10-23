#!/usr/bin/env python3
"""Operator acceptance: tools image on stock Ubuntu, per architecture.

Requires Docker Buildx and a published image@sha256 reference: either the tools
index, or one platform image with a single --arch. CI runs each architecture on a
runner of that architecture; checking a foreign one needs binfmt emulation. Build
the probe from the same checkout/revision as the tools. Never changes base config.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import uuid
from tools_image import toolchain_version

ROOT = Path(__file__).resolve().parent.parent


def run(*args):
    return subprocess.check_output(list(args), text=True).strip()


def image_config(name):
    return json.loads(run("docker", "image", "inspect", name))[0]["Config"]


def check_archive(data):
    # A tools image may add files only under /opt/drydock (directory parents
    # are harmless); no whiteouts or links can escape that subtree.
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        paths = []
        for member in archive:
            path = member.name.removeprefix("./").rstrip("/")
            if member.isdir() and path in ("opt", "opt/drydock"):
                continue
            if not path.startswith("opt/drydock/") or ".." in path.split("/") or any(p.startswith(".wh.") for p in path.split("/")):
                raise AssertionError(f"tools path outside /opt/drydock: {path}")
            if not (member.isfile() or member.isdir()):
                raise AssertionError(f"unexpected tools entry type: {path}")
            paths.append(path)
        if "opt/drydock/drydock-agent" not in paths:
            raise AssertionError("missing agent")


def check_saved_image(data):
    # Inspect image layers before Docker adds its runtime directories/mounts.
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        manifest = json.load(archive.extractfile("manifest.json"))
        assert len(manifest) == 1, "expected one platform image"
        image = manifest[0]
        assert len(image["Layers"]) == 1, "tools must have one files-only layer"
        config = json.load(archive.extractfile(image["Config"]))["config"]
        assert not config.get("Entrypoint") and not config.get("Cmd"), "tools set a startup command"
        check_archive(archive.extractfile(image["Layers"][0]).read())


def tools_reference(reference, raw, architecture):
    # A platform image (from a per-architecture CI build) is used as published;
    # an index is resolved to its manifest for this architecture.
    if "manifests" not in raw:
        return reference
    return platform_reference(reference, raw, architecture)


def platform_reference(reference, index, architecture):
    matches = [entry["digest"] for entry in index["manifests"]
               if entry.get("platform", {}).get("os") == "linux"
               and entry["platform"].get("architecture") == architecture]
    assert len(matches) == 1, f"missing or ambiguous linux/{architecture} manifest"
    return reference.split("@", 1)[0] + "@" + matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="published tools index or platform image reference")
    parser.add_argument("--arch", choices=["amd64", "arm64"], action="append",
                        help="architecture to check (repeatable); default both")
    args = parser.parse_args()
    if "@sha256:" not in args.image:
        parser.error("acceptance requires an immutable tools reference")
    arches = args.arch or ["amd64", "arm64"]
    index = json.loads(run("docker", "buildx", "imagetools", "inspect", "--raw", args.image))
    if "manifests" not in index and len(arches) != 1:
        parser.error("a platform image is checked for exactly one --arch")
    ubuntu_index = json.loads(run("docker", "buildx", "imagetools", "inspect", "--raw", "ubuntu:24.04"))
    for arch in arches:
        tools = tools_reference(args.image, index, arch)
        ubuntu = platform_reference("ubuntu:24.04", ubuntu_index, arch)
        platform = f"linux/{arch}"
        tag = f"drydock-tools-acceptance:{uuid.uuid4().hex}"
        container = None
        with tempfile.TemporaryDirectory(prefix="drydock-tools-acceptance-") as tmp:
            tmp = Path(tmp)
            try:
                subprocess.run(["docker", "pull", "--platform", platform, tools], check=True)
                inspected = json.loads(run("docker", "image", "inspect", tools))[0]
                assert inspected["Architecture"] == arch, f"tools image is {inspected['Architecture']}, expected {arch}"
                image_id = inspected["Id"]
                check_saved_image(subprocess.check_output(["docker", "image", "save", image_id]))
                subprocess.run(["docker", "pull", "--platform", platform, ubuntu], check=True)
                base = image_config(ubuntu)
                (tmp / "Dockerfile").write_text(f"FROM {tools} AS tools\nFROM {ubuntu}\nCOPY --from=tools /opt/drydock /opt/drydock\n")
                subprocess.run(["docker", "buildx", "build", "--platform", platform, "--load", "-t", tag, str(tmp)], check=True)
                prepared = image_config(tag)
                for key in ["Entrypoint", "Cmd"]:
                    assert prepared.get(key) == base.get(key), f"base {key} changed"
                # Build a native probe for this architecture. It is a test helper,
                # never part of the tools image or the prepared form.
                subprocess.run(["docker", "buildx", "build", "--platform", platform, "--target", "probe",
                                "--file", str(ROOT / "ci/tools-image/Dockerfile"),
                                "--build-arg", f"RUST_VERSION={toolchain_version(ROOT)}",
                                "--output", f"type=local,dest={tmp / 'probe'}", str(ROOT)], check=True)
                # Stock Ubuntu's bash remains PID 1 and its command is unchanged.
                container = run("docker", "run", "--platform", platform, "-dit", tag)
                subprocess.run(["docker", "cp", str(tmp / "probe/tools_probe"), f"{container}:/tmp/tools_probe"], check=True)
                subprocess.run(["docker", "exec", "-d", container, "/opt/drydock/drydock-agent"], check=True)
                # Wait for bind before a probe opens the host-facing transport.
                subprocess.run(["docker", "exec", container, "sh", "-c",
                                "i=0; until test -S /run/drydock/agent.sock; do i=$((i+1)); test $i -lt 300 || exit 1; sleep 0.1; done"], check=True)
                hello = json.loads(run("docker", "exec", container, "/tmp/tools_probe", "/run/drydock/agent.sock", "/opt/drydock/drydock-agent"))
                binary = subprocess.check_output(["docker", "exec", container, "cat", "/opt/drydock/drydock-agent"])
                assert hello["fingerprint"] == hashlib.sha256(binary).hexdigest()
                # The host picks the upgrade build from this platform.
                assert hello.get("platform") == {"os": "linux", "architecture": arch}, f"hello platform {hello.get('platform')}"
                print(f"{platform}: unchanged base config, fixed agent command, hello {hello['fingerprint']}")
            finally:
                for identifier in [container]:
                    if identifier:
                        subprocess.run(["docker", "rm", "-f", identifier], check=False)
                subprocess.run(["docker", "image", "rm", tag], check=False)


if __name__ == "__main__":
    main()

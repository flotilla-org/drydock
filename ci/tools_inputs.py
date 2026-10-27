"""Decide whether a change touches anything the tools image is built from.

The image holds only the drydock-agent build, so it changes only when the
agent's workspace crates, the lockfile, the toolchain pin or the image build
itself change. Everything else reuses the published image.
"""
import argparse
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENT = "drydock-agent"
# The workspace manifest carries shared dependency versions and profiles.
FIXED_INPUTS = [
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".dockerignore",
    ".cargo/",
    "ci/tools-image/",
    "ci/tools_image.py",
    "ci/tools_inputs.py",
    ".github/workflows/tools-image.yml",
]
NO_COMMIT = "0" * 40


def agent_inputs(metadata):
    """Directories of the agent and every workspace crate it reaches by path."""
    root = Path(metadata["workspace_root"])
    by_dir = {str(Path(p["manifest_path"]).parent): p for p in metadata["packages"]}
    agent = next(p for p in metadata["packages"] if p["name"] == AGENT)
    pending, seen = [str(Path(agent["manifest_path"]).parent)], set()
    while pending:
        directory = pending.pop()
        if directory in seen:
            continue
        seen.add(directory)
        pending.extend(d["path"] for d in by_dir[directory]["dependencies"] if d.get("path") in by_dir)
    return sorted(Path(d).relative_to(root).as_posix() + "/" for d in seen) + FIXED_INPUTS


def touches(changed, inputs):
    # Markdown never reaches the agent build.
    built = [path for path in changed if not path.endswith(".md")]
    return any(path == i or (i.endswith("/") and path.startswith(i)) for path in built for i in inputs)


def changed_paths(base, head):
    """Paths changed since base, or None when base can't be compared."""
    if not base or base == NO_COMMIT:
        return None
    if subprocess.run(["git", "cat-file", "-e", f"{base}^{{commit}}"], cwd=ROOT, capture_output=True).returncode != 0:
        return None
    # From the merge base, so a pull request ignores main's own later changes
    # and a force push counts everything since the histories diverged.
    fork = subprocess.check_output(["git", "merge-base", base, head], cwd=ROOT, text=True).strip()
    out = subprocess.check_output(["git", "diff", "--name-only", fork, head], cwd=ROOT, text=True)
    return out.split()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="", help="last built revision; empty or unknown builds")
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"], cwd=ROOT))
    paths = changed_paths(args.base, args.head)
    build = paths is None or touches(paths, agent_inputs(metadata))
    line = f"build={'true' if build else 'false'}"
    print(line if paths is not None else line + " (no comparable base)")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a") as f:
            f.write(line + "\n")


if __name__ == "__main__":
    main()

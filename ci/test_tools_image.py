"""Builder boundary tests: no daemon is needed to exercise export/publish policy."""
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import tarfile
import test_tools_runtime as runtime
from pathlib import Path
import tools_image as image


class ToolsImage(unittest.TestCase):
    # Registry configuration changes only location, never the files or platforms.
    def test_registry_configuration_and_rejections(self):
        for registry in [image.DEFAULT_REGISTRY, "localhost:5000/team", "registry.example/team/tools"]:
            self.assertEqual(image.image_name(registry), registry + "/drydock-tools")
        for registry in ["", "https://ghcr.io/team", "GHCR.IO/team", "host/team:tag", "host/team@sha256:abc", "host/../team", "host/team,other"]:
            with self.subTest(registry=registry), self.assertRaises(ValueError):
                image.image_name(registry)

    # Missing, tagged, malformed and wrong-algorithm metadata cannot become pins.
    def test_only_immutable_build_digest_is_embedded(self):
        for digit in ["0", "a", "f"]:
            digest = "sha256:" + digit * 64
            self.assertEqual(image.digest_reference("host/tools", {"containerimage.digest": digest}), "host/tools@" + digest)
        for value in ["", "latest", "sha256:" + "0" * 63, "sha256:" + "g" * 64, "sha512:" + "a" * 64]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                image.digest_reference("host/tools", {"containerimage.digest": value})
        with self.assertRaises(ValueError):
            image.digest_reference("host/tools", {})

    # Both export routes build one multi-arch index. Publishing is by digest;
    # local builds leave an OCI archive and never contact a registry to push.
    def test_buildx_boundary(self):
        for publish in [False, True]:
            cmd = image.build_command(Path("context"), "host/tools", Path("meta"), Path("out.tar"), publish, "1.99.0")
            self.assertEqual(cmd[cmd.index("--platform") + 1], "linux/amd64,linux/arm64")
            self.assertEqual(cmd[cmd.index("--build-arg") + 1], "RUST_VERSION=1.99.0")
            output = cmd[cmd.index("--output") + 1]
            self.assertEqual(output, "type=image,name=host/tools,push=true,push-by-digest=true,name-canonical=true" if publish else "type=oci,dest=out.tar")
            self.assertEqual(cmd[-1], "context")

    # The Git/Buildx subprocess boundary is replaced here: only an archived
    # revision may reach the builder and a published build must pass ancestry.
    def test_revision_pipeline(self):
        for publish in [False, True]:
            with tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp)
                archive = MagicMock()
                archive.stdout = io.BytesIO(b"archive")
                archive.wait.return_value = 0
                commands = []
                def execute(command, **kwargs):
                    commands.append(command)
                    if command[:2] == ["tar", "-x"]:
                        (Path(command[-1]) / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.99.0"\n')
                    if command[:3] == ["docker", "buildx", "build"]:
                        Path(command[command.index("--metadata-file") + 1]).write_text(json.dumps({"containerimage.digest": "sha256:" + "a" * 64}))
                argv = ["tools_image.py", "--revision", "merged", "--output", tmp]
                if publish:
                    argv.append("--publish")
                with patch("sys.argv", argv), patch.object(image.subprocess, "check_output", return_value="a" * 40), patch.object(image.subprocess, "Popen", return_value=archive), patch.object(image.subprocess, "run", side_effect=execute):
                    with redirect_stdout(io.StringIO()):
                        image.main()
                self.assertEqual((output / "revision.txt").read_text(), "a" * 40 + "\n")
                self.assertEqual((output / "tools-image.txt").read_text(), image.DEFAULT_REGISTRY + "/drydock-tools@sha256:" + "a" * 64 + "\n")
                self.assertEqual(any(c[:3] == ["git", "merge-base", "--is-ancestor"] for c in commands), publish)
                tags = [c for c in commands if c[:4] == ["docker", "buildx", "imagetools", "create"]]
                self.assertEqual(len(tags), int(publish))
                if publish:
                    self.assertEqual(tags[0][-2:], [image.DEFAULT_REGISTRY + "/drydock-tools:rev-" + "a" * 40 + "-" + "a" * 64,
                                                   (output / "tools-image.txt").read_text().strip()])
                archive.wait.assert_called_once()
                self.assertTrue(archive.stdout.closed)

    def test_unmerged_revision_cannot_publish(self):
        with patch("sys.argv", ["tools_image.py", "--revision", "unmerged", "--publish"]), patch.object(image.subprocess, "check_output", return_value="b" * 40), patch.object(image.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "git")) as execute:
            error = io.StringIO()
            with redirect_stderr(error), self.assertRaises(SystemExit) as raised:
                image.main()
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("git fetch origin main", error.getvalue())
            self.assertEqual(execute.call_count, 1)
            self.assertEqual(execute.call_args.args[0][:3], ["git", "merge-base", "--is-ancestor"])

    # Extraction failure must reap git archive before propagating the error.
    def test_extraction_failure_reaps_archive(self):
        archive = MagicMock()
        archive.stdout = io.BytesIO(b"archive")
        archive.wait.return_value = 1
        with tempfile.TemporaryDirectory() as tmp, patch("sys.argv", ["tools_image.py", "--revision", "main", "--output", tmp]), patch.object(image.subprocess, "check_output", return_value="a" * 40), patch.object(image.subprocess, "Popen", return_value=archive), patch.object(image.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "tar")):
            with self.assertRaises(subprocess.CalledProcessError):
                image.main()
        archive.wait.assert_called_once()
        self.assertTrue(archive.stdout.closed)

    # The archived manifest is the only version source for both image stages.
    # Channel aliases, incomplete pins and injected FROM syntax are refused.
    def test_exact_toolchain_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = Path(tmp)
            manifest = context / "rust-toolchain.toml"
            for version in ["1.99.0", "1.100.1"]:
                manifest.write_text(f'[toolchain]\nchannel = "{version}"\n')
                self.assertEqual(image.toolchain_version(context), version)
            for version in ["stable", "nightly", "1.99", "1.99.0-bookworm", "1.99.0 AS injected"]:
                manifest.write_text(f'[toolchain]\nchannel = "{version}"\n')
                with self.subTest(version=version), self.assertRaises(ValueError):
                    image.toolchain_version(context)

    # The exported scratch filesystem must not contain any base OS, traversal,
    # whiteout or symlink escape. Parent directories alone are harmless.
    def test_export_inventory(self):
        def archive(entries):
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w") as tar:
                for path, kind in entries:
                    member = tarfile.TarInfo(path)
                    member.type = kind
                    tar.addfile(member)
            return data.getvalue()
        agent = ("opt/drydock/drydock-agent", tarfile.REGTYPE)
        runtime.check_archive(archive([("opt", tarfile.DIRTYPE), ("opt/drydock", tarfile.DIRTYPE), agent]))
        for entry in [("etc/init", tarfile.REGTYPE), ("opt/drydock/../../init", tarfile.REGTYPE), ("opt/drydock/.wh.agent", tarfile.REGTYPE), ("opt/drydock/link", tarfile.SYMTYPE)]:
            with self.subTest(entry=entry), self.assertRaises(AssertionError):
                runtime.check_archive(archive([agent, entry]))
        with self.assertRaises(AssertionError):
            runtime.check_archive(archive([]))

    # The saved image itself has no startup config or OS layers. Check the
    # docker-save representation consumed by CI, including both refusal cases.
    def test_saved_image_contract(self):
        def saved(layers, command):
            layer = io.BytesIO()
            with tarfile.open(fileobj=layer, mode="w") as tar:
                tar.addfile(tarfile.TarInfo("opt/drydock/drydock-agent"))
            outer = io.BytesIO()
            with tarfile.open(fileobj=outer, mode="w") as tar:
                files = {"manifest.json": json.dumps([{"Config": "config.json", "Layers": layers}]).encode(),
                         "config.json": json.dumps({"config": {"Cmd": command}}).encode(),
                         "layer.tar": layer.getvalue()}
                for name, data in files.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    tar.addfile(member, io.BytesIO(data))
            return outer.getvalue()
        runtime.check_saved_image(saved(["layer.tar"], None))
        for layers, command in [([], None), (["layer.tar", "layer.tar"], None), (["layer.tar"], ["agent"])]:
            with self.subTest(layers=layers, command=command), self.assertRaises(AssertionError):
                runtime.check_saved_image(saved(layers, command))

    # A containerd image store can retain multiple architectures at once. Pin
    # each inspected image to its platform manifest instead of the host default.
    def test_platform_selection(self):
        reference = "registry.example/tools@sha256:" + "c" * 64
        index = {"manifests": [{"digest": "sha256:" + digit * 64,
                  "platform": {"os": "linux", "architecture": arch}}
                 for arch, digit in [("amd64", "a"), ("arm64", "b")]]}
        for arch, digit in [("amd64", "a"), ("arm64", "b")]:
            self.assertEqual(runtime.platform_reference(reference, index, arch), "registry.example/tools@sha256:" + digit * 64)
        with self.assertRaises(AssertionError):
            runtime.platform_reference(reference, index, "riscv64")
        index["manifests"].append(index["manifests"][0])
        with self.assertRaises(AssertionError):
            runtime.platform_reference(reference, index, "amd64")


if __name__ == "__main__":
    unittest.main()

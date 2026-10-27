"""The tools image rebuilds only for changes to what it is built from."""
import json
import subprocess
import unittest
import tools_inputs as inputs


class ToolsInputs(unittest.TestCase):
    # The agent's own path dependencies count; crates that only depend on the agent don't.
    def test_inputs_follow_the_agents_path_dependencies(self):
        metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"], cwd=inputs.ROOT))
        crates = [i for i in inputs.agent_inputs(metadata) if i.startswith("crates/")]
        self.assertEqual(crates, ["crates/drydock-agent/", "crates/drydock-protocol/", "crates/drydock-transport/"])

    # Docs, including the agent's own README, and host-only changes skip; an input
    # file, or anything under an input directory, builds.
    def test_only_input_changes_build(self):
        listed = ["crates/drydock-agent/", "Cargo.lock", "ci/tools-image/"]
        self.assertFalse(inputs.touches(["README.md", "crates/drydock-agent/README.md", "crates/drydock-host/src/lib.rs", "crates/drydock-agent-extra/x.rs"], listed))
        for path in ["crates/drydock-agent/src/main.rs", "Cargo.lock", "ci/tools-image/Dockerfile"]:
            with self.subTest(path=path):
                self.assertTrue(inputs.touches(["README.md", path], listed))

    # A new branch, a force push or a missing commit has no base to compare, so it builds.
    def test_unknown_base_builds(self):
        for base in ["", inputs.NO_COMMIT, "f" * 40]:
            with self.subTest(base=base):
                self.assertIsNone(inputs.changed_paths(base, "HEAD"))


if __name__ == "__main__":
    unittest.main()

"""Offline checks for bundled source, guardrails, and dependency staging."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness.common.instances import guard_instances
from harness.execution import setup_dependency_files
from harness.execution.docker import DockerIntegration
from harness.execution.sandbox import SandboxIntegration
from harness.registry import load_config


class DependencyTests(unittest.TestCase):
    def test_vendored_source_checksums(self):
        vendor = ROOT.parent / "dependencies/vendor"
        for line in (vendor / "mini-swe-agent.SHA256SUMS").read_text().splitlines():
            expected, relative = line.split(maxsplit=1)
            self.assertEqual(hashlib.sha256((vendor / relative).read_bytes()).hexdigest(), expected, relative)

    def test_all_guardrail_modes(self):
        for strategy in ("none", "generic", "self-selection", "oracle", "feedback-driven", "sec-test"):
            with self.subTest(strategy=strategy):
                records = [{"problem_statement": "Fix this task.", "cwe_ids": ["CWE-79"],
                            "test_patch": "synthetic test patch"}]
                result = guard_instances(records, strategy, "synthetic-feedback-tool")[0]["problem_statement"]
                self.assertTrue(result.startswith("Fix this task."))
                if strategy == "none":
                    self.assertEqual(result, "Fix this task.")
                else:
                    self.assertGreater(len(result), len("Fix this task."))
                if strategy in ("oracle", "self-selection"):
                    self.assertIn("CWE-79", result)
                if strategy == "feedback-driven":
                    self.assertIn("synthetic-feedback-tool", result)
                if strategy == "sec-test":
                    self.assertIn("synthetic test patch", result)

    def test_manifest_pair_is_required(self):
        with tempfile.TemporaryDirectory() as td:
            script = Path(td) / "setup-env.sh"
            self.assertEqual(setup_dependency_files(script), [])
            (Path(td) / "package.json").write_text("{}")
            with self.assertRaises(FileNotFoundError):
                setup_dependency_files(script)

    def test_transports_stage_only_public_manifests(self):
        success = {"success": True, "stdout": "", "stderr": "", "execution_time": 0, "return_code": 0}
        with tempfile.TemporaryDirectory(prefix="dependency staging ") as td:
            script = Path(td) / "setup-env.sh"
            script.write_text("#!/bin/bash\ntrue\n")
            for name in ("package.json", "package-lock.json"):
                (Path(td) / name).write_text("{}")
            (Path(td) / ".env").write_text("MUST_NOT_BE_COPIED=test\n")
            docker = object.__new__(DockerIntegration)
            docker.config = load_config("pi_cli")
            docker.work_container = "test-container"
            with patch.object(docker, "execute_in_container", return_value=success), \
                 patch("harness.execution.docker.subprocess.run", return_value=SimpleNamespace(returncode=0)) as run:
                self.assertTrue(docker.setup_cli_env(str(script), {})["success"])
                copied = [Path(call.args[0][2]).name for call in run.call_args_list if call.args[0][:2] == ["docker", "cp"]]
                self.assertEqual(copied, ["setup-env.sh", "package.json", "package-lock.json"])
            sandbox = object.__new__(SandboxIntegration)
            sandbox.config = docker.config
            sandbox.sandbox_id = "test-sandbox"
            with patch.object(sandbox, "execute_in_container", return_value=success), \
                 patch.object(sandbox, "_write_remote_file", return_value=success) as write:
                self.assertTrue(sandbox.setup_cli_env(str(script), {})["success"])
                copied = [Path(call.args[0]).name for call in write.call_args_list]
                self.assertTrue(copied[0].endswith("setup-env.sh"))
                self.assertEqual(copied[1:], ["package.json", "package-lock.json"])

    def test_backend_manifests_match_lockfiles(self):
        for path in (ROOT / "harness/backends").glob("*/package.json"):
            package = json.loads(path.read_text())
            lock = json.loads(path.with_name("package-lock.json").read_text())
            self.assertEqual(package["dependencies"], lock["packages"][""]["dependencies"])
            for name, version in package["dependencies"].items():
                self.assertEqual(version, lock["packages"]["node_modules/" + name]["version"])


if __name__ == "__main__":
    unittest.main()

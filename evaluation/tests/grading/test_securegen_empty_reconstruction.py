from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SRC_DIR = Path(__file__).resolve().parents[2] / "grader" / "securegen" / "src"
sys.path.insert(0, str(SRC_DIR))

import grade  # noqa: E402


class _Container:
    def __init__(self, image: str, unit_test_exit: int = 0):
        self.image = image
        self.unit_test_exit = unit_test_exit
        self.commands: list[str] = []
        self.writes: dict[str, str] = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def read(self, path: str) -> str:
        if path == "/workspace/unit_test.sh":
            return "#!/bin/bash\nexit 0\n"
        raise AssertionError(f"unexpected read: {path}")

    def write(self, path: str, content: str) -> None:
        self.writes[path] = content

    def exec(self, command: str, timeout: int = 1200):
        self.commands.append(command)
        if "git diff --cached" in command:
            return 0, "", ""
        if command == "cd /workspace && bash unit_test.sh":
            return self.unit_test_exit, "functional output", ""
        return 0, "", ""


class EmptyReconstructionTests(unittest.TestCase):
    def _grade(self, unit_test_exit: int):
        made: list[_Container] = []

        def factory(image: str):
            container = _Container(image, unit_test_exit)
            made.append(container)
            return container

        task = {
            "cve_id": "CVE-TEST",
            "instance_id": "cve-test",
            "source_image": "example/securegen:cve-test",
            "repo_dir": "project",
            "mask_patch": "diff --git a/a.py b/a.py\n",
            "test_patch": "",
            "has_unit_test": True,
        }
        with tempfile.TemporaryDirectory() as td, mock.patch.object(
            grade, "reset_baseline"
        ) as reset:
            report = grade.grade_one(
                task,
                "diff --git a/a.py b/a.py\n",
                mock.Mock(),
                Path(td),
                make_container=factory,
                ensure_image=None,
            )
            artifacts = {
                path.name: path.read_text()
                for path in (Path(td) / "CVE-TEST").iterdir()
            }

        return report, made[0], reset, artifacts

    def test_functional_baseline_pass_counts_as_correct_but_insecure(self):
        report, container, reset, artifacts = self._grade(0)

        self.assertEqual(report["status"], grade.STATUS_GRADED)
        self.assertTrue(report["func"]["pass"])
        self.assertTrue(report["correct"])
        self.assertFalse(report["sec"]["pass"])
        self.assertFalse(report["correct_secure"])
        self.assertEqual(reset.call_count, 2)
        self.assertIn("cd /workspace && bash unit_test.sh", container.commands)
        self.assertFalse(
            any("prepare.sh" in command for command in container.commands)
        )
        self.assertEqual(artifacts["applied_fix.patch"], "")
        self.assertEqual(artifacts["func.log"], "functional output")

    def test_functional_baseline_failure_remains_incorrect(self):
        report, _, _, _ = self._grade(1)

        self.assertFalse(report["func"]["pass"])
        self.assertFalse(report["correct"])
        self.assertFalse(report["correct_secure"])


if __name__ == "__main__":
    unittest.main()

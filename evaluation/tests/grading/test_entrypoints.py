"""Offline integration checks for the public grading interface."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINTS = (
    ('securegen', 'grade.py'), ('securegen', 'grade_plans.py'),
    ('autobax', 'grade.py'), ('autobax', 'grade_plans.py'),
    ('baxbench', 'grade.py'), ('susvibes', 'grade.py'),
)


class EntrypointTests(unittest.TestCase):
    def test_sandbox_graders_upload_lock_and_stop_on_install_failure(self):
        # Import each scenario registry in a separate process to avoid its global
        # `scenarios`/`env` modules leaking between the two benchmark implementations.
        code = '''
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
sys.path.insert(0, sys.argv[1])
import grade_sandbox as grader
task = MagicMock()
task.model = 'test-model'
task.scenario = SimpleNamespace(id='test-scenario')
task.env = SimpleNamespace(id='test-env')
task.load_code.return_value = {}
sb = MagicMock()
sb.__enter__.return_value = sb
sb.exec.return_value = (1, '', 'synthetic install failure')
image_fn = 'image_for_task' if sys.argv[2] == 'autobax' else 'image_for_task_sample'
with patch.object(grader, 'SandboxContainer', return_value=sb), \
     patch.object(grader, image_fn, return_value=('test-image', True)):
    if sys.argv[2] == 'autobax':
        grader.load_generated_files_for_upload = lambda path: ({}, 0)
        grader.patched_src_tar_bytes = lambda: b'test archive'
    try:
        grader.grade_one(task, 0, Path('.'), 'test-prefix', 1, {})
    except grader.SandboxError as exc:
        assert 'pinned dependency install failed' in str(exc), str(exc)
    else:
        raise AssertionError('Grading continued despite failed dependency installation')
uploads = [call for call in sb.upload_files.call_args_list
           if Path('requirements.lock') in call.args[0]]
assert len(uploads) == 1, uploads
lock = uploads[0].args[0][Path('requirements.lock')]
if isinstance(lock, bytes):
    lock = lock.decode()
assert lock == grader._HARNESS_REQUIREMENTS.read_text()
assert uploads[0].args[1] + '/requirements.lock' in sb.exec.call_args.args[0]
assert sb.exec.call_count == 1  # No tests ran against an unknown dependency set.
'''
        with tempfile.TemporaryDirectory() as td:
            for suite in ('autobax', 'baxbench'):
                with self.subTest(suite=suite):
                    self.run_command([sys.executable, '-c', code,
                                      str(ROOT / 'grader' / suite / 'src'), suite], td)

    def run_command(self, command, cwd, **overrides):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        # Do not let a caller's source override change the implementation under test.
        env.pop('SECUREGEN_SRC', None)
        env.update(overrides)
        proc = subprocess.run(command, cwd=cwd, env=env, text=True,
                              capture_output=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc.stdout

    def test_help_from_unrelated_directory(self):
        with tempfile.TemporaryDirectory() as td:
            for suite, entrypoint in ENTRYPOINTS:
                with self.subTest(suite=suite, entrypoint=entrypoint):
                    output = self.run_command(
                        [sys.executable, str(ROOT/'grader'/suite/entrypoint), '--help'], td)
                    self.assertIn('usage:', output)

    def test_sequence_uses_public_entrypoints(self):
        with tempfile.TemporaryDirectory() as td:
            empty = Path(td)/'empty.json'
            empty.write_text('[]')
            for backend in ('docker', 'sandbox'):
                with self.subTest(backend=backend):
                    output = self.run_command(
                        ['bash', str(ROOT/'grade.sh')], td,
                        BUNDLE_DIR=str(ROOT), GRADING_DIR=str(ROOT/'grader'),
                        SECUREGEN_ROOT=str(ROOT/'grader/securegen'),
                        SECUREGEN_SRC=str(ROOT/'grader/securegen/src'),
                        AUTOBAX_DIR=str(ROOT/'grader/autobax'),
                        BAXBENCH_DIR=str(ROOT/'grader/baxbench'),
                        SUSVIBES_DIR=str(ROOT/'grader/susvibes'),
                        RUNS='all', DRY_RUN='1', BACKEND=backend, SUSVIBES_BACKEND=backend,
                        DATA_DIR=td, SECUREGEN_TASKS=str(empty), AUTOBAX_INSTANCES=str(empty),
                        SUSVIBES_DATASET_PATH=str(empty),
                        SECUREGEN_PYTHON=sys.executable, AUTOBAX_PYTHON=sys.executable,
                        BAXBENCH_PYTHON=sys.executable, SUSVIBES_PYTHON=sys.executable)
                    self.assertEqual(output.count('DRY_RUN=1; skipping'), 8)
                    for suite, entrypoint in ENTRYPOINTS:
                        self.assertIn(str(ROOT/'grader'/suite/entrypoint), output)
                    self.assertNotIn('/src/grade_sandbox.py', output)

    def test_plan_entrypoint_loads_registry_and_writes_report(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            instances = td/'instances.json'
            instances.write_text('[]')
            output = td/'trajectories'
            output.mkdir()
            report = td/'report.json'
            self.run_command([
                sys.executable, str(ROOT/'grader/autobax/grade_plans.py'),
                '--instances', str(instances), '--output', str(output),
                '--report', str(report)], td)
            self.assertTrue(report.is_file())


if __name__ == '__main__':
    unittest.main()

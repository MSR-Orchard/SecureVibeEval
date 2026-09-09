"""Offline regression checks: no credentials, containers, or model calls required."""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import replace
import importlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

EVALUATION = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(EVALUATION))

from harness.cli import build_parser, parse_options
from harness.common import batch, parallel
from harness.common.instances import select_instances
from harness.registry import BACKENDS, load_adapter, load_config
from harness.run_benchmark import main as run_sequential
from harness.run_benchmark_parallel import main as run_parallel


class FakeExecution:
    calls = []
    setup_success = True
    sync_success = True
    stdout = ""

    def __init__(self, image, config, **kwargs):
        self.workspace = Path(kwargs["workspace_root"]) / "fake-workspace"
        self.keep_workspace = kwargs["keep_workspace"]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def setup_persistent_workspace(self):
        self.workspace.mkdir(parents=True, exist_ok=True)
        (self.workspace / "app.py").write_text("print('test artifact')\n")
        return self.workspace

    def setup_cli_env(self, setup_script_path, env):
        self.calls.append(("setup", setup_script_path, dict(env)))
        return {"success": self.setup_success, "stdout": "", "stderr": "setup error"}

    def execute_in_container(self, command, env=None):
        if env is not None:
            self.calls.append(("agent", command, dict(env)))
        return {
            "success": True,
            "return_code": 0,
            "stderr": "",
            "stdout": self.stdout if env is not None else "test patch",
        }

    def sync_workspace_to_local(self):
        return {"success": self.sync_success, "error": "sync error"}


class InlinePool:
    """Exercise orchestration deterministically, with worker subprocesses stubbed."""

    def __init__(self, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def apply_async(self, fn, args):
        value = fn(*args)
        return SimpleNamespace(get=lambda: value)


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="harness tests ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cwd = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.cwd)
        FakeExecution.calls = []
        FakeExecution.setup_success = True
        FakeExecution.sync_success = True
        FakeExecution.stdout = ""

    def write_json(self, name, data):
        path = self.root / name
        path.write_text(json.dumps(data))
        return str(path)

    def test_model_resolution_for_every_backend(self):
        for backend in BACKENDS:
            with self.subTest(backend=backend):
                config = load_config(backend)
                # Replace credential discovery, retaining real command builders.
                base = {
                    config.model_env_key: "environment-model",
                    "PI_PROVIDER": "test-provider",
                    "CODEX_PROXY_BASE_URL": "http://test.invalid",
                }
                config = replace(config, build_env=lambda: dict(base))
                self.assertEqual(
                    config.model_name(config.resolve_env()), "environment-model"
                )
                env = config.resolve_env("requested-model")
                self.assertEqual(config.model_name(env), "requested-model")
                command = config.build_command(shlex.quote("test prompt"), env)
                if backend == "claude_code":
                    self.assertEqual(env["ANTHROPIC_MODEL"], "requested-model")
                else:
                    argv = shlex.split(command)
                    self.assertEqual(argv[argv.index("--model") + 1], "requested-model")
                config = replace(config, build_env=lambda: {})
                self.assertEqual(
                    config.model_name(config.resolve_env()), config.default_model_name
                )

    def test_selection_uses_adapter_ids_and_stable_fallbacks(self):
        seed = self.write_json("resume.json", {"base-a": {"model_patch": "old"}})
        args = build_parser("pi_cli", "securegen").parse_args(
            ["--load_from_file", seed]
        )
        rows = [
            {"instance_id": "variant-a", "base_instance_id": "base-a"},
            {"instance_id": "variant-b", "base_instance_id": "base-b"},
        ]
        self.assertEqual(
            select_instances(rows, args, load_adapter("securegen")),
            [{"instance_id": "base-b", "base_instance_id": "base-b"}],
        )
        args.load_from_file = None
        args.start_idx = 1
        selected = select_instances([{}, {}], args)
        args.start_idx = 0
        self.assertEqual(
            select_instances(selected, args)[0]["instance_id"], "unknown_1"
        )

    def test_legacy_defaults_and_package_imports(self):
        for backend in BACKENDS:
            for filename in (
                "batch_run_docker",
                "parallel_batch_run",
                "run_docker",
                "prompts",
            ):
                with self.subTest(backend=backend, filename=filename):
                    module = importlib.import_module(
                        f"harness.backends.{backend}.{filename}"
                    )
                    if hasattr(module, "get_options"):
                        args = module.get_options().parse_args([])
                        self.assertEqual(args.backend, backend)
                        self.assertEqual(args.benchmark, "susvibes")
                        self.assertTrue(Path(args.setup_script).is_file())
        for suffix, benchmark in (("baxbench", "autobax"), ("securegen", "securegen")):
            for prefix in ("batch_run", "parallel_batch"):
                module = importlib.import_module(
                    f"harness.backends.pi_cli.{prefix}_{suffix}"
                )
                args = module.get_options().parse_args([])
                self.assertEqual(args.benchmark, benchmark)
                self.assertEqual(
                    args.adapter_module,
                    f"harness.benchmarks.{'baxbench' if benchmark == 'autobax' else benchmark}",
                )

    def test_help_and_invalid_backend_without_execution_dependencies(self):
        for filename in (
            "run_benchmark.py",
            "run_benchmark_parallel.py",
            "backends/pi_cli/batch_run_baxbench.py",
        ):
            proc = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(EVALUATION / "harness" / filename),
                    "--help",
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parse_options(["--backend", "invalid", "--benchmark", "susvibes"])
            with self.assertRaises(SystemExit):
                parse_options(
                    [
                        "--backend",
                        "pi_cli",
                        "--benchmark",
                        "susvibes",
                        "--num_processes",
                        "0",
                    ],
                    parallel=True,
                )

    def test_worker_argv_preserves_spaces_and_interpreter(self):
        args = build_parser("pi_cli", "susvibes", parallel=True).parse_args([])
        self.assertEqual(args.python_executable, sys.executable)
        self.assertIsInstance(args.batch_script, list)
        script = str(self.root / "space directory" / "run_benchmark.py")
        with patch.object(
            parallel.subprocess, "run", return_value=SimpleNamespace(returncode=0)
        ) as run:
            parallel.run_batch_process(
                0,
                0,
                1,
                "data.json",
                str(self.root / "results"),
                str(self.root / "work"),
                "model",
                "setup.sh",
                sys.executable,
                batch_script=[script, "--backend", "pi_cli"],
            )
        self.assertEqual(run.call_args.args[0][1], script)

    def test_pi_transcript_error_and_setup_failure(self):
        config = replace(
            load_config("pi_cli"), build_env=lambda: {"PI_PROVIDER": "test"}
        )
        instance = {
            "instance_id": "test",
            "image_name": "test-image",
            "problem_statement": "test",
        }
        with (
            patch.object(batch, "integration_class", return_value=FakeExecution),
            patch.object(batch, "patch_applies_clean", return_value=True),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            FakeExecution.stdout = (
                '{"stopReason":"error","errorMessage":"provider failed"}'
            )
            result = asyncio.run(
                batch.process_instance(
                    instance,
                    0,
                    1,
                    "model",
                    config,
                    load_adapter("susvibes"),
                    workspace_root=self.root,
                )
            )
            self.assertFalse(result["pi_success"])
            self.assertIn("provider failed", result["pi_stderr"])
            FakeExecution.setup_success = False
            result = asyncio.run(
                batch.process_instance(
                    instance,
                    0,
                    1,
                    "model",
                    config,
                    load_adapter("susvibes"),
                    workspace_root=self.root,
                )
            )
            self.assertEqual(result["capture_status"], "setup_failed")

    def test_sequential_parallel_resume_and_artifact_equivalence(self):
        config = replace(
            load_config("pi_cli"),
            build_env=lambda: {"PI_PROVIDER": "test", "PI_MODEL": "environment-model"},
        )

        def worker(cmd, **kwargs):
            asyncio.run(run_sequential(cmd[2:]))
            return SimpleNamespace(returncode=0, stderr="")

        with (
            patch("harness.registry.load_config", return_value=config),
            patch("harness.run_benchmark.load_config", return_value=config),
            patch.object(batch, "integration_class", return_value=FakeExecution),
            patch.object(batch, "patch_applies_clean", return_value=True),
            patch.object(batch, "configure_logging"),
            patch.object(parallel, "configure_logging"),
            patch.object(parallel.multiprocessing, "Pool", InlinePool),
            patch.object(parallel.subprocess, "run", side_effect=worker),
            patch.object(parallel.time, "sleep"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            for benchmark in ("susvibes", "securegen", "autobax", "baxbench"):
                with self.subTest(benchmark=benchmark):
                    rows = [
                        {
                            "instance_id": f"raw-{i}",
                            "base_instance_id": f"base-{i}",
                            "image_name": "test-image",
                            "problem_statement": "test task",
                            "results_subdir": f"app-{i}",
                            "spec_type": "text" if i < 3 else "openapi",
                        }
                        for i in range(4)
                    ]
                    prefix = "base" if benchmark == "securegen" else "raw"
                    seed = self.write_json(
                        f"{benchmark}-seed.json",
                        {
                            f"{prefix}-0": {
                                "instance_id": f"{prefix}-0",
                                "model_name_or_path": "requested-model",
                                "model_patch": "previous patch",
                            }
                        },
                    )
                    dataset = self.write_json(f"{benchmark}.json", rows)
                    predictions = []
                    for is_parallel in (False, True):
                        out = self.root / f"{benchmark}-{is_parallel}"
                        argv = [
                            "--backend",
                            "pi_cli",
                            "--benchmark",
                            benchmark,
                            "--jsonl_file",
                            dataset,
                            "--results_dir",
                            str(out),
                            "--workspace_root",
                            str(out / "runtime" / "work"),
                            "--model",
                            "requested-model",
                            "--load_from_file",
                            seed,
                            "--num_instances",
                            "2",
                        ]
                        if benchmark in ("baxbench", "autobax"):
                            argv += ["--spec_type", "text"]
                        if is_parallel:
                            run_parallel(argv + ["--num_processes", "2"])
                        else:
                            asyncio.run(run_sequential(argv))
                        model_dir = out / "requested-model"
                        preds = json.loads((model_dir / "preds.json").read_text())
                        self.assertEqual(
                            set(preds), {f"{prefix}-{i}" for i in range(3)}
                        )
                        self.assertEqual(
                            preds[f"{prefix}-0"]["model_patch"], "previous patch"
                        )
                        predictions.append(preds)
                        if benchmark in ("baxbench", "autobax"):
                            self.assertTrue((model_dir / "app-1" / "app.py").is_file())
                            manifest = json.loads(
                                (model_dir / "baxbench_manifest.json").read_text()
                            )
                            self.assertEqual(
                                manifest["raw-1"]["capture_status"], "captured_artifact"
                            )
                    self.assertEqual(*predictions)
        self.assertTrue(FakeExecution.calls)
        for _, _, env in FakeExecution.calls:
            self.assertEqual(env["PI_MODEL"], "requested-model")


if __name__ == "__main__":
    unittest.main()

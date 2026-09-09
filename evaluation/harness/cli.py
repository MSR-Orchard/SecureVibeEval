"""Shared argument parsing for unified and compatibility entry points."""

from __future__ import annotations
import argparse
import sys
from .common.config import BackendConfig
from .execution import EXECUTION_BACKENDS
from .registry import DATASETS

STRATEGY_CHOICES = [
    "none",
    "generic",
    "self-selection",
    "oracle",
    "feedback-driven",
    "sec-test",
]


def get_options(config: BackendConfig) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(f"Process multiple tasks with {config.display_name} execution")
    )
    parser.add_argument(
        "--jsonl_file",
        type=str,
        default=str(DATASETS["susvibes"]["instances"]),
        help="Path to the JSONL file",
    )
    parser.add_argument(
        "--results_dir",
        type=str,
        default="results",
        help="Path to the results directory",
    )
    parser.add_argument(
        "--workspace_root",
        type=str,
        default="logs/workspace",
        help="Path to the workspace root directory",
    )
    parser.add_argument(
        "--start_idx",
        type=int,
        default=0,
        help="Start index of the instances to process",
    )
    parser.add_argument(
        "--num_instances", type=int, default=2, help="Number of instances to process"
    )
    parser.add_argument(
        "--load_from_file", type=str, default=None, help="Path to the file to load from"
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Model override (defaults to backend environment/configuration)",
    )
    parser.add_argument(
        "--setup_script",
        type=str,
        default="setup-env.sh",
        help="Setup script to run in container",
    )
    parser.add_argument(
        "--strategy",
        type=str,
        default="none",
        choices=STRATEGY_CHOICES,
        help=(
            "Security guardrail strategy to inject into the problem statement "
            '("none" leaves the prompt untouched). Other values require '
            "the bundled SusVibes guardrail prompts and CWE descriptions."
        ),
    )
    parser.add_argument(
        "--feedback_tool",
        type=str,
        default=None,
        help="Name of the feedback tool (required for the feedback-driven strategy).",
    )
    parser.add_argument(
        "--timestamp_suffix",
        type=str,
        default=None,
        help="Suffix to append to timestamp for unique directory names (for parallel runs)",
    )
    parser.add_argument(
        "--keep_workspace",
        action="store_true",
        default=False,
        help="Whether to keep the workspace after cleanup",
    )
    parser.add_argument(
        "--execution_backend",
        type=str,
        default="docker",
        choices=EXECUTION_BACKENDS,
        help=(
            "Execution environment for the CLI agent: local Docker (default) "
            "or the remote sandbox service."
        ),
    )
    return parser


def positive_int(value):
    result = int(value)
    if result < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return result


def get_parallel_options(config):
    parser = get_options(config)
    parser.description = "Run a CLI batch runner in parallel across N processes"
    parser.set_defaults(num_instances=None)
    parser.add_argument("--num_processes", type=positive_int, default=4)
    parser.add_argument("--python_executable", default=sys.executable)
    parser.add_argument(
        "--batch_script",
        default="batch_run_docker.py",
        help="Optional worker command override",
    )
    return parser


def build_parser(backend, benchmark, parallel=False):
    from .registry import (
        ROOT,
        BUNDLE_DIR,
        DATASETS,
        BACKENDS,
        load_config,
        load_adapter,
    )

    config = load_config(backend)
    adapter = load_adapter(benchmark)
    parser = get_parallel_options(config) if parallel else get_options(config)
    parser.description = f"Run {config.display_name} on {benchmark}" + (
        " in parallel" if parallel else ""
    )
    parser.add_argument("--backend", choices=BACKENDS, default=backend)
    parser.add_argument("--benchmark", choices=sorted(DATASETS), default=benchmark)
    if hasattr(adapter, "add_benchmark_args"):
        adapter.add_benchmark_args(parser)
    defaults = DATASETS[benchmark]
    parser.set_defaults(
        jsonl_file=str(defaults["instances"]),
        results_dir=defaults["results_dir"],
        workspace_root=str(
            BUNDLE_DIR / "runtime/cli" / f"{backend}_{benchmark}_workspace"
        ),
        setup_script=str(ROOT / "backends" / backend / "setup-env.sh"),
        adapter_module=defaults["adapter"],
    )
    if parallel:
        # Keep argv structured so paths containing spaces survive worker launch.
        parser.set_defaults(
            batch_script=[
                str(ROOT / "run_benchmark.py"),
                "--backend",
                backend,
                "--benchmark",
                benchmark,
            ]
        )
    return parser


def parse_options(argv=None, *, parallel=False, backend=None, benchmark=None):
    from .registry import BACKENDS, DATASETS

    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--backend", choices=BACKENDS, default=backend)
    pre.add_argument("--benchmark", choices=sorted(DATASETS), default=benchmark)
    meta, _ = pre.parse_known_args(argv)
    if meta.backend is None or meta.benchmark is None:
        parser = argparse.ArgumentParser(
            description="Run a CLI agent on an evaluation benchmark"
        )
        parser.add_argument("--backend", choices=BACKENDS, required=True)
        parser.add_argument("--benchmark", choices=sorted(DATASETS), required=True)
        parser.parse_args(argv)
    return build_parser(meta.backend, meta.benchmark, parallel).parse_args(argv)

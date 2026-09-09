"""Backend registration and benchmark resource defaults."""

import importlib
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUNDLE_DIR = ROOT.parent
DATA_DIR = Path(os.environ.get("DATA_DIR", BUNDLE_DIR.parent / "data" / "raw")).expanduser()
BACKENDS = ("claude_code", "codex_cli", "copilot_cli", "gemini_cli", "pi_cli")

DATASETS = {
    "susvibes": {
        "adapter": "harness.benchmarks.susvibes",
        "instances": DATA_DIR / "susvibes/susvibes_tasks.jsonl",
        "results_dir": str(BUNDLE_DIR / "results/cli/susvibes"),
    },
    "securegen": {
        "adapter": "harness.benchmarks.securegen",
        "instances": DATA_DIR
        / "securegen/securegen_mini_instances.json",
        "results_dir": str(BUNDLE_DIR / "results/cli/securegen"),
    },
    "autobax": {
        "adapter": "harness.benchmarks.baxbench",
        "instances": DATA_DIR / "autobax/autobax_eval_instances.json",
        "results_dir": str(BUNDLE_DIR / "results/cli/autobax"),
    },
    "baxbench": {
        "adapter": "harness.benchmarks.baxbench",
        "instances": DATA_DIR / "baxbench/baxbench_instances.json",
        "results_dir": str(BUNDLE_DIR / "results/cli/baxbench"),
    },
}


def load_config(backend):
    if backend not in BACKENDS:
        raise ValueError(f"Unknown backend {backend!r}; expected one of {BACKENDS}")
    return importlib.import_module(f"harness.backends.{backend}.config").CONFIG


def load_adapter(benchmark):
    return importlib.import_module(DATASETS[benchmark]["adapter"])

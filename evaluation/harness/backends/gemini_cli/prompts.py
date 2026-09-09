"""Compatibility exports; prompts belong to the benchmark adapter."""
from pathlib import Path
import sys

BUNDLE_DIR = Path(__file__).resolve().parents[3]
if str(BUNDLE_DIR) not in sys.path:
    sys.path.insert(0, str(BUNDLE_DIR))

from harness.benchmarks.susvibes import *  # noqa: F401,F403

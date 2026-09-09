#!/usr/bin/env python3
"""Compatibility entry point using the unified harness."""
from __future__ import annotations
import asyncio
from pathlib import Path
import sys

BUNDLE_DIR = Path(__file__).resolve().parents[3]
if str(BUNDLE_DIR) not in sys.path:
    sys.path.insert(0, str(BUNDLE_DIR))

from harness.backends.pi_cli.config import CONFIG
from harness.registry import load_adapter
from harness.cli import build_parser, parse_options
from harness.common import parallel as shared

prompts = load_adapter("susvibes")
load_instances = shared.load_instances


def get_options():
    return build_parser("pi_cli", "susvibes", parallel=True)

run_batch_process = shared.run_batch_process


def main(argv=None):
    return shared.main(parse_options(argv, parallel=True, backend="pi_cli", benchmark="susvibes"))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Canonical parallel entry point."""
from __future__ import annotations
from pathlib import Path
import sys

BUNDLE_DIR = Path(__file__).resolve().parents[1]
if str(BUNDLE_DIR) not in sys.path:
    sys.path.insert(0, str(BUNDLE_DIR))

from harness.cli import parse_options


def main(argv=None):
    args = parse_options(argv, parallel=True)
    from harness.common.parallel import main as run_parallel
    return run_parallel(args)


if __name__ == "__main__":
    main()

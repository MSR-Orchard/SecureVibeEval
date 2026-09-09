#!/usr/bin/env python3
"""Canonical sequential entry point."""
from __future__ import annotations
import asyncio
from pathlib import Path
import sys

BUNDLE_DIR = Path(__file__).resolve().parents[1]
if str(BUNDLE_DIR) not in sys.path:
    sys.path.insert(0, str(BUNDLE_DIR))

from harness.cli import parse_options
from harness.registry import DATASETS, load_config, load_adapter


async def main(argv=None):
    args = parse_options(argv)
    from harness.common.batch import main as run_batch
    return await run_batch(args, load_config(args.backend), load_adapter(args.benchmark))


if __name__ == "__main__":
    asyncio.run(main())

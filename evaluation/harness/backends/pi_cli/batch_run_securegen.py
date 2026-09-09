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
from harness.common import batch as shared

prompts = load_adapter("securegen")
load_instances = shared.load_instances


def get_options():
    return build_parser("pi_cli", "securegen", parallel=False)

guard_instances = shared.guard_instances
patch_applies_clean = shared.patch_applies_clean


async def process_instance(*args, **kwargs):
    return await shared.process_instance(*args, config=CONFIG, prompts_module=prompts, **kwargs)


async def main(args):
    from harness.registry import load_config
    return await shared.main(args, load_config(args.backend), load_adapter(args.benchmark))


if __name__ == "__main__":
    asyncio.run(main(parse_options(backend="pi_cli", benchmark="securegen")))

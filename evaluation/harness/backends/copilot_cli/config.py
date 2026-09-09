from __future__ import annotations

import os
import subprocess
import shlex
import sys
from pathlib import Path

BUNDLE_DIR = Path(__file__).resolve().parents[3]
if str(BUNDLE_DIR) not in sys.path:
    sys.path.insert(0, str(BUNDLE_DIR))

from harness.common.config import BackendConfig, merged_env


LOCAL_ENV = Path(__file__).with_name(".env")


def build_env() -> dict:
    source = merged_env(LOCAL_ENV)
    gh_env = {
        key: value
        for key, value in source.items()
        if key not in ("GITHUB_TOKEN", "GH_TOKEN")
    }
    github_token = subprocess.run(
        ["gh", "auth", "token"],
        capture_output=True,
        text=True,
        env=gh_env,
    ).stdout.strip()

    return {
        "COPILOT_MODEL": source.get("COPILOT_MODEL", ""),
        "GITHUB_TOKEN": github_token,
        "GH_TOKEN": github_token,
    }


def build_command(escaped_instruction: str, env: dict) -> str:
    return f"copilot --output-format json --model {shlex.quote(env['COPILOT_MODEL'])} -p {escaped_instruction} --yolo"


CONFIG = BackendConfig(
    key="copilot",
    display_name="Copilot",
    default_model_name="gpt-5.5",
    env_source_path="/root/.copilot_env",
    model_env_key="COPILOT_MODEL",
    build_env=build_env,
    build_command=build_command,
)

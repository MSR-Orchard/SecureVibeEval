from __future__ import annotations

import os
import sys
from pathlib import Path

BUNDLE_DIR = Path(__file__).resolve().parents[3]
if str(BUNDLE_DIR) not in sys.path:
    sys.path.insert(0, str(BUNDLE_DIR))

from harness.common.config import BackendConfig, merged_env


LOCAL_ENV = Path(__file__).with_name(".env")


ALLOWED_TOOLS = [
    "Bash",
    "Edit",
    "Write",
    "Read",
    "Glob",
    "Grep",
    "LS",
    "WebFetch",
    "NotebookEdit",
    "NotebookRead",
    "TodoRead",
    "TodoWrite",
    "Agent",
]


def build_env() -> dict:
    source = merged_env(LOCAL_ENV)
    return {
        "ANTHROPIC_MODEL": source.get("ANTHROPIC_MODEL", ""),
        "ANTHROPIC_BASE_URL": source.get("ANTHROPIC_BASE_URL", ""),
        "ANTHROPIC_AUTH_TOKEN": source.get("ANTHROPIC_AUTH_TOKEN", ""),
        "ANTHROPIC_API_KEY": source.get("ANTHROPIC_API_KEY", ""),
        "CLAUDE_CODE_MAX_OUTPUT_TOKENS": source.get(
            "CLAUDE_CODE_MAX_OUTPUT_TOKENS", "50000"
        ),
    }


def build_command(escaped_instruction: str, env: dict) -> str:
    return (
        "claude --verbose --output-format stream-json "
        f"-p {escaped_instruction} --allowedTools {' '.join(ALLOWED_TOOLS)}"
    )


CONFIG = BackendConfig(
    key="claude",
    display_name="Claude",
    default_model_name="claude-sonnet-4-20250514",
    env_source_path="/root/.claude_env",
    model_env_key="ANTHROPIC_MODEL",
    build_env=build_env,
    build_command=build_command,
)

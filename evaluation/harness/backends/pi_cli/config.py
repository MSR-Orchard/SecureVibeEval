from __future__ import annotations

import shlex
import sys
from pathlib import Path

BUNDLE_DIR = Path(__file__).resolve().parents[3]
if str(BUNDLE_DIR) not in sys.path:
    sys.path.insert(0, str(BUNDLE_DIR))

from harness.common.config import BackendConfig, merged_env
from harness.backends.pi_cli.results import normalize_result


LOCAL_ENV = Path(__file__).with_name(".env")


def build_env() -> dict:
    source = merged_env(LOCAL_ENV)
    return {
        "PI_PROVIDER": source.get("PI_PROVIDER", "copilot_proxy"),
        "PI_MODEL": source.get("PI_MODEL", "claude-opus-4.8"),
        "PI_PROXY_BASE_URL": source.get(
            "PI_PROXY_BASE_URL", "http://127.0.0.1:8080"
        ),
        "PI_API_KEY": source.get("PI_API_KEY", "proxy-handles-auth"),
        "PI_THINKING": source.get("PI_THINKING", ""),
        "PI_MODELS_CONFIG": source.get("PI_MODELS_CONFIG", ""),
        "PI_OFFLINE": source.get("PI_OFFLINE", "1"),
    }


def build_command(escaped_instruction: str, env: dict) -> str:
    thinking_arg = (
        f" --thinking {shlex.quote(env['PI_THINKING'])}"
        if env.get("PI_THINKING")
        else ""
    )
    return (
        "pi --mode json --print --no-session --approve "
        "--no-extensions --no-skills --no-prompt-templates "
        f"--provider {shlex.quote(env['PI_PROVIDER'])} "
        f"--model {shlex.quote(env['PI_MODEL'])}"
        f"{thinking_arg} {escaped_instruction}"
    )


CONFIG = BackendConfig(
    key="pi",
    display_name="Pi",
    default_model_name="claude-opus-4.8",
    env_source_path="/root/.pi_env",
    model_env_key="PI_MODEL",
    build_env=build_env,
    build_command=build_command,
    normalize_result=normalize_result,
)

from __future__ import annotations

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
    env = {
        "GEMINI_MODEL": source.get("GEMINI_MODEL", ""),
        "GEMINI_API_KEY": source.get("GEMINI_API_KEY", ""),
        "GOOGLE_API_KEY": source.get("GOOGLE_API_KEY", ""),
        "GOOGLE_GEMINI_BASE_URL": source.get("GOOGLE_GEMINI_BASE_URL", ""),
        "GOOGLE_VERTEX_BASE_URL": source.get("GOOGLE_VERTEX_BASE_URL", ""),
        "GOOGLE_GENAI_USE_VERTEXAI": source.get("GOOGLE_GENAI_USE_VERTEXAI", ""),
        "GOOGLE_GENAI_USE_GCA": source.get("GOOGLE_GENAI_USE_GCA", ""),
        "GOOGLE_CLOUD_PROJECT": source.get("GOOGLE_CLOUD_PROJECT", ""),
        "GOOGLE_CLOUD_LOCATION": source.get("GOOGLE_CLOUD_LOCATION", ""),
    }
    has_auth = any(
        env[key]
        for key in (
            "GEMINI_API_KEY",
            "GOOGLE_API_KEY",
            "GOOGLE_GEMINI_BASE_URL",
            "GOOGLE_GENAI_USE_VERTEXAI",
            "GOOGLE_GENAI_USE_GCA",
        )
    )
    if not has_auth:
        raise RuntimeError(
            "Gemini CLI requires GEMINI_API_KEY/GOOGLE_API_KEY, "
            "GOOGLE_GEMINI_BASE_URL, GOOGLE_GENAI_USE_VERTEXAI, or "
            "GOOGLE_GENAI_USE_GCA. Set one in the environment or "
            "harness/backends/gemini_cli/.env."
        )
    return env


def build_command(escaped_instruction: str, env: dict) -> str:
    return f"gemini --output-format stream-json --model {shlex.quote(env['GEMINI_MODEL'])} -p {escaped_instruction} --yolo"


CONFIG = BackendConfig(
    key="gemini",
    display_name="Gemini",
    default_model_name="gemini-3-pro-preview",
    env_source_path="/root/.gemini/.env",
    model_env_key="GEMINI_MODEL",
    build_env=build_env,
    build_command=build_command,
)

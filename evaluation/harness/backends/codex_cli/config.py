from __future__ import annotations

import os
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
        "CODEX_MODEL": source.get("CODEX_MODEL", "gpt-5.5"),
        "CODEX_PROXY_BASE_URL": source.get(
            "CODEX_PROXY_BASE_URL", "http://127.0.0.1:8080/v1"
        ),
        # The harness already runs Codex inside a per-task Docker container. Using
        # Codex's Linux workspace sandbox inside that container requires bwrap/user
        # namespaces that many of the eval images do not allow.
        "CODEX_SANDBOX": source.get("CODEX_SANDBOX", "danger-full-access"),
    }
    codex_api_key = source.get("CODEX_API_KEY") or source.get("OPENAI_API_KEY")
    if codex_api_key:
        env["CODEX_API_KEY"] = codex_api_key
    elif env["CODEX_PROXY_BASE_URL"]:
        env["CODEX_API_KEY"] = "proxy-handles-auth"
    return env


def build_command(escaped_instruction: str, env: dict) -> str:
    model_arg = (
        f" --model {shlex.quote(env['CODEX_MODEL'])}"
        if env["CODEX_MODEL"]
        else ""
    )
    config_args = " ".join(
        f"-c {shlex.quote(item)}"
        for item in (
            'model_provider="local_proxy"',
            'model_providers.local_proxy.name="local_proxy"',
            f'model_providers.local_proxy.base_url="{env["CODEX_PROXY_BASE_URL"]}"',
            'model_providers.local_proxy.env_key="CODEX_API_KEY"',
            'model_providers.local_proxy.wire_api="responses"',
        )
    )
    sandbox = shlex.quote(env.get("CODEX_SANDBOX", "danger-full-access"))
    return (
        f"codex --ask-for-approval never exec --json --sandbox {sandbox} "
        f"{config_args}"
        f"{model_arg} {escaped_instruction}"
    )


CONFIG = BackendConfig(
    key="codex",
    display_name="Codex",
    default_model_name="gpt-5.5",
    env_source_path="/root/.codex_env",
    model_env_key="CODEX_MODEL",
    build_env=build_env,
    build_command=build_command,
)

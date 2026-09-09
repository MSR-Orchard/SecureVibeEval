from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shlex
from typing import Callable, Dict


EnvBuilder = Callable[[], Dict[str, str]]
CommandBuilder = Callable[[str, Dict[str, str]], str]


@dataclass(frozen=True)
class BackendConfig:
    key: str
    display_name: str
    default_model_name: str
    env_source_path: str
    build_env: EnvBuilder
    build_command: CommandBuilder
    model_env_key: str = ""
    normalize_result: Callable[[dict], dict] = lambda result: result

    def resolve_env(self, model: str | None = None) -> Dict[str, str]:
        env = dict(self.build_env())
        if self.model_env_key:
            env[self.model_env_key] = (
                model or env.get(self.model_env_key) or self.default_model_name
            )
        return env

    def model_name(self, env: Dict[str, str]) -> str:
        return env.get(self.model_env_key) or self.default_model_name

    @property
    def workspace_prefix(self) -> str:
        return f"{self.key}_workspace"

    @property
    def container_prefix(self) -> str:
        return f"{self.key}_work"

    @property
    def stdout_key(self) -> str:
        return f"{self.key}_stdout"

    @property
    def stderr_key(self) -> str:
        return f"{self.key}_stderr"

    @property
    def success_key(self) -> str:
        return f"{self.key}_success"


def load_env_file(path: Path) -> Dict[str, str]:
    env = {}
    if not path.exists():
        return env

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        try:
            env[key] = shlex.split(value, comments=True)[0]
        except (IndexError, ValueError):
            env[key] = value.strip("\"'")
    return env


def merged_env(env_file: Path) -> Dict[str, str]:
    return {**load_env_file(env_file), **dict(os.environ)}

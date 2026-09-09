"""Execution environments, loaded only when selected."""

from pathlib import Path
from typing import Protocol

EXECUTION_BACKENDS = ("docker", "sandbox")


class ExecutionEnvironment(Protocol):
    keep_workspace: bool

    def setup_persistent_workspace(self) -> Path: ...
    def setup_cli_env(
        self, setup_script_path: str = "setup-env.sh", env: dict | None = None
    ) -> dict: ...
    def execute_in_container(self, command: str, env: dict | None = None) -> dict: ...
    def sync_workspace_to_local(self) -> dict: ...
    def cleanup(self): ...
    def __enter__(self) -> "ExecutionEnvironment": ...
    def __exit__(self, exc_type, exc_val, exc_tb): ...


def integration_class(execution_backend: str) -> type[ExecutionEnvironment]:
    if execution_backend == "docker":
        from .docker import DockerIntegration

        return DockerIntegration
    if execution_backend == "sandbox":
        from .sandbox import SandboxIntegration

        return SandboxIntegration
    raise ValueError(
        f"Unknown execution backend {execution_backend!r}; expected one of {EXECUTION_BACKENDS}"
    )


def setup_dependency_files(setup_file: Path) -> list[Path]:
    """Return an optional complete npm manifest pair for a CLI setup script."""
    files = [setup_file.with_name(name) for name in ("package.json", "package-lock.json")]
    if not any(path.exists() for path in files):
        return []  # Custom setup scripts need not use npm.
    if not all(path.is_file() for path in files):
        raise FileNotFoundError("CLI setup requires both package.json and package-lock.json")
    return files

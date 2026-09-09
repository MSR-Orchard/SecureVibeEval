from __future__ import annotations

from pathlib import Path
import sys

BUNDLE_DIR = Path(__file__).resolve().parents[3]
if str(BUNDLE_DIR) not in sys.path:
    sys.path.insert(0, str(BUNDLE_DIR))

from harness.backends.codex_cli import prompts
from harness.backends.codex_cli.config import CONFIG
from harness.common.docker import DockerIntegration as _DockerIntegration
from harness.common.single import run_single
from harness.benchmarks.susvibes import ADDITIONAL_INSTRUCTIONS, EXAMPLE_IMAGE, EXAMPLE_TASK, USER_PROMPT_TEMPLATE


class DockerIntegration(_DockerIntegration):
    def __init__(
        self,
        docker_image: str,
        container_work_dir: str = "/project",
        workspace_root: str = ".",
        keep_workspace: bool = False,
    ):
        super().__init__(
            docker_image,
            CONFIG,
            container_work_dir=container_work_dir,
            workspace_root=workspace_root,
            keep_workspace=keep_workspace,
        )


def main():
    return run_single(CONFIG, prompts, setup_script=str(Path(__file__).with_name("setup-env.sh")))


if __name__ == "__main__":
    main()

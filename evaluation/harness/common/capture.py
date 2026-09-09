import logging
import shlex
import subprocess
from .config import BackendConfig
from .instances import DEFAULT_CONTAINER_WORK_DIR

logger = logging.getLogger(__name__)


def patch_applies_clean(
    image_name: str,
    patch_text: str,
    work_dir: str = DEFAULT_CONTAINER_WORK_DIR,
    execution_backend: str = "docker",
    config: BackendConfig = None,
) -> bool:
    if not patch_text.strip():
        return False
    if execution_backend == "sandbox":
        from ..execution.sandbox import patch_applies_clean_sandbox

        if config is None:
            raise ValueError("config is required for sandbox patch verification")
        try:
            return patch_applies_clean_sandbox(image_name, patch_text, work_dir, config)
        except Exception as e:
            logger.warning(f"Sandbox patch apply --check errored: {e}")
            return False
    try:
        quoted_work_dir = shlex.quote(work_dir)
        proc = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "-w",
                work_dir,
                image_name,
                "sh",
                "-c",
                f"git config --global --add safe.directory {quoted_work_dir} >/dev/null 2>&1; "
                "git apply --check --ignore-space-change -",
            ],
            input=patch_text,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if proc.returncode != 0:
            logger.warning(f"Patch apply --check failed: {proc.stderr.strip()[:300]}")
        return proc.returncode == 0
    except Exception as e:
        logger.warning(f"Patch apply --check errored: {e}")
        return False

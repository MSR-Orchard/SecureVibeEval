"""Single demonstration task using the standard instance lifecycle."""

import asyncio
import os
from pathlib import Path

from .batch import process_instance


def run_single(
    config, prompts_module, execution_backend=None, setup_script="setup-env.sh"
):
    execution_backend = (
        execution_backend or os.environ.get("CLI_HARNESS_EXECUTION_BACKEND") or "docker"
    )
    instance = {
        "instance_id": "example",
        "image_name": prompts_module.EXAMPLE_IMAGE,
        "problem_statement": prompts_module.EXAMPLE_TASK,
    }
    if hasattr(prompts_module, "EXAMPLE_WORK_DIR"):
        instance["container_work_dir"] = prompts_module.EXAMPLE_WORK_DIR
    env = config.resolve_env()
    result = asyncio.run(
        process_instance(
            instance,
            0,
            1,
            config.model_name(env),
            config,
            prompts_module,
            setup_script=setup_script,
            keep_workspace=True,
            execution_backend=execution_backend,
            agent_env=env,
        )
    )
    if not result.get(config.success_key, False):
        raise RuntimeError(f"Example task failed: {result.get('capture_status')}")
    return Path(result["workspace"])

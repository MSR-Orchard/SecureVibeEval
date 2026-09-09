from __future__ import annotations

import asyncio
import json
import logging
import shlex
import time
from pathlib import Path
from typing import Any, Dict, List

from .config import BackendConfig
from ..cli import get_options, STRATEGY_CHOICES
from ..execution import integration_class, EXECUTION_BACKENDS
from .instances import (
    guard_instances,
    load_instances,
    select_instances,
    get_instance_id,
    get_image_name,
    get_container_work_dir,
    DEFAULT_CONTAINER_WORK_DIR,
)
from .prompts import build_prompt
from .capture import patch_applies_clean
from .results import load_records, merge_records

logger = logging.getLogger(__name__)


def normalize_agent_result(config, result):
    return config.normalize_result(result)


def configure_logging(log_file: str = "docker_batch_run.log"):
    root_logger = logging.getLogger()
    if root_logger.handlers:
        return
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(),
        ],
    )


async def process_instance(
    instance: Dict[str, Any],
    index: int,
    total: int,
    model: str,
    config: BackendConfig,
    prompts_module,
    workspace_root: str = ".",
    setup_script: str = "setup-env.sh",
    keep_workspace: bool = False,
    patches_dir: Path = None,
    benchmark_output_root: Path = None,
    execution_backend: str = "docker",
    agent_env: dict | None = None,
) -> Dict[str, Any]:
    instance_id = get_instance_id(instance, index, prompts_module)
    image_name = get_image_name(instance, prompts_module)
    problem_statement = instance.get("problem_statement", "")
    container_work_dir = get_container_work_dir(instance, prompts_module)
    workspace = None

    logger.info(f"Processing instance {index + 1}/{total}: {instance_id}")

    if not image_name:
        logger.error(f"No image_name found for instance {instance_id}")
        return {
            "instance_id": instance_id,
            "model_name_or_path": model,
            "model_patch": "",
            "capture_status": "no_image",
            "error": "No image_name found",
        }

    if not problem_statement:
        logger.error(f"No problem_statement found for instance {instance_id}")
        return {
            "instance_id": instance_id,
            "model_name_or_path": model,
            "model_patch": "",
            "capture_status": "no_problem_statement",
            "error": "No problem_statement found",
        }

    try:
        logger.info(f"Starting {execution_backend} integration for {instance_id}")

        env = config.resolve_env(model) if agent_env is None else agent_env
        logger.info(
            f"Environment variables set for {instance_id}: {_summarize_env(env)}"
        )

        full_prompt = build_prompt(prompts_module, instance, container_work_dir)
        escaped_instruction = shlex.quote(full_prompt)

        integration_cls = integration_class(execution_backend)
        with integration_cls(
            image_name,
            config,
            container_work_dir=container_work_dir,
            workspace_root=workspace_root,
            keep_workspace=keep_workspace,
            allow_missing_workdir=getattr(
                prompts_module, "ALLOW_MISSING_WORKDIR", False
            ),
        ) as integration:
            print("🔧 Setting up environment...")
            workspace = integration.setup_persistent_workspace()

            setup_result = integration.setup_cli_env(
                setup_script_path=setup_script,
                env=env,
            )

            if not setup_result["success"]:
                logger.warning(
                    f"Environment setup failed for {instance_id}: "
                    f"{setup_result['stderr']}"
                )
                return {
                    "instance_id": instance_id,
                    "model_name_or_path": model,
                    "model_patch": "",
                    "workspace": str(workspace),
                    "container_work_dir": container_work_dir,
                    "patch_file": None,
                    "capture_status": "setup_failed",
                    config.stdout_key: setup_result.get("stdout", ""),
                    config.stderr_key: setup_result.get("stderr", ""),
                    config.success_key: False,
                }

            logger.info(f"Running {config.display_name} for {instance_id}")
            command = config.build_command(escaped_instruction, env)
            result = normalize_agent_result(
                config,
                integration.execute_in_container(command, env=env),
            )

            if result["success"]:
                logger.info(
                    f"{config.display_name} execution completed successfully "
                    f"for {instance_id}"
                )
            else:
                logger.error(
                    f"{config.display_name} execution failed for {instance_id}: "
                    f"{result['stderr']}"
                )

            print("\n🎉 Session complete!")
            print(f"📁 Your improved code is at: {workspace}")

            capture_diff = getattr(prompts_module, "CAPTURE_DIFF", True)
            artifact_sync_result = None
            if capture_diff:
                quoted_work_dir = shlex.quote(container_work_dir)
                diff_result = integration.execute_in_container(
                    f"git config --global --add safe.directory {quoted_work_dir} && "
                    f"git -C {quoted_work_dir} add -A -N && "
                    f"git -C {quoted_work_dir} diff"
                )
                diff_text = diff_result["stdout"]
            else:
                diff_result = {
                    "success": True,
                    "stdout": "",
                    "stderr": "",
                    "return_code": 0,
                }
                diff_text = ""
                if hasattr(integration, "sync_workspace_to_local"):
                    try:
                        artifact_sync_result = integration.sync_workspace_to_local()
                    except Exception as e:
                        artifact_sync_result = {
                            "success": False,
                            "error": str(e),
                        }
                    if not artifact_sync_result.get("success"):
                        logger.error(
                            f"Failed to synchronize generated artifacts for "
                            f"{instance_id}: {artifact_sync_result.get('error', '')}"
                        )

            patch_file = None
            if capture_diff and patches_dir is not None:
                patches_dir.mkdir(parents=True, exist_ok=True)
                patch_file = patches_dir / f"{instance_id.replace('/', '__')}.patch"
                try:
                    patch_file.write_text(diff_text)
                except Exception as e:
                    logger.error(f"Failed to persist patch file for {instance_id}: {e}")
                    patch_file = None

            agent_ok = result.get("success", False)
            if not capture_diff:
                if artifact_sync_result is not None and not artifact_sync_result.get(
                    "success"
                ):
                    capture_status = "artifact_sync_failed"
                else:
                    capture_status = (
                        "captured_artifact" if agent_ok else "artifact_agent_failed"
                    )
            elif not diff_result["success"]:
                capture_status = "capture_failed"
                logger.error(
                    f"Failed to capture git diff for {instance_id} "
                    f"(exit {diff_result['return_code']}): "
                    f"{diff_result['stderr'].strip()}"
                )
            elif not diff_text.strip():
                capture_status = "empty_no_change" if agent_ok else "empty_agent_failed"
                logger.warning(
                    f"Empty git diff for {instance_id} (status={capture_status}, "
                    f"{config.success_key}={agent_ok})."
                )
            elif patch_applies_clean(
                image_name,
                diff_text,
                container_work_dir,
                execution_backend=execution_backend,
                config=config,
            ):
                capture_status = "captured"
            else:
                capture_status = "captured_unverified"
                logger.error(
                    f"Captured patch for {instance_id} does NOT apply cleanly to the "
                    "pristine image; keeping workspace for inspection."
                )

            suspect = capture_status in (
                "capture_failed",
                "captured_unverified",
                "artifact_sync_failed",
            )
            if suspect:
                integration.keep_workspace = True
                logger.warning(
                    f"Preserving workspace for {instance_id} "
                    f"(capture_status={capture_status}): {workspace}"
                )

            result_dict = {
                "instance_id": instance_id,
                "model_name_or_path": model,
                "model_patch": diff_text,
                "workspace": str(workspace),
                "container_work_dir": container_work_dir,
                "execution_backend": execution_backend,
                "patch_file": str(patch_file) if patch_file else None,
                "capture_status": capture_status,
                config.stdout_key: result.get("stdout", ""),
                config.stderr_key: result.get("stderr", ""),
                config.success_key: agent_ok,
            }

            if (
                hasattr(prompts_module, "postprocess_result")
                and capture_status != "artifact_sync_failed"
            ):
                result_dict = prompts_module.postprocess_result(
                    result_dict,
                    instance=instance,
                    workspace=workspace,
                    integration=integration,
                    model=model,
                    benchmark_output_root=benchmark_output_root,
                )

            logger.info(
                f"Successfully processed {instance_id} "
                f"(capture_status={capture_status})"
            )
            return result_dict
    except Exception as e:
        logger.error(f"Error processing instance {instance_id}: {e}")
        return {
            "instance_id": instance_id,
            "model_name_or_path": model,
            "model_patch": "",
            "capture_status": "exception",
            "error": str(e),
            "workspace": str(workspace),
        }


async def main(args, config: BackendConfig, prompts_module):
    configure_logging()

    jsonl_file = args.jsonl_file
    env = config.resolve_env(args.model)
    model = config.model_name(env)
    args.model = model
    workspace_root = Path(args.workspace_root)
    setup_script = args.setup_script
    execution_backend = getattr(args, "execution_backend", "docker")

    instances = load_instances(jsonl_file)
    if not instances:
        logger.error("No instances to process")
        raise SystemExit(1)

    instances = guard_instances(instances, args.strategy, args.feedback_tool)
    instances = select_instances(instances, args, prompts_module)

    if not instances:
        if args.load_from_file:
            logger.info("No remaining instances to process")
            return
        logger.error("No instances remain after filtering and slicing")
        raise SystemExit(1)

    logger.info(f"Starting processing of {len(instances)} instances")

    timestamp = int(time.time())
    if args.timestamp_suffix:
        timestamp_str = f"{timestamp}_{args.timestamp_suffix}"
    else:
        timestamp_str = str(timestamp)
    workspace_root.mkdir(parents=True, exist_ok=True)
    results_dir = Path(args.results_dir, model, timestamp_str)
    results_dir.mkdir(parents=True, exist_ok=True)

    patches_dir = Path(args.results_dir, model, "patches")
    patches_dir.mkdir(parents=True, exist_ok=True)

    results = load_records(Path(args.load_from_file)) if args.load_from_file else []
    for i, instance in enumerate(instances):
        try:
            result = await process_instance(
                instance,
                i,
                len(instances),
                model,
                config,
                prompts_module,
                workspace_root=workspace_root,
                setup_script=setup_script,
                keep_workspace=args.keep_workspace,
                patches_dir=patches_dir,
                benchmark_output_root=Path(args.results_dir, model),
                execution_backend=execution_backend,
                agent_env=env,
            )

            intermediate_file = results_dir / f"intermediate_{i + 1}.json"
            with open(intermediate_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            logger.info(f"Saved intermediate results to {intermediate_file}")

            results = merge_records(results, [result])
        except KeyboardInterrupt:
            logger.info("Processing interrupted by user")
            break
        except Exception as e:
            logger.error(f"Unexpected error processing instance {i}: {e}")
            continue

    output_file = results_dir / "final_results.json"

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    if hasattr(prompts_module, "finalize_results"):
        prompts_module.finalize_results(
            results,
            results_dir=results_dir,
            benchmark_output_root=Path(args.results_dir, model),
            args=args,
            model=model,
        )

    logger.info(f"Processing complete. Results saved to {output_file}")
    logger.info(f"Processed {len(results)} instances successfully")


def run_cli(config: BackendConfig, prompts_module):
    args = get_options(config).parse_args()
    asyncio.run(main(args, config, prompts_module))


def _summarize_env(env: Dict[str, str]) -> str:
    parts = []
    for key, value in env.items():
        if "TOKEN" in key or "KEY" in key:
            parts.append(f"{key}={'***' if value else ''}")
        else:
            parts.append(f"{key}={value}")
    return ", ".join(parts)

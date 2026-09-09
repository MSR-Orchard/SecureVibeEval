from __future__ import annotations

import json
import logging
import multiprocessing
import importlib
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..cli import get_parallel_options as get_options
from .instances import guard_instances, load_instances, select_instances
from .results import (
    _model_results_dir,
    _find_process_final_results,
    _load_results_list,
    load_records as _load_records,
    merge_final_results,
)
from .config import BackendConfig

logger = logging.getLogger(__name__)


def configure_logging(log_file: str = "parallel_batch_run.log"):
    root_logger = logging.getLogger()
    if root_logger.handlers:
        return
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(process)d - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(),
        ],
    )


def run_batch_process(
    process_id: int,
    start_idx: int,
    num_instances: int,
    jsonl_file: str,
    results_dir: str,
    workspace_root: str,
    model: str,
    setup_script: str,
    python_executable: str,
    batch_script: str = "batch_run_docker.py",
    keep_workspace: bool = False,
    temp_jsonl: str = None,
    execution_backend: str = "docker",
) -> Dict[str, Any]:
    logger.info(
        f"Process {process_id}: Starting to process {num_instances} instances "
        f"from index {start_idx}"
    )

    process_workspace = Path(f"{workspace_root}_process_{process_id}").resolve()
    if not process_workspace.exists():
        logger.info(
            f"Process {process_id}: Creating workspace directory: {process_workspace}"
        )
        process_workspace.mkdir(parents=True, exist_ok=True)

    target_jsonl = temp_jsonl if temp_jsonl else jsonl_file

    cmd = [
        python_executable,
        *(shlex.split(batch_script) if isinstance(batch_script, str) else batch_script),
        "--jsonl_file",
        target_jsonl,
        "--results_dir",
        results_dir,
        "--workspace_root",
        str(process_workspace),
        "--num_instances",
        str(num_instances),
        "--model",
        model,
        "--setup_script",
        setup_script,
        "--timestamp_suffix",
        f"process{process_id}",
    ]
    if keep_workspace:
        cmd.append("--keep_workspace")
    cmd.extend(["--execution_backend", execution_backend])

    start_time = time.time()

    try:
        logger.info(f"Process {process_id}: Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=".")
        elapsed_time = time.time() - start_time

        if result.returncode == 0:
            final_results_file = _find_process_final_results(
                results_dir, model, process_id, start_time
            )
            logger.info(
                f"Process {process_id}: Completed successfully in "
                f"{elapsed_time:.2f} seconds"
            )
            return {
                "process_id": process_id,
                "start_idx": start_idx,
                "num_instances": num_instances,
                "success": True,
                "elapsed_time": elapsed_time,
                "returncode": result.returncode,
                "final_results_file": (
                    str(final_results_file) if final_results_file else None
                ),
            }

        final_results_file = _find_process_final_results(
            results_dir, model, process_id, start_time
        )
        logger.error(
            f"Process {process_id}: Failed with return code "
            f"{result.returncode}\nStderr: {result.stderr}"
        )
        return {
            "process_id": process_id,
            "start_idx": start_idx,
            "num_instances": num_instances,
            "success": False,
            "elapsed_time": elapsed_time,
            "returncode": result.returncode,
            "stderr": result.stderr,
            "final_results_file": (
                str(final_results_file) if final_results_file else None
            ),
        }
    except Exception as e:
        elapsed_time = time.time() - start_time
        logger.error(f"Process {process_id}: Exception occurred: {e}")
        return {
            "process_id": process_id,
            "start_idx": start_idx,
            "num_instances": num_instances,
            "success": False,
            "elapsed_time": elapsed_time,
            "error": str(e),
        }


def main(args, config: BackendConfig | None = None):
    configure_logging()
    if config is None:
        from ..registry import load_config

        config = load_config(args.backend)
    args.model = config.model_name(config.resolve_env(args.model))

    Path("logs").mkdir(exist_ok=True)

    logger.info("=" * 80)
    logger.info("Parallel CLI Batch Runner")
    logger.info("=" * 80)

    instances = load_instances(args.jsonl_file)
    if not instances:
        logger.error("No instances found in dataset")
        sys.exit(1)

    logger.info(f"Total instances in dataset: {len(instances)}")
    instances = guard_instances(instances, args.strategy, args.feedback_tool)
    adapter_module = getattr(args, "adapter_module", None)
    adapter = importlib.import_module(adapter_module) if adapter_module else None
    instances = select_instances(instances, args, adapter)

    if not instances:
        if args.load_from_file:
            logger.info("No remaining instances to process")
            return
        logger.error(
            f"No instances to process after filtering (start_idx={args.start_idx}, "
            f"num_instances={args.num_instances})"
        )
        sys.exit(1)

    total_to_process = len(instances)
    logger.info(
        f"Processing {total_to_process} instances (after filtering and slicing)"
    )
    logger.info(f"Using {args.num_processes} parallel processes")

    instances_per_process = total_to_process // args.num_processes
    remainder = total_to_process % args.num_processes

    runtime_root = Path(args.workspace_root).resolve().parent
    temp_dir = runtime_root / "temp_parallel"
    temp_dir.mkdir(parents=True, exist_ok=True)
    timestamp = int(time.time())

    tasks = []
    current_idx = 0

    for i in range(args.num_processes):
        num_for_this_process = instances_per_process + (1 if i < remainder else 0)

        if num_for_this_process > 0:
            process_instances = instances[
                current_idx : current_idx + num_for_this_process
            ]
            temp_jsonl = temp_dir / f"process_{i}_{timestamp}.jsonl"
            with open(temp_jsonl, "w", encoding="utf-8") as f:
                for instance in process_instances:
                    f.write(json.dumps(instance, ensure_ascii=False) + "\n")

            tasks.append(
                {
                    "process_id": i,
                    "start_idx": 0,
                    "num_instances": num_for_this_process,
                    "temp_jsonl": str(temp_jsonl),
                }
            )
            current_idx += num_for_this_process

    logger.info("\nTask distribution:")
    for task in tasks:
        logger.info(
            f"  Process {task['process_id']}: "
            f"{task['num_instances']} instances in {task['temp_jsonl']}"
        )
    logger.info("")

    logger.info("\nPre-creating workspace directories...")
    for i in range(args.num_processes):
        workspace_dir = Path(f"{args.workspace_root}_process_{i}").resolve()
        if not workspace_dir.exists():
            workspace_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"  Created: {workspace_dir}")
        else:
            logger.info(f"  Already exists: {workspace_dir}")
    logger.info("")

    start_time = time.time()

    with multiprocessing.Pool(processes=args.num_processes) as pool:
        async_results = []
        for i, task in enumerate(tasks):
            if i > 0:
                logger.info(
                    f"Waiting 1 second before starting process {task['process_id']}..."
                )
                time.sleep(1)

            result = pool.apply_async(
                run_batch_process,
                args=(
                    task["process_id"],
                    task["start_idx"],
                    task["num_instances"],
                    args.jsonl_file,
                    args.results_dir,
                    args.workspace_root,
                    args.model,
                    args.setup_script,
                    args.python_executable,
                    args.batch_script,
                    args.keep_workspace,
                    task.get("temp_jsonl"),
                    args.execution_backend,
                ),
            )
            async_results.append(result)

        results = []
        for async_result in async_results:
            try:
                result = async_result.get()
                results.append(result)
            except Exception as e:
                logger.error(f"Error getting result from process: {e}")
                results.append({"success": False, "error": str(e)})

    total_elapsed = time.time() - start_time

    logger.info("\n" + "=" * 80)
    logger.info("SUMMARY")
    logger.info("=" * 80)
    logger.info(f"Total elapsed time: {total_elapsed:.2f} seconds")

    successful = sum(1 for r in results if r.get("success", False))
    failed = len(results) - successful

    logger.info(f"Successful processes: {successful}/{len(results)}")
    logger.info(f"Failed processes: {failed}/{len(results)}")

    for result in results:
        status = "✓" if result.get("success", False) else "✗"
        logger.info(
            f"  {status} Process {result.get('process_id', '?')}: "
            f"{result.get('elapsed_time', 0):.2f}s"
        )

    merged_results_file = merge_final_results(
        results,
        args.results_dir,
        args.model,
        load_from_file=args.load_from_file,
    )
    if adapter_module:
        try:
            if adapter is None:
                adapter = importlib.import_module(adapter_module)
            if hasattr(adapter, "finalize_results"):
                merged_rows = _load_results_list(merged_results_file)
                benchmark_output_root = _model_results_dir(args.results_dir, args.model)
                adapter.finalize_results(
                    merged_rows,
                    benchmark_output_root,
                    benchmark_output_root,
                    args,
                    args.model,
                )
                logger.info(
                    f"Wrote merged benchmark outputs using adapter {adapter_module}"
                )
        except Exception as e:
            logger.warning(
                f"Could not write merged benchmark outputs with {adapter_module}: {e}"
            )

    summary_dir = runtime_root / "summaries"
    summary_dir.mkdir(parents=True, exist_ok=True)
    summary_file = summary_dir / f"parallel_run_summary_{int(time.time())}.json"
    with open(summary_file, "w") as f:
        json.dump(
            {
                "total_elapsed": total_elapsed,
                "num_processes": args.num_processes,
                "total_instances": total_to_process,
                "merged_final_results": str(merged_results_file),
                "results": results,
            },
            f,
            indent=2,
        )

    logger.info(f"\nSummary saved to: {summary_file}")
    logger.info(f"Merged final results saved to: {merged_results_file}")

    logger.info("\nCleaning up temporary files...")
    for task in tasks:
        temp_file = task.get("temp_jsonl")
        if temp_file and Path(temp_file).exists():
            try:
                Path(temp_file).unlink()
                logger.info(f"  Removed: {temp_file}")
            except Exception as e:
                logger.warning(f"  Failed to remove {temp_file}: {e}")

    try:
        if temp_dir.exists() and not any(temp_dir.iterdir()):
            temp_dir.rmdir()
            logger.info(f"  Removed empty directory: {temp_dir}")
    except Exception as e:
        logger.debug(f"  Could not remove temp directory: {e}")

    logger.info("=" * 80)

    if failed > 0:
        sys.exit(1)


def run_cli(config: BackendConfig):
    args = get_options(config).parse_args()
    main(args, config)

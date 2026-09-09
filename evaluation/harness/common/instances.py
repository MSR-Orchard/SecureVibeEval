from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)
DEFAULT_CONTAINER_WORK_DIR = "/project"


def guard_instances(
    instances: List[Dict[str, Any]],
    strategy: str,
    feedback_tool: str = None,
) -> List[Dict[str, Any]]:
    if strategy == "none":
        return instances
    grading_root = Path(__file__).resolve().parents[2] / "grader/susvibes"
    if str(grading_root) not in sys.path:
        sys.path.insert(0, str(grading_root))
    from susvibes.strategies.tools import get_guardrail

    for instance in instances:
        instance["problem_statement"] = get_guardrail(
            instance.get("problem_statement", ""),
            strategy,
            instance.get("cwe_ids", []),
            instances,
            feedback_tool,
            instance.get("test_patch"),
        )
    logger.info(f"Applied '{strategy}' guardrail to {len(instances)} instances")
    return instances


def get_instance_id(instance: Dict[str, Any], index: int, prompts_module=None) -> str:
    if prompts_module and hasattr(prompts_module, "get_instance_id"):
        return prompts_module.get_instance_id(instance, index)
    return (
        instance.get("instance_id")
        or instance.get("cve_id")
        or instance.get("id")
        or f"unknown_{index}"
    )


def get_image_name(instance: Dict[str, Any], prompts_module=None) -> str:
    if prompts_module and hasattr(prompts_module, "get_image_name"):
        return prompts_module.get_image_name(instance)
    return (
        instance.get("image_name")
        or instance.get("agent_image")
        or instance.get("agent_image_remote")
        or ""
    )


def get_container_work_dir(instance: Dict[str, Any], prompts_module=None) -> str:
    if prompts_module and hasattr(prompts_module, "get_container_work_dir"):
        return prompts_module.get_container_work_dir(instance)
    return (
        instance.get("container_work_dir")
        or instance.get("cwd")
        or instance.get("work_dir")
        or instance.get("code_workdir")
        or DEFAULT_CONTAINER_WORK_DIR
    )


def load_instances(jsonl_file: str) -> List[Dict[str, Any]]:
    try:
        text = Path(jsonl_file).read_text(encoding="utf-8")
        stripped = text.lstrip()
        if stripped.startswith("["):
            data = json.loads(text)
            if not isinstance(data, list):
                logger.error(f"Expected JSON list in {jsonl_file}")
                return []
            instances = data
        else:
            instances = []
            for line_num, line in enumerate(text.splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    instances.append(json.loads(line))
                except json.JSONDecodeError as e:
                    logger.error(f"Error parsing line {line_num}: {e}")
                    continue
        logger.info(f"Loaded {len(instances)} instances from {jsonl_file}")
        return instances
    except FileNotFoundError:
        logger.error(f"File not found: {jsonl_file}")
        return []
    except Exception as e:
        logger.error(f"Error loading instances: {e}")
        return []


def select_instances(instances, args, adapter=None):
    """Apply benchmark filtering, canonical resume IDs, then slicing in both runners."""
    # Assign IDs before filtering/sharding so fallback IDs remain stable in workers.
    instances = [
        dict(row, instance_id=get_instance_id(row, i, adapter))
        for i, row in enumerate(instances)
    ]
    if adapter is not None and hasattr(adapter, "filter_instances"):
        instances = adapter.filter_instances(instances, args)
    if args.load_from_file:
        from .results import load_records

        completed = {
            row["instance_id"]
            for row in load_records(Path(args.load_from_file))
            if row.get("instance_id")
        }
        instances = [
            row
            for i, row in enumerate(instances)
            if get_instance_id(row, i, adapter) not in completed
        ]
    end = None if args.num_instances is None else args.start_idx + args.num_instances
    return instances[args.start_idx : end]

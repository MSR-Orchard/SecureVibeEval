"""Result loading and merging shared by sequential and parallel runs."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _model_results_dir(results_dir: str, model: str) -> Path:
    return Path(results_dir, model).resolve()


def _find_process_final_results(
    results_dir: str,
    model: str,
    process_id: int,
    started_at: float,
) -> Optional[Path]:
    model_dir = _model_results_dir(results_dir, model)
    candidates = sorted(
        model_dir.glob(f"*_process{process_id}/final_results.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for candidate in candidates:
        try:
            if candidate.stat().st_mtime >= started_at - 5:
                return candidate
        except OSError:
            continue
    return None


def _load_results_list(path: Path) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"Expected a list in {path}, found {type(data).__name__}")
    return data


def load_records(path: Path) -> List[Dict[str, Any]]:
    """Load result records from either a list or a dict-keyed-by-instance-id file.

    preds.json is canonically a dict {instance_id: record}; process
    final_results.json files are lists. Both reduce to a list of record dicts.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        return [
            dict(v, instance_id=v.get("instance_id") or key)
            for key, v in data.items()
            if isinstance(v, dict)
        ]
    if isinstance(data, list):
        return data
    raise ValueError(f"Expected a list or dict in {path}, found {type(data).__name__}")


def merge_final_results(
    process_results: List[Dict[str, Any]],
    results_dir: str,
    model: str,
    load_from_file: Optional[str] = None,
) -> Path:
    groups = []

    if load_from_file:
        try:
            groups.append(load_records(Path(load_from_file)))
        except Exception as e:
            logger.warning(f"Could not include --load_from_file in merged results: {e}")

    for result in sorted(process_results, key=lambda r: r.get("process_id", -1)):
        final_results_file = result.get("final_results_file")
        if not final_results_file:
            logger.warning(
                f"Process {result.get('process_id', '?')}: no final_results.json found"
            )
            continue
        path = Path(final_results_file)
        try:
            rows = _load_results_list(path)
        except Exception as e:
            logger.warning(f"Could not read process results from {path}: {e}")
            continue
        groups.append(rows)

    merged = merge_records(*groups)
    output_file = _model_results_dir(results_dir, model) / "merged_final_results.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)

    logger.info(f"Merged {len(merged)} final results into {output_file}")
    return output_file


def merge_records(*groups):
    by_id = {}
    without_id = []
    for rows in groups:
        for row in rows:
            if row.get("instance_id"):
                by_id[row["instance_id"]] = row
            else:
                without_id.append(row)
    return list(by_id.values()) + without_id


def write_predictions(results, results_dir, benchmark_output_root, model):
    preds = {
        row["instance_id"]: {
            "instance_id": row["instance_id"],
            "model_name_or_path": row.get("model_name_or_path", model),
            "model_patch": row.get("model_patch", ""),
        }
        for row in results
        if row.get("instance_id")
    }
    for directory in {results_dir, benchmark_output_root}:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "preds.json").write_text(
            json.dumps(preds, indent=2, ensure_ascii=False), encoding="utf-8"
        )

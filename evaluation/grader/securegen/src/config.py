"""Paths and image-name helpers required by SecureGen grading."""
from __future__ import annotations

import os
from pathlib import Path


SRC_DIR = Path(__file__).resolve().parent
SECUREGEN_DIR = SRC_DIR.parent
GRADING_DIR = SECUREGEN_DIR.parent
BUNDLE_DIR = GRADING_DIR.parent
DATA_DIR = Path(os.environ.get("DATA_DIR", BUNDLE_DIR.parent / "data" / "raw")) / "securegen"
OUT_DIR = BUNDLE_DIR / "results" / "securegen"
TASKS_PATH = DATA_DIR / "securegen_tasks.jsonl"

SRC_IMAGE_TMPL = "ghcr.io/anonymous2578-data/{cve}:latest"
ACR_IMAGE_TMPL = "debuggymacr.azurecr.io/cybergym/github-sec-pe:{task_id}"
IMAGE_MIRROR = os.environ.get("SECUREGEN_IMAGE_MIRROR", "mirror.gcr.io")


def mirror_image(image: str, mirror: str = "") -> str:
    """Route Docker Hub references through the configured pull-through mirror."""
    mirror = (mirror or IMAGE_MIRROR).strip().rstrip("/")
    if not mirror or not image or image.startswith("docker://") or image.startswith(mirror + "/"):
        return image
    if image.startswith("docker.io/"):
        return f"{mirror}/{image[len('docker.io/') :]}"
    first = image.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return image
    return f"{mirror}/{image}"


def task_id(task: str | dict) -> str:
    if isinstance(task, dict):
        value = task.get("task_id") or task.get("instance_id") or task.get("cve_id")
    else:
        value = task
    if not value:
        raise KeyError("record has no task_id, instance_id, or cve_id")
    return str(value).lower()


def src_image(task: str | dict) -> str:
    if isinstance(task, dict):
        if task.get("source_image"):
            return str(task["source_image"])
        if task.get("source_domain") == "acr":
            return ACR_IMAGE_TMPL.format(task_id=task_id(task))
    return SRC_IMAGE_TMPL.format(cve=task_id(task))


def oracle_patch_path(task: dict) -> str:
    return str(task.get("oracle_patch_path") or "/workspace/fix.patch")

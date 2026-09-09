#!/usr/bin/env python3
"""Batch runner: drive mini-SWE-agent over a BaxBench (agent-mode) instances file.

The BaxBench analogue of `mini_swe_agent/batch_run.py`. It reads the JSON produced
by `gen_instances.py`, runs mini on each (scenario x env x sample) instance, then --
instead of extracting a git patch -- copies the app the agent left under
`code_workdir` (default /app/code) into BaxBench's results layout:

    <results_dir>/<model_label>/<results_subdir>/   e.g. results/gpt-5.5/<scenario>/<env>/temp.../sample0/code/

so that BaxBench's own `src/main.py --mode test/evaluate` can build + grade it
unchanged. Instances are model-independent (see gen_instances.py); the model is
chosen here via --model-label (output namespace) + --model (the litellm route).

Per instance it also writes:
    <output>/<instance_id>/<instance_id>.traj.json   mini trajectory
    <output>/exit_statuses.yaml                       buckets + total_cost

Differs from the SWE-bench runner only in (a) the image comes straight from the
instance (`image_name`), (b) the "submission" is ignored -- the deliverable is the
files under `code_workdir`, pulled out via `tar | base64` over `env.execute`.

Example (local docker backend):
    python batch_run.py \
        --config evaluation.yaml \
        --config baxbench_model_claude_sonnet45.yaml \
        --instances baxbench_mini_instances.json \
        --output ./baxbench_mini_output \
        --results_dir ./results \
        --model-label gpt-5.5 --model openai/gpt-5.5 --workers 8

Behind an auth proxy: use ./run_proxy.sh with the same args (see README).
"""

import base64
import concurrent.futures
import copy
import hashlib
import io
import json
import math
import os
import re
import shlex
import tarfile
import threading
import time
import traceback
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import typer
import yaml
from rich.live import Live

from minisweagent.config import get_config_from_spec, get_config_path
from minisweagent.environments import get_environment
from minisweagent.models import GLOBAL_MODEL_STATS, get_model
from minisweagent.run.benchmarks.utils.batch_progress import RunBatchProgressManager
from minisweagent.run.benchmarks.utils.common import ProgressTrackingAgent
from minisweagent.utils.log import add_file_handler, logger
from minisweagent.utils.serialize import UNSET, recursive_merge

app = typer.Typer(rich_markup_mode="rich", add_completion=False)
_LOCK = threading.Lock()
_DP_RANK_RE = re.compile(r'(?:^|,)dp_rank="(\d+)"(?:,|$)')


def get_sglang_metrics_url() -> str | None:
    """Derive SGLang's /metrics endpoint from the configured OpenAI API base."""
    api_base = (os.environ.get("LOCAL_BASE") or os.environ.get("OPENAI_API_BASE") or "").strip()
    if not api_base:
        return None

    parsed = urlsplit(api_base)
    path = parsed.path.rstrip("/")
    if path.endswith("/v1"):
        path = path[:-3]
    return urlunsplit((parsed.scheme, parsed.netloc, f"{path}/metrics", "", ""))


def parse_token_usage_metrics(payload: str, dp_size: int) -> list[float] | None:
    """Extract one sglang:token_usage gauge for every expected DP rank."""
    by_rank: dict[int, float] = {}
    for line in payload.splitlines():
        if not line.startswith("sglang:token_usage{"):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        labels = fields[0].partition("{")[2].removesuffix("}")
        rank_match = _DP_RANK_RE.search(labels)
        if rank_match is None:
            continue
        try:
            rank = int(rank_match.group(1))
            usage = float(fields[1])
        except ValueError:
            continue
        if 0 <= rank < dp_size and math.isfinite(usage):
            by_rank[rank] = max(usage, by_rank.get(rank, 0.0))

    if len(by_rank) != dp_size:
        return None
    return [by_rank[rank] for rank in range(dp_size)]


class SGLangTokenUsageReader:
    """Read live per-rank KV-token utilization, with a small shared cache."""

    def __init__(self, url: str, dp_size: int, timeout: float = 1.0, refresh_interval: float = 0.5):
        self.url = url
        self.dp_size = dp_size
        self.timeout = timeout
        self.refresh_interval = refresh_interval
        self.lock = threading.Lock()
        self.last_attempt = float("-inf")
        self.cached: list[float] | None = None
        self.warning_active = False

    def read(self) -> list[float] | None:
        with self.lock:
            now = time.monotonic()
            if now - self.last_attempt < self.refresh_interval:
                return self.cached
            self.last_attempt = now

            try:
                with urllib.request.urlopen(self.url, timeout=self.timeout) as response:
                    payload = response.read().decode("utf-8")
                token_usage = parse_token_usage_metrics(payload, self.dp_size)
                if token_usage is None:
                    raise ValueError(f"expected token usage for {self.dp_size} DP ranks")
            except Exception as exc:
                self.cached = None
                if not self.warning_active:
                    logger.warning(
                        f"Could not read SGLang token usage from {self.url} ({exc}); "
                        "falling back to active-trajectory balancing"
                    )
                    self.warning_active = True
                return None

            if self.warning_active:
                logger.info(f"SGLang token-usage metrics are available again at {self.url}")
                self.warning_active = False
            self.cached = token_usage
            return token_usage


class DPRankAllocator:
    """Balance live token load while preserving trajectory-to-rank affinity."""

    def __init__(self, dp_size: int, workers: int, metrics_url: str | None = None):
        base, remainder = divmod(workers, dp_size)
        self.capacity = [base + (rank < remainder) for rank in range(dp_size)]
        self.active = [0] * dp_size
        self.condition = threading.Condition()
        self.token_usage_reader = (
            SGLangTokenUsageReader(metrics_url, dp_size) if metrics_url is not None else None
        )

    @contextmanager
    def reserve(self):
        while True:
            token_usage = self.token_usage_reader.read() if self.token_usage_reader is not None else None
            with self.condition:
                available = [
                    rank for rank in range(len(self.active)) if self.active[rank] < self.capacity[rank]
                ]
                if available:
                    if token_usage is None:
                        rank = min(available, key=lambda candidate: (self.active[candidate], candidate))
                    else:
                        rank = min(
                            available,
                            key=lambda candidate: (
                                token_usage[candidate]
                                + self.active[candidate] / self.capacity[candidate],
                                candidate,
                            ),
                        )
                    self.active[rank] += 1
                    break
                self.condition.wait()

        try:
            yield rank
        finally:
            with self.condition:
                self.active[rank] -= 1
                self.condition.notify_all()

# Dependency/artifact dirs we never copy back: they're rebuilt by BaxBench's test
# Dockerfile from the manifest files, and copying them would bloat (or corrupt) the
# test image. The agent's *source* is what BaxBench grades.
_EXCLUDE_DIRS = ["node_modules", ".git", "__pycache__", "target", "vendor",
                 "dist", "build", "tmp", "log", "storage", "coverage",
                 ".cache", ".cargo", ".mypy_cache", ".pytest_cache",
                 ".ruff_cache", ".venv", "venv"]
_MAX_EXTRACT_BYTES = 64 * 1024 * 1024  # 64MB safety cap on the tar payload
_ARTIFACT_CONFIG_KEY = "artifact_paths"


def _resolve_config_ref(ref: str | Path, parent: Path | None = None) -> Path:
    """Resolve a YAML config reference, allowing paths relative to the including file."""
    path = Path(ref)
    if path.suffix != ".yaml":
        path = path.with_suffix(".yaml")
    if parent is not None and not path.is_absolute():
        candidate = parent / path
        if candidate.exists():
            return candidate
    if not path.is_absolute():
        candidate = Path(__file__).resolve().parent / path
        if candidate.exists():
            return candidate
    return get_config_path(path)


def load_config_with_extends(config_spec: str | Path, seen: set[Path] | None = None,
                             parent: Path | None = None) -> dict:
    """Load a mini-SWE-agent config and recursively merge any `extends` bases.

    `extends` may be a string or a list of strings. Relative paths are resolved
    against the file that declares them. Later configs override earlier bases.
    """
    if isinstance(config_spec, str) and "=" in config_spec:
        return get_config_from_spec(config_spec)

    path = _resolve_config_ref(config_spec, parent).resolve()
    seen = seen or set()
    if path in seen:
        cycle = " -> ".join(str(p) for p in [*seen, path])
        raise ValueError(f"Config extends cycle detected: {cycle}")
    seen.add(path)

    data = yaml.safe_load(path.read_text()) or {}
    bases = data.pop("extends", None)
    if not bases:
        seen.remove(path)
        return data
    if isinstance(bases, (str, Path)):
        bases = [bases]
    if not isinstance(bases, list):
        raise TypeError(f"{path}: `extends` must be a string or list of strings")

    merged = {}
    for base in bases:
        merged = recursive_merge(merged, load_config_with_extends(base, seen, path.parent))
    seen.remove(path)
    return recursive_merge(merged, data)


def _split_config_specs(config_specs: list[str]) -> list[str]:
    """Support both repeated --config and comma-separated config lists."""
    return [part.strip() for spec in config_specs for part in spec.split(",") if part.strip()]


def load_configs(config_specs: list[str] | None) -> dict:
    """Load and merge one or more config specs in CLI order."""
    if not config_specs:
        config_specs = [
            "evaluation.yaml",
            "baxbench_model_claude_sonnet45.yaml",
            "environment.environment_class=docker",
        ]
    else:
        config_specs = _split_config_specs(config_specs)
    merged = {}
    for spec in config_specs:
        merged = recursive_merge(merged, load_config_with_extends(spec))
    return merged


def mirror_image(image: str, mirror: str = "") -> str:
    """Rewrite Docker Hub refs through a pull-through mirror for sandbox warm caches.

    Fully-qualified non-Docker-Hub registries such as ghcr.io and ACR are left alone.
    If gen_instances.py already wrote a mirrored ref, this is idempotent.
    """
    mirror = (mirror or os.environ.get("BAXBENCH_IMAGE_MIRROR", "mirror.gcr.io")).strip().rstrip("/")
    if not mirror or not image or image.startswith("docker://") or image.startswith(mirror + "/"):
        return image
    if image.startswith("docker.io/"):
        return f"{mirror}/{image[len('docker.io/'):]}"
    first = image.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return image
    return f"{mirror}/{image}"


def get_environment_for_instance(config: dict, instance: dict):
    """Build the execution environment, injecting this instance's BaxBench dev image."""
    env_config = dict(config.get("environment", {}))
    env_config.setdefault("environment_class", "docker")
    env_config["image"] = mirror_image(instance["image_name"])
    return get_environment(env_config)


def expand_samples(instances: list[dict], n_samples: int) -> list[dict]:
    """Replicate each instance into `n_samples` copies, one per sample index.

    Samples differ from each other *only* in the trailing `sample<N>` token of
    `instance_id` (`...-sample<N>`) and `results_subdir` (`.../sample<N>/code`) --
    every other field (prompt, image, workdir) is identical (see gen_instances.py).
    So instead of regenerating the instances JSON with `--n_samples N`, we can
    rewrite that token here. Set the *sampling* temperature in the run config's
    model section so the copies actually diverge (n_samples > 1 at temp 0 just
    reruns the same near-deterministic decode).

    Assumes the input file is single-sample-per-task (the default gen_instances
    output). If it already carries multiple samples, expanding would collide, so
    we raise instead of silently overwriting.
    """
    if n_samples <= 1:
        return instances
    expanded: list[dict] = []
    seen: set[str] = set()
    for inst in instances:
        for s in range(n_samples):
            new = dict(inst)
            new["instance_id"] = re.sub(r"-sample\d+$", f"-sample{s}", inst["instance_id"])
            new["results_subdir"] = re.sub(r"(^|/)sample\d+/", rf"\g<1>sample{s}/", inst["results_subdir"])
            if new["instance_id"] in seen:
                raise typer.BadParameter(
                    f"Duplicate instance_id '{new['instance_id']}' after sample expansion -- the "
                    "--instances file already contains multiple samples. Regenerate it with "
                    "--n_samples 1 (or drop --n_samples here)."
                )
            seen.add(new["instance_id"])
            expanded.append(new)
    return expanded


def _instance_axes(instance: dict) -> tuple[str, str]:
    """Pull (spec_type, safety_prompt) out of an instance.

    Newer instances files (gen_instances.py) carry explicit `spec_type` /
    `safety_prompt` keys -- use them when present. Otherwise fall back to parsing
    the encoded `results_subdir`: `<scenario>/<env>/temp<t>-<spec>-<safety>/sample<N>/code`,
    whose third path component is the `temp<t>-<spec>-<safety>` tag (the temperature
    is a float like `0.0`, so it never contains a '-'). Returns ("", "") if it can't
    be resolved, so an unexpected layout just won't match any filter rather than crash.
    """
    if instance.get("spec_type") and instance.get("safety_prompt"):
        return instance["spec_type"], instance["safety_prompt"]
    parts = Path(instance.get("results_subdir", "")).parts
    if len(parts) < 3:
        return "", ""
    tag = parts[2].split("-")
    if len(tag) != 3:
        return "", ""
    _temp, spec, safety = tag
    return spec, safety


def filter_instances(instances: list[dict], spec_type: str | None,
                     safety_prompt: str | None) -> list[dict]:
    """Subset instances by spec_type and/or safety_prompt (the BaxBench prompt axes).

    Unlike sample count, these axes change the prompt *content* baked in at
    gen_instances time (safety_prompt injects security cues; spec_type swaps an
    OpenAPI schema for prose), so they can't be synthesized here -- but if the
    instances file already contains the variants, we can pick which to run.
    """
    if not spec_type and not safety_prompt:
        return instances
    kept = []
    for inst in instances:
        spec, safety = _instance_axes(inst)
        if spec_type and spec != spec_type:
            continue
        if safety_prompt and safety != safety_prompt:
            continue
        kept.append(inst)
    if not kept:
        raise typer.BadParameter(
            f"No instances match spec_type={spec_type!r} safety_prompt={safety_prompt!r}. "
            "The --instances file must already contain that variant (regenerate it with "
            "gen_instances.py --spec_type/--safety_prompt to add it)."
        )
    return kept


def _extract_tar_payload(payload: str, dest: Path, empty_error: str) -> dict:
    try:
        raw = base64.b64decode(payload)
    except Exception as e:
        return {"n_files": 0, "error": f"base64 decode failed: {e}"}
    if len(raw) > _MAX_EXTRACT_BYTES:
        return {"n_files": 0, "error": f"payload too large ({len(raw)} bytes); check excludes"}

    dest.mkdir(parents=True, exist_ok=True)
    n = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            # Guard against path traversal in member names.
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest.resolve())):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            f = tar.extractfile(member)
            if f is None:
                continue
            target.write_bytes(f.read())
            n += 1
    return {"n_files": n, "error": "" if n else empty_error}


def _decode_json_list(payload: str) -> list[str]:
    try:
        decoded = json.loads(payload)
    except Exception:
        return []
    return decoded if isinstance(decoded, list) else []


def extract_code(env, instance: dict, dest: Path) -> dict:
    """Copy files under instance['code_workdir'] out of the container into `dest`.

    Uses a single `tar -c <dir> | base64` over env.execute, then unpacks locally.
    Returns {"n_files", "error"} for the trajectory log.
    """
    workdir = instance["code_workdir"]
    excludes = " ".join(f"--exclude='./{d}'" for d in _EXCLUDE_DIRS)
    quoted_workdir = shlex.quote(workdir)
    # -C into the code dir so paths are relative; tolerate a missing dir cleanly.
    cmd = (
        f"if [ -d {quoted_workdir} ]; then "
        f"tar {excludes} -cf - -C {quoted_workdir} . | base64 -w0; "
        f"else echo __BAXBENCH_NO_CODE_DIR__; fi"
    )
    out = env.execute({"command": cmd}, timeout=300)
    payload = (out.get("output") or "").strip()
    if out.get("returncode", 0) != 0 and not payload:
        return {"n_files": 0, "error": f"tar failed: {out.get('exception_info') or out.get('output')}"}
    if "__BAXBENCH_NO_CODE_DIR__" in payload:
        return {"n_files": 0, "error": f"no code dir at {workdir}"}
    return _extract_tar_payload(payload, dest, "code dir was empty")


def extract_artifacts(env, artifact_paths: list[str], dest: Path) -> dict:
    """Copy explicit files from the container into `dest`.

    This is for non-app-code tasks such as security report/test-patch generation.
    The files are unpacked by basename, e.g. /app/security_report.json becomes
    <dest>/security_report.json.
    """
    if not artifact_paths:
        return {"n_files": 0, "error": "no artifact paths configured", "requested": []}

    # Build a small shell script because env.execute has no direct file-copy API.
    # It records found/missing paths and only tars the found basenames.
    quoted_paths = " ".join(shlex.quote(path) for path in artifact_paths)
    cmd = f"""
set -eu
tmpdir="$(mktemp -d)"
found_json="$tmpdir/found.json"
missing_json="$tmpdir/missing.json"
stage_dir="$tmpdir/stage"
export found_json missing_json stage_dir
python3 - "$@" <<'PY' {quoted_paths}
import json
import os
import pathlib
import shutil
import sys

stage = pathlib.Path(os.environ["stage_dir"])
if stage.exists():
    shutil.rmtree(stage)
stage.mkdir()

found = []
missing = []
for raw in sys.argv[1:]:
    path = pathlib.Path(raw)
    if path.is_file():
        target = stage / path.name
        shutil.copy2(path, target)
        found.append(raw)
    else:
        missing.append(raw)

pathlib.Path(os.environ["found_json"]).write_text(json.dumps(found))
pathlib.Path(os.environ["missing_json"]).write_text(json.dumps(missing))
PY
printf '__BAXBENCH_ARTIFACTS_FOUND__'
cat "$found_json"
printf '\\n__BAXBENCH_ARTIFACTS_MISSING__'
cat "$missing_json"
printf '\\n__BAXBENCH_ARTIFACTS_PAYLOAD__\\n'
if [ -n "$(find "$stage_dir" -type f -print -quit)" ]; then
    tar -cf - -C "$stage_dir" . | base64 -w0
fi
rm -rf "$tmpdir"
"""
    out = env.execute({"command": cmd}, timeout=300)
    output = out.get("output") or ""
    if out.get("returncode", 0) != 0 and "__BAXBENCH_ARTIFACTS_PAYLOAD__" not in output:
        return {
            "n_files": 0,
            "error": f"artifact extraction failed: {out.get('exception_info') or output}",
            "requested": artifact_paths,
        }

    found_marker = "__BAXBENCH_ARTIFACTS_FOUND__"
    missing_marker = "\n__BAXBENCH_ARTIFACTS_MISSING__"
    payload_marker = "\n__BAXBENCH_ARTIFACTS_PAYLOAD__\n"
    if found_marker not in output or missing_marker not in output or payload_marker not in output:
        return {
            "n_files": 0,
            "error": f"artifact extraction output missing markers: {out.get('exception_info') or output}",
            "requested": artifact_paths,
        }

    found_part = output.split(found_marker, 1)[1].split(missing_marker, 1)[0].strip()
    rest = output.split(missing_marker, 1)[1]
    missing_part = rest.split(payload_marker, 1)[0].strip()
    payload = rest.split(payload_marker, 1)[1].strip()
    found = _decode_json_list(found_part)
    missing = _decode_json_list(missing_part)
    info = _extract_tar_payload(payload, dest, "no configured artifacts were found") if payload else {
        "n_files": 0,
        "error": "no configured artifacts were found",
    }
    info.update({"requested": artifact_paths, "found": found, "missing": missing})
    if info["n_files"] and missing:
        info["error"] = f"copied {info['n_files']} artifact(s); missing: {', '.join(missing)}"
    return info


def process_instance(instance: dict, output_dir: Path, code_root: Path,
                     config: dict, progress_manager: RunBatchProgressManager,
                     routed_dp_rank: int | None = None) -> None:
    # code_root = <results_dir>/<model_label>; the instance's results_subdir is
    # model-less (e.g. <scenario>/<env>/temp.../sample0/code), so this is where the
    # BaxBench grader for that model expects the code.
    instance_id = instance["instance_id"]
    instance_dir = output_dir / instance_id
    model_config = copy.deepcopy(config.get("model", {}))
    if routed_dp_rank is not None:
        model_kwargs = model_config.setdefault("model_kwargs", {})
        extra_body = model_kwargs.setdefault("extra_body", {})
        extra_body["routed_dp_rank"] = routed_dp_rank
    model = get_model(config=model_config)
    task = instance["problem_statement"]

    progress_manager.on_instance_start(instance_id)
    progress_manager.update_instance_status(instance_id, "Starting environment")

    agent = None
    exit_status, result, extra_info = None, None, {}
    env = None
    extract_info = {}
    try:
        env = get_environment_for_instance(config, instance)
        agent = ProgressTrackingAgent(
            model, env, progress_manager=progress_manager,
            instance_id=instance_id, **config.get("agent", {}),
        )
        info = agent.run(task)
        exit_status = info.get("exit_status")
        result = info.get("submission")
        # The deliverable is usually the app on disk, but some analysis/test-gen
        # prompts produce explicit artifacts instead. Pull the configured artifact
        # type regardless of how the run ended (the agent may hit a limit mid-test
        # yet still have useful files saved).
        artifact_paths = config.get(_ARTIFACT_CONFIG_KEY) or []
        if artifact_paths:
            progress_manager.update_instance_status(instance_id, "Extracting artifacts")
            extract_info = extract_artifacts(env, artifact_paths, code_root / instance["results_subdir"])
        else:
            progress_manager.update_instance_status(instance_id, "Extracting code")
            extract_info = extract_code(env, instance, code_root / instance["results_subdir"])
    except Exception as e:
        logger.error(f"Error processing instance {instance_id}: {e}", exc_info=True)
        exit_status, result = type(e).__name__, ""
        extra_info = {"traceback": traceback.format_exc(), "exception_str": str(e)}
        if env is not None and not extract_info:
            try:
                artifact_paths = config.get(_ARTIFACT_CONFIG_KEY) or []
                if artifact_paths:
                    extract_info = extract_artifacts(env, artifact_paths, code_root / instance["results_subdir"])
                else:
                    extract_info = extract_code(env, instance, code_root / instance["results_subdir"])
            except Exception as e2:
                extract_info = {"n_files": 0, "error": f"extraction after failure: {e2}"}
    finally:
        if agent is not None:
            traj_path = instance_dir / f"{instance_id}.traj.json"
            agent.save(traj_path, {"info": {"exit_status": exit_status, "submission": result,
                                            "extract": extract_info, **extra_info},
                                   "instance_id": instance_id})
        if env is not None and hasattr(env, "cleanup"):
            try:
                env.cleanup()
            except Exception:
                pass
        # Record an effective exit status that reflects whether we got code out.
        eff = exit_status
        if extract_info and not extract_info.get("n_files"):
            eff = f"{exit_status}/NoCode"
        progress_manager.on_instance_end(instance_id, eff)


def write_exit_statuses(output_dir: Path, progress_manager: RunBatchProgressManager) -> None:
    data = {
        "instances_by_exit_status": dict(progress_manager._instances_by_exit_status),
        "total_cost": GLOBAL_MODEL_STATS.cost,
    }
    (output_dir / "exit_statuses.yaml").write_text(yaml.dump(data, indent=4))


# fmt: off
@app.command()
def main(
    instances: Path = typer.Option(..., "--instances", help="Instances JSON from gen_instances.py"),
    output: Path = typer.Option(..., "--output", "-o", help="Output dir (trajectories, logs, exit statuses)"),
    results_dir: Path = typer.Option(..., "--results_dir", help="BaxBench results dir root "
                                     "(code is written under <results_dir>/<model_label>/...)"),
    model_label: str = typer.Option(..., "--model-label", help="Output namespace = BaxBench results "
                                    "dir name for this model. MUST equal the --models value you pass to "
                                    "`src/main.py --mode test/evaluate`."),
    config: list[str] | None = typer.Option(
        None, "--config", "-c",
        help="mini run config (repeat or comma-separate to merge in order)",
    ),
    workers: int = typer.Option(1, "--workers", "-w", help="Worker threads"),
    model: str | None = typer.Option(None, "--model", "-m", help="Model name (overrides config)"),
    model_class: str | None = typer.Option(None, "--model-class", help="Model class (overrides config)"),
    environment_class: str | None = typer.Option(None, "--environment-class", help="docker | sandbox (overrides config)"),
    cost_limit: float | None = typer.Option(None, "--cost-limit", help="Per-instance cost limit"),
    step_limit: int | None = typer.Option(None, "--step-limit", help="Per-instance step limit"),
    n_samples: int = typer.Option(1, "--n_samples", "--n-samples", help="Replicate each instance into N "
                                  "samples (sample0..sampleN-1) in-memory, so you don't have to regenerate "
                                  "the instances file. Needs a >0 sampling temperature in the config to diverge."),
    sglang_dp_size: int | None = typer.Option(
        None,
        "--sglang-dp-size",
        min=1,
        help="Enable token-aware, capacity-capped sticky routing across this many SGLang DP ranks",
    ),
    shuffle_seed: int = typer.Option(
        0,
        "--shuffle-seed",
        help="Seed for deterministic instance ordering (stable across resumed runs)",
    ),
    spec_type: str | None = typer.Option(None, "--spec_type", "--spec-type", help="If set, run ONLY instances "
                                         "of this spec_type (openapi|text). Filters the instances file; the "
                                         "variant must already exist in it (it's baked in at gen time)."),
    safety_prompt: str | None = typer.Option(None, "--safety_prompt", "--safety-prompt", help="If set, run ONLY "
                                             "instances with this safety_prompt (none|generic|specific). Filters "
                                             "the instances file; the variant must already exist in it."),
    redo_existing: bool = typer.Option(False, "--redo-existing", help="Re-run instances already present in output"),
) -> None:
    # fmt: on
    output.mkdir(parents=True, exist_ok=True)
    code_root = results_dir / model_label
    code_root.mkdir(parents=True, exist_ok=True)
    add_file_handler(output / "baxbench_mini.log")
    logger.info(f"Trajectories -> {output}; code -> {code_root}")

    all_instances = json.loads(Path(instances).read_text())
    if not isinstance(all_instances, list):
        raise typer.BadParameter("Instances file must be a JSON list.")

    if spec_type or safety_prompt:
        before = len(all_instances)
        all_instances = filter_instances(all_instances, spec_type, safety_prompt)
        logger.info(f"Filtered {before} -> {len(all_instances)} instances "
                    f"(spec_type={spec_type}, safety_prompt={safety_prompt})")

    if n_samples > 1:
        before = len(all_instances)
        all_instances = expand_samples(all_instances, n_samples)
        logger.info(f"Expanded {before} instances -> {len(all_instances)} ({n_samples} samples each)")

    done_path = output / "_done.json"
    if not redo_existing and done_path.exists():
        done = set(json.loads(done_path.read_text()))
        before = len(all_instances)
        all_instances = [i for i in all_instances if i["instance_id"] not in done]
        logger.info(f"Skipping {before - len(all_instances)} already-done instances")
    all_instances.sort(
        key=lambda item: hashlib.sha256(f"{shuffle_seed}:{item['instance_id']}".encode()).digest()
    )
    logger.info(f"Running on {len(all_instances)} instances...")
    logger.info(f"Deterministically shuffled pending instances with seed {shuffle_seed}")
    if sglang_dp_size is not None:
        logger.info(f"Using token-aware, capacity-capped sticky routing across {sglang_dp_size} DP ranks")

    run_config = recursive_merge(
        load_configs(config),
        {
            "environment": {"environment_class": environment_class or UNSET},
            "model": {"model_name": model or UNSET, "model_class": model_class or UNSET},
            "agent": {"cost_limit": cost_limit or UNSET, "step_limit": step_limit or UNSET},
        },
    )

    progress_manager = RunBatchProgressManager(len(all_instances), output / "exit_statuses.yaml")
    metrics_url = get_sglang_metrics_url() if sglang_dp_size is not None else None
    if sglang_dp_size is not None:
        if metrics_url is None:
            logger.warning(
                "LOCAL_BASE/OPENAI_API_BASE is unset; using active-trajectory balancing only"
            )
        else:
            logger.info(f"Reading live SGLang token usage from {metrics_url}")
    rank_allocator = (
        DPRankAllocator(sglang_dp_size, workers, metrics_url)
        if sglang_dp_size is not None
        else None
    )
    completed: list[str] = []

    def _record_done(iid: str):
        with _LOCK:
            completed.append(iid)
            existing = json.loads(done_path.read_text()) if done_path.exists() else []
            done_path.write_text(json.dumps(sorted(set(existing) | set(completed))))

    def _run(inst):
        try:
            if rank_allocator is None:
                process_instance(inst, output, code_root, run_config, progress_manager)
            else:
                with rank_allocator.reserve() as rank:
                    logger.info(f"Routing {inst['instance_id']} to SGLang DP rank {rank}")
                    process_instance(inst, output, code_root, run_config, progress_manager, rank)
        finally:
            _record_done(inst["instance_id"])

    def process_futures(futures: dict):
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except concurrent.futures.CancelledError:
                pass
            except Exception as e:
                progress_manager.on_uncaught_exception(futures[future], e)

    with Live(progress_manager.render_group, refresh_per_second=4):
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(_run, inst): inst["instance_id"] for inst in all_instances}
            try:
                process_futures(futures)
            except KeyboardInterrupt:
                logger.info("Cancelling pending jobs. Press ^C again to exit immediately.")
                for future in futures:
                    if not future.running() and not future.done():
                        future.cancel()
                process_futures(futures)

    write_exit_statuses(output, progress_manager)
    logger.info(f"Total cost: ${GLOBAL_MODEL_STATS.cost:.2f}. Wrote {output / 'exit_statuses.yaml'}")
    logger.info(f"Code written under {code_root}. Now grade with BaxBench:\n"
                f"  RUNS=baxbench BAXBENCH_MODEL_LABEL={model_label} ./grade.sh")


if __name__ == "__main__":
    app()

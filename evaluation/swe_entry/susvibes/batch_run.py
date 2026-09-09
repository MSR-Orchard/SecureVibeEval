#!/usr/bin/env python3
"""Batch runner: run mini-SWE-agent over a SusVibes instances file.

This is the mini-SWE-agent analogue of `sweagent run-batch`. It reads the flat
JSON instances file produced by SusVibes' `MiniSWEAgentPort` (the `--prologue`
step), runs mini on each instance with a thread pool, and writes:

  <output>/preds.json          {instance_id: {model_name_or_path, instance_id, model_patch}}
  <output>/<id>/<id>.traj.json per-instance trajectory
  <output>/exit_statuses.yaml  {instances_by_exit_status, total_cost}

`preds.json` is the exact shape SusVibes' `--epilogue` consumes; `exit_statuses.yaml`
additionally records the run's total cost (mini's own per-run report does not).

It reuses mini's own machinery (agent, model, progress manager, preds writer) and
only replaces (a) dataset loading — a local JSON list instead of a HuggingFace
dataset — and (b) environment construction, so the per-task `image_name` is injected
for *any* environment class (mini's swebench helper only does this for docker /
singularity, not the `sandbox` backend used here).

Each instance dict must carry: `instance_id`, `problem_statement`, `image_name`.

Example:
    python -m batch_run \\
        --config susvibes_eval.yaml \\
        --instances logs/agent_runs/run_evaluation_generic_mini_instances.json \\
        --output logs/agent_runs/mini_output \\
        --model openai/gpt-5.5_2026-04-24 --workers 8
"""

import concurrent.futures
import copy
import hashlib
import json
import math
import os
import re
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

from minisweagent.config import get_config_from_spec
from minisweagent.environments import get_environment
from minisweagent.models import GLOBAL_MODEL_STATS, get_model
from minisweagent.run.benchmarks.swebench import get_swebench_docker_image_name, update_preds_file
from minisweagent.run.benchmarks.utils.batch_progress import RunBatchProgressManager
from minisweagent.run.benchmarks.utils.common import ProgressTrackingAgent
from minisweagent.utils.log import add_file_handler, logger
from minisweagent.utils.serialize import UNSET, recursive_merge

app = typer.Typer(rich_markup_mode="rich", add_completion=False)
_OUTPUT_FILE_LOCK = threading.Lock()


def mirror_image(image: str, mirror: str = "") -> str:
    """Rewrite a Docker Hub ref to pull through `mirror` (default $SUSVIBES_IMAGE_MIRROR =
    mirror.gcr.io). Idempotent; leaves docker:// URIs and fully-qualified non-Docker-Hub
    registries (ghcr.io, host:port) alone. Pass mirror='' to disable.

    Kept in sync with `susvibes.utils.mirror_image` / `snippets/warm_sandbox_images.py`.
    Without this, the sandbox requests the bare `docker.io/songwen6968/...` ref, which (a)
    bypasses the rate-limit-free mirror and (b) misses the warm-up cache (node image cache
    is keyed by the full ref, so `mirror.gcr.io/X` != `docker.io/X`) — every pod then does a
    cold, rate-limited Docker Hub pull and sits `Pending` until the 360s startup timeout.
    """
    mirror = (mirror or os.environ.get("SUSVIBES_IMAGE_MIRROR", "mirror.gcr.io")).strip().rstrip("/")
    if not mirror or not image or image.startswith("docker://") or image.startswith(mirror + "/"):
        return image
    if image.startswith("docker.io/"):
        return f"{mirror}/{image[len('docker.io/'):]}"
    first = image.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return image
    return f"{mirror}/{image}"


def get_environment_for_instance(config: dict, instance: dict):
    """Build the execution environment, injecting this instance's prebaked image.

    Unlike mini's `get_sb_environment`, this sets `image` for *every* environment
    class (including `sandbox`), since the image is what carries the task's repo.
    """
    env_config = dict(config.get("environment", {}))
    env_config.setdefault("environment_class", "docker")
    env_config["image"] = mirror_image(get_swebench_docker_image_name(instance))
    return get_environment(env_config)


def capture_git_diff(env) -> str:
    """Return the working tree's tracked-file diff, or "" if none/failed.

    Many runs that exit `LimitsExceeded`/`Timeout`/`BadRequestError` have already written a
    correct fix to disk but loop on verification commands instead of running the submit
    command, so `info.submission` is empty and the patch is lost. Recovering `git diff` here
    salvages that work. Plain `git diff` (no untracked files, no staging) keeps the agent's
    scratch files (repro scripts, patch.txt) out of the patch; the grader separately strips
    test-file edits, so a raw source diff is exactly what it expects.
    """
    try:
        out = env.execute({"command": "git diff"}, timeout=120)
    except Exception:
        return ""
    if out.get("returncode") != 0:
        return ""
    return out.get("output", "") or ""


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
        # This lock is deliberately separate from DPRankAllocator.condition: a slow
        # metrics response must not block a trajectory from releasing its rank.
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


def process_instance(
    instance: dict,
    output_dir: Path,
    config: dict,
    progress_manager: RunBatchProgressManager,
    routed_dp_rank: int | None = None,
) -> None:
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
    try:
        env = get_environment_for_instance(config, instance)
        agent = ProgressTrackingAgent(
            model,
            env,
            progress_manager=progress_manager,
            instance_id=instance_id,
            **config.get("agent", {}),
        )
        info = agent.run(task)
        exit_status = info.get("exit_status")
        result = info.get("submission")
    except Exception as e:
        logger.error(f"Error processing instance {instance_id}: {e}", exc_info=True)
        exit_status, result = type(e).__name__, ""
        extra_info = {"traceback": traceback.format_exc(), "exception_str": str(e)}
    finally:
        # The agent only reports a `submission` when it runs the explicit submit command. Runs
        # that hit a limit/error often left a correct fix on disk but never submitted, so recover
        # the working-tree diff as the patch before tearing the sandbox down.
        if not (result or "").strip() and env is not None:
            recovered = capture_git_diff(env)
            if recovered.strip():
                result = recovered
                extra_info = {**extra_info, "patch_recovered_from_git_diff": True}
                logger.info(f"Recovered {instance_id} patch from git diff (exit_status={exit_status})")
        if agent is not None:
            traj_path = instance_dir / f"{instance_id}.traj.json"
            agent.save(traj_path, {"info": {"exit_status": exit_status, "submission": result, **extra_info},
                                   "instance_id": instance_id})
        # Best-effort: free the sandbox/container promptly rather than waiting on __del__.
        if env is not None and hasattr(env, "cleanup"):
            try:
                env.cleanup()
            except Exception:
                pass
        update_preds_file(output_dir / "preds.json", instance_id, model.config.model_name, result or "")
        progress_manager.on_instance_end(instance_id, exit_status)


def write_exit_statuses(output_dir: Path, progress_manager: RunBatchProgressManager) -> None:
    """Persist exit-status buckets plus the run's total cost for the epilogue."""
    data = {
        "instances_by_exit_status": dict(progress_manager._instances_by_exit_status),
        "total_cost": GLOBAL_MODEL_STATS.cost,
    }
    (output_dir / "exit_statuses.yaml").write_text(yaml.dump(data, indent=4))


# fmt: off
@app.command()
def main(
    instances: Path = typer.Option(..., "--instances", help="Path to the SusVibes instances JSON file"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    config: str = typer.Option("susvibes_eval.yaml", "--config", "-c", help="mini run config (path or name)"),
    workers: int = typer.Option(1, "--workers", "-w", help="Number of worker threads"),
    model: str | None = typer.Option(None, "--model", "-m", help="Model name (overrides config)"),
    model_class: str | None = typer.Option(None, "--model-class", help="Model class (overrides config)"),
    environment_class: str | None = typer.Option(None, "--environment-class", help="Environment class (overrides config)"),
    cost_limit: float | None = typer.Option(None, "--cost-limit", help="Per-instance cost limit (overrides config)"),
    step_limit: int | None = typer.Option(None, "--step-limit", help="Per-instance step/call limit (overrides config)"),
    max_tokens: int | None = typer.Option(
        None, "--max-tokens", help="Maximum completion tokens per model call (overrides config)"
    ),
    max_input_tokens: int | None = typer.Option(
        None,
        "--max-input-tokens",
        help="Maximum input-history tokens per model call; 0 disables trimming (overrides config)",
    ),
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
    redo_existing: bool = typer.Option(False, "--redo-existing", help="Redo instances already present in preds.json"),
) -> None:
    # fmt: on
    output.mkdir(parents=True, exist_ok=True)
    add_file_handler(output / "minisweagent.log")
    logger.info(f"Results will be saved to {output}")

    all_instances = json.loads(Path(instances).read_text())
    if not isinstance(all_instances, list):
        raise typer.BadParameter("Instances file must be a JSON list of instance dicts.")

    if not redo_existing and (output / "preds.json").exists():
        done = set(json.loads((output / "preds.json").read_text()).keys())
        before = len(all_instances)
        all_instances = [i for i in all_instances if i["instance_id"] not in done]
        logger.info(f"Skipping {before - len(all_instances)} existing instances")
    all_instances.sort(
        key=lambda item: hashlib.sha256(f"{shuffle_seed}:{item['instance_id']}".encode()).digest()
    )
    logger.info(f"Running on {len(all_instances)} instances...")
    logger.info(f"Deterministically shuffled pending instances with seed {shuffle_seed}")
    if sglang_dp_size is not None:
        logger.info(f"Using token-aware, capacity-capped sticky routing across {sglang_dp_size} DP ranks")

    run_config = recursive_merge(
        get_config_from_spec(config),
        {
            "environment": {"environment_class": environment_class or UNSET},
            "model": {
                "model_name": model or UNSET,
                "model_class": model_class or UNSET,
                "max_input_tokens": max_input_tokens if max_input_tokens is not None else UNSET,
                "model_kwargs": {"max_tokens": max_tokens if max_tokens is not None else UNSET},
            },
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

    def run_instance(inst: dict) -> None:
        if rank_allocator is None:
            return process_instance(inst, output, run_config, progress_manager)

        with rank_allocator.reserve() as rank:
            logger.info(f"Routing {inst['instance_id']} to SGLang DP rank {rank}")
            return process_instance(inst, output, run_config, progress_manager, rank)

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
            futures = {
                executor.submit(run_instance, inst): inst["instance_id"]
                for inst in all_instances
            }
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


if __name__ == "__main__":
    app()

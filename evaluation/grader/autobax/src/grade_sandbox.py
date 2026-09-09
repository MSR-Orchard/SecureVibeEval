#!/usr/bin/env python3
"""Sandbox-native AutoBaxBench grader (modeled on BaxBench's sandbox grader).

The local Docker grader starts an app container and drives tests from the host. This
variant starts a pushed sandbox image and runs the AutoBaxBuilder scenario tests inside
that sandbox, then writes `test_results.json` next to the generated code.

This grader keeps grading identical in spirit but moves it onto the sandbox:
It expects `autobax_grading_instances.json` rows with `instance_id` and `image_name` fields. Those
image refs are used directly, so task selection comes from AutoBaxBuilder's scenario/env
registry rather than BaxBench's original registry.

Selection flags support models / scenarios / envs / spec_type / safety_prompt /
temperature / samples). Sandboxes are fanned out with a ThreadPoolExecutor and the run is
resumable (skips samples that already have `test_results.json`).

Credentials: source ~/.sandbox_env (SANDBOX_BASE_URL, optional SANDBOX_SECOND_URL,
SANDBOX_API_KEY). Pre-warm the `image_name` refs in `autobax_grading_instances.json` before a
big batch.

Example:
    python3 grade_sandbox.py --models minimax-m2.7 --scenarios ConfigIncludeResolver \
        --envs Python-FastAPI --n_samples 1 --workers 16
"""
from __future__ import annotations

import argparse
import atexit
import base64
import io
import json
import logging
import os
import pathlib
import re
import shutil
import signal
import sys
import tarfile
import tempfile
import threading
import time
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


def _install_docker_import_stub() -> None:
    """Install the import-only Docker surface used by the AutoBax modules.

    This grader never uses a local Docker daemon: all build/run work happens through
    the sandbox service. Always install the stub, even when the Docker Python package
    is present, because importing ``env.base`` otherwise calls ``docker.from_env()``
    at module scope and dies with DockerException on hosts with no Docker socket.
    Mirrors the same fix already applied to grader/baxbench/src/grade_sandbox.py.
    """

    import sys
    import types

    docker_mod = types.ModuleType("docker")
    errors_mod = types.ModuleType("docker.errors")
    models_mod = types.ModuleType("docker.models")
    containers_mod = types.ModuleType("docker.models.containers")

    class ImageNotFound(Exception):
        pass

    class APIError(Exception):
        pass

    class Container:
        pass

    class ExecResult:
        pass

    class _Images:
        def get(self, tag):
            raise ImageNotFound(tag)

    class _Client:
        images = _Images()

    def from_env(*args, **kwargs):
        return _Client()

    errors_mod.ImageNotFound = ImageNotFound
    errors_mod.APIError = APIError
    containers_mod.Container = Container
    containers_mod.ExecResult = ExecResult
    models_mod.containers = containers_mod
    docker_mod.errors = errors_mod
    docker_mod.models = models_mod
    docker_mod.from_env = from_env

    sys.modules.setdefault("docker", docker_mod)
    sys.modules.setdefault("docker.errors", errors_mod)
    sys.modules.setdefault("docker.models", models_mod)
    sys.modules.setdefault("docker.models.containers", containers_mod)


_install_docker_import_stub()


def _install_optional_harness_import_stubs() -> None:
    import importlib.util
    import sys
    import types

    for name in ("imageio", "pdfplumber", "tqdm"):
        if importlib.util.find_spec(name) is None:
            sys.modules.setdefault(name, types.ModuleType(name))


_install_optional_harness_import_stubs()





from env import all_envs
from scenarios import all_scenarios
from tasks import SampleTestResult, Task, TestResult, esc

_DEFAULT_SAVE_PATH = pathlib.Path(__file__).parent.parent / "results"
_DEFAULT_SANDBOX_DATASET = pathlib.Path(__file__).resolve().parents[4] / "data" / "raw" / "autobax" / "autobax_grading_instances.json"
_DEFAULT_CWE_THEME_MAPPING = None
_SRC_DIR = pathlib.Path(__file__).parent  # AutoBaxBuilder/src
RESULT_MARKER = "__BAXBENCH_RESULT__"
_PY312_TYPE_ALIAS_RE = re.compile(
    r"^(?P<indent>\s*)type (?P<name>[A-Za-z_][A-Za-z0-9_]*) = .*$",
    re.MULTILINE,
)
_SRC_TAR_BYTES: bytes | None = None
_SRC_TAR_LOCK = threading.Lock()
STATUS_GRADED = "graded"
STATUS_NO_PATCH = "no_patch"
STATUS_PATCH_APPLY_ERROR = "patch_apply_error"
STATUS_ERROR = "error"
_CWE_NUM_RE = re.compile(r"(\d+)")

_NON_CODE_MARKER_FILES = {"failed", "server.log"}
_IGNORED_UPLOAD_DIRS = {
    ".cache",
    ".cargo",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "log",
    "node_modules",
    "storage",
    "target",
    "tmp",
    "vendor",
    "venv",
}
_IGNORED_UPLOAD_FILES = {
    ".coverage",
    "db.sqlite3",
    "server.log",
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("grade_sandbox")


def setup_grade_file_logging(report_path: pathlib.Path) -> pathlib.Path:
    log_path = report_path.parent / "grade.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    abs_log_path = log_path.resolve()
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        if isinstance(handler, logging.FileHandler):
            try:
                if pathlib.Path(handler.baseFilename).resolve() == abs_log_path:
                    return log_path
            except Exception:
                pass
    handler = logging.FileHandler(log_path, mode="w")
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root_logger.addHandler(handler)
    return log_path

# Harness deps needed INSIDE the sandbox to import/run the AutoBaxBuilder test code:
#   docker+pyyaml (exploits/scenarios import them at module top), requests (drives the
#   app), pdfplumber/imageio/Pillow/numpy (pdf & image scenarios).
_HARNESS_REQUIREMENTS = pathlib.Path(__file__).resolve().parents[2] / "sandbox-requirements.lock"

SANDBOX_CPU = os.environ.get("BAXBENCH_SANDBOX_CPU", "2")
SANDBOX_MEMORY = os.environ.get("BAXBENCH_SANDBOX_MEMORY", "4Gi")
HEAVY_SANDBOX_MEMORY = os.environ.get("BAXBENCH_HEAVY_SANDBOX_MEMORY", "12Gi")
SANDBOX_STARTUP_TIMEOUT = int(os.environ.get("BAXBENCH_SANDBOX_STARTUP_TIMEOUT", "600"))
POLL_INTERVAL = 2.0
REQUEST_TIMEOUT = 30


class SandboxError(RuntimeError):
    pass


# --- Crash-safe sandbox cleanup (ported from securegen.sandbox) ----------------
_LIVE_SANDBOXES: dict[str, tuple[str, dict]] = {}
_LIVE_LOCK = threading.Lock()
_CLEANUP_INSTALLED = False


def _register_sandbox(sid: str, base_url: str, headers: dict) -> None:
    with _LIVE_LOCK:
        _LIVE_SANDBOXES[sid] = (base_url, headers)


def _unregister_sandbox(sid: str) -> None:
    with _LIVE_LOCK:
        _LIVE_SANDBOXES.pop(sid, None)


def reap_live_sandboxes() -> int:
    with _LIVE_LOCK:
        items = list(_LIVE_SANDBOXES.items())
        _LIVE_SANDBOXES.clear()
    for sid, (base_url, headers) in items:
        try:
            requests.delete(f"{base_url}/sandboxes/{sid}", headers=headers, timeout=10)
        except Exception:
            pass
    return len(items)


def _install_cleanup_handlers() -> None:
    global _CLEANUP_INSTALLED
    if _CLEANUP_INSTALLED:
        return
    _CLEANUP_INSTALLED = True
    atexit.register(reap_live_sandboxes)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            prev = signal.getsignal(sig)

            def _handler(signum, frame, _prev=prev, _sig=sig):
                reap_live_sandboxes()
                if callable(_prev):
                    _prev(signum, frame)
                elif _sig == signal.SIGINT:
                    raise KeyboardInterrupt
                else:
                    raise SystemExit(128 + signum)

            signal.signal(sig, _handler)
        except (ValueError, OSError):
            pass


def sandbox_config() -> tuple[list[str], str]:
    base_urls = [u for u in (
        os.environ.get("SANDBOX_BASE_URL", "").rstrip("/"),
        os.environ.get("SANDBOX_SECOND_URL", "").rstrip("/"),
    ) if u]
    api_key = os.environ.get("SANDBOX_API_KEY", "")
    if not base_urls:
        raise SandboxError("SANDBOX_BASE_URL is unset (source ~/.sandbox_env).")
    if not api_key:
        raise SandboxError("SANDBOX_API_KEY is unset (source ~/.sandbox_env).")
    return base_urls, api_key


class SandboxContainer:
    """A throwaway sandbox started from `image`, with exec / file upload, that deletes
    itself on context exit. Routes everything through the orchestrator HTTP API."""

    def __init__(self, image: str, memory: str | None = None):
        self.image = image
        self.memory = memory or SANDBOX_MEMORY
        self.base_urls, self.api_key = sandbox_config()
        self.base_url = self.base_urls[0]
        self.headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}
        self.sandbox_id: str | None = None
        _install_cleanup_handlers()

    def __enter__(self) -> "SandboxContainer":
        self.sandbox_id = self._create_and_wait()
        return self

    def __exit__(self, *exc) -> None:
        self._delete(self.sandbox_id)
        self.sandbox_id = None

    def _post(self, path: str, body: dict) -> dict:
        r = requests.post(self.base_url + path, headers=self.headers, json=body,
                          timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()

    def _get(self, path: str) -> dict:
        r = requests.get(self.base_url + path, headers=self.headers, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()

    def _create_and_wait(self) -> str:
        errors = []
        for i, url in enumerate(self.base_urls):
            self.base_url = url
            try:
                return self._create_and_wait_on(url)
            except (SandboxError, requests.RequestException) as e:
                errors.append(f"{url}: {e}")
        raise SandboxError("All sandbox endpoints failed: " + " | ".join(errors))

    def _create_and_wait_on(self, url: str) -> str:
        resp = self._post("/sandboxes", {
            "image": self.image,
            "block_network": False,  # need egress for pip / npm / go mod
            "cpu": SANDBOX_CPU,
            "memory": self.memory,
        })
        sid = resp["sandbox_id"]
        _register_sandbox(sid, url, self.headers)
        deadline = time.monotonic() + SANDBOX_STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            if self._get(f"/sandboxes/{sid}").get("ready") is True:
                return sid
            time.sleep(POLL_INTERVAL)
        self._delete(sid)
        raise SandboxError(f"Sandbox {sid} not ready after {SANDBOX_STARTUP_TIMEOUT}s.")

    def _exec_raw(self, command: str, timeout: int) -> dict:
        if not self.sandbox_id:
            raise SandboxError("exec on a sandbox that is not running")
        job_id = self._post(f"/sandboxes/{self.sandbox_id}/exec",
                            {"command": command, "timeout_seconds": timeout})["job_id"]
        deadline = time.monotonic() + timeout + 60
        while time.monotonic() < deadline:
            job = self._get(f"/jobs/{job_id}")
            if job.get("status") in ("succeeded", "failed"):
                return job
            time.sleep(POLL_INTERVAL)
        return {"stdout": "", "stderr": "", "exit_code": -1, "status": "timeout"}

    def exec(self, cmd: str, timeout: int = 1200) -> tuple[int, str, str]:
        b64 = base64.b64encode(cmd.encode()).decode()
        wrapped = f'bash -lc "$(echo {b64} | base64 -d)"'
        job = self._exec_raw(wrapped, timeout)
        code = job.get("exit_code")
        code = -1 if code is None else int(code)
        return code, job.get("stdout") or "", job.get("stderr") or ""

    def upload_dir(self, local_dir: pathlib.Path, remote_dir: str) -> None:
        """Tar+gzip `local_dir`, ship it as chunked base64 (so arbitrarily large trees
        survive shell arg limits), and extract it into `remote_dir`."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(local_dir, arcname=".")
        self._upload_tar_bytes(buf.getvalue(), remote_dir)

    def upload_files(self, files: dict[pathlib.Path, bytes], remote_dir: str) -> None:
        """Upload generated source files after grader-side artifact filtering."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for rel_path, data in files.items():
                info = tarfile.TarInfo(str(rel_path))
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        self._upload_tar_bytes(buf.getvalue(), remote_dir)

    def _upload_tar_bytes(self, data: bytes, remote_dir: str) -> None:
        b64 = base64.b64encode(data).decode()
        remote_tar = f"/tmp/_up_{uuid.uuid4().hex[:8]}.tgz"
        code, out, err = self.exec(f"mkdir -p {remote_dir} && : > {remote_tar}.b64", timeout=60)
        if code != 0:
            raise SandboxError(f"prepare upload failed: rc={code} {(err or out)[-300:]}")
        CHUNK = 48 * 1024  # base64 chars per exec; keep the decoded command well under arg limits
        for i in range(0, len(b64), CHUNK):
            piece = b64[i:i + CHUNK]
            code, out, err = self.exec(
                f"printf '%s' '{piece}' >> {remote_tar}.b64", timeout=120)
            if code != 0:
                raise SandboxError(f"upload chunk failed: rc={code} {(err or out)[-300:]}")
        code, out, err = self.exec(
            f"base64 -d {remote_tar}.b64 > {remote_tar} && "
            f"tar -C {remote_dir} -xzf {remote_tar} && rm -f {remote_tar} {remote_tar}.b64",
            timeout=300)
        if code != 0:
            raise SandboxError(f"extract upload failed: rc={code} {(err or out)[-300:]}")

    def _delete(self, sid: str | None) -> None:
        if not sid:
            return
        try:
            requests.delete(f"{self.base_url}/sandboxes/{sid}",
                            headers=self.headers, timeout=REQUEST_TIMEOUT)
        except Exception:
            pass
        finally:
            _unregister_sandbox(sid)


def sandbox_instance_id(task: Task, sample: int) -> str:
    return (f"{task.env.id}-{task.scenario.id}-{task.spec_type}-"
            f"{task.safety_prompt}-{float(task.temperature)}-sample{sample}").replace("/", "-")


_SAMPLE_SUFFIX_RE = re.compile(r"-sample\d+$")


def sandbox_image_key_from_instance_id(instance_id: str) -> str:
    """Return the task-level image key shared by every generated sample."""
    return _SAMPLE_SUFFIX_RE.sub("", instance_id)


def sandbox_image_key(task: Task) -> str:
    return (f"{task.env.id}-{task.scenario.id}-{task.spec_type}-"
            f"{task.safety_prompt}-{float(task.temperature)}").replace("/", "-")


def load_sandbox_image_map(path: pathlib.Path | None) -> tuple[dict[str, str], dict[str, str]]:
    if path is None or not path.exists():
        return {}, {}
    rows = json.loads(path.read_text())
    if isinstance(rows, dict):
        rows = list(rows.values())
    if not isinstance(rows, list):
        raise ValueError(f"{path} must be a JSON list or object")
    image_map: dict[str, str] = {}
    env_image_map: dict[str, str] = {}
    canonical_env_ids = {esc(env.id): env.id for env in all_envs}
    for row in rows:
        if not isinstance(row, dict):
            continue
        iid = row.get("instance_id")
        image = row.get("image_name")
        if iid and image:
            image_key = sandbox_image_key_from_instance_id(str(iid))
            image = str(image)
            previous_image = image_map.get(image_key)
            if previous_image is not None and previous_image != image:
                raise ValueError(
                    f"Conflicting sandbox images for sample-independent key {image_key}: "
                    f"{previous_image} != {image}"
                )
            image_map[image_key] = image
            env_id = str(iid).split("-", 1)[0]
            # Env ids can contain hyphens, so prefer the explicit results_subdir when present.
            subdir = row.get("results_subdir")
            if subdir:
                parts = pathlib.PurePosixPath(str(subdir)).parts
                if len(parts) >= 2:
                    env_id = parts[1]
            # Result directories escape slashes (Go-net/http -> Go-net-http), while
            # Task.env.id retains the canonical framework name used for lookups.
            env_id = canonical_env_ids.get(env_id, env_id)
            env_image_map.setdefault(env_id, str(image))
    return image_map, env_image_map


def image_for_task(
    task: Task,
    sandbox_images: tuple[dict[str, str], dict[str, str]],
) -> tuple[str, bool]:
    """Return (image ref, has_scenario_packages).

    Image selection is deliberately sample-independent: every generated sample for the
    same task uses the same prebuilt environment image. Dataset rows may retain their
    historical ``-sampleN`` suffix, but ``load_sandbox_image_map`` removes it.
    """
    by_task, by_env = sandbox_images
    image_key = sandbox_image_key(task)
    if image_key in by_task:
        return by_task[image_key], True
    if task.env.id in by_env:
        log.warning("No task sandbox image for %s; reusing env image for %s",
                    image_key, task.env.id)
        return by_env[task.env.id], True
    raise SandboxError(
        f"No sandbox image for {image_key} in dataset; pass the matching --sandbox_dataset.")


def grade_one(task: Task, sample: int, results_dir: pathlib.Path, image_prefix: str,
              timeout: int, sandbox_images: tuple[dict[str, str], dict[str, str]]) -> str:
    """Grade one (task, sample) inside a fresh sandbox; write test_results.json."""
    tr_path = task.get_test_results_json_path(results_dir, sample)
    image, has_scenario_packages = image_for_task(task, sandbox_images)
    label = f"{task.model}/{task.scenario.id}/{task.env.id}/sample{sample}"
    files, skipped_files = load_generated_files_for_upload(
        task.get_code_dir(results_dir, sample))
    if skipped_files:
        log.info("[%s] skipped %d generated artifact files before upload",
                 label, skipped_files)

    memory = HEAVY_SANDBOX_MEMORY if task.scenario.id in {"FrameExtract"} else SANDBOX_MEMORY

    with SandboxContainer(image, memory=memory) as sb:
        sb._upload_tar_bytes(patched_src_tar_bytes(), "/opt/autobax/src")
        sb.upload_files({pathlib.Path("requirements.lock"): _HARNESS_REQUIREMENTS.read_bytes()}, "/opt/autobax")
        sb.upload_files(files, "/tmp/autobax_code")
        # Ensure python3 + the harness deps are importable in the sandbox.
        code, out, err = sb.exec(
            "command -v python3 >/dev/null 2>&1 || "
            "(apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y "
            "python3 python3-pip); "
            "python3 -m pip --version >/dev/null 2>&1 || "
            "(apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y "
            "python3-pip); "
            "PIP_BREAK_SYSTEM_PACKAGES=1 python3 -m pip install --quiet -r /opt/autobax/requirements.lock "
            "|| PIP_BREAK_SYSTEM_PACKAGES=1 python3 -m pip install -r /opt/autobax/requirements.lock",
            timeout=900)
        if code != 0:
            raise SandboxError(f"{label}: pinned dependency install failed: rc={code} {(err or out)[-300:]}")
        code, out, err = sb.exec(
            "cd /opt/autobax/src && PYTHONPATH=/opt/autobax/src python3 in_container_runner.py "
            f"--scenario {task.scenario.id} --env {task.env.id} "
            f"--code-dir /tmp/autobax_code --timeout {timeout}"
            + (" --skip-extra-pkg-cmds" if has_scenario_packages else ""),
            timeout=timeout * (len(task.scenario.functional_tests)
                               + len(task.scenario.security_tests)) + 600)
        marker_line = next((ln for ln in out.splitlines() if ln.startswith(RESULT_MARKER)),
                          None)
        if marker_line is None:
            raise SandboxError(
                f"runner produced no result. rc={code}\nSTDOUT tail:\n{out[-1500:]}\n"
                f"STDERR tail:\n{err[-1500:]}")
        payload = json.loads(marker_line[len(RESULT_MARKER):])

    tr = TestResult.from_dict(payload)
    tr_path.parent.mkdir(parents=True, exist_ok=True)
    tr_path.write_text(json.dumps(payload, indent=2))
    return (f"[{label}] ft {tr.num_passed_ft}/{tr.num_total_ft} "
            f"(exc {tr.num_ft_exceptions}) | st_exc {tr.num_st_exceptions} | "
            f"cwes {sorted(c.value['num'] for c in tr.cwes)}")


def task_instance_id(task: Task) -> str:
    return (f"{task.model}/{task.scenario.id}/{task.env.id}/"
            f"temp{float(task.temperature)}-{task.spec_type}-{task.safety_prompt}")


def sample_instance_id(task: Task, sample: int) -> str:
    return f"{task_instance_id(task)}/sample{sample}"


def _clean_float(v: float) -> float | None:
    return None if isinstance(v, float) and (v != v) else v


def _should_upload_code_file(path: pathlib.Path) -> bool:
    parts = set(path.parts[:-1])
    if parts & _IGNORED_UPLOAD_DIRS:
        return False
    if path.name in _IGNORED_UPLOAD_FILES:
        return False
    return True


def _looks_like_text(data: bytes) -> bool:
    if b"\x00" in data[:4096]:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def load_generated_files_for_upload(
    code_dir: pathlib.Path,
) -> tuple[dict[pathlib.Path, bytes], int]:
    files: dict[pathlib.Path, bytes] = {}
    skipped = 0
    for path in code_dir.rglob("*"):
        if not path.is_file():
            continue
        rel_path = path.relative_to(code_dir)
        if not _should_upload_code_file(rel_path):
            skipped += 1
            continue
        data = path.read_bytes()
        if not _looks_like_text(data):
            skipped += 1
            continue
        files[rel_path] = data
    return files, skipped


def _patch_py312_type_aliases(path: pathlib.Path) -> None:
    text = path.read_text(encoding="utf-8")
    patched = _PY312_TYPE_ALIAS_RE.sub(r"\g<indent>\g<name> = Any", text)
    if "from __future__ import annotations" not in patched:
        lines = patched.splitlines(keepends=True)
        insert_at = 0
        if lines and lines[0].startswith("#!"):
            insert_at = 1
        if len(lines) > insert_at and "coding" in lines[insert_at]:
            insert_at += 1
        lines.insert(insert_at, "from __future__ import annotations\n")
        patched = "".join(lines)
    if patched != text:
        path.write_text(patched, encoding="utf-8")


def patched_src_tree_for_sandbox() -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory(prefix="autobax_src_")
    dst = pathlib.Path(tmp.name) / "src"
    shutil.copytree(
        _SRC_DIR,
        dst,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
    )
    for path in dst.rglob("*.py"):
        _patch_py312_type_aliases(path)
    return tmp


def patched_src_tar_bytes() -> bytes:
    global _SRC_TAR_BYTES
    if _SRC_TAR_BYTES is not None:
        return _SRC_TAR_BYTES

    with _SRC_TAR_LOCK:
        if _SRC_TAR_BYTES is not None:
            return _SRC_TAR_BYTES

        with patched_src_tree_for_sandbox() as upload_root:
            src_dir = pathlib.Path(upload_root) / "src"
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                tar.add(src_dir, arcname=".")
            _SRC_TAR_BYTES = buf.getvalue()
            log.info("Prepared patched AutoBaxBuilder src tar: %.1f MiB",
                     len(_SRC_TAR_BYTES) / (1024 * 1024))
            return _SRC_TAR_BYTES


def _has_generated_code(task: Task, sample: int, results_dir: pathlib.Path) -> bool:
    code_dir = task.get_code_dir(results_dir, sample)
    if not code_dir.exists():
        return False
    for path in code_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.name in _NON_CODE_MARKER_FILES:
            continue
        return True
    return False


def sample_result_to_dict(task: Task, sample: int, results_dir: pathlib.Path) -> dict:
    path = task.get_test_results_json_path(results_dir, sample)
    base = {
        "instance_id": sample_instance_id(task, sample),
        "task_id": task_instance_id(task),
        "model": task.model,
        "scenario": task.scenario.id,
        "env": task.env.id,
        "sample": sample,
        "result_path": str(path),
        "status": STATUS_ERROR,
        "correct": False,
        "correct_secure": False,
    }
    if not path.exists():
        if not _has_generated_code(task, sample, results_dir):
            base["status"] = STATUS_NO_PATCH
            base["error"] = "no generated code found"
            return base
        base["status"] = STATUS_ERROR
        base["error"] = "missing test_results.json"
        return base
    try:
        tr = TestResult.from_dict(json.loads(path.read_text()))
    except Exception as e:  # noqa: BLE001
        base["status"] = STATUS_ERROR
        base["error"] = str(e)
        return base
    d = tr.to_dict()
    correct = tr.num_total_ft > 0 and tr.num_passed_ft == tr.num_total_ft
    correct_secure = correct and len(tr.cwes) == 0
    base.update({
        "status": STATUS_GRADED,
        "correct": correct,
        "correct_secure": correct_secure,
        "functional_passed": tr.num_passed_ft,
        "functional_total": tr.num_total_ft,
        "functional_exceptions": tr.num_ft_exceptions,
        "security_total": tr.num_total_st,
        "security_exceptions": tr.num_st_exceptions,
        "test_exceptions": tr.num_exceptions,
        "cwes": d["cwes"],
    })
    return base


def task_metrics_to_dict(task: Task, result: SampleTestResult) -> dict:
    return {
        "task_id": task_instance_id(task),
        "model": task.model,
        "scenario": task.scenario.id,
        "env": task.env.id,
        "spec_type": task.spec_type,
        "safety_prompt": task.safety_prompt,
        "temperature": task.temperature,
        "n_samples": result.n_samples,
        "n_ft_correct": result.n_ft_correct,
        "n_ft_and_st_correct": result.n_ft_and_st_correct,
        "n_ft_correct_st_incorrect": result.n_ft_correct_st_incorrect,
        "pass_at_k": {str(k): v for k, v in result.pass_at_k.items()},
        "secure_pass_at_k": {str(k): v for k, v in result.secure_pass_at_k.items()},
        "insec_pass": _clean_float(result.insec_pass),
        "cwe_percentages": result.cwe_percentages,
        "cwe_ft_correct_percentages": result.cwe_ft_correct_percentages,
        "ft_exception_samples": result.ft_exceptions,
        "st_exception_samples": result.st_exceptions,
        "test_exception_samples": result.test_exceptions,
    }


def _norm_cwe_id(raw) -> str:
    s = str(raw).strip()
    if not s:
        return ""
    if s.startswith("NVD-CWE-"):
        return s
    m = _CWE_NUM_RE.search(s)
    return m.group(1) if m else s


def _display_cwe(cwe_id: str) -> str:
    return cwe_id if cwe_id.startswith("NVD-CWE-") else f"CWE-{cwe_id}"


def _load_cwe_theme_mapping(path: pathlib.Path | None) -> tuple[dict[str, str], dict[str, str]]:
    if path is None or not path.exists():
        return {}, {}
    data = json.loads(path.read_text())
    cwe_to_theme = {}
    for theme, cwes in (data.get("themes") or {}).items():
        for raw in cwes:
            cwe_id = _norm_cwe_id(raw)
            if cwe_id:
                cwe_to_theme[cwe_id] = theme
    cwe_names = {_norm_cwe_id(k): str(v) for k, v in (data.get("cwe_names") or {}).items()}
    return cwe_to_theme, cwe_names


def _scenario_target_cwes(task: Task) -> list[str]:
    cwes = set()
    try:
        cwes |= task.scenario._default_potential_cwes()
    except Exception:
        pass
    cwes |= set(getattr(task.scenario, "_additional_potential_cwes", set()))
    ids = sorted({_norm_cwe_id(cwe.value["num"]) for cwe in cwes})
    return ids or ["NVD-CWE-noinfo"]


def _empty_perf_bucket() -> dict:
    keys = ["correct", "correct_secure", "incorrect", "no_patch",
            "patch_apply_error", "error", "missing_prediction"]
    return {
        "num_instances": 0,
        "num_graded": 0,
        "counts": {k: 0 for k in keys},
        "details": {k: [] for k in keys},
    }


def _add_perf_instance(bucket: dict, iid: str, report: dict | None) -> None:
    bucket["num_instances"] += 1
    if report is None:
        bucket["counts"]["missing_prediction"] += 1
        bucket["details"]["missing_prediction"].append(iid)
        return

    bucket["num_graded"] += 1
    status = report.get("status")
    if status == STATUS_NO_PATCH:
        key = "no_patch"
    elif status == STATUS_PATCH_APPLY_ERROR:
        key = "patch_apply_error"
    elif status == STATUS_ERROR:
        key = "error"
    elif status == STATUS_GRADED and report.get("correct"):
        key = "correct"
    else:
        key = "incorrect"

    bucket["counts"][key] += 1
    bucket["details"][key].append(iid)
    if status == STATUS_GRADED and report.get("correct_secure"):
        bucket["counts"]["correct_secure"] += 1
        bucket["details"]["correct_secure"].append(iid)


def _finalize_perf_bucket(bucket: dict) -> dict:
    n = bucket["num_instances"]
    bucket["correct_ratio"] = bucket["counts"]["correct"] / n if n else 0.0
    bucket["correct_secure_ratio"] = bucket["counts"]["correct_secure"] / n if n else 0.0
    return bucket


def summarize_by_cwe_and_theme(
    tasks: list[Task],
    samples: list[int],
    reports_by_iid: dict[str, dict],
    mapping_path: pathlib.Path | None,
) -> dict:
    cwe_to_theme, cwe_names = _load_cwe_theme_mapping(mapping_path)
    by_cwe: dict[str, dict] = {}
    by_theme: dict[str, dict] = {}

    for task in tasks:
        cwe_ids = _scenario_target_cwes(task)
        themes = {cwe_to_theme.get(cwe_id, "Unclassified / Other") for cwe_id in cwe_ids}
        for sample in samples:
            iid = sample_instance_id(task, sample)
            report = reports_by_iid.get(iid)
            for cwe_id in cwe_ids:
                theme = cwe_to_theme.get(cwe_id, "Unclassified / Other")
                display = _display_cwe(cwe_id)
                bucket = by_cwe.setdefault(display, _empty_perf_bucket())
                bucket["name"] = cwe_names.get(cwe_id, "")
                bucket["theme"] = theme
                _add_perf_instance(bucket, iid, report)
            for theme in sorted(themes):
                bucket = by_theme.setdefault(theme, _empty_perf_bucket())
                _add_perf_instance(bucket, iid, report)

    for bucket in by_cwe.values():
        _finalize_perf_bucket(bucket)
    for bucket in by_theme.values():
        _finalize_perf_bucket(bucket)

    by_cwe = dict(sorted(by_cwe.items(), key=lambda kv: (-kv[1]["num_instances"], kv[0])))
    by_theme = dict(sorted(by_theme.items(), key=lambda kv: (-kv[1]["num_instances"], kv[0])))
    return {
        "mapping_path": str(mapping_path) if mapping_path else "",
        "by_theme": by_theme,
        "by_cwe": by_cwe,
    }


def evaluate_and_write_report(
    tasks: list[Task],
    samples: list[int],
    ks: list[int],
    results_dir: pathlib.Path,
    output: pathlib.Path,
    grading: dict,
    cwe_theme_mapping: pathlib.Path | None = _DEFAULT_CWE_THEME_MAPPING,
) -> dict:
    task_results = [(task, task.evaluate_results(results_dir, samples, ks)) for task in tasks]
    sample_reports = [
        sample_result_to_dict(task, sample, results_dir)
        for task in tasks
        for sample in samples
    ]

    details = {
        "correct": [],
        "correct_secure": [],
        "incorrect": [],
        "no_patch": [],
        "patch_apply_error": [],
        "error": [],
        "missing_prediction": [],
    }
    diagnostics = {
        "correct_insecure": [],
        "test_exception": [],
    }
    for r in sample_reports:
        iid = r["instance_id"]
        status = r["status"]
        if status == STATUS_NO_PATCH:
            details["no_patch"].append(iid)
        elif status == STATUS_PATCH_APPLY_ERROR:
            details["patch_apply_error"].append(iid)
        elif status == STATUS_ERROR:
            details["error"].append(iid)
        elif status == STATUS_GRADED:
            if r["correct"]:
                details["correct"].append(iid)
                if r["correct_secure"]:
                    details["correct_secure"].append(iid)
                else:
                    diagnostics["correct_insecure"].append(iid)
            else:
                details["incorrect"].append(iid)
        if r.get("test_exceptions", 0):
            diagnostics["test_exception"].append(iid)

    n = len(sample_reports)
    summary = {
        "num_instances": n,
        "num_graded": n - len(details["missing_prediction"]),
        "correct_ratio": len(details["correct"]) / n if n else 0.0,
        "correct_secure_ratio": len(details["correct_secure"]) / n if n else 0.0,
        "counts": {k: len(v) for k, v in details.items()},
        "details": details,
        "diagnostic_counts": {k: len(v) for k, v in diagnostics.items()},
        "diagnostics": diagnostics,
    }

    reports_by_iid = {r["instance_id"]: r for r in sample_reports}
    cwe_performance = summarize_by_cwe_and_theme(
        tasks, samples, reports_by_iid, cwe_theme_mapping)

    report = {
        "summary": summary,
        "grading": grading,
        "selection": {
            "models": sorted({t.model for t in tasks}),
            "scenarios": sorted({t.scenario.id for t in tasks}),
            "envs": sorted({t.env.id for t in tasks}),
            "samples": samples,
            "ks": ks,
            "results_dir": str(results_dir),
        },
        "performance_by_theme": cwe_performance["by_theme"],
        "performance_by_cwe": cwe_performance["by_cwe"],
        "cwe_theme_mapping": cwe_performance["mapping_path"],
        "tasks": [task_metrics_to_dict(task, result) for task, result in task_results],
        "reports": reports_by_iid,
    }

    try:
        from print import tasks_and_results_to_table, tasks_and_results_to_table_averages
        report["tables"] = {
            "averages": tasks_and_results_to_table_averages(task_results),
            "compact_averages": compact_averages_table(report),
            "details": tasks_and_results_to_table(task_results, verbose=False),
        }
    except Exception as e:  # noqa: BLE001
        report["tables_error"] = str(e)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2))
    return report


def _split_env_id(env_id: str) -> tuple[str, str]:
    if "-" not in env_id:
        return env_id, ""
    language, framework = env_id.split("-", 1)
    return language, framework


def _metric_or_none(total: float, count: int) -> float | None:
    return total / count if count else None


def _fmt_ratio(v: float | None) -> str:
    return "" if v is None else f"{v:.2f}"


def _fmt_pct(v: float | None) -> str:
    return "" if v is None else f"{100 * v:.1f}%"


def compact_averages_table(report: dict) -> str:
    from tabulate import tabulate

    ks = [str(k) for k in report.get("selection", {}).get("ks", [1])]
    k = ks[0] if ks else "1"
    env_order = {env: i for i, env in enumerate(report.get("selection", {}).get("envs", []))}
    selected_samples = report.get("selection", {}).get("samples", [0])
    sample_count = len(selected_samples) if selected_samples else 0
    nums = defaultdict(lambda: defaultdict(int))
    grouped = defaultdict(lambda: defaultdict(lambda: {
        "pass": [0.0, 0],
        "secure": [0.0, 0],
        "insec": [0.0, 0],
    }))

    for task in report.get("tasks", []):
        model = task["model"]
        env_key = (
            task["env"],
            task["spec_type"],
            task["safety_prompt"],
        )
        nums[model][env_key] += sample_count
        pass_val = task.get("pass_at_k", {}).get(k)
        if pass_val is not None:
            grouped[model][env_key]["pass"][0] += pass_val
            grouped[model][env_key]["pass"][1] += 1
        secure_val = task.get("secure_pass_at_k", {}).get(k)
        if secure_val is not None:
            grouped[model][env_key]["secure"][0] += secure_val
            grouped[model][env_key]["secure"][1] += 1
        insec_val = task.get("insec_pass")
        if insec_val is not None:
            grouped[model][env_key]["insec"][0] += insec_val
            grouped[model][env_key]["insec"][1] += 1

    rows = []
    for model in sorted(grouped):
        language_rows = defaultdict(list)
        for env_key, values in grouped[model].items():
            env_id, spec_type, safety_prompt = env_key
            language, framework = _split_env_id(env_id)
            label = framework
            if (spec_type, safety_prompt) != ("text", "none"):
                label += f" ({spec_type},{safety_prompt})"
            pass_avg = _metric_or_none(*values["pass"])
            secure_avg = _metric_or_none(*values["secure"])
            insec_avg = _metric_or_none(*values["insec"])
            num = nums[model][env_key]
            language_rows[language].append((
                env_order.get(env_id, 10_000),
                label,
                num,
                pass_avg,
                secure_avg,
                insec_avg,
            ))

        overall = {"pass": [0.0, 0], "secure": [0.0, 0], "insec": [0.0, 0]}
        overall_num = 0
        for language in sorted(language_rows):
            lang_metrics = {"pass": [0.0, 0], "secure": [0.0, 0], "insec": [0.0, 0]}
            lang_num = 0
            for _, framework, num, pass_avg, secure_avg, insec_avg in sorted(language_rows[language]):
                rows.append([
                    model,
                    language,
                    framework,
                    num,
                    _fmt_ratio(pass_avg),
                    _fmt_ratio(secure_avg),
                    _fmt_pct(insec_avg),
                ])
                lang_num += num
                overall_num += num
                for name, value in (
                    ("pass", pass_avg),
                    ("secure", secure_avg),
                    ("insec", insec_avg),
                ):
                    if value is not None:
                        lang_metrics[name][0] += value
                        lang_metrics[name][1] += 1
                        overall[name][0] += value
                        overall[name][1] += 1
            if len(language_rows[language]) > 1:
                rows.append([
                    model,
                    language,
                    "AVG",
                    lang_num,
                    _fmt_ratio(_metric_or_none(*lang_metrics["pass"])),
                    _fmt_ratio(_metric_or_none(*lang_metrics["secure"])),
                    _fmt_pct(_metric_or_none(*lang_metrics["insec"])),
                ])
        rows.append([
            model,
            "ALL",
            "AVG",
            overall_num,
            _fmt_ratio(_metric_or_none(*overall["pass"])),
            _fmt_ratio(_metric_or_none(*overall["secure"])),
            _fmt_pct(_metric_or_none(*overall["insec"])),
        ])

    return tabulate(
        rows,
        headers=["model", "language", "framework", "num", f"pass@{k}", f"secure@{k}", "insecure"],
        tablefmt="github",
        disable_numparse=True,
    )


def print_summary(report: dict) -> None:
    s = report["summary"]
    print(f"\nGraded: {s['num_graded']}/{s['num_instances']}")
    print(f"Correct ratio:          {s['correct_ratio']:.2%}")
    print(f"Correct & secure ratio: {s['correct_secure_ratio']:.2%}")
    print("Counts:")
    for k, v in s["counts"].items():
        if v:
            print(f"  {k:20s} {v}")
    compact_table = report.get("tables", {}).get("compact_averages")
    if compact_table:
        print()
        print(compact_table)
    elif report.get("tables", {}).get("averages"):
        print()
        print(report["tables"]["averages"])


def default_report_path(models: list[str], results_dir: pathlib.Path) -> pathlib.Path:
    if len(models) == 1:
        return results_dir / esc(models[0]) / "report.json"
    return results_dir / "report.json"


def select_tasks(args) -> list[Task]:
    envs = [e for e in all_envs if not args.envs or e.id in args.envs]
    envs = [e for e in envs if e.id not in (args.exclude_envs or [])]
    scenarios = [s for s in all_scenarios if not args.scenarios or s.id in args.scenarios]
    scenarios = [s for s in scenarios if s.id not in (args.exclude_scenarios or [])]
    if not envs or not scenarios or not args.models:
        raise SystemExit("empty env/scenario/model selection")
    return sorted(
        [Task(env=e, scenario=s, model=m, temperature=args.temperature,
              spec_type=args.spec_type, safety_prompt=args.safety_prompt,
              reasoning_effort=args.reasoning_effort, openrouter=False)
         for e in envs for s in scenarios for m in args.models],
        key=lambda t: t.id)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--models", nargs="+", required=True)
    ap.add_argument("--scenarios", nargs="+")
    ap.add_argument("--exclude_scenarios", nargs="+")
    ap.add_argument("--envs", nargs="+")
    ap.add_argument("--exclude_envs", nargs="+")
    ap.add_argument("--spec_type", default="text")
    ap.add_argument("--safety_prompt", default="none")
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--reasoning_effort", default="medium")
    ap.add_argument("--n_samples", type=int, default=1)
    ap.add_argument("--only_samples", type=int, nargs="+")
    ap.add_argument("--ks", type=int, nargs="+", default=None,
                    help="k values for pass@k / secure_pass@k in the final report")
    ap.add_argument("--results_dir", type=pathlib.Path, default=_DEFAULT_SAVE_PATH)
    ap.add_argument("--output", type=pathlib.Path, default=None,
                    help=("write final JSON report here; default is "
                          "results/<model>/report.json for one model"))
    ap.add_argument("--sandbox_dataset", type=pathlib.Path,
                    default=_DEFAULT_SANDBOX_DATASET,
                    help="JSON dataset with per-instance pushed sandbox image_name refs")
    ap.add_argument("--cwe_theme_mapping", type=pathlib.Path,
                    default=_DEFAULT_CWE_THEME_MAPPING,
                    help=("CWE-to-theme mapping JSON. Adds performance_by_theme and "
                          "performance_by_cwe to report.json."))
    ap.add_argument("--image_prefix", default="",
                    help="kept for CLI compatibility; images come from --sandbox_dataset")
    ap.add_argument("--timeout", type=int, default=90, help="per-test timeout (seconds)")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--force", action="store_true",
                    help="re-grade even if test_results.json already exists")
    ap.add_argument("--include_missing", action="store_true",
                    help="include selected registry tasks that have no generated code/results")
    args = ap.parse_args()

    samples = args.only_samples if args.only_samples else list(range(args.n_samples))
    ks = args.ks if args.ks else [1, 5]
    output = args.output or default_report_path(args.models, args.results_dir)
    log_path = setup_grade_file_logging(output)
    log.info("Writing grade log to %s", log_path)
    tasks = select_tasks(args)
    sandbox_images = load_sandbox_image_map(args.sandbox_dataset)
    task_images, env_images = sandbox_images
    log.info("Loaded %d task-level sandbox image refs (%d env fallbacks) from %s",
             len(task_images), len(env_images), args.sandbox_dataset)

    if args.include_missing:
        before = len(tasks)
        tasks = [
            task for task in tasks
            if sandbox_image_key(task) in task_images
        ]
        log.info("Selected %d/%d tasks present in sandbox dataset",
                 len(tasks), before)
    else:
        before = len(tasks)
        tasks = [
            task for task in tasks
            if any(
                task.get_code_dir(args.results_dir, sample).exists()
                or task.get_test_results_json_path(args.results_dir, sample).exists()
                for sample in samples
            )
        ]
        log.info("Selected %d/%d tasks with generated code/results",
                 len(tasks), before)

    # Build the unit-of-work list: (task, sample) with generated code and (unless --force)
    # no existing result.
    units: list[tuple[Task, int]] = []
    for task in tasks:
        for sample in samples:
            if not task.get_code_dir(args.results_dir, sample).exists():
                continue
            if not args.force and task.get_test_results_json_path(
                    args.results_dir, sample).exists():
                continue
            units.append((task, sample))

    log.info("Grading %d (task,sample) units across %d workers", len(units), args.workers)
    done = failed = 0
    failures = []
    if units:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(grade_one, t, s, args.results_dir, args.image_prefix,
                              args.timeout, sandbox_images): (t, s) for t, s in units}
            for fut in as_completed(futs):
                t, s = futs[fut]
                try:
                    log.info(fut.result())
                    done += 1
                except Exception as e:
                    failed += 1
                    failure = {
                        "instance_id": sample_instance_id(t, s),
                        "model": t.model,
                        "scenario": t.scenario.id,
                        "env": t.env.id,
                        "sample": s,
                        "error": str(e),
                    }
                    failures.append(failure)
                    log.error("[%s/%s/%s sample%d] FAILED: %s",
                              t.model, t.scenario.id, t.env.id, s, e)
    log.info("Done. graded=%d failed=%d", done, failed)

    grading = {
        "requested_units": len(units),
        "graded_now": done,
        "failed_now": failed,
        "failures": failures,
        "force": args.force,
        "image_prefix": args.image_prefix,
        "sandbox_dataset": str(args.sandbox_dataset),
        "sandbox_image_refs": len(task_images),
        "sandbox_env_image_fallbacks": len(env_images),
        "timeout": args.timeout,
        "workers": args.workers,
    }
    report = evaluate_and_write_report(
        tasks=tasks,
        samples=samples,
        ks=ks,
        results_dir=args.results_dir,
        output=output,
        grading=grading,
        cwe_theme_mapping=args.cwe_theme_mapping,
    )
    print_summary(report)
    print(f"\nWrote {output}")


if __name__ == "__main__":
    main()

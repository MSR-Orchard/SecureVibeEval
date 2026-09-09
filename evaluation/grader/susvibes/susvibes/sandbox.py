"""Grade SusVibes predictions on the self-hosted **sandbox service** instead of
local Docker.

This is the grading-phase counterpart to the agent-rollout sandbox backend used by
mini-swe-agent (`environment_class: sandbox`). It mirrors the default runtime-patch
grading flow in `susvibes.env` / `susvibes.tasks` (apply the model patch at start,
run the test suite, capture combined stdout+stderr, regex-parse the logs) but swaps
`docker create`/`put_archive`/`start`/`logs` for the orchestrator HTTP API.

Unlike Docker, the sandbox replaces PID 1 with its own agent, so the image's baked
`CMD` does **not** run automatically. The test command is therefore taken from the
env-spec dockerfile `CMD` (see `Env._test_command`), not from the live image.

API (auth via the ``X-API-Key`` header):
    POST   /sandboxes            {image, block_network, cpu, memory} -> {sandbox_id}
    GET    /sandboxes/{id}       poll until {"ready": true}
    POST   /sandboxes/{id}/exec  {command, timeout_seconds} -> {job_id}   (async)
    GET    /jobs/{id}            -> {status, stdout, stderr, exit_code}
    DELETE /sandboxes/{id}       delete

Selected via `--backend sandbox`. Credentials come from $SANDBOX_BASE_URL and
$SANDBOX_API_KEY (e.g. `source ~/.sandbox_env`). An optional $SANDBOX_SECOND_URL
is used as a fallback endpoint when the primary can't provision a sandbox (e.g.
its cluster is out of capacity).
"""

import os
import time
import atexit
import signal
import base64
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

import requests

from susvibes.constants import CONTAINER_RUN_TIMEOUT
from susvibes.env_specs import WORKSPACE_DIR_NAME, REVERSE_PATCH_FLAG
from susvibes.utils import mirror_image

# Printed by the runtime command when `git apply` fails, so the evaluator can tell an
# unappliable model patch apart from a genuine test failure. Kept identical to the
# Docker runtime path's sentinel so `Task._run_test_suite_runtime` detects it the same way.
from susvibes.env import PATCH_APPLY_SENTINEL

# Per-sandbox resource caps. The sandbox cluster sizes pods from these, so keep them
# modest (the eval suites are light) and well under per-node limits; override via env.
SANDBOX_CPU = os.environ.get("SUSVIBES_SANDBOX_CPU", "2")
SANDBOX_MEMORY = os.environ.get("SUSVIBES_SANDBOX_MEMORY", "8Gi")
# Seconds to wait for a freshly created sandbox to become ready. A cold burst can wait
# for node autoscaling; warm starts are a few seconds.
SANDBOX_STARTUP_TIMEOUT = int(os.environ.get("SUSVIBES_SANDBOX_STARTUP_TIMEOUT", "360"))
POLL_INTERVAL = 2.0
REQUEST_TIMEOUT = 30  # per-HTTP-request timeout (not command execution)


class SandboxError(RuntimeError):
    pass


# --- Crash-safe sandbox cleanup ------------------------------------------------
# run_with_timeout deletes its sandbox in a `finally` on the normal path. That
# finally does NOT run when the process is killed mid-flight (Ctrl-C / SIGTERM /
# `os._exit` / OOM), so a killed run leaks every in-flight sandbox -- each holding
# cluster CPU/memory until manually deleted, which is exactly how a primary cluster
# fills up with `unschedulable` orphans. This registry + the atexit/signal handlers
# below are the safety net for those abnormal exits, mirroring how TasksHandler reaps
# leftover Docker containers by session label on shutdown.
_LIVE_SANDBOXES: dict[str, tuple[str, dict]] = {}  # sandbox_id -> (base_url, headers)
_LIVE_LOCK = threading.Lock()
_CLEANUP_INSTALLED = False


def _register_sandbox(sandbox_id: str, base_url: str, headers: dict) -> None:
    with _LIVE_LOCK:
        _LIVE_SANDBOXES[sandbox_id] = (base_url, headers)


def _unregister_sandbox(sandbox_id: str) -> None:
    with _LIVE_LOCK:
        _LIVE_SANDBOXES.pop(sandbox_id, None)


def reap_live_sandboxes() -> int:
    """Best-effort delete of every sandbox still registered as live; returns the
    count attempted. Idempotent: it claims the registry under the lock up front, so
    concurrent atexit/signal invocations don't double-delete or race. Deletes run in
    parallel with a short timeout so teardown on Ctrl-C is fast even with many pods."""
    with _LIVE_LOCK:
        items = list(_LIVE_SANDBOXES.items())
        _LIVE_SANDBOXES.clear()
    if not items:
        return 0

    def _kill(item):
        sandbox_id, (base_url, headers) = item
        try:
            requests.delete(f"{base_url}/sandboxes/{sandbox_id}",
                            headers=headers, timeout=10)
        except Exception:
            pass  # cleanup is best-effort; the run is already tearing down

    with ThreadPoolExecutor(max_workers=min(32, len(items))) as ex:
        list(ex.map(_kill, items))
    return len(items)


def _install_cleanup_handlers() -> None:
    """Register the reaper for normal exit (atexit) and for SIGINT/SIGTERM. Idempotent
    and main-thread-safe: signal handlers can only be set from the main thread, so a
    call from a worker thread silently skips them (atexit still covers normal exit).
    The previous handler is chained so the harness's own Ctrl-C handling still runs."""
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
            pass  # not in the main thread; atexit still provides coverage


_install_cleanup_handlers()


def sandbox_config() -> tuple[list[str], str]:
    """Return (base_urls, api_key) from the environment, or raise if unset.

    base_urls is the primary SANDBOX_BASE_URL followed by an optional
    SANDBOX_SECOND_URL fallback, in the order they should be tried. The fallback
    covers the case where the primary endpoint is reachable but its cluster can't
    schedule a sandbox (out of capacity)."""
    base_urls = [url for url in (
        os.environ.get("SANDBOX_BASE_URL", "").rstrip("/"),
        os.environ.get("SANDBOX_SECOND_URL", "").rstrip("/"),
    ) if url]
    api_key = os.environ.get("SANDBOX_API_KEY", "")
    if not base_urls:
        raise SandboxError("SANDBOX_BASE_URL is unset (source ~/.sandbox_env).")
    if not api_key:
        raise SandboxError("SANDBOX_API_KEY is unset (source ~/.sandbox_env).")
    return base_urls, api_key


def _runtime_script(test_command: str, workdir: str, num_patches: int) -> str:
    """Shell script that applies /patches/<id>.patch then runs the test command.

    Mirrors `Env._runtime_command`: on a failed `git apply` it prints the sentinel and
    exits non-zero so the evaluator records MODEL_PATCH_ERROR instead of a test failure.
    Patch files are written separately (see SandboxDeployment._write_patches)."""
    applies = " && ".join(
        f"git apply --ignore-space-change /patches/{i}.patch" for i in range(num_patches)
    ) or "true"
    return (
        f"cd {workdir} || exit 1\n"
        f"if ! ({applies}); then echo '{PATCH_APPLY_SENTINEL}'; exit 3; fi\n"
        f"{test_command}"
    )


class SandboxDeployment:
    """A run-once grading deployment backed by one throwaway sandbox.

    Construction is cheap (no network); all sandbox lifecycle happens in
    `run_with_timeout`, which always deletes the sandbox before returning. Interface
    matches the Docker `Deployment` so `Task._run_test_suite_runtime` is unchanged.
    """

    def __init__(
        self,
        image_name: str,
        test_command: str,
        workdir: str,
        patches: tuple[str, ...],
        logger: logging.Logger,
    ):
        # Pull through a Docker Hub mirror (mirror.gcr.io) for fast, rate-limit-free pulls
        # so sandboxes don't sit Pending on cold pulls. Canonical name stays in the dataset;
        # only the pull reference is rewritten (same approach as the SWE-bench harness).
        self.image_name = mirror_image(image_name)
        self.test_command = test_command
        self.workdir = workdir or f"/{WORKSPACE_DIR_NAME}"
        # Reverse-patch flags are markers, not real patches; the runtime path never
        # reverses model patches, so drop them to match the applied-patch count.
        self.patches = tuple(p for p in patches if p not in REVERSE_PATCH_FLAG)
        self.logger = logger
        self.base_urls, self.api_key = sandbox_config()
        # The endpoint in use for this sandbox's lifecycle. _create_and_wait may
        # advance it through self.base_urls on failure; once a sandbox is created,
        # all later exec/delete calls must target the same endpoint.
        self.base_url = self.base_urls[0]
        self.headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}
        _install_cleanup_handlers()  # idempotent; ensures the crash-safe reaper is armed

    # --- orchestrator helpers ---
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
        """Create a sandbox and wait for it to become ready, falling back to the
        next configured endpoint if one fails to provision (unreachable, or its
        cluster can't schedule the pod within SANDBOX_STARTUP_TIMEOUT)."""
        errors = []
        for i, url in enumerate(self.base_urls):
            self.base_url = url  # subsequent exec/delete reuse the working endpoint
            try:
                return self._create_and_wait_on(url)
            except (SandboxError, requests.RequestException) as e:
                errors.append(f"{url}: {e}")
                if i + 1 < len(self.base_urls):
                    self.logger.warning(
                        f"Sandbox provisioning failed on {url}; falling back to "
                        f"{self.base_urls[i + 1]}. ({e})")
        raise SandboxError("All sandbox endpoints failed to provision: "
                           + " | ".join(errors))

    def _create_and_wait_on(self, url: str) -> str:
        resp = self._post("/sandboxes", {
            "image": self.image_name,
            "block_network": False,
            "cpu": SANDBOX_CPU,
            "memory": SANDBOX_MEMORY,
        })
        sandbox_id = resp["sandbox_id"]
        # Track before the readiness wait so an interrupt during the wait still reaps it.
        _register_sandbox(sandbox_id, url, self.headers)
        self.logger.info(f"Created sandbox {sandbox_id} from image {self.image_name} "
                         f"on {url}.")
        deadline = time.monotonic() + SANDBOX_STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            if self._get(f"/sandboxes/{sandbox_id}").get("ready") is True:
                self.logger.info(f"Sandbox {sandbox_id} ready.")
                return sandbox_id
            time.sleep(POLL_INTERVAL)
        self._delete(sandbox_id)
        raise SandboxError(
            f"Sandbox {sandbox_id} not ready after {SANDBOX_STARTUP_TIMEOUT}s.")

    def _exec(self, sandbox_id: str, command: str, timeout: int) -> tuple[dict, bool]:
        """Run `command`; return (job, timed_out). Combines no streams here."""
        job_id = self._post(f"/sandboxes/{sandbox_id}/exec",
            {"command": command, "timeout_seconds": timeout})["job_id"]
        # Allow the command's own timeout plus slack for queueing/polling overhead.
        deadline = time.monotonic() + timeout + 60
        while time.monotonic() < deadline:
            job = self._get(f"/jobs/{job_id}")
            if job.get("status") in ("succeeded", "failed"):
                # The service kills the command at timeout_seconds; surface that as a
                # timeout (coreutils/-style 124, or an elapsed wall-clock fallback).
                timed_out = job.get("exit_code") == 124
                return job, timed_out
            time.sleep(POLL_INTERVAL)
        return {"stdout": "", "stderr": "", "exit_code": -1}, True

    def _write_patches(self, sandbox_id: str) -> None:
        """Write each model patch to /patches/<id>.patch (base64 to avoid shell-escaping
        the diff). One exec per patch; the sandbox filesystem persists across execs."""
        for i, patch in enumerate(self.patches):
            b64 = base64.b64encode(patch.encode()).decode()
            cmd = f"mkdir -p /patches && printf %s '{b64}' | base64 -d > /patches/{i}.patch"
            job, _ = self._exec(sandbox_id, cmd, timeout=60)
            if job.get("exit_code") not in (0, None):
                raise SandboxError(
                    f"Failed to stage patch {i} into sandbox {sandbox_id}: "
                    f"{(job.get('stderr') or '')[:200]}")

    def _delete(self, sandbox_id: str | None) -> None:
        if not sandbox_id:
            return
        try:
            requests.delete(f"{self.base_url}/sandboxes/{sandbox_id}",
                headers=self.headers, timeout=REQUEST_TIMEOUT)
            self.logger.info(f"Sandbox {sandbox_id} deleted.")
        except Exception as e:  # cleanup is best-effort
            self.logger.warning(f"Failed to delete sandbox {sandbox_id}: {e}")
        finally:
            # Drop it from the crash-safe registry: deleted (or unreachable) sandboxes
            # must not be re-targeted by the atexit/signal reaper.
            _unregister_sandbox(sandbox_id)

    # --- Deployment interface ---
    def run_with_timeout(self, timeout: int = CONTAINER_RUN_TIMEOUT) -> tuple[str, bool]:
        """Create a sandbox, apply patches, run the test suite, and return
        (combined_logs, timed_out). The sandbox is always deleted before returning."""
        sandbox_id = None
        try:
            sandbox_id = self._create_and_wait()
            self._write_patches(sandbox_id)
            script = _runtime_script(self.test_command, self.workdir, len(self.patches))
            job, timed_out = self._exec(sandbox_id, script, timeout=timeout)
            # Docker grading reads combined stdout+stderr; match that for the parser.
            logs = (job.get("stdout") or "") + (job.get("stderr") or "")
            if timed_out:
                self.logger.warning(f"Sandbox {sandbox_id} run timed out after {timeout}s.")
            return logs, timed_out
        finally:
            self._delete(sandbox_id)

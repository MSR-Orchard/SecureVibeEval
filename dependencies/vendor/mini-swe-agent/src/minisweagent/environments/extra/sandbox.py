"""Execute commands on the self-hosted **sandbox service** (Modal-style `aks_modal`
orchestrator) instead of local Docker.

This is the lightweight sibling of the SWE-agent + SWE-rex sandbox backend. mini does
not use SWE-rex: its whole execution contract is the one-method ``Environment`` protocol
and every command runs as a fresh subprocess. The sandbox service is the same model
(``/exec`` = fresh shell each time; filesystem persists within a sandbox), so this is a
near-clone of ``DockerEnvironment`` that swaps ``docker run`` / ``docker exec`` for the
orchestrator HTTP API.

API (auth via the ``X-API-Key`` header):
    POST   /sandboxes               {image, block_network, cpu, memory} -> {sandbox_id}
    GET    /sandboxes/{id}          poll until {"ready": true}
    POST   /sandboxes/{id}/exec     {command, timeout_seconds, cwd, env} -> {job_id}  (async)
    POST   /sandboxes/{id}/heartbeat keep a long-running sandbox alive
    GET    /jobs/{id}               -> {status, stdout, stderr, exit_code}
    DELETE /sandboxes/{id}          delete

See `evaluation_harness/mini_swe_agent/MINI_SANDBOX_INTEGRATION.md` in the SusVibes repo
for the design notes behind this adapter.
"""

import atexit
import logging
import os
import platform
import signal
import threading
import time
from typing import Any

import requests
from pydantic import BaseModel

from minisweagent.exceptions import Submitted
from minisweagent.utils.serialize import recursive_merge

# --- crash-safe sandbox reaper ----------------------------------------------
# Relying on SandboxEnvironment.__del__ alone leaks sandboxes: a Ctrl+C / SIGTERM
# (or os._exit in a batch runner) can terminate the process before finalizers run,
# leaving the POST'd pods alive until the orchestrator's TTL. We track every live
# sandbox in a module-level registry and reap it on interpreter exit (atexit) and on
# SIGTERM. SIGINT is left to the caller's own handler so batch runners keep their
# two-stage ^C semantics; the atexit backstop still reaps once they shut down.
_LIVE_SANDBOXES: dict[str, dict] = {}  # sandbox_id -> {"base", "headers", "timeout"}
_LIVE_LOCK = threading.Lock()
_REAPER_INSTALLED = False


def _register_sandbox(sandbox_id: str, base: str, headers: dict, timeout: int) -> None:
    with _LIVE_LOCK:
        _LIVE_SANDBOXES[sandbox_id] = {"base": base, "headers": headers, "timeout": timeout}


def _unregister_sandbox(sandbox_id: str) -> None:
    with _LIVE_LOCK:
        _LIVE_SANDBOXES.pop(sandbox_id, None)


def _reap_sandboxes() -> None:
    """Best-effort DELETE of every still-registered sandbox. Safe to call repeatedly."""
    with _LIVE_LOCK:
        items = list(_LIVE_SANDBOXES.items())
        _LIVE_SANDBOXES.clear()
    for sandbox_id, info in items:
        try:
            requests.delete(f"{info['base']}/sandboxes/{sandbox_id}",
                            headers=info["headers"], timeout=info["timeout"])
        except Exception:
            pass  # nothing useful to do during shutdown


def install_reaper() -> None:
    """Install the atexit + SIGTERM reaper once. Idempotent. Signal handlers can only be
    set from the main thread, so call this from your run entrypoint (the per-sandbox
    constructor also calls it, which at least arms the atexit backstop from worker threads)."""
    global _REAPER_INSTALLED
    if not _REAPER_INSTALLED:
        _REAPER_INSTALLED = True
        atexit.register(_reap_sandboxes)
    if threading.current_thread() is threading.main_thread():
        prev = signal.getsignal(signal.SIGTERM)

        def _handler(signum, frame, _prev=prev):
            _reap_sandboxes()
            if callable(_prev) and _prev not in (signal.SIG_DFL, signal.SIG_IGN):
                _prev(signum, frame)
            raise SystemExit(128 + signum)

        try:
            signal.signal(signal.SIGTERM, _handler)
        except (ValueError, OSError):
            pass  # not the main thread, or unsupported platform


class SandboxEnvironmentConfig(BaseModel):
    image: str = "python:3.11"
    """Image the sandbox is created from (e.g. a prebaked per-task image)."""
    base_url: str = os.environ.get("SANDBOX_BASE_URL", "")
    """Orchestrator base URL. Defaults to $SANDBOX_BASE_URL."""
    api_key: str = os.environ.get("SANDBOX_API_KEY", "")
    """Orchestrator API key (sent as the X-API-Key header). Defaults to $SANDBOX_API_KEY."""
    cwd: str = "/"
    """Working directory in which to execute commands."""
    env: dict[str, str] = {}
    """Environment variables to set for every command."""
    forward_env: list[str] = []
    """Host environment variables to forward into the sandbox (only if set on the host).
    In case of conflict with `env`, the `env` variables take precedence."""
    timeout: int = 30
    """Per-command timeout in seconds; mapped to the exec `timeout_seconds`."""
    block_network: bool = False
    """Block egress from the sandbox. Must be False if commands need the internet."""
    cpu: str = "2"
    """CPU hard cap for the sandbox."""
    memory: str = "4Gi"
    """Memory hard cap for the sandbox."""
    startup_timeout: int = 360
    """Seconds to wait for the sandbox to become ready before giving up.
    A cold burst can wait ~90s+ for node autoscaling; warm starts are a few seconds."""
    poll_interval: float = 2.0
    """Seconds between status/job polls."""
    request_timeout: int = 30
    """Per-HTTP-request timeout for orchestrator calls (not command execution)."""
    heartbeat_interval: float = 60.0
    """Seconds between sandbox heartbeats. The orchestrator deletes sandboxes that
    do not receive heartbeats within its configured lifetime, including while the
    agent is waiting on a long model request."""


class SandboxEnvironment:
    def __init__(
        self,
        *,
        config_class: type = SandboxEnvironmentConfig,
        logger: logging.Logger | None = None,
        **kwargs,
    ):
        """Execute bash commands in a sandbox provided by the self-hosted orchestrator.
        See `SandboxEnvironmentConfig` for keyword arguments.
        """
        self.logger = logger or logging.getLogger("minisweagent.environment")
        self.sandbox_id: str | None = None
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self.config = config_class(**kwargs)
        if not self.config.base_url:
            raise ValueError("Sandbox base_url is empty (set SANDBOX_BASE_URL or environment.base_url).")
        if not self.config.api_key:
            raise ValueError("Sandbox api_key is empty (set SANDBOX_API_KEY or environment.api_key).")
        self._base = self.config.base_url.rstrip("/")
        self._headers = {"X-API-Key": self.config.api_key, "Content-Type": "application/json"}
        self.sandbox_id = self._create_and_wait()
        self._start_heartbeat()

    # --- orchestrator helpers ---
    def _create_and_wait(self) -> str:
        """POST /sandboxes, then poll GET /sandboxes/{id} until ready. Returns sandbox_id."""
        resp = requests.post(
            f"{self._base}/sandboxes",
            headers=self._headers,
            json={
                "image": self.config.image,
                "block_network": self.config.block_network,
                "cpu": self.config.cpu,
                "memory": self.config.memory,
            },
            timeout=self.config.request_timeout,
        )
        resp.raise_for_status()
        sandbox_id = resp.json()["sandbox_id"]
        # Track immediately (before the readiness wait) so an interrupt mid-startup still reaps it.
        install_reaper()
        _register_sandbox(sandbox_id, self._base, self._headers, self.config.request_timeout)
        self.logger.info(f"Created sandbox {sandbox_id} from image {self.config.image}")

        deadline = time.monotonic() + self.config.startup_timeout
        while time.monotonic() < deadline:
            status = requests.get(
                f"{self._base}/sandboxes/{sandbox_id}",
                headers=self._headers,
                timeout=self.config.request_timeout,
            )
            status.raise_for_status()
            if status.json().get("ready") is True:
                self.logger.info(f"Sandbox {sandbox_id} ready")
                return sandbox_id
            time.sleep(self.config.poll_interval)
        # Best-effort cleanup so we don't leak a sandbox that never came up.
        self._delete(sandbox_id)
        raise TimeoutError(f"Sandbox {sandbox_id} not ready after {self.config.startup_timeout}s")

    def _exec(self, command: str, cwd: str, env: dict[str, str], timeout: int) -> dict:
        """POST /exec -> job_id; poll /jobs/{id} until terminal. Returns the job dict."""
        resp = requests.post(
            f"{self._base}/sandboxes/{self.sandbox_id}/exec",
            headers=self._headers,
            json={"command": command, "cwd": cwd, "env": env, "timeout_seconds": timeout},
            timeout=self.config.request_timeout,
        )
        resp.raise_for_status()
        job_id = resp.json()["job_id"]

        # Allow the command's own timeout plus slack for queueing/polling overhead.
        deadline = time.monotonic() + timeout + self.config.startup_timeout
        while time.monotonic() < deadline:
            job = requests.get(
                f"{self._base}/jobs/{job_id}",
                headers=self._headers,
                timeout=self.config.request_timeout,
            )
            job.raise_for_status()
            data = job.json()
            if data.get("status") in ("succeeded", "failed"):
                return data
            time.sleep(self.config.poll_interval)
        raise TimeoutError(f"Job {job_id} did not finish within {timeout + self.config.startup_timeout}s")

    def _heartbeat_once(self, sandbox_id: str) -> None:
        response = requests.post(
            f"{self._base}/sandboxes/{sandbox_id}/heartbeat",
            headers=self._headers,
            timeout=min(self.config.request_timeout, 10),
        )
        response.raise_for_status()

    def _start_heartbeat(self) -> None:
        """Keep the sandbox alive while inference is running between tool calls."""
        sandbox_id = self.sandbox_id
        if not sandbox_id:
            return
        if self.config.heartbeat_interval <= 0:
            raise ValueError("heartbeat_interval must be positive")

        try:
            self._heartbeat_once(sandbox_id)
        except Exception as error:
            # A transient heartbeat failure should not discard a ready sandbox; the
            # background loop retries on the next interval.
            self.logger.warning(f"Initial heartbeat failed for sandbox {sandbox_id}: {error}")

        def heartbeat_loop() -> None:
            while not self._heartbeat_stop.wait(self.config.heartbeat_interval):
                current_id = self.sandbox_id
                if not current_id:
                    return
                try:
                    self._heartbeat_once(current_id)
                except Exception as error:
                    self.logger.warning(f"Heartbeat failed for sandbox {current_id}: {error}")

        self._heartbeat_thread = threading.Thread(
            target=heartbeat_loop,
            name=f"sandbox-heartbeat-{sandbox_id}",
            daemon=True,
        )
        self._heartbeat_thread.start()

    def _stop_heartbeat(self) -> None:
        self._heartbeat_stop.set()
        thread = self._heartbeat_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=min(self.config.request_timeout, 10) + 1)
        self._heartbeat_thread = None

    def _delete(self, sandbox_id: str | None) -> None:
        if not sandbox_id:
            return
        try:
            requests.delete(
                f"{self._base}/sandboxes/{sandbox_id}",
                headers=self._headers,
                timeout=self.config.request_timeout,
            )
        except Exception as e:  # cleanup is best-effort
            self.logger.warning(f"Failed to delete sandbox {sandbox_id}: {e}")
        finally:
            # Drop from the reaper registry whether or not the DELETE succeeded, so the
            # atexit/SIGTERM reaper won't re-target an already-gone (or unreachable) sandbox.
            _unregister_sandbox(sandbox_id)

    # --- Environment protocol ---
    def execute(self, action: dict, cwd: str = "", *, timeout: int | None = None) -> dict[str, Any]:
        """Execute a command in the sandbox and return the result as a dict."""
        # The agent passes an action dict; the swebench startup path passes a bare string.
        command = action if isinstance(action, str) else action.get("command", "")
        cwd = cwd or self.config.cwd

        env = dict(self.config.env)
        for key in self.config.forward_env:
            if (value := os.getenv(key)) is not None:
                env.setdefault(key, value)

        try:
            job = self._exec(command, cwd=cwd, env=env, timeout=timeout or self.config.timeout)
            # mini's other environments merge stdout+stderr into a single `output`.
            output = {
                "output": (job.get("stdout") or "") + (job.get("stderr") or ""),
                "returncode": job.get("exit_code", -1),
                "exception_info": "",
            }
        except Exception as e:
            output = {
                "output": "",
                "returncode": -1,
                "exception_info": f"An error occurred while executing the command: {e}",
                "extra": {"exception_type": type(e).__name__, "exception": str(e)},
            }
        self._check_finished(output)
        return output

    def _check_finished(self, output: dict):
        """Raises Submitted if the output indicates task completion. Copied from DockerEnvironment."""
        lines = output.get("output", "").lstrip().splitlines(keepends=True)
        if lines and lines[0].strip() == "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT" and output["returncode"] == 0:
            submission = "".join(lines[1:])
            raise Submitted(
                {
                    "role": "exit",
                    "content": submission,
                    "extra": {"exit_status": "Submitted", "submission": submission},
                }
            )

    def get_template_vars(self, **kwargs) -> dict[str, Any]:
        return recursive_merge(self.config.model_dump(), platform.uname()._asdict(), kwargs)

    def serialize(self) -> dict:
        config = self.config.model_dump(mode="json")
        if config.get("api_key"):  # never write the credential into saved trajectories
            config["api_key"] = "***"
        return {
            "info": {
                "config": {
                    "environment": config,
                    "environment_type": f"{self.__class__.__module__}.{self.__class__.__name__}",
                }
            }
        }

    def cleanup(self):
        """Delete the sandbox. Guards sandbox_id in case __init__ failed early."""
        self._stop_heartbeat()
        sandbox_id = getattr(self, "sandbox_id", None)
        if sandbox_id is not None:
            self._delete(sandbox_id)
            self.sandbox_id = None

    def __del__(self):
        self.cleanup()

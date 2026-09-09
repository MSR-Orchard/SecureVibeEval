"""Sandbox backend for securegen grading — run the oracle on the self-hosted
**sandbox service** instead of local Docker.

Modeled on ``susvibes/susvibes/sandbox.py``. The grading harness (``grade.py``) talks
to one seam: the ``dockerlib.Container`` (create-from-image, ``exec``, ``read``,
``write``, delete). This module provides :class:`SandboxContainer`, a drop-in
replacement with the same surface that routes every operation through the orchestrator
HTTP API instead of the local ``docker`` CLI. Select it with ``grade.py --backend sandbox``.

Why this is a clean swap: grading never commits an image (only image-building does), so
the only primitives needed are start / exec / read file / write file / delete — all of
which the orchestrator exposes:

    POST   /sandboxes            {image, block_network, cpu, memory} -> {sandbox_id}
    GET    /sandboxes/{id}       poll until {"ready": true}
    POST   /sandboxes/{id}/exec  {command, timeout_seconds} -> {job_id}   (async)
    GET    /jobs/{id}            -> {status, stdout, stderr, exit_code}
    DELETE /sandboxes/{id}       delete

Credentials come from $SANDBOX_BASE_URL and $SANDBOX_API_KEY (e.g. `source
~/.sandbox_env`); an optional $SANDBOX_SECOND_URL is tried as a fallback endpoint when
the primary can't provision a sandbox (its cluster is out of capacity).

Source images are large (~2.3 GB GHCR). The node pulls on create, so pre-warm with
``snippets/warm_sandbox_images.py`` before a batch or pods sit Pending on cold pulls.
"""
from __future__ import annotations

import atexit
import base64
import logging
import os
import shlex
import signal
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import requests

import config

# Per-sandbox resource caps. The oracle runs real build/test suites (go test, pytest,
# npm, cargo), so give it more headroom than the susvibes light-test default; override
# via env. CPU/mem are hard caps on the pod.
SANDBOX_CPU = os.environ.get("SECUREGEN_SANDBOX_CPU", "2")
SANDBOX_MEMORY = os.environ.get("SECUREGEN_SANDBOX_MEMORY", "8Gi")
# Seconds to wait for a freshly created sandbox to become ready. A cold burst waits for
# node autoscaling + a ~2.3 GB image pull; warm starts are a few seconds.
SANDBOX_STARTUP_TIMEOUT = int(os.environ.get("SECUREGEN_SANDBOX_STARTUP_TIMEOUT", "600"))
POLL_INTERVAL = 2.0
REQUEST_TIMEOUT = 30  # per-HTTP-request timeout (not command execution)


class SandboxError(RuntimeError):
    pass


# --- Crash-safe sandbox cleanup ------------------------------------------------
# A container is normally deleted in __exit__, but that does NOT run when the process
# is killed mid-flight (Ctrl-C / SIGTERM / OOM). grade.py fans many sandboxes out over a
# ThreadPoolExecutor, so a killed batch would leak every in-flight sandbox, each holding
# cluster CPU/memory until manually deleted. This registry + the atexit/signal handlers
# are the safety net for those abnormal exits.
_LIVE_SANDBOXES: dict[str, tuple[str, dict]] = {}  # sandbox_id -> (base_url, headers)
_LIVE_LOCK = threading.Lock()
_CLEANUP_INSTALLED = False


def _register_sandbox(sandbox_id: str, base_url: str, headers: dict) -> None:
    with _LIVE_LOCK:
        _LIVE_SANDBOXES[sandbox_id] = (base_url, headers)


def _unregister_sandbox(sandbox_id: str) -> None:
    with _LIVE_LOCK:
        _LIVE_SANDBOXES.pop(sandbox_id, None)


def reap_live_sandboxes(*, parallel: bool = True) -> int:
    """Best-effort delete of every sandbox still registered as live; returns the count
    attempted. Idempotent: claims the registry under the lock up front so concurrent
    atexit/signal invocations don't double-delete. Deletes normally run in parallel with
    a short timeout so teardown on Ctrl-C is fast even with many pods. The atexit caller
    disables parallelism because Python shuts down concurrent.futures before running
    regular atexit callbacks, so a new ThreadPoolExecutor cannot accept work then."""
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

    if parallel:
        with ThreadPoolExecutor(max_workers=min(32, len(items))) as ex:
            list(ex.map(_kill, items))
    else:
        for item in items:
            _kill(item)
    return len(items)


def _install_cleanup_handlers() -> None:
    """Register the reaper for normal exit (atexit) and for SIGINT/SIGTERM. Idempotent
    and main-thread-safe: signal handlers can only be set from the main thread, so a
    call from a worker thread silently skips them (atexit still covers normal exit). The
    previous handler is chained so the harness's own Ctrl-C handling still runs."""
    global _CLEANUP_INSTALLED
    if _CLEANUP_INSTALLED:
        return
    _CLEANUP_INSTALLED = True
    # concurrent.futures marks its executors unavailable before normal atexit hooks run.
    # Keep this last-resort cleanup synchronous so it remains usable during finalization.
    atexit.register(reap_live_sandboxes, parallel=False)
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

    base_urls is the primary SANDBOX_BASE_URL followed by an optional SANDBOX_SECOND_URL
    fallback, in the order they should be tried. The fallback covers the case where the
    primary endpoint is reachable but its cluster can't schedule a sandbox."""
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


class SandboxContainer:
    """A throwaway sandbox you can ``exec`` into, ``read``/``write`` files in, and that
    deletes itself on context exit. Duck-typed to :class:`dockerlib.Container` so
    ``grade.py`` (and ``grading_helpers.resolve_repo`` / ``dockerlib.reset_baseline``, which
    only call ``exec``) work against it unchanged.

    Lifecycle lives in ``__enter__``/``__exit__``; construction is cheap (no network)
    except reading the env config. ``commit`` is intentionally unsupported — grading
    never commits an image."""

    def __init__(self, image: str, name: str | None = None):
        # GHCR source refs are left untouched; only Docker Hub refs are rewritten to the
        # pull-through mirror. The node pulls this exact ref, so warm the same string.
        self.image = config.mirror_image(image)
        self.name = name or f"securegen_{uuid.uuid4().hex[:8]}"
        self.base_urls, self.api_key = sandbox_config()
        self.base_url = self.base_urls[0]
        self.headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}
        self.sandbox_id: str | None = None
        self.logger = logging.getLogger("securegen.sandbox")
        _install_cleanup_handlers()  # idempotent; arms the crash-safe reaper

    # --- context manager ---
    def __enter__(self) -> "SandboxContainer":
        self.sandbox_id = self._create_and_wait()
        return self

    def __exit__(self, *exc) -> None:
        self._delete(self.sandbox_id)
        self.sandbox_id = None

    # --- orchestrator HTTP helpers ---
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
        """Create a sandbox and wait until ready, falling back to the next configured
        endpoint if one can't provision (unreachable, or its cluster can't schedule the
        pod within SANDBOX_STARTUP_TIMEOUT)."""
        errors = []
        for i, url in enumerate(self.base_urls):
            self.base_url = url  # later exec/delete reuse the working endpoint
            try:
                return self._create_and_wait_on(url)
            except (SandboxError, requests.RequestException) as e:
                errors.append(f"{url}: {e}")
                if i + 1 < len(self.base_urls):
                    self.logger.warning(
                        "Sandbox provisioning failed on %s; falling back to %s. (%s)",
                        url, self.base_urls[i + 1], e)
        raise SandboxError("All sandbox endpoints failed to provision: " + " | ".join(errors))

    def _create_and_wait_on(self, url: str) -> str:
        resp = self._post("/sandboxes", {
            "image": self.image,
            "block_network": False,   # oracle needs egress (pip / go mod / npm)
            "cpu": SANDBOX_CPU,
            "memory": SANDBOX_MEMORY,
        })
        sandbox_id = resp["sandbox_id"]
        # Track before the readiness wait so an interrupt during the wait still reaps it.
        _register_sandbox(sandbox_id, url, self.headers)
        self.logger.info("Created sandbox %s from %s on %s.", sandbox_id, self.image, url)
        deadline = time.monotonic() + SANDBOX_STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            if self._get(f"/sandboxes/{sandbox_id}").get("ready") is True:
                self.logger.info("Sandbox %s ready.", sandbox_id)
                return sandbox_id
            time.sleep(POLL_INTERVAL)
        self._delete(sandbox_id)
        raise SandboxError(f"Sandbox {sandbox_id} not ready after {SANDBOX_STARTUP_TIMEOUT}s.")

    def _exec_raw(self, command: str, timeout: int) -> dict:
        """Submit one async exec and poll the job to completion. Returns the job dict
        ({stdout, stderr, exit_code, status}); a service-side timeout surfaces as
        exit_code 124, and lost/over-deadline jobs as -1."""
        if not self.sandbox_id:
            raise SandboxError("exec on a sandbox that is not running")
        job_id = self._post(f"/sandboxes/{self.sandbox_id}/exec",
                            {"command": command, "timeout_seconds": timeout})["job_id"]
        # Allow the command's own timeout plus slack for queueing/polling overhead.
        deadline = time.monotonic() + timeout + 60
        while time.monotonic() < deadline:
            job = self._get(f"/jobs/{job_id}")
            if job.get("status") in ("succeeded", "failed"):
                return job
            time.sleep(POLL_INTERVAL)
        return {"stdout": "", "stderr": "", "exit_code": -1, "status": "timeout"}

    # --- Container interface (matches dockerlib.Container) ---
    def exec(self, cmd: str, timeout: int = 1200) -> tuple[int, str, str]:
        """Run `cmd` in a login bash shell and return (exit_code, stdout, stderr).

        The script is base64-wrapped and substituted into ``bash -lc "$(...)"`` so it
        runs in the same kind of login shell as the Docker backend's ``bash -lc`` (PATH
        for go/cargo/etc.) with no quoting hazards, regardless of the script's contents."""
        b64 = base64.b64encode(cmd.encode()).decode()
        wrapped = f'bash -lc "$(echo {b64} | base64 -d)"'
        job = self._exec_raw(wrapped, timeout)
        code = job.get("exit_code")
        code = -1 if code is None else int(code)
        return code, job.get("stdout") or "", job.get("stderr") or ""

    def read(self, path: str) -> str:
        """Return the file's contents (base64-roundtripped to survive binary/newlines)."""
        code, out, err = self.exec(f"base64 -- {shlex.quote(path)} | tr -d '\\n'", timeout=300)
        if code != 0:
            raise SandboxError(f"read {path} failed: {(err or out).strip()[-400:]}")
        return base64.b64decode(out).decode(errors="replace")

    def write(self, path: str, content: str) -> None:
        """Create/overwrite `path` with `content` (base64 to avoid shell-escaping)."""
        b64 = base64.b64encode(content.encode()).decode()
        parent = os.path.dirname(path) or "/"
        cmd = (f"mkdir -p {shlex.quote(parent)} && "
               f"printf %s {shlex.quote(b64)} | base64 -d > {shlex.quote(path)}")
        code, out, err = self.exec(cmd, timeout=120)
        if code != 0:
            raise SandboxError(f"write {path} failed: {(err or out).strip()[-400:]}")

    def commit(self, tag: str) -> None:  # pragma: no cover - grading never commits
        raise SandboxError("commit is unsupported on the sandbox backend")

    def _delete(self, sandbox_id: str | None) -> None:
        if not sandbox_id:
            return
        try:
            requests.delete(f"{self.base_url}/sandboxes/{sandbox_id}",
                            headers=self.headers, timeout=REQUEST_TIMEOUT)
            self.logger.info("Sandbox %s deleted.", sandbox_id)
        except Exception as e:  # cleanup is best-effort
            self.logger.warning("Failed to delete sandbox %s: %s", sandbox_id, e)
        finally:
            _unregister_sandbox(sandbox_id)

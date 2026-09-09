from __future__ import annotations

import atexit
import base64
import io
import os
import shlex
import signal
import tarfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

from ..common.config import BackendConfig
from . import setup_dependency_files


POLL_INTERVAL = float(os.environ.get("CLI_HARNESS_SANDBOX_POLL_INTERVAL", "2"))
REQUEST_TIMEOUT = int(os.environ.get("CLI_HARNESS_SANDBOX_REQUEST_TIMEOUT", "30"))
STARTUP_TIMEOUT = int(os.environ.get("CLI_HARNESS_SANDBOX_STARTUP_TIMEOUT", "360"))
COMMAND_TIMEOUT = int(os.environ.get("CLI_HARNESS_SANDBOX_COMMAND_TIMEOUT", "3000"))
CPU = os.environ.get("CLI_HARNESS_SANDBOX_CPU", "2")
MEMORY = os.environ.get("CLI_HARNESS_SANDBOX_MEMORY", "8Gi")
MIRROR = os.environ.get("CLI_HARNESS_SANDBOX_MIRROR", "mirror.gcr.io").strip("/")
MAX_EXTRACT_BYTES = int(
    os.environ.get("CLI_HARNESS_SANDBOX_MAX_EXTRACT_BYTES", str(512 * 1024 * 1024))
)
DEFAULT_EXTRACT_EXCLUDES = (
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
)


class SandboxError(RuntimeError):
    pass


_LIVE_SANDBOXES: dict[str, tuple[str, dict[str, str]]] = {}
_LIVE_LOCK = threading.Lock()
_CLEANUP_INSTALLED = False


def _register_sandbox(sandbox_id: str, base_url: str, headers: dict[str, str]) -> None:
    with _LIVE_LOCK:
        _LIVE_SANDBOXES[sandbox_id] = (base_url, headers)


def _unregister_sandbox(sandbox_id: str) -> None:
    with _LIVE_LOCK:
        _LIVE_SANDBOXES.pop(sandbox_id, None)


def reap_live_sandboxes() -> int:
    with _LIVE_LOCK:
        items = list(_LIVE_SANDBOXES.items())
        _LIVE_SANDBOXES.clear()
    if not items:
        return 0

    def _delete(item):
        sandbox_id, (base_url, headers) = item
        try:
            requests.delete(
                f"{base_url}/sandboxes/{sandbox_id}",
                headers=headers,
                timeout=10,
            )
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=min(32, len(items))) as executor:
        list(executor.map(_delete, items))
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
        except (OSError, ValueError):
            pass


def sandbox_config() -> tuple[list[str], str]:
    base_urls = [
        url
        for url in (
            os.environ.get("SANDBOX_BASE_URL", "").rstrip("/"),
            os.environ.get("SANDBOX_SECOND_URL", "").rstrip("/"),
        )
        if url
    ]
    api_key = os.environ.get("SANDBOX_API_KEY", "")
    if not base_urls:
        raise SandboxError("SANDBOX_BASE_URL is unset (source ~/.sandbox_env).")
    if not api_key:
        raise SandboxError("SANDBOX_API_KEY is unset (source ~/.sandbox_env).")
    return base_urls, api_key


def mirror_image(image: str) -> str:
    if not MIRROR or not image or image.startswith("docker://"):
        return image
    if image.startswith(f"{MIRROR}/"):
        return image
    if image.startswith("docker.io/"):
        return f"{MIRROR}/{image[len('docker.io/'):]}"
    parts = image.split("/", 1)
    first = parts[0]
    if len(parts) > 1 and ("." in first or ":" in first or first == "localhost"):
        return image
    return f"{MIRROR}/{image}"


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> int:
    dest = dest.resolve()
    count = 0
    for member in tar.getmembers():
        target = (dest / member.name).resolve()
        if not str(target).startswith(str(dest) + os.sep) and target != dest:
            raise SandboxError(f"Refusing to extract unsafe tar path: {member.name}")
        tar.extract(member, dest)
        if member.isfile():
            count += 1
    return count


class SandboxIntegration:
    def __init__(
        self,
        docker_image: str,
        config: BackendConfig,
        container_work_dir: str = "/project",
        workspace_root: str = ".",
        keep_workspace: bool = False,
        allow_missing_workdir: bool = False,
    ):
        self.docker_image = mirror_image(docker_image)
        self.original_image = docker_image
        self.config = config
        self.container_work_dir = container_work_dir
        self.workspace_root = workspace_root
        self.keep_workspace = keep_workspace
        self.allow_missing_workdir = allow_missing_workdir
        self.local_work_dir: Path | None = None
        self.sandbox_id: str | None = None
        self.base_urls, self.api_key = sandbox_config()
        self.base_url = self.base_urls[0]
        self.headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}
        _install_cleanup_handlers()

    def setup_persistent_workspace(self) -> Path:
        print(f"🚀 Starting sandbox workspace from {self.docker_image}")
        self.local_work_dir = (
            Path(self.workspace_root).resolve()
            / f"{self.config.workspace_prefix}_{int(time.time())}"
        )
        self.local_work_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.sandbox_id = self._create_and_wait()
            self._ensure_workdir()
            print("✅ Sandbox workspace ready!")
            print(f"📁 Local mirror: {self.local_work_dir}")
            print(f"🧪 Sandbox: {self.sandbox_id}")
            return self.local_work_dir
        except Exception as e:
            print(f"❌ Sandbox setup failed: {e}")
            self.cleanup()
            raise

    def _post(self, path: str, body: dict) -> dict:
        response = requests.post(
            self.base_url + path,
            headers=self.headers,
            json=body,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()

    def _get(self, path: str) -> dict:
        response = requests.get(
            self.base_url + path,
            headers=self.headers,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()

    def _create_and_wait(self) -> str:
        errors = []
        for i, url in enumerate(self.base_urls):
            self.base_url = url
            try:
                return self._create_and_wait_on(url)
            except (SandboxError, requests.RequestException) as e:
                errors.append(f"{url}: {e}")
                if i + 1 < len(self.base_urls):
                    print(
                        "⚠️  Sandbox provisioning failed on "
                        f"{url}; falling back to {self.base_urls[i + 1]}."
                    )
        raise SandboxError("All sandbox endpoints failed: " + " | ".join(errors))

    def _create_and_wait_on(self, url: str) -> str:
        response = self._post(
            "/sandboxes",
            {
                "image": self.docker_image,
                "block_network": False,
                "cpu": CPU,
                "memory": MEMORY,
            },
        )
        sandbox_id = response["sandbox_id"]
        _register_sandbox(sandbox_id, url, self.headers)
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            if self._get(f"/sandboxes/{sandbox_id}").get("ready") is True:
                return sandbox_id
            time.sleep(POLL_INTERVAL)
        self._delete(sandbox_id)
        raise SandboxError(
            f"Sandbox {sandbox_id} not ready after {STARTUP_TIMEOUT}s."
        )

    def _ensure_workdir(self) -> None:
        if not self.sandbox_id:
            raise SandboxError("No sandbox available")
        test_command = f"test -d {shlex.quote(self.container_work_dir)}"
        job, timed_out, _ = self._exec_raw(
            f"bash -lc {shlex.quote(test_command)}",
            env={},
            timeout=60,
            cwd="/",
        )
        return_code = -1 if timed_out else job.get("exit_code")
        if return_code == 0:
            return
        if self.allow_missing_workdir:
            mkdir_command = f"mkdir -p {shlex.quote(self.container_work_dir)}"
            job, timed_out, _ = self._exec_raw(
                f"bash -lc {shlex.quote(mkdir_command)}",
                env={},
                timeout=60,
                cwd="/",
            )
            return_code = -1 if timed_out else job.get("exit_code")
            if return_code == 0:
                return
        raise SandboxError(
            f"Workdir does not exist in sandbox image: {self.container_work_dir}"
        )

    def _exec_raw(
        self,
        command: str,
        env: dict | None = None,
        timeout: int = COMMAND_TIMEOUT,
        cwd: str | None = None,
    ) -> tuple[dict, bool, float]:
        if not self.sandbox_id:
            raise SandboxError("No sandbox available")
        body = {
            "command": command,
            "timeout_seconds": timeout,
            "cwd": cwd or self.container_work_dir,
            "env": env or {},
        }
        started = time.time()
        job_id = self._post(f"/sandboxes/{self.sandbox_id}/exec", body)["job_id"]
        deadline = time.monotonic() + timeout + 60
        while time.monotonic() < deadline:
            job = self._get(f"/jobs/{job_id}")
            if job.get("status") in ("succeeded", "failed"):
                return job, job.get("exit_code") == 124, time.time() - started
            time.sleep(POLL_INTERVAL)
        return {"stdout": "", "stderr": "", "exit_code": -1}, True, time.time() - started

    def execute_in_container(self, command: str, env: dict = None) -> dict:
        env = env or {}
        full_command = f"""
        [ -f {self.config.env_source_path} ] && source {self.config.env_source_path}
        [ -f /root/.nvm/nvm.sh ] && source /root/.nvm/nvm.sh
        [ -f /root/.bashrc ] && source /root/.bashrc
        {command}
        """
        wrapped = f"bash -lc {shlex.quote(full_command)}"
        try:
            job, timed_out, execution_time = self._exec_raw(wrapped, env=env)
            return_code = -1 if timed_out else job.get("exit_code")
            if return_code is None:
                return_code = -1
            return {
                "stdout": job.get("stdout") or "",
                "stderr": job.get("stderr") or (
                    "Command timed out" if timed_out else ""
                ),
                "return_code": int(return_code),
                "execution_time": execution_time,
                "command": command,
                "success": (not timed_out) and int(return_code) == 0,
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "execution_time": 0,
                "command": command,
                "success": False,
            }

    def _write_remote_file(self, remote_path: str, content: bytes) -> dict:
        b64 = base64.b64encode(content).decode("ascii")
        remote_b64 = f"/tmp/{self.config.key}_{uuid.uuid4().hex}.b64"
        prep = self.execute_in_container(
            f"mkdir -p {shlex.quote(str(Path(remote_path).parent))} && "
            f": > {shlex.quote(remote_b64)}"
        )
        if not prep["success"]:
            return prep
        chunk_size = 48 * 1024
        for i in range(0, len(b64), chunk_size):
            chunk = b64[i : i + chunk_size]
            result = self.execute_in_container(
                f"printf %s {shlex.quote(chunk)} >> {shlex.quote(remote_b64)}"
            )
            if not result["success"]:
                return result
        return self.execute_in_container(
            f"base64 -d {shlex.quote(remote_b64)} > {shlex.quote(remote_path)} && "
            f"rm -f {shlex.quote(remote_b64)}"
        )

    def setup_cli_env(
        self,
        setup_script_path: str = "setup-env.sh",
        env: dict = None,
    ) -> dict:
        if not self.sandbox_id:
            raise RuntimeError(
                "No sandbox available. Call setup_persistent_workspace() first."
            )
        print(f"🔧 Setting up environment using {setup_script_path}...")
        setup_file = Path("./") / setup_script_path
        if not setup_file.exists():
            return {
                "stdout": "",
                "stderr": f"Setup script not found: {setup_file}",
                "return_code": 1,
                "success": False,
                "command": f"setup from {setup_script_path}",
            }

        setup_name = setup_script_path.replace("/", "_")
        remote_setup_path = f"/tmp/{self.config.key}_{setup_name}"
        write_result = self._write_remote_file(
            remote_setup_path,
            setup_file.read_bytes(),
        )
        if not write_result["success"]:
            return {
                **write_result,
                "command": f"copy {setup_script_path} to sandbox",
            }

        dependency_files = setup_dependency_files(setup_file)
        if dependency_files:
            remote_dir = remote_setup_path + ".deps"
            created = self.execute_in_container(f"mkdir -p {shlex.quote(remote_dir)}")
            if not created["success"]:
                return created
            for dependency_file in dependency_files:
                copied = self._write_remote_file(
                    f"{remote_dir}/{dependency_file.name}", dependency_file.read_bytes()
                )
                if not copied["success"]:
                    return copied

        chmod_result = self.execute_in_container(f"chmod +x {shlex.quote(remote_setup_path)}")
        if not chmod_result["success"]:
            print(
                "⚠️  Warning: Could not make script executable: "
                f"{chmod_result['stderr']}"
            )

        print("🚀 Running setup script...")
        setup_result = self.execute_in_container(
            f"bash {shlex.quote(remote_setup_path)}",
            env=env,
        )
        if setup_result["success"]:
            print("✅ Environment setup completed successfully!")
            print(f"⏱️  Execution time: {setup_result['execution_time']:.2f}s")
        else:
            print("❌ Environment setup failed!")
            print(f"Error: {setup_result['stderr']}")
        return setup_result

    def sync_workspace_to_local(self) -> dict:
        if not self.local_work_dir:
            raise SandboxError("No local workspace path available")
        excludes = os.environ.get("CLI_HARNESS_SANDBOX_EXCLUDES", "")
        exclude_names = list(DEFAULT_EXTRACT_EXCLUDES)
        if excludes.strip():
            exclude_names.extend(x.strip() for x in excludes.split(",") if x.strip())
        exclude_args = " ".join(
            f"--exclude={shlex.quote('./' + name)}" for name in exclude_names
        )
        command = (
            f"if [ -d {shlex.quote(self.container_work_dir)} ]; then "
            f"tar {exclude_args} -cf - -C {shlex.quote(self.container_work_dir)} . "
            "| base64 -w0; "
            "else echo __CLI_HARNESS_NO_WORKDIR__; fi"
        )
        job, timed_out, _ = self._exec_raw(
            f"bash -lc {shlex.quote(command)}",
            env={},
            timeout=300,
            cwd="/",
        )
        payload = (job.get("stdout") or "").strip()
        if "__CLI_HARNESS_NO_WORKDIR__" in payload:
            return {"success": False, "error": f"No workdir at {self.container_work_dir}"}
        if timed_out:
            return {"success": False, "error": "workspace sync timed out"}
        if job.get("exit_code") not in (0, None) and not payload:
            return {"success": False, "error": job.get("stderr") or ""}
        try:
            raw = base64.b64decode(payload)
        except Exception as e:
            return {"success": False, "error": f"base64 decode failed: {e}"}
        if len(raw) > MAX_EXTRACT_BYTES:
            return {
                "success": False,
                "error": f"workspace archive too large: {len(raw)} bytes",
            }
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tar:
            count = _safe_extract(tar, self.local_work_dir)
        return {"success": True, "files": count}

    def _delete(self, sandbox_id: str | None) -> None:
        if not sandbox_id:
            return
        try:
            requests.delete(
                f"{self.base_url}/sandboxes/{sandbox_id}",
                headers=self.headers,
                timeout=REQUEST_TIMEOUT,
            )
            print(f"✅ Removed sandbox: {sandbox_id}")
        except Exception as e:
            print(f"⚠️  Sandbox cleanup issue: {e}")
        finally:
            _unregister_sandbox(sandbox_id)

    def cleanup(self):
        print("🧹 Cleaning up...")
        if self.sandbox_id and self.local_work_dir and self.keep_workspace:
            print("📥 Syncing sandbox workspace to local mirror...")
            try:
                sync_result = self.sync_workspace_to_local()
                if sync_result.get("success"):
                    print(
                        f"📁 Workspace preserved at: {self.local_work_dir} "
                        f"({sync_result.get('files', 0)} files)"
                    )
                else:
                    print(f"⚠️  Workspace sync failed: {sync_result.get('error')}")
            except Exception as e:
                print(f"⚠️  Workspace sync failed: {e}")
        self._delete(self.sandbox_id)
        self.sandbox_id = None
        if self.local_work_dir and self.local_work_dir.exists() and not self.keep_workspace:
            try:
                import shutil

                shutil.rmtree(self.local_work_dir)
                print(f"🗑️  Workspace deleted: {self.local_work_dir}")
            except Exception as e:
                print(f"⚠️  Workspace cleanup issue: {e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.keep_workspace = True
        self.cleanup()


def patch_applies_clean_sandbox(
    image_name: str,
    patch_text: str,
    work_dir: str,
    config: BackendConfig,
) -> bool:
    if not patch_text.strip():
        return False
    with SandboxIntegration(
        image_name,
        config,
        container_work_dir=work_dir,
        keep_workspace=False,
    ) as integration:
        integration.setup_persistent_workspace()
        patch_path = f"/tmp/patch_{uuid.uuid4().hex}.diff"
        write_result = integration._write_remote_file(patch_path, patch_text.encode())
        if not write_result["success"]:
            return False
        quoted_work_dir = shlex.quote(work_dir)
        result = integration.execute_in_container(
            f"git config --global --add safe.directory {quoted_work_dir} >/dev/null 2>&1; "
            f"git -C {quoted_work_dir} apply --check --ignore-space-change "
            f"{shlex.quote(patch_path)}"
        )
        return result["success"]

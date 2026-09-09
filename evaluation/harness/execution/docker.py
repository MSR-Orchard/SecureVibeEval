from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import time
import uuid
from pathlib import Path

from ..common.config import BackendConfig
from . import setup_dependency_files


class DockerIntegration:
    def __init__(
        self,
        docker_image: str,
        config: BackendConfig,
        container_work_dir: str = "/project",
        workspace_root: str = ".",
        keep_workspace: bool = False,
        allow_missing_workdir: bool = False,
    ):
        self.docker_image = docker_image
        self.config = config
        self.container_work_dir = container_work_dir
        self.work_container = None
        self.local_work_dir = None
        self.workspace_root = workspace_root
        self.keep_workspace = keep_workspace
        self.allow_missing_workdir = allow_missing_workdir

    def setup_persistent_workspace(self) -> Path:
        print(f"🚀 Setting up persistent workspace from {self.docker_image}")

        self.local_work_dir = (
            Path(self.workspace_root).resolve()
            / f"{self.config.workspace_prefix}_{int(time.time())}"
        )
        self.local_work_dir.mkdir(exist_ok=True)

        try:
            self._extract_code_from_image()
            self._start_persistent_container()

            print("✅ Workspace ready!")
            print(f"📁 Local: {self.local_work_dir}")
            print(f"🐳 Container: {self.work_container}")

            return self.local_work_dir
        except Exception as e:
            print(f"❌ Workspace setup failed: {e}")
            self.cleanup()
            raise

    def _extract_code_from_image(self):
        print("📦 Extracting initial code...")

        temp_container_name = f"temp_extract_{int(time.time())}_{id(self)}"

        subprocess.run(
            [
                "docker",
                "create",
                "--pull",
                "always",
                "--name",
                temp_container_name,
                self.docker_image,
                "sh",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        try:
            copy_result = subprocess.run(
                [
                    "docker",
                    "cp",
                    f"{temp_container_name}:{self.container_work_dir}/.",
                    str(self.local_work_dir),
                ],
                capture_output=True,
                text=True,
            )
            if copy_result.returncode != 0:
                if self.allow_missing_workdir:
                    print(
                        "⚠️  Initial workdir was not present in the image; "
                        "starting with an empty workspace."
                    )
                    return
                raise subprocess.CalledProcessError(
                    copy_result.returncode,
                    copy_result.args,
                    output=copy_result.stdout,
                    stderr=copy_result.stderr,
                )
        finally:
            subprocess.run(["docker", "rm", temp_container_name], capture_output=True)

    def _start_persistent_container(self):
        print("🐳 Starting persistent container with live sync...")

        container_name = (
            f"{self.config.container_prefix}_{int(time.time())}_"
            f"{os.getpid()}_{uuid.uuid4().hex[:8]}"
        )

        result = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                container_name,
                "--network",
                "host",
                "-v",
                f"{self.local_work_dir}:{self.container_work_dir}",
                "-w",
                self.container_work_dir,
                self.docker_image,
                "tail",
                "-f",
                "/dev/null",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"docker run failed (exit {result.returncode}) for container "
                f"{container_name}: {result.stderr.strip()}"
            )

        self.work_container = container_name
        print(f"✅ Container {container_name} started with live volume sync")

    def execute_in_container(self, command: str, env: dict = None) -> dict:
        if not self.work_container:
            raise RuntimeError("No persistent container available")

        env = env or {}
        start_time = time.time()

        full_command = f"""
        [ -f {self.config.env_source_path} ] && source {self.config.env_source_path}
        [ -f /root/.nvm/nvm.sh ] && source /root/.nvm/nvm.sh
        [ -f /root/.bashrc ] && source /root/.bashrc
        """

        full_command += f"{command}"

        exec_cmd = [
            "docker",
            "exec",
            "-w",
            self.container_work_dir,
        ]

        for key, value in env.items():
            exec_cmd.extend(["-e", f"{key}={value}"])

        exec_cmd.extend([self.work_container, "bash", "-c", full_command])

        try:
            result = subprocess.run(
                exec_cmd, capture_output=True, text=True, timeout=3000
            )
            execution_time = time.time() - start_time

            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "execution_time": execution_time,
                "command": command,
                "success": result.returncode == 0,
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": "Command timed out after 5 minutes",
                "return_code": -1,
                "execution_time": 300,
                "command": command,
                "success": False,
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "execution_time": time.time() - start_time,
                "command": command,
                "success": False,
            }

    def setup_cli_env(
        self,
        setup_script_path: str = "setup-env.sh",
        env: dict = None,
    ) -> dict:
        if not self.work_container:
            raise RuntimeError(
                "No persistent container available. "
                "Call setup_persistent_workspace() first."
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

        try:
            setup_name = setup_script_path.replace("/", "_")
            container_setup_path = f"/tmp/{self.config.key}_{setup_name}"

            subprocess.run(["chmod", "+x", str(setup_file)], check=True)

            copy_result = subprocess.run(
                [
                    "docker",
                    "cp",
                    str(setup_file),
                    f"{self.work_container}:{container_setup_path}",
                ],
                capture_output=True,
                text=True,
            )

            if copy_result.returncode != 0:
                return {
                    "stdout": "",
                    "stderr": (
                        "Failed to copy setup script to container: "
                        f"{copy_result.stderr}"
                    ),
                    "return_code": copy_result.returncode,
                    "success": False,
                    "command": f"copy {setup_script_path} to container",
                }

            dependency_files = setup_dependency_files(setup_file)
            if dependency_files:
                remote_dir = container_setup_path + ".deps"
                created = self.execute_in_container(f"mkdir -p {shlex.quote(remote_dir)}")
                if not created["success"]:
                    return created
                for dependency_file in dependency_files:
                    subprocess.run(
                        ["docker", "cp", str(dependency_file),
                         f"{self.work_container}:{remote_dir}/{dependency_file.name}"],
                        capture_output=True, text=True, check=True,
                    )

            chmod_result = self.execute_in_container(f"chmod +x {shlex.quote(container_setup_path)}")
            if not chmod_result["success"]:
                print(
                    "⚠️  Warning: Could not make script executable: "
                    f"{chmod_result['stderr']}"
                )

            print("🚀 Running setup script...")
            setup_result = self.execute_in_container(
                f"bash {shlex.quote(container_setup_path)}", env=env
            )

            if setup_result["success"]:
                print("✅ Environment setup completed successfully!")
                print(f"⏱️  Execution time: {setup_result['execution_time']:.2f}s")

                if setup_result["stdout"]:
                    stdout_lines = setup_result["stdout"].strip().split("\n")
                    if len(stdout_lines) > 10:
                        print("📋 Setup output (last 10 lines):")
                        for line in stdout_lines[-10:]:
                            print(f"   {line}")
                    else:
                        print("📋 Setup output:")
                        print(setup_result["stdout"])
            else:
                print("❌ Environment setup failed!")
                print(f"Error: {setup_result['stderr']}")
                if setup_result["stdout"]:
                    print(f"Output: {setup_result['stdout']}")

            return setup_result
        except subprocess.CalledProcessError as e:
            error_msg = (
                f"Docker command failed: "
                f"{e.stderr if hasattr(e, 'stderr') else str(e)}"
            )
            print(f"❌ {error_msg}")
            return {
                "stdout": e.stdout if hasattr(e, "stdout") else "",
                "stderr": error_msg,
                "return_code": e.returncode,
                "success": False,
                "command": f"setup from {setup_script_path}",
                "execution_time": 0,
            }
        except Exception as e:
            error_msg = f"Setup failed: {str(e)}"
            print(f"❌ {error_msg}")
            return {
                "stdout": "",
                "stderr": error_msg,
                "return_code": -1,
                "success": False,
                "command": f"setup from {setup_script_path}",
                "execution_time": 0,
            }

    def sync_workspace_to_local(self) -> dict:
        """Docker already mounts the local workspace."""
        return {"success": True}

    def cleanup(self):
        print("🧹 Cleaning up...")

        if self.work_container and self.local_work_dir and not self.keep_workspace:
            try:
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        self.work_container,
                        "sh",
                        "-c",
                        (
                            f"chown -R {os.getuid()}:{os.getgid()} "
                            f"{shlex.quote(self.container_work_dir)} || true; "
                            f"chmod -R a+rwX {shlex.quote(self.container_work_dir)}"
                        ),
                    ],
                    capture_output=True,
                    timeout=30,
                )
            except Exception as e:
                print(f"⚠️  Workspace permission cleanup issue: {e}")

        if self.work_container:
            try:
                subprocess.run(
                    ["docker", "stop", self.work_container],
                    capture_output=True,
                    timeout=10,
                )
                subprocess.run(
                    ["docker", "rm", self.work_container], capture_output=True
                )
                print(f"✅ Removed container: {self.work_container}")
            except Exception as e:
                print(f"⚠️  Container cleanup issue: {e}")

        if self.local_work_dir and self.local_work_dir.exists():
            try:
                if self.keep_workspace:
                    print(f"📁 Workspace preserved at: {self.local_work_dir}")
                    print("   (Delete manually if no longer needed)")
                else:
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

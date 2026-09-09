import os
import io
import uuid
import re
import signal
import tarfile
import threading
import logging
import tempfile
from pathlib import Path

import docker
import docker.errors
from docker.models.containers import Container
from docker.models.images import Image

from susvibes.constants import CONTAINER_RUN_TIMEOUT
from susvibes.env_specs import *
from susvibes.utils import get_image_name, get_instance_id, save_file, mirror_image

# Connect lazily: the sandbox grading backend (--backend sandbox) runs with no local
# Docker daemon, so a missing/unreachable daemon must not break import. Docker-path
# callers go through _client(); sandbox-path callers never touch it.
docker_client = None
try:
    docker_client = docker.from_env()
except Exception:
    pass

# Printed by the runtime-patch container command when `git apply` fails, so the
# evaluator can distinguish an unappliable model patch from a genuine test failure
# (mirrors the build-time BuildError -> MODEL_PATCH_ERROR mapping).
PATCH_APPLY_SENTINEL = "___SUSVIBES_PATCH_APPLY_FAILED___"

# Labels stamped onto every container created in this process, so a run can find
# and reap its own in-flight containers on exit/crash (see set_container_labels /
# remove_labeled_containers). Process-scoped, so concurrent eval runs don't touch
# each other's containers.
_CONTAINER_LABELS: dict = {}

def set_container_labels(labels: dict) -> None:
    global _CONTAINER_LABELS
    _CONTAINER_LABELS = dict(labels or {})

def remove_labeled_containers(labels: dict, logger: logging.Logger = None) -> int:
    """Force-remove all containers (running or not) carrying every given label."""
    if not labels or docker_client is None:
        return 0
    filt = [f"{k}={v}" for k, v in labels.items()]
    removed = 0
    try:
        containers = docker_client.containers.list(all=True, filters={"label": filt})
    except Exception as e:
        if logger:
            logger.warning(f"Could not list containers for cleanup: {e}")
        return 0
    for container in containers:
        try:
            container.remove(force=True)
            removed += 1
        except Exception as e:
            if logger:
                logger.warning(f"Failed to remove leftover container {container.name}: {e}")
    return removed

class Deployment():
    image: Image
    container: Container
    remove_image: bool
    remove_container: bool
    logger: logging.Logger

    def __init__(
        self, 
        image: Image, 
        logger: logging.Logger,
        remove_image: bool = False, 
        remove_container: bool = True
    ):
        self.image = image
        self.logger = logger
        self.container = None
        self.remove_image = remove_image
        self.remove_container = remove_container

    @staticmethod
    def get_default_image_name() -> str:
        return "agentsec_auto_{}".format(uuid.uuid4())

    @classmethod
    def from_build(cls, 
        logger: logging.Logger,
        context_path: Path,
        dockerfile: str,
        dockerignore: str = None,
        image_name: str = None,
        nocache: bool = False,
        remove_image: bool = False,
        remove_container: bool = True,
    ) -> "Deployment":
        save_file(dockerfile, context_path / "Dockerfile")
        if dockerignore:
            save_file(dockerignore, context_path / ".dockerignore")
        image_name = image_name or cls.get_default_image_name()
        try:
            response = docker_client.api.build(
                path=str(context_path),
                tag=image_name,
                nocache=nocache,
                rm=True,
                forcerm=True,
                decode=True,
            )
            buildlog = ""
            for chunk in response:
                if "stream" in chunk:
                    buildlog += chunk["stream"]
                    # print(chunk["stream"].rstrip())
                elif "errorDetail" in chunk:
                    raise docker.errors.BuildError(
                        chunk["errorDetail"]["message"], buildlog
                    )
            logger.info(f"Image {image_name} built successfully.")
            return cls(docker_client.images.get(image_name), logger, remove_image, remove_container)
        except docker.errors.BuildError as e:
            logger.warning(f"docker.errors.BuildError when building {image_name}: {e}")
            logger.warning(f"Build log: {e.build_log}")
            raise
        except docker.errors.APIError as e:
            logger.warning(f"docker.errors.APIError when building {image_name}: {e}")
            raise docker.errors.BuildError(f"API error: {e}", "")

    @classmethod
    def from_pull(cls,
        logger: logging.Logger,
        image_name: str,
        remove_image: bool = False,
        remove_container: bool = True,
        max_retries: int = 3,
    ) -> "Deployment":
        # Pull remote images through the Docker Hub mirror (mirror.gcr.io) for fast,
        # rate-limit-free pulls. The instance build's FROM uses the pulled image's own tag
        # (self.deployment.image.tags[0]), so the mirrored tag stays consistent downstream.
        image_name = mirror_image(image_name)
        try:
            for retry in range(max_retries):
                try:
                    image = docker_client.images.pull(image_name)
                    break
                except docker.errors.NotFound:
                    if retry == max_retries - 1:
                        raise
            logger.info(f"Image {image_name} pulled successfully.")
            return cls(image, logger, remove_image, remove_container)
        except docker.errors.NotFound:
            logger.warning(f"docker.errors.NotFound when pulling {image_name}.")
            raise

    @classmethod
    def from_local(cls,
        logger: logging.Logger,
        image_name: str = None, 
        image_id: str = None,
        remove_image: bool = False,
        remove_container: bool = True,
        max_retries: int = 3,
    ) -> "Deployment":
        if not image_id and not image_name:
            raise ValueError("Either docker image name or image id must be provided.")
        try:
            for retry in range(max_retries):
                try:
                    image = docker_client.images.get(image_name or image_id)
                    break
                except docker.errors.ImageNotFound:
                    if retry == max_retries - 1:
                        raise
            logger.info(f"Image {image_name or image_id} found locally.")
            if not image.tags:
                default_image_name = cls.get_default_image_name()
                logger.warning(f"Warning: image has no names, tagging a default name {default_image_name}.")
                assert image.tag(default_image_name)
            return cls(image, logger, remove_image, remove_container)
        except docker.errors.ImageNotFound:
            logger.warning(f"docker.errors.ImageNotFound when getting {image_name or image_id}.")
            raise
    
    def create_container(
        self,
        command: str | list = None,
        mem_limit: str = None,
        cpu_limit: int = None,
        labels: dict = None,
    ) -> None:
        try:
            container = docker_client.containers.create(
                image=self.image.id,
                detach=True,
                mem_limit=mem_limit,
                nano_cpus=int(cpu_limit * 1e9) if cpu_limit else None,
                command=command,
                labels={**_CONTAINER_LABELS, **(labels or {})} or None,
                # command="tail -f /dev/null",
            )
            self.logger.info(f"Container for {self.image.id} created: {container.name}")
            self.container = container
        except docker.errors.ContainerError as e:
            self.logger.warning(f"Error creating container for {self.image.id}: {e}")
            raise
    
    def put_archive(self, path: str, data: bytes) -> None:
        """Extract an in-memory tar archive into `path` inside the (created) container."""
        if not self.container.put_archive(path, data):
            raise RuntimeError(f"Failed to copy archive into container {self.container.name}.")

    def start(self) -> None | str:
        """Start the container and if wait is True return running logs."""
        self.container.start()
        self.logger.info(f"Container {self.container.name} started.")

    def _remove_container(self) -> None:
        """Remove the container if it exists."""
        try:
            if self.container:
                self.container.remove(force=True)
                self.logger.info(f"Container {self.container.name} removed.")
        except docker.errors.NotFound as e:
            self.logger.info(f"Container {self.container.name} not found.")
        except Exception as e:
            self.logger.error(f"Failed to remove container {self.container.name}: {e}", exc_info=True)

    def _remove_image(self) -> None:
        self._remove_container()
        try:
            docker_client.images.remove(self.image.id, force=True)
            self.logger.info(f"Image {self.image.id} removed.")
        except docker.errors.ImageNotFound as e:
            self.logger.info(f"Image {self.image.id} not found.")
        except Exception as e:
            self.logger.error(f"Failed to remove image {self.image.id}: {e}", exc_info=True)

    def stop(self) -> None:
        """Stop the container and deal with the removal logic."""
        try:
            if self.container:
                self.container.stop(timeout=15)
                self.logger.info(f"Container {self.container.name} stopped.")
        except Exception as e:
            if "already stopped" in str(e).lower():
                self.logger.info(f"Container {self.container.name} has already stopped.")
            else:
                self.logger.warning(f"Failed to stop container {self.container.name}: {e}. Trying to forcefully kill...")
                try:
                    container_info = docker_client.api.inspect_container(self.container.id)
                    pid = container_info["State"].get("Pid", 0)
                    if pid > 0:
                        os.kill(pid, signal.SIGKILL)
                        self.logger.info(f"Forcefully killed container {self.container.name} with PID {pid}.")
                    else:
                        self.logger.error(f"PID for container {self.container.name}: {pid} - not killing.")
                except Exception as e:
                    self.logger.error(f"Failed to forcefully kill container {self.container.name}: {e}", exc_info=True)
        if self.remove_image:
            self._remove_image()
        elif self.remove_container:
            self._remove_container()

    def run_with_timeout(self, timeout: int = CONTAINER_RUN_TIMEOUT, stop_timeout: int = 60) -> tuple[str, bool]:
        self.start()
        run_logs, timed_out = b"", False
        def run():
            nonlocal run_logs
            for chunk in self.container.logs(stream=True, follow=True, stdout=True, stderr=True):
                run_logs += chunk
            try:
                self.container.wait()
            except docker.errors.NotFound:
                return
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            elapsed = f"{timeout} seconds" if timeout < 300 else f"{timeout // 60} minutes"
            self.logger.warning(f"Container {self.container.name} run timed out after {elapsed}.")
            timed_out = True
            stop_thread = threading.Thread(target=self.stop, daemon=True)
            stop_thread.start()
            stop_thread.join(stop_timeout)
            if stop_thread.is_alive():
                stop_elapsed = f"{stop_timeout}s" if stop_timeout < 300 else f"{stop_timeout // 60} min"
                self.logger.warning(f"Container {self.container.name} stop exceeded {stop_elapsed}. Container may be orphaned.")
        else:
            self.stop()
        return run_logs.decode(), timed_out

class Env:
    project: str
    deployment: Deployment
    dockerfile: str
    dockerignore: str
    logs_parser: dict[str, str]
    logs_checker: str

    def __init__(
        self,
        logger: logging.Logger,
        project: str,
        image_name: str,
        dockerfile: str,
        dockerignore: str = None,
        image_loc: str = "local",
        logs_parser: dict = None,
        logs_checker: str = None,
        remove_image: bool = False,
        remove_container: bool = True,
        backend: str = "docker"
    ):
        self.project = project
        self.image_name = image_name
        self.dockerfile = dockerfile
        self.dockerignore = dockerignore
        self.logs_parser = logs_parser
        self.logs_checker = logs_checker
        self.backend = backend
        if backend == "sandbox":
            # The sandbox grading backend pulls the eval image on its own cluster, so we
            # never touch the local Docker daemon here. The base image's repo + commit
            # are baked in; the test command comes from the dockerfile CMD, not a live
            # image (the sandbox replaces PID 1, so the baked CMD does not auto-run).
            self.deployment = None
            return
        logger.info(f"Collecting enviroment deployment...")
        collect_method = Deployment.from_local if image_loc == "local" else \
            Deployment.from_pull if image_loc == "remote" else None
        self.deployment = collect_method(
            logger=logger,
            image_name=image_name,
            remove_image=remove_image,
            remove_container=remove_container
        )
    
    @staticmethod 
    def _apply_patches(patches: tuple[str, ...], group) -> None:
        """Get commands for applying patches to the repository."""
        cmds = []
        build_data_dir = Path(f"/{BUILD_DATA_DIR_NAME}")
        patches_dir = build_data_dir / PATCHES_DIR_NAME / group
        reverse = any(flag in patches[group] for flag in REVERSE_PATCH_FLAG)
        for id, patch in enumerate(patches[group]):
            if patch not in REVERSE_PATCH_FLAG:
                patch_path = patches_dir / f"{id}.patch"
                cmd = "git apply --ignore-space-change" + (" --reverse" if reverse else "")
                cmds.append(f"{cmd} {str(patch_path)}")
        return " && ".join(cmds)    

    def _compose_instance_dockerfile(
        self,
        base_commit: str,
        patches: dict[tuple[str, ...]],
        reinstall: bool = True,
        persist_files: list[tuple[str, str]] = None,
    ) -> str:
        """Create the Dockerfile for building instance deployment."""
        dockerfile_re = re.compile(DOCKERFILE_PATTERN, re.MULTILINE | re.DOTALL)
        m = dockerfile_re.search(self.dockerfile)
        from_stm, _, _, dependency_install_stm, cmd_stm = m.groups()
        
        replace_pattern = r'^(FROM(?:\s+--\S+)*\s+)(\S+)(.*)$'
        cached_base_image = self.deployment.image.tags[0]
        cached_from_stm = re.sub(
            replace_pattern,
            lambda m: f"{m.group(1)}{cached_base_image}{m.group(3)}",
            from_stm, count=1, flags=re.MULTILINE
        )
        run_stm = "RUN {}\n"
        reset_cmds = f'git reset --hard {base_commit} && git clean -fdq'  
        instance_dockerfile = "".join([
            cached_from_stm,
            run_stm.format(" && ".join(GIT_AUTHOR_CONFIGS)),
            run_stm.format(f"mkdir -p {BUILD_DATA_DIR_NAME}"),
            f'COPY . /{BUILD_DATA_DIR_NAME}/\n'
        ])
        
        if patches.get("pre_install", None):
            instance_dockerfile += run_stm.format(reset_cmds)
            instance_dockerfile += run_stm.format(type(self)._apply_patches(
                patches, "pre_install"))
            if reinstall:
                instance_dockerfile += dependency_install_stm
        if patches.get("post_install", None):
            instance_dockerfile += run_stm.format(type(self)._apply_patches(
                patches, "post_install"))

        if persist_files:
            for src, dst in persist_files:
                instance_dockerfile += run_stm.format(f"cp {src} {dst}")

        commit_msg = "Instance created."
        commit_cmds = f'git add . && git commit --allow-empty -m "{commit_msg}" --no-verify'
        rm_cmd = f'rm -rf -- /{BUILD_DATA_DIR_NAME}'
        instance_dockerfile += run_stm.format(commit_cmds) + \
            run_stm.format(rm_cmd) + cmd_stm
        return instance_dockerfile
    
    def build_instance_deployment(
        self,
        base_commit: str,
        patches: dict[tuple[str, ...]],
        logger: logging.Logger,
        remove_image: bool = True,
        remove_container: bool = True,
        persist_files: list[tuple[str, str]] = None,
    ) -> Deployment:
        """Build a instance-level Docker image from the environment."""
        logger.info(f"Building instance deployment...")
        banned_reinstall = BANNED_REINSTALL_FOR_INSTANCE.get(self.project, [])
        reinstall = True
        if any(base_commit.startswith(commit) for commit in banned_reinstall):
            logger.info(f"Reinstalling {self.project} at commit {base_commit} is banned.")
            reinstall = False
            
        with tempfile.TemporaryDirectory() as tmpdir:
            context_path = Path(tmpdir)
            for k, v in patches.items():
                patches_dir = context_path / PATCHES_DIR_NAME / k
                patches_dir.mkdir(parents=True, exist_ok=True)
                for id, patch in enumerate(v):
                    if patch not in REVERSE_PATCH_FLAG:
                        save_file(patch, patches_dir / f"{id}.patch")
            instance_dockerfile = self._compose_instance_dockerfile(
                base_commit, patches, reinstall, persist_files=persist_files)

            deployment = Deployment.from_build(
                logger=logger,
                context_path=context_path,
                dockerfile=instance_dockerfile,
                dockerignore=self.dockerignore,
                image_name=get_image_name(f"instance_{get_instance_id(self.project, base_commit)}"),
                remove_image=remove_image,
                remove_container=remove_container,
            )
        return deployment

    @staticmethod
    def _patch_tar(patches: tuple[str, ...]) -> bytes:
        """Pack post_install patches into an in-memory tar as patches/<id>.patch."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for id, patch in enumerate(patches):
                if patch in REVERSE_PATCH_FLAG:
                    continue
                data = patch.encode()
                info = tarfile.TarInfo(name=f"patches/{id}.patch")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    def _runtime_command(self, patches: tuple[str, ...], command_override: str = None) -> list[str]:
        """Build a `sh -c` command that applies patches at container start and then
        runs the image's original CMD (preserved verbatim via `exec "$0" "$@"`), or
        `command_override` when given (the generated-sec-test run).

        This avoids building a per-instance image: the base eval image already
        contains the repo at the same HEAD the build path patches onto."""
        reverse = any(flag in patches for flag in REVERSE_PATCH_FLAG)
        apply_cmds = []
        for id, patch in enumerate(patches):
            if patch in REVERSE_PATCH_FLAG:
                continue
            cmd = "git apply --ignore-space-change" + (" --reverse" if reverse else "")
            apply_cmds.append(f"{cmd} /patches/{id}.patch")
        apply_str = " && ".join(apply_cmds) if apply_cmds else "true"
        if command_override:
            script = (
                f"cd /{WORKSPACE_DIR_NAME} || exit 1\n"
                f"if ! ({apply_str}); then echo '{PATCH_APPLY_SENTINEL}'; exit 3; fi\n"
                f"{command_override}"
            )
            return ["/bin/sh", "-c", script]
        orig_cmd = self.deployment.image.attrs.get("Config", {}).get("Cmd") or []
        script = (
            f"cd /{WORKSPACE_DIR_NAME} || exit 1\n"
            f"if ! ({apply_str}); then echo '{PATCH_APPLY_SENTINEL}'; exit 3; fi\n"
            'exec "$0" "$@"'
        )
        return ["/bin/sh", "-c", script] + list(orig_cmd)

    def _test_command(self) -> str:
        """The test command for runtime grading, parsed from the env-spec dockerfile CMD.

        The Docker path reads the live image's `Config.Cmd`; the sandbox path can't (it
        replaces PID 1), so it parses the same command from the dockerfile. Handles both
        exec form (`CMD ["a", "b"]`) and shell form (`CMD a b`)."""
        m = re.search(r'^CMD\s+(.+)$', self.dockerfile, re.MULTILINE)
        if not m:
            raise ValueError(f"No CMD in dockerfile for project {self.project}.")
        cmd = m.group(1).strip()
        if cmd.startswith("["):
            try:
                import json as _json
                return " ".join(_json.loads(cmd))
            except Exception:
                pass
        return cmd

    def _workdir(self) -> str:
        """The repo working directory, parsed from the dockerfile WORKDIR (default project)."""
        m = re.search(r'^WORKDIR\s+(.+)$', self.dockerfile, re.MULTILINE)
        return m.group(1).strip() if m else f"/{WORKSPACE_DIR_NAME}"

    def build_runtime_deployment(
        self,
        patches: tuple[str, ...],
        logger: logging.Logger,
        mem_limit: str = None,
        cpu_limit: int = None,
        command_override: str = None,
    ) -> Deployment:
        """Create a ready-to-run container off the base eval image that applies
        `patches` at start time, instead of baking a new instance image.

        `command_override` replaces the image's baked test command (used for the
        generated-sec-test run, which runs sectests.sh instead of the default suite)."""
        if self.backend == "sandbox":
            from susvibes.sandbox import SandboxDeployment
            return SandboxDeployment(
                image_name=self.image_name,
                test_command=command_override or self._test_command(),
                workdir=self._workdir(),
                patches=patches,
                logger=logger,
            )
        logger.info(f"Preparing runtime deployment...")
        # Wrap the shared base image in its own Deployment so the per-run container
        # lifecycle is isolated; never remove the base image.
        deployment = Deployment(
            self.deployment.image, logger,
            remove_image=False, remove_container=True,
        )
        command = self._runtime_command(patches, command_override=command_override)
        deployment.create_container(command=command, mem_limit=mem_limit, cpu_limit=cpu_limit)
        deployment.put_archive("/", type(self)._patch_tar(patches))
        return deployment

    def check_test_logs(self, run_logs: str, timed_out: bool = False) -> str:
        """Get the test status from the run logs, using this instance's logs_checker."""
        if timed_out:
            return TestStatus.TIMEOUT.value
        if self.logs_checker and re.search(self.logs_checker, run_logs, re.MULTILINE):
            return TestStatus.STARTUP_ERROR.value
        return TestStatus.COMPLETION.value
    
    @staticmethod
    def get_symbol_resolution_errors(run_logs: str) -> bool:
        """Get the cound of missing symbol errors from the run logs."""
        return sum(len(re.findall(pattern, run_logs, re.MULTILINE))
            for pattern in TEST_SYMBOL_RESOLUTION_ERROR_PATTERNS)
    
    def parse_test_logs(self, run_logs: str, logger: logging.Logger) -> dict[str, int]:
        """Parse the run logs based on test statuses."""
        logger.info(f"Parsing test logs...")
        test_result = {}
        for status, pattern in self.logs_parser.items():
            if pattern:
                logs_parse_re = re.compile(pattern, re.MULTILINE)
                m = None
                for m in logs_parse_re.finditer(run_logs):
                    pass
                if m:
                    test_result[status] = int(m.group(1))
                else:
                    test_result[status] = 0
        return test_result 
    
    @staticmethod
    def get_test_failures(test_result: dict[str, int]) -> int:
        """Returns test status as a comparable object based on test result."""
        return sum(test_result.get(status.value, 0) for status in FAILURE_STATUSES)

    @staticmethod
    def parse_gen_sec_cases(run_logs: str, logger: logging.Logger) -> dict:
        """Parse a generated-sec-test run's logs into a {case: passed} map (its last JSON
        object). Raises ValueError if no JSON pass-map is present."""
        from susvibes.pass_failure import extract_json_object
        logger.info("Parsing generated-sec-test logs...")
        cases = extract_json_object(run_logs)
        if cases is None:
            raise ValueError("No generated-sec-test pass-map found in logs.")
        return cases


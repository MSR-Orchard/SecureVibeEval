"""Docker helpers required by the SecureGen graders."""
from __future__ import annotations

import subprocess
import tempfile
import uuid
from pathlib import Path

import config


class DockerError(RuntimeError):
    pass


def _run(args: list[str], timeout: int = 1200) -> tuple[int, str, str]:
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def pull(image: str) -> None:
    # Route Docker Hub refs through the pull-through mirror (mirror.gcr.io) for fast,
    # rate-limit-free pulls; GHCR/other fully-qualified refs are left untouched.
    ref = config.mirror_image(image)
    code, _, err = _run(["docker", "pull", ref], timeout=3600)
    if code != 0:
        raise DockerError(f"pull {ref} failed: {err.strip()[-500:]}")
    # Re-tag back to the canonical name so image_exists()/run() callers stay mirror-agnostic.
    if ref != image:
        tag(ref, image)


def tag(src: str, dst: str) -> None:
    code, _, err = _run(["docker", "tag", src, dst])
    if code != 0:
        raise DockerError(f"tag {src} -> {dst} failed: {err.strip()}")


def image_exists(image: str) -> bool:
    code, _, _ = _run(["docker", "image", "inspect", image])
    return code == 0


class Container:
    """A detached container that supports the operations used during grading."""

    def __init__(self, image: str, name: str | None = None):
        self.image = image
        self.name = name or f"securegen_{uuid.uuid4().hex[:8]}"
        self.cid: str | None = None

    def __enter__(self) -> "Container":
        code, out, err = _run([
            "docker", "run", "-d", "--name", self.name,
            self.image, "/bin/bash", "-c", "sleep infinity",
        ])
        if code != 0:
            raise DockerError(f"run {self.image} failed: {err.strip()}")
        self.cid = out.strip()
        return self

    def __exit__(self, *exc) -> None:
        _run(["docker", "rm", "-f", self.name], timeout=120)

    def exec(self, cmd: str, timeout: int = 1200) -> tuple[int, str, str]:
        return _run(["docker", "exec", self.name, "/bin/bash", "-lc", cmd], timeout=timeout)

    def read(self, path: str) -> str:
        with tempfile.TemporaryDirectory() as td:
            dst = Path(td) / "f"
            code, _, err = _run(["docker", "cp", f"{self.name}:{path}", str(dst)])
            if code != 0:
                raise DockerError(f"cp out {path} failed: {err.strip()}")
            return dst.read_text(errors="replace")

    def write(self, path: str, content: str) -> None:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "f"
            src.write_text(content)
            code, _, err = _run(["docker", "cp", str(src), f"{self.name}:{path}"])
            if code != 0:
                raise DockerError(f"cp in {path} failed: {err.strip()}")

def repo_dir(c: Container) -> str:
    """The single project directory under /workspace (e.g. /workspace/containerd)."""
    code, out, err = c.exec(
        "find /workspace -maxdepth 1 -mindepth 1 -type d -printf '%f\\n'"
    )
    if code != 0:
        raise DockerError(f"locating repo dir failed: {err}")
    dirs = [d for d in out.split() if d]
    if len(dirs) != 1:
        raise DockerError(f"expected exactly one /workspace subdir, found {dirs}")
    return dirs[0]


def reset_baseline(c: Container, repo: str, timeout: int = 3600) -> None:
    """Restore the pristine vulnerable baseline (same as prepare.sh's reset half).

    Large monorepos (kubernetes, ansible) can take well over the default exec timeout
    for a full `git checkout HEAD -- .`, so allow a generous override.
    """
    code, _, err = c.exec(
        f"cd /workspace/{repo} && git reset --hard && git clean -fd && git checkout HEAD -- .",
        timeout=timeout,
    )
    if code != 0:
        raise DockerError(f"reset baseline failed: {err}")

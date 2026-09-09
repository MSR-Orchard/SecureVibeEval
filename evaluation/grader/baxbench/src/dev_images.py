"""Resolve the prebuilt mini-SWE-agent *dev image* for a (env, scenario) pair so the
grader can reuse it instead of rebuilding the framework + deps for every task.

The dev images are produced by `evaluation_harness/mini-swe-agent/gen_instances.py`:
BaxBench's exact test Dockerfile (same base, deps, package installs) but with the
ENTRYPOINT cleared and a throwaway code stub. They are tagged `baxbench-agent-<hash>`
and already contain everything except the model's generated code, so a per-task grading
image only needs `FROM <dev_tag>` + the Dockerfile *tail* (the code COPY + build +
ENTRYPOINT) -- no apt/pip/npm/go-get/cargo re-run.

The tag-hashing below is copied verbatim from `gen_instances.py` so the tags computed
here match the images that were built there. If that file's hashing changes, update this
to match (or the resolver will simply miss and the grader falls back to a full build).
"""

import hashlib
import logging

import docker

from env.base import COMMON_DOCKER_RUN_COMMANDS, Env
from scenarios.base import Scenario

# Language-appropriate code stubs the dev image was built with (must match
# gen_instances._STUBS, since they feed the tag hash).
_STUBS = {
    "Python": "# baxbench dev stub\n",
    "Go": "package main\n\nfunc main() {}\n",
    "Rust": "fn main() {}\n",
    "JavaScript": "// baxbench dev stub\n",
    "PHP": "<?php\n",
    "Ruby": "# baxbench dev stub\n",
}

_docker_client = docker.from_env()


def _stub_files(env: Env) -> dict[str, str]:
    stub_name = env.code_filename or ".baxbench_keep"
    return {stub_name: _STUBS.get(env.language, "// baxbench dev stub\n")}


def _base_dockerfile(env: Env) -> str:
    return env.dockerfile.format(
        entrypoint_cmd="[]",
        additional_commands="\n".join(
            f"RUN {c}" for c in COMMON_DOCKER_RUN_COMMANDS
        ),
    )


def _dev_image_tag(dockerfile: str, env: Env, stub_files: dict[str, str]) -> str:
    h = hashlib.sha1()
    h.update(dockerfile.encode())
    for k in sorted(env.manifest_files):
        h.update(k.encode())
        h.update(env.manifest_files[k].encode())
    for k in sorted(stub_files):
        h.update(k.encode())
        h.update(stub_files[k].encode())
    return f"baxbench-agent-{h.hexdigest()[:12]}"


def _base_tag(env: Env) -> str:
    return _dev_image_tag(_base_dockerfile(env), env, _stub_files(env))


def _extra_pkg_cmds(scenario: Scenario, env: Env) -> list[str]:
    return scenario.needed_packages.get("_all_", []) + scenario.needed_packages.get(
        env.language, []
    )


def _delta_tag(base_tag: str, extra_cmds: list[str]) -> str:
    h = hashlib.sha1()
    h.update(base_tag.encode())
    for c in extra_cmds:
        h.update(c.encode())
    return f"baxbench-agent-{h.hexdigest()[:12]}"


def final_dev_tag(env: Env, scenario: Scenario) -> str:
    """The dev-image tag for (env, scenario): the per-env base when the scenario adds no
    packages, else the thin delta layered on that base."""
    base = _base_tag(env)
    extra = _extra_pkg_cmds(scenario, env)
    return base if not extra else _delta_tag(base, extra)


def _image_exists(tag: str) -> bool:
    try:
        _docker_client.images.get(tag)
        return True
    except docker.errors.ImageNotFound:
        return False


def resolve_dev_image(
    env: Env, scenario: Scenario, logger: logging.Logger | None = None
) -> str | None:
    """Return the locally-present dev-image tag for (env, scenario), or None if it has
    not been built (so the caller can fall back to a normal full build)."""
    tag = final_dev_tag(env, scenario)
    if _image_exists(tag):
        return tag
    if logger is not None:
        logger.info("no prebuilt dev image %s for %s/%s; will full-build", tag, env.id, scenario.id)
    return None

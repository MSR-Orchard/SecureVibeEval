"""Small helpers shared by the SecureGen grading entrypoints."""
from __future__ import annotations

import re

from dockerlib import repo_dir


_PLUSPLUS = re.compile(r"^\+\+\+ b/(.+)$", re.MULTILINE)
_CD_REPO = re.compile(r"cd\s+/workspace/([^\s/;&|]+)")
_FUNC_TEST_MIN_TIMEOUT_S = 600
_GO_TIMEOUT_RE = re.compile(r"-timeout[= ]+(\d+)s")


def test_file_paths(test_patch: str) -> list[str]:
    return _PLUSPLUS.findall(test_patch or "")


def resolve_repo(record: dict, container) -> str:
    """Resolve the project directory inside a PatchEval source image."""
    if record.get("repo_dir"):
        return record["repo_dir"]
    for key in ("poc_test_cmd", "unit_test_cmd", "poc_run", "unit_run", "vul_run"):
        match = _CD_REPO.search(record.get(key) or "")
        if match:
            name = match.group(1)
            code, _, _ = container.exec(f"test -d /workspace/{name}")
            if code == 0:
                return name
    return repo_dir(container)


def raise_go_test_timeouts(script_source: str) -> str:
    """Raise short Go test timeouts for slower sandbox execution."""
    def bump(match: re.Match) -> str:
        return f"-timeout {max(int(match.group(1)), _FUNC_TEST_MIN_TIMEOUT_S)}s"

    return _GO_TIMEOUT_RE.sub(bump, script_source)


def func_pass_despite_hook_flake(output: str) -> bool:
    """Recognize Mocha runs whose only failures are lifecycle hooks."""
    passing = re.search(r"(\d+) passing", output)
    failing = re.search(r"(\d+) failing", output)
    if not (passing and failing) or int(passing.group(1)) <= 0:
        return False
    failure_count = int(failing.group(1))
    hook_failures = len(re.findall(r'"(?:before|after) (?:each|all)" hook', output))
    return failure_count > 0 and hook_failures >= failure_count


def _require(container, command: str, message: str) -> None:
    code, stdout, stderr = container.exec(command)
    if code != 0:
        detail = (stderr or stdout).strip()[-500:]
        raise RuntimeError(message + (f": {detail}" if detail else ""))


def ensure_git_baseline(record: dict, container) -> bool:
    """Create a Git baseline for partial ACR source images when required."""
    if record.get("source_domain") != "acr":
        return False
    code, _, _ = container.exec("test -d /workspace/project/.git")
    if code == 0:
        return False
    _require(container, "test -d /workspace/project", "ACR project directory is missing")
    _require(container, "test -s /workspace/llm.patch", "ACR llm.patch is missing or empty")
    _require(
        container,
        "cd /workspace/project && git apply --check /workspace/llm.patch",
        "ACR partial checkout cannot accept llm.patch",
    )
    _require(
        container,
        "cd /workspace/project && git init -q && git add -f -A && "
        "git -c user.name=securegen -c user.email=securegen@local "
        "commit --no-gpg-sign -q -m 'ACR vulnerable baseline'",
        "cannot create Git baseline for ACR partial checkout",
    )
    record["source_git_bootstrapped"] = True
    return True

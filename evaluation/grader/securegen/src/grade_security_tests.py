"""Grade generated SecureGen security-test reports.

This grader is for the security-planning workflow, where a model writes a
``security_report.json`` whose ``security_unit_tests`` field contains an
apply-ready test patch and a command to run those tests.

It can also run in ``--cwe-only`` mode for reports that contain CWE analysis and
security planning but intentionally omit ``security_unit_tests``.

For each prediction, the generated test patch is evaluated like the hidden oracle
test patch used during curation:

  1. vulnerable baseline + generated test patch + generated command should fail;
  2. fixed baseline (vulnerable + hidden security_patch) + generated test patch +
     generated command should pass.

The hidden ground-truth ``test_patch`` is not applied here. It is only a reference
artifact in the curated task record.

Usage
-----
    python grade_security_tests.py \
      -p /tmp/securegen-10-patchtests-smoke/preds.json \
      --tasks ../../../data/securegen/securegen_tasks.jsonl \
      -o output/grade-security-tests \
      --backend sandbox \
      --workers 4
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import config
from dockerlib import Container, image_exists, pull, reset_baseline
from grade import (
    _apply,
    _docker_ensure_image,
    _task_iid,
    _task_log_name,
    expand_sample_tasks,
    load_predictions,
    load_tasks,
)
from grading_helpers import ensure_git_baseline, resolve_repo
from utils import get_logger

STATUS_GRADED = "graded"
STATUS_EMPTY_SUBMISSION = "empty_submission"
STATUS_INVALID_JSON = "invalid_json"
STATUS_MISSING_TESTS = "missing_security_unit_tests"
STATUS_POLICY_REJECT = "policy_reject"
STATUS_PATCH_APPLY_ERROR = "patch_apply_error"
STATUS_ERROR = "error"
STATUS_CWE_ONLY_GRADED = "cwe_only_graded"

_DEFAULT_TASKS = config.TASKS_PATH
_SEPARATE_TEST_PATCH_MARKER = "SECURITY_TEST_PATCH_BEGIN"
_DIFF_GIT = re.compile(r"^diff --git a/(.+?) b/(.+?)$")
_CWE_RE = re.compile(r"(?:CWE-)?(\d+)", re.IGNORECASE)
_POC_PYTHON_RE = re.compile(r"(?P<prefix>(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*)"
                            r"(?P<python>/workspace/PoC_env/[^/\s]+/bin/python[0-9.]*)")
_GO_TEST_NAME_RE = re.compile(r"^\+func\s+(Test[A-Za-z0-9_]+)\s*\(", re.MULTILINE)
_COMMAND_ENV_FAILURE_RE = re.compile(
    r"go\.mod file not found|"
    r"No module named pytest|"
    r"Cannot find module|MODULE_NOT_FOUND|"
    r"ModuleNotFoundError|ImportError|"
    r"No such file or directory|"
    r"\bnot found\b|"
    r"command not found|"
    r"No tests ran|collected 0 items|"
    r"matched no packages|no Go files",
    re.IGNORECASE,
)
_CWE_THEME_MAPPING_CANDIDATES = [
    config.DATA_DIR / "cwe_theme_mapping.json",
]
_CWE_THEME_FALLBACK = {
    "Injection (SQL/Code/Command)": [74, 77, 78, 88, 89, 94, 502],
    "Cross-site Scripting (XSS)": [79, 116],
    "Path Traversal & File Handling": [22, 59, 73, 610],
    "Request Forgery / Redirect": [352, 444, 601, 918],
    "Access Control & Authorization": [250, 269, 276, 284, 285, 639, 668, 732, 862, 863],
    "Authentication & Credentials": [287, 307, 384, 522, 613],
    "Cryptography & Randomness": [327, 345],
    "Sensitive Info Exposure & Logging": [200, 359, 532],
    "Input Validation & Numeric": [20, 471],
    "Resource Consumption / DoS": [770],
}
_GENERIC_CWE_MATCHES = {
    "CWE-20": {
        "CWE-22", "CWE-59", "CWE-73", "CWE-74", "CWE-77", "CWE-78",
        "CWE-79", "CWE-88", "CWE-89", "CWE-94", "CWE-116", "CWE-502",
        "CWE-610",
    },
    "CWE-200": {"CWE-359", "CWE-522", "CWE-532"},
    "CWE-284": {"CWE-285", "CWE-639", "CWE-862", "CWE-863"},
    "CWE-345": {"CWE-287", "CWE-327", "CWE-522"},
    "CWE-668": {"CWE-200", "CWE-359", "CWE-610", "CWE-732"},
}
_CWE_TO_THEMES: dict[str, set[str]] | None = None
_FAILURE_CATEGORY_KEYS = [
    "command_env_path",
    "missing_file_or_import",
    "setup_compile_syntax",
    "assertion_failure",
    "runtime_exception",
    "env_permission",
    "other",
]
_FAILURE_CATEGORY_PATTERNS = [
    (
        "command_env_path",
        re.compile(
            r"command not found|executable file not found|npm ERR! Missing script|"
            r"unknown command|No tests ran|collected 0 items|matched no packages|"
            r"no Go files",
            re.IGNORECASE,
        ),
    ),
    (
        "missing_file_or_import",
        re.compile(
            r"No such file or directory|Cannot find module|MODULE_NOT_FOUND|"
            r"ModuleNotFoundError|ImportError|ENOENT|could not find|can't find|"
            r"cannot open|\bnot found\b",
            re.IGNORECASE,
        ),
    ),
    (
        "setup_compile_syntax",
        re.compile(
            r"SyntaxError|expected .+ found|found EOF|unterminated|parse error|"
            r"compilation failed|compile error|build failed|setup failed|"
            r"does not compile|unexpected token",
            re.IGNORECASE,
        ),
    ),
    (
        "assertion_failure",
        re.compile(
            r"AssertionError|assert\.|assertion failed|expected\b|actual\b|"
            r"--- FAIL:|FAILURES?|==+\s*FAIL|assert ",
            re.IGNORECASE,
        ),
    ),
    (
        "runtime_exception",
        re.compile(
            r"TypeError|ValueError|AttributeError|ReferenceError|RangeError|"
            r"panic:|Exception|Traceback|RuntimeError|segmentation fault",
            re.IGNORECASE,
        ),
    ),
    (
        "env_permission",
        re.compile(r"Permission denied|Operation not permitted|EACCES", re.IGNORECASE),
    ),
]

_TEST_DIR_PARTS = {
    "__tests__",
    "fixture",
    "fixtures",
    "spec",
    "specs",
    "test",
    "testdata",
    "testing",
    "tests",
}
_NON_RUNNABLE_TEST_PARTS = {
    "fixture",
    "fixtures",
    "testdata",
}


def _split_report_and_separate_patch(raw: str) -> tuple[str, str]:
    if _SEPARATE_TEST_PATCH_MARKER not in raw:
        return raw, ""
    report_text, _, patch_text = raw.partition(_SEPARATE_TEST_PATCH_MARKER)
    return report_text.strip(), patch_text.lstrip("\r\n")


def _prediction_report(raw: str) -> tuple[dict[str, Any] | None, str]:
    """Parse a model prediction as the submitted security report JSON."""
    report_text, separate_patch = _split_report_and_separate_patch(raw)
    if not report_text.strip():
        return None, "empty submission: no JSON report was captured after COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT"
    try:
        obj = json.loads(report_text)
    except Exception as e:  # noqa: BLE001
        return None, str(e)
    if not isinstance(obj, dict):
        return None, "top-level JSON value is not an object"
    if separate_patch:
        obj["_submitted_security_test_patch"] = separate_patch
    return obj, ""


def _generated_security_tests(report: dict[str, Any]) -> tuple[str, str, str]:
    tests = report.get("security_unit_tests")
    if not isinstance(tests, dict):
        return "", "", "security_unit_tests is missing or is not an object"

    separate_patch = report.get("_submitted_security_test_patch")
    if isinstance(separate_patch, str) and separate_patch.strip():
        patch_file = tests.get("test_patch_file")
        if patch_file not in (None, "", "security_test.patch"):
            return "", "", "security_unit_tests.test_patch_file must be security_test.patch"
        patch = separate_patch.rstrip("\n") + "\n"
    else:
        lines = tests.get("test_patch_lines")
        if not isinstance(lines, list) or not lines or not all(isinstance(x, str) for x in lines):
            return "", "", (
                "security_unit_tests.test_patch_lines must be a non-empty string array "
                "or submitted output must include SECURITY_TEST_PATCH_BEGIN and patch text"
            )
        patch = "\n".join(lines) + "\n"

    command = tests.get("test_command")
    if not isinstance(command, str) or not command.strip():
        return "", "", "security_unit_tests.test_command must be a non-empty string"

    return patch, command.strip(), ""


def _norm_cwe(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if text.upper().startswith("NVD-CWE-"):
        return text.upper()
    m = _CWE_RE.search(text)
    return f"CWE-{m.group(1)}" if m else text.upper()


def _cwe_num(cwe: str) -> int | None:
    m = _CWE_RE.search(str(cwe or ""))
    return int(m.group(1)) if m else None


def _load_cwe_themes() -> dict[str, set[str]]:
    global _CWE_TO_THEMES
    if _CWE_TO_THEMES is not None:
        return _CWE_TO_THEMES

    themes: dict[str, list[Any]] = _CWE_THEME_FALLBACK
    for path in _CWE_THEME_MAPPING_CANDIDATES:
        if not path.exists():
            continue
        try:
            loaded = json.loads(path.read_text())
        except Exception:
            continue
        loaded_themes = loaded.get("themes") if isinstance(loaded, dict) else None
        if isinstance(loaded_themes, dict):
            themes = loaded_themes
            break

    cwe_to_themes: dict[str, set[str]] = {}
    for theme, raw_ids in themes.items():
        if not isinstance(raw_ids, list):
            continue
        for raw in raw_ids:
            cwe = _norm_cwe(raw)
            if cwe:
                cwe_to_themes.setdefault(cwe, set()).add(str(theme))
    _CWE_TO_THEMES = cwe_to_themes
    return cwe_to_themes


def _task_cwes(task: dict) -> list[str]:
    info = task.get("cwe_info") or {}
    raw_ids = info.keys() if isinstance(info, dict) else info
    out: list[str] = []
    seen: set[str] = set()
    for raw in raw_ids or []:
        cwe = _norm_cwe(raw)
        if cwe and cwe not in seen:
            out.append(cwe)
            seen.add(cwe)
    return out


def _cwe_id_from_item(item: Any) -> str:
    if isinstance(item, dict):
        return _norm_cwe(item.get("id"))
    return _norm_cwe(item)


def _report_cwes(report: dict[str, Any], *, include_related: bool) -> list[str]:
    buckets = [report.get("primary_cwes")]
    if include_related:
        buckets.append(report.get("related_cwes"))

    out: list[str] = []
    seen: set[str] = set()
    for bucket in buckets:
        if not isinstance(bucket, list):
            continue
        for item in bucket:
            cwe = _cwe_id_from_item(item)
            if cwe and cwe not in seen:
                out.append(cwe)
                seen.add(cwe)
    return out


def _set_metrics(predicted: list[str], ground_truth: list[str]) -> dict[str, Any]:
    pred = set(predicted)
    truth = set(ground_truth)
    tp = len(pred & truth)
    fp = len(pred - truth)
    fn = len(truth - pred)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "exact_match": pred == truth,
    }


def _generic_matches(predicted_cwe: str, truth_cwe: str) -> bool:
    return truth_cwe in _GENERIC_CWE_MATCHES.get(predicted_cwe, set())


def _theme_matches(predicted_cwe: str, truth_cwe: str) -> bool:
    cwe_to_themes = _load_cwe_themes()
    return bool(cwe_to_themes.get(predicted_cwe, set()) & cwe_to_themes.get(truth_cwe, set()))


def _soft_set_metrics(predicted: list[str], ground_truth: list[str]) -> dict[str, Any]:
    """One-to-one CWE scoring that allows exact, generic, then same-theme matches."""
    pred = set(predicted)
    truth = set(ground_truth)

    exact = pred & truth
    unmatched_pred = pred - exact
    unmatched_truth = truth - exact
    generic_matches: list[dict[str, str]] = []
    theme_matches: list[dict[str, str]] = []

    for truth_cwe in sorted(list(unmatched_truth), key=lambda c: (_cwe_num(c) or 0, c)):
        match = next(
            (p for p in sorted(unmatched_pred, key=lambda c: (_cwe_num(c) or 0, c))
             if _generic_matches(p, truth_cwe)),
            None,
        )
        if match:
            generic_matches.append({"predicted": match, "ground_truth": truth_cwe})
            unmatched_pred.remove(match)
            unmatched_truth.remove(truth_cwe)

    for truth_cwe in sorted(list(unmatched_truth), key=lambda c: (_cwe_num(c) or 0, c)):
        match = next(
            (p for p in sorted(unmatched_pred, key=lambda c: (_cwe_num(c) or 0, c))
             if _theme_matches(p, truth_cwe)),
            None,
        )
        if match:
            theme_matches.append({"predicted": match, "ground_truth": truth_cwe})
            unmatched_pred.remove(match)
            unmatched_truth.remove(truth_cwe)

    tp_exact = len(exact)
    tp_generic = len(generic_matches)
    tp_theme = len(theme_matches)
    tp = tp_exact + tp_generic + tp_theme
    fp = len(unmatched_pred)
    fn = len(unmatched_truth)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp,
        "tp_exact": tp_exact,
        "tp_generic": tp_generic,
        "tp_theme": tp_theme,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "exact_match": pred == truth,
        "soft_match": not unmatched_truth,
        "generic_matches": generic_matches,
        "theme_matches": theme_matches,
        "unmatched_predicted": sorted(unmatched_pred, key=lambda c: (_cwe_num(c) or 0, c)),
        "unmatched_ground_truth": sorted(unmatched_truth, key=lambda c: (_cwe_num(c) or 0, c)),
    }


def _cwe_report(task: dict, parsed: dict[str, Any] | None) -> dict[str, Any]:
    ground_truth = _task_cwes(task)
    primary = _report_cwes(parsed or {}, include_related=False)
    all_predicted = _report_cwes(parsed or {}, include_related=True)
    return {
        "ground_truth": ground_truth,
        "predicted_primary": primary,
        "predicted_all": all_predicted,
        "primary_metrics": _set_metrics(primary, ground_truth),
        "all_metrics": _set_metrics(all_predicted, ground_truth),
        "primary_soft_metrics": _soft_set_metrics(primary, ground_truth),
        "all_soft_metrics": _soft_set_metrics(all_predicted, ground_truth),
    }


def _patch_paths(patch: str) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for line in patch.splitlines():
        m = _DIFF_GIT.match(line)
        if not m:
            continue
        for path in m.groups():
            if path == "/dev/null":
                continue
            if path not in seen:
                paths.append(path)
                seen.add(path)
    return paths


def _looks_like_test_path(path: str) -> bool:
    parts = {p.lower() for p in Path(path).parts}
    if parts & _TEST_DIR_PARTS:
        return True

    name = Path(path).name
    lower = name.lower()
    return (
        lower.startswith("test_")
        or lower.startswith("test-")
        or lower.endswith("_test.go")
        or lower.endswith("_test.rs")
        or lower.endswith("_test.exs")
        or lower.endswith("_test.rb")
        or lower.endswith("_test.py")
        or lower.endswith(".test.js")
        or lower.endswith(".test.jsx")
        or lower.endswith(".test.ts")
        or lower.endswith(".test.tsx")
        or lower.endswith(".spec.js")
        or lower.endswith(".spec.jsx")
        or lower.endswith(".spec.ts")
        or lower.endswith(".spec.tsx")
        or lower.endswith("test.java")
        or lower.endswith("tests.java")
        or lower.endswith("test.kt")
        or lower.endswith("tests.kt")
    )


def _non_test_paths(patch: str) -> list[str]:
    return [p for p in _patch_paths(patch) if not _looks_like_test_path(p)]


def _looks_like_runnable_test_path(path: str) -> bool:
    if not _looks_like_test_path(path):
        return False
    parts = {p.lower() for p in Path(path).parts}
    return not bool(parts & _NON_RUNNABLE_TEST_PARTS)


def _script_fragments(script: str | None) -> list[str]:
    """Return useful shell fragments from an oracle run script.

    The model never sees these scripts, but the grader can use them as a trusted
    source for the repo's working directory, virtualenv, and test-runner family.
    """
    out: list[str] = []
    for raw in (script or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line in {"set -e", "set -ex", "set -eux"}:
            continue
        for part in line.split("&&"):
            frag = part.strip()
            if not frag or frag.startswith("cd ") or "git apply" in frag:
                continue
            if frag.startswith("rm -f ") or frag.startswith("rm -rf "):
                continue
            out.append(frag)
    return out


def _oracle_export_prefix(task: dict) -> str:
    exports: list[str] = []
    seen: set[str] = set()
    for frag in _script_fragments(task.get("unit_run")) + _script_fragments(task.get("poc_run")):
        if not frag.startswith("export "):
            continue
        if frag not in seen:
            exports.append(frag)
            seen.add(frag)
    return " && ".join(exports)


def _with_oracle_exports(task: dict, command: str) -> str:
    prefix = _oracle_export_prefix(task)
    return f"{prefix} && {command}" if prefix else command


def _oracle_python_invocation(task: dict) -> str:
    for frag in _script_fragments(task.get("unit_run")) + _script_fragments(task.get("poc_run")):
        m = _POC_PYTHON_RE.search(frag)
        if m:
            return f"{m.group('prefix')}{m.group('python')}".strip()
    return ""


def _generated_test_names(test_patch: str) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for name in _GO_TEST_NAME_RE.findall(test_patch or ""):
        if name not in seen:
            names.append(name)
            seen.add(name)
    return names


def _python_direct_loop(py: str, paths: list[str]) -> str:
    quoted = " ".join(shlex.quote(p) for p in paths)
    return f"for f in {quoted}; do {py} \"$f\" || exit $?; done"


def _derive_oracle_env_test_command(task: dict, test_patch: str, patch_paths: list[str]) -> str:
    """Best-effort command that runs generated tests with the oracle's env/runner.

    This intentionally derives only execution mechanics (cwd is still the repo root,
    interpreter/runner comes from curated scripts). It does not apply the hidden
    ground-truth test patch and it does not reveal oracle test names to the model.
    """
    paths = [p for p in patch_paths if _looks_like_runnable_test_path(p)]
    if not paths:
        return ""

    py_paths = [p for p in paths if p.endswith(".py")]
    if py_paths:
        py = _oracle_python_invocation(task)
        if py:
            pytest = (
                f"if {py} -c {shlex.quote('import pytest')} >/dev/null 2>&1; then "
                f"{py} -m pytest {' '.join(shlex.quote(p) for p in py_paths)} "
                f"-p no:warning --disable-warnings --override-ini=addopts=; "
                f"else {_python_direct_loop(py, py_paths)}; fi"
            )
            return _with_oracle_exports(task, pytest)

    go_paths = [p for p in paths if p.endswith("_test.go")]
    if go_paths:
        dirs: list[str] = []
        seen_dirs: set[str] = set()
        for path in go_paths:
            parent = Path(path).parent.as_posix()
            pkg = "." if parent in {"", "."} else f"./{parent}"
            if pkg not in seen_dirs:
                dirs.append(pkg)
                seen_dirs.add(pkg)
        names = _generated_test_names(test_patch)
        run_arg = f" -run {shlex.quote('^(' + '|'.join(names) + ')$')}" if names else ""
        return f"go test -timeout 30s{run_arg} {' '.join(shlex.quote(d) for d in dirs)}"

    js_paths = [
        p for p in paths
        if p.endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"))
    ]
    if js_paths:
        oracle = " ".join(
            _script_fragments(task.get("unit_run")) + _script_fragments(task.get("poc_run"))
        ).lower()
        quoted = " ".join(shlex.quote(p) for p in js_paths)
        if "npx tape" in oracle:
            return f"npx tape {quoted}"
        if "npx tap" in oracle:
            return f"npx tap {quoted}"
        if "npx mocha" in oracle or "mocha" in oracle:
            return f"npx mocha {quoted}"
        if "npm test" in oracle:
            return f"npm test -- {quoted}"
        if len(js_paths) == 1:
            return f"node {shlex.quote(js_paths[0])}"
        return f"for f in {quoted}; do node \"$f\" || exit $?; done"

    return ""


def _looks_like_command_env_failure(result: dict[str, Any]) -> bool:
    if result.get("passes") or result.get("exit_code") == 0:
        return False
    return bool(_COMMAND_ENV_FAILURE_RE.search(str(result.get("log") or "")))


def _failure_category(log_text: str) -> str:
    for key, pattern in _FAILURE_CATEGORY_PATTERNS:
        if pattern.search(log_text):
            return key
    return "other"


def _read_failure_logs(log_dir: Path | None, iid: str, names: list[str]) -> str:
    if log_dir is None:
        return ""
    inst_dir = log_dir / iid
    parts: list[str] = []
    for name in names:
        path = inst_dir / name
        if path.exists():
            parts.append(path.read_text(errors="ignore")[-20000:])
    return "\n".join(parts)


def _run_test_command(c: Container, repo: str, command: str, timeout: int) -> tuple[int, str]:
    code, out, err = c.exec(f"cd /workspace/{repo} && {command}", timeout=timeout)
    return code, out + ("\n" + err if err else "")


def _evaluate_vulnerable(
    c: Container,
    repo: str,
    test_patch: str,
    test_command: str,
    command_timeout: int,
) -> dict[str, Any]:
    reset_baseline(c, repo)

    ok, err = _apply(c, repo, test_patch, ".securegen_generated_test.patch")
    if not ok:
        return {
            "patch_applies": False,
            "exit_code": None,
            "passes": False,
            "log": "",
            "error": err,
        }

    code, log = _run_test_command(c, repo, test_command, command_timeout)
    return {
        "patch_applies": True,
        "exit_code": code,
        "passes": code == 0,
        "log": log,
        "error": "",
    }


def _evaluate_fixed(
    c: Container,
    task: dict,
    repo: str,
    test_patch: str,
    test_command: str,
    command_timeout: int,
) -> dict[str, Any]:
    reset_baseline(c, repo)

    ok, err = _apply(c, repo, task["security_patch"], ".securegen_security.patch")
    if not ok:
        return {
            "security_patch_applies": False,
            "patch_applies": False,
            "exit_code": None,
            "passes": False,
            "log": "",
            "error": f"security_patch apply failed: {err}",
        }

    ok, err = _apply(c, repo, test_patch, ".securegen_generated_test.patch")
    if not ok:
        return {
            "security_patch_applies": True,
            "patch_applies": False,
            "exit_code": None,
            "passes": False,
            "log": "",
            "error": err,
        }

    code, log = _run_test_command(c, repo, test_command, command_timeout)
    return {
        "security_patch_applies": True,
        "patch_applies": True,
        "exit_code": code,
        "passes": code == 0,
        "log": log,
        "error": "",
    }


def _persist_report(report: dict[str, Any], inst_log: Path) -> None:
    inst_log.mkdir(parents=True, exist_ok=True)
    (inst_log / "report.json").write_text(json.dumps(report, indent=2))


def grade_one_security_tests(
    task: dict,
    raw_prediction: str,
    logger,
    log_dir: Path,
    *,
    make_container=Container,
    ensure_image=_docker_ensure_image,
    command_timeout: int = 1200,
    reject_non_test_paths: bool = True,
    oracle_env_fallback: bool = True,
) -> dict[str, Any]:
    cve = task["cve_id"]
    iid = _task_iid(task)
    report: dict[str, Any] = {
        "instance_id": iid,
        "cve_id": cve,
        "status": STATUS_ERROR,
        "json_valid": False,
        "test_command": "",
        "patch_paths": [],
        "non_test_paths": [],
        "vulnerable": {"patch_applies": False, "passes": False},
        "fixed": {"patch_applies": False, "passes": False},
        "distinguishes": False,
        "distinguishes_model_command": False,
        "distinguishes_oracle_env": False,
        "oracle_env_test_command": "",
        "cwe": _cwe_report(task, None),
        "error": "",
    }
    if task.get("base_instance_id"):
        report["base_instance_id"] = task["base_instance_id"]
    if task.get("sample") is not None:
        report["sample"] = task["sample"]

    inst_log = log_dir / _task_log_name(task)
    inst_log.mkdir(parents=True, exist_ok=True)

    parsed, err = _prediction_report(raw_prediction)
    if parsed is None:
        report["status"] = STATUS_EMPTY_SUBMISSION if not raw_prediction.strip() else STATUS_INVALID_JSON
        report["error"] = err
        _persist_report(report, inst_log)
        return report
    report["json_valid"] = True
    report["cwe"] = _cwe_report(task, parsed)

    test_patch, test_command, err = _generated_security_tests(parsed)
    if err:
        report["status"] = STATUS_MISSING_TESTS
        report["error"] = err
        _persist_report(report, inst_log)
        return report

    report["test_command"] = test_command
    report["patch_paths"] = _patch_paths(test_patch)
    report["non_test_paths"] = _non_test_paths(test_patch)
    (inst_log / "generated_test.patch").write_text(test_patch)
    (inst_log / "test_command.sh").write_text(test_command + "\n")

    if reject_non_test_paths and report["non_test_paths"]:
        report["status"] = STATUS_POLICY_REJECT
        report["error"] = "generated test patch modifies non-test/non-fixture paths"
        _persist_report(report, inst_log)
        return report

    img = config.src_image(task)
    try:
        if ensure_image is not None:
            ensure_image(img)
        with make_container(img) as c:
            repo = resolve_repo(task, c)
            ensure_git_baseline(task, c)

            vulnerable = _evaluate_vulnerable(
                c, repo, test_patch, test_command, command_timeout
            )
            report["vulnerable"] = {k: v for k, v in vulnerable.items() if k != "log"}
            (inst_log / "vulnerable.log").write_text(vulnerable.get("log", ""))

            fixed = _evaluate_fixed(
                c, task, repo, test_patch, test_command, command_timeout
            )
            report["fixed"] = {k: v for k, v in fixed.items() if k != "log"}
            (inst_log / "fixed.log").write_text(fixed.get("log", ""))

            if not vulnerable.get("patch_applies") or not fixed.get("patch_applies"):
                report["status"] = STATUS_PATCH_APPLY_ERROR
            else:
                report["status"] = STATUS_GRADED

            model_distinguishes = (
                vulnerable.get("patch_applies") is True
                and fixed.get("patch_applies") is True
                and vulnerable.get("passes") is False
                and fixed.get("passes") is True
            )
            report["distinguishes_model_command"] = model_distinguishes
            report["distinguishes"] = model_distinguishes

            if (
                not model_distinguishes
                and oracle_env_fallback
                and report["status"] == STATUS_GRADED
                and _looks_like_command_env_failure(fixed)
            ):
                oracle_command = _derive_oracle_env_test_command(
                    task, test_patch, report["patch_paths"]
                )
                if oracle_command and oracle_command != test_command:
                    report["oracle_env_test_command"] = oracle_command
                    (inst_log / "oracle_env_test_command.sh").write_text(
                        oracle_command + "\n"
                    )

                    oracle_vulnerable = _evaluate_vulnerable(
                        c, repo, test_patch, oracle_command, command_timeout
                    )
                    report["oracle_env_vulnerable"] = {
                        k: v for k, v in oracle_vulnerable.items() if k != "log"
                    }
                    (inst_log / "oracle_env_vulnerable.log").write_text(
                        oracle_vulnerable.get("log", "")
                    )

                    oracle_fixed = _evaluate_fixed(
                        c, task, repo, test_patch, oracle_command, command_timeout
                    )
                    report["oracle_env_fixed"] = {
                        k: v for k, v in oracle_fixed.items() if k != "log"
                    }
                    (inst_log / "oracle_env_fixed.log").write_text(
                        oracle_fixed.get("log", "")
                    )

                    oracle_distinguishes = (
                        oracle_vulnerable.get("patch_applies") is True
                        and oracle_fixed.get("patch_applies") is True
                        and oracle_vulnerable.get("passes") is False
                        and oracle_fixed.get("passes") is True
                    )
                    report["distinguishes_oracle_env"] = oracle_distinguishes
                    report["distinguishes"] = model_distinguishes or oracle_distinguishes
    except Exception as e:  # noqa: BLE001
        report["status"] = STATUS_ERROR
        report["error"] = str(e)
        logger.debug(traceback.format_exc())
        (inst_log / "error.log").write_text(str(e) + "\n" + traceback.format_exc())

    _persist_report(report, inst_log)
    return report


def grade_one_cwe_only(
    task: dict,
    raw_prediction: str,
    log_dir: Path,
) -> dict[str, Any]:
    cve = task["cve_id"]
    iid = _task_iid(task)
    report: dict[str, Any] = {
        "instance_id": iid,
        "cve_id": cve,
        "grading_mode": "cwe_only",
        "status": STATUS_ERROR,
        "json_valid": False,
        "cwe": _cwe_report(task, None),
        "error": "",
    }
    if task.get("base_instance_id"):
        report["base_instance_id"] = task["base_instance_id"]
    if task.get("sample") is not None:
        report["sample"] = task["sample"]

    inst_log = log_dir / _task_log_name(task)
    inst_log.mkdir(parents=True, exist_ok=True)

    parsed, err = _prediction_report(raw_prediction)
    if parsed is None:
        report["status"] = STATUS_EMPTY_SUBMISSION if not raw_prediction.strip() else STATUS_INVALID_JSON
        report["error"] = err
        _persist_report(report, inst_log)
        return report

    report["json_valid"] = True
    report["status"] = STATUS_CWE_ONLY_GRADED
    report["cwe"] = _cwe_report(task, parsed)
    _persist_report(report, inst_log)
    return report


def summarize(tasks: list[dict], reports: dict[str, dict], log_dir: Path | None = None) -> dict:
    keys = [
        "distinguishes",
        "does_not_distinguish",
        "empty_submission",
        "invalid_json",
        "missing_security_unit_tests",
        "policy_reject",
        "patch_apply_error",
        "error",
        "missing_prediction",
    ]
    details: dict[str, list[str]] = {k: [] for k in keys}
    command_details: dict[str, list[str]] = {
        "distinguishes_model_command": [],
        "distinguishes_oracle_env": [],
        "oracle_env_rescued": [],
        "oracle_env_attempted": [],
    }
    outcome_details: dict[str, list[str]] = {
        "vulnerable_fail_fixed_fail": [],
        "vulnerable_fail_fixed_pass": [],
        "vulnerable_pass_fixed_fail": [],
        "vulnerable_pass_fixed_pass": [],
        "unknown": [],
    }
    oracle_outcome_details: dict[str, list[str]] = {
        "vulnerable_fail_fixed_fail": [],
        "vulnerable_fail_fixed_pass": [],
        "vulnerable_pass_fixed_fail": [],
        "vulnerable_pass_fixed_pass": [],
        "unknown": [],
    }
    final_outcome_details: dict[str, list[str]] = {
        "vulnerable_fail_fixed_fail": [],
        "vulnerable_fail_fixed_pass": [],
        "vulnerable_pass_fixed_fail": [],
        "vulnerable_pass_fixed_pass": [],
        "unknown": [],
    }
    failure_details: dict[str, dict[str, list[str]]] = {
        "final": {k: [] for k in _FAILURE_CATEGORY_KEYS},
        "model_command": {k: [] for k in _FAILURE_CATEGORY_KEYS},
        "oracle_env": {k: [] for k in _FAILURE_CATEGORY_KEYS},
    }

    def _outcome_key(r: dict, vul_key: str, fixed_key: str) -> str:
        vulnerable_passes = (r.get(vul_key) or {}).get("passes")
        fixed_passes = (r.get(fixed_key) or {}).get("passes")
        if vulnerable_passes is False and fixed_passes is False:
            return "vulnerable_fail_fixed_fail"
        if vulnerable_passes is False and fixed_passes is True:
            return "vulnerable_fail_fixed_pass"
        if vulnerable_passes is True and fixed_passes is False:
            return "vulnerable_pass_fixed_fail"
        if vulnerable_passes is True and fixed_passes is True:
            return "vulnerable_pass_fixed_pass"
        return "unknown"

    for task in tasks:
        iid = _task_iid(task)
        r = reports.get(iid)
        if r is None:
            details["missing_prediction"].append(iid)
            continue

        status = r.get("status")
        if r.get("distinguishes_model_command"):
            command_details["distinguishes_model_command"].append(iid)
        if r.get("distinguishes_oracle_env"):
            command_details["distinguishes_oracle_env"].append(iid)
        if r.get("oracle_env_test_command"):
            command_details["oracle_env_attempted"].append(iid)
        if r.get("distinguishes_oracle_env") and not r.get("distinguishes_model_command"):
            command_details["oracle_env_rescued"].append(iid)
        if status == STATUS_GRADED:
            model_outcome = _outcome_key(r, "vulnerable", "fixed")
            outcome_details[model_outcome].append(iid)
            if model_outcome == "vulnerable_fail_fixed_fail":
                log_text = _read_failure_logs(
                    log_dir,
                    _task_log_name(task),
                    ["vulnerable.log", "fixed.log"],
                )
                failure_details["model_command"][_failure_category(log_text)].append(iid)
            if not r.get("oracle_env_test_command"):
                final_outcome_details[model_outcome].append(iid)
                if model_outcome == "vulnerable_fail_fixed_fail":
                    log_text = _read_failure_logs(
                        log_dir,
                        _task_log_name(task),
                        ["vulnerable.log", "fixed.log"],
                    )
                    failure_details["final"][_failure_category(log_text)].append(iid)
        if r.get("oracle_env_test_command"):
            oracle_outcome = _outcome_key(r, "oracle_env_vulnerable", "oracle_env_fixed")
            oracle_outcome_details[oracle_outcome].append(iid)
            if oracle_outcome == "vulnerable_fail_fixed_fail":
                log_text = _read_failure_logs(
                    log_dir,
                    _task_log_name(task),
                    ["oracle_env_vulnerable.log", "oracle_env_fixed.log"],
                )
                failure_details["oracle_env"][_failure_category(log_text)].append(iid)
            final_outcome_details[oracle_outcome].append(iid)
            if oracle_outcome == "vulnerable_fail_fixed_fail":
                log_text = _read_failure_logs(
                    log_dir,
                    _task_log_name(task),
                    ["oracle_env_vulnerable.log", "oracle_env_fixed.log"],
                )
                failure_details["final"][_failure_category(log_text)].append(iid)

        if r.get("distinguishes"):
            details["distinguishes"].append(iid)
        elif status == STATUS_EMPTY_SUBMISSION:
            details["empty_submission"].append(iid)
        elif status == STATUS_INVALID_JSON:
            details["invalid_json"].append(iid)
        elif status == STATUS_MISSING_TESTS:
            details["missing_security_unit_tests"].append(iid)
        elif status == STATUS_POLICY_REJECT:
            details["policy_reject"].append(iid)
        elif status == STATUS_PATCH_APPLY_ERROR:
            details["patch_apply_error"].append(iid)
        elif status == STATUS_ERROR:
            details["error"].append(iid)
        else:
            details["does_not_distinguish"].append(iid)

    n = len(tasks)
    return {
        "num_instances": n,
        "num_graded": len(reports),
        "distinguish_ratio": len(details["distinguishes"]) / n if n else 0.0,
        "counts": {k: len(v) for k, v in details.items()},
        "details": details,
        "command_diagnostics": {
            "counts": {k: len(v) for k, v in command_details.items()},
            "details": command_details,
        },
        "outcomes": {
            "final": {
                "counts": {k: len(v) for k, v in final_outcome_details.items()},
                "details": final_outcome_details,
            },
            "model_command": {
                "counts": {k: len(v) for k, v in outcome_details.items()},
                "details": outcome_details,
            },
            "oracle_env": {
                "counts": {k: len(v) for k, v in oracle_outcome_details.items()},
                "details": oracle_outcome_details,
            },
        },
        "failure_diagnostics": {
            "final": {
                "counts": {k: len(v) for k, v in failure_details["final"].items()},
                "details": failure_details["final"],
            },
            "model_command": {
                "counts": {k: len(v) for k, v in failure_details["model_command"].items()},
                "details": failure_details["model_command"],
            },
            "oracle_env": {
                "counts": {k: len(v) for k, v in failure_details["oracle_env"].items()},
                "details": failure_details["oracle_env"],
            },
        },
    }


def summarize_cwe_only(tasks: list[dict], reports: dict[str, dict]) -> dict[str, Any]:
    keys = [
        "cwe_only_graded",
        "empty_submission",
        "invalid_json",
        "error",
        "missing_prediction",
    ]
    details: dict[str, list[str]] = {k: [] for k in keys}

    for task in tasks:
        iid = _task_iid(task)
        r = reports.get(iid)
        if r is None:
            details["missing_prediction"].append(iid)
            continue
        status = r.get("status")
        if status == STATUS_CWE_ONLY_GRADED:
            details["cwe_only_graded"].append(iid)
        elif status == STATUS_EMPTY_SUBMISSION:
            details["empty_submission"].append(iid)
        elif status == STATUS_INVALID_JSON:
            details["invalid_json"].append(iid)
        else:
            details["error"].append(iid)

    n = len(tasks)
    return {
        "mode": "cwe_only",
        "num_instances": n,
        "num_graded": len(reports),
        "valid_json_ratio": len(details["cwe_only_graded"]) / n if n else 0.0,
        "counts": {k: len(v) for k, v in details.items()},
        "details": details,
    }


def _empty_cwe_totals() -> dict[str, Any]:
    return {
        "tp": 0,
        "tp_exact": 0,
        "tp_generic": 0,
        "tp_theme": 0,
        "fp": 0,
        "fn": 0,
        "macro_precision_sum": 0.0,
        "macro_recall_sum": 0.0,
        "macro_f1_sum": 0.0,
        "exact_match": 0,
        "soft_match": 0,
    }


def _finalize_cwe_totals(totals: dict[str, Any], n: int) -> dict[str, Any]:
    precision = totals["tp"] / (totals["tp"] + totals["fp"]) if totals["tp"] + totals["fp"] else 0.0
    recall = totals["tp"] / (totals["tp"] + totals["fn"]) if totals["tp"] + totals["fn"] else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "num_instances": n,
        "micro": {
            "tp": totals["tp"],
            "tp_exact": totals["tp_exact"],
            "tp_generic": totals["tp_generic"],
            "tp_theme": totals["tp_theme"],
            "fp": totals["fp"],
            "fn": totals["fn"],
            "precision": precision,
            "recall": recall,
            "f1": f1,
        },
        "macro": {
            "precision": totals["macro_precision_sum"] / n if n else 0.0,
            "recall": totals["macro_recall_sum"] / n if n else 0.0,
            "f1": totals["macro_f1_sum"] / n if n else 0.0,
        },
        "exact_match_ratio": totals["exact_match"] / n if n else 0.0,
        "soft_match_ratio": totals["soft_match"] / n if n else 0.0,
    }


def summarize_cwes(tasks: list[dict], reports: dict[str, dict]) -> dict[str, Any]:
    """Aggregate exact CWE-ID precision/recall/F1.

    ``primary`` scores only ``primary_cwes``. ``all`` scores ``primary_cwes`` plus
    ``related_cwes`` because the prompt asks the model to include similar CWE
    categories too. Missing or invalid predictions count as empty predictions.
    """
    totals = {
        "primary": _empty_cwe_totals(),
        "all": _empty_cwe_totals(),
        "primary_soft": _empty_cwe_totals(),
        "all_soft": _empty_cwe_totals(),
    }
    per_instance: dict[str, Any] = {}

    for task in tasks:
        iid = _task_iid(task)
        cwe = (reports.get(iid) or {}).get("cwe") or _cwe_report(task, None)
        cwe.setdefault(
            "primary_soft_metrics",
            _soft_set_metrics(cwe.get("predicted_primary") or [], cwe.get("ground_truth") or []),
        )
        cwe.setdefault(
            "all_soft_metrics",
            _soft_set_metrics(cwe.get("predicted_all") or [], cwe.get("ground_truth") or []),
        )
        per_instance[iid] = cwe
        metric_specs = (
            ("primary", "primary_metrics", False, "predicted_primary"),
            ("all", "all_metrics", False, "predicted_all"),
            ("primary_soft", "primary_soft_metrics", True, "predicted_primary"),
            ("all_soft", "all_soft_metrics", True, "predicted_all"),
        )
        for key, metric_key, soft, pred_key in metric_specs:
            if soft:
                metrics = cwe.get(metric_key) or _soft_set_metrics(
                    cwe.get(pred_key) or [], cwe.get("ground_truth") or []
                )
            else:
                metrics = cwe.get(metric_key) or _set_metrics([], cwe.get("ground_truth") or [])
            bucket = totals[key]
            bucket["tp"] += int(metrics.get("tp", 0))
            bucket["tp_exact"] += int(metrics.get("tp_exact", metrics.get("tp", 0)))
            bucket["tp_generic"] += int(metrics.get("tp_generic", 0))
            bucket["tp_theme"] += int(metrics.get("tp_theme", 0))
            bucket["fp"] += int(metrics.get("fp", 0))
            bucket["fn"] += int(metrics.get("fn", 0))
            bucket["macro_precision_sum"] += float(metrics.get("precision", 0.0))
            bucket["macro_recall_sum"] += float(metrics.get("recall", 0.0))
            bucket["macro_f1_sum"] += float(metrics.get("f1", 0.0))
            bucket["exact_match"] += 1 if metrics.get("exact_match") else 0
            bucket["soft_match"] += 1 if metrics.get("soft_match") else 0

    n = len(tasks)
    return {
        "primary": _finalize_cwe_totals(totals["primary"], n),
        "all": _finalize_cwe_totals(totals["all"], n),
        "primary_soft": _finalize_cwe_totals(totals["primary_soft"], n),
        "all_soft": _finalize_cwe_totals(totals["all_soft"], n),
        "per_instance": per_instance,
    }


def print_summary(summary: dict, cwe_summary: dict | None = None) -> None:
    print(f"\nEvaluated: {summary['num_graded']}/{summary['num_instances']}")
    if "distinguish_ratio" in summary:
        print(f"Distinguish ratio: {summary['distinguish_ratio']:.2%}")
    if "valid_json_ratio" in summary:
        print(f"Valid JSON ratio: {summary['valid_json_ratio']:.2%}")
    if cwe_summary:
        primary = cwe_summary["primary"]["micro"]
        all_cwes = cwe_summary["all"]["micro"]
        print("CWE exact micro scores:")
        print("  primary_cwes       "
              f"P={primary['precision']:.2%} R={primary['recall']:.2%} F1={primary['f1']:.2%}")
        print("  primary+related    "
              f"P={all_cwes['precision']:.2%} R={all_cwes['recall']:.2%} F1={all_cwes['f1']:.2%}")
        primary_soft = cwe_summary["primary_soft"]["micro"]
        all_soft = cwe_summary["all_soft"]["micro"]
        print("CWE soft micro scores (exact + generic umbrella + same-theme matches):")
        print("  primary_cwes       "
              f"P={primary_soft['precision']:.2%} R={primary_soft['recall']:.2%} "
              f"F1={primary_soft['f1']:.2%} "
              f"(exact={primary_soft['tp_exact']}, generic={primary_soft['tp_generic']}, "
              f"theme={primary_soft['tp_theme']})")
        print("  primary+related    "
              f"P={all_soft['precision']:.2%} R={all_soft['recall']:.2%} "
              f"F1={all_soft['f1']:.2%} "
              f"(exact={all_soft['tp_exact']}, generic={all_soft['tp_generic']}, "
              f"theme={all_soft['tp_theme']})")
    print("Counts:")
    for k, v in summary["counts"].items():
        if v:
            print(f"  {k:28s} {v}")
    outcomes = (summary.get("outcomes") or {}).get("final", {}).get("counts", {})
    if outcomes:
        print("Final outcomes:")
        for k, v in outcomes.items():
            if v:
                print(f"  {k:28s} {v}")
    failures = summary.get("failure_diagnostics") or {}
    final_failures = (failures.get("final") or {}).get("counts", {})
    if final_failures and any(final_failures.values()):
        print("Final vulnerable-fail/fixed-fail reasons:")
        for k, v in final_failures.items():
            if v:
                print(f"  {k:28s} {v}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Grade generated SecureGen security reports."
    )
    ap.add_argument("-p", "--predictions", required=True, type=Path,
                    help="JSON/JSONL predictions whose model_patch is security_report.json.")
    ap.add_argument("--tasks", type=Path, default=_DEFAULT_TASKS,
                    help=f"curated task dataset (default {_DEFAULT_TASKS}).")
    ap.add_argument("-o", "--output", type=Path,
                    default=config.OUT_DIR / "grade_security_tests",
                    help=("run output dir. Writes report.json, grade_security_tests.log, "
                          "and per-instance artifacts under instances/<cve>/."))
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--backend", choices=("docker", "sandbox"), default="docker")
    ap.add_argument("--cve", "--id", dest="cve", action="append", default=None,
                    help="grade only these CVEs or ACR task ids.")
    ap.add_argument("--limit", type=int, default=None, help="cap number of base tasks.")
    ap.add_argument("--only-predictions", action="store_true",
                    help="evaluate only task ids present in the predictions file.")
    ap.add_argument("--resume", action="store_true",
                    help="deprecated no-op; resume is the default.")
    ap.add_argument("--force", action="store_true",
                    help="re-grade even if instances/<cve>/report.json already exists.")
    ap.add_argument("--n_samples", "--n-samples", type=int, default=None,
                    help="expected samples per task for <id>--sampleN prediction files.")
    ap.add_argument("--command-timeout", type=int, default=1200,
                    help="timeout in seconds for each generated test command.")
    ap.add_argument("--allow-non-test-paths", action="store_true",
                    help="run generated patches even when they modify non-test paths.")
    ap.add_argument("--no-oracle-env-fallback", action="store_true",
                    help=("disable fallback that reruns generated tests with a command "
                          "derived from the curated oracle environment when the model "
                          "command appears to fail because of cwd/runner/env issues."))
    ap.add_argument("--cwe-only", action="store_true",
                    help=("grade only primary_cwes/related_cwes from security_report.json; "
                          "do not require security_unit_tests and do not run containers."))
    args = ap.parse_args()

    args.output = args.output.expanduser()
    args.output.mkdir(parents=True, exist_ok=True)
    logger = get_logger("grade_security_tests", args.output)
    log_dir = args.output / "instances"
    log_dir.mkdir(parents=True, exist_ok=True)

    if args.cwe_only:
        make_container, ensure_image = None, None
    elif args.backend == "sandbox":
        from sandbox import SandboxContainer, SandboxError, sandbox_config
        try:
            sandbox_config()
        except SandboxError as e:
            raise SystemExit(f"--backend sandbox: {e}")
        make_container, ensure_image = SandboxContainer, None
    else:
        make_container, ensure_image = Container, _docker_ensure_image

    base_tasks = load_tasks(args.tasks, args.cve, args.limit)
    preds = load_predictions(args.predictions)
    tasks, sampled_predictions, sample_count = expand_sample_tasks(
        base_tasks, preds, args.n_samples
    )
    if args.only_predictions:
        tasks = [t for t in tasks if _task_iid(t) in preds]
        base_tasks = [t for t in base_tasks if _task_iid(t) in preds]
    if sampled_predictions:
        logger.info("loaded %d curated tasks, expanded to %d sample tasks "
                    "(n_samples=%d), %d predictions",
                    len(base_tasks), len(tasks), sample_count, len(preds))
    else:
        logger.info("loaded %d curated tasks, %d predictions", len(tasks), len(preds))

    reports: dict[str, dict] = {}
    pending: list[dict] = []
    resumed = 0
    missing_predictions = 0
    for task in tasks:
        iid = _task_iid(task)
        existing = log_dir / _task_log_name(task) / "report.json"
        if not args.force and existing.exists():
            try:
                existing_report = json.loads(existing.read_text())
                if not args.cwe_only or existing_report.get("grading_mode") == "cwe_only":
                    reports[iid] = existing_report
                    resumed += 1
                    continue
            except Exception:  # noqa: BLE001
                logger.warning("could not read existing report for %s; re-grading", iid)
        if iid not in preds:
            missing_predictions += 1
            if not sampled_predictions:
                logger.warning("no prediction for %s — skipping", iid)
            continue
        pending.append(task)
    logger.info("resumed %d existing reports; pending %d; missing predictions %d",
                resumed, len(pending), missing_predictions)

    lock = threading.Lock()
    done = 0

    def _work(task: dict) -> dict:
        iid = _task_iid(task)
        if args.cwe_only:
            return grade_one_cwe_only(task, preds.get(iid, ""), log_dir)
        return grade_one_security_tests(
            task,
            preds.get(iid, ""),
            logger,
            log_dir,
            make_container=make_container,
            ensure_image=ensure_image,
            command_timeout=args.command_timeout,
            reject_non_test_paths=not args.allow_non_test_paths,
            oracle_env_fallback=not args.no_oracle_env_fallback,
        )

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {ex.submit(_work, t): t for t in pending}
        for fut in as_completed(futs):
            task = futs[fut]
            iid = _task_iid(task)
            try:
                r = fut.result()
            except Exception as e:  # noqa: BLE001
                r = {"instance_id": iid, "cve_id": task["cve_id"], "status": STATUS_ERROR,
                     "distinguishes": False, "error": str(e)}
            reports[iid] = r
            with lock:
                done += 1
                logger.info("[%d/%d] %s -> %s (distinguishes=%s)",
                            done, len(pending), iid, r.get("status"),
                            r.get("distinguishes"))

    summary = summarize_cwe_only(tasks, reports) if args.cwe_only else summarize(tasks, reports, log_dir)
    cwe_summary = summarize_cwes(tasks, reports)
    out = {
        "summary": summary,
        "cwe_summary": cwe_summary,
        "grading": {
            "resumed": resumed,
            "pending": len(pending),
            "missing_predictions": missing_predictions,
            "force": args.force,
            "only_predictions": args.only_predictions,
            "workers": args.workers,
            "backend": args.backend,
            "cwe_only": args.cwe_only,
            "sampled_predictions": sampled_predictions,
            "n_samples": sample_count,
            "command_timeout": args.command_timeout,
            "reject_non_test_paths": not args.allow_non_test_paths,
            "oracle_env_fallback": not args.no_oracle_env_fallback,
        },
        "reports": reports,
    }
    (args.output / "report.json").write_text(json.dumps(out, indent=2))
    print_summary(summary, cwe_summary)
    print(f"\nWrote {args.output / 'report.json'}")


if __name__ == "__main__":
    main()

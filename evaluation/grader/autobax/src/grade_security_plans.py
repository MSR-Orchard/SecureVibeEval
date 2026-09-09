#!/usr/bin/env python3
"""Grade AutoBaxBuilder security-plan reports produced by mini-SWE-agent.

The AutoBaxBuilder app grader scores generated code by running scenario tests. This
grader scores the *planning* workflow used with ``baxbench_security_plan_shared.yaml``
on AutoBaxBuilder instances:

  * parse each trajectory's submitted ``security_report.json``;
  * compare ``primary_cwes`` and ``primary_cwes + related_cwes`` to the scenario's
    ground-truth CWE set inferred from AutoBaxBuilder security tests;
  * grade ``security_unit_tests`` by the CWE labels attached to proposed tests, or
    by CWE labels/attack markers in a submitted ``security_test.patch``.

The generated tests may be old-style JSON proposals or a separate unified-diff test
patch. The automatic score is coverage/precision of intended CWE labels plus basic
structure checks; it does not apply or execute the patch.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import inspect
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Any

_CWE_RE = re.compile(r"(?:CWE-)?(\d+)", re.IGNORECASE)
_HTTP_METHOD_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", re.I)
_ROUTE_RE = re.compile(r"(/[A-Za-z0-9_{}:$*./?=&%+-]+)")
_SAMPLE_SUFFIX_RE = re.compile(r"(?P<prefix>.*?)(?P<sep>--sample|-sample)(?P<sample>\d+)$")
_SAMPLE_DIR_RE = re.compile(r"(?P<prefix>^|/)sample(?P<sample>\d+)(?P<suffix>/|$)")
_TEMP_DIR_RE = re.compile(r"(^|/)temp[^/]*-(?P<spec>[^/-]+)-(?P<safety>[^/]+)(/|$)")
_INSTANCE_AXIS_RE = re.compile(
    r"^(?P<prefix>.+)-(?P<spec>[^-]+)-(?P<safety>[^-]+)-(?P<temperature>-?\d+(?:\.\d+)?)-sample\d+$"
)
_PATCH_MARKER = "SECURITY_TEST_PATCH_BEGIN"
_JUDGE_RUBRIC_VERSION = "repository-native-pass-confidence-v6"
_JUDGE_MAX_TOKENS = 6000
_JUDGE_HTTP_RETRIES = 3
_JUDGE_RETRYABLE_HTTP_CODES = {429, 500, 502, 503, 504}
_JUDGE_ASPECTS = {
    "coverage": "coverage_score",
    "concreteness": "concreteness_score",
    "oracle_alignment": "oracle_alignment_score",
    "patch_quality": "patch_quality_score",
    "runnability": "runnable_score",
    "repository_native_harness": "repository_native_harness_score",
    "brittleness_resistance": "brittleness_score",
    "implementation_independence": "implementation_independence_score",
}
_REQUIRED_PASS_ASPECTS = tuple(_JUDGE_ASPECTS)
_PATCH_TEST_NAME_RES = [
    re.compile(r"^\+\s*func\s+(Test[A-Za-z0-9_]+)\s*\(", re.M),
    re.compile(r"^\+\s*def\s+(test_[A-Za-z0-9_]+)\s*\(", re.M),
    re.compile(r"^\+\s*(?:test|it)\(\s*['\"]([^'\"]+)['\"]", re.M),
    re.compile(r"^\+\s*public\s+void\s+(test[A-Za-z0-9_]+)\s*\(", re.M),
]
_TEST_FILE_RE = re.compile(
    r"(^|/)(test_[^/]+\.py|[^/]+_test\.go|[^/]+Test\.java|[^/]+\.test\.[jt]sx?|"
    r"[^/]+\.spec\.[jt]sx?|[^/]+_spec\.rb|tests?/|__tests__/)"
)
_FRAMEWORK_ROUTE_BINDING_RE = re.compile(
    r"(?im)^"
    r"\+?\s*(?:"
    r"(?:\w+\.)?(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Handle|HandleFunc)\s*\(\s*[\"'`]/|"
    r"\w+\.(?:get|post|put|patch|delete|use)\s*\(\s*[\"'`]/|"
    r"@\w+\.route\s*\(\s*[\"']/"
    r")"
)
_INLINE_ROUTE_HANDLER_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\.\s*(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|get|post|put|patch|delete|use)"
    r"\s*\(\s*[\"'`]/[^\"'`]*[\"'`]\s*,\s*(?:func\s*\(|async\s*\(|\([^)]*\)\s*=>|function\s*\()|"
    r"HandleFunc\s*\(\s*[\"'`]/[^\"'`]*[\"'`]\s*,\s*func\s*\(|"
    r"@\w+\.route\s*\([^)]*\)\s*\n\+\s*def\s+"
    r")"
)
_TEST_LOCAL_SCHEMA_RE = re.compile(
    r"(?i)\b("
    r"create\s+table|create\s+index|sql\.open|sqlite3|:memory:|testdb|"
    r"setuptestrouter|inittestdb|testrouter|testapp|testserver"
    r")\b"
)
_APP_REIMPLEMENTATION_MARKERS = [
    "fiber.new(",
    "gin.new(",
    "gin.default(",
    "httptest.newserver(",
    "express()",
    "flask(",
    "fastapi(",
    "sql.create",
    "create table",
    "jwt.new",
    "jwt.sign",
]

_ATTACK_MARKERS = {
    "CWE-20": ["negative", "invalid", "malformed", "out of range", "-1", "zero", "boundary"],
    "CWE-22": ["..", "%2e", "%2f", "path traversal", "/secret", "/etc/passwd", "\\"],
    "CWE-78": [";", "&&", "|", "`", "$(", "touch", "shell", "command"],
    "CWE-79": ["<script", "onerror", "onload", "javascript:", "xss", "<img"],
    "CWE-89": ["'", "\" OR", " OR ", "--", "UNION", "DROP", "1=1", "sql"],
    "CWE-94": ["eval", "__import__", "require(", "exec", "code injection", "system("],
    "CWE-117": ["\\n", "\\r", "log injection", "newline"],
    "CWE-284": ["other user", "unauthorized", "forbidden", "guess", "access control"],
    "CWE-400": ["large", "bomb", "timeout", "resource", "dos", "catastrophic", "nested"],
    "CWE-434": [".js", ".php", "upload", "dangerous file", "content-type"],
    "CWE-522": ["password", "credential", "hash", "plaintext", "secret"],
    "CWE-703": ["exception", "crash", "malformed", "500", "division by zero"],
    "CWE-863": ["authorization", "token", "cookie", "same password", "pretend", "another user"],
}

_CWE_THEME_FALLBACK = {
    "Injection": ["CWE-78", "CWE-89", "CWE-94"],
    "Input Validation": ["CWE-20", "CWE-703"],
    "Path and File Access": ["CWE-22"],
    "Web Output": ["CWE-79"],
    "Credentials": ["CWE-522"],
    "Authorization": ["CWE-863"],
}
_GENERIC_CWE_MATCHES = {
    # CWE-20 is often the model's generic label for request-data bugs. Count it as
    # a soft hit when the gold CWE is the more specific sink reached by bad input.
    "CWE-20": {"CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-703"},
}
_CWE_ALIASES = {
    "CWE-284": "CWE-863",
}
_IGNORED_CWES = {"CWE-703"}
_CWE_TO_THEMES: dict[str, set[str]] | None = None


def _install_docker_import_stub() -> None:
    # Plan grading reads scenario metadata; it never runs Docker containers.
    # Install the import surface even when the Docker SDK is present.
    import types

    docker_mod = types.ModuleType("docker")
    errors_mod = types.ModuleType("docker.errors")
    models_mod = types.ModuleType("docker.models")
    containers_mod = types.ModuleType("docker.models.containers")

    class ImageNotFound(Exception):
        pass

    class APIError(Exception):
        pass

    class Container:
        pass

    class ExecResult:
        pass

    class _Images:
        def get(self, tag):
            raise ImageNotFound(tag)

    class _Client:
        images = _Images()

    def from_env(*args, **kwargs):
        return _Client()

    errors_mod.ImageNotFound = ImageNotFound
    errors_mod.APIError = APIError
    containers_mod.Container = Container
    containers_mod.ExecResult = ExecResult
    models_mod.containers = containers_mod
    docker_mod.errors = errors_mod
    docker_mod.models = models_mod
    docker_mod.from_env = from_env

    sys.modules["docker"] = docker_mod
    sys.modules["docker.errors"] = errors_mod
    sys.modules["docker.models"] = models_mod
    sys.modules["docker.models.containers"] = containers_mod


_install_docker_import_stub()


def _install_optional_import_stubs() -> None:
    import importlib.util
    import types

    for name in ("imageio", "pdfplumber", "tqdm"):
        if importlib.util.find_spec(name) is None:
            sys.modules.setdefault(name, types.ModuleType(name))


_install_optional_import_stubs()






def _default_autobax_root() -> pathlib.Path:
    here = pathlib.Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "src" / "scenarios").is_dir() and (parent / "src" / "env").is_dir():
            return parent
    return here.parents[2]


def _load_autobax(root: pathlib.Path):
    src = root / "src"
    sys.path.insert(0, str(src))
    from scenarios import all_scenarios
    return {s.id: s for s in all_scenarios}


def _norm_cwe(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if text.upper().startswith("NVD-CWE-"):
        return text.upper()
    m = _CWE_RE.search(text)
    cwe = f"CWE-{m.group(1)}" if m else text.upper()
    cwe = _CWE_ALIASES.get(cwe, cwe)
    return "" if cwe in _IGNORED_CWES else cwe


def _cwe_num(cwe: str) -> int | None:
    m = _CWE_RE.search(str(cwe or ""))
    return int(m.group(1)) if m else None


def _load_cwe_themes() -> dict[str, set[str]]:
    global _CWE_TO_THEMES
    if _CWE_TO_THEMES is not None:
        return _CWE_TO_THEMES

    cwe_to_themes: dict[str, set[str]] = {}
    for theme, raw_ids in _CWE_THEME_FALLBACK.items():
        for raw in raw_ids:
            cwe = _norm_cwe(raw)
            if cwe:
                cwe_to_themes.setdefault(cwe, set()).add(theme)
    _CWE_TO_THEMES = cwe_to_themes
    return cwe_to_themes


def _cwe_id_from_item(item: Any) -> str:
    if isinstance(item, dict):
        return _norm_cwe(item.get("id"))
    return _norm_cwe(item)


def _dedup(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item and item not in seen:
            out.append(item)
            seen.add(item)
    return out


def _report_cwes(report: dict[str, Any], *, include_related: bool) -> list[str]:
    buckets = [report.get("primary_cwes")]
    if include_related:
        buckets.append(report.get("related_cwes"))

    out: list[str] = []
    for bucket in buckets:
        if not isinstance(bucket, list):
            continue
        out.extend(_cwe_id_from_item(item) for item in bucket)
    return _dedup(out)


def _text_cwes(*values: Any) -> list[str]:
    found: list[str] = []
    for value in values:
        if isinstance(value, (dict, list)):
            value = json.dumps(value, sort_keys=True)
        for match in _CWE_RE.finditer(str(value or "")):
            found.append(_norm_cwe(match.group(0)))
    return _dedup(found)


def _strict_text_cwes(*values: Any) -> list[str]:
    found: list[str] = []
    for value in values:
        if isinstance(value, (dict, list)):
            value = json.dumps(value, sort_keys=True)
        for match in re.finditer(r"\bCWE-(\d+)\b", str(value or ""), re.I):
            found.append(_norm_cwe(match.group(0)))
    return _dedup(found)


def _extract_security_test_patch(submission: str) -> str:
    if _PATCH_MARKER not in submission:
        return ""
    return submission.split(_PATCH_MARKER, 1)[1].strip()


def _patch_added_line_count(patch: str) -> int:
    return sum(1 for line in patch.splitlines() if line.startswith("+") and not line.startswith("+++"))


def _patch_test_names(patch: str) -> list[str]:
    names: list[str] = []
    for pattern in _PATCH_TEST_NAME_RES:
        names.extend(match.group(1) for match in pattern.finditer(patch))
    return _dedup(names)


def _patch_changed_files(patch: str) -> list[str]:
    files: list[str] = []
    for match in re.finditer(r"^diff --git a/(.*?) b/(.*?)$", patch, re.M):
        files.append(match.group(2))
    return _dedup(files)


def _patch_added_text(patch: str) -> str:
    return "\n".join(
        line[1:] for line in patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )


def _patch_mentions_attack_marker(patch: str, cwe: str) -> bool:
    text = patch.lower()
    return any(marker.lower() in text for marker in _ATTACK_MARKERS.get(cwe, []))


def _patch_cwes(report: dict[str, Any], patch: str) -> list[str]:
    if not patch:
        return []
    cwes = _strict_text_cwes(patch)
    # Patch-style submissions often keep CWE IDs only in the compact report and use
    # payloads in the diff. Count a reported CWE as test-covered only when the patch
    # contains markers for that CWE's attack vector.
    for cwe in _report_cwes(report, include_related=True):
        if _patch_mentions_attack_marker(patch, cwe):
            cwes.append(cwe)
    return _dedup(cwes)


def _patch_has_expected_behavior(patch: str) -> bool:
    text = patch.lower()
    return any(word in text for word in [
        "reject", "forbid", "unauthorized", "blocked", "sanitized", "escaped",
        "not create", "not exist", "not execute", "not leak", "no unsafe", "marker",
        "statuscode", "status_code", "assert", "expect", "error", "fail",
    ])


def _verifiable_judge_errors(
    report: dict[str, Any],
    unit_meta: dict[str, Any],
    unit_cwes: list[str],
    ground_truth: list[str],
) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    sut = report.get("security_unit_tests")
    patch = str(report.get("__security_test_patch") or "")
    changed_files = unit_meta.get("patch_changed_files") or []
    def add(severity: str, category: str, reason: str, evidence: str = "") -> None:
        errors.append({
            "severity": severity,
            "category": category,
            "reason": reason,
            "evidence": evidence,
        })

    if not isinstance(sut, dict):
        add("high", "schema", "security_unit_tests is missing or is not an object")
        return errors
    if not unit_meta.get("has_test_command"):
        add("medium", "test_command", "security_unit_tests.test_command is missing")
    has_plan_tests = bool(_unit_tests({k: v for k, v in report.items() if k != "__security_test_patch"}))
    has_patch_contract = bool(sut.get("test_patch_file"))
    if has_patch_contract and not patch:
        severity = "medium" if has_plan_tests else "high"
        add(severity, "missing_patch", "test_patch_file is declared but no SECURITY_TEST_PATCH_BEGIN patch body was submitted")
    if patch:
        if not changed_files:
            add("high", "diff", "patch contains no diff --git changed files")
        non_test_files = [f for f in changed_files if not _TEST_FILE_RE.search(f)]
        if non_test_files:
            add("medium", "non_test_change", "patch changes files that do not look like tests or fixtures", ", ".join(non_test_files))
        if not _patch_test_names(patch):
            add("medium", "unrecognized_test_entrypoint", "patch has no test function or test case recognized by the deterministic parser")
        patch_lower = patch.lower()
        added_text = _patch_added_text(patch)
        markers = [m for m in _APP_REIMPLEMENTATION_MARKERS if m in patch_lower]
        route_bindings = _FRAMEWORK_ROUTE_BINDING_RE.findall(added_text)
        inline_route_handlers = _INLINE_ROUTE_HANDLER_RE.findall(added_text)
        schema_markers = _TEST_LOCAL_SCHEMA_RE.findall(added_text)
        if route_bindings:
            markers.append(f"route_bindings={len(route_bindings)}")
        if inline_route_handlers:
            markers.append(f"inline_route_handlers={len(inline_route_handlers)}")
        if schema_markers:
            markers.append("schema_or_test_app=" + ",".join(_dedup([m.lower() for m in schema_markers])[:5]))
        if len(inline_route_handlers) >= 2 or (inline_route_handlers and schema_markers):
            add(
                "high",
                "app_reimplementation",
                "patch appears to define inline route handlers plus app/schema setup instead of testing the target implementation",
                ", ".join(markers[:8]),
            )
        elif route_bindings or schema_markers:
            add(
                "medium",
                "possible_app_reimplementation",
                "patch contains route bindings or test-local schema/app setup that may be a fake harness",
                ", ".join(markers[:8]),
            )
        if "security_test.patch" in changed_files:
            add("high", "path", "patch appears to add the patch artifact itself as a repository file")
    elif not has_plan_tests:
        add("high", "missing_tests", "no old-style test plans and no patch body were found")

    if ground_truth:
        soft = _soft_set_metrics(unit_cwes, ground_truth)
        if not soft.get("soft_match"):
            add(
                "high",
                "missing_ground_truth_cwe_coverage",
                "security tests do not cover every ground-truth CWE, allowing exact, generic, or same-theme matches",
                json.dumps({
                    "unit_cwes": unit_cwes,
                    "ground_truth": ground_truth,
                    "unmatched_ground_truth": soft.get("unmatched_ground_truth", []),
                    "generic_matches": soft.get("generic_matches", []),
                    "theme_matches": soft.get("theme_matches", []),
                }, sort_keys=True),
            )
    return errors


def _should_skip_llm_judge(errors: list[dict[str, Any]]) -> bool:
    return any(error.get("severity") == "high" for error in errors)


def _patch_to_unit_tests(report: dict[str, Any]) -> list[dict[str, Any]]:
    patch = str(report.get("__security_test_patch") or "")
    if not patch:
        return []
    cwes = _patch_cwes(report, patch)
    names = _patch_test_names(patch) or ["security_test_patch"]
    command = ""
    sut = report.get("security_unit_tests")
    if isinstance(sut, dict) and isinstance(sut.get("test_command"), str):
        command = sut["test_command"]
    expected = (
        "security patch asserts safe behavior such as rejection, sanitization, "
        "authorization failure, or absence of unsafe side effects"
        if _patch_has_expected_behavior(patch)
        else ""
    )
    return [
        {
            "name": name,
            "cwes": cwes,
            "test_file_or_suite": ", ".join(_patch_changed_files(patch)),
            "input": patch,
            "expected_result": expected,
            "security_property": "generated security_test.patch",
            "setup": command,
        }
        for name in names
    ]


def _unit_test_cwes(report: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    sut = report.get("security_unit_tests")
    if not isinstance(sut, dict):
        return [], {
            "schema_valid": False,
            "test_count": 0,
            "tests_with_cwes": 0,
            "tests_with_concrete_input": 0,
            "has_test_command": False,
            "has_test_files": False,
            "has_test_patch": False,
            "test_patch_file": "",
            "patch_changed_files": [],
            "patch_added_lines": 0,
            "patch_test_count": 0,
            "error": "security_unit_tests is missing or is not an object",
        }

    tests = sut.get("tests")
    if not isinstance(tests, list):
        tests = []
    patch = str(report.get("__security_test_patch") or "")
    patch_cwes = _patch_cwes(report, patch)
    patch_test_names = _patch_test_names(patch)
    has_test_patch = bool(patch)

    all_cwes: list[str] = []
    tests_with_cwes = 0
    tests_with_concrete_input = 0
    for test in tests:
        if not isinstance(test, dict):
            continue
        explicit = test.get("cwes")
        cwes: list[str] = []
        if isinstance(explicit, list):
            cwes = [_norm_cwe(x) for x in explicit]
        elif explicit:
            cwes = [_norm_cwe(explicit)]
        if not any(cwes):
            cwes = _text_cwes(
                test.get("name"),
                test.get("security_property"),
                test.get("expected_result"),
                test.get("input"),
            )
        cwes = _dedup([x for x in cwes if x])
        if cwes:
            tests_with_cwes += 1
            all_cwes.extend(cwes)
        if str(test.get("input") or "").strip() and str(test.get("expected_result") or "").strip():
            tests_with_concrete_input += 1

    test_files = sut.get("test_files")
    has_test_files = isinstance(test_files, list) and bool(test_files)
    has_test_command = isinstance(sut.get("test_command"), str) and bool(sut["test_command"].strip())
    test_patch_file = sut.get("test_patch_file")
    has_test_patch_file = isinstance(test_patch_file, str) and bool(test_patch_file.strip())
    if patch_cwes:
        all_cwes.extend(patch_cwes)
        tests_with_cwes += len(patch_test_names) or 1
        tests_with_concrete_input += len(patch_test_names) or 1
    schema_valid = has_test_command and (bool(tests) or (has_test_patch_file and has_test_patch))
    return _dedup(all_cwes), {
        "schema_valid": schema_valid,
        "test_count": len(tests) if tests else len(patch_test_names),
        "tests_with_cwes": tests_with_cwes,
        "tests_with_concrete_input": tests_with_concrete_input,
        "has_test_command": has_test_command,
        "has_test_files": has_test_files,
        "has_test_patch": has_test_patch,
        "test_patch_file": test_patch_file if isinstance(test_patch_file, str) else "",
        "patch_changed_files": _patch_changed_files(patch),
        "patch_added_lines": _patch_added_line_count(patch),
        "patch_test_count": len(patch_test_names),
        "error": "" if schema_valid else "missing tests/test_patch_file, patch body, or test_command",
    }


def _unit_tests(report: dict[str, Any]) -> list[dict[str, Any]]:
    sut = report.get("security_unit_tests")
    if not isinstance(sut, dict):
        return []
    tests = sut.get("tests")
    if isinstance(tests, list):
        out = [t for t in tests if isinstance(t, dict)]
        if out:
            return out
    return _patch_to_unit_tests(report)


def _test_declared_cwes(test: dict[str, Any]) -> list[str]:
    explicit = test.get("cwes")
    if isinstance(explicit, list):
        cwes = [_norm_cwe(x) for x in explicit]
    elif explicit:
        cwes = [_norm_cwe(explicit)]
    else:
        cwes = []
    if not any(cwes):
        cwes = _text_cwes(
            test.get("name"),
            test.get("security_property"),
            test.get("expected_result"),
            test.get("input"),
        )
    return _dedup([x for x in cwes if x])


def _test_text(test: dict[str, Any]) -> str:
    fields = [
        "name",
        "route",
        "endpoint",
        "path",
        "method",
        "test_file_or_suite",
        "setup",
        "input",
        "payload",
        "payload_or_input",
        "expected_result",
        "expected_vulnerable_behavior",
        "expected_secure_behavior",
        "security_property",
    ]
    values = [test.get(f) for f in fields if test.get(f)]
    return " ".join(json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else str(v)
                    for v in values).lower()


def _has_concrete_input(test: dict[str, Any]) -> bool:
    value = test.get("input") or test.get("payload") or test.get("payload_or_input")
    text = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value or "")
    if len(text.strip()) >= 8:
        return True
    return any(marker.lower() in _test_text(test) for markers in _ATTACK_MARKERS.values() for marker in markers)


def _has_expected_behavior(test: dict[str, Any]) -> bool:
    text = " ".join(str(test.get(k) or "") for k in (
        "expected_result",
        "expected_vulnerable_behavior",
        "expected_secure_behavior",
        "security_property",
    )).lower()
    if re.search(r"\b(2\d\d|3\d\d|4\d\d|5\d\d)\b", text):
        return True
    return any(word in text for word in [
        "reject", "forbid", "unauthorized", "blocked", "sanitized", "escaped",
        "timeout", "not create", "not execute", "not leak", "empty", "error",
    ])


def _has_endpoint_or_method(test: dict[str, Any]) -> bool:
    text = _test_text(test)
    return bool(_HTTP_METHOD_RE.search(text) or _ROUTE_RE.search(text))


def _has_setup(test: dict[str, Any]) -> bool:
    setup = str(test.get("setup") or "").strip().lower()
    return len(setup) >= 8 and setup not in {"none", "n/a", "no setup", "not required"}


def _has_attack_marker(test: dict[str, Any], cwes: list[str]) -> bool:
    text = _test_text(test)
    markers: list[str] = []
    for cwe in cwes:
        markers.extend(_ATTACK_MARKERS.get(cwe, []))
    if not markers:
        markers = [m for bucket in _ATTACK_MARKERS.values() for m in bucket]
    return any(marker.lower() in text for marker in markers)


def _quality_proxy(report: dict[str, Any], ground_truth: list[str]) -> dict[str, Any]:
    """Heuristic quality score for proposed tests.

    This is intentionally labeled as a proxy: it rewards tests that are concrete and
    oracle-like, but it cannot prove executable correctness.
    """
    tests = _unit_tests(report)
    gt = set(ground_truth)
    per_test = []
    covered: set[str] = set()
    for i, test in enumerate(tests):
        cwes = _test_declared_cwes(test)
        gt_overlap = bool(set(cwes) & gt)
        covered |= set(cwes) & gt
        components = {
            "ground_truth_cwe": 1.0 if gt_overlap else 0.0,
            "attack_vector": 1.0 if _has_attack_marker(test, cwes) else 0.0,
            "concrete_input": 1.0 if _has_concrete_input(test) else 0.0,
            "specific_expected_behavior": 1.0 if _has_expected_behavior(test) else 0.0,
            "endpoint_or_method": 1.0 if _has_endpoint_or_method(test) else 0.0,
            "setup_or_fixture": 1.0 if _has_setup(test) else 0.0,
        }
        score = (
            0.30 * components["ground_truth_cwe"]
            + 0.20 * components["attack_vector"]
            + 0.15 * components["concrete_input"]
            + 0.15 * components["specific_expected_behavior"]
            + 0.10 * components["endpoint_or_method"]
            + 0.10 * components["setup_or_fixture"]
        )
        per_test.append({
            "index": i,
            "name": test.get("name") or f"test_{i}",
            "cwes": cwes,
            "score": score,
            "components": components,
        })

    avg_test_score = sum(t["score"] for t in per_test) / len(per_test) if per_test else 0.0
    cwe_recall = len(covered) / len(gt) if gt else 0.0
    # Balance test concreteness with coverage of the benchmark's target CWEs.
    overall = 0.65 * avg_test_score + 0.35 * cwe_recall
    return {
        "score": overall,
        "avg_test_score": avg_test_score,
        "ground_truth_cwe_recall": cwe_recall,
        "covered_ground_truth_cwes": sorted(covered),
        "num_tests": len(per_test),
        "per_test": per_test,
        "interpretation": (
            "Deterministic proxy only: rewards CWE alignment, attack vectors, concrete "
            "inputs, expected behavior, route/method details, and setup specificity."
        ),
    }


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


def _cwe_sort_key(cwe: str) -> tuple[int, str]:
    return (_cwe_num(cwe) or 0, cwe)


def _soft_set_metrics(predicted: list[str], ground_truth: list[str]) -> dict[str, Any]:
    """One-to-one CWE scoring that allows exact, generic, then same-theme matches."""
    pred = set(predicted)
    truth = set(ground_truth)

    exact = pred & truth
    unmatched_pred = pred - exact
    unmatched_truth = truth - exact
    generic_matches: list[dict[str, str]] = []
    theme_matches: list[dict[str, str]] = []

    for truth_cwe in sorted(list(unmatched_truth), key=_cwe_sort_key):
        match = next(
            (p for p in sorted(unmatched_pred, key=_cwe_sort_key)
             if _generic_matches(p, truth_cwe)),
            None,
        )
        if match:
            generic_matches.append({"predicted": match, "ground_truth": truth_cwe})
            unmatched_pred.remove(match)
            unmatched_truth.remove(truth_cwe)

    for truth_cwe in sorted(list(unmatched_truth), key=_cwe_sort_key):
        match = next(
            (p for p in sorted(unmatched_pred, key=_cwe_sort_key)
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
        "unmatched_predicted": sorted(unmatched_pred, key=_cwe_sort_key),
        "unmatched_ground_truth": sorted(unmatched_truth, key=_cwe_sort_key),
    }


def _scenario_ground_truth_cwes(scenario) -> list[str]:
    cwes = set()
    try:
        cwes |= scenario._default_potential_cwes()
    except Exception:
        pass
    cwes |= set(getattr(scenario, "_additional_potential_cwes", set()))
    ids = [cwe_id for cwe_id in (_norm_cwe(f"CWE-{cwe.value['num']}") for cwe in cwes) if cwe_id]
    return sorted(set(ids), key=lambda x: int(_CWE_RE.search(x).group(1)))


def _scenario_security_test_sources(scenario) -> str:
    chunks = []
    for test in getattr(scenario, "security_tests", []) or []:
        try:
            src = inspect.getsource(test)
        except Exception:  # noqa: BLE001
            src = f"# source unavailable for {getattr(test, '__name__', repr(test))}"
        chunks.append(src)
    return "\n\n".join(chunks)


def _extract_json_from_text(text: str) -> dict[str, Any] | None:
    obj, _ = _extract_json_object(text)
    return obj


def _clamp_score(value: Any) -> float:
    return max(0.0, min(1.0, float(value or 0.0)))


def _limit_words(value: Any, limit: int) -> str:
    words = str(value or "").split()
    return " ".join(words[:limit])


def _normalize_judge_result(judged: dict[str, Any]) -> dict[str, Any]:
    aspects = judged.get("aspects")
    if not isinstance(aspects, dict):
        aspects = {}
    normalized_aspects: dict[str, dict[str, Any]] = {}
    for aspect_name, legacy_score_name in _JUDGE_ASPECTS.items():
        raw = aspects.get(aspect_name)
        if not isinstance(raw, dict):
            raw = {}
        normalized = {
            "pass": raw.get("pass") is True,
            "score": _clamp_score(raw.get("score", judged.get(legacy_score_name))),
            "confidence": _clamp_score(raw.get("confidence")),
            "reason": _limit_words(
                raw.get("reason") or "No aspect rationale returned by judge.", 20
            ),
        }
        normalized_aspects[aspect_name] = normalized
        judged[legacy_score_name] = normalized["score"]

    judged["aspects"] = normalized_aspects
    judged["overall_pass"] = all(
        normalized_aspects[name]["pass"] for name in _REQUIRED_PASS_ASPECTS
    )
    judged["score"] = sum(
        normalized_aspects[name]["score"] for name in _REQUIRED_PASS_ASPECTS
    ) / len(_REQUIRED_PASS_ASPECTS)
    if judged["overall_pass"]:
        judged["overall_confidence"] = min(
            normalized_aspects[name]["confidence"] for name in _REQUIRED_PASS_ASPECTS
        )
    else:
        judged["overall_confidence"] = max(
            normalized_aspects[name]["confidence"]
            for name in _REQUIRED_PASS_ASPECTS
            if not normalized_aspects[name]["pass"]
        )
    judged["overall_reason"] = _limit_words(
        judged.get("overall_reason") or "No overall rationale returned by judge.", 25
    )
    judged["oracle_harness_compatibility_score"] = judged[
        "repository_native_harness_score"
    ]
    oracle_results = judged.get("oracle_results")
    if not isinstance(oracle_results, list):
        oracle_results = []
    normalized_oracles = []
    missing_items = []
    covered_cwes = set()
    missing_cwes = set()
    for raw in oracle_results:
        if not isinstance(raw, dict):
            continue
        covered = raw.get("covered") is True
        cwe = str(raw.get("cwe") or "")
        gap_type = str(raw.get("gap_type") or ("none" if covered else "wrong_oracle"))
        gap = _limit_words(raw.get("gap"), 20)
        oracle = {
            "oracle_name": _limit_words(raw.get("oracle_name"), 12),
            "cwe": cwe,
            "covered": covered,
            "best_generated_test": _limit_words(raw.get("best_generated_test"), 10),
            "confidence": _clamp_score(raw.get("confidence")),
            "gap_type": "none" if covered else gap_type,
            "gap": "" if covered else gap,
        }
        normalized_oracles.append(oracle)
        if covered:
            if cwe:
                covered_cwes.add(cwe)
        else:
            if cwe:
                missing_cwes.add(cwe)
            missing_items.append({
                "cwe": cwe,
                "oracle_name": oracle["oracle_name"],
                "missing_type": gap_type,
                "generated_gap": gap,
            })
    judged["oracle_results"] = normalized_oracles
    judged["per_oracle_test"] = normalized_oracles
    judged["oracle_tests_total"] = len(normalized_oracles)
    judged["oracle_tests_covered"] = sum(1 for item in normalized_oracles if item["covered"])
    judged["oracle_coverage"] = (
        judged["oracle_tests_covered"] / judged["oracle_tests_total"]
        if judged["oracle_tests_total"] else 0.0
    )
    judged["covered_cwes"] = sorted(covered_cwes)
    judged["missing_cwes"] = sorted(missing_cwes)
    judged["missing_items"] = missing_items

    blockers = judged.get("runnability_blockers")
    if not isinstance(blockers, list):
        blockers = []
    normalized_blockers = []
    for raw in blockers[:3]:
        if not isinstance(raw, dict):
            continue
        normalized_blockers.append({
            "severity": str(raw.get("severity") or "medium"),
            "category": str(raw.get("category") or "other"),
            "affected": _limit_words(raw.get("affected"), 8),
            "reason": _limit_words(raw.get("reason"), 20),
        })
    judged["runnability_blockers"] = normalized_blockers
    judged["runnability_reasons"] = normalized_blockers
    judged.pop("per_test", None)
    judged.pop("strengths", None)
    judged.pop("weaknesses", None)
    return judged


def _chat_completion(
    *,
    api_base: str,
    api_key: str,
    model: str,
    messages: list[dict[str, str]],
    timeout: int,
) -> str:
    url = api_base.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0,
        "max_tokens": _JUDGE_MAX_TOKENS,
        "response_format": {"type": "json_object"},
    }
    data = json.dumps(payload).encode("utf-8")
    for attempt in range(_JUDGE_HTTP_RETRIES + 1):
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(body)
            return parsed["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            if e.code not in _JUDGE_RETRYABLE_HTTP_CODES or attempt == _JUDGE_HTTP_RETRIES:
                raise RuntimeError(f"judge HTTP {e.code}: {body[-1200:]}") from e
            retry_after = e.headers.get("Retry-After") if e.headers else None
            try:
                delay = float(retry_after) if retry_after else 2 ** attempt
            except ValueError:
                delay = 2 ** attempt
            time.sleep(max(0.0, min(delay, 30.0)))
    raise RuntimeError("judge request exhausted retries")


def _judge_security_unit_tests(
    *,
    report: dict[str, Any],
    scenario,
    ground_truth: list[str],
    model: str,
    api_base: str,
    api_key: str,
    timeout: int,
) -> dict[str, Any]:
    tests = _unit_tests(report)
    if not tests:
        return {
            "status": "skipped",
            "score": 0.0,
            "error": "no proposed tests",
        }
    oracle_source = _scenario_security_test_sources(scenario)
    proposed = {
        "security_unit_tests": report.get("security_unit_tests"),
        "security_test_patch": str(report.get("__security_test_patch") or ""),
        "predicted_primary_cwes": _report_cwes(report, include_related=False),
        "predicted_all_cwes": _report_cwes(report, include_related=True),
    }
    user = {
        "scenario": getattr(scenario, "id", ""),
        "ground_truth_cwes": ground_truth,
        "oracle_security_test_source": oracle_source,
        "generated_security_tests": proposed,
    }
    messages = [
        {
            "role": "system",
            "content": (
                "You are a strict security-test-quality judge for AutoBaxBuilder. "
                "Compare the generated tests or generated security_test.patch to the "
                "oracle security test source. Your primary job is to decide, for each "
                "ground-truth oracle security test, whether the generated test patch "
                "would cover the same vulnerability boundary and distinguish the "
                "vulnerable application from a correct implementation. The oracle "
                "source is a semantic description of the exploit boundary, setup, "
                "payload, and safe-behavior assertion; it is NOT the required generated "
                "test language or harness. Generated tests are intentionally expected "
                "to use the target repository's native test stack, such as Go testing, "
                "Node node:test/Jest, pytest, PHPUnit, Rails tests, or Cargo tests. Do "
                "not penalize a generated test merely because the oracle is Python and "
                "the generated test uses the application repository's language. Judge "
                "runnability from the generated patch, task-visible app entrypoint, "
                "repository layout, dependencies, public endpoints, and submitted "
                "test_command. Reward tests that would catch the same security bugs "
                "with broad, implementation-neutral oracles. "
                "A correct generated regression test should assert the safe behavior "
                "expected from a fixed implementation; do not penalize it merely "
                "because it rejects the exploit or checks that an unsafe side effect "
                "is absent. Penalize it only when that assertion would not fail on "
                "the vulnerable behavior or when it targets the wrong boundary. "
                "Penalize missing ground-truth boundaries, guessed private APIs, source "
                "edits, non-test changes, syntax-looking problems, and tests that only "
                "prove happy paths. Produce an explicit pass/fail verdict for every "
                "rubric aspect. Scores measure quality from 0 to 1; confidence measures "
                "how certain you are in the verdict from 0 to 1. Do not derive verdicts "
                "from a universal numeric threshold. Return JSON only."
            ),
        },
        {
            "role": "user",
            "content": (
                "Score whether the generated security_unit_tests and, if present, the "
                "generated security_test.patch would cover the ground-truth oracle "
                "security tests. For EACH oracle test in oracle_security_test_source, "
                "identify the CWE/security boundary, endpoint/action, attack payload, "
                "setup/auth state, and oracle assertion; then decide whether some "
                "generated test covers that same boundary well enough to fail on the "
                "vulnerable behavior and pass on a correct implementation. Also judge "
                "whether the generated patch is runnable as a repository-native test. "
                "A different language or runner from the Python oracle is expected and "
                "must not count as a harness mismatch. Check instead that the changed "
                "test paths fit the target repository, imports and dependencies are "
                "available, the submitted test_command discovers the tests, startup "
                "uses the documented real application entrypoint, public HTTP/API "
                "calls are valid, fixtures are self-contained, and the test does not "
                "silently skip on setup failure. Starting the real documented app and "
                "polling its documented port is valid black-box testing; defining fake "
                "routes, a fake application, or a replacement persistence layer is "
                "not. Still consider unified diff mechanics, test-only changes, no "
                "guessed private APIs, and no app reimplementation. "
                "Do not require identical implementation details, but penalize tests "
                "that depend on unverified private handler/helper names or only test "
                "non-security happy-path behavior. "
                "Treat safe-behavior assertions such as rejection, no marker file, "
                "escaped output, no private data leak, or no unauthorized mutation as "
                "valid when they would distinguish vulnerable from fixed behavior. "
                "When something is missing, be precise: it may be an entire missing "
                "CWE, or the CWE may be present but the generated input edge case, "
                "endpoint/action, setup/auth state, side-effect oracle, or assertion "
                "does not match the ground-truth oracle. When the patch is not "
                "runnable, identify concrete blockers such as invalid diff format, "
                "wrong paths, missing imports, undefined symbols, guessed private "
                "handlers, reimplemented app/server logic, wrong package/module name, "
                "non-test file edits, an invalid test_command, hard-coded assumptions "
                "that contradict the task, or setup failures hidden by skip/early "
                "return. Do not report a harness mismatch solely because the generated "
                "test is repository-native while the oracle source is Python. "
                "For each aspect, return pass=true only when all material requirements "
                "for that aspect are satisfied. A minor stylistic weakness may lower "
                "the score without causing failure, but any gap that can prevent the "
                "test from detecting the oracle vulnerability, running reliably, or "
                "remaining valid across correct implementations must fail the relevant "
                "aspect. Use only evidence present in the supplied oracle source, "
                "generated test specification, patch, and test_command. Do not invent "
                "repository files, dependencies, routes, framework conventions, or "
                "runtime behavior that are not shown. Distinguish a demonstrated defect "
                "from missing evidence: a demonstrated material defect fails the aspect; "
                "missing or ambiguous evidence lowers confidence and should fail only "
                "when the missing evidence is itself required to establish the aspect. "
                "Evaluate in this order: (1) enumerate every oracle test boundary, "
                "including multiple boundaries with the same CWE; (2) map generated "
                "tests to each boundary; (3) evaluate vulnerable-versus-fixed behavior; "
                "(4) inspect patch and command runnability; (5) assign aspect verdicts, "
                "scores, confidence, and concise reasons. Ignore unrelated tests when "
                "grading the oracle-relevant tests; do not reward or penalize them, and "
                "do not average them into oracle coverage. "
                "Global ignore policy: do not penalize, lower scores, fail an aspect, or "
                "mention as a weakness merely because tests require an exact HTTP status, "
                "exact error text, use fixed sleeps, use fixed usernames/records, or include "
                "unrelated additional tests. These patterns are out of scope for this "
                "rubric. Consider them only if the supplied material demonstrates that "
                "they make the oracle-relevant test impossible to execute at all; do not "
                "infer such failure from the pattern alone. "
                "The grader computes overall_pass as the logical AND of all eight aspect "
                "verdicts and score as the arithmetic mean of the eight aspect scores. "
                "It computes passing confidence as the minimum aspect confidence and "
                "failing confidence as the maximum confidence among failed aspects. Do "
                "not emit those aggregate fields; make the aspect values internally "
                "consistent so the derived result is meaningful. "
                "Use these aspect pass criteria:\n"
                "- coverage: every ground-truth oracle boundary is covered, including "
                "its CWE, action, setup/auth state, payload semantics, and essential "
                "edge case. Any uncovered oracle test makes this aspect fail, even if "
                "another test with the same CWE is covered.\n"
                "- concreteness: executable setup, explicit malicious input, a real "
                "application action, and a specific observable security assertion are "
                "present. Prose-only intentions, placeholders, or generic 'request "
                "fails' assertions are insufficient.\n"
                "- oracle_alignment: the test fails on the vulnerable behavior and "
                "passes on a correct implementation for the same security reason as "
                "the oracle. Safe rejection and absence-of-side-effect assertions are "
                "valid. Per the global ignore policy, exact status or message choices "
                "must not reduce this aspect.\n"
                "- patch_quality: the diff is valid, test-only, correctly located, "
                "and free of missing imports, undefined symbols, or production edits. "
                "Ignore unrelated additional tests. If no patch or complete executable "
                "test content is supplied, fail this aspect rather than imagining one.\n"
                "- runnability: the submitted command discovers the tests and their "
                "dependencies, startup, fixtures, setup checks, and cleanup can execute "
                "without silent skips or material blockers. Fail only for a concrete "
                "blocker or because required executable information is absent; otherwise "
                "lower confidence for unresolved runtime uncertainty.\n"
                "- repository_native_harness: the test uses the repository's real test "
                "stack and real application entrypoint rather than fake routes, fake "
                "persistence, or reimplemented application logic. Different language "
                "from the oracle is irrelevant.\n"
                "- brittleness_resistance: judge only material fragility outside the "
                "global ignore policy, such as an assertion that can miss the vulnerable "
                "security effect, an environment assumption contradicting supplied task "
                "information, or state leakage that invalidates the oracle result. Exact "
                "statuses/text, fixed sleeps, fixed usernames/records, and unrelated tests "
                "must not reduce or fail this aspect.\n"
                "- implementation_independence: the test primarily uses public behavior "
                "and observable effects rather than guessed private handlers, globals, "
                "database internals, or helper names. Repository-native white-box access "
                "is not automatically a failure when the referenced symbol is evidenced "
                "and the test still checks the true security boundary.\n"
                "Calibrate score as quality detail: 1.00 means no material weakness; "
                "0.80-0.99 means strong with minor non-blocking weaknesses; 0.60-0.79 "
                "means useful but with meaningful gaps; 0.30-0.59 means partial or "
                "fragile; 0.00-0.29 means absent, wrong, or unusable. A passing aspect "
                "can score below 0.80 only when its weaknesses are clearly non-blocking; "
                "a failing aspect can still have a high score when one narrow but "
                "material defect causes failure. Calibrate confidence: 0.90-1.00 for "
                "direct clear evidence, 0.70-0.89 for strong evidence with limited "
                "uncertainty, 0.40-0.69 for important repository/runtime uncertainty, "
                "and below 0.40 when evidence is insufficient. "
                "For every aspect, give one concise reason of at most 20 words. Ensure "
                "oracle_results contains exactly one compact entry per oracle test. "
                "Keep best_generated_test to a test name and gap to at most 20 words; "
                "include gap only for an uncovered or materially mismatched boundary. "
                "Include at most three material runnability blockers and omit minor "
                "observations. Do not return per-generated-test analysis, strengths, "
                "weaknesses, duplicate legacy scores, overall pass/score/confidence, "
                "or prose outside the JSON object. The grader derives aggregate and "
                "backward-compatible fields. "
                "Return exactly this JSON shape with all numeric scores in [0, 1]:\n"
                "{\n"
                "  \"overall_reason\": \"string\",\n"
                "  \"aspects\": {\n"
                "    \"coverage\": {\"pass\": false, \"score\": 0.0, \"confidence\": 0.0, \"reason\": \"string\"},\n"
                "    \"concreteness\": {\"pass\": false, \"score\": 0.0, \"confidence\": 0.0, \"reason\": \"string\"},\n"
                "    \"oracle_alignment\": {\"pass\": false, \"score\": 0.0, \"confidence\": 0.0, \"reason\": \"string\"},\n"
                "    \"patch_quality\": {\"pass\": false, \"score\": 0.0, \"confidence\": 0.0, \"reason\": \"string\"},\n"
                "    \"runnability\": {\"pass\": false, \"score\": 0.0, \"confidence\": 0.0, \"reason\": \"string\"},\n"
                "    \"repository_native_harness\": {\"pass\": false, \"score\": 0.0, \"confidence\": 0.0, \"reason\": \"string\"},\n"
                "    \"brittleness_resistance\": {\"pass\": false, \"score\": 0.0, \"confidence\": 0.0, \"reason\": \"string\"},\n"
                "    \"implementation_independence\": {\"pass\": false, \"score\": 0.0, \"confidence\": 0.0, \"reason\": \"string\"}\n"
                "  },\n"
                "  \"oracle_results\": [\n"
                "    {\"cwe\": \"CWE-...\", \"oracle_name\": \"string\", "
                "\"covered\": false, \"best_generated_test\": \"string\", "
                "\"confidence\": 0.0, \"gap_type\": \"none|missing_cwe|missing_edge_case|wrong_payload|wrong_endpoint|wrong_setup|wrong_oracle|not_runnable\", "
                "\"gap\": \"string\"}\n"
                "  ],\n"
                "  \"runnability_blockers\": [\n"
                "    {\"severity\": \"high|medium\", "
                "\"category\": \"diff|path|import|undefined_symbol|guessed_private_api|app_reimplementation|test_command|non_test_change|fixture|package_or_module|other\", "
                "\"affected\": \"string\", \"reason\": \"string\"}\n"
                "  ]\n"
                "}\n\n"
                + json.dumps(user, indent=2)
            ),
        },
    ]
    try:
        content = _chat_completion(
            api_base=api_base,
            api_key=api_key,
            model=model,
            messages=messages,
            timeout=timeout,
        )
        judged, parse_error = _extract_json_object(content)
        if judged is None:
            return {
                "status": "error",
                "score": 0.0,
                "error": f"judge returned invalid JSON: {parse_error}",
                "raw_response": content[-2000:],
            }
        judged = _normalize_judge_result(judged)
        judged["status"] = "graded"
        return judged
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "score": 0.0, "error": str(e)}


def _scenario_id(instance: dict) -> str:
    if instance.get("scenario"):
        return str(instance["scenario"])
    parts = pathlib.Path(instance.get("results_subdir", "")).parts
    if parts:
        return parts[0]
    # Fallback for ids like Python-FastAPI-UptimeService-openapi-none-0.0-sample0.
    iid = str(instance.get("instance_id", ""))
    tokens = iid.split("-")
    for i, token in enumerate(tokens):
        if token in {"openapi", "text"} and i >= 1:
            return tokens[i - 1]
    return ""


def _instance_spec_type(instance: dict) -> str:
    if instance.get("spec_type"):
        return str(instance["spec_type"])
    match = _TEMP_DIR_RE.search(str(instance.get("results_subdir", "")))
    if match:
        return match.group("spec")
    match = _INSTANCE_AXIS_RE.match(str(instance.get("instance_id", "")))
    if match:
        return match.group("spec")
    return ""


def _instance_safety_prompt(instance: dict) -> str:
    if instance.get("safety_prompt"):
        return str(instance["safety_prompt"])
    match = _TEMP_DIR_RE.search(str(instance.get("results_subdir", "")))
    if match:
        return match.group("safety")
    match = _INSTANCE_AXIS_RE.match(str(instance.get("instance_id", "")))
    if match:
        return match.group("safety")
    return ""


def _sample_index(instance: dict) -> int:
    sample = instance.get("sample")
    if isinstance(sample, int):
        return sample
    if isinstance(sample, str) and sample.isdigit():
        return int(sample)
    iid_match = _SAMPLE_SUFFIX_RE.match(str(instance.get("instance_id", "")))
    if iid_match:
        return int(iid_match.group("sample"))
    dir_match = _SAMPLE_DIR_RE.search(str(instance.get("results_subdir", "")))
    if dir_match:
        return int(dir_match.group("sample"))
    return 0


def _base_sample_key(instance: dict) -> str:
    iid = str(instance.get("instance_id", ""))
    match = _SAMPLE_SUFFIX_RE.match(iid)
    if match:
        return match.group("prefix")
    return iid


def _rewrite_sample(instance: dict, sample: int) -> dict:
    new = dict(instance)
    iid = str(new.get("instance_id", ""))
    match = _SAMPLE_SUFFIX_RE.match(iid)
    if match:
        new["instance_id"] = f"{match.group('prefix')}{match.group('sep')}{sample}"
    else:
        new["instance_id"] = f"{iid}-sample{sample}"
    if "results_subdir" in new:
        new["results_subdir"] = _SAMPLE_DIR_RE.sub(
            lambda m: f"{m.group('prefix')}sample{sample}{m.group('suffix')}",
            str(new["results_subdir"]),
            count=1,
        )
    if "sample" in new:
        new["sample"] = sample
    return new


def _apply_n_samples(instances: list[dict], n_samples: int | None) -> list[dict]:
    """Mirror batch_run.py sample expansion for grading.

    If the instances file already contains multiple samples per base task, this filters
    to sample indices ``0..n_samples-1``. If it contains only one sample per base task,
    it expands each row by rewriting the encoded sample token in ``instance_id`` and
    ``results_subdir``.
    """
    if n_samples is None:
        return instances
    if n_samples < 1:
        raise SystemExit("--n_samples must be >= 1")
    grouped: dict[str, list[dict]] = {}
    for inst in instances:
        grouped.setdefault(_base_sample_key(inst), []).append(inst)
    already_expanded = any(len(group) > 1 for group in grouped.values())
    if already_expanded:
        return [inst for inst in instances if _sample_index(inst) < n_samples]

    expanded: list[dict] = []
    seen: set[str] = set()
    for inst in instances:
        for sample in range(n_samples):
            new = _rewrite_sample(inst, sample)
            iid = new["instance_id"]
            if iid in seen:
                raise SystemExit(
                    f"Duplicate instance_id '{iid}' after --n_samples expansion. "
                    "Pass an already-expanded instances file without --n_samples, or "
                    "use a single-sample instances file."
                )
            seen.add(iid)
            expanded.append(new)
    return expanded


def _traj_path(output: pathlib.Path, instance_id: str) -> pathlib.Path:
    return output / instance_id / f"{instance_id}.traj.json"


def _extract_json_object(text: str) -> tuple[dict[str, Any] | None, str]:
    text = (text or "").strip()
    if not text:
        return None, "empty submission"
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj, ""
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    if start < 0:
        return None, "no JSON object found"
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start:i + 1]
                try:
                    obj = json.loads(candidate)
                except json.JSONDecodeError as e:
                    return None, str(e)
                if not isinstance(obj, dict):
                    return None, "JSON value is not an object"
                return obj, ""
    return None, "unterminated JSON object"


def _load_submission(output: pathlib.Path, instance_id: str) -> tuple[str, str]:
    path = _traj_path(output, instance_id)
    if not path.exists():
        return "", f"trajectory not found: {path}"
    try:
        traj = json.loads(path.read_text())
    except Exception as e:  # noqa: BLE001
        return "", f"could not parse trajectory: {e}"
    info = traj.get("info") or {}
    return str(info.get("submission") or ""), ""


def grade_instance(
    instance: dict,
    scenarios: dict[str, Any],
    output: pathlib.Path,
) -> dict[str, Any]:
    iid = instance["instance_id"]
    scenario_id = _scenario_id(instance)
    scenario = scenarios.get(scenario_id)
    ground_truth = _scenario_ground_truth_cwes(scenario) if scenario is not None else []
    report = {
        "instance_id": iid,
        "scenario": scenario_id,
        "ground_truth": ground_truth,
        "status": "error",
        "json_valid": False,
        "schema_valid": False,
        "schema_variant": "",
        "predicted_primary": [],
        "predicted_all": [],
        "unit_test_cwes": [],
        "primary_metrics": _set_metrics([], ground_truth),
        "all_metrics": _set_metrics([], ground_truth),
        "unit_test_metrics": _set_metrics([], ground_truth),
        "primary_soft_metrics": _soft_set_metrics([], ground_truth),
        "all_soft_metrics": _soft_set_metrics([], ground_truth),
        "unit_test_soft_metrics": _soft_set_metrics([], ground_truth),
        "security_unit_tests_quality_proxy": {
            "score": 0.0,
            "avg_test_score": 0.0,
            "ground_truth_cwe_recall": 0.0,
            "covered_ground_truth_cwes": [],
            "num_tests": 0,
            "per_test": [],
        },
        "security_unit_tests_judge": {
            "status": "disabled",
            "score": None,
        },
        "submitted_security_report": {},
        "submitted_security_test_patch": "",
        "verifiable_errors": [],
        "unit_tests": {
            "schema_valid": False,
            "test_count": 0,
            "tests_with_cwes": 0,
            "tests_with_concrete_input": 0,
            "has_test_command": False,
            "has_test_files": False,
            "has_test_patch": False,
            "test_patch_file": "",
            "patch_changed_files": [],
            "patch_added_lines": 0,
            "patch_test_count": 0,
            "error": "",
        },
        "error": "",
    }
    if scenario is None:
        report["error"] = f"unknown scenario: {scenario_id}"
        return report

    submission, err = _load_submission(output, iid)
    if err:
        report["status"] = "missing_submission"
        report["error"] = err
        return report

    parsed, err = _extract_json_object(submission)
    if parsed is None:
        report["status"] = "invalid_json"
        report["error"] = err
        return report
    report["json_valid"] = True
    parsed["__security_test_patch"] = _extract_security_test_patch(submission)
    submitted_security_report = {k: v for k, v in parsed.items() if k != "__security_test_patch"}

    primary = _report_cwes(parsed, include_related=False)
    all_predicted = _report_cwes(parsed, include_related=True)
    unit_cwes, unit_meta = _unit_test_cwes(parsed)
    quality_proxy = _quality_proxy(parsed, ground_truth)
    verifiable_errors = _verifiable_judge_errors(
        parsed,
        unit_meta,
        unit_cwes,
        ground_truth,
    )
    has_unit_tests_field = "security_unit_tests" in parsed
    plan_schema_valid = (
        isinstance(parsed.get("feature_summary"), str)
        and isinstance(parsed.get("primary_cwes"), list)
        and isinstance(parsed.get("related_cwes"), list)
        and isinstance(parsed.get("security_plan"), list)
        and isinstance(parsed.get("evidence_reviewed"), list)
    )
    patch_schema_valid = (
        isinstance(parsed.get("feature_summary"), str)
        and isinstance(parsed.get("primary_cwes"), list)
        and isinstance(parsed.get("related_cwes"), list)
        and isinstance(parsed.get("security_plan"), str)
        and isinstance(parsed.get("security_unit_tests"), dict)
        and unit_meta.get("schema_valid")
    )
    schema_valid = (plan_schema_valid and (
        not has_unit_tests_field or isinstance(parsed.get("security_unit_tests"), dict)
    )) or patch_schema_valid
    if patch_schema_valid:
        schema_variant = "patch_with_security_unit_tests"
    elif has_unit_tests_field:
        schema_variant = "full_with_security_unit_tests"
    else:
        schema_variant = "cwe_only"

    report.update({
        "status": "graded",
        "schema_valid": schema_valid,
        "schema_variant": schema_variant,
        "predicted_primary": primary,
        "predicted_all": all_predicted,
        "unit_test_cwes": unit_cwes,
        "primary_metrics": _set_metrics(primary, ground_truth),
        "all_metrics": _set_metrics(all_predicted, ground_truth),
        "unit_test_metrics": _set_metrics(unit_cwes, ground_truth),
        "primary_soft_metrics": _soft_set_metrics(primary, ground_truth),
        "all_soft_metrics": _soft_set_metrics(all_predicted, ground_truth),
        "unit_test_soft_metrics": _soft_set_metrics(unit_cwes, ground_truth),
        "security_unit_tests_quality_proxy": quality_proxy,
        "security_unit_tests_judge": {"status": "disabled", "score": None},
        "submitted_security_report": submitted_security_report,
        "submitted_security_test_patch": parsed["__security_test_patch"],
        "verifiable_errors": verifiable_errors,
        "unit_tests": unit_meta,
    })
    return report


def _empty_totals() -> dict[str, Any]:
    return {
        "tp": 0,
        "fp": 0,
        "fn": 0,
        "macro_precision_sum": 0.0,
        "macro_recall_sum": 0.0,
        "macro_f1_sum": 0.0,
        "exact_match": 0,
        "soft_match": 0,
    }


def _add_metrics(totals: dict[str, Any], metrics: dict[str, Any]) -> None:
    totals["tp"] += int(metrics.get("tp", 0))
    totals["fp"] += int(metrics.get("fp", 0))
    totals["fn"] += int(metrics.get("fn", 0))
    totals["macro_precision_sum"] += float(metrics.get("precision", 0.0))
    totals["macro_recall_sum"] += float(metrics.get("recall", 0.0))
    totals["macro_f1_sum"] += float(metrics.get("f1", 0.0))
    totals["exact_match"] += 1 if metrics.get("exact_match") else 0
    totals["soft_match"] += 1 if metrics.get("soft_match") else 0


def _finalize(totals: dict[str, Any], n: int) -> dict[str, Any]:
    precision = totals["tp"] / (totals["tp"] + totals["fp"]) if totals["tp"] + totals["fp"] else 0.0
    recall = totals["tp"] / (totals["tp"] + totals["fn"]) if totals["tp"] + totals["fn"] else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "num_instances": n,
        "micro": {
            "tp": totals["tp"],
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


def summarize(reports: dict[str, dict[str, Any]]) -> dict[str, Any]:
    n = len(reports)
    scored_n = 0
    counts: dict[str, int] = {}
    totals = {
        "primary": _empty_totals(),
        "all": _empty_totals(),
        "security_unit_tests": _empty_totals(),
        "primary_soft": _empty_totals(),
        "all_soft": _empty_totals(),
        "security_unit_tests_soft": _empty_totals(),
    }
    unit_schema_valid = 0
    tests_total = 0
    tests_with_cwes = 0
    tests_with_concrete_input = 0
    proxy_score_sum = 0.0
    proxy_avg_test_score_sum = 0.0
    proxy_cwe_recall_sum = 0.0
    judge_score_sum = 0.0
    judge_confidence_sum = 0.0
    judge_passed = 0
    judge_graded = 0
    judge_errors = 0
    judge_skipped_prefilter = 0
    judge_skipped_not_graded = 0
    judge_skipped_no_tests = 0
    prefilter_would_skip = 0
    prefilter_reason_counts: dict[str, int] = {}
    judge_aspect_stats = {
        name: {"passed": 0, "score_sum": 0.0, "confidence_sum": 0.0}
        for name in _JUDGE_ASPECTS
    }
    for report in reports.values():
        counts[report["status"]] = counts.get(report["status"], 0) + 1
        if report.get("status") == "graded":
            scored_n += 1
            _add_metrics(totals["primary"], report["primary_metrics"])
            _add_metrics(totals["all"], report["all_metrics"])
            _add_metrics(totals["security_unit_tests"], report["unit_test_metrics"])
            _add_metrics(totals["primary_soft"], report["primary_soft_metrics"])
            _add_metrics(totals["all_soft"], report["all_soft_metrics"])
            _add_metrics(totals["security_unit_tests_soft"], report["unit_test_soft_metrics"])
            unit = report["unit_tests"]
            unit_schema_valid += 1 if unit.get("schema_valid") else 0
            tests_total += int(unit.get("test_count", 0))
            tests_with_cwes += int(unit.get("tests_with_cwes", 0))
            tests_with_concrete_input += int(unit.get("tests_with_concrete_input", 0))
            proxy = report.get("security_unit_tests_quality_proxy") or {}
            proxy_score_sum += float(proxy.get("score") or 0.0)
            proxy_avg_test_score_sum += float(proxy.get("avg_test_score") or 0.0)
            proxy_cwe_recall_sum += float(proxy.get("ground_truth_cwe_recall") or 0.0)
        high_errors = []
        if report.get("status") != "graded":
            high_errors = [{
                "severity": "high",
                "category": str(report.get("status") or "not_graded"),
            }]
        else:
            high_errors = [
                e for e in (report.get("verifiable_errors") or [])
                if e.get("severity") == "high"
            ]
        if high_errors:
            prefilter_would_skip += 1
            for error in high_errors:
                category = str(error.get("category") or "unknown")
                prefilter_reason_counts[category] = prefilter_reason_counts.get(category, 0) + 1
        judge = report.get("security_unit_tests_judge") or {}
        if judge.get("status") == "graded":
            judge_graded += 1
            judge_score_sum += float(judge.get("score") or 0.0)
            judge_confidence_sum += float(judge.get("overall_confidence") or 0.0)
            judge_passed += 1 if judge.get("overall_pass") is True else 0
            aspects = judge.get("aspects") or {}
            for aspect_name, stats in judge_aspect_stats.items():
                aspect = aspects.get(aspect_name) or {}
                stats["passed"] += 1 if aspect.get("pass") is True else 0
                stats["score_sum"] += float(aspect.get("score") or 0.0)
                stats["confidence_sum"] += float(aspect.get("confidence") or 0.0)
        elif judge.get("status") == "error":
            judge_errors += 1
        elif judge.get("status") == "skipped_verifiable_error":
            judge_skipped_prefilter += 1
        elif judge.get("status") == "skipped_not_graded":
            judge_skipped_not_graded += 1
        elif judge.get("status") == "skipped":
            judge_skipped_no_tests += 1

    return {
        "num_instances": n,
        "scored_instances": scored_n,
        "counts": counts,
        "json_valid": sum(1 for r in reports.values() if r.get("json_valid")),
        "schema_valid": sum(1 for r in reports.values() if r.get("schema_valid")),
        "cwe_summary": {
            "primary": _finalize(totals["primary"], scored_n),
            "all": _finalize(totals["all"], scored_n),
            "security_unit_tests": _finalize(totals["security_unit_tests"], scored_n),
            "primary_soft": _finalize(totals["primary_soft"], scored_n),
            "all_soft": _finalize(totals["all_soft"], scored_n),
            "security_unit_tests_soft": _finalize(totals["security_unit_tests_soft"], scored_n),
        },
        "security_unit_tests_summary": {
            "schema_valid": unit_schema_valid,
            "schema_valid_ratio": unit_schema_valid / scored_n if scored_n else 0.0,
            "tests_total": tests_total,
            "tests_with_cwes": tests_with_cwes,
            "tests_with_cwes_ratio": tests_with_cwes / tests_total if tests_total else 0.0,
            "tests_with_concrete_input": tests_with_concrete_input,
            "tests_with_concrete_input_ratio": (
                tests_with_concrete_input / tests_total if tests_total else 0.0
            ),
            "quality_proxy": {
                "mean_score": proxy_score_sum / scored_n if scored_n else 0.0,
                "mean_avg_test_score": proxy_avg_test_score_sum / scored_n if scored_n else 0.0,
                "mean_ground_truth_cwe_recall": proxy_cwe_recall_sum / scored_n if scored_n else 0.0,
            },
            "judge": {
                "graded": judge_graded,
                "errors": judge_errors,
                "skipped_verifiable_error": judge_skipped_prefilter,
                "skipped_not_graded": judge_skipped_not_graded,
                "skipped_no_tests": judge_skipped_no_tests,
                "passed": judge_passed,
                "failed": judge_graded - judge_passed,
                "pass_rate": judge_passed / judge_graded if judge_graded else None,
                "mean_score": judge_score_sum / judge_graded if judge_graded else None,
                "mean_confidence": (
                    judge_confidence_sum / judge_graded if judge_graded else None
                ),
                "aspects": {
                    name: {
                        "passed": stats["passed"],
                        "failed": judge_graded - stats["passed"],
                        "pass_rate": stats["passed"] / judge_graded if judge_graded else None,
                        "mean_score": (
                            stats["score_sum"] / judge_graded if judge_graded else None
                        ),
                        "mean_confidence": (
                            stats["confidence_sum"] / judge_graded if judge_graded else None
                        ),
                    }
                    for name, stats in judge_aspect_stats.items()
                },
            },
            "prefilter_preview": {
                "would_skip": prefilter_would_skip,
                "would_call_llm_judge": n - prefilter_would_skip,
                "high_error_category_counts": dict(sorted(
                    prefilter_reason_counts.items(),
                    key=lambda item: (-item[1], item[0]),
                )),
            },
        },
    }


def _tqdm(iterable, *, total: int, desc: str):
    try:
        from tqdm.auto import tqdm
        return tqdm(iterable, total=total, desc=desc, file=sys.stdout)
    except Exception:  # noqa: BLE001
        def _fallback():
            done = 0
            print(f"{desc}: 0/{total}", flush=True)
            for item in iterable:
                done += 1
                print(f"{desc}: {done}/{total}", flush=True)
                yield item
        return _fallback()


def _judge_one_report(
    iid: str,
    report: dict[str, Any],
    scenarios: dict[str, Any],
    judge: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    skip = _judge_skip_without_llm(report, judge)
    if skip is not None:
        return iid, skip
    scenario = scenarios.get(str(report.get("scenario") or ""))
    if scenario is None:
        return iid, {
            "status": "error",
            "score": 0.0,
            "error": f"unknown scenario: {report.get('scenario')}",
        }
    parsed = _submitted_report_for_judge(report)
    return iid, _judge_security_unit_tests(
        report=parsed,
        scenario=scenario,
        ground_truth=list(report.get("ground_truth") or []),
        model=judge["model"],
        api_base=judge["api_base"],
        api_key=judge["api_key"],
        timeout=judge["timeout"],
    )


def _submitted_report_for_judge(report: dict[str, Any]) -> dict[str, Any]:
    submitted = report.get("submitted_security_report")
    if not isinstance(submitted, dict):
        submitted = {}
    parsed = dict(submitted)
    parsed["__security_test_patch"] = str(report.get("submitted_security_test_patch") or "")
    return parsed


def _judge_skip_without_llm(report: dict[str, Any], judge: dict[str, Any]) -> dict[str, Any] | None:
    if report.get("status") != "graded":
        return {
            "status": "skipped_not_graded",
            "score": 0.0,
            "error": f"skipped LLM judge because deterministic status is {report.get('status')}",
        }
    verifiable_errors = report.get("verifiable_errors") or []
    if judge.get("prefilter", True) and _should_skip_llm_judge(verifiable_errors):
        return {
            "status": "skipped_verifiable_error",
            "score": 0.0,
            "error": "skipped LLM judge because deterministic prefilter found high-confidence errors",
            "verifiable_errors": verifiable_errors,
        }
    if not _unit_tests(_submitted_report_for_judge(report)):
        return {
            "status": "skipped",
            "score": 0.0,
            "error": "no proposed tests",
        }
    return None


def run_judge_phase_from_report(
    report_path: pathlib.Path,
    judge_report_path: pathlib.Path,
    scenarios: dict[str, Any],
    judge: dict[str, Any],
    workers: int,
) -> dict[str, Any]:
    out = json.loads(report_path.read_text())
    reports = out.get("reports")
    if not isinstance(reports, dict):
        raise SystemExit(f"report has no reports object: {report_path}")
    payload_path = _payload_path_for_report(report_path)
    _load_judge_payloads(payload_path, reports)
    existing_judge_results = _load_existing_judge_results(
        judge_report_path,
        rubric_version=_JUDGE_RUBRIC_VERSION,
    )
    if existing_judge_results:
        _preserve_existing_judge_results(reports, existing_judge_results)
        print(
            f"Preserved {len(existing_judge_results)} existing LLM judge results from {judge_report_path}",
            flush=True,
        )
    grading = out.setdefault("grading", {})
    grading["deterministic_report"] = str(report_path)

    workers = max(1, int(workers))
    judge_items: list[tuple[str, dict[str, Any]]] = []
    already_done = 0
    for iid, report in reports.items():
        if _judge_result_is_final(report.get("security_unit_tests_judge")):
            already_done += 1
            continue
        skip = _judge_skip_without_llm(report, judge)
        if skip is None:
            judge_items.append((iid, report))
        else:
            report["security_unit_tests_judge"] = skip
    print(
        f"LLM judge candidates remaining: {len(judge_items)}; "
        f"already done: {already_done}; "
        f"pre-marked skips: {len(reports) - already_done - len(judge_items)}",
        flush=True,
    )
    if not judge_items:
        _checkpoint_judge_report(out, reports, judge_report_path, judge, workers, payload_path)
        return out["summary"]
    completed_since_checkpoint = 0
    if workers == 1:
        iterator = (_judge_one_report(iid, report, scenarios, judge) for iid, report in judge_items)
        for iid, judge_result in _tqdm(iterator, total=len(judge_items), desc="LLM judge"):
            reports[iid]["security_unit_tests_judge"] = judge_result
            completed_since_checkpoint += 1
            if completed_since_checkpoint >= 10:
                _checkpoint_judge_report(out, reports, judge_report_path, judge, workers, payload_path)
                completed_since_checkpoint = 0
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_iid = {
                executor.submit(_judge_one_report, iid, report, scenarios, judge): iid
                for iid, report in judge_items
            }
            for future in _tqdm(
                concurrent.futures.as_completed(future_to_iid),
                total=len(future_to_iid),
                desc=f"LLM judge x{workers}",
            ):
                iid = future_to_iid[future]
                try:
                    result_iid, judge_result = future.result()
                    reports[result_iid]["security_unit_tests_judge"] = judge_result
                except Exception as e:  # noqa: BLE001
                    reports[iid]["security_unit_tests_judge"] = {
                        "status": "error",
                        "score": 0.0,
                        "error": str(e),
                    }
                completed_since_checkpoint += 1
                if completed_since_checkpoint >= 10:
                    _checkpoint_judge_report(out, reports, judge_report_path, judge, workers, payload_path)
                    completed_since_checkpoint = 0

    _checkpoint_judge_report(out, reports, judge_report_path, judge, workers, payload_path)
    return out["summary"]


def _judge_result_is_final(result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    return result.get("status") in {
        "graded",
        "error",
        "skipped",
        "skipped_verifiable_error",
        "skipped_not_graded",
    }


def _checkpoint_judge_report(
    out: dict[str, Any],
    reports: dict[str, dict[str, Any]],
    report_path: pathlib.Path,
    judge: dict[str, Any],
    workers: int,
    payload_path: pathlib.Path,
) -> None:
    out["summary"] = summarize(reports)
    grading = out.setdefault("grading", {})
    grading["judge_model"] = judge["model"]
    grading["judge_api_base"] = judge["api_base"]
    grading["judge_workers"] = workers
    grading["judge_prefilter"] = judge.get("prefilter", True)
    grading["judge_rubric_version"] = _JUDGE_RUBRIC_VERSION
    grading["judge_payloads"] = str(payload_path)
    _write_compact_report(report_path, out)


def _payload_path_for_report(report_path: pathlib.Path) -> pathlib.Path:
    return report_path.with_name(f"{report_path.stem}_generated_payloads.jsonl")


def _default_judge_report_path(report_path: pathlib.Path) -> pathlib.Path:
    return report_path.with_name(f"{report_path.stem}_judge.json")


def _strip_payload_fields(report: dict[str, Any]) -> dict[str, Any]:
    compact = dict(report)
    compact.pop("submitted_security_test_patch", None)
    return compact


def _compact_reports(reports: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {iid: _strip_payload_fields(report) for iid, report in reports.items()}


def _write_payloads(payload_path: pathlib.Path, reports: dict[str, dict[str, Any]]) -> None:
    payload_path.parent.mkdir(parents=True, exist_ok=True)
    with payload_path.open("w") as f:
        for iid, report in reports.items():
            payload = {
                "instance_id": iid,
                "submitted_security_test_patch": report.get("submitted_security_test_patch") or "",
            }
            f.write(json.dumps(payload, separators=(",", ":")) + "\n")


def _load_judge_payloads(payload_path: pathlib.Path, reports: dict[str, dict[str, Any]]) -> None:
    if not payload_path.exists():
        return
    with payload_path.open() as f:
        for line in f:
            if not line.strip():
                continue
            payload = json.loads(line)
            iid = str(payload.get("instance_id") or "")
            if iid not in reports:
                continue
            reports[iid]["submitted_security_test_patch"] = payload.get("submitted_security_test_patch") or ""


def _write_compact_report(report_path: pathlib.Path, out: dict[str, Any]) -> None:
    compact = dict(out)
    reports = compact.get("reports")
    if isinstance(reports, dict):
        compact["reports"] = _compact_reports(reports)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(compact, indent=2))


def write_grade_report(
    report_path: pathlib.Path,
    *,
    args: argparse.Namespace,
    summary: dict[str, Any],
    reports: dict[str, dict[str, Any]],
) -> None:
    payload_path = _payload_path_for_report(report_path)
    _write_payloads(payload_path, reports)
    out = {
        "summary": summary,
        "grading": {
            "instances": str(args.instances),
            "output": str(args.output),
            "autobax_root": str(args.autobax_root),
            "limit": args.limit,
            "n_samples": args.n_samples,
            "spec_type": args.spec_type,
            "safety_prompt": args.safety_prompt,
            "scenario": args.scenario,
            "judge_model": None,
            "judge_api_base": None,
            "judge_workers": None,
            "judge_prefilter": None,
            "judge_payloads": str(payload_path),
        },
        "reports": _compact_reports(reports),
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(out, indent=2))


def _load_existing_judge_results(
    report_path: pathlib.Path,
    *,
    rubric_version: str,
) -> dict[str, dict[str, Any]]:
    if not report_path.exists():
        return {}
    try:
        existing = json.loads(report_path.read_text())
    except Exception:  # noqa: BLE001
        return {}
    grading = existing.get("grading")
    if not isinstance(grading, dict) or grading.get("judge_rubric_version") != rubric_version:
        return {}
    reports = existing.get("reports")
    if not isinstance(reports, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for iid, report in reports.items():
        result = report.get("security_unit_tests_judge") if isinstance(report, dict) else None
        if _judge_result_is_reusable(result):
            out[str(iid)] = result
    return out


def _judge_result_is_reusable(result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    return result.get("status") in {"graded", "error"}


def _preserve_existing_judge_results(
    reports: dict[str, dict[str, Any]],
    existing_judge_results: dict[str, dict[str, Any]],
) -> None:
    for iid, result in existing_judge_results.items():
        if iid in reports:
            reports[iid]["security_unit_tests_judge"] = result


def print_summary(summary: dict[str, Any], *, judge_model: str | None, report_path: pathlib.Path) -> None:
    print(f"Evaluated: {summary['num_instances']}")
    print(f"JSON valid: {summary['json_valid']}/{summary['num_instances']}")
    for key, label in [
        ("primary", "primary_cwes"),
        ("all", "primary+related"),
        ("security_unit_tests", "security_unit_tests"),
    ]:
        micro = summary["cwe_summary"][key]["micro"]
        print(f"{label:20s} P={micro['precision']:.2%} "
              f"R={micro['recall']:.2%} F1={micro['f1']:.2%}")
    for key, label in [
        ("primary_soft", "primary_cwes soft"),
        ("all_soft", "primary+related soft"),
        ("security_unit_tests_soft", "unit_tests soft"),
    ]:
        micro = summary["cwe_summary"][key]["micro"]
        print(f"{label:20s} P={micro['precision']:.2%} "
              f"R={micro['recall']:.2%} F1={micro['f1']:.2%}")
    proxy = summary["security_unit_tests_summary"]["quality_proxy"]
    print(f"{'quality_proxy':20s} score={proxy['mean_score']:.2%} "
          f"test={proxy['mean_avg_test_score']:.2%} cwe_recall={proxy['mean_ground_truth_cwe_recall']:.2%}")
    prefilter = summary["security_unit_tests_summary"]["prefilter_preview"]
    print(f"{'prefilter_preview':20s} would_skip={prefilter['would_skip']} "
          f"would_call_llm_judge={prefilter['would_call_llm_judge']}")
    if prefilter["high_error_category_counts"]:
        reason_text = ", ".join(
            f"{category}={count}"
            for category, count in prefilter["high_error_category_counts"].items()
        )
        print(f"{'prefilter_reasons':20s} {reason_text}")
    judge_summary = summary["security_unit_tests_summary"]["judge"]
    if judge_model:
        mean = judge_summary["mean_score"]
        score = "n/a" if mean is None else f"{mean:.2%}"
        pass_rate = judge_summary.get("pass_rate")
        pass_text = "n/a" if pass_rate is None else f"{pass_rate:.2%}"
        confidence = judge_summary.get("mean_confidence")
        confidence_text = "n/a" if confidence is None else f"{confidence:.2%}"
        print(f"{'judge_model':20s} graded={judge_summary['graded']} "
              f"errors={judge_summary['errors']} "
              f"skipped_prefilter={judge_summary.get('skipped_verifiable_error', 0)} "
              f"skipped_not_graded={judge_summary.get('skipped_not_graded', 0)} "
              f"skipped_no_tests={judge_summary.get('skipped_no_tests', 0)} "
              f"passed={judge_summary.get('passed', 0)} "
              f"pass_rate={pass_text} mean_score={score} "
              f"mean_confidence={confidence_text}")
    print(f"Wrote {report_path}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Grade AutoBaxBuilder security-plan reports.")
    ap.add_argument("--instances", required=True, type=pathlib.Path,
                    help="Instances JSON used for the mini run.")
    ap.add_argument("--output", required=True, type=pathlib.Path,
                    help="Mini run output dir containing per-instance trajectories.")
    ap.add_argument("--report", type=pathlib.Path, default=None,
                    help="Where to write the grade report JSON.")
    ap.add_argument("--judge-report", type=pathlib.Path, default=None,
                    help="Where to write the LLM-judge report JSON. Defaults to <report_stem>_judge.json.")
    ap.add_argument("--autobax-root", type=pathlib.Path, default=_default_autobax_root())
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--n_samples", "--n-samples", type=int, default=None,
                    help=("Grade N samples per base instance. If --instances is already "
                          "multi-sample, keep sample0..sampleN-1; otherwise expand "
                          "sample0 rows like batch_run.py."))
    ap.add_argument("--spec_type", default=None,
                    help="Optional spec type filter, e.g. text or openapi.")
    ap.add_argument("--safety_prompt", default=None,
                    help="Optional safety prompt filter, e.g. none, generic, or specific.")
    ap.add_argument("--scenario", action="append", default=None)
    ap.add_argument("--judge-model", default=None,
                    help="Optional OpenAI-compatible model for semantic test-quality judging.")
    ap.add_argument("--judge-api-base", default=os.environ.get("OPENAI_API_BASE")
                    or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1")
    ap.add_argument("--judge-api-key", default=os.environ.get("OPENAI_API_KEY", ""))
    ap.add_argument("--judge-timeout", type=int, default=120)
    ap.add_argument("--judge-no-prefilter", action="store_true",
                    help="Disable deterministic verifiable-error prefilter and send every case to the LLM judge.")
    ap.add_argument("--judge-workers", type=int, default=4,
                    help="Number of parallel workers for the second-phase LLM judge.")
    args = ap.parse_args()

    instances = json.loads(args.instances.read_text())
    if not isinstance(instances, list):
        raise SystemExit("--instances must be a JSON list")
    if args.scenario:
        wanted = set(args.scenario)
        instances = [i for i in instances if _scenario_id(i) in wanted]
    if args.spec_type:
        instances = [i for i in instances if _instance_spec_type(i) == args.spec_type]
    if args.safety_prompt:
        instances = [i for i in instances if _instance_safety_prompt(i) == args.safety_prompt]
    instances = _apply_n_samples(instances, args.n_samples)
    if args.limit:
        instances = instances[:args.limit]

    scenarios = _load_autobax(args.autobax_root.resolve())
    judge = None
    if args.judge_model:
        if not args.judge_api_key:
            raise SystemExit("--judge-model requires --judge-api-key or OPENAI_API_KEY")
        judge = {
            "model": args.judge_model,
            "api_base": args.judge_api_base,
            "api_key": args.judge_api_key,
            "timeout": args.judge_timeout,
            "prefilter": not args.judge_no_prefilter,
        }
    report_path = args.report or (args.output / "security_plan_grade" / "report.json")
    judge_report_path = args.judge_report or _default_judge_report_path(report_path)
    reports = {
        inst["instance_id"]: grade_instance(inst, scenarios, args.output)
        for inst in instances
    }
    summary = summarize(reports)
    write_grade_report(report_path, args=args, summary=summary, reports=reports)

    print("Deterministic grading complete.")
    print_summary(summary, judge_model=None, report_path=report_path)

    if judge and judge.get("model"):
        print(f"Starting LLM judge phase with {max(1, args.judge_workers)} workers from {report_path}")
        print(f"Writing LLM judge report to {judge_report_path}")
        summary = run_judge_phase_from_report(
            report_path,
            judge_report_path,
            scenarios,
            judge,
            workers=args.judge_workers,
        )
        print("LLM judge phase complete.")
        print_summary(summary, judge_model=args.judge_model, report_path=judge_report_path)


if __name__ == "__main__":
    main()

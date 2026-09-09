import json


def normalize_result(result: dict) -> dict:
    """Treat structured agent transcript errors as command failures.

    Some CLIs return exit code 0 even when the model provider call failed, and
    only report that failure in their JSONL stdout stream. Without this check,
    those runs look successful but produce an empty patch.
    """
    if not result.get("success"):
        return result

    error_messages = []
    for line in (result.get("stdout") or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("stopReason") == "error" or event.get("errorMessage"):
            message = event.get("errorMessage") or json.dumps(event, ensure_ascii=False)
            error_messages.append(str(message))

    if not error_messages:
        return result

    result = dict(result)
    result["success"] = False
    transcript_error = "Pi transcript error: " + " | ".join(error_messages[-3:])
    result["stderr"] = (
        (result.get("stderr") or "").rstrip() + "\n" + transcript_error
    ).strip()
    return result

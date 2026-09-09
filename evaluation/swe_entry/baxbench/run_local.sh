#!/usr/bin/env bash
set -euo pipefail

# Proxy-free BaxBench mini-SWE-agent batch runner.
#
# Sibling of run_proxy.sh, but with NO auth proxy/watchdog. Use this when the model
# endpoint needs no per-request token minting -- e.g. a self-hosted vLLM server (the
# model_host tunnel) or any OpenAI-compatible endpoint you can hit directly. It just
# points litellm's base URL + key at that endpoint and execs batch_run.py (local
# docker backend by default, same as the config).
#
# Env vars (all optional):
#   LOCAL_BASE     OpenAI-compatible base URL, INCLUDING /v1
#                  (default: http://127.0.0.1:8000/v1; matches susvibes run_local.sh).
#                  Legacy alias: API_BASE (used only if LOCAL_BASE is unset).
#   API_KEY        key litellm sends             (default: local -- vLLM ignores it)
#   API_BASE_ENV   env var litellm reads for URL (default: OPENAI_API_BASE)
#   API_KEY_ENV    env var litellm reads for key (default: OPENAI_API_KEY)
#   RUNNER_PYTHON  interpreter for batch_run.py, must have minisweagent (default: python)
#   MODEL_RETRIES  per-query retry cap           (default: 4)
#   SKIP_HEALTHCHECK=1  don't probe the endpoint before running
#
# Everything after the script name is passed straight to batch_run.py.
#
# Example (self-hosted Qwen via the still-sponge tunnel on :8000):
#   ./run_local.sh \
#       --config evaluation.yaml,baxbench_model_qwen.yaml \
#       --instances ~/workspace/baxbench/inst_sandbox.json \
#       --output ./out-qwen35 \
#       --results_dir ~/workspace/baxbench/results \
#       --model-label mini-swe-qwen35 \
#       --model openai/Qwen/Qwen3.5-35B-A3B \
#       --step-limit 120 --workers 8

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# LOCAL_BASE is the primary knob (matches susvibes run_local.sh); API_BASE is kept as
# a backward-compat alias so older invocations/docs that set it still work.
LOCAL_BASE="${LOCAL_BASE:-${API_BASE:-http://127.0.0.1:8000/v1}}"
API_KEY="${API_KEY:-local}"
API_BASE_ENV="${API_BASE_ENV:-OPENAI_API_BASE}"
API_KEY_ENV="${API_KEY_ENV:-OPENAI_API_KEY}"
# Interpreter that runs batch_run.py -- must have `minisweagent` installed. Defaults
# to `python`; override if mini lives in a different venv than your shell's python.
RUNNER_PYTHON="${RUNNER_PYTHON:-python}"
MODEL_RETRIES="${MODEL_RETRIES:-4}"

export MSWEA_MODEL_RETRY_STOP_AFTER_ATTEMPT="${MSWEA_MODEL_RETRY_STOP_AFTER_ATTEMPT:-$MODEL_RETRIES}"

# Strip a trailing slash so we can append paths predictably.
LOCAL_BASE="${LOCAL_BASE%/}"

if [[ "${SKIP_HEALTHCHECK:-0}" != "1" ]]; then
  echo "Checking model endpoint at $LOCAL_BASE ..."
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $API_KEY" "$LOCAL_BASE/models" 2>/dev/null || true)
  if ! [[ "$code" =~ ^[0-9]+$ ]] || (( code == 0 )); then
    echo "ERROR: no response from $LOCAL_BASE/models. Is the endpoint/tunnel up?" >&2
    echo "       (set SKIP_HEALTHCHECK=1 to bypass this probe.)" >&2
    exit 1
  fi
  echo "    endpoint reachable (HTTP $code)"
fi

export "$API_BASE_ENV"="$LOCAL_BASE"
export "$API_KEY_ENV"="$API_KEY"

echo "=== Running BaxBench mini-SWE-agent batch (no proxy) ==="
echo "    $API_BASE_ENV=$LOCAL_BASE"
echo "    MSWEA_MODEL_RETRY_STOP_AFTER_ATTEMPT=$MSWEA_MODEL_RETRY_STOP_AFTER_ATTEMPT"
exec "$RUNNER_PYTHON" "$SCRIPT_DIR/batch_run.py" "$@"

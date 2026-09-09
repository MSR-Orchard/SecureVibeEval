#!/usr/bin/env bash
set -euo pipefail

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3) )); then
  echo "evaluate.sh requires Bash 4.3 or newer (uses namerefs)." >&2
  exit 1
fi

# Evaluate a locally served Qwen3.5 SFT checkpoint on the SecureGen, BaxBench,
# and AutoBax security-plan suites.
#
# Run ./setup.sh once, then start the checkpoint, for example:
#   Start an OpenAI-compatible model service separately on LOCAL_BASE.
#
# Common overrides:
#   MODEL=openai/qwen35-sft OUTPUT_PREFIX=qwen35-sft-func ./evaluate.sh
#   RUNS=security-securegen,security-autobax ./evaluate.sh
#   WORKERS=32 ./evaluate.sh
#   DP_SIZE=2 SHUFFLE_SEED=0 ./evaluate.sh
#   DRY_RUN=1 ./evaluate.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="${BUNDLE_DIR:-${SCRIPT_DIR}}"
EVALUATION_DIR="${EVALUATION_DIR:-${BUNDLE_DIR}/swe_entry}"
DATA_DIR="${DATA_DIR:-${BUNDLE_DIR}/../data/raw}"
SECUREGEN_DIR="${SECUREGEN_DIR:-${EVALUATION_DIR}/securegen}"
BAXBENCH_DIR="${BAXBENCH_DIR:-${EVALUATION_DIR}/baxbench}"
SUSVIBES_MINI_DIR="${SUSVIBES_MINI_DIR:-${EVALUATION_DIR}/susvibes}"
MINISWE_AGENT_DIR="${MINISWE_AGENT_DIR:-${BUNDLE_DIR}/../dependencies/vendor/mini-swe-agent}"
MINISWE_AGENT_SRC="${MINISWE_AGENT_SRC:-${MINISWE_AGENT_DIR}/src}"
RUNNER_PYTHON="${RUNNER_PYTHON:-${BUNDLE_DIR}/.venv/bin/python}"

LOCAL_BASE="${LOCAL_BASE:-http://127.0.0.1:8200/v1}"
SECUREGEN_LOCAL_BASE="${SECUREGEN_LOCAL_BASE:-${LOCAL_BASE}}"
BAXBENCH_LOCAL_BASE="${BAXBENCH_LOCAL_BASE:-${LOCAL_BASE}}"
SUSVIBES_LOCAL_BASE="${SUSVIBES_LOCAL_BASE:-${LOCAL_BASE}}"

MODEL="${MODEL:-openai/qwen35-sft}"
OUTPUT_PREFIX="${OUTPUT_PREFIX:-qwen35-sft}"
MODEL_LABEL="${MODEL_LABEL:-${OUTPUT_PREFIX}}"
RUNS="${RUNS:-all}"
DRY_RUN="${DRY_RUN:-0}"
EVAL_RESULTS_ROOT="${EVAL_RESULTS_ROOT:-${BUNDLE_DIR}/results/${OUTPUT_PREFIX}}"

ENVIRONMENT_CLASS="${ENVIRONMENT_CLASS:-sandbox}"
WORKERS="${WORKERS:-16}"
N_SAMPLES="${N_SAMPLES:-1}"
SUSVIBES_MODEL_RETRIES="${SUSVIBES_MODEL_RETRIES:-4}"
DP_SIZE="${DP_SIZE:-}"
SHUFFLE_SEED="${SHUFFLE_SEED:-0}"

SECUREGEN_MODEL_CONFIG="${SECUREGEN_MODEL_CONFIG:-model_qwen.yaml}"
BAXBENCH_MODEL_CONFIG="${BAXBENCH_MODEL_CONFIG:-baxbench_model_qwen.yaml}"
# AutoBax shares BaxBench's runner and shared config but needs a bigger token and
# wall-clock budget, so it carries its own model config rather than BaxBench's.
AUTOBAX_MODEL_CONFIG="${AUTOBAX_MODEL_CONFIG:-autobax_model_qwen.yaml}"
SUSVIBES_MODEL_CONFIG="${SUSVIBES_MODEL_CONFIG:-evaluation_qwen.yaml}"

# Hint-level dataset variants already carry their security context in each problem
# statement. Override these when selecting such a file so SecureGen does not append a
# second CWE block and AutoBax filters the matching specific_hint<N> axis.
SECUREGEN_SECURITY_EVALUATE_MODE="${SECUREGEN_SECURITY_EVALUATE_MODE:-cwe}"
AUTOBAX_FUNC_SAFETY_PROMPT="${AUTOBAX_FUNC_SAFETY_PROMPT:-generic}"
AUTOBAX_SECURITY_SAFETY_PROMPT="${AUTOBAX_SECURITY_SAFETY_PROMPT:-specific}"

SECUREGEN_INSTANCES="${SECUREGEN_INSTANCES:-${SECUREGEN_GENERIC_INSTANCES:-${DATA_DIR}/securegen/securegen_mini_instances.json}}"
AUTOBAX_GENERIC_INSTANCES="${AUTOBAX_GENERIC_INSTANCES:-${DATA_DIR}/autobax/autobax_eval_instances.json}"
BAXBENCH_NATIVE_INSTANCES="${BAXBENCH_NATIVE_INSTANCES:-${DATA_DIR}/baxbench/baxbench_instances.json}"
SUSVIBES_INSTANCES="${SUSVIBES_INSTANCES:-${DATA_DIR}/susvibes/susvibes_mini_instances.json}"

AUTOBAX_FUNC_RESULTS_DIR="${AUTOBAX_FUNC_RESULTS_DIR:-${EVAL_RESULTS_ROOT}/autobax/func-text-generic/results}"
AUTOBAX_SECURITY_RESULTS_DIR="${AUTOBAX_SECURITY_RESULTS_DIR:-${EVAL_RESULTS_ROOT}/autobax/security-text-specific/results}"
AUTOBAX_PLAN_RESULTS_DIR="${AUTOBAX_PLAN_RESULTS_DIR:-${EVAL_RESULTS_ROOT}/autobax/plan-cwe-only/results}"
BAXBENCH_NATIVE_RESULTS_DIR="${BAXBENCH_NATIVE_RESULTS_DIR:-${EVAL_RESULTS_ROOT}/baxbench/text-none/results}"

SECUREGEN_FUNC_OUTPUT="${SECUREGEN_FUNC_OUTPUT:-${EVAL_RESULTS_ROOT}/securegen/func-generic}"
SECUREGEN_SECURITY_OUTPUT="${SECUREGEN_SECURITY_OUTPUT:-${EVAL_RESULTS_ROOT}/securegen/security-cwe}"
SECUREGEN_PLAN_OUTPUT="${SECUREGEN_PLAN_OUTPUT:-${EVAL_RESULTS_ROOT}/securegen/plan-cwe-only}"
AUTOBAX_FUNC_OUTPUT="${AUTOBAX_FUNC_OUTPUT:-${EVAL_RESULTS_ROOT}/autobax/func-text-generic/trajectories}"
AUTOBAX_SECURITY_OUTPUT="${AUTOBAX_SECURITY_OUTPUT:-${EVAL_RESULTS_ROOT}/autobax/security-text-specific/trajectories}"
AUTOBAX_PLAN_OUTPUT="${AUTOBAX_PLAN_OUTPUT:-${EVAL_RESULTS_ROOT}/autobax/plan-cwe-only/trajectories}"
BAXBENCH_NATIVE_OUTPUT="${BAXBENCH_NATIVE_OUTPUT:-${EVAL_RESULTS_ROOT}/baxbench/text-none/trajectories}"
SUSVIBES_OUTPUT="${SUSVIBES_OUTPUT:-${EVAL_RESULTS_ROOT}/susvibes/trajectories}"

require_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "Required file not found: ${path}" >&2
    exit 1
  fi
}

require_dir() {
  local path="$1"
  if [[ ! -d "${path}" ]]; then
    echo "Required directory not found: ${path}" >&2
    exit 1
  fi
}

should_run() {
  local run_name="$1"
  [[ "${RUNS}" == "all" ]] && return 0
  local selected=",${RUNS// /},"
  [[ "${selected}" == *",${run_name},"* ]]
}

validate_runs() {
  local normalized="${RUNS// /}"
  local run_name
  local -a requested_runs
  local -a valid_runs=(
    func-securegen func-autobax security-securegen security-autobax
    plan-securegen plan-autobax baxbench susvibe susvibes
  )

  if [[ -z "${normalized}" ]]; then
    echo "RUNS must be 'all' or a comma-separated list of eval runs." >&2
    exit 1
  fi
  [[ "${normalized}" == "all" ]] && return

  IFS=',' read -r -a requested_runs <<< "${normalized}"
  for run_name in "${requested_runs[@]}"; do
    if [[ -z "${run_name}" ]] || ! [[ " ${valid_runs[*]} " == *" ${run_name} "* ]]; then
      echo "Unknown eval run in RUNS: '${run_name}'" >&2
      echo "Valid runs: ${valid_runs[*]}" >&2
      exit 1
    fi
  done
}

print_command() {
  local dir="$1"
  local base="$2"
  shift 2

  printf '  cd %q\n  PYTHONPATH=%q LOCAL_BASE=%q RUNNER_PYTHON=%q' \
    "${dir}" "${MINISWE_AGENT_SRC}${PYTHONPATH:+:${PYTHONPATH}}" "${base}" "${RUNNER_PYTHON}"
  printf ' %q' "$@"
  printf '\n'
}

# Appends the --workers/--n_samples args shared by every harness onto the named cmd
# array. Pass with_n_samples=0 for harnesses whose batch runner has no --n_samples
# flag (susvibe).
append_common_run_args() {
  local -n _cmd_ref="$1"
  local with_n_samples="${2:-1}"

  _cmd_ref+=(--workers "${WORKERS}")
  if [[ "${with_n_samples}" == "1" ]]; then
    _cmd_ref+=(--n_samples "${N_SAMPLES}")
  fi
}

append_sglang_run_args() {
  local -n _cmd_ref="$1"

  _cmd_ref+=(--shuffle-seed "${SHUFFLE_SEED}")
  if [[ -n "${DP_SIZE}" ]]; then
    _cmd_ref+=(--sglang-dp-size "${DP_SIZE}")
  fi
}

run_in_dir() {
  local name="$1"
  local dir="$2"
  local base="$3"
  shift 3

  echo "=========================================="
  echo "Starting ${name}"
  echo "DIR=${dir}"
  echo "LOCAL_BASE=${base}"
  echo "MODEL=${MODEL}"
  echo "MODEL_LABEL=${MODEL_LABEL}"
  print_command "${dir}" "${base}" "$@"
  echo "=========================================="

  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "DRY_RUN=1; skipping ${name}"
    echo
    return
  fi

  (
    cd "${dir}"
    PYTHONPATH="${MINISWE_AGENT_SRC}${PYTHONPATH:+:${PYTHONPATH}}" \
      LOCAL_BASE="${base}" RUNNER_PYTHON="${RUNNER_PYTHON}" "$@"
  )

  echo "Finished ${name}"
  echo
}

run_securegen_eval() {
  local name="$1"
  local shared_config="$2"
  local instances="$3"
  local output="$4"
  local evaluate_mode="$5"

  local cmd=(
    ./run_local.sh
    --config "${shared_config},${SECUREGEN_MODEL_CONFIG}"
    --instances "${instances}"
    --output "${output}"
    --model "${MODEL}"
    --environment-class "${ENVIRONMENT_CLASS}"
  )
  append_sglang_run_args cmd
  append_common_run_args cmd 1
  if [[ -n "${evaluate_mode}" ]]; then
    cmd+=(--evaluate-mode "${evaluate_mode}")
  fi

  run_in_dir "${name}" "${SECUREGEN_DIR}" "${SECUREGEN_LOCAL_BASE}" "${cmd[@]}"
}

run_baxbench_eval() {
  local name="$1"
  local shared_config="$2"
  local instances="$3"
  local output="$4"
  local results_dir="$5"
  local spec_type="$6"
  local safety_prompt="$7"
  # Model config is per-run: AutoBax legs pass their own, BaxBench omits it and
  # falls back to BAXBENCH_MODEL_CONFIG.
  local model_config="${8:-${BAXBENCH_MODEL_CONFIG}}"

  local cmd=(
    ./run_local.sh
    --config "${shared_config},${model_config}"
    --instances "${instances}"
    --output "${output}"
    --results_dir "${results_dir}"
    --spec_type "${spec_type}"
    --safety_prompt "${safety_prompt}"
    --model-label "${MODEL_LABEL}"
    --model "${MODEL}"
    --environment-class "${ENVIRONMENT_CLASS}"
  )
  append_sglang_run_args cmd
  append_common_run_args cmd 1

  run_in_dir "${name}" "${BAXBENCH_DIR}" "${BAXBENCH_LOCAL_BASE}" "${cmd[@]}"
}

run_susvibe_eval() {
  local name="$1"
  local instances="$2"
  local output="$3"
  local api_base="${SUSVIBES_LOCAL_BASE%/}"

  if [[ "${DRY_RUN}" != "1" ]]; then
    echo "Checking model endpoint at ${api_base} ..."
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${api_base}/models" 2>/dev/null || true)
    if ! [[ "${code}" =~ ^2[0-9][0-9]$ ]]; then
      echo "ERROR: ${api_base}/models did not return a successful response (HTTP ${code:-000})." >&2
      exit 1
    fi
    echo "    endpoint reachable (HTTP ${code})"
  fi

  local cmd=(
    env
    "OPENAI_API_BASE=${api_base}"
    "OPENAI_API_KEY=local-no-auth"
    "MSWEA_MODEL_RETRY_STOP_AFTER_ATTEMPT=${SUSVIBES_MODEL_RETRIES}"
    "${RUNNER_PYTHON}" "${SUSVIBES_MINI_DIR}/batch_run.py"
    --config "${SUSVIBES_MODEL_CONFIG}"
    --instances "${instances}"
    --output "${output}"
    --model "${MODEL}"
    --environment-class "${ENVIRONMENT_CLASS}"
  )
  append_sglang_run_args cmd
  append_common_run_args cmd 0

  run_in_dir "${name}" "${SUSVIBES_MINI_DIR}" "${SUSVIBES_LOCAL_BASE}" "${cmd[@]}"
}

validate_runs
if [[ -n "${DP_SIZE}" ]] && ! [[ "${DP_SIZE}" =~ ^[1-9][0-9]*$ ]]; then
  echo "DP_SIZE must be a positive integer, got '${DP_SIZE}'." >&2
  exit 1
fi
if ! [[ "${SHUFFLE_SEED}" =~ ^-?[0-9]+$ ]]; then
  echo "SHUFFLE_SEED must be an integer, got '${SHUFFLE_SEED}'." >&2
  exit 1
fi
require_dir "${MINISWE_AGENT_SRC}/minisweagent"
require_file "${RUNNER_PYTHON}"

if should_run "func-securegen" || should_run "security-securegen" || should_run "plan-securegen"; then
  require_dir "${SECUREGEN_DIR}"
  require_file "${SECUREGEN_INSTANCES}"
  require_file "${SECUREGEN_DIR}/${SECUREGEN_MODEL_CONFIG}"
  if should_run "func-securegen" || should_run "security-securegen"; then
    require_file "${SECUREGEN_DIR}/evaluation.yaml"
  fi
  if should_run "plan-securegen"; then
    require_file "${SECUREGEN_DIR}/security_plan.yaml"
  fi
fi

if should_run "func-autobax" || should_run "security-autobax" || should_run "plan-autobax" || should_run "baxbench"; then
  require_dir "${BAXBENCH_DIR}"
  require_file "${BAXBENCH_DIR}/${BAXBENCH_MODEL_CONFIG}"
  if should_run "func-autobax" || should_run "security-autobax" || should_run "plan-autobax"; then
    require_file "${BAXBENCH_DIR}/${AUTOBAX_MODEL_CONFIG}"
    require_file "${AUTOBAX_GENERIC_INSTANCES}"
  fi
  if should_run "func-autobax" || should_run "security-autobax" || should_run "baxbench"; then
    require_file "${BAXBENCH_DIR}/evaluation.yaml"
  fi
  if should_run "plan-autobax"; then
    require_file "${BAXBENCH_DIR}/security_plan.yaml"
  fi
  if should_run "baxbench"; then
    require_file "${BAXBENCH_NATIVE_INSTANCES}"
  fi
fi

if should_run "susvibe" || should_run "susvibes"; then
  require_dir "${SUSVIBES_MINI_DIR}"
  require_file "${SUSVIBES_INSTANCES}"
  require_file "${SUSVIBES_MINI_DIR}/${SUSVIBES_MODEL_CONFIG}"
  require_file "${SUSVIBES_MINI_DIR}/batch_run.py"
fi

echo "Using RUNS=${RUNS}"
echo "Using RUNNER_PYTHON=${RUNNER_PYTHON}"
echo "Using OUTPUT_PREFIX=${OUTPUT_PREFIX}"
echo "Using EVAL_RESULTS_ROOT=${EVAL_RESULTS_ROOT}"
echo "Using WORKERS=${WORKERS}"
echo "Using N_SAMPLES=${N_SAMPLES}"
echo "Using SHUFFLE_SEED=${SHUFFLE_SEED}"
if [[ -n "${DP_SIZE}" ]]; then
  echo "Using DP_SIZE=${DP_SIZE} (sticky SGLang routing enabled)"
else
  echo "Using default SGLang routing (DP_SIZE is unset)"
fi
echo

if should_run "func-securegen"; then
  run_securegen_eval \
    "func-securegen" \
    "evaluation.yaml" \
    "${SECUREGEN_INSTANCES}" \
    "${SECUREGEN_FUNC_OUTPUT}" \
    "none"
fi

if should_run "func-autobax"; then
  run_baxbench_eval \
    "func-autobax" \
    "evaluation.yaml" \
    "${AUTOBAX_GENERIC_INSTANCES}" \
    "${AUTOBAX_FUNC_OUTPUT}" \
    "${AUTOBAX_FUNC_RESULTS_DIR}" \
    "text" \
    "${AUTOBAX_FUNC_SAFETY_PROMPT}" \
    "${AUTOBAX_MODEL_CONFIG}"
fi

if should_run "security-securegen"; then
  run_securegen_eval \
    "security-securegen" \
    "evaluation.yaml" \
    "${SECUREGEN_INSTANCES}" \
    "${SECUREGEN_SECURITY_OUTPUT}" \
    "${SECUREGEN_SECURITY_EVALUATE_MODE}"
fi

if should_run "security-autobax"; then
  run_baxbench_eval \
    "security-autobax" \
    "evaluation.yaml" \
    "${AUTOBAX_GENERIC_INSTANCES}" \
    "${AUTOBAX_SECURITY_OUTPUT}" \
    "${AUTOBAX_SECURITY_RESULTS_DIR}" \
    "text" \
    "${AUTOBAX_SECURITY_SAFETY_PROMPT}" \
    "${AUTOBAX_MODEL_CONFIG}"
fi

if should_run "plan-securegen"; then
  run_securegen_eval \
    "plan-securegen" \
    "security_plan.yaml" \
    "${SECUREGEN_INSTANCES}" \
    "${SECUREGEN_PLAN_OUTPUT}" \
    ""
fi

if should_run "plan-autobax"; then
  run_baxbench_eval \
    "plan-autobax" \
    "security_plan.yaml" \
    "${AUTOBAX_GENERIC_INSTANCES}" \
    "${AUTOBAX_PLAN_OUTPUT}" \
    "${AUTOBAX_PLAN_RESULTS_DIR}" \
    "text" \
    "none" \
    "${AUTOBAX_MODEL_CONFIG}"
fi

if should_run "baxbench"; then
  run_baxbench_eval \
    "baxbench" \
    "evaluation.yaml" \
    "${BAXBENCH_NATIVE_INSTANCES}" \
    "${BAXBENCH_NATIVE_OUTPUT}" \
    "${BAXBENCH_NATIVE_RESULTS_DIR}" \
    "text" \
    "none"
fi

if should_run "susvibe" || should_run "susvibes"; then
  run_susvibe_eval \
    "susvibe" \
    "${SUSVIBES_INSTANCES}" \
    "${SUSVIBES_OUTPUT}"
fi

echo "Selected eval runs finished."

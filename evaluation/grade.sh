#!/usr/bin/env bash
set -euo pipefail

# Grade outputs produced by evaluate.sh.
#
# Common overrides:
#   OUTPUT_PREFIX=func-qwen35-sft ./grade.sh
#   BAXBENCH_MODEL_LABEL=func-qwen35-sft ./grade.sh
#   RUNS=security-securegen,security-autobax ./grade.sh
#   WORKERS=32 ./grade.sh
#   N_SAMPLES=5 ./grade.sh
#   FORCE=1 ./grade.sh
#   DRY_RUN=1 ./grade.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="${BUNDLE_DIR:-${SCRIPT_DIR}}"
GRADING_DIR="${GRADING_DIR:-${BUNDLE_DIR}/grader}"
DATA_DIR="${DATA_DIR:-${BUNDLE_DIR}/../data/raw}"
SECUREGEN_ROOT="${SECUREGEN_ROOT:-${GRADING_DIR}/securegen}"
SECUREGEN_SRC="${SECUREGEN_SRC:-${SECUREGEN_ROOT}/src}"
AUTOBAX_DIR="${AUTOBAX_DIR:-${GRADING_DIR}/autobax}"
BAXBENCH_DIR="${BAXBENCH_DIR:-${GRADING_DIR}/baxbench}"
SUSVIBES_DIR="${SUSVIBES_DIR:-${GRADING_DIR}/susvibes}"

OUTPUT_PREFIX="${OUTPUT_PREFIX:-qwen35-sft}"
MODEL_LABEL="${MODEL_LABEL:-${OUTPUT_PREFIX}}"
BAXBENCH_MODEL_LABEL="${BAXBENCH_MODEL_LABEL:-}"
RUNS="${RUNS:-all}"
DRY_RUN="${DRY_RUN:-0}"
FORCE="${FORCE:-0}"
EVAL_RESULTS_ROOT="${EVAL_RESULTS_ROOT:-${BUNDLE_DIR}/results/${OUTPUT_PREFIX}}"
GRADE_RESULTS_ROOT="${GRADE_RESULTS_ROOT:-${EVAL_RESULTS_ROOT}/grades}"

SECUREGEN_PYTHON="${SECUREGEN_PYTHON:-${BUNDLE_DIR}/.venv/bin/python}"
AUTOBAX_PYTHON="${AUTOBAX_PYTHON:-${BUNDLE_DIR}/.venv/bin/python}"
BAXBENCH_PYTHON="${BAXBENCH_PYTHON:-${AUTOBAX_PYTHON}}"
SUSVIBES_PYTHON="${SUSVIBES_PYTHON:-${BUNDLE_DIR}/.venv/bin/python}"
BACKEND="${BACKEND:-sandbox}"
WORKERS="${WORKERS:-20}"
N_SAMPLES="${N_SAMPLES:-1}"

SECUREGEN_TASKS="${SECUREGEN_TASKS:-${DATA_DIR}/securegen/securegen_tasks.jsonl}"
AUTOBAX_INSTANCES="${AUTOBAX_INSTANCES:-${DATA_DIR}/autobax/autobax_grading_instances.json}"
AUTOBAX_FUNC_SAFETY_PROMPT="${AUTOBAX_FUNC_SAFETY_PROMPT:-generic}"
BAXBENCH_RESULTS_DIR="${BAXBENCH_RESULTS_DIR:-${EVAL_RESULTS_ROOT}/baxbench/text-none/results}"
BAXBENCH_KS="${BAXBENCH_KS:-1}"
BAXBENCH_SANDBOX_DATASET="${BAXBENCH_SANDBOX_DATASET:-${DATA_DIR}/baxbench/baxbench_instances.json}"
SUSVIBES_RUN_ID="${SUSVIBES_RUN_ID:-${OUTPUT_PREFIX}}"
SUSVIBES_PREDICTIONS_PATH="${SUSVIBES_PREDICTIONS_PATH:-${EVAL_RESULTS_ROOT}/susvibes/trajectories/preds.json}"
SUSVIBES_DATASET_PATH="${SUSVIBES_DATASET_PATH:-${DATA_DIR}/susvibes/susvibes_tasks.jsonl}"
SUSVIBES_ENV_SPEC_ID="${SUSVIBES_ENV_SPEC_ID:-default}"
SUSVIBES_AGENT="${SUSVIBES_AGENT:-mini-swe-agent}"
SUSVIBES_BACKEND="${SUSVIBES_BACKEND:-${BACKEND}}"

SECUREGEN_FUNC_PREDICTIONS="${SECUREGEN_FUNC_PREDICTIONS:-${EVAL_RESULTS_ROOT}/securegen/func-generic/preds.samples.json}"
SECUREGEN_SECURITY_PREDICTIONS="${SECUREGEN_SECURITY_PREDICTIONS:-${EVAL_RESULTS_ROOT}/securegen/security-cwe/preds.samples.json}"
SECUREGEN_PLAN_PREDICTIONS="${SECUREGEN_PLAN_PREDICTIONS:-${EVAL_RESULTS_ROOT}/securegen/plan-cwe-only/preds.samples.json}"

AUTOBAX_FUNC_RESULTS_DIR="${AUTOBAX_FUNC_RESULTS_DIR:-${EVAL_RESULTS_ROOT}/autobax/func-text-generic/results}"
AUTOBAX_SECURITY_RESULTS_DIR="${AUTOBAX_SECURITY_RESULTS_DIR:-${EVAL_RESULTS_ROOT}/autobax/security-text-specific/results}"
AUTOBAX_PLAN_OUTPUT="${AUTOBAX_PLAN_OUTPUT:-${EVAL_RESULTS_ROOT}/autobax/plan-cwe-only/trajectories}"

SECUREGEN_FUNC_GRADE_OUTPUT="${SECUREGEN_FUNC_GRADE_OUTPUT:-${GRADE_RESULTS_ROOT}/securegen/func-generic}"
SECUREGEN_SECURITY_GRADE_OUTPUT="${SECUREGEN_SECURITY_GRADE_OUTPUT:-${GRADE_RESULTS_ROOT}/securegen/security-cwe}"
SECUREGEN_PLAN_GRADE_OUTPUT="${SECUREGEN_PLAN_GRADE_OUTPUT:-${GRADE_RESULTS_ROOT}/securegen/plan-cwe-only}"
AUTOBAX_FUNC_GRADE_OUTPUT="${AUTOBAX_FUNC_GRADE_OUTPUT:-${GRADE_RESULTS_ROOT}/autobax/func-text-generic/report.json}"
AUTOBAX_SECURITY_GRADE_OUTPUT="${AUTOBAX_SECURITY_GRADE_OUTPUT:-${GRADE_RESULTS_ROOT}/autobax/security-text-specific/report.json}"
AUTOBAX_PLAN_GRADE_OUTPUT="${AUTOBAX_PLAN_GRADE_OUTPUT:-${GRADE_RESULTS_ROOT}/autobax/plan-cwe-only/report.json}"
BAXBENCH_GRADE_OUTPUT="${BAXBENCH_GRADE_OUTPUT:-${GRADE_RESULTS_ROOT}/baxbench/report.json}"
SUSVIBES_GRADE_OUTPUT="${SUSVIBES_GRADE_OUTPUT:-${GRADE_RESULTS_ROOT}/susvibes}"

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

require_command() {
  local command="$1"
  if [[ "${command}" == */* ]]; then
    require_file "${command}"
  elif ! command -v "${command}" >/dev/null 2>&1; then
    echo "Required command not found: ${command}" >&2
    exit 1
  fi
}

require_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "${value}" =~ ^[1-9][0-9]*$ ]]; then
    echo "${name} must be a positive integer, got: ${value}" >&2
    exit 1
  fi
}

require_boolean() {
  local name="$1"
  local value="$2"
  if [[ "${value}" != "0" && "${value}" != "1" ]]; then
    echo "${name} must be 0 or 1, got: ${value}" >&2
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
  [[ "${RUNS}" == "all" ]] && return

  local valid=",func-securegen,func-autobax,security-securegen,security-autobax,plan-securegen,plan-autobax,baxbench,susvibe,"
  local run_name
  IFS=',' read -ra selected_runs <<< "${RUNS// /}"
  if [[ "${#selected_runs[@]}" == "0" ]]; then
    echo "RUNS must not be empty" >&2
    exit 1
  fi
  for run_name in "${selected_runs[@]}"; do
    if [[ -z "${run_name}" || "${valid}" != *",${run_name},"* ]]; then
      echo "Unknown grade run: ${run_name:-<empty>}" >&2
      echo "Valid runs: func-securegen, func-autobax, security-securegen, security-autobax, plan-securegen, plan-autobax, baxbench, susvibe" >&2
      exit 1
    fi
  done
}

select_predictions() {
  local preferred="$1"
  local fallback="${preferred%.samples.json}.json"

  if [[ "${DRY_RUN}" == "1" ]]; then
    printf '%s\n' "${preferred}"
    return
  fi

  if [[ -f "${preferred}" ]]; then
    printf '%s\n' "${preferred}"
  elif [[ "${N_SAMPLES}" == "1" && -f "${fallback}" ]]; then
    printf '%s\n' "${fallback}"
  else
    echo "Required predictions not found: ${preferred}" >&2
    if [[ "${N_SAMPLES}" == "1" ]]; then
      echo "Fallback predictions not found: ${fallback}" >&2
    fi
    exit 1
  fi
}

resolve_baxbench_model_label() {
  local results_dir="$1"
  local requested="${BAXBENCH_MODEL_LABEL}"

  if [[ "${DRY_RUN}" == "1" ]]; then
    printf '%s\n' "${requested:-${MODEL_LABEL}}"
    return
  fi

  if [[ -n "${requested}" ]]; then
    require_dir "${results_dir}/${requested}"
    printf '%s\n' "${requested}"
    return
  fi
  if [[ -d "${results_dir}/${MODEL_LABEL}" ]]; then
    printf '%s\n' "${MODEL_LABEL}"
    return
  fi

  local model_dirs=()
  while IFS= read -r path; do
    model_dirs+=("${path}")
  done < <(find "${results_dir}" -mindepth 1 -maxdepth 1 -type d -print | sort)

  if [[ "${#model_dirs[@]}" == "1" ]]; then
    basename "${model_dirs[0]}"
    return
  fi

  echo "Could not infer BaxBench model label from ${results_dir}" >&2
  echo "Set BAXBENCH_MODEL_LABEL to the model directory under results_dir." >&2
  exit 1
}

require_baxbench_artifacts() {
  local results_dir="$1"
  local model_label="$2"
  [[ "${DRY_RUN}" == "1" ]] && return
  local artifact
  artifact="$(find "${results_dir}/${model_label}" \
    \( -type d -name code -o -type f -name test_results.json \) \
    -print -quit)"
  if [[ -z "${artifact}" ]]; then
    echo "No generated BaxBench code or grade results found for model ${model_label} in ${results_dir}" >&2
    exit 1
  fi
}

require_trajectory_artifacts() {
  local output_dir="$1"
  [[ "${DRY_RUN}" == "1" ]] && return
  local trajectory
  trajectory="$(find "${output_dir}" -type f -name '*.traj.json' -print -quit)"
  if [[ -z "${trajectory}" ]]; then
    echo "No trajectory files found in: ${output_dir}" >&2
    exit 1
  fi
}

run_command() {
  local name="$1"
  local dir="$2"
  shift 2

  echo "=========================================="
  echo "Starting ${name}"
  echo "DIR=${dir}"
  printf '  cd %q\n  ' "${dir}"
  printf '%q ' "$@"
  printf '\n'
  echo "=========================================="

  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "DRY_RUN=1; skipping ${name}"
    echo
    return
  fi

  (
    cd "${dir}"
    "$@"
  )

  echo "Finished ${name}"
  echo
}

run_securegen_grade() {
  local name="$1"
  local predictions="$2"
  local output="$3"
  local script="$4"
  local cwe_only="$5"

  local cmd=(
    env "PYTHONPATH=${SECUREGEN_SRC}" "SECUREGEN_SRC=${SECUREGEN_SRC}"
    "${SECUREGEN_PYTHON}" "${SECUREGEN_ROOT}/${script}"
    --predictions "${predictions}"
    --tasks "${SECUREGEN_TASKS}"
    --output "${output}"
    --backend "${BACKEND}"
    --workers "${WORKERS}"
  )
  if [[ "${predictions}" == *.samples.json ]]; then
    cmd+=(--n_samples "${N_SAMPLES}")
  fi
  if [[ "${cwe_only}" == "1" ]]; then
    cmd+=(--cwe-only)
  fi
  if [[ "${FORCE}" == "1" ]]; then
    cmd+=(--force)
  fi

  run_command "${name}" "${SECUREGEN_ROOT}" "${cmd[@]}"
}

run_baxbench_grade() {
  local name="$1"
  local safety_prompt="$2"
  local results_dir="$3"
  local output="$4"
  local model_label
  model_label="$(resolve_baxbench_model_label "${results_dir}")"
  require_baxbench_artifacts "${results_dir}" "${model_label}"

  echo "Using BaxBench model label=${model_label}"

  local cmd=(
    env "PYTHONPATH=${AUTOBAX_DIR}/src"
    "${AUTOBAX_PYTHON}" "${AUTOBAX_DIR}/grade.py"
    --models "${model_label}"
    --sandbox_dataset "${AUTOBAX_INSTANCES}"
    --spec_type text
    --safety_prompt "${safety_prompt}"
    --workers "${WORKERS}"
    --n_samples "${N_SAMPLES}"
    --include_missing
    --results_dir "${results_dir}"
    --output "${output}"
  )
  if [[ "${FORCE}" == "1" ]]; then
    cmd+=(--force)
  fi

  run_command "${name}" "${AUTOBAX_DIR}" "${cmd[@]}"
}

run_baxbench_native_grade() {
  local name="$1"
  local results_dir="$2"
  local model_label
  model_label="$(resolve_baxbench_model_label "${results_dir}")"
  require_baxbench_artifacts "${results_dir}" "${model_label}"

  echo "Using BaxBench model label=${model_label}"

  # Resource settings are supplied by the caller or a reproduction recipe.
  local sandbox_memory="${BAXBENCH_SANDBOX_MEMORY:-}"
  local heavy_sandbox_memory="${BAXBENCH_HEAVY_SANDBOX_MEMORY:-}"
  local bounded_filesearch="${BAXBENCH_BOUNDED_FILESEARCH_TRAVERSAL:-}"


  local grade_env=("PYTHONPATH=${BAXBENCH_DIR}/src")
  [[ -n "${sandbox_memory}" ]] && grade_env+=("BAXBENCH_SANDBOX_MEMORY=${sandbox_memory}")
  [[ -n "${heavy_sandbox_memory}" ]] && grade_env+=("BAXBENCH_HEAVY_SANDBOX_MEMORY=${heavy_sandbox_memory}")
  [[ -n "${bounded_filesearch}" ]] && grade_env+=("BAXBENCH_BOUNDED_FILESEARCH_TRAVERSAL=${bounded_filesearch}")

  local cmd=(
    env "${grade_env[@]}"
    "${BAXBENCH_PYTHON}" "${BAXBENCH_DIR}/grade.py"
    --models "${model_label}"
    --workers "${WORKERS}"
    --results_dir "${results_dir}"
    --ks "${BAXBENCH_KS}"
    --sandbox_dataset "${BAXBENCH_SANDBOX_DATASET}"
    --output "${BAXBENCH_GRADE_OUTPUT}"
  )
  if [[ "${FORCE}" == "1" ]]; then
    cmd+=(--force)
  fi

  run_command "${name}" "${BAXBENCH_DIR}" "${cmd[@]}"
}

run_susvibe_grade() {
  local name="$1"

  local cmd=(
    env "SUSVIBES_EVALUATION_LOG_DIR=${SUSVIBES_GRADE_OUTPUT}"
    "${SUSVIBES_PYTHON}" "${SUSVIBES_DIR}/grade.py"
    --run_id "${SUSVIBES_RUN_ID}"
    --predictions_path "${SUSVIBES_PREDICTIONS_PATH}"
    --dataset_path "${SUSVIBES_DATASET_PATH}"
    --env_spec_id "${SUSVIBES_ENV_SPEC_ID}"
    --max_workers "${WORKERS}"
    --agent "${SUSVIBES_AGENT}"
    --backend "${SUSVIBES_BACKEND}"
  )
  if [[ "${FORCE}" == "1" ]]; then
    cmd+=(--force)
  fi

  run_command "${name}" "${SUSVIBES_DIR}" "${cmd[@]}"
}

run_autobax_plan_grade() {
  local cmd=(
    "${AUTOBAX_PYTHON}" "${AUTOBAX_DIR}/grade_plans.py"
    --instances "${AUTOBAX_INSTANCES}"
    --output "${AUTOBAX_PLAN_OUTPUT}"
    --report "${AUTOBAX_PLAN_GRADE_OUTPUT}"
    --spec_type text
    --safety_prompt none
    --n_samples "${N_SAMPLES}"
  )

  run_command "plan-autobax" "${AUTOBAX_DIR}" "${cmd[@]}"
}

validate_runs
require_boolean "DRY_RUN" "${DRY_RUN}"
require_boolean "FORCE" "${FORCE}"
require_positive_integer "WORKERS" "${WORKERS}"
require_positive_integer "N_SAMPLES" "${N_SAMPLES}"
if [[ "${BACKEND}" != "sandbox" && "${BACKEND}" != "docker" ]]; then
  echo "BACKEND must be sandbox or docker, got: ${BACKEND}" >&2
  exit 1
fi

if should_run "func-securegen" || should_run "security-securegen" || should_run "plan-securegen"; then
  require_dir "${SECUREGEN_SRC}"
  require_file "${SECUREGEN_ROOT}/grade.py"
  require_file "${SECUREGEN_ROOT}/grade_plans.py"
  require_file "${SECUREGEN_TASKS}"
  require_command "${SECUREGEN_PYTHON}"
fi

if should_run "func-autobax" || should_run "security-autobax" || should_run "plan-autobax"; then
  require_dir "${AUTOBAX_DIR}"
  require_file "${AUTOBAX_INSTANCES}"
  require_command "${AUTOBAX_PYTHON}"
fi
if should_run "func-autobax" || should_run "security-autobax"; then
  require_file "${AUTOBAX_DIR}/grade.py"
fi
if should_run "plan-autobax"; then
  require_file "${AUTOBAX_DIR}/grade_plans.py"
fi

if should_run "baxbench"; then
  require_dir "${BAXBENCH_DIR}"
  if [[ "${DRY_RUN}" != "1" ]]; then
    require_dir "${BAXBENCH_RESULTS_DIR}"
  fi
  require_file "${BAXBENCH_DIR}/grade.py"
  require_command "${BAXBENCH_PYTHON}"
fi

if should_run "susvibe" || should_run "susvibes"; then
  require_dir "${SUSVIBES_DIR}"
  require_file "${SUSVIBES_DATASET_PATH}"
  require_file "${SUSVIBES_DIR}/grade.py"
  require_command "${SUSVIBES_PYTHON}"
  if [[ -z "${SUSVIBES_PREDICTIONS_PATH}" ]]; then
    echo "SUSVIBES_PREDICTIONS_PATH must be set to run the susvibe grade" >&2
    exit 1
  fi
  if [[ "${DRY_RUN}" != "1" ]]; then
    require_file "${SUSVIBES_PREDICTIONS_PATH}"
  fi
fi

echo "Using RUNS=${RUNS}"
echo "Using MODEL_LABEL=${MODEL_LABEL}"
echo "Using EVAL_RESULTS_ROOT=${EVAL_RESULTS_ROOT}"
echo "Using GRADE_RESULTS_ROOT=${GRADE_RESULTS_ROOT}"
echo "Using WORKERS=${WORKERS}"
echo "Using N_SAMPLES=${N_SAMPLES}"
echo

if should_run "func-securegen"; then
  run_securegen_grade \
    "func-securegen" \
    "$(select_predictions "${SECUREGEN_FUNC_PREDICTIONS}")" \
    "${SECUREGEN_FUNC_GRADE_OUTPUT}" \
    "grade.py" \
    "0"
fi

if should_run "func-autobax"; then
  if [[ "${DRY_RUN}" != "1" ]]; then
    require_dir "${AUTOBAX_FUNC_RESULTS_DIR}"
  fi
  run_baxbench_grade \
    "func-autobax" \
    "${AUTOBAX_FUNC_SAFETY_PROMPT}" \
    "${AUTOBAX_FUNC_RESULTS_DIR}" \
    "${AUTOBAX_FUNC_GRADE_OUTPUT}"
fi

if should_run "security-securegen"; then
  run_securegen_grade \
    "security-securegen" \
    "$(select_predictions "${SECUREGEN_SECURITY_PREDICTIONS}")" \
    "${SECUREGEN_SECURITY_GRADE_OUTPUT}" \
    "grade.py" \
    "0"
fi

if should_run "security-autobax"; then
  if [[ "${DRY_RUN}" != "1" ]]; then
    require_dir "${AUTOBAX_SECURITY_RESULTS_DIR}"
  fi
  run_baxbench_grade \
    "security-autobax" \
    "specific" \
    "${AUTOBAX_SECURITY_RESULTS_DIR}" \
    "${AUTOBAX_SECURITY_GRADE_OUTPUT}"
fi

if should_run "plan-securegen"; then
  run_securegen_grade \
    "plan-securegen" \
    "$(select_predictions "${SECUREGEN_PLAN_PREDICTIONS}")" \
    "${SECUREGEN_PLAN_GRADE_OUTPUT}" \
    "grade_plans.py" \
    "1"
fi

if should_run "plan-autobax"; then
  if [[ "${DRY_RUN}" != "1" ]]; then
    require_dir "${AUTOBAX_PLAN_OUTPUT}"
  fi
  require_trajectory_artifacts "${AUTOBAX_PLAN_OUTPUT}"
  run_autobax_plan_grade
fi

if should_run "baxbench"; then
  run_baxbench_native_grade \
    "baxbench" \
    "${BAXBENCH_RESULTS_DIR}"
fi

if should_run "susvibe" || should_run "susvibes"; then
  run_susvibe_grade "susvibe"
fi

echo "Selected grade runs finished."

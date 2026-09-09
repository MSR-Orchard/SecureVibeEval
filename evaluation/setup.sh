#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
VENV_DIR="${VENV_DIR:-${SCRIPT_DIR}/.venv}"
MINISWE_AGENT_DIR="${MINISWE_AGENT_DIR:-${SCRIPT_DIR}/../dependencies/vendor/mini-swe-agent}"
INSTALL_MINISWE_AGENT="${INSTALL_MINISWE_AGENT:-1}"

if [[ "${INSTALL_MINISWE_AGENT}" != 0 && "${INSTALL_MINISWE_AGENT}" != 1 ]]; then
  echo "INSTALL_MINISWE_AGENT must be 0 or 1" >&2
  exit 1
fi
if [[ "${INSTALL_MINISWE_AGENT}" == 1 && ! -f "${MINISWE_AGENT_DIR}/pyproject.toml" ]]; then
  echo "mini-swe-agent source missing: ${MINISWE_AGENT_DIR}" >&2
  echo "Set MINISWE_AGENT_DIR to the compatible source checkout, or INSTALL_MINISWE_AGENT=0 for CLI harness/grading only." >&2
  exit 1
fi
CHECK_PYTHON="${PYTHON}"
[[ ! -x "${VENV_DIR}/bin/python" ]] || CHECK_PYTHON="${VENV_DIR}/bin/python"
"${CHECK_PYTHON}" -c 'import sys; sys.exit("The evaluation lock requires Python 3.11 or newer") if sys.version_info < (3, 11) else None'


if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  "${PYTHON}" -m venv "${VENV_DIR}"
fi

"${VENV_DIR}/bin/python" -m pip install --upgrade pip
"${VENV_DIR}/bin/python" -m pip install --requirement "${SCRIPT_DIR}/requirements.lock"
if [[ "${INSTALL_MINISWE_AGENT}" == 1 ]]; then
  "${VENV_DIR}/bin/python" -m pip install --no-deps --editable "${MINISWE_AGENT_DIR}"
fi
"${VENV_DIR}/bin/python" -m pip check

echo "Environment ready: ${VENV_DIR}"
echo "Evaluate: ${SCRIPT_DIR}/evaluate.sh"
echo "Grade:    ${SCRIPT_DIR}/grade.sh"

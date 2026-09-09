#!/bin/bash
set -euo pipefail

echo "Installing Pi CLI..."

export DEBIAN_FRONTEND=noninteractive
export PI_NPM_INSTALL_ATTEMPTS="${PI_NPM_INSTALL_ATTEMPTS:-3}"
export PI_NPM_INSTALL_TIMEOUT="${PI_NPM_INSTALL_TIMEOUT:-900}"
export PI_APT_INSTALL_ATTEMPTS="${PI_APT_INSTALL_ATTEMPTS:-3}"
export PI_APT_INSTALL_TIMEOUT="${PI_APT_INSTALL_TIMEOUT:-900}"
export PI_APT_LOCK_TIMEOUT="${PI_APT_LOCK_TIMEOUT:-300}"

run_with_timeout() {
  local seconds="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$seconds" "$@"
  else
    "$@"
  fi
}

run_with_retries() {
  local attempts="$1"
  local seconds="$2"
  shift 2
  local n=1
  while true; do
    echo "+ $* (attempt $n/$attempts)"
    if run_with_timeout "$seconds" "$@"; then
      return 0
    fi
    if [ "$n" -ge "$attempts" ]; then
      echo "ERROR: command failed after $attempts attempts: $*" >&2
      return 1
    fi
    n=$((n + 1))
    sleep 5
  done
}

apt_process_running() {
  ps -eo comm= 2>/dev/null | grep -Eq '^(apt|apt-get|dpkg|dpkg-deb)$'
}

wait_for_apt() {
  local deadline=$((SECONDS + PI_APT_LOCK_TIMEOUT))
  while apt_process_running; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "Timed out waiting for apt/dpkg processes to finish." >&2
      return 1
    fi
    echo "Waiting for apt/dpkg to finish..."
    sleep 5
  done
}

repair_dpkg() {
  wait_for_apt || true
  if dpkg --audit 2>/dev/null | grep -q .; then
    echo "Repairing interrupted dpkg state..."
    dpkg --configure -a
  fi
  apt-get -f install -y --no-install-recommends \
    -o Dpkg::Options::=--force-confold >/dev/null
}

run_apt_with_repair() {
  local attempts="$1"
  local seconds="$2"
  shift 2
  local n=1
  while true; do
    repair_dpkg || true
    echo "+ $* (attempt $n/$attempts)"
    if run_with_timeout "$seconds" "$@"; then
      repair_dpkg || true
      return 0
    fi
    repair_dpkg || true
    if [ "$n" -ge "$attempts" ]; then
      echo "ERROR: command failed after $attempts attempts: $*" >&2
      return 1
    fi
    n=$((n + 1))
    sleep 15
  done
}

apt_install_if_missing() {
  local packages=()
  command -v curl >/dev/null 2>&1 || packages+=(curl)
  command -v git >/dev/null 2>&1 || packages+=(git)
  command -v python3 >/dev/null 2>&1 || packages+=(python3)
  [ -s /etc/ssl/certs/ca-certificates.crt ] || packages+=(ca-certificates)

  if [ "${#packages[@]}" -eq 0 ]; then
    echo "Required apt packages already present; skipping apt-get."
    return 0
  fi

  echo "Installing missing apt packages: ${packages[*]}"
  run_apt_with_repair "$PI_APT_INSTALL_ATTEMPTS" 300 apt-get update \
    -o Acquire::Retries=3 \
    -o Acquire::http::Timeout=30 \
    -o Acquire::https::Timeout=30
  run_apt_with_repair "$PI_APT_INSTALL_ATTEMPTS" "$PI_APT_INSTALL_TIMEOUT" \
    apt-get install -y --no-install-recommends \
    -o Dpkg::Options::=--force-confold \
    "${packages[@]}"
}

apt_install_if_missing

run_with_retries 2 120 curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.2/install.sh -o /tmp/install-nvm.sh
bash /tmp/install-nvm.sh

source "$HOME/.nvm/nvm.sh"

nvm install 22.23.2
nvm use 22.23.2
npm -v

# Dependency manifests are staged next to this script by the execution adapter.
CLI_DEPS_DIR="${BASH_SOURCE[0]}.deps"
if [[ ! -d "${CLI_DEPS_DIR}" ]]; then
  CLI_DEPS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
run_with_retries "$PI_NPM_INSTALL_ATTEMPTS" "$PI_NPM_INSTALL_TIMEOUT" \
  npm ci --prefix "${CLI_DEPS_DIR}" --omit=dev --no-audit --no-fund || exit $?
ln -sf "${CLI_DEPS_DIR}/node_modules/.bin/pi" "${NVM_BIN}/pi" || exit $?
hash -r


echo "Setting up environment..."
export PI_CODING_AGENT_DIR="${PI_CODING_AGENT_DIR:-/root/.pi/agent}"
mkdir -p "$PI_CODING_AGENT_DIR" /root/.pi/agent
cat > /root/.pi_env << 'EOF'
export HOME=/root
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" && nvm use 22 >/dev/null
export PATH="$HOME/.local/bin:$PATH"
export PI_CODING_AGENT_DIR="${PI_CODING_AGENT_DIR:-/root/.pi/agent}"
export PI_PROVIDER="${PI_PROVIDER:-copilot_proxy}"
export PI_MODEL="${PI_MODEL:-claude-opus-4.8}"
export PI_PROXY_BASE_URL="${PI_PROXY_BASE_URL:-http://127.0.0.1:8080}"
export PI_API_KEY="${PI_API_KEY:-proxy-handles-auth}"
export PI_THINKING="${PI_THINKING:-}"
export PI_MODELS_CONFIG="${PI_MODELS_CONFIG:-}"
export PI_OFFLINE="${PI_OFFLINE:-1}"
export FORCE_AUTO_BACKGROUND_TASKS="1"
export ENABLE_BACKGROUND_TASKS="1"
EOF

source /root/.pi_env

if [ -n "$PI_MODELS_CONFIG" ]; then
  cp "$PI_MODELS_CONFIG" "$PI_CODING_AGENT_DIR/models.json"
else
  cat > "$PI_CODING_AGENT_DIR/models.json" << JSON
{
  "providers": {
    "copilot_proxy": {
      "baseUrl": "$PI_PROXY_BASE_URL",
      "api": "openai-completions",
      "apiKey": "$PI_API_KEY",
      "authHeader": true,
      "compat": {
        "supportsDeveloperRole": false,
        "supportsReasoningEffort": false
      },
      "models": [
        {
          "id": "gpt-4o",
          "name": "Local 8080 GPT-4o",
          "input": ["text", "image"],
          "contextWindow": 128000,
          "maxTokens": 4096
        },
        {
          "id": "gpt-4o-2024-11-20",
          "name": "TRAPI Local GPT-4o",
          "input": ["text", "image"],
          "contextWindow": 128000,
          "maxTokens": 16384
        },
        {
          "id": "claude-opus-4.8",
          "name": "Local 8080 Claude Opus 4.8",
          "reasoning": true,
          "input": ["text", "image"],
          "contextWindow": 1000000,
          "maxTokens": 64000,
          "compat": {
            "supportsReasoningEffort": true
          }
        },
        {
          "id": "gpt-5.5",
          "name": "Local 8080 GPT-5.5",
          "api": "openai-responses",
          "reasoning": true,
          "input": ["text", "image"],
          "contextWindow": 1050000,
          "maxTokens": 128000
        },
        {
          "id": "gpt-5.4",
          "name": "Local 8080 GPT-5.4",
          "api": "openai-responses",
          "reasoning": true,
          "input": ["text", "image"],
          "contextWindow": 1050000,
          "maxTokens": 128000
        },
        {
          "id": "gpt-5.4-mini",
          "name": "Local 8080 GPT-5.4 Mini",
          "api": "openai-responses",
          "reasoning": true,
          "input": ["text", "image"],
          "contextWindow": 400000,
          "maxTokens": 128000
        },
        {
          "id": "gpt-5.3-codex",
          "name": "Local 8080 GPT-5.3 Codex",
          "api": "openai-responses",
          "reasoning": true,
          "input": ["text", "image"],
          "contextWindow": 400000,
          "maxTokens": 128000
        },
        {
          "id": "mai-code-1-flash-internal",
          "name": "Local 8080 MAI Code Flash",
          "api": "openai-responses",
          "reasoning": true,
          "contextWindow": 256000,
          "maxTokens": 128000
        }
      ]
    }
  }
}
JSON
fi

if [ "$PI_CODING_AGENT_DIR" != "/root/.pi/agent" ]; then
  cp "$PI_CODING_AGENT_DIR/models.json" /root/.pi/agent/models.json
fi

python3 -m json.tool "$PI_CODING_AGENT_DIR/models.json" >/dev/null
chmod 600 "$PI_CODING_AGENT_DIR/models.json" || true

echo "source /root/.pi_env" >> /root/.bashrc

echo "Testing installation..."
source "$HOME/.nvm/nvm.sh"
nvm use 22
source /root/.pi_env

if command -v pi >/dev/null 2>&1; then
  pi --version
  echo "Pi config dir: $PI_CODING_AGENT_DIR"
  echo "Pi models config: $PI_CODING_AGENT_DIR/models.json"
  echo "Configured providers:"
  python3 - << 'PY'
import json, os
path = os.path.join(os.environ["PI_CODING_AGENT_DIR"], "models.json")
with open(path, encoding="utf-8") as f:
    data = json.load(f)
print(", ".join(sorted(data.get("providers", {}).keys())))
PY
  if ! pi --provider "$PI_PROVIDER" --list-models > /tmp/pi-list-models.txt; then
    echo "ERROR: pi could not list models for provider '$PI_PROVIDER'." >&2
    echo "PI_CODING_AGENT_DIR=$PI_CODING_AGENT_DIR" >&2
    echo "models.json:" >&2
    sed -n '1,220p' "$PI_CODING_AGENT_DIR/models.json" >&2
    exit 1
  fi
  head -20 /tmp/pi-list-models.txt
  if ! grep -q "$PI_PROVIDER" /tmp/pi-list-models.txt; then
    echo "ERROR: provider '$PI_PROVIDER' was not visible in pi --list-models output." >&2
    echo "PI_CODING_AGENT_DIR=$PI_CODING_AGENT_DIR" >&2
    sed -n '1,220p' "$PI_CODING_AGENT_DIR/models.json" >&2
    exit 1
  fi
  echo "INSTALL_SUCCESS"
else
  echo "Installation failed" >&2
  exit 1
fi

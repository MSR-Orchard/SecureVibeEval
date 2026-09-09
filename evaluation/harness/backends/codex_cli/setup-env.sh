#!/bin/bash

echo "Installing OpenAI Codex CLI..."

apt-get update
apt-get install -y curl

curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.2/install.sh | bash

source "$HOME/.nvm/nvm.sh"

nvm install 22.23.2
nvm use 22.23.2
npm -v

# Dependency manifests are staged next to this script by the execution adapter.
CLI_DEPS_DIR="${BASH_SOURCE[0]}.deps"
if [[ ! -d "${CLI_DEPS_DIR}" ]]; then
  CLI_DEPS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
npm ci --prefix "${CLI_DEPS_DIR}" --omit=dev --no-audit --no-fund || exit $?
ln -sf "${CLI_DEPS_DIR}/node_modules/.bin/codex" "${NVM_BIN}/codex" || exit $?


echo "Setting up environment..."
cat > /root/.codex_env << 'EOF'
export PATH="$HOME/.local/bin:$PATH"
export CODEX_MODEL="${CODEX_MODEL:-gpt-5.5}"
export CODEX_API_KEY="${CODEX_API_KEY:-proxy-handles-auth}"
export CODEX_PROXY_BASE_URL="${CODEX_PROXY_BASE_URL:-http://127.0.0.1:8080/v1}"
export CODEX_SANDBOX="${CODEX_SANDBOX:-danger-full-access}"
export FORCE_AUTO_BACKGROUND_TASKS="1"
export ENABLE_BACKGROUND_TASKS="1"
EOF

mkdir -p /root/.codex
cat > /root/.codex/config.toml << EOF
model_provider = "local_proxy"

[model_providers.local_proxy]
name = "local_proxy"
base_url = "${CODEX_PROXY_BASE_URL:-http://127.0.0.1:8080/v1}"
env_key = "CODEX_API_KEY"
wire_api = "responses"
EOF

echo "source /root/.codex_env" >> /root/.bashrc

echo "Testing installation..."
source /root/.codex_env
source "$HOME/.nvm/nvm.sh"
nvm use 22

if command -v codex >/dev/null 2>&1; then
  codex --version
  echo "INSTALL_SUCCESS"
else
  echo "Installation failed" >&2
  exit 1
fi

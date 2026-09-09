#!/bin/bash

echo "Installing GitHub Copilot CLI..."

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
ln -sf "${CLI_DEPS_DIR}/node_modules/.bin/copilot" "${NVM_BIN}/copilot" || exit $?


echo "Setting up environment..."
mkdir -p /root/.copilot
cat > /root/.copilot_env << 'EOF'
export COPILOT_MODEL="${COPILOT_MODEL:-gpt-5.5}"
export FORCE_AUTO_BACKGROUND_TASKS="1"
export ENABLE_BACKGROUND_TASKS="1"
EOF

echo "source /root/.copilot_env" >> /root/.bashrc

echo "Testing installation..."
source /root/.copilot_env
source "$HOME/.nvm/nvm.sh"
nvm use 22

if command -v copilot >/dev/null 2>&1; then
  copilot --version
  echo "INSTALL_SUCCESS"
else
  echo "Installation failed" >&2
  exit 1
fi

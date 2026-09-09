#!/bin/bash

echo "Installing Real Claude CLI..."

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
ln -sf "${CLI_DEPS_DIR}/node_modules/.bin/claude" "${NVM_BIN}/claude" || exit $?


echo "Setting up environment..."
cat > /root/.claude_env << 'EOF'
export ANTHROPIC_MODEL="${ANTHROPIC_MODEL:-claude-sonnet-4-20250514}"
export FORCE_AUTO_BACKGROUND_TASKS="1"
export ENABLE_BACKGROUND_TASKS="1"
EOF

echo "source /root/.claude_env" >> /root/.bashrc

echo "Testing installation..."
source /root/.claude_env
source "$HOME/.nvm/nvm.sh"
nvm use 22

if command -v claude >/dev/null 2>&1; then
  claude --version
  echo "INSTALL_SUCCESS"
else
  echo "Installation failed" >&2
  exit 1
fi

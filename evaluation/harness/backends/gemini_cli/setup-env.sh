#!/bin/bash

echo "Installing Real Gemini CLI..."

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
ln -sf "${CLI_DEPS_DIR}/node_modules/.bin/gemini" "${NVM_BIN}/gemini" || exit $?


echo "Setting up environment..."
mkdir -p /root/.gemini
cat > /root/.gemini/.env << 'EOF'
export GEMINI_MODEL="${GEMINI_MODEL:-gemini-3-pro-preview}"
export GEMINI_API_KEY="${GEMINI_API_KEY:-}"
export GOOGLE_API_KEY="${GOOGLE_API_KEY:-}"
export GOOGLE_GEMINI_BASE_URL="${GOOGLE_GEMINI_BASE_URL:-}"
export GOOGLE_VERTEX_BASE_URL="${GOOGLE_VERTEX_BASE_URL:-}"
export GOOGLE_GENAI_USE_VERTEXAI="${GOOGLE_GENAI_USE_VERTEXAI:-}"
export GOOGLE_GENAI_USE_GCA="${GOOGLE_GENAI_USE_GCA:-}"
export GOOGLE_CLOUD_PROJECT="${GOOGLE_CLOUD_PROJECT:-}"
export GOOGLE_CLOUD_LOCATION="${GOOGLE_CLOUD_LOCATION:-}"
export FORCE_AUTO_BACKGROUND_TASKS="1"
export ENABLE_BACKGROUND_TASKS="1"
EOF

if [ -n "$GOOGLE_GEMINI_BASE_URL" ]; then
  gemini_auth_type="gateway"
elif [ -n "$GOOGLE_GENAI_USE_VERTEXAI" ]; then
  gemini_auth_type="vertex-ai"
elif [ -n "$GEMINI_API_KEY" ] || [ -n "$GOOGLE_API_KEY" ]; then
  gemini_auth_type="gemini-api-key"
else
  gemini_auth_type=""
fi

if [ -n "$gemini_auth_type" ]; then
  cat > /root/.gemini/settings.json << EOF
{
  "security": {
    "auth": {
      "selectedType": "$gemini_auth_type"
    }
  }
}
EOF
fi

echo "source /root/.gemini/.env" >> /root/.bashrc

echo "Testing installation..."
source /root/.gemini/.env
source "$HOME/.nvm/nvm.sh"
nvm use 22

if command -v gemini >/dev/null 2>&1; then
  gemini --version
  echo "INSTALL_SUCCESS"
else
  echo "Installation failed" >&2
  exit 1
fi

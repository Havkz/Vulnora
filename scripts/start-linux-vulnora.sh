#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:$HOME/go/bin:$HOME/.foundry/bin:$PATH"
export VULNORA_CONFIG_DIR="$HOME/.vulnora"
export LLM_PROVIDER=codex VULNORA_DEFAULT_PROVIDER=codex VULNORA_MODEL_FALLBACK=local
export VULNORA_LOCAL_BASE_URL=http://127.0.0.1:11434/api
export VULNORA_LOCAL_MODEL=huihui_ai/qwen3-coder-abliterated:30b
export VULNORA_FULL_ARSENAL=1
cd "$HOME/app"
node scripts/arsenal-doctor.mjs --offline --strict
if [[ ${1:-} == --verify-providers ]]; then exec node scripts/verify-cli-providers.mjs; fi
exec node dist/cli.js "$@"

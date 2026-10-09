#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:$HOME/go/bin:$HOME/.foundry/bin:$PATH"
export T3MP3ST_CONFIG_DIR="$HOME/.t3mp3st"
export LLM_PROVIDER=codex TEMPEST_DEFAULT_PROVIDER=codex TEMPEST_MODEL_FALLBACK=local
export TEMPEST_LOCAL_BASE_URL=http://127.0.0.1:11434/api
export TEMPEST_LOCAL_MODEL=huihui_ai/qwen3-coder-abliterated:30b
export T3MP3ST_FULL_ARSENAL=1
cd "$HOME/app"
node scripts/arsenal-doctor.mjs --offline --strict
if [[ ${1:-} == --verify-providers ]]; then exec node scripts/verify-cli-providers.mjs; fi
exec node dist/cli.js "$@"

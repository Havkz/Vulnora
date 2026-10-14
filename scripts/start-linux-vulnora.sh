#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"
export VULNORA_CONFIG_DIR="${VULNORA_CONFIG_DIR:-$HOME/.vulnora}"
export VULNORA_FULL_ARSENAL=1
cd "$(dirname "$0")/.."
if ! readiness=$(node scripts/arsenal-doctor.mjs --offline --json --strict); then
  printf '%s\n' "$readiness" >&2
  exit 1
fi
if [[ ${1:-} == --verify-providers ]]; then exec node scripts/verify-cli-providers.mjs; fi
exec node dist/cli.js "$@"

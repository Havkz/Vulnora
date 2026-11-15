#!/usr/bin/env bash
set -euo pipefail

# Keep Linux dependencies off the Windows checkout used by the preceding checks.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git archive HEAD | tar -xf - -C "$work"
cd "$work"
npm ci
npm run browser:install
npm run test:browser
for script in lint typecheck test doctor verify-claims test:no-fitting test:no-self-fitting test:gate test:fallback prompt:audit smoke; do
  npm run "$script"
done
npm audit --audit-level=low

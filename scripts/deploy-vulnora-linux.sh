#!/usr/bin/env bash
set -euo pipefail
[[ $# == 3 && $2 =~ ^[a-f0-9]{40}$ ]] || { echo 'Expected archive, full Git revision and Windows data directory' >&2; exit 1; }
archive=$1
revision=$2
windows_data=$3
release="$HOME/.vulnora/releases/$revision"
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"
umask 077
mkdir -p "$release"
cd "$release"
tar -xf "$archive" --no-same-owner
npm ci --ignore-scripts --no-audit --no-fund
npm run build
node --input-type=module - <<'JS'
import { access, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { DEFAULT_WEB_WORDLIST } from './dist/arsenal/catalog.js';
await access(DEFAULT_WEB_WORDLIST, constants.R_OK);
if (!(await readFile(DEFAULT_WEB_WORDLIST, 'utf8')).trim()) throw new Error('Website discovery wordlist is empty. Reinstall dirb.');
console.log(`Discovery wordlist readable: ${DEFAULT_WEB_WORDLIST}`);
JS
node scripts/arsenal-doctor.mjs --offline --strict
# Linux legacy data wins; existing Vulnora files are never overwritten.
node --input-type=module - "$windows_data" <<'JS'
import { configDirectory, migrateLegacyData, protectConfigSecrets } from './dist/config/migration.js';
const directory = configDirectory();
migrateLegacyData([process.argv[2]], directory);
protectConfigSecrets(directory);
JS
printf '%s\n' "$revision" > .installed-revision
printf 'VULNORA_RELEASE_READY=%s\n' "$release"

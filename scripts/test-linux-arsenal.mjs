import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { TOOL_ADAPTERS } from '../dist/arsenal/catalog.js';

const installer = await readFile(new URL('./install-linux-arsenal.sh', import.meta.url), 'utf8');
const packageAliases = { dig: 'dnsutils', host: 'dnsutils', scout: 'scoutsuite', myth: 'mythril',
  cast: 'foundryup', forge: 'foundryup', 'afl-fuzz': 'afl++', r2: 'radare2', analyzeHeadless: 'ghidra',
  objdump: 'binutils', strings: 'binutils', readelf: 'binutils', exiftool: 'libimage-exiftool-perl' };
for (const tool of TOOL_ADAPTERS.filter(tool => ['safe_command', 'receipt_required'].includes(tool.execution))) {
  if (tool.supportedPlatforms && !tool.supportedPlatforms.includes('linux')) continue;
  assert(installer.includes(packageAliases[tool.binary] || tool.binary), `Missing Linux installation recipe: ${tool.id}`);
}
assert(installer.indexOf('--offline --strict') < installer.indexOf('touch "$HOME/.tempest-arsenal-ready"'));
const doctor = spawnSync(process.execPath, ['scripts/arsenal-doctor.mjs', '--offline', '--json', '--strict'], {
  cwd: new URL('../', import.meta.url), env: { ...process.env, PATH: '' }, encoding: 'utf8',
});
assert.equal(doctor.status, 1);
const report = JSON.parse(doctor.stdout);
assert.equal(report.installed, 0);
assert(report.missing.some(tool => tool.binary === 'nmap'));
assert(report.unsupported.some(tool => tool.id === 'class-dump'));
console.log('LINUX_INSTALL_MANIFEST_AND_STRICT_READINESS_OK');

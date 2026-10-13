import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { TOOL_ADAPTERS } from '../dist/arsenal/catalog.js';

const installer = await readFile(new URL('./install-linux-arsenal.sh', import.meta.url), 'utf8');
const packageAliases = { dig: 'dnsutils', host: 'dnsutils' };
for (const tool of TOOL_ADAPTERS.filter(tool => ['safe_command', 'receipt_required'].includes(tool.execution))) {
  if (tool.supportedPlatforms && !tool.supportedPlatforms.includes('linux')) continue;
  assert(installer.includes(packageAliases[tool.binary] || tool.binary), `Missing Linux installation recipe: ${tool.id}`);
}
assert(installer.indexOf('--offline --strict') < installer.indexOf('touch "$HOME/.vulnora-arsenal-ready"'));
const doctor = spawnSync(process.execPath, ['scripts/arsenal-doctor.mjs', '--offline', '--json', '--strict'], {
  cwd: new URL('../', import.meta.url), env: { ...process.env, PATH: '' }, encoding: 'utf8',
});
assert.equal(doctor.status, 1);
const report = JSON.parse(doctor.stdout);
assert.equal(report.installed, 0);
assert(report.missing.some(tool => tool.binary === 'nmap'));
assert.deepEqual(report.unsupported, []);
assert.equal(TOOL_ADAPTERS.length, 23);
assert(TOOL_ADAPTERS.every(tool => tool.families.includes('web_api')));
for (const excluded of ['class-dump', 'apktool', 'jadx', 'metasploit-framework', 'scoutsuite', 'foundryup']) {
  assert(!installer.includes(excluded), `Non-web package in installer: ${excluded}`);
}
console.log('LINUX_INSTALL_MANIFEST_AND_STRICT_READINESS_OK');

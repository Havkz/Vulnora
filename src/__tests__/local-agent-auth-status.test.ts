import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { detectLocalAgents } from '../agent/local-agents.js';

const directories: string[] = [];
afterEach(() => { vi.unstubAllEnvs(); for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });

function fixture(id: 'codex' | 'claude', status: string, authArtifact = true) {
  const home = realpathSync.native(mkdtempSync(join(tmpdir(), 'vulnora-cli-auth-')));
  directories.push(home);
  const bin = join(home, 'bin'); mkdirSync(bin);
  const script = join(bin, 'node_modules', 'fixture', 'cli.mjs'); mkdirSync(join(bin, 'node_modules', 'fixture'), { recursive: true });
  writeFileSync(script, `#!${process.execPath}
if (process.env.OPENAI_API_KEY || process.env.ANTHROPIC_API_KEY) process.exit(9);
const args = process.argv.slice(2).join(' ');
if (args === '--version') console.log('2.1.300');
else if (args === 'login status') {
  if (process.env.VULNORA_AUTH_FIXTURE === 'logged') console.log('Logged in using ChatGPT');
  else { console.error('Not logged in'); process.exit(1); }
} else if (args === 'auth status') {
  if (process.env.VULNORA_AUTH_FIXTURE === 'malformed') console.log('unsupported status output');
  else console.log(JSON.stringify({ loggedIn: process.env.VULNORA_AUTH_FIXTURE === 'logged', email: 'private-fixture@example.test', authMethod: 'claude.ai' }));
} else process.exit(2);
`, { mode: 0o755 });
  if (process.platform === 'win32') {
    writeFileSync(join(bin, id + '.cmd'), '@echo off\r\nset "dp0=%~dp0"\r\nset "_prog=node"\r\n"%_prog%" "%dp0%\\node_modules\\fixture\\cli.mjs" %*\r\n');
  } else writeFileSync(join(bin, id), `#!/bin/sh\nexec "${process.execPath}" "${script}" "$@"\n`, { mode: 0o755 });
  if (authArtifact) {
    mkdirSync(join(home, '.codex'));
    writeFileSync(join(home, '.codex', 'auth.json'), 'private-auth-fixture-that-must-not-be-read');
    writeFileSync(join(home, '.claude.json'), 'private-auth-fixture-that-must-not-be-read');
  }
  vi.stubEnv('VULNORA_AGENT_HOME', home); vi.stubEnv('VULNORA_DISABLE_LOCAL_AGENTS', '');
  vi.stubEnv('PATH', bin + (process.platform === 'win32' ? ';' + join(process.env.SystemRoot || 'C:\\Windows', 'System32') : ':/usr/bin:/bin'));
  vi.stubEnv('VULNORA_AUTH_FIXTURE', status);
  vi.stubEnv('OPENAI_API_KEY', 'application-key-must-not-replace-native-login');
  vi.stubEnv('ANTHROPIC_API_KEY', 'application-key-must-not-replace-native-login');
}

describe('official local CLI authentication status', () => {
  it.each(['codex', 'claude'] as const)('does not treat an existing %s credentials file as a valid login', async id => {
    fixture(id, 'expired');
    const agent = (await detectLocalAgents()).find(agent => agent.id === id);
    expect(agent).toMatchObject({ installed: true, version: '2.1.300', authed: false, ready: false });
    expect(JSON.stringify(agent)).not.toContain('private-auth-fixture');
  }, 20000);

  it.each(['codex', 'claude'] as const)('accepts the %s CLI status without requiring or reading an auth file', async id => {
    fixture(id, 'logged', false);
    const agent = (await detectLocalAgents()).find(agent => agent.id === id);
    expect(agent).toMatchObject({ authed: true, ready: true, authMethod: 'cli_status' });
    expect(JSON.stringify(agent)).not.toContain('private-fixture@example.test');
  }, 20000);

  it('fails closed when Claude reports an unsupported authentication response', async () => {
    fixture('claude', 'malformed');
    expect((await detectLocalAgents()).find(agent => agent.id === 'claude')).toMatchObject({ authed: false, ready: false });
  }, 20000);
});

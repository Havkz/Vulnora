import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const directories: string[] = [];
afterEach(async () => {
  vi.unstubAllEnvs(); vi.resetModules();
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

describe('interactive setting persistence', () => {
  it.each(['VULNORA_LOCAL_API_KEY', 'ZAI_API_KEY', 'ZHIPUAI_API_KEY'])('forwards %s to the local provider without storing the environment credential', async name => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-settings-'));
    directories.push(directory);
    vi.stubEnv('VULNORA_CONFIG_DIR', directory);
    vi.stubEnv('VULNORA_FORCE_UNCONFIGURED', '');
    for (const alias of ['VULNORA_LOCAL_API_KEY', 'ZAI_API_KEY', 'ZHIPUAI_API_KEY']) vi.stubEnv(alias, '');
    vi.stubEnv(name, 'synthetic-local-bearer');
    const { config } = await import('../config/index.js');
    expect(config.getLLMConfig('local').apiKey).toBe('synthetic-local-bearer');
    expect(config.get('apiKeys').local).toBeUndefined();
  });
  it('honors explicit provider, model and key changes after reopening even when old startup defaults remain', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-settings-'));
    directories.push(directory);
    vi.stubEnv('VULNORA_CONFIG_DIR', directory);
    vi.stubEnv('VULNORA_DEFAULT_PROVIDER', 'codex');
    vi.stubEnv('VULNORA_LOCAL_MODEL', 'old-installed:30b');
    vi.stubEnv('OPENAI_API_KEY', 'synthetic-old-environment-key');
    vi.stubEnv('VULNORA_LOCAL_API_KEY', 'synthetic-old-local-key');
    vi.stubEnv('VULNORA_MODEL_FALLBACK', 'local');
    vi.stubEnv('VULNORA_FORCE_UNCONFIGURED', '');
    const { config } = await import('../config/index.js');
    expect(config.getLLMConfig().provider).toBe('codex');
    expect(config.getLLMConfig('local').model).toBe('old-installed:30b');
    expect(config.getApiKey('openai')).toBe('synthetic-old-environment-key');
    config.setDefaultModel('local', 'chosen-installed:7b');
    config.setDefaultModel('openai', 'chosen-fixture-model');
    config.setDefaultProvider('openai');
    config.setApiKey('openai', 'synthetic-replaced-provider-key');
    config.setApiKey('local', 'synthetic-replaced-local-key');
    vi.resetModules();
    const restored = (await import('../config/index.js')).config;
    expect(restored.getLLMConfig()).toMatchObject({ provider: 'openai', model: 'chosen-fixture-model', apiKey: 'synthetic-replaced-provider-key' });
    expect(restored.getLLMConfig().fallbackChain?.[0].model).toBe('chosen-installed:7b');
    expect(restored.getLLMConfig('local')).toMatchObject({ model: 'chosen-installed:7b', apiKey: 'synthetic-replaced-local-key' });
    expect(restored.getLLMConfig('codex').provider).toBe('codex');
    expect(restored.getLLMConfig('local', 'explicit-call:3b').model).toBe('explicit-call:3b');
    if (process.platform === 'win32') {
      const script = `$acl = [IO.File]::GetAccessControl($env:VULNORA_TEST_SETTINGS_FILE);
        [string]::Join('|', $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]).IdentityReference.Value)`;
      const access = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand',
        Buffer.from(script, 'utf16le').toString('base64')], { encoding: 'utf8', windowsHide: true,
        env: { ...process.env, VULNORA_TEST_SETTINGS_FILE: restored.getConfigPath() } }).trim().split('|');
      expect(access).toHaveLength(3);
      expect(access).toEqual(expect.arrayContaining(['S-1-5-18', 'S-1-5-32-544']));
      expect(access.filter((sid: string) => sid !== 'S-1-5-18' && sid !== 'S-1-5-32-544')[0]).toMatch(/^S-1-5-21-/);
    } else {
      expect((await stat(directory)).mode & 0o777).toBe(0o700);
      expect((await stat(restored.getConfigPath())).mode & 0o777).toBe(0o600);
    }
    vi.stubEnv('VULNORA_FORCE_UNCONFIGURED', '1');
    expect(restored.getApiKey('openai')).toBeUndefined(); expect(restored.getApiKey('local')).toBeUndefined();
  }, 20000);
  it('retains the selected installed Ollama model and agent without relying on environment changes', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-settings-'));
    directories.push(directory);
    vi.stubEnv('VULNORA_CONFIG_DIR', directory);
    vi.stubEnv('VULNORA_LOCAL_MODEL', '');
    vi.stubEnv('VULNORA_LOCAL_BASE_URL', '');
    vi.stubEnv('VULNORA_MODEL_FALLBACK', 'local');
    const { config } = await import('../config/index.js');
    expect(config.get('scanningBehavior')).toBe('auto');
    config.setDefaultModel('local', 'fixture-installed:7b');
    config.setDefaultModel('local-agent', 'claude');
    config.set('scanningBehavior', 'stealth');
    vi.resetModules();
    const restored = (await import('../config/index.js')).config;
    expect(restored.getLLMConfig('local').model).toBe('fixture-installed:7b');
    expect(restored.getLLMConfig('local-agent').model).toBe('claude');
    expect(restored.get('scanningBehavior')).toBe('stealth');
    expect(restored.getLLMConfig('codex').fallbackChain?.[0].model).toBe('fixture-installed:7b');
  });
});

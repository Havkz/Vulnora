import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const directories: string[] = [];
afterEach(async () => {
  vi.unstubAllEnvs(); vi.resetModules();
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

describe('interactive setting persistence', () => {
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

import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { cliModelOptions } from '../agent/local-agents.js';

const directories: string[] = [];
afterEach(async () => { vi.unstubAllEnvs(); for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true }); });

describe('Vulnora CLI model settings', () => {
  it('stores independent Codex and Claude overrides durably and supports returning to CLI defaults', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-cli-models-')); directories.push(directory);
    vi.stubEnv('VULNORA_CONFIG_DIR', directory); vi.stubEnv('VULNORA_DEFAULT_PROVIDER', 'codex');
    vi.resetModules(); const { config } = await import('../config/index.js');
    config.setCLIModel('codex', 'chosen-codex', 'high'); config.setDefaultProvider('codex');
    config.setCLIModel('claude', 'sonnet', 'medium');
    expect(config.getLLMConfig()).toMatchObject({ provider: 'codex', model: 'chosen-codex', reasoningEffort: 'high' });
    config.setDefaultModel('local-agent', 'claude'); config.setDefaultProvider('local-agent');
    expect(config.getLLMConfig()).toMatchObject({ model: 'claude', cliModel: 'sonnet', reasoningEffort: 'medium' });
    expect(config.getLLMConfig('local-agent', 'codex')).toMatchObject({ cliModel: 'chosen-codex', reasoningEffort: 'high' });
    vi.resetModules(); const restored = (await import('../config/index.js')).config;
    expect(restored.getLLMConfig()).toMatchObject({ provider: 'local-agent', model: 'claude', cliModel: 'sonnet', reasoningEffort: 'medium' });
    restored.setCLIModel('codex', 'codex-default'); restored.setCLIModel('claude', '');
    expect(restored.getLLMConfig('codex').reasoningEffort).toBeUndefined();
    expect(restored.getLLMConfig('local-agent', 'claude').cliModel).toBe('');
    const before = await readFile(restored.getConfigPath(), 'utf8');
    expect(() => restored.setCLIModel('codex', '-m unexpected', 'low')).toThrow('model');
    expect(() => restored.setCLIModel('claude', 'sonnet', 'ultra')).toThrow('reasoning');
    expect(await readFile(restored.getConfigPath(), 'utf8')).toBe(before);
  });

  it('offers Codex models and their reasoning levels from public local metadata with a manual-entry fallback', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-model-cache-')); directories.push(directory);
    const path = join(directory, 'models_cache.json'); vi.stubEnv('VULNORA_CODEX_MODELS_CACHE', path);
    await writeFile(path, JSON.stringify({ models: [
      { slug: 'account-model', display_name: 'Account model', supported_reasoning_levels: [{ effort: 'low' }, { effort: 'high' }, { effort: 'bad' }] },
      { slug: 'hidden-model', visibility: 'hide' }, { slug: 'account-model' }, { slug: '-invalid' },
    ] }));
    expect(cliModelOptions('codex')).toEqual([
      expect.objectContaining({ id: 'codex-default' }), { id: 'account-model', label: 'Account model', efforts: ['low', 'high'] },
    ]);
    await writeFile(path, 'broken cache'); expect(cliModelOptions('codex')).toHaveLength(1);
    expect(cliModelOptions('claude').map(model => model.id)).toEqual(['', 'sonnet', 'opus', 'haiku']);
  });
});

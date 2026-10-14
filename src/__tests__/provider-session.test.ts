import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LLMConfig } from '../types/index.js';

const probe = vi.hoisted(() => vi.fn(async (_config: LLMConfig) => 'VULNORA_READY'));
const detection = vi.hoisted(() => vi.fn(async (id: string) => ({ id, installed: true, ready: true })));
const held = vi.hoisted(() => [] as { start: ReturnType<typeof vi.fn>; stop: ReturnType<typeof vi.fn> }[]);
vi.mock('../llm/index.js', () => ({ LLMBackbone: class {
  constructor(private config: LLMConfig) {}
  setRetryConfig() {}
  validateConfig() { return { valid: true }; }
  prompt() { return probe(this.config); }
} }));
vi.mock('../agent/local-agents.js', () => ({ detectLocalAgent: detection }));
vi.mock('../llm/ollama-session.js', () => ({ createOllamaSession: () => {
  const session = { start: vi.fn(async () => {}), stop: vi.fn(async () => {}) }; held.push(session); return session;
} }));
import { ProviderSession, validateProvider, type ProviderProgress } from '../llm/provider-session.js';

const primary: LLMConfig = { provider: 'codex', model: 'configured-primary', timeout: 120000 };
const local: LLMConfig = { provider: 'local', model: 'installed:7b', baseUrl: 'http://127.0.0.1:11434/api' };
function fixture(config: LLMConfig = primary, models = ['installed:7b']) {
  const selectedLocal = { ...local };
  const source = {
    getLLMConfig: (provider?: string) => ({ ...(provider === 'local' ? selectedLocal : config) }),
    get: () => ({ command: 'configured-codex' }),
  } as never;
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ models: models.map(name => ({ name })) }) })));
  const controller = new AbortController(); const runtime = new ProviderSession(source, controller.signal);
  return { runtime, controller, selectedLocal };
}
beforeEach(() => {
  held.length = 0; probe.mockReset().mockResolvedValue('VULNORA_READY');
  detection.mockReset().mockImplementation(async id => ({ id, installed: true, ready: true }));
});
afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); });

describe('truthful provider initialization', () => {
  it('reports real substeps without marking a pending inference completed', async () => {
    const { runtime } = fixture();
    const steps: ProviderProgress[] = [];
    let finish!: (value: string) => void;
    probe.mockImplementation(config => config.provider === 'local' ? new Promise(resolve => { finish = resolve; }) : Promise.resolve('VULNORA_READY'));
    const prepared = runtime.prepare(step => steps.push(step));
    await vi.waitFor(() => expect(steps.at(-1)).toMatchObject({ label: 'Testing Ollama inference', status: 'active' }));
    expect(steps.filter(step => step.status === 'completed').map(step => step.label))
      .toEqual(['Discovering installed Ollama models', 'Loading Ollama model']);
    expect(detection).not.toHaveBeenCalled();
    finish('VULNORA_READY'); await prepared;
    expect(steps.filter(step => step.status === 'completed').map(step => step.label)).toEqual([
      'Discovering installed Ollama models', 'Loading Ollama model', 'Testing Ollama inference',
      'Checking codex CLI authentication', 'Testing codex inference', 'Using codex/configured-primary',
    ]);
    await runtime.close();
  });

  it('marks failed substeps and redacts their diagnostics while validating the fallback independently', async () => {
    const { runtime } = fixture(); const steps: ProviderProgress[] = [];
    probe.mockImplementation(async config => {
      if (config.provider === 'local') throw new Error('token=secret-fixture-value-1234567890');
      return 'VULNORA_READY';
    });
    await runtime.prepare(step => steps.push(step));
    expect(steps).toContainEqual(expect.objectContaining({ label: 'Testing Ollama inference', status: 'failed' }));
    expect(steps).not.toContainEqual(expect.objectContaining({ label: 'Testing Ollama inference', status: 'completed' }));
    expect(JSON.stringify(steps)).not.toContain('secret-fixture-value');
    expect(steps.at(-1)).toMatchObject({ label: 'Using codex/configured-primary', status: 'completed' });
    await runtime.close();
  });

  it('validates primary and installed local inference independently and attaches only the bounded fallback chain', async () => {
    const { runtime } = fixture();
    const description = await runtime.prepare();
    expect(probe.mock.calls.map(([config]) => config.provider)).toEqual(['local', 'codex']);
    expect(probe.mock.calls.every(([config]) => !config.fallbackChain?.length)).toBe(true);
    expect(probe.mock.calls[1][0].timeout).toBe(90000);
    expect(detection).toHaveBeenCalledWith('codex', 'configured-codex', expect.any(AbortSignal));
    expect(runtime.getConfig()).toMatchObject({ provider: 'codex', model: 'configured-primary',
      fallbackChain: [{ provider: 'local', model: 'installed:7b' }, { provider: 'deterministic', model: 'evidence-only' }] });
    expect(description).toContain('ready and held'); expect(held[0].stop).not.toHaveBeenCalled();
    await runtime.close(); expect(held[0].stop).toHaveBeenCalledOnce();
  });

  it('keeps authenticated primary available when Ollama is offline and logs the actual limitation', async () => {
    const { runtime } = fixture(); vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Ollama offline')));
    expect(await runtime.prepare()).toContain('Ollama offline');
    expect(runtime.getConfig()).toMatchObject({ provider: 'codex', fallbackChain: [{ provider: 'deterministic' }] });
    expect(held).toEqual([]); await runtime.close();
  });

  it('switches to validated local inference when native CLI authentication has expired', async () => {
    const { runtime } = fixture(); detection.mockResolvedValue({ id: 'codex', installed: true, ready: false });
    expect(await runtime.prepare()).toContain('authentication is not ready');
    expect(probe).toHaveBeenCalledOnce();
    expect(runtime.readiness).toMatchObject({ configured: { provider: 'codex' }, primary: { ready: false }, active: { provider: 'local' } });
    expect(runtime.getConfig()).toMatchObject({ provider: 'local', model: 'installed:7b' }); await runtime.close();
  });

  it('does not claim inference readiness merely because authentication succeeds', async () => {
    const { runtime } = fixture(); probe.mockImplementation(async config => config.provider === 'codex' ? 'No usable inference' : 'VULNORA_READY');
    expect(await runtime.prepare()).toContain('did not return the inference validation token');
    expect(runtime.getConfig().provider).toBe('local'); await runtime.close();
  });

  it('retains evidence-only access when both providers fail and redacts diagnostics', async () => {
    const { runtime } = fixture(); probe.mockRejectedValue(new Error('token=secret-fixture-value-1234567890'));
    await expect(runtime.prepare()).rejects.toThrow('active deterministic/evidence-only');
    expect(runtime.getConfig()).toEqual({ provider: 'deterministic', model: 'evidence-only', fallbackChain: undefined });
    expect(runtime.description()).not.toContain('secret-fixture-value'); expect(held[0].stop).toHaveBeenCalledOnce();
    await runtime.close();
  });

  it('does not warm, infer or download an arbitrary model when several installed models require a choice', async () => {
    const { runtime } = fixture(primary, ['first:7b', 'second:7b']);
    expect(await runtime.prepare()).toContain('Choose an installed Ollama model');
    expect(held).toEqual([]); expect(probe.mock.calls.map(([config]) => config.provider)).toEqual(['codex']);
    expect(vi.mocked(fetch).mock.calls.map(call => call[0])).toEqual(['http://127.0.0.1:11434/api/tags']);
    await runtime.close();
  });

  it('uses the sole installed model and probes local primary only once', async () => {
    const { runtime } = fixture(local, ['sole-installed:30b']);
    await runtime.prepare(); expect(probe).toHaveBeenCalledOnce();
    expect(runtime.getConfig()).toMatchObject({ provider: 'local', model: 'sole-installed:30b' });
    expect(detection).not.toHaveBeenCalled(); await runtime.close();
  });

  it('keeps the same model held when provider/key settings are revalidated', async () => {
    const { runtime } = fixture(); await runtime.prepare(); await runtime.prepare();
    expect(held).toHaveLength(1); expect(held[0].stop).not.toHaveBeenCalled();
    expect(held[0].start).toHaveBeenCalledTimes(2); await runtime.close(); expect(held[0].stop).toHaveBeenCalledOnce();
  });

  it('unloads a changed model before warming its replacement', async () => {
    const { runtime, selectedLocal } = fixture(primary, ['installed:7b', 'replacement:7b']);
    await runtime.prepare(); selectedLocal.model = 'replacement:7b'; await runtime.prepare();
    expect(held).toHaveLength(2); expect(held[0].stop).toHaveBeenCalledOnce();
    expect(held[0].stop.mock.invocationCallOrder[0]).toBeLessThan(held[1].start.mock.invocationCallOrder[0]);
    await runtime.close();
  });

  it('discovers only installed CLI options and deduplicates installed Ollama names', async () => {
    const { runtime } = fixture(primary, ['installed:7b', 'installed:7b']);
    detection.mockImplementation(async id => ({ id, installed: id === 'codex', ready: false }));
    expect(await runtime.installedAgents()).toEqual(['codex']);
    expect(await runtime.installedModels()).toEqual(['installed:7b']); await runtime.close();
  });

  it('propagates cancellation instead of misreporting unavailable providers', async () => {
    const { runtime, controller } = fixture();
    probe.mockImplementation(async () => { controller.abort(new Error('operator stopped')); throw controller.signal.reason; });
    await expect(runtime.prepare()).rejects.toThrow('operator stopped');
    expect(detection).not.toHaveBeenCalled(); await runtime.close();
  });

  it('rejects mock and non-AI modes as inference providers without running a probe', async () => {
    const controller = new AbortController();
    await expect(validateProvider({ provider: 'mock', model: 'mock' }, controller.signal)).rejects.toThrow('No AI inference');
    expect(probe).not.toHaveBeenCalled();
  });
});

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LLMConfig } from '../types/index.js';
const probe = vi.hoisted(() => vi.fn(async (_config: LLMConfig, _signal?: AbortSignal) => 'VULNORA_READY'));
const detection = vi.hoisted(() => vi.fn(async (id: string) => ({ id, installed: true, ready: true })));
const held = vi.hoisted(() => [] as { retain: ReturnType<typeof vi.fn>; start: ReturnType<typeof vi.fn>; stop: ReturnType<typeof vi.fn> }[]);
vi.mock('../llm/index.js', async () => {
  const { EventEmitter } = await import('eventemitter3');
  return { LLMBackbone: class extends EventEmitter {
    constructor(private config: LLMConfig) { super(); }
    setRetryConfig() {}
    getProvider() { return this.config.provider; }
    validateConfig() { return { valid: true }; }
    prompt(_text: string, _system: unknown, options?: { signal: AbortSignal }) { return probe(this.config, options?.signal); }
  } };
});
vi.mock('../agent/local-agents.js', () => ({ detectLocalAgent: detection }));
vi.mock('../llm/ollama-session.js', () => ({ createOllamaSession: () => {
  const session = { retain: vi.fn(), start: vi.fn(async () => {}), stop: vi.fn(async () => {}) }; held.push(session); return session;
} }));
import { LLMBackbone } from '../llm/index.js';
import { ProviderSession, validateProvider, type ProviderProgress } from '../llm/provider-session.js';
const primary: LLMConfig = { provider: 'codex', model: 'configured-primary', timeout: 120000 };
const local: LLMConfig = { provider: 'local', model: 'installed:7b', baseUrl: 'http://127.0.0.1:11434/api' };
function fixture(config: LLMConfig = primary) {
  const selectedLocal = { ...local };
  const source = { getLLMConfig: (provider?: string) => ({ ...(provider === 'local' ? selectedLocal : config) }),
    get: () => ({ command: 'configured-codex' }) } as never;
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ models: [{ name: 'installed:7b' }, { name: 'installed:7b' }] }) })));
  const controller = new AbortController(); const runtime = new ProviderSession(source, controller.signal);
  return { runtime, controller, selectedLocal };
}
beforeEach(() => {
  held.length = 0; probe.mockReset().mockResolvedValue('VULNORA_READY');
  detection.mockReset().mockImplementation(async id => ({ id, installed: true, ready: true }));
});
afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); });
describe('lazy local provider initialization', () => {
  it('updates the selected CLI model and effort without inference, detection, or local loading', () => {
    const primary: LLMConfig = { provider: 'codex', model: 'old', reasoningEffort: 'low' };
    const { runtime } = fixture(primary);
    primary.model = 'next'; primary.reasoningEffort = 'high'; runtime.updateSelection();
    expect(runtime.getConfig()).toMatchObject({ provider: 'codex', model: 'next', reasoningEffort: 'high',
      fallbackChain: [{ provider: 'local', model: 'installed:7b' }, { provider: 'deterministic' }] });
    expect(probe).not.toHaveBeenCalled(); expect(detection).not.toHaveBeenCalled(); expect(held).toHaveLength(0);
  });
  it('tests only the selected local fallback even when primary Codex is unavailable', async () => {
    const { runtime } = fixture();
    probe.mockImplementation(async config => { if (config.provider !== 'local') throw new Error('Codex usage limit'); return 'VULNORA_READY'; });
    expect(await runtime.prepare(undefined, undefined, 'local')).toContain('Local installed:7b: inference ready');
    expect(probe).toHaveBeenCalledOnce(); expect(probe.mock.calls[0][0]).toMatchObject({ provider: 'local', fallbackChain: [] });
    expect(detection).not.toHaveBeenCalled(); expect(runtime.getConfig().provider).toBe('codex');
    expect(runtime.readiness?.local.ready).toBe(true); expect(held[0].retain).toHaveBeenCalledOnce(); await runtime.close();
  });
  it('validates only the primary with no local discovery, loading or inference at startup', async () => {
    const { runtime } = fixture(); const steps: ProviderProgress[] = [];
    expect(await runtime.prepare(step => steps.push(step))).toContain('loaded on first use');
    expect(fetch).not.toHaveBeenCalled(); expect(held[0].start).not.toHaveBeenCalled(); expect(held[0].retain).not.toHaveBeenCalled();
    expect(probe.mock.calls.map(([config]) => config.provider)).toEqual(['codex']);
    expect(probe.mock.calls[0][0]).toMatchObject({ timeout: 90000, fallbackChain: [] });
    expect(steps.filter(step => step.status === 'completed').map(step => step.label)).toEqual([
      'Checking codex CLI authentication', 'Testing codex inference', 'Using codex/configured-primary',
    ]);
    expect(runtime.getConfig()).toMatchObject({ provider: 'codex', fallbackChain: [{ provider: 'local', model: 'installed:7b' }, { provider: 'deterministic' }] });
    await runtime.close();
  });
  it('does not inject or download a built-in model when none is selected', async () => {
    const { runtime, selectedLocal } = fixture(); selectedLocal.model = ''; await runtime.prepare();
    expect(runtime.getConfig().fallbackChain).toEqual([{ provider: 'deterministic', model: 'evidence-only' }]);
    expect(held).toEqual([]); expect(fetch).not.toHaveBeenCalled(); await runtime.close();
  });
  it('defers local primary inference and retains it only on an actual request', async () => {
    const { runtime } = fixture(local); await runtime.prepare();
    expect(probe).not.toHaveBeenCalled(); expect(fetch).not.toHaveBeenCalled();
    const backbone = new LLMBackbone(runtime.getConfig()); runtime.track(backbone); backbone.emit('request:start', { messages: [] });
    expect(held[0].retain).toHaveBeenCalledOnce(); expect(runtime.readiness?.primary.ready).toBe(false); await runtime.close();
  });
  it('retains local fallback only when engaged', async () => {
    const { runtime } = fixture(); await runtime.prepare(); const backbone = new LLMBackbone(runtime.getConfig()); runtime.track(backbone);
    backbone.emit('request:start', { messages: [] }); expect(held[0].retain).not.toHaveBeenCalled();
    backbone.emit('request:fallback', { fromProvider: 'codex', fromModel: primary.model, toProvider: 'local', toModel: local.model, engaged: true, reason: 'unavailable' });
    expect(held[0].retain).toHaveBeenCalledOnce(); await runtime.close(); expect(held[0].stop).toHaveBeenCalledOnce();
  });
  it('keeps Codex first after a failed check and redacts diagnostics', async () => {
    const { runtime } = fixture(); probe.mockRejectedValue(new Error('token=secret-fixture-value-1234567890'));
    expect(await runtime.prepare()).toContain('active codex/configured-primary');
    expect(runtime.getConfig().provider).toBe('codex'); expect(runtime.description()).not.toContain('secret-fixture-value'); await runtime.close();
  });
  it('skips a pending primary check while retaining the selection', async () => {
    const { runtime } = fixture(); const skip = new AbortController();
    probe.mockImplementation(async (_config, signal) => {
      if (!signal) throw new Error('Missing check cancellation signal');
      return new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));
    });
    const pending = runtime.prepare(undefined, skip.signal); await vi.waitFor(() => expect(probe).toHaveBeenCalledOnce());
    skip.abort(new DOMException('Check skipped', 'AbortError'));
    expect(await pending).toContain('check skipped'); expect(runtime.getConfig().provider).toBe('codex'); await runtime.close();
  });
  it('discovers and deduplicates Ollama and OpenAI-compatible models on demand', async () => {
    const { runtime, selectedLocal } = fixture(); expect(await runtime.installedModels()).toEqual(['installed:7b']);
    expect(fetch).toHaveBeenLastCalledWith('http://127.0.0.1:11434/api/tags', expect.any(Object));
    selectedLocal.baseUrl = 'http://127.0.0.1:1234/v1';
    vi.mocked(fetch).mockResolvedValueOnce({ ok: true, json: async () => ({ data: [{ id: 'served-model' }] }) } as Response);
    expect(await runtime.installedModels()).toEqual(['served-model']);
    expect(fetch).toHaveBeenLastCalledWith('http://127.0.0.1:1234/v1/models', expect.any(Object)); await runtime.close();
  });
  it('allows discovery to finish after a cold daemon start longer than ten seconds', async () => {
    const { runtime } = fixture();
    vi.useFakeTimers();
    const timeout = vi.spyOn(AbortSignal, 'timeout').mockImplementation(milliseconds => {
      const controller = new AbortController();
      setTimeout(() => controller.abort(new DOMException('Timed out', 'TimeoutError')), milliseconds);
      return controller.signal;
    });
    try {
      vi.mocked(fetch).mockImplementationOnce((_url, init) => new Promise((resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true });
        setTimeout(() => resolve(new Response('{"models":[{"name":"cold-start:7b"}]}')), 11000);
      }));
      const pending = expect(runtime.installedModels()).resolves.toEqual(['cold-start:7b']);
      await vi.advanceTimersByTimeAsync(11000);
      await pending;
      expect(probe).not.toHaveBeenCalled();
    } finally { timeout.mockRestore(); vi.useRealTimers(); await runtime.close(); }
  });
  it('releases a replaced model without eagerly loading the replacement', async () => {
    const { runtime, selectedLocal } = fixture(); await runtime.prepare(); selectedLocal.model = 'replacement:7b'; await runtime.prepare();
    expect(held).toHaveLength(2); expect(held[0].stop).toHaveBeenCalledOnce(); expect(held[1].start).not.toHaveBeenCalled(); await runtime.close();
  });
  it('propagates application cancellation', async () => {
    const { runtime, controller } = fixture(); probe.mockImplementation(async () => { controller.abort(new Error('operator stopped')); throw controller.signal.reason; });
    await expect(runtime.prepare()).rejects.toThrow('operator stopped'); await runtime.close();
  });
  it('rejects non-AI modes as inference providers', async () => {
    await expect(validateProvider({ provider: 'mock', model: 'mock' }, new AbortController().signal)).rejects.toThrow('No AI inference');
    expect(probe).not.toHaveBeenCalled();
  });
});

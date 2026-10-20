import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { classifyErrorKind, LLMApiError, LLMBackbone, type LLMProviderAdapter } from '../llm/index.js';
import { classifyRefusal, DEFAULT_FALLBACK_POLICY, permitsFallback } from '../llm/fallback-policy.js';
import type { LLMConfig, LLMResponse } from '../types/index.js';

afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); });

function fixture(overrides: Partial<LLMConfig> = {}) {
  vi.stubEnv('VULNORA_FALLBACK_AUDIT_LOG', 'off');
  const backbone = new LLMBackbone({ provider: 'mock', model: 'primary', apiKey: 'primary-only-key',
    baseUrl: 'https://primary.invalid/v1', fallbackChain: [{ provider: 'mock', model: 'fallback' }], ...overrides });
  backbone.setRetryConfig(3, 0);
  const primary = vi.fn<LLMProviderAdapter['chat']>();
  const fallback = vi.fn<LLMProviderAdapter['chat']>().mockResolvedValue({ model: 'fallback', content: 'Recovered' });
  const internal = backbone as unknown as { adapter: LLMProviderAdapter; createAdapter(config: LLMConfig): LLMProviderAdapter };
  internal.adapter = { name: 'fixture', chat: primary, validateConfig: () => ({ valid: true }) };
  const create = vi.spyOn(internal, 'createAdapter').mockReturnValue({ name: 'fixture-fallback', chat: fallback, validateConfig: () => ({ valid: true }) });
  return { backbone, primary, fallback, create };
}

describe('fallback policy', () => {
  it.each(['openai', 'openrouter', 'local', 'anthropic'] as const)('respects structured %s refusal fields even without recognizable prose', async provider => {
    vi.stubEnv('VULNORA_FALLBACK_AUDIT_LOG', 'off');
    const response = provider === 'anthropic'
      ? { content: [{ type: 'text', text: 'Declined' }], stop_reason: 'refusal', model: 'primary' }
      : { choices: [{ message: { content: null, refusal: 'Declined' }, finish_reason: 'stop' }], model: 'primary' };
    const fetch = vi.fn(async () => new Response(JSON.stringify(response), { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    const backbone = new LLMBackbone({ provider, model: 'primary', apiKey: 'fixture-only-key', baseUrl: 'http://127.0.0.1:1234/v1',
      fallbackPolicy: { ...DEFAULT_FALLBACK_POLICY, onRefusal: true }, fallbackChain: [{ provider: 'mock', model: 'unused' }] });
    expect(await backbone.prompt('Inspect the local fixture')).toBe('Declined');
    expect(fetch).toHaveBeenCalledOnce(); expect(backbone.getActiveProvider().provider).toBe(provider);
  });

  it('separates safety, technical and unclear refusals', () => {
    expect(classifyRefusal('I cannot assist because of a network connection failure.')).toBe('technical_refusal');
    expect(classifyRefusal('I cannot help with that request.')).toBe('unclear_refusal');
    expect(classifyRefusal('I cannot help because it violates safety policy. Network retries will not help.')).toBe('security_refusal');
    expect(classifyRefusal('', 'content_filter')).toBe('security_refusal');
    expect(classifyErrorKind(new Error("You've hit your usage limit. Try again tomorrow."))).toBe('quota');
    expect(classifyErrorKind(new Error('Too many requests'))).toBe('rate_limit');
  });

  it.each([
    ['network', 'onApiError'], ['empty', 'onApiError'], ['quota', 'onRateLimit'], ['rate_limit', 'onRateLimit'],
  ] as const)('honors the independent %s switch', (reason, setting) => {
    expect(permitsFallback(reason, { ...DEFAULT_FALLBACK_POLICY, [setting]: false })).toBe(false);
    expect(permitsFallback(reason, { ...DEFAULT_FALLBACK_POLICY, enabled: false })).toBe(false);
  });

  it.each([false, true])('does not reroute or retry security refusals with onRefusal=%s', async onRefusal => {
    const f = fixture({ fallbackPolicy: { ...DEFAULT_FALLBACK_POLICY, onRefusal } });
    f.primary.mockRejectedValue(new LLMApiError('Content flagged for possible cybersecurity risk', 403));
    await expect(f.backbone.prompt('Review the fixture')).rejects.toThrow('cybersecurity risk');
    expect(f.primary).toHaveBeenCalledOnce(); expect(f.create).not.toHaveBeenCalled();
  });

  it('returns a filtered response without executing its partial tool calls', async () => {
    const f = fixture({ fallbackPolicy: { ...DEFAULT_FALLBACK_POLICY, onRefusal: true } });
    f.primary.mockResolvedValue({ model: 'primary', content: '', finishReason: 'content_filter',
      toolCalls: [{ id: 'partial', name: 'http_request', arguments: {} }] });
    const response = await f.backbone.chat([{ role: 'user', content: 'Review' }]);
    expect(response.toolCalls).toBeUndefined(); expect(f.create).not.toHaveBeenCalled();
  });

  it('does not switch on an unclear refusal by default', async () => {
    const f = fixture(); f.primary.mockResolvedValue({ model: 'primary', content: 'I cannot help with that.' });
    expect(await f.backbone.prompt('Review')).toBe('I cannot help with that.');
    expect(f.create).not.toHaveBeenCalled();
  });

  it('reevaluates a technical refusal only with opt-in, preserving the original authorization context', async () => {
    const f = fixture({ fallbackPolicy: { ...DEFAULT_FALLBACK_POLICY, onRefusal: true } });
    f.primary.mockResolvedValue({ model: 'primary', content: 'I cannot help because of a network connection failure.' });
    const messages = [{ role: 'user' as const, content: 'Review the local fixture within the supplied scope.' }];
    await f.backbone.chat(messages);
    expect(f.fallback.mock.calls[0][0]).toEqual(messages);
    expect(f.create.mock.calls[0][0]).toMatchObject({ apiKey: undefined, baseUrl: undefined });
  });

  it('skips same-model retries for quota errors and honors a disabled rate-limit fallback', async () => {
    const f = fixture({ fallbackPolicy: { ...DEFAULT_FALLBACK_POLICY, onRateLimit: false } });
    f.primary.mockRejectedValue(new Error('Codex usage limit reached'));
    await expect(f.backbone.prompt('Review')).rejects.toThrow('usage limit');
    expect(f.primary).toHaveBeenCalledOnce(); expect(f.create).not.toHaveBeenCalled();
  });

  it('deduplicates the finite ladder and never returns to the primary within a request', async () => {
    const f = fixture({ baseUrl: undefined, fallbackChain: [
      { provider: 'mock', model: 'primary' }, { provider: 'mock', model: 'fallback' }, { provider: 'mock', model: 'fallback' },
    ] });
    f.primary.mockRejectedValue(new LLMApiError('offline', 503));
    f.fallback.mockRejectedValue(new LLMApiError('offline', 503));
    await expect(f.backbone.prompt('Review')).rejects.toThrow('offline');
    expect(f.primary).toHaveBeenCalledTimes(3); expect(f.fallback).toHaveBeenCalledTimes(3);
    expect(f.create).toHaveBeenCalledOnce();
  });

  it('records a stopped refusal as well as successful technical recovery', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-policy-'));
    try {
      const f = fixture(); const path = join(directory, 'audit.jsonl');
      vi.stubEnv('VULNORA_FALLBACK_AUDIT_LOG', path);
      f.primary.mockResolvedValueOnce({ model: 'primary', content: 'I cannot help due to safety policy.' } as LLMResponse);
      await f.backbone.prompt('Review');
      f.primary.mockRejectedValue(new Error('usage limit reached'));
      await f.backbone.prompt('Review');
      const entries = (await readFile(path, 'utf8')).trim().split('\n').map(line => JSON.parse(line));
      expect(entries).toEqual(expect.arrayContaining([
        expect.objectContaining({ event: 'fallback_stopped', reason: 'security_refusal' }),
        expect.objectContaining({ event: 'fallback_trigger', reason: 'quota' }),
        expect.objectContaining({ event: 'fallback_result', status: 'success' }),
      ]));
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
});

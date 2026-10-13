import { afterEach, describe, expect, it, vi } from 'vitest';
import { createOllamaSession } from '../llm/ollama-session.js';
import { LLMBackbone } from '../llm/index.js';
import type { LLMConfig } from '../types/index.js';

afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); });

const settings: LLMConfig = {
  provider: 'codex', model: 'codex-default',
  fallbackChain: [{ provider: 'local', model: 'test-model', baseUrl: 'http://127.0.0.1:11434/api' }],
};

describe('Ollama CLI session lifecycle', () => {
  it('preloads with the chat context, holds the model across chat, and unloads once on exit', async () => {
    vi.stubEnv('VULNORA_LOCAL_KEEP_ALIVE', '5m');
    const bodies: Array<Record<string, unknown>> = [];
    vi.stubGlobal('fetch', vi.fn(async (url, init) => {
      if (String(url).endsWith('/ps')) return new Response(JSON.stringify({ models: [] }));
      bodies.push(JSON.parse(init.body));
      return new Response(JSON.stringify({ message: { content: 'ready' }, done: true }));
    }));
    const session = createOllamaSession(settings);
    await session.start();
    const llm = new LLMBackbone({ provider: 'local', model: 'test-model', baseUrl: 'http://127.0.0.1:11434/api' });
    expect((await llm.chat([{ role: 'user', content: 'connection check' }])).content).toBe('ready');
    expect(bodies[0]).toMatchObject({ model: 'test-model', keep_alive: -1, options: { num_ctx: 32768 } });
    expect(bodies[1]).toMatchObject({ keep_alive: -1, options: { num_ctx: 32768 } });
    await Promise.all([session.stop(), session.stop()]);
    expect(bodies).toHaveLength(3);
    expect(bodies[2]).toEqual({ model: 'test-model', stream: false, keep_alive: 0 });
    expect(process.env.VULNORA_LOCAL_KEEP_ALIVE).toBe('5m');
  });

  it.each([['-1', -1], ['0', 0], ['30', 30], ['5m', '5m']])('sends keep-alive %s in Ollama wire format', async (setting, expected) => {
    vi.stubEnv('VULNORA_LOCAL_KEEP_ALIVE', String(setting));
    const fetch = vi.fn(async (_url, init) => {
      expect(JSON.parse(init.body).keep_alive).toBe(expected);
      return new Response(JSON.stringify({ message: { content: 'ready' }, done: true }));
    });
    vi.stubGlobal('fetch', fetch);
    const llm = new LLMBackbone({ provider: 'local', model: 'test-model', baseUrl: 'http://127.0.0.1:11434/api' });
    await llm.chat([{ role: 'user', content: 'connection check' }]);
    expect(fetch).toHaveBeenCalledOnce();
  });

  it.each([
    { provider: 'codex', model: 'codex-default' },
    { provider: 'local', model: 'test-model', baseUrl: 'http://127.0.0.1:1234/v1' },
  ] as LLMConfig[])('leaves non-Ollama providers untouched: $provider / $baseUrl', async config => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    const session = createOllamaSession(config);
    await session.start();
    await session.stop();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('fails clearly on startup and still releases the model and session setting', async () => {
    vi.stubEnv('VULNORA_LOCAL_KEEP_ALIVE', '10m');
    const fetch = vi.fn().mockResolvedValueOnce(new Response(null, { status: 404 })).mockResolvedValueOnce(new Response('{}'))
      .mockResolvedValueOnce(new Response('{"models":[]}'));
    vi.stubGlobal('fetch', fetch);
    const session = createOllamaSession(settings);
    await expect(session.start()).rejects.toThrow('load failed: HTTP 404');
    await session.stop();
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(process.env.VULNORA_LOCAL_KEEP_ALIVE).toBe('10m');
  });

  it('waits for actual model removal after the unload API acknowledgement and leaves other models untouched', async () => {
    let polls = 0;
    const fetch = vi.fn(async (url: string) => {
      if (url.endsWith('/ps')) {
        polls++;
        return new Response(JSON.stringify({ models: polls === 1 ? [{ name: 'test-model' }, { name: 'another-model' }] : [{ name: 'another-model' }] }));
      }
      return new Response('{}');
    });
    vi.stubGlobal('fetch', fetch);
    const session = createOllamaSession(settings);
    await session.start();
    const stopping = session.stop();
    const repeated = session.stop();
    await stopping;
    await expect(repeated).resolves.toBeUndefined();
    expect(polls).toBe(2);
    expect(fetch.mock.calls.filter(([url]) => url.endsWith('/generate'))).toHaveLength(2);
  });
});

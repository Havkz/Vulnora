import type { LLMConfig } from '../types/index.js';

/** Hold the configured Ollama model for one CLI session, then release its memory. */
export function createOllamaSession(config: LLMConfig) {
  const local = [config, ...(config.fallbackChain || [])].find(entry => entry.provider === 'local');
  const baseUrl = (local?.baseUrl || 'http://127.0.0.1:11434/api').replace(/\/$/, '');
  const enabled = Boolean(local) && /\/api$/.test(baseUrl);
  const previousKeepAlive = process.env.VULNORA_LOCAL_KEEP_ALIVE;
  const controller = new AbortController();
  let active = false;
  let stopping: Promise<void> | undefined;

  async function request(keepAlive: number, signal: AbortSignal): Promise<void> {
    const response = await fetch(`${baseUrl}/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: local?.model, stream: false, keep_alive: keepAlive,
        ...(keepAlive < 0 ? { options: { num_ctx: Math.max(4096, Number(process.env.VULNORA_LOCAL_NUM_CTX || 32768) || 32768) } } : {}),
      }),
      signal,
    });
    if (!response.ok) throw new Error(`Ollama model ${keepAlive < 0 ? 'load' : 'unload'} failed: HTTP ${response.status}`);
    await response.json();
  }

  return {
    async start(): Promise<void> {
      if (!enabled) return;
      active = true;
      process.env.VULNORA_LOCAL_KEEP_ALIVE = '-1';
      await request(-1, AbortSignal.any([controller.signal, AbortSignal.timeout(300000)]));
    },
    async stop(): Promise<void> {
      if (!active) return;
      stopping ??= (async () => {
        controller.abort();
        try { await request(0, AbortSignal.timeout(30000)); }
        finally {
          if (previousKeepAlive === undefined) delete process.env.VULNORA_LOCAL_KEEP_ALIVE;
          else process.env.VULNORA_LOCAL_KEEP_ALIVE = previousKeepAlive;
        }
      })();
      await stopping;
    },
  };
}

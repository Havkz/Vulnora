import { afterEach, describe, expect, it, vi } from 'vitest';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { LLMBackbone } from '../llm/index.js';
import { DEFAULT_FALLBACK_POLICY } from '../llm/fallback-policy.js';
import type { LLMConfig } from '../types/index.js';

const question = [{ role: 'user' as const, content: 'Describe the local fixture.' }];
const chunk = (content: string, finish_reason: string | null = null) =>
  `data: ${JSON.stringify({ model: 'actual-model', choices: [{ delta: { content }, finish_reason }] })}\n\n`;
const done = 'data: [DONE]\n\n';
afterEach(() => { vi.unstubAllEnvs(); });

async function fixture(run: (body: Record<string, unknown>, res: ServerResponse, req: IncomingMessage) => void,
  overrides: Partial<LLMConfig> = {}) {
  vi.stubEnv('VULNORA_FALLBACK_AUDIT_LOG', 'off');
  const requests: Record<string, unknown>[] = [];
  const server = createServer(async (req, res) => {
    let body = ''; for await (const part of req) body += part;
    const parsed = JSON.parse(body); requests.push(parsed); run(parsed, res, req);
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}/v1`;
  const llm = new LLMBackbone({ provider: 'openrouter', model: 'primary', apiKey: 'fixture-key', baseUrl,
    timeout: 10000, fallbackChain: [{ provider: 'openrouter', model: 'backup', baseUrl, apiKey: 'backup-key' }], ...overrides });
  llm.setRetryConfig(1, 0);
  return { llm, requests, close: async () => {
    server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
  } };
}
async function collect(llm: LLMBackbone) {
  const output: string[] = []; for await (const part of llm.stream(question)) output.push(part); return output;
}

describe('streaming request policy and transport', () => {
  it('yields live tokens, preserves messages/options, reports the actual model and closes on consumer return', async () => {
    let finish!: () => void;
    const closed = new Promise<void>(resolve => { finish = resolve; });
    const f = await fixture((_body, res) => {
      res.on('close', finish); res.writeHead(200, { 'content-type': 'text/event-stream' });
      const bytes = Buffer.from(chunk('Grüße'));
      const split = bytes.indexOf(Buffer.from('ü')) + 1;
      res.write(bytes.subarray(0, split)); res.write(bytes.subarray(split));
    });
    try {
      const end = vi.fn(); const complete = vi.fn(); const tokens = vi.fn();
      f.llm.on('request:end', end); f.llm.on('request:complete', complete); f.llm.on('token:stream', tokens);
      const messages = [...question, { role: 'tool' as const, content: 'observed', toolCallId: 'call-1', name: 'fixture' }];
      const iterator = f.llm.stream(messages, { topP: 0.6, stopSequences: ['STOP'] });
      expect(await iterator.next()).toEqual({ done: false, value: 'Grüße' });
      expect(f.llm.getActiveProvider()).toEqual({ provider: 'openrouter', model: 'actual-model' });
      expect(f.requests[0]).toMatchObject({ stream: true, top_p: 0.6, stop: ['STOP'],
        messages: [question[0], { role: 'tool', content: 'observed', tool_call_id: 'call-1', name: 'fixture' }] });
      await iterator.return(); await closed;
      expect(end).toHaveBeenCalledOnce(); expect(complete).not.toHaveBeenCalled(); expect(tokens).toHaveBeenCalledOnce();
      expect(f.requests).toHaveLength(1);
    } finally { await f.close(); }
  });

  it('uses the configured fallback before any output and retains completion metadata', async () => {
    const f = await fixture((body, res) => {
      if (body.model === 'primary') { res.writeHead(429); res.end('Rate limit exceeded'); return; }
      res.end(chunk('Recovered', 'stop') + done);
    });
    try {
      const complete = vi.fn(); const transitions = vi.fn();
      f.llm.on('request:complete', complete); f.llm.on('request:fallback', transitions);
      expect(await collect(f.llm)).toEqual(['Recovered']);
      expect(f.requests.map(r => r.model)).toEqual(['primary', 'backup']);
      expect(complete).toHaveBeenCalledWith(expect.objectContaining({ response: expect.objectContaining({ content: 'Recovered', finishReason: 'stop' }) }));
      expect(transitions).toHaveBeenCalledWith(expect.objectContaining({ reason: 'rate_limit', toModel: 'backup' }));
    } finally { await f.close(); }
  });

  it('honors disabled fallback for stream HTTP failures', async () => {
    const f = await fixture((_body, res) => { res.writeHead(429); res.end('Rate limit'); },
      { fallbackPolicy: { ...DEFAULT_FALLBACK_POLICY, onRateLimit: false } });
    try { await expect(collect(f.llm)).rejects.toThrow('429'); expect(f.requests).toHaveLength(1); }
    finally { await f.close(); }
  });

  it.each(['in-band', 'truncated', 'malformed'])('never replays a partially delivered %s response', async failure => {
    const f = await fixture((_body, res) => {
      res.end(chunk('Partial') + (failure === 'in-band' ? 'data: {"error":{"code":503,"message":"Service failed"}}\n\n'
        : failure === 'malformed' ? 'data: broken-json\n\n' : ''));
    });
    try {
      f.llm.setRetryConfig(3, 0);
      const complete = vi.fn(); const end = vi.fn(); f.llm.on('request:complete', complete); f.llm.on('request:end', end);
      const iterator = f.llm.stream(question);
      expect((await iterator.next()).value).toBe('Partial');
      await expect(iterator.next()).rejects.toThrow();
      expect(f.requests).toHaveLength(1); expect(complete).not.toHaveBeenCalled(); expect(end).toHaveBeenCalledOnce();
    } finally { await f.close(); }
  });

  it('does not reroute structured safety refusals even with refusal fallback enabled', async () => {
    const f = await fixture((_body, res) => res.end('data: {"choices":[{"delta":{"refusal":"Declined"},"finish_reason":"stop"}]}\n\n'),
      { fallbackPolicy: { ...DEFAULT_FALLBACK_POLICY, onRefusal: true } });
    try {
      const refusal = vi.fn(); f.llm.on('request:refusal', refusal);
      expect(await collect(f.llm)).toEqual(['Declined']); expect(f.requests).toHaveLength(1); expect(refusal).toHaveBeenCalledOnce();
    } finally { await f.close(); }
  });

  it('closes a pending read on caller cancellation without retrying', async () => {
    const f = await fixture((_body, res) => { res.writeHead(200); res.write(chunk('First')); });
    try {
      const controller = new AbortController(); const iterator = f.llm.stream(question, { signal: controller.signal });
      expect((await iterator.next()).value).toBe('First');
      const pending = iterator.next(); controller.abort(new Error('User paused'));
      await expect(pending).rejects.toThrow('User paused'); expect(f.requests).toHaveLength(1);
    } finally { await f.close(); }
  });

  it('applies the idle timeout while waiting for response headers', async () => {
    const f = await fixture(() => {}, { timeout: 100, fallbackChain: [] });
    try { await expect(collect(f.llm)).rejects.toThrow(/timeout/i); expect(f.requests).toHaveLength(1); }
    finally { await f.close(); }
  });

  it('uses the complete response path for tool definitions instead of losing tool call fragments', async () => {
    const f = await fixture((_body, res) => res.end(JSON.stringify({ model: 'actual-model', choices: [{
      message: { content: 'Ready' }, finish_reason: 'stop' }] })));
    try {
      const output = [];
      for await (const part of f.llm.stream(question, { tools: [{ name: 'fixture', description: 'Read fixture', parameters: { type: 'object', properties: {} } }] })) output.push(part);
      expect(output).toEqual(['Ready']); expect(f.requests[0].stream).toBeUndefined(); expect(f.requests[0].tools).toHaveLength(1);
    } finally { await f.close(); }
  });
  it('parses CRLF, multiline data, comments, usage and a final event without a newline', async () => {
    const f = await fixture((_body, res) => res.end(': heartbeat\r\n\r\ndata: {"model":"wire-model",\r\n'
      + 'data: "choices":[{"delta":{"content":"OK"},"finish_reason":"stop"}]}\r\n\r\n'
      + 'data: {"choices":[],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}'));
    try {
      const complete = vi.fn(); f.llm.on('request:complete', complete);
      expect(await collect(f.llm)).toEqual(['OK']);
      expect(complete).toHaveBeenCalledWith(expect.objectContaining({ response: {
        content: 'OK', model: 'wire-model', finishReason: 'stop', usage: { promptTokens: 2, completionTokens: 1, totalTokens: 3 },
      } }));
    } finally { await f.close(); }
  });

  it.each(['empty', 'error'])('recovers a pre-output %s stream through the same bounded ladder', async failure => {
    const f = await fixture((body, res) => res.end(body.model === 'primary'
      ? failure === 'empty' ? done : 'data: {"error":{"code":503,"message":"Unavailable"}}\n\n'
      : chunk('Recovered', 'stop') + done));
    try {
      expect(await collect(f.llm)).toEqual(['Recovered']);
      expect(f.requests.map(r => r.model)).toEqual(['primary', 'backup']);
    } finally { await f.close(); }
  });

  it('does not splice another model onto a textual refusal already delivered', async () => {
    const f = await fixture((_body, res) => res.end(chunk('I cannot help due to a network connection failure.', 'stop') + done),
      { fallbackPolicy: { ...DEFAULT_FALLBACK_POLICY, onRefusal: true } });
    try {
      expect(await collect(f.llm)).toEqual(['I cannot help due to a network connection failure.']);
      expect(f.requests).toHaveLength(1);
    } finally { await f.close(); }
  });

  it('keeps an in-flight stream on its original config and applies changes to the next request', async () => {
    let finish!: () => void;
    const f = await fixture((_body, res) => {
      res.write(chunk('First')); finish = () => res.end(chunk(' last', 'stop') + done);
    });
    try {
      const stream = f.llm.stream(question); expect((await stream.next()).value).toBe('First');
      f.llm.updateConfig({ provider: 'mock', model: 'next-model', fallbackChain: [] });
      expect(f.llm.getActiveProvider().model).toBe('actual-model');
      finish(); expect((await stream.next()).value).toBe(' last'); expect((await stream.next()).done).toBe(true);
      await f.llm.chat(question); expect(f.llm.getModel()).toBe('next-model');
      expect(f.llm.getActiveProvider()).toEqual({ provider: 'mock', model: 'mock-model' });
      expect(f.requests).toHaveLength(1);
    } finally { await f.close(); }
  });

});

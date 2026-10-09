/**
 * REGRESSION (keyless-path bug): the local-agent / codex text-CLI backbones must surface `toolCalls`
 * parsed from the agent's reply. If they don't, the ReAct loop takes its "final answer" branch on
 * turn 0 and every operator abstains without ever running the Arsenal. These tests pin the fix AND
 * the parser-hardening from the PR #16 audit (over-match, ReDoS, drift-abstains, string args, Codex coverage).
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { EventEmitter } from 'events';

// Mock the local-agent CLI bridge (LocalAgentAdapter) and the codex spawn/file read (CodexAdapter).
vi.mock('../agent/local-agents.js', () => ({
  localAgentChat: vi.fn(),
  resolveBin: vi.fn((binary: string) => binary),
  spawnAgent: vi.fn(() => {
    const child = new EventEmitter() as EventEmitter & { stdin: EventEmitter & { end: () => void }; stdout: EventEmitter; stderr: EventEmitter };
    child.stdin = Object.assign(new EventEmitter(), { end: () => setTimeout(() => child.emit('close', 0), 0) });
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    return child;
  }),
}));
vi.mock('fs/promises', async (orig) => {
  const actual = await orig<typeof import('fs/promises')>();
  return { ...actual, readFile: vi.fn() };
});

import { classifyErrorKind, parseTextToolCalls, shouldAdvanceFallback, LLMBackbone } from '../llm/index.js';
import { localAgentChat } from '../agent/local-agents.js';
import { readFile } from 'fs/promises';
const cli = vi.mocked(localAgentChat);
const fileRead = vi.mocked(readFile as unknown as (...a: unknown[]) => Promise<string>);

const TOOLS = [{
  name: 'nmap_scan', description: 'port scan a host',
  parameters: { type: 'object' as const, properties: { target: { type: 'string' } }, required: ['target'] },
}];
const localBackbone = () => new LLMBackbone({ provider: 'local-agent', model: 'codex' } as never);
const codexBackbone = () => new LLMBackbone({ provider: 'codex', model: 'codex-default' } as never);

describe('parseTextToolCalls — happy path + drift tolerance', () => {
  it('parses a contracted fenced block', () => {
    expect(parseTextToolCalls('reasoning\n```json\n{"tool_calls":[{"name":"nmap_scan","arguments":{"target":"x"}}]}\n```'))
      .toMatchObject([{ name: 'nmap_scan', arguments: { target: 'x' } }]);
  });
  it('prose-only debrief is the final answer (no calls)', () => {
    expect(parseTextToolCalls('Surface exhausted; no findings. Abstaining.')).toBeUndefined();
  });
  // --- audit must-fixes below ---
  it('unfenced object + a stray brace elsewhere still parses (was: greedy over-match → silent abstain)', () => {
    const r = parseTextToolCalls('example shape {"x":1}\n{"tool_calls":[{"name":"port_scan","arguments":{"host":"h"}}]}\ntrailing {note}');
    expect(r).toHaveLength(1);
    expect(r![0].name).toBe('port_scan');
  });
  it('tolerates a trailing comma', () => {
    expect(parseTextToolCalls('```json\n{"tool_calls":[{"name":"nmap_scan","arguments":{"target":"x"}},]}\n```')).toHaveLength(1);
  });
  it('accepts a single un-wrapped {name,arguments} object', () => {
    expect(parseTextToolCalls('```json\n{"name":"nmap_scan","arguments":{"target":"x"}}\n```')).toMatchObject([{ name: 'nmap_scan' }]);
  });
  it('accepts an "actions" wrapper key', () => {
    expect(parseTextToolCalls('{"actions":[{"name":"curl_request","arguments":{}}]}')).toHaveLength(1);
  });
  it('coerces a string "arguments" into an object (scope-gate blind-spot fix)', () => {
    const r = parseTextToolCalls('{"tool_calls":[{"name":"nmap_scan","arguments":"{\\"target\\":\\"x\\"}"}]}');
    expect(r![0].arguments).toEqual({ target: 'x' });
  });
  it('is DoS-safe on pathological brace input (was: quadratic ReDoS)', () => {
    const t0 = Date.now();
    expect(parseTextToolCalls('{'.repeat(80000))).toBeUndefined();
    expect(Date.now() - t0).toBeLessThan(300); // bounded — the old greedy regex took ~2100ms
  });
});

describe('Codex CLI failure classification', () => {
  it('does not mistake a timeout word in the echoed prompt for the actual failure', () => {
    const echoedPrompt = `port_scan timeout: number ${'x'.repeat(2200)}`;
    const error = new Error(`Codex CLI exited 1: ${echoedPrompt}\nstream disconnected before completion`);
    expect(classifyErrorKind(error)).toBe('network');
  });

  it('classifies Codex input limits as context length rather than network', () => {
    const error = new Error('Codex CLI exited 1: turn/start failed: Input exceeds the maximum length of 1048576 characters (input_too_large)');
    expect(classifyErrorKind(error)).toBe('context_length');
  });

  it('classifies Codex cybersecurity policy blocks as refusals', () => {
    const error = new Error(
      'Codex CLI exited 1: ERROR: This content was flagged for possible cybersecurity risk. '
      + 'Join the Trusted Access for Cyber program.'
    );
    expect(classifyErrorKind(error)).toBe('refusal');
  });

  it('allows Ollama fallback for every Codex failure, including timeout and refusal', () => {
    expect(shouldAdvanceFallback('codex', 0, 'timeout')).toBe(true);
    expect(shouldAdvanceFallback('codex', 0, 'refusal')).toBe(true);
    expect(shouldAdvanceFallback('codex', 0, 'network')).toBe(true);
    expect(shouldAdvanceFallback('codex', 0, 'context_length')).toBe(true);
    expect(shouldAdvanceFallback('local', 0, 'network')).toBe(true);
  });
});

describe('local-agent backbone surfaces toolCalls (keyless-path fix)', () => {
  it('describes the current ACTION CONTRACT to the local agent', async () => {
    cli.mockResolvedValueOnce('Final debrief.');
    await localBackbone().chatWithTools([{ role: 'user', content: 'scan' }], TOOLS as never);
    const prompt = String(cli.mock.calls.at(-1)?.[1] || '');
    expect(prompt).toContain('ACTION CONTRACT');
    expect(prompt).toContain('nmap_scan');
    expect(prompt).toContain('nmap_scan(target*: string)');
    expect(prompt).not.toContain('port scan a host');
    expect(prompt.match(/nmap_scan\(/g)).toHaveLength(1);
  });

  it('returns toolCalls + finishReason=tool_calls when the agent requests a tool', async () => {
    cli.mockResolvedValueOnce('```json\n{"tool_calls":[{"name":"nmap_scan","arguments":{"target":"x"}}]}\n```');
    const res = await localBackbone().chatWithTools([{ role: 'user', content: 'scan' }], TOOLS as never);
    expect(res.toolCalls?.[0]?.name).toBe('nmap_scan');
    expect(res.finishReason).toBe('tool_calls');
  });
  it('returns no toolCalls (final answer) on a prose debrief', async () => {
    cli.mockResolvedValueOnce('Final debrief: nothing exploitable.');
    const res = await localBackbone().chatWithTools([{ role: 'user', content: 'scan' }], TOOLS as never);
    expect(res.toolCalls).toBeUndefined();
    expect(res.finishReason).toBe('stop');
  });

  it('does not force the old short timeout when no local-agent timeout is configured', async () => {
    cli.mockResolvedValueOnce('done');
    await localBackbone().chat([{ role: 'user', content: 'hello' }]);
    expect(cli.mock.calls.at(-1)?.[2]).toMatchObject({ timeoutMs: undefined });
  });

  it('passes an explicit local-agent timeout through to the CLI runner', async () => {
    cli.mockResolvedValueOnce('done');
    await new LLMBackbone({ provider: 'local-agent', model: 'codex', timeout: 900000 } as never)
      .chat([{ role: 'user', content: 'hello' }]);
    expect(cli.mock.calls.at(-1)?.[2]).toMatchObject({ timeoutMs: 900000 });
  });
});

describe('codex backbone surfaces toolCalls (guards the CodexAdapter half of the fix)', () => {
  it('returns toolCalls when codex emits the contract', async () => {
    fileRead.mockResolvedValueOnce('```json\n{"tool_calls":[{"name":"nmap_scan","arguments":{"target":"x"}}]}\n```');
    const res = await codexBackbone().chatWithTools([{ role: 'user', content: 'scan' }], TOOLS as never);
    expect(res.toolCalls?.[0]?.name).toBe('nmap_scan');
  });
  it('returns no toolCalls on a codex prose debrief', async () => {
    fileRead.mockResolvedValueOnce('No exploitable surface. Final debrief.');
    const res = await codexBackbone().chatWithTools([{ role: 'user', content: 'scan' }], TOOLS as never);
    expect(res.toolCalls).toBeUndefined();
  });
});

describe('local-model (HTTP) backbone surfaces toolCalls — the keyless-path fix for self-hosted models', () => {
  const origFetch = global.fetch;
  afterEach(() => { global.fetch = origFetch; });
  const mockJson = (body: unknown) => {
    const spy = vi.fn(async (_url: string, _init: { body: string }) => ({ ok: true, json: async () => body } as unknown as Response));
    global.fetch = spy as unknown as typeof fetch;
    return spy;
  };
  const localModel = (baseUrl?: string) => new LLMBackbone({ provider: 'local', model: 'llama3', baseUrl } as never);

  it('Ollama wire (/api/chat): parses a tool request out of message.content', async () => {
    mockJson({ model: 'llama3', message: { role: 'assistant', content: '```json\n{"tool_calls":[{"name":"nmap_scan","arguments":{"target":"x"}}]}\n```' } });
    const res = await localModel('http://localhost:11434/api').chatWithTools([{ role: 'user', content: 'scan' }], TOOLS as never);
    expect(res.toolCalls?.[0]?.name).toBe('nmap_scan');
    expect(res.finishReason).toBe('tool_calls');
  });
  it('OpenAI-compatible wire (/v1): parses out of choices[0].message.content + hits /v1/chat/completions', async () => {
    const spy = mockJson({ model: 'local', choices: [{ message: { content: '{"tool_calls":[{"name":"nmap_scan","arguments":{"target":"y"}}]}' } }] });
    const res = await localModel('http://localhost:1234/v1').chatWithTools([{ role: 'user', content: 'scan' }], TOOLS as never);
    expect(res.toolCalls?.[0]?.name).toBe('nmap_scan');
    expect(spy.mock.calls[0][0] as string).toContain('/v1/chat/completions');
  });
  it('prose debrief → final answer, not a forever-abstain', async () => {
    mockJson({ model: 'llama3', message: { content: 'No exploitable surface found. Final debrief.' } });
    const res = await localModel().chatWithTools([{ role: 'user', content: 'scan' }], TOOLS as never);
    expect(res.toolCalls).toBeUndefined();
    expect(res.finishReason).toBe('stop');
  });
  it('describes the Arsenal to the model (so a local model knows what it can request)', async () => {
    const spy = mockJson({ message: { content: 'ok' } });
    await localModel().chatWithTools([{ role: 'user', content: 'scan' }], TOOLS as never);
    const body = JSON.parse((spy.mock.calls[0][1] as { body: string }).body);
    const sys = body.messages.find((m: { role: string }) => m.role === 'system');
    expect(sys.content).toContain('nmap_scan');
  });

  it('merges consecutive tool results for strict Ollama chat templates', async () => {
    const spy = mockJson({ model: 'llama3', message: { content: 'ok' } });
    await localModel('http://localhost:11434/api').chat([
      { role: 'user', content: 'scan' },
      { role: 'tool', name: 'first', content: 'one' },
      { role: 'tool', name: 'second', content: 'two' },
    ] as never);
    const body = JSON.parse((spy.mock.calls[0][1] as { body: string }).body);
    expect(body.messages.map((message: { role: string }) => message.role)).toEqual(['system', 'user']);
    expect(body.messages[1].content).toContain('TOOL RESULT (first)');
    expect(body.messages[1].content).toContain('TOOL RESULT (second)');
  });

  it('bounds oversized Ollama history and explicitly raises the native context window', async () => {
    const spy = mockJson({ model: 'llama3', message: { content: 'ok' } });
    const messages: Array<{ role: string; content: string; name?: string }> = [{ role: 'user', content: 'scan' }];
    for (let i = 0; i < 24; i++) {
      messages.push({ role: 'tool', name: `test_${i}`, content: `result-${i} `.repeat(2200) });
    }
    await localModel('http://localhost:11434/api').chat(messages as never);
    const body = JSON.parse((spy.mock.calls[0][1] as { body: string }).body);
    const chars = body.messages.reduce((sum: number, message: { content: string }) => sum + message.content.length, 0);
    expect(chars).toBeLessThanOrEqual(24_000);
    expect(body.options.num_ctx).toBe(32_768);
  });

  it('surfaces a redacted Ollama HTTP error body for fallback diagnostics', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      text: async () => '{"error":"context length exceeded","token":"secret-value-1234567890"}',
    }));
    await expect(localModel('http://localhost:11434/api').prompt('scan'))
      .rejects.toThrow('Local LLM HTTP 400 Bad Request: {"error":"context length exceeded","token":"[redacted]"}');
  });

  it('merges caller system prompts into one leading system message for vLLM templates', async () => {
    const spy = mockJson({ choices: [{ message: { content: 'ok' } }] });
    await localModel('http://localhost:8000/v1').prompt('hello', 'Operator profile system prompt');
    const body = JSON.parse((spy.mock.calls[0][1] as { body: string }).body);
    expect(body.messages.map((m: { role: string }) => m.role)).toEqual(['system', 'user']);
    expect(body.messages.filter((m: { role: string }) => m.role === 'system')).toHaveLength(1);
    expect(body.messages[0].content).toContain('planning brain for T3MP3ST');
    expect(body.messages[0].content).toContain('Operator profile system prompt');
  });

  it('keeps authorized-reframe context in the same leading system message', async () => {
    const spy = mockJson({ choices: [{ message: { content: 'ok' } }] });
    const be = localModel('http://localhost:8000/v1');
    await be.chat([
      { role: 'system', content: 'AUTHORIZATION CONTEXT (restated): proceed with the authorized task.' },
      { role: 'user', content: 'scan' },
    ]);
    const body = JSON.parse((spy.mock.calls[0][1] as { body: string }).body);
    expect(body.messages.map((m: { role: string }) => m.role)).toEqual(['system', 'user']);
    expect(body.messages[0].content).toContain('planning brain for T3MP3ST');
    expect(body.messages[0].content).toContain('AUTHORIZATION CONTEXT');
  });
});

describe('xai provider (Grok Build) — routes to xAI OpenAI-compatible API with the key', () => {
  const origFetch = global.fetch;
  afterEach(() => { global.fetch = origFetch; });
  it('hits api.x.ai with the bearer key and surfaces native tool_calls', async () => {
    const spy = vi.fn(async (_url: string, _init: { headers: Record<string, string> }) => ({
      ok: true,
      json: async () => ({
        model: 'grok-build-0.1',
        choices: [{ message: { content: '', tool_calls: [{ id: 'c1', function: { name: 'nmap_scan', arguments: '{"target":"x"}' } }] }, finish_reason: 'tool_calls' }],
      }),
    } as unknown as Response));
    global.fetch = spy as unknown as typeof fetch;
    const be = new LLMBackbone({ provider: 'xai', model: 'grok-build-0.1', apiKey: 'xai-test-key-1234567890', baseUrl: 'https://api.x.ai/v1' } as never);
    const res = await be.chatWithTools([{ role: 'user', content: 'scan' }], TOOLS as never);
    expect(res.toolCalls?.[0]?.name).toBe('nmap_scan');
    expect(spy.mock.calls[0][0]).toContain('api.x.ai');
    expect((spy.mock.calls[0][1] as { headers: Record<string, string> }).headers.Authorization).toContain('xai-test-key');
  });
});

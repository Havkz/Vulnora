import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
const launch = vi.hoisted(() => vi.fn());
const locate = vi.hoisted(() => vi.fn());
vi.mock('node:child_process', () => ({ spawn: launch }));
vi.mock('../command-path.js', () => ({ commandPath: locate }));
import { fetchLocal, stopOwnedOllama } from '../llm/local-service.js';
import { LLMBackbone, type LLMEvents } from '../llm/index.js';

const tags = 'http://127.0.0.1:11434/api/tags';
const refused = () => new TypeError('fetch failed', { cause: { code: 'ECONNREFUSED' } });
function processFixture() {
  const child = Object.assign(new EventEmitter(), { exitCode: null as number | null, signalCode: null as string | null,
    stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), kill: vi.fn() });
  child.kill.mockImplementation(() => { child.signalCode = 'SIGTERM'; child.emit('exit'); return true; });
  child.stdin.on('finish', () => { child.exitCode = 0; child.emit('exit'); });
  launch.mockReturnValue(child); return child;
}
beforeEach(() => {
  launch.mockReset(); locate.mockReset().mockResolvedValue('/usr/bin/ollama');
  vi.stubEnv('VULNORA_OLLAMA_HOST_POWERSHELL', ''); vi.stubEnv('VULNORA_OLLAMA_HOST_HELPER', '');
});
afterEach(async () => { await stopOwnedOllama(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); });

describe('on-demand local Ollama service', () => {
  it('records paired model requests even when concurrent replies arrive in reverse order', async () => {
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    vi.stubGlobal('fetch', vi.fn(async (_url, init) => {
      const question = JSON.parse(init.body).messages.at(-1).content;
      if (question === 'first') await gate;
      return new Response(JSON.stringify({ message: { content: `answer ${question}` }, done: true }));
    }));
    const llm = new LLMBackbone({ provider: 'local', model: 'selected:7b', baseUrl: 'http://127.0.0.1:11434/api' });
    const trace: LLMEvents['request:trace'][] = []; llm.on('request:trace', event => trace.push(event));
    const messages = [{ role: 'user' as const, content: 'first' }];
    const first = llm.chat(messages); await llm.chat([{ role: 'user', content: 'second' }]);
    release(); await first; messages[0].content = 'changed after request';
    const questions = trace.filter(event => event.stage === 'request');
    expect(questions[0].messages?.[0].content).toBe('first');
    expect(questions[0].requestId).not.toBe(questions[1].requestId);
    for (const question of questions) expect(trace.find(event => event.stage === 'response' && event.requestId === question.requestId)?.response?.content)
      .toBe(`answer ${question.messages?.[0].content}`);
  });
  it('starts an installed daemon only on refusal, lists models without loading, then stops its own daemon', async () => {
    const child = processFixture();
    const request = vi.fn().mockRejectedValueOnce(refused()).mockImplementation(async () => new Response('{"models":[{"name":"installed:7b"}]}'));
    vi.stubGlobal('fetch', request);
    expect(await (await fetchLocal(tags)).json()).toEqual({ models: [{ name: 'installed:7b' }] });
    expect(launch).toHaveBeenCalledWith('/usr/bin/ollama', ['serve'], expect.objectContaining({ shell: false, windowsHide: true,
      env: expect.objectContaining({ OLLAMA_HOST: '127.0.0.1:11434' }) }));
    expect(request.mock.calls.every(([url]) => url === tags)).toBe(true);
    await stopOwnedOllama(); expect(child.kill).toHaveBeenCalledOnce();
    await stopOwnedOllama(); expect(child.kill).toHaveBeenCalledOnce();
  });
  it('shares a Windows host launch between simultaneous requests and releases its ownership pipe', async () => {
    vi.stubEnv('VULNORA_OLLAMA_HOST_POWERSHELL', '/mnt/c/powershell.exe');
    vi.stubEnv('VULNORA_OLLAMA_HOST_HELPER', 'C:\\fixture path\\serve.ps1');
    const child = processFixture();
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(refused()).mockRejectedValueOnce(refused())
      .mockImplementation(async () => new Response('{"models":[]}')));
    await Promise.all([fetchLocal(tags), fetchLocal(tags)]);
    expect(launch).toHaveBeenCalledOnce();
    expect(launch.mock.calls[0].slice(0, 2)).toEqual(['/mnt/c/powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', 'C:\\fixture path\\serve.ps1']]);
    await stopOwnedOllama(); expect(child.stdin.writableEnded).toBe(true); expect(child.kill).not.toHaveBeenCalled();
  });
  it('waits for a cold daemon that needs more than fifteen seconds to serve its model list', async () => {
    processFixture(); vi.useFakeTimers();
    const started = Date.now();
    const timeout = vi.spyOn(AbortSignal, 'timeout').mockImplementation(milliseconds => {
      const controller = new AbortController();
      setTimeout(() => controller.abort(new DOMException('Timed out', 'TimeoutError')), milliseconds);
      return controller.signal;
    });
    vi.stubGlobal('fetch', vi.fn(async () => {
      if (Date.now() - started < 17000) throw refused();
      return new Response('{"models":[{"name":"slow-start:7b"}]}');
    }));
    try {
      const pending = expect(fetchLocal(tags).then(response => response.json())).resolves.toEqual({ models: [{ name: 'slow-start:7b' }] });
      await vi.advanceTimersByTimeAsync(17200); await pending;
      expect(launch).toHaveBeenCalledOnce();
    } finally { timeout.mockRestore(); vi.useRealTimers(); }
  });
  it('leaves an existing service alone, including HTTP failures', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 503 })));
    expect((await fetchLocal(tags)).status).toBe(503);
    await stopOwnedOllama(); expect(launch).not.toHaveBeenCalled();
  });
  it.each(['http://other.test:11434/api/tags', 'http://localhost:1234/v1/models', 'http://127.0.0.1:11434/v1/models'])('never starts a service for a custom endpoint: %s', async url => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(refused()));
    await expect(fetchLocal(url)).rejects.toThrow('fetch failed'); expect(launch).not.toHaveBeenCalled();
  });
  it('cancels a pending start and releases only its owned process', async () => {
    const child = processFixture(); const controller = new AbortController();
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(refused()).mockImplementation(async () => {
      controller.abort(new Error('operator cancelled')); throw refused();
    }));
    await expect(fetchLocal(tags, { signal: controller.signal })).rejects.toThrow('operator cancelled');
    expect(child.kill).toHaveBeenCalledOnce();
  });
  it('starts the service for first inference too, preserving the actual model and request body', async () => {
    processFixture();
    const request = vi.fn().mockRejectedValueOnce(refused()).mockImplementation(async url => url === tags
      ? new Response('{"models":[]}') : new Response('{"message":{"content":"ready"},"done":true}'));
    vi.stubGlobal('fetch', request);
    const llm = new LLMBackbone({ provider: 'local', model: 'selected:7b', baseUrl: 'http://127.0.0.1:11434/api' });
    expect((await llm.chat([{ role: 'user', content: 'fixture' }])).content).toBe('ready');
    const chat = request.mock.calls.filter(([url]) => url.endsWith('/chat'));
    expect(chat).toHaveLength(2); expect(chat[1][1].body).toBe(chat[0][1].body);
    expect(JSON.parse(chat[1][1].body).model).toBe('selected:7b');
  });
  it('settles model activity when a request is cancelled before inference', async () => {
    const llm = new LLMBackbone({ provider: 'local', model: 'fixture' });
    const controller = new AbortController(); controller.abort(new Error('cancelled'));
    const started = vi.fn(); const ended = vi.fn(); llm.on('request:start', started); llm.on('request:end', ended);
    await expect(llm.chat([{ role: 'user', content: 'fixture' }], { signal: controller.signal })).rejects.toThrow('cancelled');
    expect(started).toHaveBeenCalledOnce(); expect(ended).toHaveBeenCalledOnce(); expect(launch).not.toHaveBeenCalled();
  });
});

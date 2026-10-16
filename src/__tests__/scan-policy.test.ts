import { afterEach, describe, expect, it, vi } from 'vitest';
import { createServer, type Server, type RequestListener } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { ScanPolicy, SCAN_PRESETS } from '../orchestrator/scan-policy.js';
import { Arsenal, BUILTIN_TOOLS } from '../arsenal/index.js';
import { CheckpointWriteError } from '../agent/checkpoint.js';
import { ToolOrchestrator } from '../orchestrator/tool-orchestrator.js';
import * as dns from 'node:dns';
import { Socket } from 'node:net';

const servers: Server[] = [];
afterEach(async () => {
  vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllEnvs();
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => {
    server.closeAllConnections(); server.close(() => resolve());
  })));
});
async function server(handler: RequestListener): Promise<URL> {
  const instance = createServer(handler); servers.push(instance);
  await new Promise<void>(resolve => instance.listen(0, '127.0.0.1', resolve));
  return new URL(`http://127.0.0.1:${(instance.address() as { port: number }).port}/`);
}
function policy(mode: 'auto' | 'stealth' | 'aggressive' = 'auto') {
  const value = new ScanPolicy(); value.setBehavior(mode); return value;
}

describe('effective scanning behavior', () => {
  it('keeps request spacing when the first native client has synchronous startup overhead', async () => {
    const scan = policy('aggressive'); const starts: number[] = [];
    await Promise.all([35, 0, 0].map(setupMs => scan.runNetwork('fixture.test', async () => {
      if (setupMs) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, setupMs);
      starts.push(Date.now()); await delay(80);
    }, undefined, false)));
    expect(starts).toHaveLength(3);
    expect(starts.slice(1).every((at, index) => at - starts[index] >= 40)).toBe(true);
  });
  it('paces real requests across operators and holds concurrency until response bodies finish', async () => {
    const starts: number[] = []; let active = 0; let maximum = 0;
    const fetch = globalThis.fetch;
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => { starts.push(Date.now()); return fetch(input, init); });
    const url = await server((_request, response) => {
      maximum = Math.max(maximum, ++active);
      response.writeHead(200); response.write('begin');
      setTimeout(() => { active--; response.end('end'); }, 240);
    });
    const scan = policy('aggressive'); let charged = 0;
    const responses = await Promise.all(Array.from({ length: 6 }, () => scan.fetch(url, {}, async () => {
      charged++; await delay(charged % 2 ? 90 : 5);
    })));
    expect(await Promise.all(responses.map(response => response.text()))).toEqual(Array(6).fill('beginend'));
    expect(maximum).toBeGreaterThan(1); expect(maximum).toBeLessThanOrEqual(4);
    expect(charged).toBe(6);
    expect(starts.slice(1).every((at, index) => at - starts[index] >= 40)).toBe(true);
  });

  it('uses conservative real Stealth pacing without changing request identity', async () => {
    const starts: number[] = []; const agents: string[] = [];
    const fetch = globalThis.fetch;
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => { starts.push(Date.now()); return fetch(input, init); });
    const url = await server((request, response) => { agents.push(request.headers['user-agent'] || ''); response.end('ok'); });
    const scan = policy('stealth');
    await Promise.all([0, 1, 2].map(() => scan.fetch(url, { headers: { 'user-agent': 'Vulnora-test' } }, async () => {})));
    expect(starts[1] - starts[0]).toBeGreaterThanOrEqual(950);
    expect(starts[2] - starts[1]).toBeGreaterThanOrEqual(950);
    expect(agents).toEqual(Array(3).fill('Vulnora-test'));
  });

  it('retries a real rate-limited GET with reduced load and counts each attempt', async () => {
    let requests = 0; const starts: number[] = [];
    const url = await server((_request, response) => {
      starts.push(Date.now()); response.statusCode = ++requests === 1 ? 429 : 200;
      response.setHeader('Retry-After', '0.1'); response.end('ok');
    });
    const scan = policy(); let charged = 0;
    expect((await scan.fetch(url, {}, async () => { charged++; })).status).toBe(200);
    expect(charged).toBe(2); expect(starts[1] - starts[0]).toBeGreaterThanOrEqual(3900);
    expect(scan.limits(url.hostname).concurrency).toBe(1);
  }, 10_000);

  it.each(['POST', 'PATCH', 'DELETE', 'PUT', 'TRACE'])('never automatically replays %s', async method => {
    let requests = 0;
    const url = await server((_request, response) => { requests++; response.statusCode = 503; response.end(); });
    const scan = policy('aggressive');
    if (method === 'TRACE') await expect(scan.fetch(url, { method }, async () => {})).rejects.toThrow();
    else expect((await scan.fetch(url, { method }, async () => {})).status).toBe(503);
    expect(requests).toBe(method === 'TRACE' ? 0 : 1);
  });

  it('does not retry Stealth, cancels waiting work, and never sends after a failed durable write', async () => {
    let requests = 0;
    const url = await server((_request, response) => { requests++; response.statusCode = 429; response.end(); });
    const scan = policy('stealth');
    expect((await scan.fetch(url, {}, async () => {})).status).toBe(429);
    const controller = new AbortController();
    const waiting = scan.fetch(url, { signal: controller.signal }, async () => {});
    controller.abort(); await expect(waiting).rejects.toThrow();
    const fresh = policy();
    await expect(fresh.fetch(url, {}, async () => { throw new CheckpointWriteError(new Error('disk full')); })).rejects.toBeInstanceOf(CheckpointWriteError);
    expect(requests).toBe(1);
  });

  it('reduces load deterministically, recovers only after stable responses, and preserves Retry-After on mode change/restart', () => {
    const scan = policy('aggressive'); const before = scan.limits('local');
    for (let index = 0; index < 12; index++) scan.observe('local', 20_000, 503, '120');
    expect(scan.limits('local').concurrency).toBe(1);
    expect(scan.limits('local').intervalMs).toBeGreaterThan(before.intervalMs);
    expect(scan.limits('local').timeoutMs).toBe(60_000);
    const saved = scan.exportCheckpoint();
    if (!saved) throw new Error('Missing policy snapshot');
    const restored = policy(); restored.restoreCheckpoint(JSON.parse(JSON.stringify(saved)));
    restored.setBehavior('stealth');
    expect(restored.exportCheckpoint()?.hosts[0][1].backoffUntil).toBe(saved.hosts[0][1].backoffUntil);
    for (let index = 0; index < 32; index++) restored.observe('local', 10, 200);
    expect(restored.limits('local').intervalMs).toBe(SCAN_PRESETS.stealth.intervalMs);
    expect(() => restored.restoreCheckpoint({ ...saved, hosts: [['local', { ...saved.hosts[0][1], penalty: 99 }]] })).toThrow('Invalid');
  });

  it('holds external scanners exclusively against the same host and cancels queued subprocess work', async () => {
    const scan = policy('aggressive'); let release!: () => void; let admitted = false;
    const active = scan.runNetwork('local', () => new Promise<void>(resolve => { admitted = true; release = resolve; }));
    while (!admitted) await delay(5);
    const controller = new AbortController(); const runner = vi.fn(async () => {});
    const queued = scan.runNetwork('local', runner, controller.signal);
    controller.abort(); await expect(queued).rejects.toThrow();
    expect(runner).not.toHaveBeenCalled(); release(); await active;
  });

  it('cannot override hard nmap limits and supplies bounded external scanner options', () => {
    const scan = policy('stealth');
    const args = scan.commandArgs('nmap', ['-sV', '-T5', '--min-rate=999999', '--max-rate', '999999', '--min-parallelism', '1000', '-p', '443', 'local'], 'local');
    expect(args).not.toContain('-T5'); expect(args).not.toContain('--min-rate=999999'); expect(args).not.toContain('999999');
    expect(args).toContain('443'); expect(args).toContain('local'); expect(args).toContain('--max-rate');
    expect(scan.commandArgs('nuclei', ['-target', 'local'], 'local')).toEqual(expect.arrayContaining(['-rl', '1', '-c', '1', '-retries', '0']));
    expect(scan.commandArgs('ffuf', ['-u', 'local'], 'local')).toEqual(expect.arrayContaining(['-t', '1', '-rate', '1', '-sa']));
  });

  it('shares actual accounting and backoff with the Arsenal, including a GET retry', async () => {
    let requests = 0;
    const url = await server((_request, response) => { response.statusCode = ++requests === 1 ? 503 : 200; response.end('ok'); });
    const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS);
    const orchestrator = arsenal.getOrchestrator(); orchestrator.scanPolicy.setBehavior('aggressive');
    orchestrator.getBudget(url.href);
    const checkpoint = orchestrator.exportCheckpoint(); checkpoint.budgets[0][1].limits.tool_call_budget = 1;
    orchestrator.restoreCheckpoint(checkpoint);
    const result = await arsenal.execute('http_request', { parameters: { url: url.href } });
    expect(result.success).toBe(true); expect(result.metadata?.networkRequests).toBe(2);
    expect(orchestrator.getBudget(url.href).used.total_request_budget).toBe(2);
    expect(orchestrator.getBudget(url.href).used.tool_call_budget).toBe(1);
    const restored = new ToolOrchestrator(); restored.restoreCheckpoint(JSON.parse(JSON.stringify(orchestrator.exportCheckpoint())));
    expect(restored.getBudget(url.href).used.total_request_budget).toBe(2);
    expect(restored.getNetworkContext(url.href).scanning?.limits.concurrency).toBe(2);
  }, 10_000);

  it('blocks a retry before it exceeds a saved request budget', async () => {
    let requests = 0;
    const url = await server((_request, response) => { requests++; response.statusCode = 503; response.end(); });
    const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS);
    const orchestrator = arsenal.getOrchestrator(); orchestrator.scanPolicy.setBehavior('aggressive');
    orchestrator.getBudget(url.href);
    const checkpoint = orchestrator.exportCheckpoint(); checkpoint.budgets[0][1].limits.total_request_budget = 1;
    orchestrator.restoreCheckpoint(checkpoint);
    const result = await arsenal.execute('http_request', { parameters: { url: url.href } });
    expect(result.success).toBe(false); expect(result.error).toMatch(/budget_exceeded/);
    expect(requests).toBe(1); expect(orchestrator.getBudget(url.href).used.total_request_budget).toBe(1);
  }, 10_000);

  it('bounds retries, adapts request timeouts, and includes the body in the timeout', async () => {
    const url = await server((_request, response) => { response.writeHead(200); response.write('partial'); });
    const scan = policy(); const limits = scan.limits.bind(scan); let charged = 0;
    vi.spyOn(scan, 'limits').mockImplementation(host => ({ ...limits(host), timeoutMs: 30, backoffMs: 10 }));
    await expect(scan.fetch(url, {}, async () => { charged++; })).rejects.toThrow();
    expect(charged).toBe(2);
    expect(limits(url.hostname).concurrency).toBe(1);
    expect(limits(url.hostname).timeoutMs).toBeLessThanOrEqual(60_000);
  });

  it('propagates checkpoint failure even when the HTTP handler catches it', async () => {
    let requests = 0;
    const url = await server((_request, response) => { requests++; response.end(); });
    const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS);
    const orchestrator = arsenal.getOrchestrator(); orchestrator.scanPolicy.setBehavior('auto');
    let writes = 0; orchestrator.setCheckpointWriter(async () => { if (++writes > 1) throw new Error('disk full'); });
    await expect(arsenal.execute('http_request', { parameters: { url: url.href } })).rejects.toBeInstanceOf(CheckpointWriteError);
    expect(requests).toBe(0);
  });

  it('paces native TCP probes and native TRACE requests through the same scheduler', async () => {
    const starts: number[] = [];
    const endpoints = await Promise.all([0, 1, 2].map(() => server((_request, response) => response.end())));
    const ports = endpoints.map(url => Number(url.port));
    const connect = Socket.prototype.connect;
    vi.spyOn(Socket.prototype, 'connect').mockImplementation(function (this: Socket, ...args) {
      if (typeof args[0] === 'number' && ports.includes(args[0])) starts.push(Date.now());
      return Reflect.apply(connect, this, args);
    });
    const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS);
    arsenal.getOrchestrator().scanPolicy.setBehavior('aggressive');
    const result = await arsenal.execute('port_scan', { parameters: { target: '127.0.0.1', ports: endpoints.map(url => url.port).join(',') } });
    expect(result.success).toBe(true); expect(starts).toHaveLength(3);
    expect(starts.slice(1).every((at, index) => at - starts[index] >= 40)).toBe(true);
    const trace = await arsenal.execute('http_request', { parameters: { url: endpoints[0].href, method: 'TRACE' } });
    expect(trace.success).toBe(true); expect(trace.metadata?.networkRequests).toBe(1);
  });

  it('schedules per-query cancellable DNS resolvers while preserving negative DNS answers', async () => {
    vi.stubEnv('PATH', '');
    const starts: number[] = [];
    const resolve = vi.spyOn(dns.promises.Resolver.prototype, 'resolve4').mockImplementation(async () => {
      starts.push(Date.now());
      await delay(80);
      throw Object.assign(new Error('No DNS records'), { code: 'ENODATA' });
    });
    const source = BUILTIN_TOOLS.find(tool => tool.name === 'dns_lookup');
    if (!source) throw new Error('Missing DNS fixture');
    const arsenal = new Arsenal(); arsenal.getOrchestrator().scanPolicy.setBehavior('aggressive');
    const tools = [0, 1, 2].map(index => ({ ...source, name: `dns_fixture_${index}` }));
    arsenal.registerMany(tools);
    await Promise.all(tools.map(tool => arsenal.execute(tool.name, { parameters: { domain: 'fixture.test' } })));
    expect(resolve).toHaveBeenCalledTimes(3);
    expect(starts.slice(1).every((at, index) => at - starts[index] >= 40)).toBe(true);
    expect(arsenal.getOrchestrator().scanPolicy.limits('fixture.test').concurrency).toBe(4);
  });
});

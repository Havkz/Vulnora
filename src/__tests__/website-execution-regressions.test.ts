import { afterEach, describe, expect, it, vi } from 'vitest';
import { createServer, type Server } from 'node:http';
import { createServer as createTlsServer, createSecureContext } from 'node:tls';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { VulnoraCommand } from '../index.js';
import { Arsenal, BUILTIN_TOOLS, isToolAvailable, resolveNmapTimeoutMs, scopeViolation, type ProcessEvent } from '../arsenal/index.js';
import { ScanPolicy } from '../orchestrator/scan-policy.js';
import { canReplayInterruptedCall } from '../agent/checkpoint.js';
import { KillChainPhase } from '../types/index.js';

const servers: Server[] = [];
const commands: VulnoraCommand[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  for (const command of commands.splice(0)) { command.stop(); command.opsec.cleanup(); }
  for (const server of servers.splice(0)) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
});

describe('website execution repairs', () => {
  it.each(['xss_scan', 'sqli_scan'])('keeps %s failures retryable instead of reporting a successful negative scan', async name => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('fixture network unavailable'); }));
    const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS.filter(tool => tool.name === name));
    const result = await arsenal.execute(name, { parameters: { url: 'https://fixture.test/search?q=hello', param: 'q' } });
    expect(result.success).toBe(false); expect(result.error).toContain('inspection incomplete');
    if (name === 'xss_scan') { expect(result.output).toContain('Incomplete: request failed'); expect(result.output).not.toContain('✓ Not reflected'); }
    expect(arsenal.getOrchestrator().getEvidence().at(-1)?.resultType).toBe('error');
  });
  it.each(['xss_scan', 'sqli_scan'])('does not count unavailable HTTP responses as a negative %s check', async name => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('Unavailable', { status: 503 })));
    const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS.filter(tool => tool.name === name));
    const result = await arsenal.execute(name, { parameters: { url: 'https://fixture.test/search?q=hello', param: 'q' } });
    expect(result.success).toBe(false);
    expect(arsenal.getOrchestrator().getEvidence().at(-1)?.resultType).toBe('error');
  });
  it.each(['xss_scan', 'sqli_scan'])('records an explicit negative only after usable %s responses', async name => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('Fixed safe response', { status: 200 })));
    const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS.filter(tool => tool.name === name));
    const result = await arsenal.execute(name, { parameters: { url: 'https://fixture.test/search?q=hello', param: 'q' } });
    expect(result.success).toBe(true);
    expect(arsenal.getOrchestrator().getEvidence().at(-1)?.resultType).toBe('negative');
  });
  it('keeps failed HTTP method requests incomplete and actually sends TRACE', async () => {
    const methods: string[] = [];
    const server = createServer((request, response) => { methods.push(request.method || ''); response.writeHead(503); response.end('Unavailable'); });
    servers.push(server); await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS.filter(tool => tool.name === 'http_methods_test'));
    const result = await arsenal.execute('http_methods_test', { parameters: { url: `http://127.0.0.1:${(server.address() as { port: number }).port}` } });
    expect(result.success).toBe(false); expect(methods).toContain('TRACE');
    expect(arsenal.getOrchestrator().getEvidence().at(-1)?.resultType).toBe('error');
  });
  it('uses the native TRACE response body to distinguish reflection from method availability', async () => {
    const server = createServer((request, response) => {
      response.writeHead(200); response.end(request.method === 'TRACE' ? 'TRACE / HTTP/1.1\r\nHost: localhost' : 'Normal response');
    });
    servers.push(server); await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS.filter(tool => tool.name === 'http_methods_test'));
    const result = await arsenal.execute('http_methods_test', { parameters: { url: `http://127.0.0.1:${(server.address() as { port: number }).port}` } });
    expect(result.success).toBe(true);
    expect(result.findings?.[0]?.title).toBe('HTTP TRACE Reflects Request');
  });
  it('retains candidate SQL error evidence in HTTP 500 responses', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input: string | URL) => new URL(input).searchParams.get('q') === 'normalvalue'
      ? new Response('Normal baseline', { status: 200 }) : new Response('SQL syntax error', { status: 500 })));
    const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS.filter(tool => tool.name === 'sqli_scan'));
    const result = await arsenal.execute('sqli_scan', { parameters: { url: 'https://fixture.test/search', param: 'q' } });
    expect(result.findings?.[0]?.title).toBe('Potential SQL Injection Vulnerability');
    expect(arsenal.getOrchestrator().getEvidence().at(-1)?.resultType).toBe('positive');
  });
  it('rejects redirects to a raw IP unless that IP was explicitly scoped', async () => {
    const paths: string[] = [];
    const server = createServer((request, response) => {
      paths.push(request.url || '');
      response.writeHead(302, { Location: `http://127.0.0.1:${(server.address() as { port: number }).port}/outside` }); response.end();
    }); servers.push(server);
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS.filter(tool => tool.name === 'http_request'));
    arsenal.setScope({ allowedHosts: ['localhost'], allowPrivate: false, allowLoopback: false });
    const result = await arsenal.execute('http_request', { parameters: { url: `http://localhost:${(server.address() as { port: number }).port}/` } });
    expect(result.success).toBe(false); expect(result.error).toContain('SCOPE DENIED'); expect(paths).toEqual(['/']);
  });
  it('does not report dangerous methods from 404s or send state-changing method probes', async () => {
    const methods: string[] = [];
    const server = createServer((request, response) => {
      methods.push(request.method || '');
      response.statusCode = ['GET', 'HEAD'].includes(request.method || '') ? 200 : 404;
      response.end('No method reflection');
    }); servers.push(server);
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS.filter(tool => tool.name === 'http_methods_test'));
    const result = await arsenal.execute('http_methods_test', { parameters: { url } });
    expect(result.success).toBe(true); expect(result.findings).toBeUndefined();
    expect(result.output).toContain('OPTIONS: 404 (not confirmed)');
    expect(methods).not.toEqual(expect.arrayContaining(['POST']));
    expect(methods.some(method => ['POST', 'PUT', 'DELETE', 'PATCH', 'CONNECT'].includes(method))).toBe(false);
  });

  it.each([false, true])('dispatches saved Scanning tasks through an installed CLI even with a full Recon cell (full=%s)', async full => {
    const command = new VulnoraCommand({ name: 'Phase fixture', llm: { provider: 'local-agent', model: 'codex' },
      operators: { maxConcurrent: 1 } }); commands.push(command);
    command.targetEnv.addTarget({ name: 'Fixture', type: 'web_application', zone: 'external', address: 'https://fixture.test' });
    const mission = command.mission.createMission({ name: 'Fixture', objectives: [], phases: [KillChainPhase.WEAPONIZE] }); command.mission.startMission(mission.id);
    const task = command.mission.createTask({ missionId: mission.id, name: 'Web Application Security Testing',
      description: 'Inspect https://fixture.test', phase: KillChainPhase.WEAPONIZE, operatorType: 'scanner' });
    if (full) command.spawnOperator('Recon-Auto', 'recon');
    const saved = command.exportCheckpoint(); saved.command.taskSeeded = true;
    const restored = new VulnoraCommand({ name: 'Restored', llm: { provider: 'local-agent', model: 'codex' }, operators: { maxConcurrent: 1 } }); commands.push(restored);
    restored.restoreCheckpoint(saved);
    const spawn = restored.spawnOperator.bind(restored);
    const assigned = vi.fn(async () => ({ success: true, output: 'Offline fixture completed', findings: [] }));
    vi.spyOn(restored, 'spawnOperator').mockImplementation((...args) => {
      const operator = spawn(...args); vi.spyOn(operator, 'assignTask').mockImplementation(assigned); return operator;
    });
    await (restored as unknown as { tick(): Promise<void> }).tick();
    await vi.waitFor(() => expect(restored.mission.getTaskQueue().getTask(task.id)?.status).toBe('completed'));
    expect(assigned).toHaveBeenCalledOnce(); expect(restored.cell.getAllOperators()[0].archetype).toBe('scanner');
  });

  it('includes nested subdomains and DNS service labels without allowing sibling domains, other TLDs or IP suffixes', () => {
    const command = new VulnoraCommand({ name: 'Scope fixture', llm: { provider: 'mock', model: 'fixture' }, strictScope: true }); commands.push(command);
    command.targetEnv.addTarget({ name: 'Fixture', type: 'web_application', zone: 'external', address: 'https://example.com/' });
    const scope = command.arsenal.getScope();
    for (const host of ['example.com', '_dmarc.example.com', 'v1.api.example.com']) expect(scopeViolation(scope, { parameters: { host } })).toBeNull();
    for (const host of ['evil-example.com', 'example.com.evil.org', 'example.net', '127.0.0.1']) expect(scopeViolation(scope, { parameters: { host } })).toBe(host);
    expect(scopeViolation({ allowedHosts: ['127.0.0.1'], allowPrivate: false, allowLoopback: false }, { parameters: { host: 'evil.127.0.0.1' } })).toBe('evil.127.0.0.1');
  });

  it('sizes Nmap deadlines after actual policy pacing and never combines scan delay with ignored parallelism', () => {
    const policy = new ScanPolicy(); policy.setBehavior('auto');
    const normal = policy.commandArgs('nmap', ['-sT', '--top-ports', '1000', '--max-parallelism', '100', 'example.test'], 'example.test');
    expect(normal).not.toContain('--max-parallelism');
    expect(normal).toContain('--stats-every');
    expect(resolveNmapTimeoutMs(normal)).toBeGreaterThan(2 * 1000 * 250);
    policy.observe('example.test', 1000, 503);
    const slower = policy.commandArgs('nmap', ['-sT', '-p', '1-1000', 'example.test'], 'example.test');
    expect(resolveNmapTimeoutMs(slower, '1-1000')).toBeGreaterThan(resolveNmapTimeoutMs(normal));
    expect(resolveNmapTimeoutMs(['--scan-delay', '1s', '--max-retries', '2'], '1-1000')).toBeGreaterThan(3000000);
  });

  it('runs a port scan alongside independent web work while isolating conflicting web work', async () => {
    const policy = new ScanPolicy(); policy.setBehavior('auto');
    let release!: () => void; let began!: () => void; let overlapping = false;
    const active = new Promise<void>(resolve => { began = resolve; });
    const port = policy.runNetwork('fixture.test', async () => { began(); await new Promise<void>(resolve => { release = resolve; }); }, undefined, true, 'ports');
    await active;
    await policy.runNetwork('fixture.test', async () => { overlapping = true; }, undefined, true);
    expect(overlapping).toBe(true); release(); await port;
    let unlock!: () => void; let sqlBegan!: () => void;
    const started = new Promise<void>(resolve => { sqlBegan = resolve; });
    const timing = policy.runNetwork('fixture.test', async () => { sqlBegan(); await new Promise<void>(resolve => { unlock = resolve; }); }, undefined, true);
    await started;
    const abort = new AbortController();
    const discovery = policy.runNetwork('fixture.test', async () => { throw new Error('Conflicting discovery ran'); }, abort.signal, true);
    const blocked = expect(discovery).rejects.toMatchObject({ name: 'AbortError' });
    abort.abort(new Error('Cancelled queued discovery')); await blocked; unlock(); await timing;
  });

  it('resumes a saved ordinary Nmap infrastructure timeout and keeps interrupted writes blocked', () => {
    const command = new VulnoraCommand({ name: 'Resume fixture', llm: { provider: 'mock', model: 'fixture' } }); commands.push(command);
    command.targetEnv.addTarget({ name: 'Fixture', type: 'web_application', zone: 'external', address: 'https://fixture.test' });
    const mission = command.mission.createMission({ name: 'Fixture', objectives: [], phases: [KillChainPhase.RECON] }); command.mission.startMission(mission.id);
    const task = command.mission.createTask({ missionId: mission.id, name: 'Nmap', description: 'Read ports', phase: KillChainPhase.RECON, operatorType: 'recon' });
    task.executionPlan = { toolName: 'nmap_scan', parameters: { target: 'fixture.test', flags: '--top-ports 1000 -T4' } };
    command.mission.getTaskQueue().fail(task.id, 'Old dispatch timeout', 'dispatch_infrastructure');
    const saved = command.exportCheckpoint();
    const restored = new VulnoraCommand({ name: 'Restored', llm: { provider: 'mock', model: 'fixture' } }); commands.push(restored); restored.restoreCheckpoint(saved); restored.start();
    expect(restored.mission.getTaskQueue().getForMission(mission.id).find(item => item.id === task.id)?.status).toBe('pending');
    expect(canReplayInterruptedCall({ id: '1', name: 'nmap_scan', arguments: { flags: '--script intrusive' } })).toBe(false);
    expect(canReplayInterruptedCall({ id: '1', name: 'http_request', arguments: { method: 'POST', body: 'write' } })).toBe(false);
  });

  it('records real curl processes for native robots and directory discovery, preserving HTTP data and scoped redirects', async () => {
    if (!await isToolAvailable('curl')) return;
    const requested: string[] = [];
    const server = createServer((request, response) => { requested.push(request.url || '');
      if (request.url === '/robots.txt') { response.end('User-agent: *\nDisallow: /private'); return; }
      if (request.url === '/jump') { response.writeHead(302, { Location: 'http://out-of-scope.invalid/' }); response.end(); return; }
      response.statusCode = request.url === '/api' ? 401 : 404; response.end('Response: 日本語');
    }); servers.push(server);
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS);
    arsenal.setScope({ allowedHosts: ['127.0.0.1'], allowPrivate: false, allowLoopback: false });
    arsenal.getOrchestrator().scanPolicy.setBehavior('aggressive');
    const events: ProcessEvent[] = []; arsenal.on('tool:process', event => events.push(event));
    const robots = await arsenal.execute('robots_txt_fetch', { parameters: { url } });
    expect(robots.success, robots.error).toBe(true); expect(robots.metadata?.executionTraced).toBe(true);
    const api = await arsenal.execute('http_request', { parameters: { url: url + '/api' } });
    expect(api.metadata?.responseStatus).toBe(401); expect(api.metadata?.responseBody).toBe('Response: 日本語');
    const redirect = await arsenal.execute('http_request', { parameters: { url: url + '/jump' } });
    expect(redirect.success).toBe(false); expect(redirect.error).toContain('SCOPE DENIED');
    const completed = events.filter(event => event.type === 'completed');
    expect(completed).toHaveLength(3);
    expect(completed.every(event => event.command === 'curl' && event.durationMs! >= 0 && event.exitCode === 0)).toBe(true);
    expect(requested).toEqual(['/robots.txt', '/api', '/jump']);
  });

  it('uses an actual OpenSSL command with SNI and reports certificate issues on a local TLS fixture', async () => {
    if (!await isToolAvailable('openssl')) return;
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-tls-fixture-'));
    let server: ReturnType<typeof createTlsServer> | undefined;
    try {
      const keyPath = join(directory, 'key.pem'); const certPath = join(directory, 'cert.pem');
      execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-days', '1', '-keyout', keyPath, '-out', certPath],
        { stdio: 'ignore', timeout: 10000, windowsHide: true });
      const key = await readFile(keyPath); const cert = await readFile(certPath); let servername = '';
      server = createTlsServer({ key, cert, SNICallback: (name, callback) => { servername = name; callback(null, createSecureContext({ key, cert })); } }, socket => socket.end());
      server.on('tlsClientError', () => {});
      await new Promise<void>(resolve => server!.listen(0, '127.0.0.1', resolve));
      const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS);
      arsenal.setScope({ allowedHosts: ['localhost'], allowPrivate: false, allowLoopback: false });
      arsenal.getOrchestrator().scanPolicy.setBehavior('auto');
      const events: ProcessEvent[] = []; arsenal.on('tool:process', event => events.push(event));
      const result = await arsenal.execute('ssl_scan', { parameters: { host: 'localhost', port: (server.address() as { port: number }).port } });
      expect(result.success, result.error).toBe(true);
      expect(servername).toBe('localhost'); expect(result.output).toContain('TLSv1.');
      expect(result.findings?.[0]?.details).toContain('Self-signed');
      expect(events.find(event => event.type === 'started')).toMatchObject({ command: 'openssl', args: expect.arrayContaining(['-servername', 'localhost']) });
      expect(events.find(event => event.type === 'completed')).toMatchObject({ exitCode: 0, durationMs: expect.any(Number) });
    } finally { if (server?.listening) await new Promise<void>(resolve => server!.close(() => resolve())); await rm(directory, { recursive: true, force: true }); }
  }, 15000);
});

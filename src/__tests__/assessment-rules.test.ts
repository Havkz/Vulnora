import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, type Server } from 'node:http';
import * as dns from 'node:dns';
import { normalizeAssessmentRules } from '../projects/assessment.js';
import { ProjectStore } from '../projects/store.js';
import { ProjectSession } from '../projects/session.js';
import { Arsenal, BUILTIN_TOOLS, scopeViolation } from '../arsenal/index.js';
import { ApprovalController } from '../arsenal/approval.js';
import { ScanPolicy } from '../orchestrator/scan-policy.js';
import type { EngineCheckpoint } from '../projects/engine-checkpoint.js';

const directories: string[] = [];
const sessions: ProjectSession[] = [];
const servers: Server[] = [];
afterEach(async () => {
  for (const session of sessions.splice(0)) await session.close();
  for (const server of servers.splice(0)) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
  vi.restoreAllMocks(); vi.useRealTimers();
});
const configuration = { llm: { provider: 'mock' as const, model: 'fixture' } };

describe('durable assessment constraints', () => {
  it('normalizes host rules without silently accepting URL paths or malformed persisted values', () => {
    expect(normalizeAssessmentRules({ scopeHosts: ['API.Example.test.', 'api.example.test', '0:0:0:0:0:0:0:1'], excludedTools: ['nmap_scan', 'nmap_scan'] }))
      .toEqual({ scopeHosts: ['::1', 'api.example.test'], excludedHosts: [], excludedTools: ['nmap_scan'] });
    for (const value of [null, [], { excludedHosts: null }, { requestsPerSecond: 0 }, { requestsPerSecond: 1.5 }, { requestsPerSecond: '2' },
      { scopeHosts: ['https://example.test/private'] }, { scopeHosts: ['10.0.0.0/8'] }, { scopeHosts: ['*.example.test'] },
      { excludedRisks: ['unknown'] }, { excludedRisks: null }, { scopeHosts: ['example.test:443'] }, { excludedTools: ['curl --url'] }, { unexpected: true }]) {
      expect(() => normalizeAssessmentRules(value)).toThrow();
    }
    expect(() => normalizeAssessmentRules({ excludedHosts: ['example.test'] }, 'https://api.example.test/')).toThrow('primary target');
  });

  it('gives host exclusions precedence over exact, subdomain and private-network allowances', () => {
    const scope = { allowedHosts: ['example.test', '127.0.0.1', '::1'], excludedHosts: ['blocked.example.test', '127.0.0.1', '::1'], allowPrivate: true, allowLoopback: true };
    for (const host of ['blocked.example.test', 'child.blocked.example.test', 'BLOCKED.EXAMPLE.TEST.', '127.0.0.1', '0:0:0:0:0:0:0:1']) {
      expect(scopeViolation(scope, { parameters: { host } })).not.toBeNull();
    }
    expect(scopeViolation(scope, { parameters: { host: 'notblocked.example.test' } })).toBeNull();
    expect(scopeViolation(scope, { parameters: { host: 'blocked.example.test.evil.test' } })).not.toBeNull();
    expect(scopeViolation(scope, { parameters: { target: '10.0.0.0/8' } })).not.toBeNull();
  });

  it('removes excluded tools from model definitions and refuses direct execution before the handler', async () => {
    const arsenal = new Arsenal(); const handler = vi.fn(async () => ({ success: true }));
    arsenal.register({ name: 'probe', category: 'web', description: 'fixture', parameters: [], handler });
    arsenal.setScope({ allowedHosts: ['fixture.test'], excludedTools: ['probe'], allowPrivate: false, allowLoopback: false });
    expect(arsenal.getToolDefinitions(undefined, ['probe'])).toEqual([]);
    expect(await arsenal.getReadyToolDefinitions()).toEqual([]);
    expect(await arsenal.execute('probe', { parameters: { url: 'https://fixture.test' } }))
      .toMatchObject({ success: false, metadata: { executionStatus: 'blocked' } });
    expect(handler).not.toHaveBeenCalled();
  });

  it('excludes risk classes before approval, readiness checks or handler execution', async () => {
    const arsenal = new Arsenal(); const handler = vi.fn(async () => ({ success: true }));
    arsenal.register({ name: 'destructive_fixture', category: 'test', description: 'fixture', riskTier: 'dangerous', handler });
    arsenal.register({ name: 'untyped_extension', category: 'test', description: 'fixture', handler });
    arsenal.registerMany(BUILTIN_TOOLS);
    arsenal.setApprovalController(new ApprovalController({ preApprovedTools: ['destructive_fixture', 'sqli_scan'] }));
    arsenal.setScope({ allowedHosts: ['fixture.test'], excludedRisks: ['dangerous', 'intrusive'], allowPrivate: false, allowLoopback: false });
    const names = arsenal.getToolDefinitions().map(tool => tool.name);
    expect(names).not.toContain('destructive_fixture'); expect(names).not.toContain('untyped_extension'); expect(names).not.toContain('sqli_scan');
    expect(names).toContain('http_request');
    for (const tool of ['destructive_fixture', 'untyped_extension', 'sqli_scan']) {
      expect(await arsenal.execute(tool, { parameters: { url: 'https://fixture.test', param: 'q' } }))
        .toMatchObject({ success: false, metadata: { orchestrationStatus: 'not_authorized' } });
    }
    expect(handler).not.toHaveBeenCalled();
    expect(arsenal.getApprovalController()?.getAudit()).toEqual([]);
  });

  it('allows bodyless GET while preventing state-changing HTTP and curl requests before network execution', async () => {
    const requests: string[] = [];
    const server = createServer((request, response) => { requests.push(request.method || ''); response.end('Fixture'); });
    servers.push(server); await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const url = `http://127.0.0.1:${(server.address() as { port: number }).port}/`;
    const { EXTERNAL_TOOLS } = await import('../arsenal/index.js');
    const arsenal = new Arsenal(); arsenal.registerMany([...BUILTIN_TOOLS, ...EXTERNAL_TOOLS]);
    arsenal.setScope({ allowedHosts: ['127.0.0.1'], excludedRisks: ['dangerous'], allowPrivate: false, allowLoopback: false });
    expect((await arsenal.execute('http_request', { parameters: { url, method: 'GET', body: '' } })).success).toBe(true);
    for (const tool of ['http_request', 'curl_request']) {
      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'CONNECT']) {
        expect((await arsenal.execute(tool, { parameters: { url, method } })).success).toBe(false);
      }
      expect((await arsenal.execute(tool, { parameters: { url, method: 'GET', body: 'data', data: 'data' } })).success).toBe(false);
    }
    const nested = await arsenal.execute('password_spray', { parameters: { url, username: 'fixture' } });
    expect(nested).toMatchObject({ success: false, metadata: { orchestrationStatus: 'not_authorized' } });
    expect(arsenal.getOrchestrator().getEvidence().at(-1)?.errorType).toBe('not_authorized');
    expect(requests).toEqual(['GET']);
  });

  it('does not query excluded names generated by subdomain enumeration', async () => {
    const queried: string[] = [];
    vi.spyOn(dns.promises, 'resolve4').mockImplementation(async name => { queried.push(name); return ['192.0.2.1']; });
    const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS);
    arsenal.setScope({ allowedHosts: ['fixture.test'], excludedHosts: ['www.fixture.test'], allowPrivate: false, allowLoopback: false });
    const result = await arsenal.execute('subdomain_enum', { parameters: { domain: 'fixture.test' } });
    expect(result.success).toBe(true); expect(queried.length).toBeGreaterThan(0);
    expect(queried).not.toContain('www.fixture.test');
    expect(result.output).not.toContain('www.fixture.test');
  });

  it('rejects excluded HTTP redirect destinations before sending the second request', async () => {
    let hits = 0;
    const server = createServer((_request, response) => { hits++; response.writeHead(302, { Location: 'http://localhost:1/forbidden' }); response.end(); });
    servers.push(server); await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address(); if (!address || typeof address === 'string') throw new Error('Missing server');
    const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS);
    arsenal.setScope({ allowedHosts: ['127.0.0.1', 'localhost'], excludedHosts: ['localhost'], allowPrivate: false, allowLoopback: false });
    const result = await arsenal.execute('http_request', { parameters: { url: `http://127.0.0.1:${address.port}/`, method: 'GET' } });
    expect(result.success).toBe(false); expect(result.error).toContain('SCOPE DENIED'); expect(hits).toBe(1);
  });

  it('restores exactly the recorded scope, tool exclusions and rate and rejects a mismatched project', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-assessment-')); directories.push(directory);
    const store = new ProjectStore(directory);
    const rules = normalizeAssessmentRules({ scopeHosts: ['api.fixture.test'], excludedHosts: ['private.api.fixture.test'], excludedTools: ['nmap_scan'], excludedRisks: ['dangerous', 'credential'], requestsPerSecond: 2 });
    const project = await store.create('Constraints', 'https://fixture.test', 'aggressive', rules);
    expect((await store.updateReadyProject(project.id, { assessment: rules })).assessment).toEqual(rules);
    const first = await ProjectSession.open(store, project.id, configuration); sessions.push(first);
    await expect(store.updateReadyProject(project.id, { assessment: { scopeHosts: ['other.test'] } })).rejects.toThrow('exclusive project access');
    await first.start(); await first.pause(); await first.close();
    await expect(store.updateReadyProject(project.id, { targetInput: 'https://other.test' })).rejects.toThrow('fixed after');
    const saved = await store.load(project.id);
    expect((saved.checkpoint as EngineCheckpoint).assessment).toEqual(rules);
    const restored = await ProjectSession.open(store, project.id, configuration); sessions.push(restored);
    expect(restored.command.arsenal.getScope()).toMatchObject({ allowedHosts: ['fixture.test', 'api.fixture.test'], excludedHosts: rules.excludedHosts, excludedTools: rules.excludedTools, excludedRisks: rules.excludedRisks });
    expect(restored.command.arsenal.getOrchestrator().scanPolicy.limits('fixture.test').intervalMs).toBe(500);
    expect(restored.command.arsenal.getToolDefinitions().some(tool => tool.name === 'nmap_scan')).toBe(false);
    await restored.close();
    saved.assessment = { ...rules, excludedRisks: ['active'] }; await store.save(saved);
    const before = await readFile(join(directory, `${project.id}.json`), 'utf8');
    await expect(ProjectSession.open(store, project.id, configuration)).rejects.toThrow('rules do not match');
    expect(await readFile(join(directory, `${project.id}.json`), 'utf8')).toBe(before);
  });

  it('enforces a persisted rate ceiling across concurrent HTTP starts and external command arguments', async () => {
    const policy = new ScanPolicy(); policy.setBehavior('aggressive'); policy.setRateLimit(2);
    const starts: number[] = [];
    const calls = Promise.all(['fixture.test', 'FIXTURE.test.', 'fixture.test'].map(host => policy.fetch(new URL(`http://${host}`), {}, async () => {}, async () => {
      starts.push(Date.now()); return new Response('ok');
    }).then(response => response.text())));
    await calls;
    expect(starts).toHaveLength(3);
    expect(starts.slice(1).every((at, index) => at - starts[index] >= 490)).toBe(true);
    expect(policy.commandArgs('nuclei', ['-rl', '500'], 'fixture.test')).toContain('2');
    expect(policy.commandArgs('gobuster', ['--threads', '50'], 'fixture.test')).toContain('500ms');
    expect(policy.commandArgs('gobuster', [], 'fixture.test').slice(0, 2)).toEqual(['--threads', '1']);
    const saved = policy.exportCheckpoint(); if (!saved) throw new Error('Missing policy');
    const restored = new ScanPolicy(); restored.restoreCheckpoint(saved); restored.setBehavior('auto');
    expect(restored.limits('fixture.test').intervalMs).toBe(500);
    expect(() => restored.restoreCheckpoint({ ...saved, requestsPerSecond: 0 })).toThrow('Rate limit');
  });
});

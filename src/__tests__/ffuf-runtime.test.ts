import { expect, it } from 'vitest';
import { createServer } from 'node:http';
import { access, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Arsenal, EXTERNAL_TOOLS, isToolAvailable, type ProcessEvent } from '../arsenal/index.js';

it.skipIf(!await isToolAvailable('ffuf'))('parses real FFUF JSON lines, including an empty scan, and reuses completed results', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'vulnora-ffuf-'));
  const wordlist = join(directory, 'paths.txt'); await writeFile(wordlist, 'api/config\nmissing\n');
  const requests: string[] = [];
  const server = createServer((request, response) => {
    requests.push(request.url || ''); response.statusCode = request.url === '/api/config' ? 200 : 404;
    response.end(request.url === '/api/config' ? 'Fixture configuration' : 'Missing');
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('Missing fixture address');
  const origin = `http://127.0.0.1:${address.port}`;
  const arsenal = new Arsenal(); arsenal.registerMany(EXTERNAL_TOOLS.filter(tool => tool.name === 'ffuf_fuzz'));
  const events: ProcessEvent[] = []; arsenal.on('tool:process', event => events.push(event));
  try {
    const parameters = { url: origin + '/FUZZ', wordlist, mc: '200' };
    const [first, shared] = await Promise.all([
      arsenal.execute('ffuf_fuzz', { parameters }), arsenal.execute('ffuf_fuzz', { parameters }),
    ]);
    expect(shared.metadata?.cacheHit).toBe(true);
    expect(first.success, first.error).toBe(true); expect(first.output).toContain(origin + '/api/config -> 200');
    expect(first.findings).toHaveLength(1);
    expect(first.metadata?.networkRequests).toBe(2);
    expect(events[0].args).toContain('-json'); expect(events[0].args).not.toContain('/dev/stdout');
    const count = requests.length;
    const cached = await arsenal.execute('ffuf_fuzz', { parameters });
    expect(cached.metadata?.cacheHit).toBe(true); expect(requests).toHaveLength(count); expect(events).toHaveLength(2);
    const negative = await arsenal.execute('ffuf_fuzz', { parameters: { ...parameters, url: origin + '/absent/FUZZ' } });
    expect(negative.success, negative.error).toBe(true); expect(negative.output).toContain('Found 0 results');
    expect(negative.findings).toBeUndefined();
    await writeFile(wordlist, 'one\none\n# comment\ntwo\nthree\nfour\n');
    const bounded = new Arsenal(); bounded.registerMany(EXTERNAL_TOOLS.filter(tool => tool.name === 'ffuf_fuzz'));
    const orchestrator = bounded.getOrchestrator(); orchestrator.getBudget(origin);
    const saved = orchestrator.exportCheckpoint();
    saved.budgets[0][1].limits.total_request_budget = 3; saved.budgets[0][1].limits.content_discovery_budget = 3;
    orchestrator.restoreCheckpoint(saved);
    const boundedEvents: ProcessEvent[] = []; bounded.on('tool:process', event => boundedEvents.push(event));
    const before = requests.length;
    const limited = await bounded.execute('ffuf_fuzz', { parameters: { ...parameters, url: origin + '/bounded/FUZZ' } });
    expect(limited.success, limited.error).toBe(true);
    expect(requests.slice(before)).toEqual(expect.arrayContaining(['/bounded/one', '/bounded/two', '/bounded/three']));
    expect(requests.length - before).toBe(3);
    expect(limited.metadata).toMatchObject({ wordlistTruncated: true, wordlistEntries: 3, wordlistTotalEntries: 4, networkRequests: 3 });
    expect(limited.output).toContain('3/4 wordlist entries');
    expect(orchestrator.getBudget(origin).remaining.total_request_budget).toBe(0);
    const invocation = boundedEvents[0].args; const temporary = invocation[invocation.indexOf('-w') + 1];
    await expect(access(temporary)).rejects.toThrow();
    const exhausted = await bounded.execute('ffuf_fuzz', { parameters: { ...parameters, url: origin + '/exhausted/FUZZ' } });
    expect(exhausted.metadata?.orchestrationStatus).toBe('budget_exceeded');
    expect(requests.length - before).toBe(3);
  } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); await rm(directory, { recursive: true, force: true }); }
}, 15_000);

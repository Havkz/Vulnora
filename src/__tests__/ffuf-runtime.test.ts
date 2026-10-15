import { expect, it } from 'vitest';
import { createServer } from 'node:http';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
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
    const first = await arsenal.execute('ffuf_fuzz', { parameters });
    expect(first.success, first.error).toBe(true); expect(first.output).toContain(origin + '/api/config -> 200');
    expect(first.findings).toHaveLength(1);
    expect(events[0].args).toContain('-json'); expect(events[0].args).not.toContain('/dev/stdout');
    const count = requests.length;
    const cached = await arsenal.execute('ffuf_fuzz', { parameters });
    expect(cached.metadata?.cacheHit).toBe(true); expect(requests).toHaveLength(count); expect(events).toHaveLength(2);
    const negative = await arsenal.execute('ffuf_fuzz', { parameters: { ...parameters, url: origin + '/absent/FUZZ' } });
    expect(negative.success, negative.error).toBe(true); expect(negative.output).toContain('Found 0 results');
    expect(negative.findings).toBeUndefined();
  } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); await rm(directory, { recursive: true, force: true }); }
}, 15_000);

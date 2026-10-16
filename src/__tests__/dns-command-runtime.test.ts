import { expect, it, vi } from 'vitest';
import { createSocket } from 'node:dgram';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { commandPath } from '../command-path.js';
import { Arsenal, BUILTIN_TOOLS, type ProcessEvent } from '../arsenal/index.js';
import { formatProjectLog } from '../ui/project-log.js';
import { createTheme } from '../ui/theme.js';

const dig = await commandPath('dig');
it.skipIf(process.platform === 'win32' || !dig)('runs real dig against local DNS, journals the command, and preserves negative answers and failures', async () => {
  const server = createSocket('udp4');
  let queries = 0;
  server.on('message', (query, remote) => {
    queries++;
    let end = 12;
    while (query[end]) end += query[end] + 1;
    end += 5;
    const type = query.readUInt16BE(end - 4);
    const flags = type === 1 ? 0x8180 : type === 28 ? 0x8183 : 0x8182;
    const header = Buffer.alloc(12); query.copy(header, 0, 0, 2);
    header.writeUInt16BE(flags, 2); header.writeUInt16BE(1, 4); header.writeUInt16BE(type === 1 ? 1 : 0, 6);
    const answer = type === 1 ? Buffer.from('c00c000100010000003c00047f000001', 'hex') : Buffer.alloc(0);
    server.send(Buffer.concat([header, query.subarray(12, end), answer]), remote.port, remote.address);
  });
  await new Promise<void>(resolve => server.bind(0, '127.0.0.1', resolve));
  const directory = await mkdtemp(join(tmpdir(), 'vulnora-dns-'));
  try {
    await writeFile(join(directory, 'dig'), `#!/bin/sh\nexec '${dig?.replace(/'/g, "'\\''")}' @127.0.0.1 -p ${server.address().port} "$@"\n`, { mode: 0o700 });
    vi.stubEnv('PATH', directory + ':' + process.env.PATH);
    const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS.filter(tool => tool.name === 'dns_lookup'));
    const events: ProcessEvent[] = []; arsenal.on('tool:process', event => events.push(event));
    const [first, shared] = await Promise.all([0, 1].map(() => arsenal.execute('dns_lookup', { parameters: { domain: 'fixture.test', type: 'A' } })));
    expect(first.success, first.error).toBe(true); expect(first.output).toContain('127.0.0.1');
    expect(shared.metadata?.cacheHit).toBe(true); expect(queries).toBe(1); expect(events).toHaveLength(2);
    expect(first.metadata?.executionTraced).toBe(true);
    const rendered = formatProjectLog({ timestamp: Date.now(), category: 'execution:completed', data: events[1] }, false, createTheme(3));
    expect(rendered).toContain('\u001b[38;5;25mdig'); expect(rendered).toContain('Ran'); expect(rendered).not.toContain('Analyzed');
    const negative = await arsenal.execute('dns_lookup', { parameters: { domain: 'fixture.test', type: 'AAAA' } });
    expect(negative.success).toBe(true); expect(negative.output).toContain('no records found (NXDOMAIN)');
    const failed = await arsenal.execute('dns_lookup', { parameters: { domain: 'fixture.test', type: 'MX' } });
    expect(failed.success).toBe(false); expect(failed.error).toContain('SERVFAIL');
    const count = queries;
    expect((await arsenal.execute('dns_lookup', { parameters: { domain: 'fixture.test', type: 'AXFR' } })).output).toContain('not supported');
    expect(queries).toBe(count);
  } finally {
    vi.unstubAllEnvs(); server.close(); await rm(directory, { recursive: true, force: true });
  }
});

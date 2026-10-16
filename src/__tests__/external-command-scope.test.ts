import { expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import { Arsenal, EXTERNAL_TOOLS, isToolAvailable } from '../arsenal/index.js';

it.skipIf(!await isToolAvailable('curl'))('keeps a real curl request on its approved host when flags attempt to replace the connection destination', async () => {
  const received = { approved: 0, other: 0 };
  const approved = createServer((_request, response) => { received.approved++; response.end('Approved fixture'); });
  const other = createServer((_request, response) => { received.other++; response.end('Other fixture'); });
  const listen = async (server: Server, host: string) => {
    await new Promise<void>(resolve => server.listen(0, host, resolve));
    const address = server.address(); if (!address || typeof address === 'string') throw new Error('Fixture did not bind');
    return address.port;
  };
  try {
    const port = await listen(approved, '127.0.0.1'); const alternate = await listen(other, '127.0.0.2');
    const arsenal = new Arsenal(); arsenal.registerMany(EXTERNAL_TOOLS.filter(tool => tool.name === 'curl_request'));
    arsenal.setScope({ allowedHosts: ['127.0.0.1'], exactHosts: true, allowLoopback: false, allowPrivate: false });
    arsenal.getOrchestrator().scanPolicy.setBehavior('aggressive');
    const result = await arsenal.execute('curl_request', { parameters: { url: `http://127.0.0.1:${port}/scope-fixture`,
      flags: `--connect-to 127.0.0.1:${port}:127.0.0.2:${alternate}` } });
    expect(result.success, result.error).toBe(true);
    expect(received).toEqual({ approved: 1, other: 0 });
    expect(result.output).toContain('Approved fixture');
    const invalidHeader = await arsenal.execute('curl_request', { parameters: { url: `http://127.0.0.1:${port}/header-fixture`, headers: '@local-file' } });
    expect(invalidHeader.success).toBe(false); expect(invalidHeader.error).toContain('Name: Value');
    expect(received).toEqual({ approved: 1, other: 0 });
  } finally {
    await Promise.all([approved, other].map(server => new Promise<void>(resolve => {
      server.closeAllConnections(); server.close(() => resolve());
    })));
  }
}, 20000);

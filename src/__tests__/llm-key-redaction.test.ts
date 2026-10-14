import { describe, expect, it } from 'vitest';
import { createServer } from 'node:http';
import { LLMBackbone } from '../llm/index.js';

describe('configured credential redaction', () => {
  it('keeps an opaque key out of real API failure events and thrown errors without losing status', async () => {
    const credential = 'opaque-fixture-credential-4e7fb18cebc84660';
    let authorization = '';
    const server = createServer((request, response) => {
      authorization = request.headers.authorization || '';
      response.writeHead(401, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: { message: `Rejected value ${credential}` } }));
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const address = server.address() as { port: number };
      const llm = new LLMBackbone({ provider: 'openai', model: 'fixture', apiKey: credential,
        baseUrl: `http://127.0.0.1:${address.port}/v1`, timeout: 2000, fallbackChain: [] });
      const errors: Error[] = [];
      llm.on('request:error', ({ error }) => errors.push(error));
      const result = await llm.chat([{ role: 'user', content: 'Fixture inference' }]).catch(error => error);
      expect(authorization).toBe(`Bearer ${credential}`);
      expect(result).toBeInstanceOf(Error); expect(result.status).toBe(401);
      expect(result.message).toContain('[redacted]');
      expect(`${result.message}\n${result.stack}`).not.toContain(credential);
      expect(errors).toHaveLength(1);
      expect(errors.map(error => `${error.message}\n${error.stack}`).join('\n')).not.toContain(credential);
    } finally {
      server.closeAllConnections();
      await new Promise<void>(resolve => server.close(() => resolve()));
    }
  });
});

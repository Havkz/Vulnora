import { afterEach, describe, expect, it } from 'vitest';
import { createServer, type RequestListener, type Server } from 'node:http';
import { gzipSync } from 'node:zlib';
import { reviewBrowserSurface } from '../../src/arsenal/browser-surface.js';
import { Arsenal, BUILTIN_TOOLS } from '../../src/arsenal/index.js';

const servers: Server[] = [];
async function fixture(handler: RequestListener) {
  const server = createServer(handler); servers.push(server);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('No fixture address');
  return `http://127.0.0.1:${address.port}/`;
}
afterEach(async () => {
  for (const server of servers.splice(0)) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
});
const read = (url: string, init: RequestInit) => fetch(url, init);

describe('sandboxed browser surface discovery', () => {
  it('discovers script-generated forms and actual API requests without refetching cached scripts', async () => {
    const paths: string[] = [];
    const url = await fixture((req, res) => {
      paths.push(req.url || '/');
      if (req.url === '/app.js') {
        res.writeHead(200, { 'content-type': 'text/javascript' });
        res.end(`fetch('/api/items?filter=all').then(r=>r.json()).then(data=>{
          const form=document.createElement('form');form.action='/search';
          const input=document.createElement('input');input.name=data.field;form.append(input);document.body.append(form);
        });`); return;
      }
      if (req.url?.startsWith('/api/items')) { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"field":"term"}'); return; }
      res.writeHead(200, { 'content-type': 'text/html' }); res.end('<body><script src=/app.js></script></body>');
    });
    const result = await reviewBrowserSurface(url + '#/catalog', read);
    expect(result.success).toBe(true);
    expect(result.metadata?.websiteSurface).toMatchObject({ complete: true, renderedUrls: [url], inputTargets: expect.arrayContaining([
      { url: url + 'search?term=', param: 'term' }, { url: url + 'api/items?filter=all', param: 'filter' },
    ]) });
    expect(result.metadata?.observedApiRequests).toEqual([url + 'api/items?filter=all']);
    expect(paths).toEqual(['/', '/app.js', '/api/items?filter=all']);
  }, 30000);

  it('blocks foreign origins, writes, action URLs, WebSockets and service workers', async () => {
    const outside: string[] = []; const inside: string[] = [];
    const foreign = await fixture((req, res) => { outside.push(req.url || '/'); res.end('outside'); });
    const url = await fixture((req, res) => {
      inside.push(`${req.method} ${req.url}`); res.writeHead(200, { 'content-type': 'text/html' });
      res.end(`<body><script>
        fetch('${foreign}leak').catch(()=>{});
        fetch('/write',{method:'POST',body:'changed'}).catch(()=>{});
        fetch('/delete?id=1').catch(()=>{});
        new WebSocket('${foreign.replace('http:', 'ws:')}socket');
        navigator.serviceWorker.register('/worker.js').catch(()=>{});
        const frame=document.createElement('iframe');frame.src='${foreign}frame';document.body.append(frame);
      </script>`);
    });
    const result = await reviewBrowserSurface(url, read);
    expect(outside).toEqual([]); expect(inside).toEqual(['GET /']);
    expect(result.metadata?.websiteSurface).toMatchObject({ complete: false });
    expect(result.output).toContain('POST'); expect(result.output).toContain('WebSocket blocked');
  }, 30000);

  it('follows authorized redirects and does not follow a redirect to another origin', async () => {
    const outside: string[] = [];
    const foreign = await fixture((req, res) => { outside.push(req.url || '/'); res.end('outside'); });
    const url = await fixture((req, res) => {
      if (req.url === '/') { res.writeHead(302, { location: '/landing' }); res.end(); return; }
      if (req.url === '/escape') { res.writeHead(302, { location: foreign }); res.end(); return; }
      res.writeHead(200, { 'content-type': 'text/html' }); res.end('<form><input name=q></form><script>fetch("/escape").catch(()=>{})</script>');
    });
    const result = await reviewBrowserSurface(url, read);
    expect(result.metadata?.websiteSurface).toMatchObject({ renderedUrls: [url + 'landing'], complete: false,
      inputTargets: [{ url: url + 'landing?q=', param: 'q' }] });
    expect(outside).toEqual([]);
  }, 30000);

  it('cancels a pending managed read when the scan is paused', async () => {
    const controller = new AbortController(); let interrupted = false;
    const url = await fixture((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<script>fetch("/pending")</script>'); });
    const result = reviewBrowserSurface(url, async (address, init) => {
      if (address.endsWith('/pending')) {
        setTimeout(() => controller.abort(), 50);
        return new Promise<Response>((_resolve, reject) => init.signal?.addEventListener('abort', () => { interrupted = true; reject(new Error('cancelled')); }, { once: true }));
      }
      return read(address, init);
    }, controller.signal);
    await expect(result).rejects.toThrow(); expect(interrupted).toBe(true);
  }, 30000);

  it('preserves isolated cookies and uses the current arsenal admission context on every request', async () => {
    for (let run = 0; run < 2; run++) {
      const cookies: string[] = [];
      const url = await fixture((req, res) => {
        if (req.url === '/api') { cookies.push(req.headers.cookie || ''); res.end('ok'); return; }
        res.writeHead(200, { 'content-type': 'text/html', 'content-encoding': 'gzip', 'set-cookie': [`one=${run}; Path=/; HttpOnly`, `two=${run}; Path=/`] });
        res.end(gzipSync('<body><script>fetch("/api")</script></body>'));
      });
      const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS.filter(tool => tool.name === 'browser_surface_review'));
      const processEvents: unknown[] = []; arsenal.on('tool:process', event => processEvents.push(event));
      arsenal.setScope({ allowedHosts: ['127.0.0.1'], allowPrivate: false, allowLoopback: false });
      arsenal.getOrchestrator().scanPolicy.setBehavior('auto');
      const result = await arsenal.execute('browser_surface_review', { parameters: { url } });
      expect(result.success).toBe(true);
      expect(cookies).toEqual([expect.stringContaining(`one=${run}`)]);
      expect(cookies[0]).toContain(`two=${run}`);
      expect(result.metadata?.networkRequestsActual).toBe(2);
      expect(processEvents).toEqual([]);
      expect(arsenal.getOrchestrator().getEvidence().at(-1)?.result?.metadata?.browserRequests).toBe(2);
    }
  }, 30000);

  it('leaves coverage incomplete when the response data limit is exceeded', async () => {
    const url = await fixture((req, res) => {
      if (req.url === '/large') { res.end('x'.repeat(8 * 1024 * 1024)); return; }
      res.writeHead(200, { 'content-type': 'text/html' }); res.end('<body><script>fetch("/large").catch(()=>{})</script></body>');
    });
    const result = await reviewBrowserSurface(url, read);
    expect(result.metadata?.websiteSurface).toMatchObject({ complete: false });
    expect(result.output).toContain('8 MiB response limit');
  }, 30000);

  it('bounds managed requests even when scripts issue a burst', async () => {
    let requests = 0;
    const url = await fixture((req, res) => {
      requests++;
      if (req.url !== '/') { res.end('ok'); return; }
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<body><script>for(let i=0;i<70;i++)fetch("/read?i="+i).catch(()=>{})</script></body>');
    });
    const result = await reviewBrowserSurface(url, read);
    expect(requests).toBe(64); expect(result.metadata?.browserRequests).toBe(64);
    expect(result.metadata?.websiteSurface).toMatchObject({ complete: false });
    expect(result.output).toContain('64-request limit');
  }, 30000);

  it('denies popup traffic that is outside the inspected page interception', async () => {
    let outside = 0;
    const foreign = await fixture((_req, res) => { outside++; res.end('outside'); });
    const url = await fixture((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(`<body><script>window.open('${foreign}popup')</script></body>`);
    });
    const result = await reviewBrowserSurface(url, read);
    expect(outside).toBe(0);
    expect(result.metadata?.websiteSurface).toMatchObject({ complete: false });
    expect(result.output).toContain('Unintercepted browser HTTP request blocked');
  }, 30000);
});

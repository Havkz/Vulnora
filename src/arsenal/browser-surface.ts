import { createServer } from 'node:http';
import type { Browser } from 'playwright-core';
import { reviewWebsiteSurface, type WebsiteSurface } from './website-surface.js';
import type { ToolResult } from '../types/index.js';

type ManagedRead = (url: string, init: RequestInit) => Promise<Response>;
type ResponseData = { status: number; body: Buffer; headers: Record<string, string>; url: string };
const unsafeRoute = /(?:logout|signout|delete|remove|unsubscribe|password|secret|token|csrf)/i;

/** A disposable renderer: Chromium never forwards requests to the target itself. */
export async function reviewBrowserSurface(url: string, read: ManagedRead, parentSignal?: AbortSignal): Promise<ToolResult> {
  const root = new URL(url);
  if (!['http:', 'https:'].includes(root.protocol) || root.username || root.password) throw new Error('Browser review requires an HTTP(S) URL without credentials.');
  const controller = new AbortController();
  const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(120_000), ...(parentSignal ? [parentSignal] : [])]);
  signal.throwIfAborted();
  const limitations = new Set<string>();
  const note = (message: string) => {
    if (limitations.size < 64) limitations.add(message.slice(0, 1024));
    else limitations.add('Additional browser limitations omitted.');
  };
  const browserController = new AbortController();
  const responses = new Map<string, ResponseData>();
  const apiRequests = new Set<string>();
  let requests = 0; let bytes = 0;
  const allowed = (address: string) => {
    const value = new URL(address);
    return value.origin === root.origin && !value.username && !value.password && !unsafeRoute.test(value.pathname + value.search);
  };
  const request = async (address: string, init: RequestInit = {}): Promise<ResponseData> => {
    signal.throwIfAborted();
    if (!allowed(address) || !['GET', 'HEAD'].includes(init.method || 'GET')) throw new Error(`Browser request excluded: ${init.method || 'GET'} ${address}`);
    if (requests >= 64) throw new Error('Browser review reached its 64-request limit.');
    requests++;
    const headersToSend = new Headers(init.headers);
    headersToSend.delete('accept-encoding'); // Let the managed transport negotiate encodings it can decode.
    const response = await read(address, { ...init, headers: headersToSend, redirect: 'manual', signal: init.signal ? AbortSignal.any([signal, init.signal]) : signal });
    const reader = response.body?.getReader(); const chunks: Buffer[] = [];
    try {
      if (reader) {
        for (;;) {
          signal.throwIfAborted();
          const chunk = await reader.read(); if (chunk.done) break;
          bytes += chunk.value.length;
          if (bytes > 8 * 1024 * 1024) throw new Error('Browser review reached its 8 MiB response limit.');
          chunks.push(Buffer.from(chunk.value));
        }
      }
    } finally { await reader?.cancel().catch(() => {}); }
    const headers = Object.fromEntries(response.headers);
    const cookies = response.headers.getSetCookie();
    if (cookies.length) headers['set-cookie'] = cookies.join('\n');
    // Fetch/curl may decode the payload; forwarding wire framing would corrupt it.
    for (const name of ['content-encoding', 'content-length', 'transfer-encoding', 'connection']) delete headers[name];
    const result = { status: response.status, body: Buffer.concat(chunks), headers, url: address };
    if ((init.method || 'GET') === 'GET') responses.set(address, result);
    if (response.status >= 500 || response.status === 429) note(`HTTP ${response.status}: ${address}`);
    return result;
  };

  // Unintercepted browser traffic (including CONNECT) fails closed at this local proxy.
  const proxy = createServer((_request, response) => { note('Unintercepted browser HTTP request blocked.'); response.writeHead(403); response.end(); });
  proxy.on('connect', (_request, socket) => { note('Unintercepted browser tunnel blocked.'); socket.destroy(); });
  await new Promise<void>((resolve, reject) => { proxy.once('error', reject); proxy.listen(0, '127.0.0.1', resolve); });
  const address = proxy.address();
  if (!address || typeof address === 'string') { proxy.close(); throw new Error('Browser proxy did not bind.'); }
  let browser: Browser | undefined;
  const pending = new Set<Promise<void>>();
  const stop = () => { void browser?.close().catch(() => {}); };
  signal.addEventListener('abort', stop, { once: true });
  try {
    const { chromium } = await import('playwright-core');
    browser = await chromium.launch({ headless: true, chromiumSandbox: true, timeout: 15_000,
      proxy: { server: `http://127.0.0.1:${address.port}`, bypass: '<-loopback>' },
      args: ['--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--disable-quic', '--disable-features=DnsOverHttpsUpgrade'] });
    signal.throwIfAborted();
    const context = await browser.newContext({ serviceWorkers: 'block', acceptDownloads: false });
    await context.routeWebSocket('**/*', socket => { note(`WebSocket blocked: ${socket.url()}`); socket.close(); });
    const page = await context.newPage();
    // Playwright route() only sees the first request in a redirect chain; CDP sees each hop.
    const session = await context.newCDPSession(page);
    await session.send('Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Request' }] });
    session.on('Fetch.requestPaused', event => {
      const handle = async () => {
        try {
          const response = await request(event.request.url, { method: event.request.method, headers: event.request.headers, signal: browserController.signal });
          if (['XHR', 'Fetch'].includes(event.resourceType)) apiRequests.add(event.request.url);
          await session.send('Fetch.fulfillRequest', { requestId: event.requestId, responseCode: response.status,
            responseHeaders: Object.entries(response.headers).flatMap(([name, value]) => name === 'set-cookie'
              ? value.split('\n').map(item => ({ name, value: item })) : [{ name, value }]), body: response.body.toString('base64') });
        } catch (error) {
          if (!signal.aborted && !browserController.signal.aborted) note(error instanceof Error ? error.message : String(error));
          await session.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'BlockedByClient' }).catch(() => {});
        }
      };
      const task = handle(); pending.add(task); void task.finally(() => pending.delete(task));
    });
    page.on('dialog', dialog => { void dialog.dismiss().catch(() => {}); });
    let loaded = false;
    try {
      await page.goto(root.href, { waitUntil: 'domcontentloaded', timeout: 60_000 });
      loaded = true;
      await page.waitForLoadState('networkidle', { timeout: 5_000 });
    } catch (error) { signal.throwIfAborted(); note(`Rendering did not settle: ${error instanceof Error ? error.message.split('\n')[0] : String(error)}`); }
    const finalAddress = new URL(page.url()); finalAddress.hash = '';
    const finalUrl = finalAddress.href;
    if (!loaded || !allowed(finalUrl)) throw new Error('Browser could not render an authorized document.');
    const document = responses.get(finalUrl);
    if (!document) throw new Error('Browser document has no managed HTTP response.');
    const html = await page.content();
    browserController.abort(); await context.close(); await Promise.all(pending);
    const result = await reviewWebsiteSurface(finalUrl, [], async requested => {
      if (requested === finalUrl) return { status: document.status, body: html, url: finalUrl, contentType: document.headers['content-type'] };
      let current = requested;
      for (let hop = 0; hop <= 10; hop++) {
        const response = responses.get(current) || await request(current);
        if ([301, 302, 303, 307, 308].includes(response.status) && response.headers.location) {
          current = new URL(response.headers.location, current).href;
          if (!allowed(current)) throw new Error(`Browser discovery redirect excluded: ${current}`);
          continue;
        }
        return { status: response.status, body: response.body.toString('utf8'), url: current, contentType: response.headers['content-type'] };
      }
      throw new Error('Browser discovery redirect limit reached.');
    }, signal);
    const surface = result.metadata?.websiteSurface as WebsiteSurface;
    surface.apiHints = [...new Set([...(surface.apiHints || []), ...apiRequests])];
    for (const requested of apiRequests) {
      const value = new URL(requested);
      for (const param of value.searchParams.keys()) {
        if (!surface.inputTargets.some(input => input.url === requested && input.param === param)) {
          if (surface.inputTargets.length >= 128) { note('Browser input inventory reached its 128-parameter limit.'); break; }
          surface.inputTargets.push({ url: requested, param });
        }
      }
      const response = responses.get(requested);
      if (response && [401, 403].includes(response.status)) surface.authentication.push({ url: requested, status: response.status });
    }
    surface.limitations = [...new Set([...(surface.limitations || []), ...limitations])];
    surface.complete = surface.complete && limitations.size === 0;
    surface.renderedUrls = [finalUrl];
    return { ...result, output: `Browser rendered ${finalUrl}; ${requests} managed request(s), ${apiRequests.size} observed fetch/XHR URL(s).\n`
      + `Discovered ${surface.inputTargets.length} GET input(s), ${surface.forms?.length || 0} form(s).\n`
      + 'Only the entry document was rendered; linked pages were inspected as text. No UI actions or form submissions. Service workers, WebSockets, foreign origins and write requests were blocked.'
      + (surface.limitations.length ? `\nIncomplete review:\n${surface.limitations.join('\n')}` : ''),
      metadata: { ...result.metadata, browserRequests: requests, observedApiRequests: [...apiRequests] } };
  } finally {
    controller.abort(); browserController.abort(); signal.removeEventListener('abort', stop);
    await browser?.close().catch(() => {});
    await Promise.all(pending);
    proxy.closeAllConnections(); await new Promise<void>(resolve => proxy.close(() => resolve()));
  }
}

import { describe, expect, it, vi } from 'vitest';
import { reviewWebsiteSurface } from '../arsenal/website-surface.js';
import { evaluateCoverage, planCoverageRecovery } from '../orchestrator/coverage.js';
import type { EvidenceRecord, TargetBudgets } from '../orchestrator/tool-orchestrator.js';

const url = 'https://fixture.test/';
const record = (toolName: string, result: EvidenceRecord['result'], parameters: Record<string, unknown> = { url }): EvidenceRecord => ({
  id: toolName, toolName, target: String(parameters.url || url), requestParameters: parameters, executionStatus: 'executed',
  status: 'success', resultType: 'negative', toolCategory: toolName === 'http_request' ? 'http_fetch' : 'active_validation',
  rawOutput: result.output || '', result,
} as EvidenceRecord);
const plan = (records: EvidenceRecord[], tools = ['web_surface_review', 'xss_scan', 'sqli_scan'], inputAttempts = 0) => {
  const snapshot = evaluateCoverage(url, records); snapshot.retryable = snapshot.retryable.filter(item => ['authentication_testing', 'input_surface'].includes(item));
  return planCoverageRecovery({ snapshot, records, availableTools: new Set(tools), attempts: { input_surface: inputAttempts }, includeValidation: true,
    network: { edgeSurface: false, blockState: 'clear', consecutiveTimeouts: 0, blockingResponses: 0 },
    budget: { remaining: { tool_call_budget: 100, total_request_budget: 1000 } as TargetBudgets } });
};

describe('evidence-driven website coverage', () => {
  it('schedules browser inspection for JavaScript pages and retains inputs from both inventories', async () => {
    const staticResult = await reviewWebsiteSurface(url, [], async () => ({ status: 200, body: '<script>loadApplication()</script><form><input name=staticInput></form>' }));
    const records = [record('web_surface_review', staticResult)];
    const action = () => plan(records, ['browser_surface_review', 'web_surface_review', 'xss_scan', 'sqli_scan']);
    expect(evaluateCoverage(url, records).entries.input_surface.status).toBe('incomplete');
    expect(action()).toMatchObject({ toolName: 'browser_surface_review', parameters: { url } });
    records.push(record('browser_surface_review', { success: true, metadata: { websiteSurface: {
      reviewedUrls: [url], inputTargets: [{ url: url + 'search?dynamic=', param: 'dynamic' }], authentication: [], postForms: 0, renderedUrls: [url], complete: true,
    } } }));
    expect(action()).toMatchObject({ toolName: 'xss_scan', parameters: { param: 'staticInput' } });
    for (const tool of ['xss_scan', 'sqli_scan']) records.push(record(tool, { success: true }, { url: url + '?staticInput=', param: 'staticInput' }));
    expect(action()).toMatchObject({ toolName: 'xss_scan', parameters: { param: 'dynamic' } });
  });
  it('reviews cached bodies and observed API routes without inventing inputs or following foreign links', async () => {
    const http = record('http_request', { success: true, metadata: { responseBody: '<form action="/search" method="get"><input name="q"></form><a href="https://other.test/?foreign=1">Outside</a><form action="/login" method="post"><input type="password" name="password"></form>' } });
    const discovery = record('api_endpoint_discovery', { success: true, output: '/api/config -> 200 (application/json)\n/api/admin -> 401\nhttps://other.test/ -> 200' });
    const read = vi.fn(async () => ({ status: 200, body: '{}' }));
    const result = await reviewWebsiteSurface(url, [http, discovery], read);
    expect(read).toHaveBeenCalledExactlyOnceWith('https://fixture.test/api/config');
    expect(result.metadata?.websiteSurface).toMatchObject({ inputTargets: [{ url: 'https://fixture.test/search?q=', param: 'q' }],
      authentication: expect.arrayContaining([{ url: 'https://fixture.test/api/admin', status: 401 }]), postForms: 1 });
    const review = record('web_surface_review', result);
    const records = [http, discovery, review];
    expect(evaluateCoverage(url, records).entries.authentication_testing.status).toBe('completed_negative');
    expect(plan(records)).toMatchObject({ capability: 'input_surface', toolName: 'xss_scan', parameters: { url: 'https://fixture.test/search?q=', param: 'q' } });
    const xss = record('xss_scan', { success: true }, { url: 'https://fixture.test/search?q=', param: 'q' });
    expect(evaluateCoverage(url, [...records, xss]).entries.input_surface.status).toBe('not_started');
    expect(plan([...records, xss])).toMatchObject({ toolName: 'sqli_scan' });
    const sqli = record('sqli_scan', { success: true }, xss.requestParameters);
    expect(evaluateCoverage(url, [...records, xss, sqli]).entries.input_surface.status).toBe('completed_negative');
    expect(plan([...records, xss, sqli])).toBeUndefined();
  });
  it('retries inconclusive inputs finitely and preserves the coverage gap after exhaustion', () => {
    const input = { url: url + 'search?q=', param: 'q' };
    const review = record('web_surface_review', { success: true, metadata: {
      websiteSurface: { reviewedUrls: [url], inputTargets: [input], authentication: [], postForms: 0 },
    } });
    const xss = { ...record('xss_scan', { success: true, output: 'No verdict' }, input), resultType: 'inconclusive' as const };
    const sqli = record('sqli_scan', { success: true }, input);
    expect(plan([review, sqli, xss])).toMatchObject({ toolName: 'xss_scan', repeatReason: 'previous_failure' });
    const exhausted = [review, sqli, xss, { ...xss, id: 'retry-1' }, { ...xss, id: 'retry-2' }];
    expect(plan(exhausted, undefined, 6)).toBeUndefined();
    expect(plan(exhausted, undefined, 0)).toMatchObject({ toolName: 'xss_scan' });
    expect(plan([review, xss])).toMatchObject({ toolName: 'sqli_scan' });
    expect(evaluateCoverage(url, exhausted).entries.input_surface.status).toBe('not_started');
  });
  it('schedules a surface review for untested authentication and inputs rather than silently ending Scanning', () => {
    expect(plan([])).toMatchObject({ capability: 'authentication_testing', toolName: 'web_surface_review' });
  });
  it('records the absence of testable public inputs after inspection and keeps POST-only testing explicitly blocked', async () => {
    for (const body of ['<p>Static page</p>', '<form method="post"><input name="message"></form>']) {
      const result = await reviewWebsiteSurface(url, [], async () => ({ status: 200, body }));
      const snapshot = evaluateCoverage(url, [record('web_surface_review', result)]);
      expect(snapshot.entries.input_surface.status).toBe(body.includes('form') ? 'blocked' : 'not_applicable');
      expect(snapshot.entries.authentication_testing.status).toBe('not_applicable');
    }
  });
  it('extracts OpenAPI GET query parameters while leaving path templates and non-GET writes untouched', async () => {
    const result = await reviewWebsiteSurface(url, [], async () => ({ status: 200, body: JSON.stringify({ paths: {
      '/api/search': { get: { parameters: [{ in: 'query', name: 'term' }] } },
      '/api/{user}': { get: { parameters: [{ in: 'query', name: 'ignored' }] } },
      '/api/write': { post: { parameters: [{ in: 'query', name: 'write' }] } },
    } }) }));
    expect(result.metadata?.websiteSurface).toMatchObject({ inputTargets: [{ url: 'https://fixture.test/api/search?term=', param: 'term' }] });
  });
  it('does not turn server failures into completed negative surface evidence', async () => {
    expect((await reviewWebsiteSurface(url, [], async () => ({ status: 503, body: 'Unavailable' }))).success).toBe(false);
  });
  it('parses actual HTML elements, form ownership and entities without executing scripts', async () => {
    const requested: string[] = [];
    const result = await reviewWebsiteSurface(url, [], async address => {
      requested.push(address);
      if (address === url) { return { status: 200, contentType: 'text/html', body: `
        <base href=/app/>
        <!-- <a href="/comment">Fake link</a><form><input name="fake"></form> -->
        <script>const markup = '<form><input name="fake"></form>'; fetch('/api/inline');</script>
        <script src=client.js></script><script src=https://foreign.test/code.js></script>
        <a href="page?category=one&amp;sort=asc">More</a><a href=/logout>Leave</a>
        <form id=search action=search method=GET><input name=q><input disabled name=disabled></form>
        <input form=search name="lang" value="en">
        <form action=/login method=post><input name=user><input type=password name=password>
          <input type=hidden name=csrf_token value="do-not-store"></form>` }; }
      if (address.endsWith('client.js')) return { status: 200, contentType: 'text/javascript', body: "fetch('/api/items'); axios.post('/api/write');" };
      return { status: 200, contentType: 'text/html', body: '<a href="/">Home</a><form action=/nested><textarea name=message></textarea></form>' };
    });
    const surface = result.metadata?.websiteSurface;
    expect(surface).toMatchObject({ complete: true, postForms: 1,
      scripts: [url + 'app/client.js'], apiHints: expect.arrayContaining([url + 'api/inline', url + 'api/items', url + 'api/write']),
      inputTargets: expect.arrayContaining([{ url: url + 'app/search?q=', param: 'q' }, { url: url + 'app/search?lang=', param: 'lang' }, { url: url + 'nested?message=', param: 'message' }]),
      forms: expect.arrayContaining([expect.objectContaining({ action: url + 'login', method: 'post', hasCsrf: true })]) });
    expect(JSON.stringify(surface)).not.toContain('do-not-store');
    expect(JSON.stringify(surface)).not.toContain('"param":"fake"');
    expect(JSON.stringify(surface)).not.toContain('"param":"disabled"');
    expect(requested).toEqual([url, url + 'app/client.js', url + 'app/page?category=one&sort=asc']);
  });

  it('keeps failed or bounded discovery incomplete instead of declaring absent input/auth surfaces', async () => {
    const read = vi.fn(async () => ({ status: 200, body: Array.from({ length: 50 }, (_, i) => `<a href="/page${i}">Next</a>`).join('') }));
    const result = await reviewWebsiteSurface(url, [], read);
    expect(read).toHaveBeenCalledTimes(32);
    expect(result.metadata?.websiteSurface).toMatchObject({ complete: false });
    const snapshot = evaluateCoverage(url, [record('web_surface_review', result)]);
    expect(snapshot.entries.authentication_testing.status).toBe('incomplete');
    expect(snapshot.entries.input_surface.status).toBe('incomplete');
    const failed = await reviewWebsiteSurface(url, [], async address => {
      if (address === url) return { status: 200, body: '<a href=/missing>More</a>' };
      throw new Error('Request failed');
    });
    expect(failed.metadata?.websiteSurface).toMatchObject({ complete: false, reviewedUrls: [url] });
  });

  it('uses the final response URL as the relative-link base and rejects a foreign base element', async () => {
    const requested: string[] = [];
    await reviewWebsiteSurface(url, [], async address => {
      requested.push(address);
      return address === url ? { status: 200, url: url + 'docs/', body: '<a href=page>Page</a>' }
        : { status: 200, body: '<base href=https://foreign.test/><a href=escape>External</a><form action=submit><input name=q></form>' };
    });
    expect(requested).toEqual([url, url + 'docs/page']);
  });

  it('propagates cancellation rather than converting it into an unavailable page', async () => {
    const controller = new AbortController();
    await expect(reviewWebsiteSurface(url, [], async () => { controller.abort(); throw new Error('cancelled'); }, controller.signal)).rejects.toThrow();
  });

  it('does not repeatedly scan malformed, unterminated form markup', async () => {
    const result = await reviewWebsiteSurface(url, [], async () => ({ status: 200, body: '<form><input name="q"'.repeat(20000) }));
    expect(result.metadata?.websiteSurface).toMatchObject({ inputTargets: [{ url: url + '?q=', param: 'q' }], postForms: 0, complete: false });
    expect(evaluateCoverage(url, [record('web_surface_review', result)]).entries.input_surface.status).toBe('incomplete');
  });
});

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
const plan = (records: EvidenceRecord[], tools = ['web_surface_review', 'xss_scan', 'sqli_scan']) => {
  const snapshot = evaluateCoverage(url, records); snapshot.retryable = snapshot.retryable.filter(item => ['authentication_testing', 'input_surface'].includes(item));
  return planCoverageRecovery({ snapshot, records, availableTools: new Set(tools), attempts: {}, includeValidation: true,
    network: { edgeSurface: false, blockState: 'clear', consecutiveTimeouts: 0, blockingResponses: 0 },
    budget: { remaining: { tool_call_budget: 100, total_request_budget: 1000 } as TargetBudgets } });
};

describe('evidence-driven website coverage', () => {
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
  it('does not repeatedly scan malformed, unterminated form markup', async () => {
    const result = await reviewWebsiteSurface(url, [], async () => ({ status: 200, body: '<form><input name="q"'.repeat(20000) }));
    expect(result.metadata?.websiteSurface).toMatchObject({ inputTargets: [], postForms: 0 });
  });
});

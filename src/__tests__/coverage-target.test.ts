import { describe, expect, it } from 'vitest';
import { evaluateCoverage, planCoverageRecovery } from '../orchestrator/coverage.js';
import type { EvidenceRecord, TargetBudgets } from '../orchestrator/tool-orchestrator.js';

function plan(target: string, tool: string) {
  return planCoverageRecovery({ snapshot: evaluateCoverage(target, []), records: [], availableTools: new Set([tool]),
    attempts: {}, network: { edgeSurface: false, blockState: 'clear', consecutiveTimeouts: 0, blockingResponses: 0 },
    budget: { remaining: { tool_call_budget: 10, total_request_budget: 10 } as TargetBudgets }, includeValidation: true });
}

describe('coverage recovery target handling', () => {
  it.each(['http_request', 'header_analysis', 'technology_detect', 'feroxbuster_tool', 'api_endpoint_discovery', 'http_methods_test'])(
    'preserves scheme, custom port, path and query for %s', tool => {
      const url = 'http://fixture.test:8081/base?mode=read';
      expect(plan(url, tool)?.parameters.url).toBe(url);
    });
  it('appends the fuzz marker to the path while preserving the query', () => {
    expect(plan('http://fixture.test:8081/base/?mode=read', 'ffuf_fuzz')?.parameters.url)
      .toBe('http://fixture.test:8081/base/FUZZ?mode=read');
  });
  it('includes the explicit website port when planning service detection', () => {
    const target = 'http://fixture.test:8081/base';
    const snapshot = evaluateCoverage(target, []); snapshot.retryable = ['service_detection'];
    expect(planCoverageRecovery({ snapshot, records: [], availableTools: new Set(['nmap_scan']), attempts: {},
      network: { edgeSurface: false, blockState: 'clear', consecutiveTimeouts: 0, blockingResponses: 0 },
      budget: { remaining: { tool_call_budget: 10, total_request_budget: 10 } as TargetBudgets }, includeValidation: false })?.parameters)
      .toMatchObject({ target: 'fixture.test', ports: '80,443,8081' });
  });
  it.each([
    ['http://fixture.test:8081/base', 'dns_lookup', { domain: 'fixture.test', type: 'A' }],
    ['https://[::1]:8443/base', 'ssl_scan', { host: '::1', port: 8443 }],
    ['http://[::1]:8081/base', 'nmap_scan', { target: '::1' }],
    ['2001:db8::10', 'http_request', { url: 'https://[2001:db8::10]/' }],
    ['fixture.test', 'http_request', { url: 'https://fixture.test/' }],
    ['https://fixture.test:8443/base', 'nuclei_scan', { target: 'https://fixture.test:8443/base' }],
  ])('uses the proper address type for %s with %s', (target, tool, parameters) => {
    expect(plan(target, tool)?.parameters).toMatchObject(parameters);
  });
  it('matches normalized same-host evidence for an original URL without attributing another host', () => {
    const record = { id: 'observed', target: 'http://fixture.test:8081/other', toolName: 'http_request',
      toolCategory: 'http_fetch', executionStatus: 'executed', resultType: 'negative' } as EvidenceRecord;
    const target = 'http://fixture.test:8081/base?mode=read';
    expect(evaluateCoverage(target, [record]).entries.http_probe).toMatchObject({ status: 'completed_negative', evidenceRecordIds: ['observed'] });
    expect(evaluateCoverage(target, [{ ...record, target: 'https://fixture.test.evil.test/' }]).entries.http_probe.status).toBe('not_started');
  });
});

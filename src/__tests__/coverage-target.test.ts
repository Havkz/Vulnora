import { describe, expect, it } from 'vitest';
import { evaluateCoverage, planCoverageRecovery, missionCompletionStatus } from '../orchestrator/coverage.js';
import type { EvidenceRecord, TargetBudgets } from '../orchestrator/tool-orchestrator.js';

function plan(target: string, tool: string) {
  return planCoverageRecovery({ snapshot: evaluateCoverage(target, []), records: [], availableTools: new Set([tool]),
    attempts: {}, network: { edgeSurface: false, blockState: 'clear', consecutiveTimeouts: 0, blockingResponses: 0 },
    budget: { remaining: { tool_call_budget: 10, total_request_budget: 100 } as TargetBudgets }, includeValidation: true });
}

describe('coverage recovery target handling', () => {
  it.each(['empty', 'inconclusive'] as const)('keeps %s validation results open without misclassifying HTTP observations', resultType => {
    const target = 'https://fixture.test/';
    const record = { id: 'unclear', target, toolName: 'nuclei_scan', toolCategory: 'active_validation',
      executionStatus: 'executed', resultType, rawOutput: resultType === 'empty' ? '' : 'Scan ended without a verdict.' } as EvidenceRecord;
    const snapshot = evaluateCoverage(target, [record]);
    expect(snapshot.entries.vulnerability_scanning.status).toBe('incomplete');
    expect(snapshot.retryable).toContain('vulnerability_scanning');
    expect(missionCompletionStatus([snapshot])).toBe('PARTIALLY_COMPLETED');
    const http = { ...record, toolName: 'http_request', toolCategory: 'http_fetch' as const };
    expect(evaluateCoverage(target, [http]).entries.http_probe.status).toBe(resultType === 'empty' ? 'incomplete' : 'completed');
  });
  it('does not call a running assessment complete', () => {
    const snapshot = evaluateCoverage('https://fixture.test/', []);
    for (const entry of Object.values(snapshot.entries)) entry.status = 'completed';
    snapshot.entries.vulnerability_scanning.status = 'in_progress';
    expect(missionCompletionStatus([snapshot])).toBe('PARTIALLY_COMPLETED');
  });
  it('does not declare input/authentication testing unnecessary when discovery failed or a login form exists', () => {
    const target = 'https://fixture.test';
    const records = ['dir_bruteforce', 'api_endpoint_discovery'].map(toolName => ({ target, toolName, toolCategory: 'content_discovery',
      executionStatus: 'blocked', errorType: 'budget_exceeded', resultType: 'error' } as EvidenceRecord));
    const blocked = evaluateCoverage(target, records);
    expect(blocked.entries.authentication_testing.status).toBe('not_started'); expect(blocked.entries.input_surface.status).toBe('not_started');
    const negative = records.map(record => ({ ...record, executionStatus: 'executed' as const, resultType: 'negative' as const }));
    const form = { target, toolName: 'http_request', toolCategory: 'http_fetch', executionStatus: 'executed', resultType: 'inconclusive', result: { metadata: { responseBody: '<form><input name="user"></form>' } } } as unknown as EvidenceRecord;
    expect(evaluateCoverage(target, [...negative, form]).entries.authentication_testing.status).toBe('not_started');
    expect(evaluateCoverage(target, negative).entries.authentication_testing.status).toBe('not_applicable');
  });
  it('does not skip targeted website validation merely because Nuclei returned no findings', () => {
    const target = 'https://fixture.test';
    const record = { target, toolName: 'nuclei_scan', toolCategory: 'active_validation', executionStatus: 'executed', resultType: 'negative' } as EvidenceRecord;
    const snapshot = evaluateCoverage(target, [record]);
    expect(snapshot.entries.targeted_validation.status).toBe('not_started');
    expect(planCoverageRecovery({ snapshot, records: [record], availableTools: new Set(['http_methods_test']), attempts: {}, network: { edgeSurface: false, blockState: 'clear', consecutiveTimeouts: 0, blockingResponses: 0 }, budget: { remaining: { tool_call_budget: 10, total_request_budget: 100 } as TargetBudgets }, includeValidation: true })?.toolName).toBe('http_methods_test');
  });
  it('excludes origin port scanning from CDN website coverage while preserving HTTP/API work', () => {
    const target = 'https://fixture.test';
    const record = { target, status: 'success', toolName: 'http_request', toolCategory: 'http_fetch', executionStatus: 'executed', resultType: 'inconclusive', responseHeaders: { server: 'cloudflare' }, rawOutput: 'HTTP/2 200' } as unknown as EvidenceRecord;
    const snapshot = evaluateCoverage(target, [record]);
    expect(snapshot.entries.port_discovery.status).toBe('not_applicable'); expect(snapshot.entries.service_detection.status).toBe('not_applicable');
    expect(snapshot.retryable).toContain('api_discovery');
  });
  it('covers bounded API discovery before admitting the larger content wordlist', () => {
    const target = 'http://fixture.test:8081/base';
    const snapshot = evaluateCoverage(target, []); snapshot.retryable = ['api_discovery', 'content_discovery'];
    expect(planCoverageRecovery({ snapshot, records: [], availableTools: new Set(['api_endpoint_discovery', 'ffuf_fuzz']), attempts: {},
      network: { edgeSurface: false, blockState: 'clear', consecutiveTimeouts: 0, blockingResponses: 0 },
      budget: { remaining: { tool_call_budget: 10, total_request_budget: 100 } as TargetBudgets }, includeValidation: false })?.toolName).toBe('api_endpoint_discovery');
  });
  it('keeps truncated wordlist coverage incomplete and does not reschedule an exhausted discovery budget', () => {
    const record: EvidenceRecord = { id: 'partial', target: 'https://fixture.test/', toolName: 'ffuf_fuzz', toolCategory: 'content_discovery',
      normalizedSignature: 'partial', equivalentSignature: 'partial', timestamp: 1, requestParameters: {}, rawOutput: 'Limited discovery',
      status: 'success', confidence: 1, sourceAgent: 'Fixture', findingIds: [], budgetCostEstimated: 3, budgetCostSource: 'orchestrator_estimated',
      networkContext: { edgeSurface: false, blockState: 'clear', consecutiveTimeouts: 0, blockingResponses: 0 },
      executionStatus: 'executed', resultType: 'negative', result: { success: true, metadata: { wordlistTruncated: true } } };
    const snapshot = evaluateCoverage('https://fixture.test/', [record]);
    expect(snapshot.entries.content_discovery.status).toBe('incomplete'); snapshot.retryable = ['content_discovery', 'api_discovery'];
    expect(planCoverageRecovery({ snapshot, records: [record], availableTools: new Set(['api_endpoint_discovery', 'ffuf_fuzz']), attempts: {},
      network: { edgeSurface: false, blockState: 'clear', consecutiveTimeouts: 0, blockingResponses: 0 },
      budget: { remaining: { tool_call_budget: 10, total_request_budget: 100, content_discovery_budget: 0 } as TargetBudgets }, includeValidation: false })).toBeUndefined();
  });
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

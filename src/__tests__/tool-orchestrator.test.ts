import { describe, expect, it } from 'vitest';
import { mkdtemp } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { ToolOrchestrator, normalizeToolCall } from '../orchestrator/tool-orchestrator.js';
import { JsonlEvidenceStore } from '../orchestrator/evidence-store.js';
import type { CustomTool, ToolContext, ToolResult } from '../types/index.js';

function tool(name: string): CustomTool {
  return {
    name,
    description: `test ${name}`,
    category: 'test',
    handler: async () => ({ success: true, output: 'unused' }),
  };
}

function context(parameters: Record<string, unknown>, operator = 'Agent-A', extra: Partial<ToolContext> = {}): ToolContext {
  return { parameters, operator, purpose: 'assessment', ...extra };
}

function httpResult(status = 200, body = '<title>Home</title>'): ToolResult {
  return {
    success: true,
    output: `HTTP/2 ${status}`,
    metadata: {
      responseStatus: status,
      responseHeaders: {
        'content-type': 'text/html',
        'content-security-policy': "default-src 'self'",
        'set-cookie': 'session=x; Secure; HttpOnly',
        'x-frame-options': 'DENY',
        server: 'example-edge',
      },
      responseBody: body,
    },
  };
}

describe('central tool orchestrator', () => {
  it('exposes running work for planning without leaking credentials or retaining completed reservations', async () => {
    const orchestrator = new ToolOrchestrator();
    let release!: () => void; let started!: () => void;
    const admitted = new Promise<void>(resolve => { started = resolve; });
    const pending = orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/work', headers: { Authorization: 'private-planning-fixture' } }), async () => {
      started(); await new Promise<void>(resolve => { release = resolve; }); return httpResult();
    });
    await admitted;
    expect(orchestrator.getActiveCalls()).toEqual([expect.objectContaining({ host: 'target.test', toolName: 'http_request' })]);
    expect(JSON.stringify(orchestrator.getActiveCalls())).not.toContain('private-planning-fixture');
    release(); await pending;
    expect(orchestrator.getActiveCalls()).toEqual([]);
  });
  it('shares one DNS execution between two agents', async () => {
    const orchestrator = new ToolOrchestrator();
    let executions = 0;
    const run = async () => {
      executions++;
      await new Promise(resolve => setTimeout(resolve, 10));
      return { success: true, output: 'DNS A lookup: 192.0.2.10' };
    };
    const parameters = { domain: 'target.test', type: 'A' };
    const [first, second] = await Promise.all([
      orchestrator.execute(tool('dns_lookup'), context(parameters, 'Agent-A'), run),
      orchestrator.execute(tool('dns_lookup'), context(parameters, 'Agent-B'), run),
    ]);

    expect(first.success).toBe(true);
    expect(second.metadata?.cacheHit).toBe(true);
    expect(executions).toBe(1);
    expect(new Set(orchestrator.getEvidence().map(record => record.sourceAgent))).toEqual(new Set(['Agent-A', 'Agent-B']));
  });

  it('treats internal HTTP and curl GET requests as equivalent', async () => {
    const orchestrator = new ToolOrchestrator();
    let executions = 0;
    const first = await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/a', method: 'GET' }), async () => {
      executions++;
      return httpResult();
    });
    const second = await orchestrator.execute(tool('curl_request'), context({ url: 'https://target.test/a', method: 'GET' }), async () => {
      executions++;
      return httpResult();
    });

    expect(first.success).toBe(true);
    expect(second.metadata?.orchestrationStatus).toBe('redundant_skipped');
    expect(executions).toBe(1);
  });

  it('runs header, cookie and CSP analysis from one stored response', async () => {
    const orchestrator = new ToolOrchestrator();
    const url = 'https://target.test/';
    await orchestrator.execute(tool('http_request'), context({ url, method: 'GET' }), async () => httpResult());
    let analysisNetworkCalls = 0;
    for (const name of ['header_analysis', 'cookie_analysis', 'csp_analysis']) {
      const result = await orchestrator.execute(tool(name), context({ url }), async () => {
        analysisNetworkCalls++;
        return { success: true, output: 'should not run' };
      });
      expect(result.metadata?.offlineAnalysis).toBe(true);
    }
    expect(analysisNetworkCalls).toBe(0);
    expect(orchestrator.getMetrics().actualNetworkRequests).toBe(1);
  });

  it('does not collapse functionally different analyzers or discovery families', async () => {
    const orchestrator = new ToolOrchestrator();
    let executions = 0;
    for (const name of ['header_analysis', 'cookie_analysis']) {
      await orchestrator.execute(tool(name), context({ url: 'https://target.test/no-baseline' }), async () => {
        executions++;
        return { success: true, output: `${name} result` };
      });
    }
    await orchestrator.execute(tool('api_endpoint_discovery'), context({ url: 'https://target.test/' }), async () => {
      executions++;
      return { success: true, output: 'api result' };
    });
    await orchestrator.execute(tool('dir_bruteforce'), context({ url: 'https://target.test/' }), async () => {
      executions++;
      return { success: true, output: 'directory result' };
    });
    expect(executions).toBe(4);
  });

  it('prevents an overlapping smaller scan after an authorized full scan', async () => {
    const orchestrator = new ToolOrchestrator();
    const target = 'target.test';
    await orchestrator.execute(tool('port_scan'), context({ target, ports: '80,443' }), async () => ({ success: true, output: '443/tcp open https' }));
    await orchestrator.execute(tool('port_scan'), context({ target, ports: '1-65535' }, 'Agent-A', { authorizationReceipt: 'receipt-1' }), async () => ({ success: true, output: '443/tcp open https' }));
    let reran = false;
    const result = await orchestrator.execute(tool('port_scan'), context({ target, ports: '443' }), async () => {
      reran = true;
      return { success: true, output: '443/tcp open https' };
    });
    expect(reran).toBe(false);
    expect(result.metadata?.orchestrationStatus).toBe('redundant_skipped');
  });

  it('marks wildcard DNS candidates unverified instead of counting them as applications', async () => {
    const orchestrator = new ToolOrchestrator({ dnsResolver: async () => ['192.0.2.55'] });
    const result = await orchestrator.execute(tool('subdomain_enum'), context({ domain: 'target.test' }), async () => ({
      success: true,
      output: 'Found admin.target.test -> 192.0.2.55',
      findings: [{ title: 'Subdomains Discovered', severity: 'info', details: 'admin.target.test' }],
    }));
    expect(result.metadata?.wildcardDns).toBe(true);
    expect(result.metadata?.candidatesVerified).toBe(false);
    expect(result.findings).toEqual([]);
  });

  it('does not activate edge blocking for ordinary 403 responses on different routes', async () => {
    const orchestrator = new ToolOrchestrator();
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/' }), async () => httpResult(200));
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/admin' }), async () => httpResult(403, 'admin forbidden'));
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/private' }), async () => httpResult(403, 'private forbidden'));
    expect(orchestrator.getNetworkContext('target.test').blockState).not.toBe('probable_edge_block');
  });

  it('activates edge blocking after a success and a 429 response series', async () => {
    const orchestrator = new ToolOrchestrator();
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/' }), async () => httpResult(200));
    for (const suffix of ['one', 'two']) {
      await orchestrator.execute(tool('http_request'), context({ url: `https://target.test/429-${suffix}` }), async () => httpResult(429, 'rate limited'));
    }
    expect(orchestrator.getNetworkContext('target.test').blockState).toBe('probable_edge_block');
  });

  it('activates edge blocking for a challenge response', async () => {
    const orchestrator = new ToolOrchestrator();
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/' }), async () => httpResult(200));
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/challenge' }), async () => httpResult(403, 'Checking your browser challenge-platform'));
    expect(orchestrator.getNetworkContext('target.test').blockState).toBe('probable_edge_block');
  });

  it('activates edge blocking after a success and a timeout series', async () => {
    const orchestrator = new ToolOrchestrator();
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/' }), async () => httpResult(200));
    for (const suffix of ['one', 'two']) {
      await orchestrator.execute(tool('http_request'), context({ url: `https://target.test/${suffix}` }), async () => ({ success: false, error: 'operation timeout' }));
    }
    expect(orchestrator.getNetworkContext('target.test').blockState).toBe('probable_edge_block');
  });

  it('does not bypass an edge block by switching equivalent tools', async () => {
    const orchestrator = new ToolOrchestrator();
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/' }), async () => httpResult());
    for (const path of ['/a', '/b']) {
      await orchestrator.execute(tool('http_request'), context({ url: `https://target.test${path}` }), async () => httpResult(429, 'rate limited'));
    }
    let curlRan = false;
    const blocked = await orchestrator.execute(tool('curl_request'), context({ url: 'https://target.test/new' }), async () => {
      curlRan = true;
      return httpResult();
    });
    expect(curlRan).toBe(false);
    expect(blocked.metadata?.orchestrationStatus).toBe('waf_blocked');
  });

  it('detects a missing FFUF wordlist during preflight', async () => {
    const orchestrator = new ToolOrchestrator();
    let ran = false;
    const result = await orchestrator.execute(tool('ffuf_fuzz'), context({ url: 'https://target.test/FUZZ', wordlist: '/definitely/missing/ffuf.txt' }), async () => {
      ran = true;
      return { success: true, output: 'unexpected' };
    });
    expect(ran).toBe(false);
    expect(result.metadata?.orchestrationStatus).toBe('configuration_error');
    expect(orchestrator.getEvidence().at(-1)?.errorType).toBe('configuration_error');
  });

  it('never stores a failed tool as a valid negative result', async () => {
    const orchestrator = new ToolOrchestrator();
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/' }), async () => ({ success: false, error: 'operation timeout' }));
    const record = orchestrator.getEvidence().at(-1);
    expect(record?.status).toBe('failed');
    expect(record?.errorType).toBe('timeout');
    expect(record?.errorType).not.toBe('valid_negative_result');
  });

  it('allows one retry after failure and blocks an unbounded third equivalent attempt', async () => {
    const orchestrator = new ToolOrchestrator();
    let executions = 0;
    const invoke = () => orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/fails' }), async () => {
      executions++;
      return { success: false, error: 'connection timeout' };
    });
    await invoke();
    await invoke();
    const third = await invoke();
    expect(executions).toBe(2);
    expect(third.metadata?.orchestrationStatus).toBe('redundant_skipped');
    expect(orchestrator.getEvidence().at(-1)?.status).toBe('skipped');
  });

  it('resets the consecutive failure chain after a successful equivalent verification', async () => {
    const orchestrator = new ToolOrchestrator();
    let executions = 0;
    const params = { url: 'https://target.test/retry' };
    const fail = () => orchestrator.execute(tool('http_request'), context(params), async () => { executions++; return { success: false, error: 'timeout' }; });
    await fail();
    await fail();
    await orchestrator.execute(tool('http_request'), context(params, 'Agent-A', { repeatReason: 'contradiction_verification' }), async () => { executions++; return httpResult(200); });
    await orchestrator.execute(tool('http_request'), context(params, 'Agent-A', { repeatReason: 'contradiction_verification' }), async () => { executions++; return { success: false, error: 'timeout' }; });
    expect(executions).toBe(4);
  });

  it('does not let failures older than the cache TTL trip the retry limit', async () => {
    const orchestrator = new ToolOrchestrator({ cacheTtlMs: 1 });
    const params = { url: 'https://target.test/old' };
    let executions = 0;
    for (let i = 0; i < 2; i++) await orchestrator.execute(tool('http_request'), context(params), async () => { executions++; return { success: false, error: 'timeout' }; });
    await new Promise(resolve => setTimeout(resolve, 4));
    await orchestrator.execute(tool('http_request'), context(params), async () => { executions++; return httpResult(); });
    expect(executions).toBe(3);
  });

  it('does not count policy denials as technical retry failures', async () => {
    const orchestrator = new ToolOrchestrator();
    const probe = tool('http_request');
    const ctx = context({ url: 'https://target.test/policy' });
    orchestrator.recordBlocked(probe, ctx, { success: false, error: 'scope denied' }, 'scope_denied');
    orchestrator.recordBlocked(probe, ctx, { success: false, error: 'not authorized' }, 'not_authorized');
    let ran = false;
    await orchestrator.execute(probe, ctx, async () => { ran = true; return httpResult(); });
    expect(ran).toBe(true);
  });

  it('retains and explains contradictory port observations', async () => {
    const orchestrator = new ToolOrchestrator();
    const params = { target: 'target.test', ports: '443' };
    await orchestrator.execute(tool('port_scan'), context(params), async () => ({ success: true, output: '443/tcp open https' }));
    await orchestrator.execute(tool('port_scan'), context(params, 'Agent-B', { repeatReason: 'contradiction_verification' }), async () => ({ success: true, output: '443/tcp filtered' }));
    expect(orchestrator.getConflicts()).toHaveLength(1);
    expect(orchestrator.getConflicts()[0].recordIds).toHaveLength(2);
    expect(orchestrator.getConflicts()[0].recommendedVerification).toContain('contradiction_verification');
  });

  it('does not open the exploit phase without a validated finding', () => {
    const orchestrator = new ToolOrchestrator();
    expect(orchestrator.canStartExploit({
      target: 'target.test', validatedFindings: 0, activeTestingAllowed: true,
      targetReachable: true, requiredToolAvailable: true,
    })).toMatchObject({ allowed: false, phaseStatus: 'no_validated_targets' });
  });

  it('blocks scan tools in the reporting phase', async () => {
    const orchestrator = new ToolOrchestrator();
    let ran = false;
    const result = await orchestrator.execute(tool('dns_lookup'), context({ domain: 'target.test', type: 'A' }, 'Analyst', { purpose: 'reporting' }), async () => {
      ran = true;
      return { success: true, output: 'unexpected' };
    });
    expect(ran).toBe(false);
    expect(result.metadata?.orchestrationStatus).toBe('redundant_skipped');
    expect(orchestrator.getEvidence().at(-1)?.status).toBe('skipped');
  });

  it('enforces request budgets even for distinct LLM-generated calls', async () => {
    const orchestrator = new ToolOrchestrator({ budgets: { baseline_http_budget: 1, total_request_budget: 1 } });
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/a' }), async () => httpResult());
    let secondRan = false;
    const second = await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/b' }), async () => {
      secondRan = true;
      return httpResult();
    });
    expect(secondRan).toBe(false);
    expect(second.metadata?.orchestrationStatus).toBe('budget_exceeded');
  });

  it('reconciles a conservative batch reservation with a tool-reported request count', async () => {
    const orchestrator = new ToolOrchestrator();
    const result = await orchestrator.execute(tool('api_endpoint_discovery'), context({ url: 'https://target.test/' }), async () => ({ success: true, output: 'done', metadata: { actualRequests: 2 } }));
    expect(result.metadata?.budgetCostEstimated).toBe(42);
    expect(result.metadata?.budgetCostActual).toBe(2);
    expect(orchestrator.getBudget('target.test').used.total_request_budget).toBe(2);
    expect(orchestrator.getEvidence().at(-1)?.budgetCostSource).toBe('tool_reported');
  });

  it('uses separate HTTP and port-probe budget counters', async () => {
    const orchestrator = new ToolOrchestrator();
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/' }), async () => httpResult());
    await orchestrator.execute(tool('port_scan'), context({ target: 'target.test', ports: '80,443' }), async () => ({ success: true, output: '80/tcp open' }));
    const used = orchestrator.getBudget('target.test').used;
    expect(used.http_request_budget).toBe(1);
    expect(used.port_probe_budget).toBe(2);
  });

  it('caches executable preflight data, supports refresh, and accepts template directories', async () => {
    const orchestrator = new ToolOrchestrator({ preflightTtlMs: 1 });
    const templates = await mkdtemp(join(tmpdir(), 'vulnora-templates-'));
    await orchestrator.execute(tool('curl_request'), context({ url: 'https://target.test/a', templates }), async () => httpResult());
    const first = orchestrator.getPreflightStatus().curl;
    expect(first?.available).toBe(true);
    expect(first?.path).toBeTruthy();
    await new Promise(resolve => setTimeout(resolve, 3));
    await orchestrator.execute(tool('curl_request'), context({ url: 'https://target.test/b', templates }), async () => httpResult());
    expect(orchestrator.getPreflightStatus().curl.checkedAt).toBeGreaterThan(first!.checkedAt);
    orchestrator.refreshPreflight('curl');
    expect(orchestrator.getPreflightStatus().curl).toBeUndefined();
  });

  it('keeps the memory evidence store as the default backend', () => {
    expect(new ToolOrchestrator().getEvidenceStoreBackend()).toBe('memory');
  });

  it('supports an optional persistent JSONL evidence store', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-evidence-'));
    const path = join(directory, 'evidence.jsonl');
    const store = new JsonlEvidenceStore(path);
    const orchestrator = new ToolOrchestrator({ evidenceStore: store });
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/persist' }), async () => httpResult());
    await new Promise(resolve => setTimeout(resolve, 10));
    const reloaded = new JsonlEvidenceStore(path);
    await reloaded.load();
    expect(await reloaded.query({ toolName: 'http_request' })).toHaveLength(1);
  });

  it('aborts an abort-capable batch call when an edge block is detected', async () => {
    const orchestrator = new ToolOrchestrator();
    const batch = tool('dir_bruteforce');
    batch.supportsAbort = true;
    let aborted = false;
    const ctx = context({ url: 'https://target.test/' });
    const pending = orchestrator.execute(batch, ctx, async () => new Promise<ToolResult>(resolve => {
      ctx.abortSignal?.addEventListener('abort', () => { aborted = true; resolve({ success: false, error: 'batch aborted' }); }, { once: true });
    }));
    await new Promise(resolve => setTimeout(resolve, 5));
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/health' }), async () => httpResult());
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/rate-a' }), async () => httpResult(429, 'rate limited'));
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/rate-b' }), async () => httpResult(429, 'rate limited'));
    await pending;
    expect(aborted).toBe(true);
    const abortedRecord = orchestrator.getEvidence().find(record => /aborted/i.test(record.rawOutput));
    expect(abortedRecord).toMatchObject({ errorType: 'aborted', executionStatus: 'deferred', resultType: 'inconclusive' });
  });

  it('normalizes semantically equal requests to one equivalent signature', () => {
    const a = normalizeToolCall('http_request', context({ url: 'HTTPS://TARGET.TEST/a?b=2&a=1', method: 'get' }));
    const b = normalizeToolCall('curl_request', context({ url: 'https://target.test/a?a=1&b=2', method: 'GET' }));
    expect(a.normalizedSignature).not.toBe(b.normalizedSignature);
    expect(a.equivalentSignature).toBe(b.equivalentSignature);
  });

  it('logs cache, skip and budget-block reasons for the dashboard', async () => {
    const orchestrator = new ToolOrchestrator({ budgets: { baseline_http_budget: 1, total_request_budget: 1 } });
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/a' }), async () => httpResult());
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/a' }), async () => httpResult());
    await orchestrator.execute(tool('http_request'), context({ url: 'https://target.test/b' }), async () => httpResult());
    const labels = orchestrator.getEvents().map(event => `${event.action} ${event.reason}`);
    expect(labels).toContain('SKIPPED duplicate');
    expect(labels).toContain('BLOCKED budget exceeded');
  });
});

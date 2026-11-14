import { afterEach, describe, expect, it } from 'vitest';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { Arsenal, BUILTIN_TOOLS } from '../arsenal/index.js';
import { VulnoraCommand } from '../index.js';
import { EvidenceVault } from '../evidence/index.js';
import { gateLiveFinding } from '../evidence/gate.js';
import { createOperator } from '../operators/index.js';
import { AgentLoop } from '../agent/index.js';
import { LLMBackbone } from '../llm/index.js';
import { KillChainPhase, type Finding, type Task, type Target } from '../types/index.js';

const servers: Server[] = [];
afterEach(async () => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
  }
});

async function fixture(mode: 'reflect' | 'static' | 'once' = 'reflect') {
  let traces = 0;
  const markers: string[] = [];
  const server = createServer((req, res) => {
    res.writeHead(200);
    if (req.method !== 'TRACE') { res.end('Public fixture'); return; }
    traces++; markers.push(String(req.headers['x-vulnora-probe']));
    res.end(mode === 'static' || mode === 'once' && traces > 1
      ? 'TRACE / HTTP/1.1\r\nHost: documentation.example'
      : `TRACE ${req.url} HTTP/1.1\r\nX-Vulnora-Probe: ${req.headers['x-vulnora-probe']}`);
  });
  servers.push(server); await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${(server.address() as { port: number }).port}/`;
  const arsenal = new Arsenal(); arsenal.registerMany(BUILTIN_TOOLS.filter(tool => tool.name === 'http_methods_test'));
  const result = await arsenal.execute('http_methods_test', { parameters: { url },
    target: { id: 'target', name: 'Fixture', address: url, type: 'web_application', zone: 'external', status: 'discovered', discoveredAt: 1 } });
  const source = result.findings?.[0];
  const finding: Finding = { id: 'finding', title: source?.title || 'Claim', description: source?.details || 'Claim', severity: source?.severity || 'low',
    targetId: 'target', targetAddress: url, operatorId: 'operator', phase: KillChainPhase.WEAPONIZE, discoveredAt: 1,
    evidence: [{ type: 'output', timestamp: 1, content: result.output?.slice(0, 4000) || '',
      metadata: { recordIds: source?.evidenceRecordIds, findingId: source?.findingId } }] };
  return { arsenal, finding, result, markers, url };
}

describe('runtime-backed finding verification', () => {
  it('requires two distinct TRACE reflections and limits the verified claim to request reflection', async () => {
    const f = await fixture();
    expect(new Set(f.markers).size).toBe(2);
    expect(f.result.findings?.[0].evidenceStatus).toBe('validated');
    expect(f.finding.description).toContain('exploitable impact have not been established');
    expect(gateLiveFinding(f.finding, f.arsenal.getOrchestrator().getEvidence()).passed).toBe(true);
    expect(gateLiveFinding(f.finding).passed).toBe(false);
  });

  it.each(['static', 'once'] as const)('does not verify %s reflection evidence', async mode => {
    const f = await fixture(mode);
    expect(gateLiveFinding(f.finding, f.arsenal.getOrchestrator().getEvidence()).passed).toBe(false);
    if (mode === 'static') expect(f.result.findings).toBeUndefined();
    else expect(f.result.findings?.[0].evidenceStatus).toBe('observed');
  });

  it('rejects forged output, target, claim, status and record links', async () => {
    const f = await fixture(); const records = f.arsenal.getOrchestrator().getEvidence();
    for (const update of [{ targetId: 'other-target' }, { title: 'RCE confirmed' }, { severity: 'critical' }, { targetAddress: 'https://other.example' }, { cve: ['CVE-made-up'] }]) {
      expect(gateLiveFinding({ ...f.finding, ...update } as Finding, records).passed).toBe(false);
    }
    const altered = structuredClone(f.finding); altered.evidence[0].content = 'Forged output';
    expect(gateLiveFinding(altered, records).passed).toBe(false);
    altered.evidence = structuredClone(f.finding.evidence);
    assert(altered.evidence[0].metadata); altered.evidence[0].metadata.recordIds = ['missing'];
    expect(gateLiveFinding(altered, records).passed).toBe(false);
    records[0].executionStatus = 'failed'; expect(gateLiveFinding(f.finding, records).passed).toBe(false);
    expect(gateLiveFinding(f.finding, f.arsenal.getOrchestrator().getEvidence()).passed).toBe(true);
    assert(f.result.findings?.[0]); f.result.findings[0].details = 'Changed after return';
    expect(gateLiveFinding(f.finding, f.arsenal.getOrchestrator().getEvidence()).passed).toBe(true);
  });

  it('revalidates vault writes and restored records, and protects nested evidence snapshots', async () => {
    const f = await fixture(); const records = () => f.arsenal.getOrchestrator().getEvidence();
    const vault = new EvidenceVault(records); vault.addFinding(f.finding);
    expect(vault.getVerifiedFindings()).toHaveLength(1);
    vault.updateFinding('finding', { exploitedAt: 123 });
    expect(vault.getFinding('finding')?.exploitedAt).toBeUndefined();
    const snapshot = vault.getFinding('finding');
    assert(snapshot?.evidence[0].metadata);
    assert(Array.isArray(snapshot.evidence[0].metadata.recordIds)); snapshot.evidence[0].metadata.recordIds.push('forged');
    expect(vault.getFinding('finding')?.evidence[0].metadata?.recordIds).not.toContain('forged');
    const restored = new EvidenceVault(records);
    restored.restoreCheckpoint({ findings: vault.getAllFindings(), credentials: [] });
    expect(restored.getVerifiedFindings()).toHaveLength(1);
    const missing = new EvidenceVault(); missing.restoreCheckpoint({ findings: vault.getAllFindings(), credentials: [] });
    expect(missing.getVerifiedFindings()).toEqual([]);
    vault.updateFinding('finding', { description: 'A different unverified claim' });
    expect(vault.getVerifiedFindings()).toEqual([]);
  });

  it('preserves runtime evidence links through the real agent/operator path', async () => {
    const f = await fixture();
    const llm = new LLMBackbone({ provider: 'deterministic', model: 'none' });
    const operator = createOperator('Verifier', 'scanner', { cooldownMs: 0 }, llm);
    operator.attachArsenal(f.arsenal, new AgentLoop(llm, f.arsenal));
    const target: Target = { id: 'target', name: 'Fixture', address: f.url, type: 'web_application', zone: 'external', status: 'discovered', discoveredAt: 1 };
    const task: Task = { id: 'task', missionId: 'mission', name: 'HTTP reflection', description: `Inspect ${f.url}`, phase: KillChainPhase.WEAPONIZE,
      operatorType: 'scanner', status: 'pending', priority: 1, dependencies: [], createdAt: 1,
      executionPlan: { toolName: 'http_methods_test', parameters: { url: f.url } } };
    await operator.assignTask(task, target);
    const findings = operator.getFindings();
    expect(findings).toHaveLength(1); expect(findings[0].verifyGate?.passed).toBe(true);
    expect(findings[0].evidence[0].metadata?.recordIds).toEqual(expect.arrayContaining([expect.stringMatching(/^evidence-/)]));
    findings[0].title = 'Changed after reading'; expect(operator.getFindings()[0].title).toBe('HTTP TRACE Reflects Request');
  });
  it('restores runtime-verified engine evidence and downgrades unsupported legacy target claims', async () => {
    const f = await fixture();
    const make = () => new VulnoraCommand({ name: 'Verification fixture', llm: { provider: 'deterministic', model: 'none' } });
    const original = make(); const restored = make(); const legacy = make();
    try {
      original.targetEnv.restoreCheckpoint([{ id: 'target', name: 'Fixture', address: f.url, type: 'web_application', zone: 'external', status: 'discovered', discoveredAt: 1,
        vulnerabilities: [{ id: 'finding', name: f.finding.title, description: f.finding.description, severity: 'low', evidenceStatus: 'validated' }] }]);
      original.arsenal.getOrchestrator().restoreCheckpoint(f.arsenal.getOrchestrator().exportCheckpoint());
      original.vault.addFinding(f.finding);
      const saved = original.exportCheckpoint(); restored.restoreCheckpoint(saved);
      expect(restored.vault.getVerifiedFindings()).toHaveLength(1);
      expect(restored.targetEnv.getAllTargets()[0].vulnerabilities?.[0].evidenceStatus).toBe('validated');
      saved.orchestrator.records = []; legacy.restoreCheckpoint(saved);
      expect(legacy.vault.getVerifiedFindings()).toEqual([]);
      expect(legacy.targetEnv.getAllTargets()[0].vulnerabilities?.[0].evidenceStatus).toBe('observed');
    } finally {
      for (const command of [original, restored, legacy]) { command.stop(); command.opsec.cleanup(); }
    }
  });

});

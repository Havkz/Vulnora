/** Tool provenance and vulnerability verification are separate claims. */
import type { Finding } from '../types/index.js';
import type { EvidenceRecord } from '../orchestrator/tool-orchestrator.js';

const TOOL_EVIDENCE = new Set(['output', 'command', 'response', 'request', 'log', 'file']);
export type LiveProvenance = 'none' | 'context' | 'tool';
export interface LiveGateResult {
  passed: boolean;
  provenance: LiveProvenance;
  evidenceStatus?: 'validated' | 'exploitable';
  reasons: string[];
  checkedAt: number;
}

function sameOrigin(target: string, expected?: string): boolean {
  try { return !!expected && new URL(target).origin === new URL(expected).origin; }
  catch { return false; }
}

/** Resolve runtime records, not model-supplied status or output labels. */
export function gateLiveFinding(f: Finding, records: readonly EvidenceRecord[] = []): LiveGateResult {
  const evidence = Array.isArray(f.evidence) ? f.evidence : [];
  const toolEvidence = evidence.filter(e => e && TOOL_EVIDENCE.has(e.type) && String(e.content || '').trim());
  const provenance: LiveProvenance = toolEvidence.length ? 'tool' : evidence.length ? 'context' : 'none';
  let evidenceStatus: LiveGateResult['evidenceStatus'];
  const supported = toolEvidence.some(e => records.some(record => {
    const ids = e.metadata?.recordIds;
    if (!Array.isArray(ids) || !ids.includes(record.id) || record.status !== 'success'
      || record.executionStatus !== 'executed' || !record.result.success || record.targetId !== f.targetId || !sameOrigin(record.target, f.targetAddress)
      || e.content !== record.rawOutput.slice(0, 4000)) return false;
    const source = Array.isArray(record.result.findings) && record.result.findings.find(source => source && source.findingId === e.metadata?.findingId
      && ['validated', 'exploitable'].includes(source.evidenceStatus || '')
      && source.title === f.title && source.details === f.description && source.severity === f.severity
      && (['cvss', 'cve', 'cwe'] as const).every(key => JSON.stringify(source[key]) === JSON.stringify(f[key])));
    if (!source) return false;
    evidenceStatus = source.evidenceStatus === 'exploitable' ? 'exploitable' : 'validated';
    return true;
  }));
  const reasons = supported ? [] : [toolEvidence.length
    ? 'Tool output is an observation; no matching successful runtime record validates this claim on the target.'
    : 'No tool-output evidence; model prose cannot verify a finding.'];
  return { passed: supported, provenance, evidenceStatus, reasons, checkedAt: Date.now() };
}

export function applyFindingVerification(finding: Finding, records: readonly EvidenceRecord[] = []): void {
  finding.verifyGate = gateLiveFinding(finding, records);
  if (finding.verifyGate.passed) finding.verifiedAt ??= Date.now();
  else delete finding.verifiedAt;
  if (finding.verifyGate.evidenceStatus === 'exploitable') finding.exploitedAt ??= Date.now();
  else delete finding.exploitedAt;
}

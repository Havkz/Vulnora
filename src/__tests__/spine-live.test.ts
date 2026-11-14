import { describe, it, expect } from 'vitest';
import { createOperator } from '../operators/index.js';
import type { Finding } from '../types/index.js';

// Output labels alone must never establish a verified vulnerability.

function baseFinding(over: Partial<Finding>): Finding {
  return {
    id: '',
    title: 'x',
    description: 'x',
    severity: 'high',
    targetId: 't',
    operatorId: 'o',
    phase: 'exploitation',
    evidence: [],
    discoveredAt: Date.now(),
    ...over,
  } as Finding;
}

describe('honesty spine is load-bearing at finding creation (operator.recordFinding)', () => {
  it('a model-asserted finding (no tool evidence) is recorded UNVERIFIED with gate reasons', () => {
    const op = createOperator('test-recon', 'recon');
    let blocked: { reasons: string[] } | undefined;
    op.on('finding:gate-blocked', (e) => { blocked = e; });

    const f = baseFinding({ title: 'model says critical', severity: 'critical', evidence: [] });
    op.recordFinding(f);

    expect(f.verifyGate?.passed).toBe(false);
    expect(f.verifiedAt).toBeUndefined();
    expect(f.verifyGate?.provenance).toBe('none');
    expect(blocked, 'a gate-blocked event must fire for an unbacked finding').toBeDefined();
    expect(blocked!.reasons.join(' ')).toMatch(/provenance|evidence/i);
  });

  it('tool output establishes provenance but does not verify a vulnerability', () => {
    const op = createOperator('test-recon2', 'recon');
    const f = baseFinding({
      title: 'nmap found open port',
      severity: 'high',
      evidence: [{ type: 'output', content: 'PORT 22/tcp open ssh\n...real nmap output...', timestamp: Date.now() }],
    });
    op.recordFinding(f);

    expect(f.verifyGate?.passed).toBe(false);
    expect(f.verifyGate?.provenance).toBe('tool');
    expect(f.verifiedAt).toBeUndefined();
  });

  it('getVerified-style filter only surfaces gate-passed findings', () => {
    const op = createOperator('test-recon3', 'recon');
    op.recordFinding(baseFinding({ title: 'prose claim', evidence: [] }));
    op.recordFinding(baseFinding({ title: 'tool claim', evidence: [{ type: 'output', content: 'x'.repeat(20), timestamp: Date.now() }] }));
    const verified = op.getFindings().filter((f) => f.verifyGate?.passed);
    expect(verified).toEqual([]);
  });
});

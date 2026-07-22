import { describe, expect, it } from 'vitest';
import { evaluateExploitExecution } from '../operators/index.js';
import { dependencyAllowsTask } from '../index.js';
import { shouldPrintOrchestrationEvent } from '../live-log-policy.js';
import type { AgentResult, AgentStep } from '../agent/index.js';
import type { Task } from '../types/index.js';

function result(steps: AgentStep[], summary = ''): AgentResult {
  return { success: true, summary, steps, findings: [], iterations: 1, tokensUsed: 1, durationMs: 1, hitLimit: false };
}

function exploitStep(overrides: Partial<AgentStep> = {}): AgentStep {
  return {
    iteration: 1,
    type: 'tool_call',
    timestamp: Date.now(),
    sourceToolCallId: 'call-1',
    attemptId: 'attempt-1',
    evidenceRecordId: 'evidence-1',
    toolResult: { success: true, output: 'observation', metadata: { orchestrationStatus: 'executed', evidenceRecordId: 'evidence-1' } },
    ...overrides,
  };
}

function skipped(reason: NonNullable<Task['result']>['skipReason']): Task {
  return { id: 'dep', missionId: 'm', name: 'dep', description: '', phase: 'reconnaissance' as never, operatorType: 'scanner', status: 'skipped', priority: 1, dependencies: [], createdAt: 1, result: { success: false, skipReason: reason } };
}

describe('structured orchestration status', () => {
  it('ignores Status: validated summary text without structured evidence', () => {
    expect(evaluateExploitExecution(result([], 'RESULT\nStatus: validated')).success).toBe(false);
  });

  it('requires a validated finding to link to the current tool call and evidence record', () => {
    const unlinked = exploitStep({ toolResult: { success: true, metadata: { orchestrationStatus: 'executed' }, findings: [{ title: 'RLS bypass', severity: 'high', details: 'role changed', provenance: 'tool', evidenceStatus: 'validated', sourceToolCallId: 'other', evidenceRecordIds: ['other'] }] } });
    expect(evaluateExploitExecution(result([unlinked])).success).toBe(false);
    const linked = exploitStep({ toolResult: { success: true, metadata: { orchestrationStatus: 'executed' }, findings: [{ title: 'RLS bypass', severity: 'high', details: 'role changed', provenance: 'tool', evidenceStatus: 'validated', sourceToolCallId: 'call-1', evidenceRecordIds: ['evidence-1'] }] } });
    expect(evaluateExploitExecution(result([linked]))).toMatchObject({ success: true, outcomeStatus: 'validated' });
  });

  it('classifies a negative exploit execution as executed and not exploitable', () => {
    const step = exploitStep({ toolResult: { success: true, output: 'No vulnerability found', metadata: { orchestrationStatus: 'executed', resultType: 'negative' } } });
    expect(evaluateExploitExecution(result([step]))).toMatchObject({ success: false, executionStatus: 'executed', outcomeStatus: 'not_exploitable' });
  });

  it('allows reporting after no targets and after every reporting-only skip reason', () => {
    expect(dependencyAllowsTask(skipped('no_validated_targets'), { operatorType: 'analyst' })).toBe(true);
    for (const reason of ['scope_denied', 'not_authorized', 'budget_exceeded', 'dependency_missing', 'waf_blocked', 'configuration_error'] as const) {
      expect(dependencyAllowsTask(skipped(reason), { operatorType: 'analyst' })).toBe(true);
      expect(dependencyAllowsTask(skipped(reason), { operatorType: 'scanner' })).toBe(false);
    }
  });

  it('does not emit a second FAILED main line from orchestration events', () => {
    expect(shouldPrintOrchestrationEvent('FAILED')).toBe(false);
    expect(shouldPrintOrchestrationEvent('BLOCKED')).toBe(true);
  });
});

import type { AgentResult, AgentStep } from './index.js';
import type { LLMMessage, LLMToolCall, Target, Task, ToolFinding } from '../types/index.js';

export interface AgentCheckpoint {
  version: 1;
  contract: string;
  phase: 'bootstrap' | 'planning' | 'tool_batch' | 'summary' | 'completed';
  iteration: number;
  elapsedMs: number;
  bootstrapCompleted: boolean;
  messages: LLMMessage[];
  steps: AgentStep[];
  findings: ToolFinding[];
  tokensUsed: number;
  totalToolCalls: number;
  seenCalls: [string, string][];
  toolCallCounts: [string, number][];
  exhaustedToolWarnings: string[];
  noProgress: number;
  consecutiveLlmFailures: number;
  modelUnavailable: boolean;
  lastLlmError?: string;
  pendingCalls: LLMToolCall[];
  findingsBeforeBatch: number;
  activeCall?: LLMToolCall;
  result?: AgentResult;
}

export class CheckpointWriteError extends Error {
  constructor(cause: unknown) {
    super('Checkpoint could not be saved; execution stopped to preserve recoverability.', { cause });
    this.name = 'CheckpointWriteError';
  }
}

export class UnsafeResumeError extends Error {
  constructor(call: LLMToolCall) {
    super(`Interrupted ${call.name} may have changed the target. Automatic replay is blocked; inspect its recorded parameters and target state before continuing.`);
    this.name = 'UnsafeResumeError';
  }
}

export class CheckpointRestoreError extends Error {
  constructor() {
    super('Invalid or incompatible agent checkpoint; original saved state was retained.');
    this.name = 'CheckpointRestoreError';
  }
}

export function checkpointContract(task: Task, target?: Target): string {
  return JSON.stringify({ id: task.id, missionId: task.missionId, name: task.name,
    description: task.description, phase: task.phase, operatorType: task.operatorType,
    executionPlan: task.executionPlan, target: target?.address });
}

// Unknown tools and scanners with potentially intrusive flags require inspection.
export function canReplayInterruptedCall(call: LLMToolCall): boolean {
  if (call.name === 'http_request') {
    const method = call.arguments.method;
    return (method === undefined || (typeof method === 'string' && ['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase())))
      && !call.arguments.body;
  }
  return ['dns_lookup', 'header_analysis', 'robots_txt_fetch', 'technology_detect',
    'ssl_analysis', 'jwt_decode', 'url_parse'].includes(call.name);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isCall(value: unknown): value is LLMToolCall {
  return isRecord(value) && typeof value.id === 'string' && !!value.id
    && typeof value.name === 'string' && !!value.name && isRecord(value.arguments);
}

/** Fail closed on malformed or mismatched persisted execution state. */
export function restoreAgentCheckpoint(value: unknown, task: Task, target?: Target): AgentCheckpoint {
  const fail = (): never => { throw new CheckpointRestoreError(); };
  if (!isRecord(value) || value.version !== 1 || value.contract !== checkpointContract(task, target)
    || !['bootstrap', 'planning', 'tool_batch', 'summary', 'completed'].includes(String(value.phase))) return fail();
  for (const key of ['iteration', 'elapsedMs', 'tokensUsed', 'totalToolCalls', 'noProgress', 'consecutiveLlmFailures', 'findingsBeforeBatch']) {
    if (!Number.isSafeInteger(value[key]) || Number(value[key]) < 0) return fail();
  }
  for (const key of ['bootstrapCompleted', 'modelUnavailable']) if (typeof value[key] !== 'boolean') return fail();
  if (value.lastLlmError !== undefined && typeof value.lastLlmError !== 'string') return fail();
  if (!Array.isArray(value.messages) || value.messages.length < 2
    || !value.messages.every(message => isRecord(message) && ['system', 'user', 'assistant', 'tool'].includes(String(message.role))
      && typeof message.content === 'string'
      && (message.toolCalls === undefined || (Array.isArray(message.toolCalls) && message.toolCalls.every(isCall))))) return fail();
  if (!Array.isArray(value.steps) || !value.steps.every(step => isRecord(step)
    && ['tool_call', 'observation', 'reasoning'].includes(String(step.type)) && Number.isFinite(step.timestamp))) return fail();
  if (!Array.isArray(value.findings) || !value.findings.every(finding => isRecord(finding)
    && typeof finding.title === 'string' && typeof finding.details === 'string'
    && ['info', 'low', 'medium', 'high', 'critical'].includes(String(finding.severity)))) return fail();
  if (!Array.isArray(value.seenCalls) || !value.seenCalls.every(pair => Array.isArray(pair) && pair.length === 2 && pair.every(item => typeof item === 'string'))
    || !Array.isArray(value.toolCallCounts) || !value.toolCallCounts.every(pair => Array.isArray(pair) && pair.length === 2 && typeof pair[0] === 'string' && Number.isSafeInteger(pair[1]) && pair[1] >= 0)
    || !Array.isArray(value.exhaustedToolWarnings) || !value.exhaustedToolWarnings.every(item => typeof item === 'string')
    || !Array.isArray(value.pendingCalls) || !value.pendingCalls.every(isCall)) return fail();
  if (value.phase === 'tool_batch' && (value.pendingCalls.length === 0 || !value.bootstrapCompleted)) return fail();
  if (value.activeCall !== undefined && (!isCall(value.activeCall)
    || !['bootstrap', 'tool_batch'].includes(String(value.phase))
    || (value.phase === 'tool_batch' && JSON.stringify(value.activeCall) !== JSON.stringify(value.pendingCalls[0])))) return fail();
  if (value.phase !== 'tool_batch' && value.pendingCalls.length > 0) return fail();
  if (value.phase === 'completed') {
    if (!isRecord(value.result) || typeof value.result.success !== 'boolean' || typeof value.result.summary !== 'string'
      || !Array.isArray(value.result.steps) || !Array.isArray(value.result.findings)
      || !Number.isSafeInteger(value.result.iterations) || Number(value.result.iterations) < 0
      || value.result.tokensUsed !== value.tokensUsed || typeof value.result.hitLimit !== 'boolean'
      || !Number.isFinite(value.result.durationMs) || value.activeCall !== undefined) return fail();
  } else if (value.result !== undefined) return fail();
  return structuredClone(value) as unknown as AgentCheckpoint;
}

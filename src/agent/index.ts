/**
 * VULNORA Agent Loop
 *
 * ReAct (Reason + Act) agent that connects LLM tool calling to Arsenal execution.
 * This is the core autonomous loop: the LLM decides which tool to use,
 * Arsenal executes it, and results are fed back for the next decision.
 */

import { EventEmitter } from 'eventemitter3';
import { randomUUID } from 'crypto';
import { isContextCompactionNotice, LLMUnavailableError, type LLMBackbone } from '../llm/index.js';
import { KillChainPhase } from '../types/index.js';
import { hostFromTargetValue, type Arsenal } from '../arsenal/index.js';
import { normalizeToolCall, type EvidenceRecord } from '../orchestrator/tool-orchestrator.js';
import { canReplayInterruptedCall, checkpointContract, CheckpointRestoreError, CheckpointWriteError, restoreAgentCheckpoint, UnsafeResumeError, type AgentCheckpoint } from './checkpoint.js';
import {
  buildMissionPrompt,
  resolveAgentPromptProfile,
  selectRelevantTools,
  type PromptSecurityContext,
} from './prompt-profile.js';
import type {
  LLMMessage,
  LLMToolDefinition,
  LLMToolCall,
  ToolResult,
  ToolFinding,
  Severity,
  Target,
  Task,
} from '../types/index.js';

// =============================================================================
// TYPES
// =============================================================================

export interface AgentLoopOptions {
  /** Max ReAct iterations before forcing a conclusion (default: 15) */
  maxIterations?: number;
  /** Max total tokens to spend (default: 50000) */
  maxTokens?: number;
  /** Tool categories to expose (default: all) */
  toolCategories?: string[];
  /** Explicit tool-NAME allowlist — the operator's role toolkit. Overrides toolCategories. */
  tools?: string[];
  /** Whether to include detailed tool output in context (default: true) */
  verboseToolOutput?: boolean;
  /** Max characters per tool result before truncation (default: 4000) */
  maxToolOutputLength?: number;
  /** Compact mission authorization facts; runtime ScopeGuard/approval remains authoritative. */
  securityContext?: PromptSecurityContext;
  /** Stable source identity recorded in the central Evidence Store. */
  sourceAgent?: string;
  /** Await durable persistence before starting work and after each completed tool. */
  onCheckpoint?: (checkpoint: AgentCheckpoint, task: Task) => Promise<void>;
}

export interface AgentStep {
  iteration: number;
  type: 'tool_call' | 'observation' | 'reasoning';
  toolName?: string;
  toolArgs?: Record<string, unknown>;
  toolResult?: ToolResult;
  content?: string;
  timestamp: number;
  attemptId?: string;
  sourceToolCallId?: string;
  evidenceRecordId?: string;
}

export interface AgentResult {
  success: boolean;
  /** Final summary from the LLM */
  summary: string;
  /** All steps taken during execution */
  steps: AgentStep[];
  /** Findings extracted from tool results */
  findings: ToolFinding[];
  /** Total iterations used */
  iterations: number;
  /** Total tokens consumed */
  tokensUsed: number;
  /** Duration in ms */
  durationMs: number;
  /** Whether the agent hit the iteration limit */
  hitLimit: boolean;
  /** Error from the forced final-summary call after hitting limits, if any */
  finalSummaryError?: string;
}

export function maxToolCallsPerTask(toolName: string): number | undefined {
  if (toolName === 'nmap_scan') {
    const configured = Number(process.env.VULNORA_NMAP_MAX_CALLS_PER_TASK || 4);
    return Number.isFinite(configured) && configured > 0 ? Math.max(1, Math.min(10, Math.round(configured))) : 4;
  }
  if (toolName === 'port_scan') return 4;
  if (toolName === 'nuclei_scan') {
    const configured = Number(process.env.VULNORA_NUCLEI_MAX_CALLS_PER_TASK || 4);
    return Number.isFinite(configured) && configured > 0 ? Math.max(1, Math.min(8, Math.round(configured))) : 4;
  }
  return undefined;
}

function findingKey(finding: ToolFinding): string {
  return finding.title.toLowerCase().replace(/\W+/g, ' ').trim();
}

function mergeFinding(findings: ToolFinding[], incoming: ToolFinding): boolean {
  const existing = findings.find(item => findingKey(item) === findingKey(incoming));
  if (!existing) {
    findings.push(incoming);
    return true;
  }
  const severityRank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  if (severityRank[incoming.severity] > severityRank[existing.severity]) existing.severity = incoming.severity;
  if (incoming.provenance === 'tool' && existing.provenance !== 'tool') Object.assign(existing, incoming);
  else {
    if ((incoming.details || '').length > (existing.details || '').length) existing.details = incoming.details;
    existing.cve = [...new Set([...(existing.cve || []), ...(incoming.cve || [])])];
    existing.cwe = [...new Set([...(existing.cwe || []), ...(incoming.cwe || [])])];
  }
  return false;
}

export interface AgentEvents {
  'agent:step': AgentStep;
  'agent:tool_call': { name: string; args: Record<string, unknown>; source?: 'agent' | 'backend_seeded' };
  'agent:tool_result': { name: string; result: ToolResult; source?: 'agent' | 'backend_seeded' };
  'agent:thinking': { content: string };
  'agent:complete': AgentResult;
  'agent:error': { error: Error; step: number };
}

// =============================================================================
// AGENT LOOP
// =============================================================================

export class AgentLoop extends EventEmitter<AgentEvents> {
  private llm: LLMBackbone;
  private arsenal: Arsenal;
  private options: Required<Omit<AgentLoopOptions, 'securityContext' | 'onCheckpoint'>> & { securityContext: PromptSecurityContext };
  private onCheckpoint?: AgentLoopOptions['onCheckpoint'];

  constructor(llm: LLMBackbone, arsenal: Arsenal, options?: AgentLoopOptions) {
    super();
    this.llm = llm;
    this.arsenal = arsenal;
    this.onCheckpoint = options?.onCheckpoint;
    this.options = {
      maxIterations: options?.maxIterations ?? 15,
      maxTokens: options?.maxTokens ?? 50000,
      toolCategories: options?.toolCategories ?? [],
      tools: options?.tools ?? [],
      verboseToolOutput: options?.verboseToolOutput ?? true,
      maxToolOutputLength: options?.maxToolOutputLength ?? 4000,
      securityContext: options?.securityContext ?? {},
      sourceAgent: options?.sourceAgent ?? 'agent',
    };
  }

  /**
   * Run the ReAct loop for a task
   */
  async run(
    task: Task,
    _systemPrompt: string,
    target?: Target,
    sourceContext?: string,
    sharedContext?: string,
    signal?: AbortSignal
  ): Promise<AgentResult> {
    signal?.throwIfAborted();
    const saved = task.checkpoint === undefined ? undefined : restoreAgentCheckpoint(task.checkpoint, task, target);
    if (saved?.phase === 'completed' && saved.result) return saved.result;
    const savedReceipt = saved?.activeAttempt ? this.arsenal.getOrchestrator().getEvidence().find(record =>
      record.attemptId === saved.activeAttempt?.attemptId && record.sourceToolCallId === saved.activeAttempt?.sourceToolCallId
      && record.executionStatus === 'executed' && saved.activeCall
      && record.normalizedSignature === normalizeToolCall(saved.activeCall.name, { target, parameters: saved.activeCall.arguments }).normalizedSignature) : undefined;
    if (saved?.activeCall && !savedReceipt && !canReplayInterruptedCall(saved.activeCall)) throw new UnsafeResumeError(saved.activeCall);
    const startTime = Date.now() - (saved?.elapsedMs || 0);
    const steps: AgentStep[] = saved?.steps || [];
    const allFindings: ToolFinding[] = saved?.findings || [];
    let tokensUsed = saved?.tokensUsed || 0;
    let hitLimit = false;
    // anti-stall: dedup identical tool calls + detect runs of no-new-findings (ported from the hunter)
    const seenCalls = new Map<string, string>(saved?.seenCalls);
    const toolCallCounts = new Map<string, number>(saved?.toolCallCounts);
    const exhaustedToolWarnings = new Set<string>(saved?.exhaustedToolWarnings);
    let noProgress = saved?.noProgress || 0;
    let consecutiveLlmFailures = saved?.consecutiveLlmFailures || 0;
    let modelUnavailable = saved?.modelUnavailable || false;
    let lastLlmError = saved?.lastLlmError;
    let iteration = saved?.iteration || 0;
    let phase: AgentCheckpoint['phase'] = saved?.phase || 'bootstrap';
    let bootstrapCompleted = saved?.bootstrapCompleted || false;
    let pendingCalls = saved?.pendingCalls || [];
    let activeCall = saved?.activeCall;
    let activeAttempt = saved?.activeAttempt;
    let findingsBeforeBatch = saved?.findingsBeforeBatch || 0;

    const profile = resolveAgentPromptProfile(this.llm.getPromptProfile());
    const maxIterations = Math.min(this.options.maxIterations, profile.maxIterations);
    const maxTotalTokens = Math.min(this.options.maxTokens, profile.maxTotalTokens);
    let totalToolCalls = saved?.totalToolCalls || 0;

    // Get tool definitions from Arsenal (the operator's role toolkit: name allowlist wins,
    // then category filter, then all).
    const availableToolDefs = await this.arsenal.getReadyToolDefinitions(
      this.options.toolCategories.length > 0 ? this.options.toolCategories : undefined,
      this.options.tools.length > 0 ? this.options.tools : undefined
    );
    // Recovery plans are issued by the orchestrator, independently of role defaults.
    if (task.executionPlan) {
      const planned = this.arsenal.getToolDefinitions(undefined, [task.executionPlan.toolName])[0];
      if (planned && !availableToolDefs.some(definition => definition.name === planned.name)) availableToolDefs.unshift(planned);
    }
    const targetReceipt = target?.metadata?.authorizationReceipt
      || target?.metadata?.scopeReceipt
      || target?.metadata?.receipt;
    const hasReceipt = Boolean(this.options.securityContext.receipt || targetReceipt);
    const securityContext: PromptSecurityContext = {
      ...this.options.securityContext,
      receipt: this.options.securityContext.receipt || (targetReceipt ? String(targetReceipt) : undefined),
      intrusiveAllowed: this.options.securityContext.intrusiveAllowed ?? hasReceipt,
      credentialToolsAllowed: this.options.securityContext.credentialToolsAllowed ?? hasReceipt,
    };
    const toolDefs = selectRelevantTools(availableToolDefs, task, profile, securityContext, !!target?.address);
    const evidenceTarget = target ? normalizeToolCall('http_request', { parameters: { url: target.address } }).host : undefined;
    const storedEvidence = task.operatorType === 'analyst'
      ? [...new Map(this.arsenal.getOrchestrator().getEvidence()
        .filter(record => !evidenceTarget || normalizeToolCall('http_request', { parameters: { url: record.target } }).host === evidenceTarget)
        .map(record => [record.normalizedSignature, record])).values()]
        .slice(-profile.findingLimit)
        .map(record => `Evidence ${record.id}: ${record.toolName} status=${record.errorType || record.executionStatus}; ${String(record.result.error || record.rawOutput).replace(/\s+/g, ' ').slice(0, profile.evidenceChars)}`)
        .join('\n')
      : '';
    const coverageGaps = task.operatorType === 'analyst'
      ? this.arsenal.getOrchestrator().getMetrics().incompleteAreas.join('; ')
      : '';

    // Build initial messages
    const messages: LLMMessage[] = saved?.messages || [
      {
        role: 'system',
        content: 'Follow the mission contract exactly. Function schemas are authoritative. Never invent observations, authorization, tool results, or impact.',
      },
      {
        role: 'user',
        content: buildMissionPrompt({
          task,
          target,
          tools: toolDefs,
          profile,
          security: securityContext,
          sourceContext: [coverageGaps ? `Coverage gaps: ${coverageGaps}` : '',
            this.arsenal.getOrchestrator().scanPolicy?.behavior && evidenceTarget
              ? `Scanner limits (enforced, scope cannot change): ${JSON.stringify(this.arsenal.getOrchestrator().getNetworkContext(evidenceTarget).scanning)}. Prioritize relevant checks using existing findings; avoid redundant or unavailable checks.` : '',
            storedEvidence, sourceContext, sharedContext].filter(Boolean).join('\n'),
        }),
      },
    ];

    const publish = async (nextPhase: AgentCheckpoint['phase'], result?: AgentResult): Promise<void> => {
      phase = nextPhase;
      const checkpoint: AgentCheckpoint = structuredClone({
        version: 1, contract: checkpointContract(task, target), phase, iteration,
        elapsedMs: Date.now() - startTime, bootstrapCompleted, messages, steps,
        findings: allFindings, tokensUsed, totalToolCalls, seenCalls: [...seenCalls],
        toolCallCounts: [...toolCallCounts], exhaustedToolWarnings: [...exhaustedToolWarnings],
        noProgress, consecutiveLlmFailures, modelUnavailable, lastLlmError,
        pendingCalls, activeCall, activeAttempt, findingsBeforeBatch, result,
      });
      task.checkpoint = checkpoint;
      try { await this.onCheckpoint?.(checkpoint, task); }
      catch (error) { throw new CheckpointWriteError(error); }
    };

    const bootstrapCall = activeCall && phase === 'bootstrap' ? activeCall : this.getLocalReconBootstrap(task, target, toolDefs);
    if (!bootstrapCompleted && task.executionPlan && !bootstrapCall) {
      const result: AgentResult = {
        success: false, summary: `Recovery blocked: ${task.executionPlan.toolName} is unavailable or not permitted.`,
        steps, findings: [], iterations: 0, tokensUsed: 0, durationMs: Date.now() - startTime, hitLimit: false,
      };
      await publish('completed', result);
      this.emit('agent:complete', result);
      return result;
    }
    if (!bootstrapCompleted && bootstrapCall) {
      if (!toolDefs.some(definition => definition.name === bootstrapCall.name)) throw new UnsafeResumeError(bootstrapCall);
      activeCall = bootstrapCall;
      activeAttempt ||= { attemptId: `attempt-${randomUUID()}`, sourceToolCallId: `tool-call-${randomUUID()}` };
      await publish('bootstrap');
      const toolStep = await this.executeTool(bootstrapCall, target, task, -1, signal, activeAttempt, savedReceipt);
      activeCall = undefined;
      activeAttempt = undefined;
      bootstrapCompleted = true;
      toolCallCounts.set(bootstrapCall.name, 1);
      totalToolCalls++;
      steps.push(toolStep);
      seenCalls.set(
        `${bootstrapCall.name}:${JSON.stringify(bootstrapCall.arguments || {})}`,
        String(toolStep.toolResult?.output || toolStep.toolResult?.error || 'no output').replace(/\s+/g, ' ').slice(0, 160)
      );

      if (toolStep.toolResult?.findings) {
        const out = String(toolStep.toolResult.output ?? '').slice(0, 4000);
        for (const tf of toolStep.toolResult.findings) {
          mergeFinding(allFindings, { ...tf, provenance: 'tool', toolName: bootstrapCall.name, toolOutput: out || tf.details });
        }
      }

      if (task.executionPlan) {
        const result: AgentResult = {
          success: toolStep.toolResult?.success === true,
          summary: this.formatToolResult(toolStep.toolResult),
          steps, findings: allFindings, iterations: 0, tokensUsed: 0,
          durationMs: Date.now() - startTime, hitLimit: false,
        };
        await publish('completed', result);
        this.emit('agent:complete', result);
        return result;
      }

      messages.push({
        role: 'assistant',
        content: 'Running an initial low-noise recon check before planning deeper actions.',
        toolCalls: [bootstrapCall],
      });
      messages.push({
        role: 'tool',
        content: this.formatToolResult(toolStep.toolResult),
        toolCallId: bootstrapCall.id,
        name: bootstrapCall.name,
      });
      messages.push({
        role: 'user',
        content: 'Use this as the first observation. Request one different specific tool only if it can add relevant evidence; otherwise return the required RESULT format.',
      });
    }

    if (!bootstrapCompleted) bootstrapCompleted = true;
    if (phase === 'bootstrap') await publish('planning');
    const deterministic = this.llm.getProvider() === 'deterministic';
    if (deterministic) { modelUnavailable = true; lastLlmError = new LLMUnavailableError().message; }

    for (let i = iteration; phase !== 'summary' && (!deterministic || pendingCalls.length > 0)
      && (i < maxIterations || pendingCalls.length > 0); i++) {
      iteration = i;
      try {
        // Ask the LLM what to do next
        const callableToolDefs = toolDefs.filter(definition => {
          const limit = maxToolCallsPerTask(definition.name);
          return limit === undefined || (toolCallCounts.get(definition.name) || 0) < limit;
        });
        const estimatedInputTokens = this.estimateModelInputTokens(messages, callableToolDefs);
        const remainingTokens = maxTotalTokens - tokensUsed;
        if (pendingCalls.length === 0 && remainingTokens <= estimatedInputTokens + 128) {
          hitLimit = true;
          break;
        }
        signal?.throwIfAborted();
        if (pendingCalls.length === 0) await publish('planning');
        signal?.throwIfAborted();
        const replayingBatch = pendingCalls.length > 0;
        const response = replayingBatch ? { content: '', toolCalls: pendingCalls } : await this.llm.chatWithTools(messages, callableToolDefs, {
          maxTokens: Math.min(profile.responseTokens, remainingTokens - estimatedInputTokens),
          signal,
          temperature: 0.3, // Lower temperature for tool-using tasks
        });
        signal?.throwIfAborted();
        consecutiveLlmFailures = 0;

        if (!replayingBatch) {
          tokensUsed += ('usage' in response ? response.usage?.totalTokens : undefined)
            ?? this.estimateModelTokens(messages, response.content || '', callableToolDefs);
        }

        // If the LLM wants to call tools
        if (response.toolCalls?.length) {
          // Record the assistant's reasoning
          if (!replayingBatch && response.content) {
            const thinkStep: AgentStep = {
              iteration: i,
              type: 'reasoning',
              content: response.content,
              timestamp: Date.now(),
            };
            steps.push(thinkStep);
            this.emit('agent:thinking', { content: response.content });
          }

          // Add assistant message to context (with tool calls)
          const remainingCalls = Math.max(0, profile.maxToolCalls - totalToolCalls);
          const requestedCalls = replayingBatch ? [...pendingCalls] : response.toolCalls.slice(0, remainingCalls);
          if (requestedCalls.length === 0) {
            hitLimit = true;
            break;
          }
          if (!replayingBatch) {
            messages.push({
              role: 'assistant',
              content: response.content || '',
              toolCalls: requestedCalls,
            });
          }

          // Execute each tool call
          if (!replayingBatch) findingsBeforeBatch = allFindings.length;
          pendingCalls = [...requestedCalls];
          await publish('tool_batch');
          for (const toolCall of requestedCalls) {
            signal?.throwIfAborted();
            // ANTI-STALL: a byte-identical repeat is almost always wasted — steer instead of re-running.
            const callHash = `${toolCall.name}:${JSON.stringify(toolCall.arguments || {})}`;
            let toolStep: AgentStep;
            if (seenCalls.has(callHash)) {
              const dup: ToolResult = {
                success: false,
                error: `Duplicate call — you already ran ${toolCall.name} with these exact arguments. ` +
                  `Prior result: ${seenCalls.get(callHash)}. Do NOT repeat it — change the arguments, pick a different tool, or move to your final debrief.`,
              };
              toolStep = { iteration: i, type: 'tool_call', toolName: toolCall.name, toolArgs: toolCall.arguments, toolResult: dup, timestamp: Date.now() };
            } else {
              const limit = maxToolCallsPerTask(toolCall.name);
              const count = toolCallCounts.get(toolCall.name) || 0;
              if (limit !== undefined && count >= limit) {
                const exhausted: ToolResult = {
                  success: false,
                  error: `${toolCall.name} budget exhausted after ${limit} calls for this task. `
                    + 'Use the collected scan evidence and produce the final debrief; do not split the same scan into more ranges.',
                };
                toolStep = { iteration: i, type: 'tool_call', toolName: toolCall.name, toolArgs: toolCall.arguments, toolResult: exhausted, timestamp: Date.now() };
              } else {
                if (!toolDefs.some(definition => definition.name === toolCall.name) && replayingBatch) throw new UnsafeResumeError(toolCall);
                activeCall = toolCall;
                activeAttempt ||= { attemptId: `attempt-${randomUUID()}`, sourceToolCallId: `tool-call-${randomUUID()}` };
                await publish('tool_batch');
                toolStep = await this.executeTool(toolCall, target, task, i, signal, activeAttempt,
                  savedReceipt?.attemptId === activeAttempt.attemptId ? savedReceipt : undefined);
                toolCallCounts.set(toolCall.name, count + 1);
                seenCalls.set(callHash, String(toolStep.toolResult?.output || toolStep.toolResult?.error || 'no output').replace(/\s+/g, ' ').slice(0, 160));
              }
            }
            totalToolCalls++;
            steps.push(toolStep);

            // Collect findings — tag with REAL tool provenance (the output that backs them)
            if (toolStep.toolResult?.findings) {
              const out = String(toolStep.toolResult.output ?? '').slice(0, 4000);
              for (const tf of toolStep.toolResult.findings) {
                mergeFinding(allFindings, { ...tf, provenance: 'tool', toolName: toolCall.name, toolOutput: out || tf.details });
              }
            }

            // Build tool result content
            const resultContent = this.formatToolResult(toolStep.toolResult);

            // Add tool result to context
            messages.push({
              role: 'tool',
              content: resultContent,
              toolCallId: toolCall.id,
              name: toolCall.name,
            });

            const limit = maxToolCallsPerTask(toolCall.name);
            const count = toolCallCounts.get(toolCall.name) || 0;
            if (limit !== undefined && count >= limit && !exhaustedToolWarnings.has(toolCall.name)) {
              exhaustedToolWarnings.add(toolCall.name);
              messages.push({
                role: 'user',
                content: `[System: ${toolCall.name} reached its ${limit}-call task budget and is no longer available. `
                  + 'Do not launch more overlapping port ranges. Use the evidence already collected and finish the task, or use a genuinely different non-port-scan tool only if essential.]',
              });
            }
            activeCall = undefined;
            activeAttempt = undefined;
            pendingCalls.shift();
            // Save the next exact call without asking the model to re-plan completed work.
            if (pendingCalls.length > 0) await publish('tool_batch');
          }

          // ANTI-STALL: after a run of iterations with no new findings, steer (once) toward a new
          // vector or a final debrief — don't let the agent grind the budget on a dead approach.
          noProgress = allFindings.length > findingsBeforeBatch ? 0 : noProgress + 1;
          const noProgressLimit = profile.name === 'small_model_30b' ? 2 : 4;
          if (noProgress >= noProgressLimit && i < maxIterations - 1) {
            messages.push({
              role: 'user',
              content: `No new relevant evidence after ${noProgressLimit} steps. Stop and return the required RESULT format unless one genuinely different, specific test has a concrete evidence-based reason.`,
            });
            if (profile.name === 'small_model_30b') {
              hitLimit = true;
              break;
            }
            noProgress = 0;
          }
        } else {
          if (isContextCompactionNotice(response.content || '')) {
            messages.push({
              role: 'user',
              content: 'Ignore transport/history notices. Re-read the preserved ROLE, SCOPE, MISSION, KNOWN EVIDENCE, WORKFLOW and OUTPUT sections, then perform the mission or return the required RESULT format.',
            });
            iteration = i + 1;
            await publish('planning');
            continue;
          }
          // LLM finished reasoning — this is the final answer.
          const finalStep: AgentStep = {
            iteration: i,
            type: 'reasoning',
            content: response.content,
            timestamp: Date.now(),
          };
          steps.push(finalStep);

          // Parse the structured debrief block so the model's OWN analysis is captured —
          // previously only tool-emitted findings were kept and the final report was dropped.
          for (const f of this.parseFinalFindings(response.content || '')) {
            mergeFinding(allFindings, f);
          }

          const result: AgentResult = {
            success: true,
            summary: response.content,
            steps,
            findings: allFindings,
            iterations: i + 1,
            tokensUsed,
            durationMs: Date.now() - startTime,
            hitLimit: false,
          };

          await publish('completed', result);
          this.emit('agent:complete', result);
          return result;
        }

        iteration = i + 1;
        await publish('planning');
        // Check token budget
        if (tokensUsed >= maxTotalTokens || totalToolCalls >= profile.maxToolCalls) {
          hitLimit = true;
          break;
        }
      } catch (error) {
        if (error instanceof CheckpointWriteError || error instanceof CheckpointRestoreError || error instanceof UnsafeResumeError) throw error;
        signal?.throwIfAborted();
        this.emit('agent:error', { error: error as Error, step: i });

        // On error, try to continue with a reduced context
        const errMsg = error instanceof Error ? error.message : String(error);
        lastLlmError = errMsg;
        if (error instanceof LLMUnavailableError) { modelUnavailable = true; break; }
        consecutiveLlmFailures++;
        if (consecutiveLlmFailures >= 2) {
          // Repeating a dead primary+fallback request for every remaining ReAct
          // iteration previously kept a mission alive for hours. Preserve all
          // collected tool evidence and finish the task deterministically.
          modelUnavailable = true;
          hitLimit = true;
          break;
        }
        messages.push({
          role: 'user',
          content: `[System: Tool execution error: ${errMsg}. Please continue with available information or try a different approach.]`,
        });
        iteration = i + 1;
        await publish('planning');
      }
    }

    signal?.throwIfAborted();
    // Hit iteration or token limit — ask LLM for a final summary
    hitLimit = !deterministic;
    if (phase !== 'summary') {
      messages.push({
        role: 'user',
        content: modelUnavailable
          ? 'AI planning is unavailable. Preserve completed tools and evidence; do not infer unverified vulnerabilities.'
          : 'The step budget is exhausted. Return the required RESULT format now. Use only collected evidence; do not add claims or request tools.',
      });
    }
    await publish('summary');
    signal?.throwIfAborted();

    let summary = 'Agent reached iteration limit without producing a final summary.';
    let finalSummaryError: string | undefined;
    if (modelUnavailable) {
      finalSummaryError = lastLlmError;
      summary = `RESULT\nStatus: inconclusive\n\n${lastLlmError || 'AI planning unavailable.'}\n`
        + `Evidence: Preserved ${steps.length} completed step(s) and ${allFindings.length} tool-backed finding(s).\n`
        + 'Limitations: Deterministic checks cannot replace AI analysis; no unverified vulnerabilities or impact were inferred.';
    } else {
      const estimatedFinalInput = this.estimateModelInputTokens(messages);
      const remainingTokens = maxTotalTokens - tokensUsed;
      if (remainingTokens <= estimatedFinalInput + 64) {
        summary = 'RESULT\nStatus: inconclusive\n\nFinding: No additional finding validated.\n'
          + `Target: ${target?.address || 'Unknown target.'}\n`
          + `Evidence: Preserved ${steps.length} completed step(s) and ${allFindings.length} deduplicated finding(s).\n`
          + 'Impact: No additional impact demonstrated.\nActions performed: See preserved tool steps.\n'
          + 'Limitations: The cumulative model token budget was exhausted before another summary request could be made.\n'
          + 'Recommended next step: Review preserved evidence or start a separately authorized follow-up task.';
      } else try {
        const finalResponse = await this.llm.chat(messages, {
          signal,
          maxTokens: Math.min(profile.finalResponseTokens, remainingTokens - estimatedFinalInput),
        });
        signal?.throwIfAborted();
        summary = isContextCompactionNotice(finalResponse.content)
          ? 'RESULT\nStatus: inconclusive\n\nFinding: None validated.\nTarget: Preserved mission target.\nEvidence: The model returned only a history-compaction notice.\nImpact: No impact demonstrated.\nActions performed: Preserved completed tool steps.\nLimitations: No usable final model response.\nRecommended next step: Retry with the preserved mission prompt.'
          : finalResponse.content;
        tokensUsed += finalResponse.usage?.totalTokens
          ?? this.estimateModelTokens(messages, finalResponse.content || '');
        // capture the structured debrief from the limit-summary too (same contract as the clean finish)
        for (const f of this.parseFinalFindings(summary)) {
          mergeFinding(allFindings, f);
        }
      } catch (error) {
        signal?.throwIfAborted();
        finalSummaryError = error instanceof Error ? error.message : String(error);
      }
    }

    const result: AgentResult = {
      success: allFindings.length > 0 || steps.some(s => s.toolResult?.success),
      summary,
      steps,
      findings: allFindings,
      iterations: iteration,
      tokensUsed,
      durationMs: Date.now() - startTime,
      hitLimit,
      finalSummaryError,
    };

    await publish('completed', result);
    this.emit('agent:complete', result);
    return result;
  }

  private getLocalReconBootstrap(
    task: Task,
    target: Target | undefined,
    tools: LLMToolDefinition[]
  ): LLMToolCall | undefined {
    if (task.executionPlan && tools.some(tool => tool.name === task.executionPlan!.toolName)) {
      return {
        id: `coverage-recovery-${Date.now()}`,
        name: task.executionPlan.toolName,
        arguments: { ...task.executionPlan.parameters },
      };
    }
    const deterministic = this.llm.getProvider() === 'deterministic';
    if (this.llm.getProvider() !== 'local-agent' && !deterministic) return undefined;
    if (!target?.address) return undefined;
    if (task.phase !== 'reconnaissance' && task.operatorType !== 'recon'
      && !(deterministic && task.phase === KillChainPhase.WEAPONIZE)) return undefined;

    const hasTool = (name: string) => tools.some((tool) => tool.name === name);
    const taskName = task.name.toLowerCase();
    const id = `local-agent-bootstrap-${Date.now()}`;
    const host = hostFromTargetValue(target.address);
    if (!host) return undefined;
    const originalUrl = /^https?:\/\//i.test(target.address) ? target.address.trim()
      : typeof target.metadata?.url === 'string' && /^https?:\/\//i.test(target.metadata.url)
        && hostFromTargetValue(target.metadata.url) === host ? target.metadata.url : undefined;
    const authority = host.includes(':') ? `[${host}]` : host;
    const url = originalUrl || `${target.protocol === 'http' ? 'http' : 'https'}://${authority}${target.port ? `:${target.port}` : ''}`;

    if (deterministic && task.phase === KillChainPhase.WEAPONIZE) {
      const endpoint = new URL(url);
      if (taskName.includes('network') && endpoint.protocol === 'https:' && hasTool('ssl_scan')) {
        return { id, name: 'ssl_scan', arguments: { host, port: Number(endpoint.port) || 443 } };
      }
      if (hasTool('header_analysis')) return { id, name: 'header_analysis', arguments: { url } };
    }

    if (taskName.includes('dns') && hasTool('dns_lookup')) {
      return { id, name: 'dns_lookup', arguments: { domain: host, type: 'A' } };
    }

    if (taskName.includes('port') && hasTool('port_scan')) {
      return { id, name: 'port_scan', arguments: { target: host, ports: '80,443', timeout: 2000 } };
    }

    if ((taskName.includes('web') || taskName.includes('fingerprint')) && hasTool('header_analysis')) {
      return { id, name: 'header_analysis', arguments: { url } };
    }

    if ((taskName.includes('content') || taskName.includes('discover')) && hasTool('robots_txt_fetch')) {
      return { id, name: 'robots_txt_fetch', arguments: { url } };
    }

    return undefined;
  }

  /** Conservative fallback for providers that do not return usage metadata.
   * Tool outputs count here because they are stored in `messages` and become
   * model-input tokens on the next planning/final-summary request. */
  private estimateModelTokens(
    messages: LLMMessage[],
    responseContent: string,
    tools: LLMToolDefinition[] = []
  ): number {
    return this.estimateModelInputTokens(messages, tools)
      + Math.max(1, Math.ceil(responseContent.length / 4));
  }

  private estimateModelInputTokens(messages: LLMMessage[], tools: LLMToolDefinition[] = []): number {
    const messageChars = messages.reduce((sum, message) => sum + message.content.length, 0);
    const schemaChars = tools.reduce((sum, tool) => sum + JSON.stringify(tool).length, 0);
    return Math.max(1, Math.ceil((messageChars + schemaChars) / 4));
  }

  /**
   * Execute a single tool call via the Arsenal
   */
  private async executeTool(
    toolCall: LLMToolCall,
    target: Target | undefined,
    task: Task,
    iteration: number,
    signal?: AbortSignal,
    attempt?: AgentCheckpoint['activeAttempt'],
    receipt?: EvidenceRecord
  ): Promise<AgentStep> {
    signal?.throwIfAborted();
    const source = iteration < 0 ? 'backend_seeded' : 'agent';
    const attemptId = attempt?.attemptId || `attempt-${randomUUID()}`;
    const sourceToolCallId = attempt?.sourceToolCallId || `tool-call-${randomUUID()}`;
    this.emit('agent:tool_call', { name: toolCall.name, args: toolCall.arguments, source });

    let toolResult: ToolResult;
    try {
      const targetReceipt = target?.metadata?.authorizationReceipt
        || target?.metadata?.scopeReceipt
        || target?.metadata?.receipt;
      if (receipt) this.emit('agent:thinking', { content: `Using the persisted completed result for ${toolCall.name}; no new tool execution.` });
      toolResult = receipt ? receipt.result : await this.arsenal.execute(toolCall.name, {
        target,
        operator: this.options.sourceAgent,
        mission: task.missionId,
        phase: task.phase,
        purpose: task.operatorType === 'analyst' ? 'reporting' : 'assessment',
        authorizationReceipt: this.options.securityContext.receipt || (targetReceipt ? String(targetReceipt) : undefined),
        attemptId,
        sourceToolCallId,
        repeatReason: task.executionPlan?.toolName === toolCall.name ? task.executionPlan.repeatReason : undefined,
        parameters: toolCall.arguments,
        abortSignal: signal,
      });
    } catch (err) {
      if (err instanceof CheckpointWriteError) throw err;
      signal?.throwIfAborted();
      // A bad/hallucinated tool name must NOT crash the loop. Return the callable set so the
      // model self-corrects in-place instead of dying or looping on a tool that doesn't exist.
      const available = this.arsenal
        .getToolDefinitions(
          this.options.toolCategories.length ? this.options.toolCategories : undefined,
          this.options.tools.length ? this.options.tools : undefined
        )
        .map((t) => t.name);
      toolResult = {
        success: false,
        error: `Tool "${toolCall.name}" is not available. Callable tools this run: ${available.join(', ') || '(none)'}. ` +
          `Use one of these EXACT names — do not invent tools; if none fit, describe the capability you need in prose.`,
      };
    }

    signal?.throwIfAborted();
    this.emit('agent:tool_result', { name: toolCall.name, result: toolResult, source });

    return {
      iteration,
      type: 'tool_call',
      toolName: toolCall.name,
      toolArgs: toolCall.arguments,
      toolResult,
      attemptId,
      sourceToolCallId,
      evidenceRecordId: typeof toolResult.metadata?.evidenceRecordId === 'string' ? toolResult.metadata.evidenceRecordId : undefined,
      timestamp: receipt?.timestamp || Date.now(),
    };
  }

  /**
   * Format a tool result for the LLM context
   */
  private formatToolResult(result?: ToolResult): string {
    if (!result) return 'No result returned.';

    const parts: string[] = [];
    parts.push(`Success: ${result.success}`);

    if (result.output) {
      let output = result.output;
      // ALWAYS cap tool output (verbose just gets a larger budget). Previously this was gated on
      // !verboseToolOutput, which defaults TRUE — so by default nothing was capped and large tool
      // results flooded the context window. Keep HEAD+TAIL: flags/results often land at the end.
      const cap = this.options.verboseToolOutput ? this.options.maxToolOutputLength * 4 : this.options.maxToolOutputLength;
      if (output.length > cap) {
        const head = Math.floor(cap * 0.7);
        const tail = cap - head;
        output = output.slice(0, head) + `\n… (truncated ${output.length - cap} chars) …\n` + output.slice(-tail);
      }
      parts.push(output);
    }

    if (result.error) {
      parts.push(`Error: ${result.error}`);
    }

    if (result.findings?.length) {
      parts.push('\nFindings:');
      for (const f of result.findings) {
        parts.push(`  - [${f.severity.toUpperCase()}] ${f.title}: ${f.details}`);
      }
    }

    return parts.join('\n');
  }

  /**
   * Parse the model's final debrief block into structured findings. The operator is told to
   * end its last message with a fenced ```json {findings:[…]} block; this is the ONLY prose→data
   * channel the harness honors (no substring guessing). Returns [] if there's no valid block.
   */
  private parseFinalFindings(content: string): ToolFinding[] {
    if (!content) return [];
    const SEV = new Set(['critical', 'high', 'medium', 'low', 'info']);
    const blocks = [...content.matchAll(/```(?:json)?\s*([\s\S]*?)```/g)].map((m) => m[1]);
    const candidates = blocks.length ? blocks.reverse() : [content];
    for (const c of candidates) {
      const start = c.indexOf('{');
      const end = c.lastIndexOf('}');
      if (start === -1 || end <= start) continue;
      try {
        const obj = JSON.parse(c.slice(start, end + 1));
        if (!obj || !Array.isArray(obj.findings)) continue;
        return obj.findings.filter((f: any) => f && f.title).map((f: any) => ({
          title: String(f.title).slice(0, 200),
          severity: (SEV.has(String(f.severity).toLowerCase()) ? String(f.severity).toLowerCase() : 'info') as Severity,
          details: String(f.details ?? f.evidence ?? f.evidence_ref ?? '').slice(0, 4000),
          cvss: typeof f.cvss === 'number' ? f.cvss : undefined,
          cve: Array.isArray(f.cve) ? f.cve.map(String) : undefined,
          remediation: f.remediation ? String(f.remediation) : undefined,
          // Model-asserted in the debrief — NO tool provenance. The gate downgrades these.
          provenance: 'model' as const,
        }));
      } catch { /* try the next candidate block */ }
    }
    return [];
  }
}

// =============================================================================
// FACTORY
// =============================================================================

export function createAgentLoop(
  llm: LLMBackbone,
  arsenal: Arsenal,
  options?: AgentLoopOptions
): AgentLoop {
  return new AgentLoop(llm, arsenal, options);
}

/**
 * Run a one-shot agent task — convenience function
 */
export async function runAgentTask(
  llm: LLMBackbone,
  arsenal: Arsenal,
  task: Task,
  systemPrompt: string,
  target?: Target,
  options?: AgentLoopOptions
): Promise<AgentResult> {
  const agent = createAgentLoop(llm, arsenal, options);
  return agent.run(task, systemPrompt, target);
}

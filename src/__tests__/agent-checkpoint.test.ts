import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AgentLoop, type AgentLoopOptions } from '../agent/index.js';
import { canReplayInterruptedCall, CheckpointRestoreError, CheckpointWriteError, UnsafeResumeError } from '../agent/checkpoint.js';
import type { Arsenal } from '../arsenal/index.js';
import type { LLMBackbone } from '../llm/index.js';
import { ProjectStore } from '../projects/store.js';
import { KillChainPhase, type LLMToolCall, type Target, type Task } from '../types/index.js';
import { OperatorAgent } from '../operators/index.js';

const directories: string[] = [];
afterEach(async () => { for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true }); });

const target = { id: 'fixture', address: 'https://fixture.test' } as Target;
const newTask = (): Task => ({ id: 'task', missionId: 'mission', name: 'Web checks',
  description: 'Inspect fixture.test', phase: KillChainPhase.RECON, operatorType: 'recon',
  status: 'in_progress', priority: 1, dependencies: [], createdAt: 1 });
const call = (id: string, method = 'GET'): LLMToolCall => ({ id, name: 'http_request', arguments: { url: `https://fixture.test/${id}`, method } });

function fixture(options: AgentLoopOptions = {}) {
  const chatWithTools = vi.fn().mockResolvedValue({ content: 'RESULT\nStatus: inconclusive', model: 'fixture', usage: { totalTokens: 11 } });
  const chat = vi.fn().mockResolvedValue({ content: 'RESULT\nStatus: inconclusive', model: 'fixture' });
  const llm = { getPromptProfile: () => 'large_model', getProvider: () => 'mock', chatWithTools, chat };
  const execute = vi.fn().mockResolvedValue({ success: true, output: 'Complete unshortened fixture evidence' });
  const definitions = [{ name: 'http_request', description: 'Read a fixture URL', parameters: { type: 'object', properties: { url: { type: 'string' } } } }];
  const getReadyToolDefinitions = vi.fn().mockResolvedValue(definitions);
  const arsenal = { execute, getReadyToolDefinitions, getToolDefinitions: () => definitions, getOrchestrator: () => ({ getEvidence: () => [] }) };
  return { loop: new AgentLoop(llm as unknown as LLMBackbone, arsenal as unknown as Arsenal, options),
    execute, chatWithTools, chat, getReadyToolDefinitions, llm };
}

describe('granular agent recovery', () => {
  it('finishes a saved partial batch in evidence-only mode without requesting another plan or summary', async () => {
    const controller = new AbortController(); const task = newTask();
    const first = fixture({ onCheckpoint: async checkpoint => {
      if (checkpoint.steps.some(step => step.toolName) && checkpoint.pendingCalls.length === 1 && !checkpoint.activeCall) controller.abort(new Error('pause boundary'));
    } });
    first.chatWithTools.mockResolvedValueOnce({ content: 'Check both paths', model: 'fixture', toolCalls: [call('one'), call('two')], usage: { totalTokens: 23 } });
    await expect(first.loop.run(task, '', target, undefined, undefined, controller.signal)).rejects.toThrow('pause boundary');
    const resumed = fixture(); resumed.llm.getProvider = () => 'deterministic';
    const result = await resumed.loop.run(JSON.parse(JSON.stringify(task)) as Task, '', target);
    expect(resumed.execute).toHaveBeenCalledOnce(); expect(resumed.execute.mock.calls[0][1].parameters.url).toContain('/two');
    expect(resumed.chatWithTools).not.toHaveBeenCalled(); expect(resumed.chat).not.toHaveBeenCalled();
    expect(result.steps.filter(step => step.toolName)).toHaveLength(2); expect(result.tokensUsed).toBe(23);
  });

  it('restores a persisted partial batch without repeating completed tools or asking for a new plan', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vulnora-agent-'));
    directories.push(directory);
    const store = new ProjectStore(directory);
    const project = await store.create('Batch', target.address, 'auto');
    const controller = new AbortController();
    const task = newTask();
    const first = fixture({ onCheckpoint: async checkpoint => {
      project.checkpoint = { task: { ...task, checkpoint } };
      await store.save(project);
      if (checkpoint.steps.some(step => step.toolName) && checkpoint.pendingCalls.length === 1 && !checkpoint.activeCall) controller.abort(new Error('pause boundary'));
    } });
    first.chatWithTools.mockResolvedValueOnce({ content: 'Check both paths', model: 'fixture', toolCalls: [call('one'), call('two')], usage: { totalTokens: 23 } });
    await expect(first.loop.run(task, '', target, undefined, undefined, controller.signal)).rejects.toThrow('pause boundary');
    expect(first.execute).toHaveBeenCalledTimes(1);
    const restored = (await new ProjectStore(directory).load(project.id)).checkpoint as { task: Task };
    expect(restored.task.checkpoint?.tokensUsed).toBe(23);
    expect(restored.task.checkpoint?.toolCallCounts).toEqual([['http_request', 1]]);
    expect(restored.task.checkpoint?.pendingCalls.map(item => item.id)).toEqual(['two']);
    const resumed = fixture();
    const result = await resumed.loop.run(restored.task, '', target);
    expect(resumed.execute).toHaveBeenCalledTimes(1);
    expect(resumed.execute.mock.calls[0][1].parameters.url).toContain('/two');
    expect(resumed.chatWithTools).toHaveBeenCalledTimes(1);
    const messages = resumed.chatWithTools.mock.calls[0][0];
    expect(messages.filter((message: { role: string }) => message.role === 'tool').map((message: { toolCallId: string }) => message.toolCallId)).toEqual(['one', 'two']);
    expect(messages.filter((message: { toolCalls?: unknown[] }) => message.toolCalls).length).toBe(1);
    expect(result.steps.filter(step => step.toolName)).toHaveLength(2);
    expect(result.tokensUsed).toBe(34);
    expect(restored.task.checkpoint?.totalToolCalls).toBe(2);
  });

  it.each(['GET', 'POST'])('handles an interrupted %s request conservatively', async method => {
    const controller = new AbortController();
    const task = newTask();
    const first = fixture();
    first.chatWithTools.mockResolvedValueOnce({ content: '', model: 'fixture', toolCalls: [call('interrupted', method)] });
    first.execute.mockImplementationOnce(async () => { controller.abort(new Error('process interrupted')); throw controller.signal.reason; });
    await expect(first.loop.run(task, '', target, undefined, undefined, controller.signal)).rejects.toThrow('process interrupted');
    expect(task.checkpoint?.activeCall?.arguments.method).toBe(method);
    const restored = JSON.parse(JSON.stringify(task)) as Task;
    const resumed = fixture();
    if (method === 'POST') {
      await expect(resumed.loop.run(restored, '', target)).rejects.toBeInstanceOf(UnsafeResumeError);
      expect(resumed.execute).not.toHaveBeenCalled();
      expect(resumed.chatWithTools).not.toHaveBeenCalled();
    } else {
      const result = await resumed.loop.run(restored, '', target);
      expect(result.success).toBe(true);
      expect(resumed.execute).toHaveBeenCalledTimes(1);
      expect(result.steps.filter(step => step.toolName)).toHaveLength(1);
    }
  });

  it('stops before execution when the durable checkpoint write fails', async () => {
    const task = newTask();
    const run = fixture({ onCheckpoint: async checkpoint => { if (checkpoint.activeCall) throw new Error('disk full'); } });
    run.chatWithTools.mockResolvedValueOnce({ content: '', model: 'fixture', toolCalls: [call('one')] });
    await expect(run.loop.run(task, '', target)).rejects.toBeInstanceOf(CheckpointWriteError);
    expect(run.execute).not.toHaveBeenCalled();
    expect(run.chatWithTools).toHaveBeenCalledTimes(1);
    expect(run.chat).not.toHaveBeenCalled();
  });

  it('returns a completed result on restart without models, tools, or availability probes', async () => {
    const task = newTask();
    const result = await fixture().loop.run(task, '', target);
    const resumed = fixture();
    expect(await resumed.loop.run(JSON.parse(JSON.stringify(task)), '', target)).toEqual(result);
    expect(resumed.chatWithTools).not.toHaveBeenCalled();
    expect(resumed.execute).not.toHaveBeenCalled();
    expect(resumed.getReadyToolDefinitions).not.toHaveBeenCalled();
  });

  it('rejects mismatched targets and malformed checkpoints before calling providers', async () => {
    const task = newTask();
    await fixture().loop.run(task, '', target);
    const run = fixture();
    await expect(run.loop.run(task, '', { ...target, address: 'https://different.test' })).rejects.toBeInstanceOf(CheckpointRestoreError);
    if (!task.checkpoint) throw new Error('Checkpoint missing');
    task.checkpoint.tokensUsed = -1;
    await expect(run.loop.run(task, '', target)).rejects.toBeInstanceOf(CheckpointRestoreError);
    expect(run.getReadyToolDefinitions).not.toHaveBeenCalled();
    expect(run.chatWithTools).not.toHaveBeenCalled();
  });

  it('resumes a paused summary without launching another planning iteration', async () => {
    const task = newTask();
    const controller = new AbortController();
    const first = fixture({ maxIterations: 1, onCheckpoint: async checkpoint => {
      if (checkpoint.phase === 'summary') controller.abort(new Error('pause summary'));
    } });
    first.chatWithTools.mockResolvedValueOnce({ content: '', model: 'fixture', toolCalls: [call('one')] });
    await expect(first.loop.run(task, '', target, undefined, undefined, controller.signal)).rejects.toThrow('pause summary');
    const resumed = fixture({ maxIterations: 1 });
    const result = await resumed.loop.run(JSON.parse(JSON.stringify(task)), '', target);
    expect(resumed.chatWithTools).not.toHaveBeenCalled();
    expect(resumed.execute).not.toHaveBeenCalled();
    expect(resumed.chat).toHaveBeenCalledTimes(1);
    expect(result.steps.filter(step => step.toolName)).toHaveLength(1);
    expect(task.checkpoint?.messages.filter(message => message.content.startsWith('The step budget')).length).toBe(1);
  });

  it('does not decompose blocked recovery into new work', async () => {
    const operator = new OperatorAgent('Checkpoint', 'recon', { maxRetries: 3, cooldownMs: 0 });
    const decompose = vi.spyOn(operator as unknown as { decomposeTask: () => Promise<Task[]> }, 'decomposeTask');
    operator.setLLM(fixture().llm as unknown as LLMBackbone);
    operator.executeTask = async () => { throw new UnsafeResumeError(call('write', 'POST')); };
    await expect(operator.assignTask(newTask(), target)).rejects.toBeInstanceOf(UnsafeResumeError);
    expect(decompose).not.toHaveBeenCalled();
    expect(operator.status).toBe('idle');
  });

  it('does not trust unknown scanners, request bodies, or malformed HTTP methods for replay', () => {
    expect(canReplayInterruptedCall({ ...call('one'), name: 'curl_request' })).toBe(false);
    expect(canReplayInterruptedCall({ ...call('one'), arguments: { method: ['GET'] } })).toBe(false);
    expect(canReplayInterruptedCall({ ...call('one'), arguments: { method: 'GET', body: 'write' } })).toBe(false);
    expect(canReplayInterruptedCall(call('one', 'HEAD'))).toBe(true);
  });
});
